#
# Compliance Benchmark Auditor for python - Copyright (c) 2026, Zoltán Pósfai. All rights reserved.
#
# License: GNU General Public License v3.0 (GPL-3.0)
#
# This library can be used to audit a system against a Compliance Benchmark defined in a JSON file. 
# The auditor executes specified commands and evaluates their output against defined conditions 
# to determine if the system meets the benchmark requirements. 
# The results are logged in a structured JSON format for analysis and reporting.
#
# This is only the auditor engine, it does not include any specific benchmark definitions.
# 

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, TextIO, Tuple, Union


# ============================================================================
# Data Models & Results
# ============================================================================

@dataclass
class CommandExecutionResult:
    """Encapsulates command or cmdlet execution results."""
    returncode: int
    stdout: str
    stderr: str


# ============================================================================
# Internal Cmdlet Functions
# ============================================================================

class InternalCmdlets:
    """Internal cmdlet implementations for system audit checks."""

    @staticmethod
    def _is_systemd_booted() -> bool:
        """Check if the system was booted with systemd as init (PID 1)."""
        return os.path.exists('/run/systemd/system')

    @staticmethod
    def _unescape_mount_field(field: str) -> str:
        """Decode octal escape sequences in /proc/mounts (e.g. \\040 -> space)."""
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), field)

    @staticmethod
    def _package_manager() -> Optional[str]:
        """Select the native package manager from OS metadata or PATH."""
        try:
            os_release = platform.freedesktop_os_release()
            distro_ids = set(os_release.get('ID', '').lower().split())
            distro_ids.update(os_release.get('ID_LIKE', '').lower().split())
            if distro_ids & {'debian', 'ubuntu', 'linuxmint'} and shutil.which('dpkg'):
                return 'dpkg'
            if distro_ids & {'fedora', 'rhel', 'centos', 'rocky', 'alma', 'suse', 'opensuse', 'sles'} and shutil.which('rpm'):
                return 'rpm'
        except (OSError, AttributeError):
            pass

        if shutil.which('rpm'):
            return 'rpm'
        if shutil.which('dpkg'):
            return 'dpkg'
        return None

    @classmethod
    def _package_query(cls, args: List[str], expect_installed: bool) -> Tuple[int, str, str]:
        """Check each package argument using the system's native package manager."""
        if not isinstance(args, list) or not args:
            return (1, "", "Invalid arguments: expected at least one package name")

        package_manager = cls._package_manager()
        if package_manager is None:
            return (1, "", "rpm or dpkg binary not found in PATH")
        query_args = [package_manager, '-q' if package_manager == 'rpm' else '-l']

        results = []
        stdout_parts = []
        stderr_parts = []
        try:
            for package_name in args:
                result = subprocess.run(
                    query_args + [str(package_name)],
                    capture_output=True,
                    text=True,
                    stdin=subprocess.DEVNULL
                )
                installed = result.returncode == 0
                results.append(installed == expect_installed)
                if result.stdout.strip():
                    stdout_parts.append(result.stdout.strip())
                if result.stderr.strip():
                    stderr_parts.append(result.stderr.strip())

            return (
                0 if all(results) else 1,
                "\n".join(stdout_parts),
                "\n".join(stderr_parts)
            )
        except Exception as e:
            return (1, "", f"Error querying packages with {package_manager}: {e}")

    @classmethod
    def haspkg(cls, args: List[str]) -> Tuple[int, str, str]:
        """Internal cmdlet that succeeds when all packages are installed."""
        return cls._package_query(args, expect_installed=True)

    @classmethod
    def missingpkg(cls, args: List[str]) -> Tuple[int, str, str]:
        """Internal cmdlet that succeeds when all packages are missing."""
        return cls._package_query(args, expect_installed=False)

    @staticmethod
    def _csv_filter_match(field: str, filter_spec: Optional[str]) -> bool:
        """Return whether a CSV field satisfies a validated filter specification."""
        if filter_spec is None:
            return True

        filter_type = filter_spec[0]
        expression = filter_spec[1:]
        if filter_type == 'r':
            try:
                return re.search(expression, field) is not None
            except re.error:
                return False

        if filter_type == 'l':
            return (expression == 'empty' and field == '') or (
                expression == 'non-empty' and field != ''
            )

        try:
            numeric_value = float(field)
        except ValueError:
            return False

        expression = expression.replace('$num', str(numeric_value)).replace('$len', str(len(field)))
        comparison = re.fullmatch(r'(>=|<=|==|!=|>|<)\s*(-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)', expression)
        if comparison is None:
            return False

        operator, right_value_text = comparison.groups()
        right_value = float(right_value_text)
        return {
            '>': numeric_value > right_value,
            '>=': numeric_value >= right_value,
            '<': numeric_value < right_value,
            '<=': numeric_value <= right_value,
            '==': numeric_value == right_value,
            '!=': numeric_value != right_value,
        }[operator]

    @staticmethod
    def _validate_csv_filter(filter_spec: str) -> Optional[str]:
        """Return an error for an invalid CSV filter, otherwise None."""
        if len(filter_spec) < 2 or filter_spec[0] not in ('r', 'm', 'l'):
            return "Invalid filter: expected r<regex>, m<maths_expression>, or l<logic_operator>"

        filter_type = filter_spec[0]
        filter_expression = filter_spec[1:]
        if filter_type == 'r':
            try:
                re.compile(filter_expression)
            except re.error as exc:
                return f"Invalid regular expression: {exc}"
        elif filter_type == 'm' and not re.fullmatch(
            r'(>=|<=|==|!=|>|<)\s*(?:\$num|\$len|-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)',
            filter_expression
        ):
            return "Invalid maths expression"
        elif filter_type == 'l' and filter_expression not in ('empty', 'non-empty'):
            return "Invalid logic operator: expected 'empty' or 'non-empty'"
        return None

    @classmethod
    def csvfilter(cls, args: List[str]) -> Tuple[int, str, str]:
        """Filter CSV records with optional return and post-filter stages."""
        if not isinstance(args, list) or len(args) not in (3, 5, 7):
            return (1, "", "Invalid arguments: expected 3, 5, or 7 arguments")

        path = str(args[0])
        delimiter = str(args[1])
        try:
            field_number = int(str(args[2]))
        except (TypeError, ValueError):
            return (1, "", "Invalid field number: expected a positive integer")

        if len(delimiter) != 1:
            return (1, "", "Invalid delimiter: expected exactly one character")
        if field_number < 1:
            return (1, "", "Invalid field number: expected a positive integer")

        return_type = 'field'
        filter_spec: Optional[str] = None
        post_field_number = 0
        post_filter: Optional[str] = None
        if len(args) >= 5:
            filter_spec = str(args[3])
            return_type = str(args[4])
            if return_type not in ('field', 'line'):
                return (1, "", "Invalid return type: expected 'field' or 'line'")
            filter_error = cls._validate_csv_filter(filter_spec)
            if filter_error is not None:
                return (1, "", filter_error)

        if len(args) == 7:
            try:
                post_field_number = int(str(args[5]))
            except (TypeError, ValueError):
                return (1, "", "Invalid post field number: expected a non-negative integer")
            post_filter = str(args[6])
            if (return_type == 'field' and post_field_number != 0) or (
                return_type == 'line' and post_field_number < 1
            ):
                return (1, "", "Invalid post field number: must be zero for 'field' or positive for 'line'")
            filter_error = cls._validate_csv_filter(post_filter)
            if filter_error is not None:
                return (1, "", filter_error.replace('filter', 'post-filter', 1))

        output: List[str] = []
        try:
            with open(path, 'r', encoding='utf-8', newline='') as csv_file:
                reader = csv.reader(csv_file, delimiter=delimiter, strict=True)
                for row in reader:
                    if not row or (len(row) == 1 and row[0] == ''):
                        continue
                    if field_number > len(row):
                        return (1, "", f"Field number {field_number} is not present in CSV record")
                    field = row[field_number - 1]
                    if cls._csv_filter_match(field, filter_spec):
                        returned = field if return_type == 'field' else delimiter.join(row)
                        if post_filter is not None:
                            if post_field_number > len(row):
                                return (1, "", f"Post field number {post_field_number} is not present in CSV record")
                            post_field = returned if return_type == 'field' else row[post_field_number - 1]
                            if not cls._csv_filter_match(post_field, post_filter):
                                continue
                        output.append(returned)
        except (OSError, UnicodeError, csv.Error) as exc:
            return (1, "", f"Failed to read or parse CSV file: {exc}")

        return (0, "\n".join(output), "")

    @classmethod
    def service(cls, args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
        """Internal cmdlet for checking systemd service states.

        Args:
            args: List of arguments [function_name, service_name, ...]
                  - function_name: 'isrunning', 'isenabled', or 'ismasked'
                  - service_name: Name of the systemd service to check
            timeout: Subprocess execution timeout in seconds.

        Returns:
            tuple: (exit_code, stdout, stderr)
        """
        if not isinstance(args, list) or len(args) < 2:
            return (1, "", "Invalid arguments: expected [function_name, service_name]")

        function_name = str(args[0]).lower()
        service_name = str(args[1])

        if not cls._is_systemd_booted():
            return (1, "", "systemd is not running as PID 1 on this system")

        if not shutil.which('systemctl'):
            return (1, "", "systemctl binary not found in PATH")

        try:
            if function_name == 'isrunning':
                result = subprocess.run(
                    ['systemctl', 'is-active', service_name],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    stdin=subprocess.DEVNULL
                )
                return (result.returncode, result.stdout.strip(), result.stderr.strip())

            elif function_name == 'isenabled':
                result = subprocess.run(
                    ['systemctl', 'is-enabled', service_name],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    stdin=subprocess.DEVNULL
                )
                return (result.returncode, result.stdout.strip(), result.stderr.strip())

            elif function_name == 'ismasked':
                result = subprocess.run(
                    ['systemctl', 'is-enabled', service_name],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    stdin=subprocess.DEVNULL
                )
                output = result.stdout.strip()
                if output == 'masked':
                    return (0, "masked", "")
                return (1, output, result.stderr.strip())

            else:
                return (1, "", f"Unsupported service function: {function_name}. Must be one of: isrunning, isenabled, ismasked")

        except subprocess.TimeoutExpired:
            return (1, "", f"Timeout ({timeout}s) expired while querying service {service_name}")
        except Exception as e:
            return (1, "", str(e))

    @classmethod
    def mountopt(cls, args: List[str]) -> Tuple[int, str, str]:
        """Internal cmdlet for retrieving mount options from /proc/mounts.

        Args:
            args: List of arguments [type, target]
                  - type: Either 'mountpoint' (path) or 'device' (device file)
                  - target: The mountpoint path (if type='mountpoint') or device file (if type='device')

        Returns:
            tuple: (exit_code, stdout, stderr)
        """
        if not isinstance(args, list) or len(args) < 2:
            return (1, "", "Invalid arguments: expected [type, target]")

        mount_type = str(args[0]).lower()
        target = str(args[1])

        if mount_type not in ('mountpoint', 'device'):
            return (1, "", f"Invalid type: {mount_type}. Must be 'mountpoint' or 'device'")

        normalized_target = os.path.normpath(target) if mount_type == 'mountpoint' else target

        if not os.path.exists('/proc/mounts'):
            return (1, "", "/proc/mounts not available on this system")

        matched_options: Optional[str] = None
        try:
            with open('/proc/mounts', 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue

                    device = cls._unescape_mount_field(parts[0])
                    mountpoint = os.path.normpath(cls._unescape_mount_field(parts[1]))
                    options = parts[3]

                    if mount_type == 'mountpoint' and mountpoint == normalized_target:
                        matched_options = options
                    elif mount_type == 'device' and device == normalized_target:
                        matched_options = options

            if matched_options is not None:
                return (0, matched_options, "")
            return (1, "", f"Mount not found for {mount_type}: {target}")

        except Exception as e:
            return (1, "", str(e))

    @classmethod
    def ismount(cls, args: List[str]) -> Tuple[int, str, str]:
        """Internal cmdlet for checking whether a path is a mount point."""
        if not isinstance(args, list) or len(args) != 1:
            return (1, "", "Invalid arguments: expected [path]")

        path = os.path.normpath(str(args[0]))
        if not os.path.exists(path):
            return (1, "", f"Path does not exist: {path}")

        try:
            if os.path.ismount(path):
                if os.path.exists('/proc/mounts'):
                    with open('/proc/mounts', 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                mp = os.path.normpath(cls._unescape_mount_field(parts[1]))
                                if mp == path:
                                    return (0, line.strip(), "")
                return (0, f"mounted {path}", "")
            return (1, "", "")
        except Exception as e:
            return (1, "", str(e))

    @classmethod
    def bootmounted(cls, args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
        """Internal cmdlet for checking whether a mount is enabled at boot via systemd."""
        if not isinstance(args, list) or len(args) != 1:
            return (1, "", "Invalid arguments: expected [mountpoint]")

        if not cls._is_systemd_booted():
            return (1, "", "systemd is not running as PID 1 on this system")

        if not shutil.which('systemd-escape') or not shutil.which('systemctl'):
            return (1, "", "systemd-escape or systemctl not found in PATH")

        try:
            mountpoint = str(args[0])
            escaped = subprocess.run(
                ['systemd-escape', '--path', '--suffix=mount', mountpoint],
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL
            )
            if escaped.returncode != 0:
                return (1, escaped.stdout.strip(), escaped.stderr.strip())

            mount_unit = escaped.stdout.strip()
            result = subprocess.run(
                ['systemctl', 'is-enabled', mount_unit],
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL
            )
            output = result.stdout.strip()
            if result.returncode == 0 and output.lower() not in ('masked', 'disabled'):
                return (0, output, result.stderr.strip())
            return (1, output, result.stderr.strip())
        except subprocess.TimeoutExpired:
            return (1, "", f"Timeout checking bootmounted for {args[0]}")
        except Exception as e:
            return (1, "", str(e))


# Backward-compatible alias
cmdlet_internal = InternalCmdlets

# Cmdlet Registry: Maps cmdlet_name to (cmdlet_type, callable)
CMDLET_REGISTRY: Dict[str, Tuple[str, Callable[..., Tuple[int, str, str]]]] = {
    'service': ('internal', InternalCmdlets.service),
    'haspkg': ('internal', InternalCmdlets.haspkg),
    'missingpkg': ('internal', InternalCmdlets.missingpkg),
    'csvfilter': ('internal', InternalCmdlets.csvfilter),
    'mountopt': ('internal', InternalCmdlets.mountopt),
    'ismount': ('internal', InternalCmdlets.ismount),
    'bootmoxunted': ('internal', InternalCmdlets.bootmounted),
}


# ============================================================================
# Compliance Benchmark Auditor Engine
# ============================================================================

class ComplianceBenchmarkAuditor:
    def __init__(
        self,
        benchmark_file_paths: List[str],
        max_message_length: int = 512,
        run_list: Optional[List[str]] = None,
        fail_on_missing_test: bool = False,
        output_stream: Optional[TextIO] = None,
        log_file_name: Optional[str] = None,
        command_timeout: int = 30
    ) -> None:
        """Initialize the auditor with one or more benchmark JSON file paths.

        Args:
            benchmark_file_paths: List of paths to benchmark JSON files
            max_message_length: Maximum length in bytes for stdout/stderr output (default: 512)
            run_list: List of test names to run. If None or empty, run all tests (default: None)
            fail_on_missing_test: If True, fail if any items in run_list are not found (default: False)
            output_stream: Stream for human-readable output (defaults to sys.stdout)
            log_file_name: Custom filename for JSON audit log output
            command_timeout: Maximum duration in seconds for each audit command (default: 30)
        """
        self.benchmark_file_paths = benchmark_file_paths
        self.max_message_length = max_message_length
        self.run_list = list(run_list) if run_list else []
        self.fail_on_missing_test = fail_on_missing_test
        self.command_timeout = command_timeout
        self.no_passed = 0
        self.matched_items: Set[str] = set()
        self.output_stream = output_stream if output_stream is not None else sys.stdout
        self.log_file_name = log_file_name

        # Load benchmarks
        self.benchmarks: List[Dict[str, Any]] = []
        self.test_library: List[Dict[str, Any]] = []

        if not self.benchmark_file_paths:
            raise ValueError('No benchmark file paths provided')

        for lib_id, path in enumerate(self.benchmark_file_paths):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    benchmark = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f'Failed to load benchmark file {path}: {exc}') from exc
            if not isinstance(benchmark, dict):
                raise ValueError(f'Benchmark file {path} must contain a JSON object')
            title = benchmark.get('title') or os.path.basename(path)
            self.benchmarks.append(benchmark)
            self.test_library.append({
                'id': lib_id,
                'name': title,
                'file_name': os.path.basename(path)
            })

        if not self.benchmarks:
            raise ValueError('No benchmarks loaded')

        # Initialize JSON log structure
        self.start_datetime = datetime.now(timezone.utc)
        self.perf_start = time.perf_counter()

        top_title = self.benchmarks[0].get('title', 'Benchmark') if self.benchmarks else 'Benchmark'
        if len(self.benchmarks) > 1:
            top_title = 'Combined Benchmark'

        self.log_data: Dict[str, Any] = {
            'title': top_title,
            'start_datetime': self.start_datetime.isoformat(),
            'end_datetime': None,
            'duration_seconds': None,
            'test_library': self.test_library,
            'findings': []
        }

    def __enter__(self) -> ComplianceBenchmarkAuditor:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _sanitize_output(self, text: Any) -> str:
        """Sanitize output to ensure it is JSON-safe and valid UTF-8."""
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)
        return text.encode('utf-8', errors='replace').decode('utf-8', errors='replace')

    def auditor_engine(self, item: Dict[str, Any]) -> None:
        """Execute audit items for a given benchmark item."""
        item_name = item.get('name', '<unnamed>')
        print(f"{item_name} : ", end='', file=self.output_stream, flush=True)
        item_start_time = datetime.now(timezone.utc)
        item_start_perf = time.perf_counter()

        item_pass = True
        item_error: Optional[str] = None
        audit_results: List[Dict[str, Any]] = []
        stdout_string = ""
        err_string = ""
        pass_logic = item.get('pass_logic')
        audit_items = item.get('audit', [])

        if not isinstance(audit_items, list):
            item_error = 'item audit list is missing or invalid'
            audit_items = []

        if pass_logic is not None:
            missing_names = [
                idx for idx, block in enumerate(audit_items)
                if not isinstance(block, dict) or 'audit_test_name' not in block
            ]
            if missing_names:
                item_error = f"pass_logic defined but audit_test_name missing for audit block(s): {', '.join(map(str, missing_names))}"

        for audit_item in audit_items:
            if item_error is not None:
                break
            if not isinstance(audit_item, dict):
                item_error = 'invalid audit block; expected object'
                break

            has_cmd = 'cmd' in audit_item and isinstance(audit_item.get('cmd'), str) and audit_item.get('cmd')
            has_cmdlet = 'cmdlet' in audit_item and isinstance(audit_item.get('cmdlet'), dict)

            if not (has_cmd or has_cmdlet):
                item_error = 'audit block must have either cmd or cmdlet'
                break

            if has_cmd and has_cmdlet:
                item_error = 'audit block cannot have both cmd and cmdlet'
                break

            response_conditions = audit_item.get('response_conditions')
            if not isinstance(response_conditions, list):
                item_error = 'audit block missing or invalid response_conditions'
                break

            exec_result: Optional[CommandExecutionResult] = None
            try:
                if has_cmd:
                    cmd_str = audit_item['cmd']
                    sub_res = subprocess.run(
                        cmd_str,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=self.command_timeout,
                        stdin=subprocess.DEVNULL,
                        executable='/bin/bash' if os.path.exists('/bin/bash') else None
                    )
                    exec_result = CommandExecutionResult(sub_res.returncode, sub_res.stdout, sub_res.stderr)
                else:
                    cmdlet_spec = audit_item['cmdlet']
                    cmdlet_name = cmdlet_spec.get('cmdlet_name')
                    cmdlet_type = cmdlet_spec.get('cmdlet_type')
                    cmdlet_args = cmdlet_spec.get('cmdlet_args')

                    if not cmdlet_name:
                        item_error = 'cmdlet block missing cmdlet_name'
                        break
                    if not cmdlet_type:
                        item_error = 'cmdlet block missing cmdlet_type'
                        break
                    if cmdlet_type not in ('internal', 'external'):
                        item_error = f'invalid cmdlet_type: {cmdlet_type}. Must be "internal" or "external"'
                        break
                    if not isinstance(cmdlet_args, list):
                        item_error = 'cmdlet_args must be a list'
                        break

                    if cmdlet_name not in CMDLET_REGISTRY:
                        item_error = f'cmdlet "{cmdlet_name}" not found in registry'
                        break

                    registered_type, cmdlet_func = CMDLET_REGISTRY[cmdlet_name]
                    if registered_type != cmdlet_type:
                        item_error = f'cmdlet "{cmdlet_name}" type mismatch: expected {registered_type}, got {cmdlet_type}'
                        break

                    exit_code, c_stdout, c_stderr = cmdlet_func(cmdlet_args)
                    exec_result = CommandExecutionResult(exit_code, c_stdout, c_stderr)

            except subprocess.TimeoutExpired:
                item_error = f'command timed out after {self.command_timeout} seconds'
                break
            except Exception as exc:
                item_error = f'failed to execute audit command: {exc}'
                break

            if exec_result is not None:
                stdout_string = self._sanitize_output(exec_result.stdout[:self.max_message_length])
                err_string = self._sanitize_output(exec_result.stderr[:self.max_message_length])
                item_eval = self.response_evaluator(stdout_string, err_string, response_conditions, exec_result.returncode)
                audit_results.append({
                    'audit_test_name': audit_item.get('audit_test_name'),
                    'cmd' if has_cmd else 'cmdlet': audit_item.get('cmd') if has_cmd else audit_item.get('cmdlet'),
                    'passed': bool(item_eval)
                })

        # Evaluate overall item status
        if item_error is not None:
            item_pass = False
        elif pass_logic is not None:
            try:
                item_pass = self._evaluate_pass_logic(
                    pass_logic,
                    {r['audit_test_name']: r['passed'] for r in audit_results if r.get('audit_test_name') is not None}
                )
            except ValueError as exc:
                item_pass = False
                item_error = str(exc)
        else:
            item_pass = bool(audit_results) and all(r['passed'] for r in audit_results)

        item_end_time = datetime.now(timezone.utc)
        test_duration = round(time.perf_counter() - item_start_perf, 4)

        finding: Dict[str, Any] = {
            'name': item['name'],
            'test_library_id': item.get('test_library_id'),
            'start_time': item_start_time.isoformat(),
            'end_time': item_end_time.isoformat(),
            'test_time': test_duration,
            'score': 0 if item_pass else 1,
            'stdout': stdout_string,
            'stderr': err_string,
            'audit_test_names': [r['audit_test_name'] for r in audit_results if r.get('audit_test_name') is not None],
            'audit_results': audit_results,
            'labels': item.get('labels', [])
        }
        if pass_logic is not None:
            finding['pass_logic'] = pass_logic
            finding['pass_logic_result'] = item_pass
        if item_error is not None:
            finding['errors'] = [item_error]

        self.log_data['findings'].append(finding)

        if item_pass and item_error is None:
            print("PASSED", file=self.output_stream)
            self.no_passed += 1
        else:
            print("FAILED", file=self.output_stream)

    def response_evaluator(
        self,
        stdout_string: str,
        err_string: str,
        response_conditions: List[Dict[str, Any]],
        return_code: Optional[int] = None
    ) -> bool:
        """Evaluate response conditions against command output and exit code."""
        if not isinstance(response_conditions, list) or not response_conditions:
            return False

        required_evals: List[bool] = []
        optional_evals: List[bool] = []

        for response_condition in response_conditions:
            if not isinstance(response_condition, dict):
                continue

            control_flag = response_condition.get('control_flag')
            if control_flag not in ('required', 'optional'):
                continue

            on_target = response_condition.get('on')
            response_string: Optional[str] = None
            if on_target == 'stdout':
                response_string = stdout_string
            elif on_target == 'stderr':
                response_string = err_string

            cond = response_condition.get('condition')
            iter_condition = False

            if cond == 'exitcode':
                expected = response_condition.get('exit_result')
                if expected is not None and return_code is not None:
                    try:
                        iter_condition = (return_code == int(expected))
                    except (ValueError, TypeError):
                        iter_condition = False
            elif cond == 'not_exitcode':
                expected = response_condition.get('exit_result')
                if expected is not None and return_code is not None:
                    try:
                        iter_condition = (return_code != int(expected))
                    except (ValueError, TypeError):
                        iter_condition = False
            elif cond in ('like', 'match'):
                target = response_condition.get('match_to', response_condition.get('like_to'))
                if target is not None and response_string is not None:
                    iter_condition = (str(target) in response_string)
            elif cond == 'matchregex':
                target = response_condition.get('match_to')
                if target is not None and response_string is not None:
                    try:
                        iter_condition = re.search(str(target), response_string) is not None
                    except re.error:
                        iter_condition = False
            elif cond in ('not_like', 'no_match'):
                target = response_condition.get('no_match_for', response_condition.get('no_match_to', response_condition.get('not_like_to')))
                if target is not None and response_string is not None:
                    iter_condition = (str(target) not in response_string)
            elif cond == 'pass_if_no_lines':
                iter_condition = (response_string == "")
            elif cond == 'pass_if_lines':
                iter_condition = (response_string != "")
            elif cond == 'default_pass':
                iter_condition = True

            if control_flag == 'required':
                required_evals.append(iter_condition)
            elif control_flag == 'optional':
                optional_evals.append(iter_condition)

        req_satisfied = all(required_evals) if required_evals else True
        opt_satisfied = any(optional_evals) if optional_evals else True

        if not required_evals and not optional_evals:
            return False

        return req_satisfied and opt_satisfied

    def run(self) -> int:
        """Run the complete audit. Returns 0 if all tests passed, 1 if failures or errors occurred."""
        print(self.log_data['title'], file=self.output_stream)

        # Determine which items to run from all benchmark libraries
        items_to_run: List[Dict[str, Any]] = []
        for lib_id, benchmark in enumerate(self.benchmarks):
            if not isinstance(benchmark, dict):
                continue
            for item in benchmark.get('items', []):
                if not isinstance(item, dict):
                    continue
                item_name = item.get('name')
                if self.run_list:
                    if item_name in self.run_list:
                        item_copy = dict(item)
                        item_copy['test_library_id'] = lib_id
                        items_to_run.append(item_copy)
                        self.matched_items.add(item_name)
                else:
                    item_copy = dict(item)
                    item_copy['test_library_id'] = lib_id
                    items_to_run.append(item_copy)

        for item in items_to_run:
            self.auditor_engine(item)

        print(f"{self.no_passed}/{len(items_to_run)} PASSED", file=self.output_stream)

        # Calculate summary
        failed_scans = [
            {
                'test_library_id': finding.get('test_library_id'),
                'name': finding['name']
            }
            for finding in self.log_data['findings'] if finding['score'] != 0
        ]
        self.log_data['summary'] = {
            'test_num': len(items_to_run),
            'fail_num': len(failed_scans),
            'failed_scans': failed_scans
        }

        # Check for unmatched items in run_list
        if self.run_list:
            unmatched_items = [item for item in self.run_list if item not in self.matched_items]
            if unmatched_items:
                self.log_data['sub_list_errors'] = {
                    'missing_num': len(unmatched_items),
                    'missed_list': unmatched_items
                }

        # Set overall_pass flag (0 = PASS, 1 = FAIL)
        is_failed = (self.log_data['summary']['fail_num'] > 0)
        if self.fail_on_missing_test and 'sub_list_errors' in self.log_data:
            if self.log_data['sub_list_errors']['missing_num'] > 0:
                is_failed = True

        self.log_data['overall_pass'] = 1 if is_failed else 0

        # Finalize log data
        end_datetime = datetime.now(timezone.utc)
        self.log_data['end_datetime'] = end_datetime.isoformat()
        self.log_data['duration_seconds'] = round(time.perf_counter() - self.perf_start, 4)

        return 1 if is_failed else 0

    def _tokenize_pass_logic(self, pass_logic: str) -> List[str]:
        if not isinstance(pass_logic, str):
            raise ValueError("pass_logic must be a string")
        token_pattern = re.compile(r'\(|\)|!|&&|\|\||[a-zA-Z0-9_.-]+')
        tokens = token_pattern.findall(pass_logic)
        if not tokens:
            raise ValueError("pass_logic expression is empty")
        return tokens

    def _evaluate_pass_logic(self, pass_logic: str, audit_name_values: Dict[str, bool]) -> bool:
        tokens = self._tokenize_pass_logic(pass_logic)
        position = 0

        def parse_expression() -> bool:
            nonlocal position
            value = parse_and_term()
            while position < len(tokens) and tokens[position].upper() in ('OR', '||'):
                position += 1
                rhs = parse_and_term()
                value = value or rhs
            return value

        def parse_and_term() -> bool:
            nonlocal position
            value = parse_factor()
            while position < len(tokens) and tokens[position].upper() in ('AND', '&&'):
                position += 1
                rhs = parse_factor()
                value = value and rhs
            return value

        def parse_factor() -> bool:
            nonlocal position
            if position >= len(tokens):
                raise ValueError("Unexpected end of pass_logic expression")

            token = tokens[position]
            if token in ('!', 'NOT', 'not'):
                position += 1
                return not parse_factor()

            if token == '(':
                position += 1
                value = parse_expression()
                if position >= len(tokens) or tokens[position] != ')':
                    raise ValueError("Unmatched parenthesis in pass_logic expression")
                position += 1
                return value

            position += 1
            if token.upper() in ('AND', 'OR', '&&', '||', ')'):
                raise ValueError(f"Invalid pass_logic syntax near token '{token}'")

            if token not in audit_name_values:
                raise ValueError(f"pass_logic references undefined audit_test_name '{token}'")

            return bool(audit_name_values[token])

        result = parse_expression()
        if position != len(tokens):
            raise ValueError(f"Unexpected token '{tokens[position]}' in pass_logic expression")
        return result

    def close(self) -> None:
        """Close and write the JSON log file."""
        log_file_name = self.log_file_name if self.log_file_name else (
            f"benchmark_results_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
        )
        try:
            with open(log_file_name, "w", encoding="utf-8") as f:
                json.dump(self.log_data, f, indent=2)
        except OSError as exc:
            print(f"Error writing report to {log_file_name}: {exc}", file=sys.stderr)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


# ============================================================================
# CLI Interface
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Compliance Benchmark Auditor")
    parser.add_argument('benchmark_file_paths', nargs='+', help='Path(s) to one or more benchmark JSON files')
    parser.add_argument('-o', '--output', help='Use this filename for the JSON log file')
    parser.add_argument('--quiet', action='store_true', help='Suppress human-readable output')
    parser.add_argument('--timeout', type=int, default=30, help='Command execution timeout in seconds (default: 30)')
    parser.add_argument('--fail-on-missing', action='store_true', help='Fail if any items in run_list are not found')
    parser.add_argument('--run-list', nargs='*', help='Specific test item names to run')
    args = parser.parse_args()

    out_stream = open(os.devnull, 'w') if args.quiet else None
    exit_code = 0

    try:
        with ComplianceBenchmarkAuditor(
            benchmark_file_paths=args.benchmark_file_paths,
            output_stream=out_stream,
            log_file_name=args.output,
            command_timeout=args.timeout,
            fail_on_missing_test=args.fail_on_missing,
            run_list=args.run_list
        ) as auditor:
            exit_code = auditor.run()
    except Exception as exc:
        print(f"Auditor failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if out_stream is not None:
            try:
                out_stream.close()
            except Exception:
                pass

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
