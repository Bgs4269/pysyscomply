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

# Each element in an "item"'s audit list is executed in order and every command and evaluates its response_conditions.
# The overall item result is the logical AND of the per-command results:
#  item_pass starts True and is updated by item_pass = item_pass and item_eval, so every audit element must pass for the item to be considered PASS.
#
# Per-command condition logic (in response_evaluator):
#   control_flag == 'required': required conditions are combined so all required conditions must hold (effectively AND across required conditions).
#   control_flag == 'optional': optional conditions are OR'ed into the result (any optional true can make that step succeed).
#
# Match types:
#   Positive string matches accept match/like (keys match_to or like_to).
#   Negative string matches accept no_match_for / no_match_to / legacy not_like_to.
#   exitcode / not_exitcode check returncode == exit_result or != exit_result.


import subprocess
import json
import argparse
import sys
import os
from datetime import datetime


class CISBenchmarkAuditor:
    def __init__(self, benchmark_file_paths, max_message_length=512, run_list=None, fail_on_missing_test=False, output_stream=None, log_file_name=None):
        """Initialize the auditor with one or more benchmark JSON file paths.
        
        Args:
            benchmark_file_paths: List of paths to benchmark JSON files
            max_message_length: Maximum length in bytes for stdout/stderr output (default: 512)
            run_list: List of test names to run. If None or empty, run all tests (default: None)
            fail_on_missing_test: If True, fail if any items in run_list are not found (default: False)
        """
        self.benchmark_file_paths = benchmark_file_paths
        self.max_message_length = max_message_length
        self.run_list = run_list if run_list else []
        self.fail_on_missing_test = fail_on_missing_test
        self.no_passed = 0
        self.matched_items = set()  # Track which run_list items were matched
        # Output stream for human-readable, line-by-line output (defaults to stdout)
        self.output_stream = output_stream if output_stream is not None else sys.stdout
        # Optional override for the JSON log filename
        self.log_file_name = log_file_name

        # Load benchmarks
        self.benchmarks = []
        self.test_library = []
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
        self.start_datetime = datetime.now()
        top_title = self.benchmarks[0].get('title', 'Benchmark')
        if len(self.benchmarks) > 1:
            top_title = 'Combined Benchmark'
        self.log_data = {
            'title': top_title,
            'start_datetime': self.start_datetime.isoformat(),
            'end_datetime': None,
            'duration_seconds': None,
            'test_library': self.test_library,
            'findings': []
        }
    
    def _sanitize_output(self, text):
        """Sanitize output to ensure it's JSON-safe.
        
        Handles invalid UTF-8 sequences and problematic characters.
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Encode with error handling, then decode back to ensure valid UTF-8
        return text.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
    
    def auditor_engine(self, item):
        """Execute audit items for a given benchmark item."""
        item_name = item.get('name', '<unnamed>')
        print(item_name + " : ", end='', file=self.output_stream)
        item_start_time = datetime.now()
        item_pass = True
        item_error = None
        audit_results = []
        stdout_string = ""
        err_string = ""
        pass_logic = item.get('pass_logic')
        audit_items = item.get('audit', [])

        if not isinstance(audit_items, list):
            item_error = 'item audit list is missing or invalid'
            audit_items = []

        if pass_logic is not None:
            # When pass_logic is present, every audit block must provide an audit_test_name.
            missing_names = [idx for idx, audit_item in enumerate(audit_items) if not isinstance(audit_item, dict) or 'audit_test_name' not in audit_item]
            if missing_names:
                item_error = "pass_logic defined but audit_test_name missing for audit block(s): %s" % ", ".join(str(idx) for idx in missing_names)

        for audit_item in audit_items:
            if item_error is not None:
                break
            if not isinstance(audit_item, dict):
                item_error = 'invalid audit block; expected object'
                break

            cmd = audit_item.get('cmd')
            if not isinstance(cmd, str) or not cmd:
                item_error = 'audit block missing or invalid cmd'
                break

            response_conditions = audit_item.get('response_conditions')
            if not isinstance(response_conditions, list):
                item_error = 'audit block missing or invalid response_conditions'
                break

            try:
                result = subprocess.run(cmd,
                                       shell=True,
                                       capture_output=True,
                                       text=True)
            except Exception as exc:
                item_error = f'failed to execute audit command: {exc}'
                break

            stdout_string = self._sanitize_output(result.stdout[:self.max_message_length])
            err_string = self._sanitize_output(result.stderr[:self.max_message_length])
            item_eval = self.response_evaluator(stdout_string, err_string, response_conditions, result.returncode)
            audit_results.append({
                'audit_test_name': audit_item.get('audit_test_name'),
                'cmd': cmd,
                'passed': bool(item_eval)
            })

        if item_error is None:
            if pass_logic is not None:
                try:
                    item_pass = self._evaluate_pass_logic(pass_logic, {result['audit_test_name']: result['passed'] for result in audit_results})
                except ValueError as exc:
                    item_pass = False
                    item_error = str(exc)
            else:
                item_pass = all(result['passed'] for result in audit_results)

        item_end_time = datetime.now()
        test_duration = (item_end_time - item_start_time).total_seconds()
        
        # Create finding record
        finding = {
            'name': item['name'],
            'test_library_id': item.get('test_library_id'),
            'start_time': item_start_time.isoformat(),
            'end_time': item_end_time.isoformat(),
            'test_time': test_duration,
            'score': 0 if item_pass else 1,
            'stdout': stdout_string,
            'stderr': err_string,
            'audit_test_names': [result['audit_test_name'] for result in audit_results if result['audit_test_name'] is not None],
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
    
    def response_evaluator(self, stdout_string, err_string, response_conditions, return_code=None):
        """Evaluate response conditions against command output and exit code."""
        if not isinstance(response_conditions, list):
            return False
        condition = False
        first_run = True
        
        for response_condition in response_conditions:
            if not isinstance(response_condition, dict):
                continue
            iter_response_condition = False
            response_string = None
            
            on_target = response_condition.get('on')
            if on_target == 'stdout':
                response_string = stdout_string
            elif on_target == 'stderr':
                response_string = err_string
            elif on_target == 'return_code':
                response_string = None
            
            control_flag = response_condition.get('control_flag')
            if control_flag not in ('required', 'optional'):
                continue

            # Support both old ('like'/'not_like') and new ('match'/'no_match') condition names
            cond = response_condition.get('condition')
            # Exit code condition
            if cond == 'exitcode':
                expected = response_condition.get('exit_result')
                if expected is not None and return_code is not None and return_code == expected:
                    iter_response_condition = True
            elif cond == 'not_exitcode':
                expected = response_condition.get('exit_result')
                if expected is not None and return_code is not None and return_code != expected:
                    iter_response_condition = True
            elif cond in ('like', 'match'):
                target = response_condition.get('match_to') if 'match_to' in response_condition else response_condition.get('like_to')
                if target and response_string is not None and target in response_string:
                    iter_response_condition = True        
            elif cond in ('not_like', 'no_match'):
                target = response_condition.get('no_match_for') if 'no_match_for' in response_condition else (
                    response_condition.get('no_match_to') if 'no_match_to' in response_condition else response_condition.get('not_like_to')
                )
                if target and response_string is not None and target not in response_string:
                    iter_response_condition = True
            elif cond == 'pass_if_no_lines':
                if response_string == "":
                    iter_response_condition = True
            elif cond == 'pass_if_lines':
                if response_string != "":
                    iter_response_condition = True
            elif cond == 'default_pass':
                pass
            
            if response_condition['control_flag'] == 'required':
                if first_run:
                    condition = condition or iter_response_condition
                    first_run = False
                else:
                    condition = condition and iter_response_condition
            elif response_condition['control_flag'] == 'optional':
                condition = condition or iter_response_condition
        
        return condition
    
    def run(self):
        """Run the complete audit."""
        print(self.log_data['title'], file=self.output_stream)

        # Determine which items to run from all benchmark libraries
        items_to_run = []
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

        print(str(self.no_passed) + "/" + str(len(items_to_run)) + " PASSED", file=self.output_stream)
        
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
        
        # Set overall_pass flag
        self.log_data['overall_pass'] = 1 if self.log_data['summary']['fail_num'] > 0 else 0
        
        # Override overall_pass if fail_on_missing_test is enabled and there are missing items
        if self.fail_on_missing_test and 'sub_list_errors' in self.log_data:
            if self.log_data['sub_list_errors']['missing_num'] > 0:
                self.log_data['overall_pass'] = 1
        
        # Check for unmatched items in run_list
        if self.run_list:
            unmatched_items = [item for item in self.run_list if item not in self.matched_items]
            if unmatched_items:
                self.log_data['sub_list_errors'] = {
                    'missing_num': len(unmatched_items),
                    'missed_list': unmatched_items
                }
        
        # Finalize log data
        end_datetime = datetime.now()
        self.log_data['end_datetime'] = end_datetime.isoformat()
        self.log_data['duration_seconds'] = (end_datetime - self.start_datetime).total_seconds()
    
    def _tokenize_pass_logic(self, pass_logic):
        import re
        token_pattern = re.compile(r'\(|\)|!?[^(\)\s]+')
        tokens = token_pattern.findall(pass_logic)
        if not isinstance(pass_logic, str):
            raise ValueError("pass_logic must be a string")
        if not tokens:
            raise ValueError("pass_logic expression is empty")
        return tokens

    def _evaluate_pass_logic(self, pass_logic, audit_name_values):
        tokens = self._tokenize_pass_logic(pass_logic)
        position = 0

        def parse_expression():
            nonlocal position
            value = parse_and_term()
            while position < len(tokens) and tokens[position] == 'OR':
                position += 1
                rhs = parse_and_term()
                value = value or rhs
            return value

        def parse_and_term():
            nonlocal position
            value = parse_factor()
            while position < len(tokens) and tokens[position] == 'AND':
                position += 1
                rhs = parse_factor()
                value = value and rhs
            return value

        def parse_factor():
            nonlocal position
            if position >= len(tokens):
                raise ValueError("Unexpected end of pass_logic expression")

            token = tokens[position]
            if token == '(':
                position += 1
                value = parse_expression()
                if position >= len(tokens) or tokens[position] != ')':
                    raise ValueError("Unmatched parenthesis in pass_logic expression")
                position += 1
                return value
            position += 1
            inverted = token.startswith('!')
            token_name = token[1:] if inverted else token
            if token_name in ('AND', 'OR'):
                raise ValueError("Invalid pass_logic token '%s'" % token)
            if token_name not in audit_name_values:
                raise ValueError("pass_logic references undefined audit_test_name '%s'" % token_name)
            value = bool(audit_name_values[token_name])
            return not value if inverted else value

        result = parse_expression()
        if position != len(tokens):
            raise ValueError("Unexpected token '%s' in pass_logic expression" % tokens[position])
        return result

    def close(self):
        """Close and write the JSON log file."""
        try:
            # Local imports to avoid relying on globals during interpreter shutdown
            from datetime import datetime as _dt
            import json as _json

            log_file_name = self.log_file_name if self.log_file_name else ("benchmark_results_" + _dt.today().strftime('%Y-%m-%d') + ".json")
            with open(log_file_name, "w") as f:
                _json.dump(self.log_data, f, indent=2)
        except Exception:
            # Swallow all exceptions; during shutdown modules may be partially torn down
            pass
    
    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CIS Benchmark Auditor")
    parser.add_argument('benchmark_file_paths', nargs='+', help='Path(s) to one or more benchmark JSON files')
    parser.add_argument('-o', '--output', help='Use this filename for the JSON log file')
    parser.add_argument('--quiet', action='store_true', help='Suppress human-readable output')
    args = parser.parse_args()
    # Determine output stream for human-readable output.
    _out_stream = None
    if args.quiet:
        _out_stream = open(os.devnull, 'w')
        auditor = CISBenchmarkAuditor(args.benchmark_file_paths, output_stream=_out_stream, log_file_name=args.output)
    else:
        auditor = CISBenchmarkAuditor(args.benchmark_file_paths, log_file_name=args.output)

    try:
        auditor.run()
    finally:
        # Close any opened output stream and always write the regular JSON log file
        try:
            if _out_stream:
                _out_stream.close()
        except Exception:
            pass
        auditor.close()

