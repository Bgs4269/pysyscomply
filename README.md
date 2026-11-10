# pysyscomply

`pysyscomply` is a small Python compliance auditing library. It runs commands and
registered cmdlets described in JSON benchmark files, evaluates their output, and
writes a structured JSON report. Rulesets are separate from the audit engine, so
they can be maintained, reviewed, and distributed independently.

The implementation uses only the Python standard library. The current package
version is 0.4.1. The benchmark definition is described by
[`schema/pysyscomply.schema.json`](schema/pysyscomply.schema.json).

## Requirements

- Python 3.9 or newer
- A POSIX-like system for shell and system cmdlet checks
- `/bin/bash` for shell commands when available

Install from the project root with `python -m pip install .`. The package
provides both an importable `pysyscomply` module and a `pysyscomply` command.

## Command Line

Run one or more benchmark files:

```sh
pysyscomply benchmark.json
pysyscomply benchmark.json additional.json -o report.json
```

You can also run it as a module with `python -m pysyscomply`.

Options:

| Option | Description |
| --- | --- |
| `-o`, `--output FILE` | Write the report to `FILE`. Without this option, the report is written to `benchmark_results_YYYY-MM-DD.json`. |
| `--quiet` | Suppress the human-readable progress output. |
| `--timeout SECONDS` | Maximum duration for each shell command; default is 30 seconds. |
| `--run-list NAME ...` | Run only named benchmark items. |
| `--fail-on-missing` | Return failure when a name supplied to `--run-list` is not found. |

The process exits with `0` when all selected tests pass, `1` when tests fail,
and `2` for configuration or execution errors.

## Python API

The main class is `ComplianceBenchmarkAuditor`. It accepts benchmark paths and
can be used as a context manager:

```python
from pysyscomply import ComplianceBenchmarkAuditor

with ComplianceBenchmarkAuditor(
    ["benchmark.json"],
    log_file_name="report.json",
) as auditor:
    exit_code = auditor.run()
```

`run()` returns `0` for a passing scan and `1` when any test fails. The report
is finalized by `close()`, which is called automatically by the context manager.

## Benchmark JSON

A benchmark is an object with a required `title` and `items` array. Each item
has a required `name` and `audit` array. An audit block contains either a shell
`cmd` or a `cmdlet`, never both, and must include `response_conditions`.

Minimal command benchmark:

```json
{
	"title": "Example benchmark",
	"compiled_by": "Security team",
	"compiled_on": "2026-08-27",
	"items": [
		{
			"name": "SSH configuration exists",
			"labels": ["ssh"],
			"audit": [
				{
					"cmd": "test -f /etc/ssh/sshd_config",
					"response_conditions": [
						{
							"condition": "exitcode",
							"exit_result": 0,
							"control_flag": "required",
							"on": "return_code"
						}
					]
				}
			]
		}
	]
}
```

An audit block may include `audit_test_name`. This name is required for blocks
referenced by the runtime's optional `pass_logic` expression. `pass_logic` supports
`AND`, `OR`, `&&`, `||`, `NOT`, `!`, and parentheses. For example:

```json
"pass_logic": "ssh_running AND !(ssh_disabled OR ssh_missing)"
```

## Response Conditions

Every condition has `condition`, `control_flag`, and `on` fields. The
`control_flag` is `required` or `optional`; `on` is `stdout`, `stderr`, or
`return_code`.

| Condition | Additional field | Behavior |
| --- | --- | --- |
| `like`, `match` | `match_to` or `like_to` | Pass when the literal text occurs in the selected output. |
| `matchregex` | `match_to` | Pass when the regular expression matches the selected output. |
| `not_like` | `not_like_to` | Pass when literal text does not occur. |
| `no_match` | `no_match_for` or `no_match_to` | Pass when literal text does not occur. |
| `exitcode` | `exit_result` | Pass when the process exit code equals the expected integer. |
| `not_exitcode` | `exit_result` | Pass when the process exit code differs from the expected integer. |
| `pass_if_lines` | none | Pass when the selected output is non-empty. |
| `pass_if_no_lines` | none | Pass when the selected output is empty. |
| `default_pass` | none | Always pass. |

Required conditions must all pass. If optional conditions are present, at least
one optional condition must pass.

## Built-in Cmdlets

Cmdlets are selected with `cmdlet_type: "internal"` and return an exit code,
stdout, and stderr tuple. The built-in cmdlets in version 0.4.1 are:

### `service`

Arguments are `[function, service_name]`, where `function` is `isrunning`,
`isenabled`, or `ismasked`. It uses `systemctl` on systems booted with systemd.

### `haspkg` and `missingpkg`

Arguments are one or more package names. `haspkg` succeeds only when every
package is installed; `missingpkg` succeeds only when every package is absent.
RPM-based systems use `rpm -q`; Debian-style systems use `dpkg -l`.

```json
{
	"cmdlet": {
		"cmdlet_name": "haspkg",
		"cmdlet_type": "internal",
		"cmdlet_args": ["openssl", "curl"]
	},
	"response_conditions": [
		{
			"condition": "exitcode",
			"exit_result": 0,
			"control_flag": "required",
			"on": "return_code"
		}
	]
}
```

### `csvfilter`

Arguments are `[path, delimiter, field_number]` or
`[path, delimiter, field_number, return_type, filter]`. Field numbering starts
at one. Without the optional pair, the selected field is returned for every
record. `return_type` is `field` or `line`.

The filter prefix selects its strict format:

- `r<regex>`: regular expression matched against the selected field.
- `m<expression>`: numeric comparison such as `m>10` or `m<=$len`.
- `lempty` or `lnon-empty`: test whether the selected field is empty.

In mathematical filters, `$len` is the selected field's character length and
`$num` is its numeric value. Non-numeric fields fail mathematical filters.
Missing files, inaccessible files, malformed CSV, invalid fields, and invalid
filters fail the cmdlet.

### `ismount` and `bootmounted`

`ismount` takes a filesystem path and succeeds when it is a mount point.
`bootmounted` takes a mount point and checks whether its systemd mount unit is
enabled at boot.

## JSON Schema

Use [`schema/pysyscomply.schema.json`](schema/pysyscomply.schema.json) with a
JSON Schema Draft 7 validator or editor integration. It defines:

- Required top-level `title` and `items` fields.
- Item names, labels, details, and audit blocks. `pass_logic` is supported by the
	runtime but is not currently declared as a schema property.
- Mutual exclusivity of `cmd` and `cmdlet`.
- Cmdlet fields and the `internal`/`external` type enum.
- Response condition, output target, and control flag enums.
- `cmdlet_args` as an array of strings and `exit_result` as an integer.

The schema validates benchmark structure and types. Runtime checks additionally
validate registered cmdlet names, command execution, regular expressions, CSV
files, and filter expressions.

## Reports

The report is a JSON object containing benchmark metadata, timestamps, duration,
test library information, and a `findings` array. Each finding records its
score (`0` pass, `1` fail), output, errors, labels, and individual audit results.
The top-level `summary` includes test and failure counts, while `overall_pass`
is `0` for a passing scan and `1` otherwise.

## Repository Files

| Path | Purpose |
| --- | --- |
| `src/pysyscomply/` | Importable library and CLI. |
| `pysyscomply.py` | Compatibility launcher for the 0.4.1 package. |
| `pyproject.toml` | Package metadata and build configuration. |
| `.github/workflows/` | Continuous integration and tagged-release workflows. |
| `schema/pysyscomply.schema.json` | JSON Schema Draft 7 benchmark schema. |
| `testbooks/` | Example benchmark files for cmdlets and system checks. |
| `CMDLET_FEATURE.md` | Additional cmdlet architecture notes. |
| `SECURITY.md` | Security considerations. |

## License

This project is licensed under the GNU General Public License v3.0. See
[`LICENSE`](LICENSE).

## Build and release

Build distributions locally with:

```sh
python -m pip install build
python -m build
```

The GitHub Actions release workflow builds source and wheel distributions and
attaches them to a GitHub Release when a `v*` tag is pushed. Keep the version in
`pyproject.toml` aligned with the tag (for example, `0.4.1` and `v0.4.1`).
