# Cmdlet Feature Documentation

## Overview

The cmdlet feature extends pysyscomply with a new method for executing audit tests beyond traditional shell commands. Cmdlets are predefined functions that can be either **internal** (defined within pysyscomply) or **external** (from dynamic sources).

## Key Rules

1. **Mutually Exclusive**: Each audit block must have **either** `cmd` OR `cmdlet`, but NOT both.
2. **At Least One Required**: Each audit block must have at least one of `cmd` or `cmdlet`.
3. **Required Fields**: If using `cmdlet`, all three fields must be present: `cmdlet_name`, `cmdlet_type`, and `cmdlet_args`.

## Cmdlet Structure

```json
{
  "cmdlet": {
    "cmdlet_name": "string",      // Name of the registered cmdlet
    "cmdlet_type": "string",      // "internal" or "external"
    "cmdlet_args": ["array"]      // Arguments passed to the cmdlet function
  },
  "response_conditions": [...]    // Same format as cmd blocks
}
```

## Built-in Cmdlets

### `service` Cmdlet

**Purpose**: Check systemd service status on systemd-based systems.

**Type**: internal

**Arguments**:
- `arg[0]`: Function name - one of:
  - `"isrunning"` - Check if service is currently running
  - `"isenabled"` - Check if service is enabled to start on boot
  - `"ismasked"` - Check if service is masked
- `arg[1]`: Service name (e.g., `"sshd"`, `"systemd-journald"`)

**Behavior**:
- **On systemd-based systems**: 
  - `isrunning`: Executes `systemctl is-active <service>` (exit code 0 if active)
  - `isenabled`: Executes `systemctl is-enabled <service>` (exit code 0 if enabled)
  - `ismasked`: Executes `systemctl is-enabled <service>` and returns exit code 0 if output is "masked", exit code 1 otherwise
- **On non-systemd systems**: Returns exit code 0 with stdout `"true"`

**Examples**:

Check if service is running:
```json
{
  "cmdlet": {
    "cmdlet_name": "service",
    "cmdlet_type": "internal",
    "cmdlet_args": ["isrunning", "sshd"]
  },
  "audit_test_name": "sshd_running",
  "response_conditions": [
    {
      "condition": "match",
      "match_to": "active",
      "control_flag": "required",
      "on": "stdout"
    }
  ]
}
```

Check if service is enabled:
```json
{
  "cmdlet": {
    "cmdlet_name": "service",
    "cmdlet_type": "internal",
    "cmdlet_args": ["isenabled", "sshd"]
  },
  "audit_test_name": "sshd_enabled",
  "response_conditions": [
    {
      "condition": "match",
      "match_to": "enabled",
      "control_flag": "required",
      "on": "stdout"
    }
  ]
}
```

Check if service is NOT masked:
```json
{
  "cmdlet": {
    "cmdlet_name": "service",
    "cmdlet_type": "internal",
    "cmdlet_args": ["ismasked", "sshd"]
  },
  "audit_test_name": "sshd_not_masked",
  "response_conditions": [
    {
      "condition": "exitcode",
      "exit_result": 1,
      "control_flag": "required",
      "on": "return_code"
    }
  ]
}
```

## Extending with Custom Cmdlets

### `ismount` Cmdlet

**Purpose**: Check whether a path is a dedicated mount point.

**Type**: internal

**Arguments**:
- `arg[0]`: Path to check

**Behavior**:
- Returns exit code 0 with stdout containing `true` followed by the matching `/proc/mounts` line when the path is a direct mount point.
- Returns exit code 1 when the path is not a mount point or does not exist.

Example:
```json
{
  "cmdlet": {
    "cmdlet_name": "ismount",
    "cmdlet_type": "internal",
    "cmdlet_args": ["/var"]
  }
}
```

### `bootmounted` Cmdlet

**Purpose**: Check whether the systemd mount unit for a filesystem path is enabled at boot.

**Type**: internal

**Arguments**:
- `arg[0]`: Filesystem mount point path

**Behavior**:
- Converts the path to its systemd mount unit name with `systemd-escape`.
- Executes `systemctl is-enabled <mount-unit>`.
- Returns success only when the command succeeds and its output is not `masked` or `disabled`.

Example:
```json
{
  "cmdlet": {
    "cmdlet_name": "bootmounted",
    "cmdlet_type": "internal",
    "cmdlet_args": ["/var"]
  }
}
```

To add a new cmdlet:

1. **Define the function** in pysyscomply-v0.3.0.py (before the `CMDLET_REGISTRY` definition):
   ```python
   def _cmdlet_myfunction(args):
       """Docstring describing the cmdlet."""
       # Process args as a list
       # Return tuple: (exit_code, stdout, stderr)
       return (0, "output", "")
   ```

2. **Register in CMDLET_REGISTRY**:
   ```python
   CMDLET_REGISTRY = {
       'service': ('internal', _cmdlet_service),
       'myfunction': ('internal', _cmdlet_myfunction),
   }
   ```

3. **Use in benchmark**:
   ```json
   {
     "cmdlet": {
       "cmdlet_name": "myfunction",
       "cmdlet_type": "internal",
       "cmdlet_args": ["arg1", "arg2"]
     }
   }
   ```

## Response Conditions

Cmdlets use the same response condition system as cmd blocks:

- **on**: Can be `"stdout"`, `"stderr"`, or `"return_code"`
- **condition**: All existing conditions work:
  - `match`, `like` (search for string)
  - `matchregex` (search for a regular expression)
  - `no_match`, `not_like` (string should not exist)
  - `exitcode`, `not_exitcode` (check exit code)
  - `pass_if_lines`, `pass_if_no_lines` (check output presence)
  - `default_pass` (always passes)

## JSON Schema Updates

The benchmark schema now supports:

- Audit blocks with `cmdlet` instead of `cmd`
- `cmdlet_type` enum: `["internal", "external"]`
- `cmdlet_args` as a string array
- Enhanced `condition` enum includes: `match`, `matchregex`, `no_match`, `exitcode`, `not_exitcode`
- Enhanced `on` enum includes: `return_code`

## Error Handling

Validation errors are captured in the audit results:

- Both `cmd` and `cmdlet` present: `"audit block cannot have both cmd and cmdlet"`
- Neither present: `"audit block must have either cmd or cmdlet"`
- Missing required cmdlet field: `"cmdlet block missing <field>"`
- Invalid cmdlet_type: `"invalid cmdlet_type: <value>. Must be \"internal\" or \"external\""`
- Cmdlet not found: `"cmdlet \"<name>\" not found in registry"`
- Type mismatch: `"cmdlet \"<name>\" type mismatch: expected <type>, got <actual>"`

## Backward Compatibility

All existing benchmarks using `cmd` blocks continue to work without modification. The feature is fully backward compatible.

## Testing

Test files are provided:
- `testbooks/cmdlet-test.json`: Basic functionality tests
- `testbooks/cmdlet-validation-test.json`: Validation rule tests
