# Custom Rules

How to write your own audit rules for `mb audit`.

## Rule file format

Rules are simple `key=value` files in `rules/`. The bundled rule files are:

- `cis-ssh.rules` — expected SSH daemon configuration
- `cis-firewall.rules` — expected firewall configuration
- `cis-kernel.rules` — expected sysctl parameters
- `cis-docker.rules` — expected Docker daemon configuration

Edit these in place to match your environment. For example, if your SSH port is `2200`:

```bash
# rules/cis-ssh.rules
Port=2200
```

The `cis-benchmark` module reads expected values from these files at runtime.

## Adding custom checks

Copy the example template to create your own rule set:

```bash
cp rules/custom.rules.example rules/custom.rules
```

Then edit `rules/custom.rules`:

```
# custom.rules
MyServiceRunning=yes
DataDirPerms=750
CustomBannerSet=yes
```

For each key, define a check function in a new module file (or extend `modules/cis-benchmark.sh`):

```bash
check_custom_myservicerunning() {
    if systemctl is-active --quiet my-service; then
        mb_emit_finding PASS info "custom" "myservice_running" \
            "my-service is running" ""
    else
        mb_emit_finding FAIL high "custom" "myservice_running" \
            "my-service is not running" \
            "sudo systemctl start my-service"
    fi
}
```

The function name must be `check_custom_<key>` (lowercase, matching the rule key). `mb audit run` discovers all `check_*` functions automatically.

## Finding format

Every check emits a finding via `mb_emit_finding`:

```bash
mb_emit_finding <status> <severity> <module> <check> <message> <fix_command>
```

- **status** — `PASS`, `FAIL`, or `WARN`
- **severity** — `info`, `low`, `medium`, `high`, `critical`
- **module** — a short label for grouping in the report
- **check** — the specific check name
- **message** — human-readable description
- **fix_command** — a ready-to-run remediation command (empty for PASS)

## Tips

- **Keep rules version-controlled.** Commit your `rules/` directory so changes are auditable.
- **Test with --dry-run.** After changing rules, run `sudo ./mb audit fix --dry-run` to preview what would change.
- **Use WARN for soft checks.** Use `WARN` when something is suboptimal but not a security hole; reserve `FAIL` for real issues.
- **Always include a fix command.** The value of this tool is that every finding is actionable. If you can't suggest a fix, reconsider whether the check is useful.
