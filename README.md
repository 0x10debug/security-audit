# VPS Security Audit — CIS Benchmark, Drift Detection & Auto-Fix

A self-hosted VPS security audit tool that checks your server against CIS Benchmark controls, analyzes auth logs for suspicious activity, scans running Docker containers for known CVEs, and detects configuration drift from a trusted baseline. Every finding ships with a ready-to-run fix command — you go from "problem found" to "problem fixed" in one step.

Built for operators who run their own Linux VPS and want continuous, automated security hardening without a commercial SIEM. Pairs naturally with [0x10debug/vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) (initial server hardening) and [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack) (metrics & alerting). Pure Bash, no runtime dependencies beyond standard system tools, and every script is idempotent so you can re-run safely.

---

## Audit Modules

| Module | What it checks | Fix command included |
|---|---|---|
| `cis-benchmark` | SSH hardening, firewall defaults, kernel sysctl params, Docker daemon config, auto-updates | Yes |
| `lynis` | Full system hardening scan via Lynis (auto-installs if missing) | Lynis suggestions |
| `log-audit` | Failed SSH logins, successful logins from new IPs, sudo events, user add/remove, crontab changes, file integrity mtime | Yes |
| `container-scan` | Trivy vulnerability scan of all running Docker images, grouped by Critical/High/Medium/Low | Yes |
| `drift` | Compares current SSH, firewall, kernel, Docker state against a baseline snapshot | Yes |

---

## Quick Start

```bash
# Clone
git clone https://github.com/0x10debug/security-audit.git
cd security-audit

# Run a full audit (generates HTML + JSON reports)
sudo ./mb audit run

# See the summary of the last run
./mb audit status

# Open the latest HTML report
./mb audit report

# Preview fixes without changing anything
sudo ./mb audit fix --dry-run

# Apply all fixes
sudo ./mb audit fix
```

Reports are saved to `/var/log/mb-audit/reports/`:
- `audit-latest.html` — human-readable report (symlink to the newest run)
- `audit-latest.json` — machine-readable report for integration

---

## Usage

### Run specific modules only

```bash
sudo ./mb audit run --module cis-benchmark,log-audit
```

### Create a baseline snapshot

Capture the current trusted state so you can detect drift later:

```bash
sudo ./mb audit baseline
```

The baseline is saved to `/etc/mb-backup/baseline.yaml` (aligned with vps-bootstrap).

### Check for configuration drift

```bash
sudo ./mb audit drift
```

### Schedule a daily audit (cron)

```bash
sudo ./mb audit schedule --daily        # default 03:15
sudo ./mb audit schedule --daily --hour 4 --minute 30
sudo ./mb audit schedule --remove
sudo ./mb audit schedule                # show current status
```

### Update the tool

```bash
sudo ./mb audit update      # git pull
```

---

## Custom Rules

Rules live in `rules/*.rules` as simple `key=value` files. Edit them to match your environment:

```bash
# rules/cis-ssh.rules
Port=2222
PermitRootLogin=no
PasswordAuthentication=no
```

See [`docs/custom-rules.md`](docs/custom-rules.md) for writing your own checks, and copy `rules/custom.rules.example` to `rules/custom.rules` to get started.

---

## FAQ

**1. Does this require an internet connection?**
Only for the first run if Lynis or Trivy need to be installed. After that, audits run fully offline. `mb audit update` (git pull) needs connectivity.

**2. Is it safe to run `mb audit fix` on a production server?**
Always run with `--dry-run` first. The fix scripts back up every file they touch (`.mb.bak.<timestamp>`) and only change directives that differ from the expected value. SSH restarts are handled automatically.

**3. Which distros are supported?**
Any Debian/Ubuntu or RHEL-family (CentOS, Rocky, Alma, Fedora) Linux with Bash 4+. Firewall checks prefer ufw and fall back to iptables.

**4. How is this different from just running Lynis?**
Lynis is one module. This tool also does log analysis, container CVE scanning, baseline drift detection, and — crucially — emits a concrete fix command for every finding so you can remediate in one step instead of reading a report and figuring out the commands yourself.

**5. Where is the baseline stored and why?**
At `/etc/mb-backup/baseline.yaml`, the same location vps-bootstrap writes its backups. This keeps all mb-suite state in one predictable place that survives package upgrades.

---

## Documentation

- [Audit Guide](docs/audit-guide.md) — how to run audits and interpret reports
- [CIS Benchmark](docs/cis-benchmark.md) — what controls are checked and why
- [Drift Detection](docs/drift-detection.md) — how drift detection works and why it matters
- [Custom Rules](docs/custom-rules.md) — how to write your own audit rules

---

## Related Repositories

- [0x10debug/vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) — initial VPS hardening & setup
- [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack) — monitoring & alerting stack

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 [0x10debug](https://github.com/0x10debug).
