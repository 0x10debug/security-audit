# VPS Security Audit — CIS Benchmark, Drift Detection and Auto-Remediation

A self-hosted VPS security audit tool: checks servers against CIS Benchmark controls, analyzes auth logs for suspicious activity, scans running Docker containers for known CVEs, and detects configuration drift against a trusted baseline. Every finding comes with a directly executable remediation command — from "discovering a problem" to "fixing it" takes just one step.

Designed for operators running self-built Linux VPSes who want continuous automated security hardening without introducing a commercial SIEM. Used alongside [0x10debug/vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) (initial server hardening) and [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack) (monitoring and alerting). Pure Bash implementation with no runtime dependencies beyond standard system tools; all scripts are idempotent and repeatable.

---

## Audit Modules

| Module | What it checks | Includes remediation commands |
|---|---|---|
| `cis-benchmark` | SSH hardening, firewall default policies, kernel sysctl parameters, Docker daemon configuration, automatic updates | Yes |
| `cis-v14` | CIS Benchmark v14.0 checks (same as cis-benchmark, an alias for explicitly running v14.0) | Yes |
| `lynis` | Full system hardening scan via Lynis (auto-installs if missing) | Lynis suggestions |
| `lynis-score` | Lynis CIS compliance scoring — runs Lynis, maps results to CIS v14.0 controls, generates a 0–100 compliance score and a chapter-grouped report (TXT + JSON) | Yes |
| `log-audit` | SSH failed logins, successful logins from new IPs, sudo events, user add/remove, crontab modifications, sensitive file mtime integrity | Yes |
| `container-scan` | Scans all running Docker images with Trivy, grouped by Critical/High/Medium/Low | Yes |
| `crowdsec` | CrowdSec deployment and security configuration audit — installation status, acquisition sources, scenarios, bouncers, decisions/alerts, threat intelligence, API exposure, config file permissions (TXT + JSON) | Yes |
| `docker` | Docker security audit (CIS Docker Benchmark v1.6.0) — daemon configuration, container security posture (privileged, cap, namespace sharing, root user, readonly rootfs, healthcheck, resource limits, sensitive mounts), image security (tag pinning, content trust, dangling images), Compose security (TXT + JSON) | Yes |
| `drift` | Compares current SSH, firewall, kernel, and Docker state against a baseline snapshot | Yes |

---

## Quick Start

```bash
# Clone
git clone https://github.com/0x10debug/security-audit.git
cd security-audit

# Run a full audit (generates HTML + JSON reports)
sudo ./mb audit run

# View summary of the last run
./mb audit status

# Open the latest HTML report
./mb audit report

# Preview remediation without applying changes
sudo ./mb audit fix --dry-run

# Apply all fixes
sudo ./mb audit fix
```

Reports are saved in `/var/log/mb-audit/reports/`:
- `audit-latest.html` — human-readable report (symlink pointing to the latest run)
- `audit-latest.json` — machine-readable report for integration

---

## Usage

### Run only specific modules

```bash
sudo ./mb audit run --module cis-benchmark,log-audit
```

### Run CIS v14.0 compliance scoring

```bash
# Run the Lynis-based CIS v14.0 compliance scoring module
sudo ./mb audit run --module lynis-score

# Scoring reports are saved to:
#   /var/log/mb-audit/reports/cis-score-latest.txt
#   /var/log/mb-audit/reports/cis-score-latest.json
```

The scoring module runs Lynis, maps results to the full CIS Benchmark v14.0 control set
(6 chapters, 300+ controls), generates a weighted compliance score (0–100) and a chapter-grouped report.
For the complete control→remediation script mapping, see
[`docs/cis-v14.0-mapping.md`](docs/cis-v14.0-mapping.md).

### Apply CIS v14.0 remediation scripts

```bash
# SSH hardening (CIS v14.0 Section 5.1)
sudo fixes/cis-ssh-hardening.sh --all

# Kernel and network hardening (CIS v14.0 Sections 3.1/3.2/1.6)
sudo fixes/cis-kernel-hardening.sh --all

# Firewall configuration (CIS v14.0 Section 3.4)
sudo fixes/cis-firewall-setup.sh --all

# File permissions and system maintenance (CIS v14.0 Sections 1.1/6.1/6.2)
sudo fixes/cis-permissions-fix.sh --all

# Preview remediation without applying changes
sudo fixes/cis-ssh-hardening.sh --all --dry-run
```

### Create a baseline snapshot

Capture the current trusted state so you can detect drift later:

```bash
sudo ./mb audit baseline
```

The baseline is saved to `/etc/mb-backup/baseline.yaml` (aligned with vps-bootstrap).

### Check configuration drift

```bash
sudo ./mb audit drift
```

### Set up daily scheduled audit (cron)

```bash
sudo ./mb audit schedule --daily        # default 03:15
sudo ./mb audit schedule --daily --hour 4 --minute 30
sudo ./mb audit schedule --remove
sudo ./mb audit schedule                # view current status
```

### Update the tool

```bash
sudo ./mb audit update      # git pull
```

---

## Custom Rules

Rule files are located in `rules/*.rules` and use a simple `key=value` format. Modify them for your environment:

```bash
# rules/cis-ssh.rules
Port=2222
PermitRootLogin=no
PasswordAuthentication=no
```

For writing custom checks, see [`docs/custom-rules.md`](docs/custom-rules.md); copy `rules/custom.rules.example` to `rules/custom.rules` to get started.

---

## FAQ

**1. Does it require an internet connection?**
Only on first run (if Lynis or Trivy need to be installed). After that, audits can run fully offline. `mb audit update` (git pull) requires connectivity.

**2. Is it safe to run `mb audit fix` on a production server?**
Always preview with `--dry-run` first. Remediation scripts back up every modified file (`.mb.bak.<timestamp>`) and only change directives that differ from the expected value. SSH restarts are handled automatically.

**3. Which distributions are supported?**
Any Debian/Ubuntu or RHEL-family (CentOS, Rocky, Alma, Fedora) Linux with Bash 4+. Firewall checks prefer ufw, falling back to iptables.

**4. How is this different from running Lynis directly?**
Lynis is just one module. This tool also does log analysis, container CVE scanning, and baseline drift detection — and crucially, outputs specific remediation commands for each finding, so you can fix issues in one step instead of reading a report and then looking up commands yourself.

**5. Where is the baseline stored, and why?**
In `/etc/mb-backup/baseline.yaml`, consistent with vps-bootstrap's backup directory. This keeps all mb suite state in one predictable location that persists across package upgrades.

---

## Documentation

- [Audit Guide](docs/audit-guide.md) — How to run audits and interpret reports
- [CIS Benchmark](docs/cis-benchmark.md) — Which controls are checked and why
- [CIS v14.0 Mapping](docs/cis-v14.0-mapping.md) — Complete CIS v14.0 control→audit rule→remediation script mapping and scoring methodology
- [Drift Detection](docs/drift-detection.md) — How drift detection works and why it matters
- [CrowdSec Audit](docs/crowdsec-audit.md) — CrowdSec deployment and security configuration audit
- [Docker Audit](docs/docker-audit.md) — Docker security audit (CIS Docker Benchmark v1.6.0)
- [Custom Rules](docs/custom-rules.md) — How to write custom audit rules

---

## Related Repositories

- [0x10debug/vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) — VPS initial hardening and configuration
- [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack) — Monitoring and alerting stack

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 [0x10debug](https://github.com/0x10debug).
