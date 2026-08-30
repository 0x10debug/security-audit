# auditd Rules Audit

The `auditd` audit module performs a read-only assessment of auditd (Linux
Audit Daemon) configuration and rule coverage based on **CIS Benchmark**
recommendations.

## Usage

```bash
# Run auditd audit via mb CLI
mb audit run --module auditd

# Run directly
./modules/auditd-rules-audit.sh
```

## What It Checks

### Service Status (4 checks)

| Check | Description |
|---|---|
| AUDITD-001 | auditd installed |
| AUDITD-002 | auditd service running |
| AUDITD-003 | auditd enabled on boot |
| AUDITD-004 | Kernel audit enabled |

### Login & Authentication (8 checks)

| Check | Description |
|---|---|
| AUDITD-101 | Login events audited (faillog/lastlog) |
| AUDITD-102 | Session modification audited (utmp/wtmp) |
| AUDITD-103 | Group file modifications audited |
| AUDITD-104 | Password file modifications audited |
| AUDITD-105 | Shadow file modifications audited |
| AUDITD-106 | Gshadow file modifications audited |
| AUDITD-107 | sudoers file modifications audited |
| AUDITD-108 | sudoers.d directory modifications audited |

### Privilege Escalation (6 checks)

| Check | Description |
|---|---|
| AUDITD-201 | setuid/setgid binary execution audited |
| AUDITD-202 | File permission change syscalls audited |
| AUDITD-203 | User/group management commands audited |
| AUDITD-204 | su command usage audited |
| AUDITD-205 | sudo command usage audited |
| AUDITD-206 | passwd command usage audited |

### Network & System Config (5 checks)

| Check | Description |
|---|---|
| AUDITD-301 | Network environment modifications audited |
| AUDITD-302 | MAC policy (AppArmor/SELinux) modifications audited |
| AUDITD-303 | Kernel module loading audited |
| AUDITD-304 | System time modifications audited |
| AUDITD-305 | Cron configuration modifications audited |

### Log Configuration (7 checks)

| Check | Description |
|---|---|
| AUDITD-401 | Audit log file configured |
| AUDITD-402 | Max log file size (8MB+) |
| AUDITD-403 | Log rotation action (rotate/keep_logs) |
| AUDITD-404 | Number of rotated logs (5+) |
| AUDITD-405 | Disk full action (halt/single) |
| AUDITD-406 | Space left threshold (50MB+) |
| AUDITD-407 | Remote audit logging (optional) |

### Rule File Checks (5 checks)

| Check | Description |
|---|---|
| AUDITD-501 | Audit rule files exist |
| AUDITD-502 | Rules are immutable (-e 2) |
| AUDITD-503 | Buffer size configured |
| AUDITD-504 | Failure mode (-f 2) |
| AUDITD-505 | Comprehensive rule coverage (20+ rules) |

## Reports

- **TXT**: `/var/log/auditd-audit/auditd-audit-latest.txt`
- **JSON**: `/var/log/auditd-audit/auditd-audit-latest.json`

## Requirements

- `auditd` and `auditctl` installed
- Root access to read auditd configuration and rules

## Related

- [CIS Benchmark for Linux](https://www.cisecurity.org/benchmark/linux)
- `vps-bootstrap` auditd module — installs and configures auditd rules
- `vps-security-enhancement-scripts` — C3 audit menu includes auditd
