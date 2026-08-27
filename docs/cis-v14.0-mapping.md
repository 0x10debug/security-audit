# CIS Benchmark v14.0 Control Mapping

This document maps the CIS Benchmark v14.0 controls to the audit rules, fix scripts, and scoring logic in this repository. It is the reference for understanding what `mb audit run --module lynis-score` checks, how the compliance score is computed, and how to remediate each finding.

---

## Overview

The CIS Benchmark v14.0 for Ubuntu/Debian Linux is organized into six chapters:

| Chapter | Title | Rule file |
|---|---|---|
| 1 | Initial Setup | `rules/cis-v14.0/1-initial-setup.rules` |
| 2 | Services | `rules/cis-v14.0/2-services.rules` |
| 3 | Network Parameters | `rules/cis-v14.0/3-network.rules` |
| 4 | Logging and Auditing | `rules/cis-v14.0/4-logging.rules` |
| 5 | Access, Authentication and Authorization | `rules/cis-v14.0/5-access.rules` |
| 6 | System Maintenance | `rules/cis-v14.0/6-system-maintenance.rules` |

Each rule file uses a pipe-delimited format:

```
<control_id>|<key>|<expected>|<severity>|<fix_script>
```

- **control_id** — the CIS v14.0 control number (e.g. `5.1.1`)
- **key** — the audit check key used by `modules/lynis-scoring.sh`
- **expected** — the expected value (string comparison)
- **severity** — `critical` | `high` | `medium` | `low` | `info`
- **fix_script** — the remediation script (empty = manual remediation required)

---

## Compliance Scoring

The scoring module (`modules/lynis-scoring.sh`) computes a weighted compliance score:

### Severity Weights

| Severity | Weight |
|---|---|
| critical | 4 |
| high | 3 |
| medium | 2 |
| low | 1 |
| info | 0 |

### Score Formula

```
chapter_score = (satisfied_weight / applicable_weight) × 100
overall_score = Σ(chapter_score × applicable_controls) / Σ(applicable_controls × 100)
```

- **satisfied** — the control passes (Lynis result is OK, or local sysctl/sshd check matches)
- **unsatisfied** — the control fails (Lynis warning/suggestion, or local check mismatches)
- **not_applicable** — the control cannot be verified on this system (excluded from denominator)

### Evaluation Heuristics

The scoring module uses three heuristics to determine control status:

1. **Lynis control mapping** — CIS control keys are mapped to Lynis control ID prefixes (e.g. `ssh_*` → `SSH-*`, `net.ipv4_*` → `KRNL-*`). If a matching Lynis control has result `OK`/`DONE`, the control is satisfied; `WARNING`/`SUGGESTION` → unsatisfied.

2. **Local sysctl verification** — for `net.ipv4.*`, `net.ipv6.*`, `kernel.*`, and `fs.*` keys, the module reads the value via `sysctl -n` and compares it to the expected value.

3. **Service presence check** — for controls expecting `not_installed`/`disabled`/`absent`, the module checks if the service binary exists and (if systemd is available) whether the service is enabled.

Controls that cannot be evaluated by any heuristic are marked `not_applicable` and excluded from the score.

### Output

- **TXT report**: `/var/log/mb-audit/reports/cis-score-latest.txt`
- **JSON report**: `/var/log/mb-audit/reports/cis-score-latest.json`
- **Pipe-delimited findings**: consumed by the standard report generator

---

## Lynis Hardening Index Correspondence

Lynis produces its own hardening index (0–100) based on all checks it runs. The CIS compliance score in this repo is narrower in scope — it only evaluates the CIS v14.0 control set, not all Lynis checks. The relationship:

| Lynis Hardening Index | CIS Compliance Score | Interpretation |
|---|---|---|
| 90–100 | 90–100 | Well-hardened, CIS-compliant |
| 70–89 | 70–89 | Good baseline, some gaps |
| 50–69 | 50–69 | Moderate risk, several controls failing |
| < 50 | < 50 | High risk, significant remediation needed |

The Lynis hardening index is included in the CIS score report for cross-reference when available.

---

## Control → Audit Rule → Fix Script Mapping

### Chapter 1 — Initial Setup

| Control | Key | Expected | Fix Script |
|---|---|---|---|
| 1.1.1.1 | fs_cramfs | removed | `fixes/cis-permissions-fix.sh` |
| 1.1.2 | fs_tmp_mounted | yes | `fixes/cis-permissions-fix.sh` |
| 1.1.19 | fs_sticky_bit | yes | `fixes/cis-permissions-fix.sh --sticky-bit` |
| 1.1.20 | fs_var_perm | 755 | `fixes/cis-permissions-fix.sh --var-perm` |
| 1.1.21 | fs_var_log_perm | 750 | `fixes/cis-permissions-fix.sh --var-log-perm` |
| 1.1.30 | fs_shadow_file_perm | 640 | `fixes/cis-permissions-fix.sh --shadow-perm` |
| 1.4.1 | auditd_installed | yes | `fixes/cis-permissions-fix.sh --install-auditd` |
| 1.6.2 | core_dumps_disabled | yes | `fixes/cis-permissions-fix.sh --disable-core-dumps` |
| 1.6.3 | aslr_enabled | yes | `fixes/cis-kernel-hardening.sh --aslr` |
| 1.8.1 | motd_configured | yes | `fixes/cis-permissions-fix.sh --motd-banner` |
| 1.9.1 | time_sync_installed | yes | `fixes/cis-permissions-fix.sh --install-timesync` |
| 1.10.3 | cron_perm | 600 | `fixes/cis-permissions-fix.sh --cron-perm` |
| 1.11.2 | sudoers_use_pty | yes | `fixes/cis-permissions-fix.sh --sudo-pty` |
| 1.11.5 | sudoers_perm | 440 | `fixes/cis-permissions-fix.sh --sudoers-perm` |

### Chapter 2 — Services

| Control | Key | Expected | Fix Script |
|---|---|---|---|
| 2.1.1 | inetd_installed | not_installed | `fixes/cis-permissions-fix.sh --remove-inetd` |
| 2.2.3 | avahi_daemon | disabled | `fixes/cis-permissions-fix.sh --disable-avahi` |
| 2.2.4 | cups | disabled | `fixes/cis-permissions-fix.sh --disable-cups` |
| 2.2.9 | nfs_server | disabled | `fixes/cis-permissions-fix.sh --disable-nfs` |
| 2.2.11 | dns_server | disabled | `fixes/cis-permissions-fix.sh --disable-dns` |
| 2.4.1 | ntp_installed | yes | `fixes/cis-permissions-fix.sh --install-ntp` |

### Chapter 3 — Network Parameters

| Control | Key | Expected | Fix Script |
|---|---|---|---|
| 3.1.1 | net_ipv4_ip_forward | 0 | `fixes/cis-kernel-hardening.sh --ip-forward` |
| 3.1.3 | net_ipv4_conf_all_send_redirects | 0 | `fixes/cis-kernel-hardening.sh --send-redirects` |
| 3.1.5 | net_ipv4_conf_all_accept_redirects | 0 | `fixes/cis-kernel-hardening.sh --accept-redirects` |
| 3.1.11 | net_ipv4_conf_all_accept_source_route | 0 | `fixes/cis-kernel-hardening.sh --source-route` |
| 3.1.13 | net_ipv4_conf_all_rp_filter | 1 | `fixes/cis-kernel-hardening.sh --rp-filter` |
| 3.1.15 | net_ipv4_icmp_echo_ignore_broadcasts | 1 | `fixes/cis-kernel-hardening.sh --icmp-broadcast` |
| 3.1.17 | net_ipv4_tcp_syncookies | 1 | `fixes/cis-kernel-hardening.sh --syncookies` |
| 3.2.1 | net_ipv6_conf_all_disable_ipv6 | 0 | `fixes/cis-kernel-hardening.sh --ipv6-disable` |
| 3.4.1 | firewall_installed | yes | `fixes/cis-firewall-setup.sh --install` |
| 3.4.2 | firewall_enabled | yes | `fixes/cis-firewall-setup.sh --enable` |
| 3.4.3 | firewall_default_incoming | deny | `fixes/cis-firewall-setup.sh --default-incoming` |
| 3.4.7 | firewall_allowed_ports | 22,80,443 | `fixes/cis-firewall-setup.sh --allowed-ports` |
| 3.4.8 | firewall_rate_limit_ssh | yes | `fixes/cis-firewall-setup.sh --rate-limit-ssh` |

### Chapter 4 — Logging and Auditing

| Control | Key | Expected | Fix Script |
|---|---|---|---|
| 4.1.1 | rsyslog_installed | yes | `fixes/cis-permissions-fix.sh --install-rsyslog` |
| 4.1.2 | rsyslog_enabled | yes | `fixes/cis-permissions-fix.sh --enable-rsyslog` |
| 4.4.1 | auditd_installed | yes | `fixes/cis-permissions-fix.sh --install-auditd` |
| 4.4.2 | auditd_enabled | yes | `fixes/cis-permissions-fix.sh --enable-auditd` |
| 4.4.5 | auditd_log_perm | 600 | `fixes/cis-permissions-fix.sh --auditd-log-perm` |
| 4.5.1 | audit_date_time | yes | `fixes/cis-permissions-fix.sh --audit-date-time` |
| 4.6.1 | logrotate_installed | yes | `fixes/cis-permissions-fix.sh --install-logrotate` |

### Chapter 5 — Access, Authentication and Authorization

| Control | Key | Expected | Fix Script |
|---|---|---|---|
| 5.1.1 | ssh_permitrootlogin | no | `fixes/cis-ssh-hardening.sh --permit-root-login` |
| 5.1.2 | ssh_permitemptypasswords | no | `fixes/cis-ssh-hardening.sh --permit-empty-passwords` |
| 5.1.6 | ssh_maxauthtries | 3 | `fixes/cis-ssh-hardening.sh --max-auth-tries` |
| 5.1.8 | ssh_ciphers | strong | `fixes/cis-ssh-hardening.sh --ciphers` |
| 5.1.9 | ssh_macs | strong | `fixes/cis-ssh-hardening.sh --macs` |
| 5.1.10 | ssh_kexalgorithms | strong | `fixes/cis-ssh-hardening.sh --kex-algorithms` |
| 5.1.22 | ssh_passwordauthentication | no | `fixes/cis-ssh-hardening.sh --password-auth` |
| 5.1.27 | ssh_port | 2222 | `fixes/cis-ssh-hardening.sh --port` |
| 5.2.6 | pam_faillock | yes | `fixes/cis-permissions-fix.sh --pam-faillock` |
| 5.3.1 | pass_max_days | 60 | `fixes/cis-permissions-fix.sh --pass-max-days` |
| 5.3.5 | pass_min_len | 14 | `fixes/cis-permissions-fix.sh --pass-min-len` |
| 5.3.6 | pass_complexity | yes | `fixes/cis-permissions-fix.sh --pass-complexity` |
| 5.4.1 | root_gid_zero | 0 | `fixes/cis-permissions-fix.sh --root-gid` |
| 5.4.10 | system_accounts_shell | nologin | `fixes/cis-permissions-fix.sh --system-accounts-shell` |
| 5.4.11 | default_umask | 027 | `fixes/cis-permissions-fix.sh --default-umask` |
| 5.5.1 | session_timeout | 900 | `fixes/cis-permissions-fix.sh --session-timeout` |

### Chapter 6 — System Maintenance

| Control | Key | Expected | Fix Script |
|---|---|---|---|
| 6.1.4 | fs_passwd_perm | 644 | `fixes/cis-permissions-fix.sh --passwd-perm` |
| 6.1.8 | fs_shadow_perm | 640 | `fixes/cis-permissions-fix.sh --shadow-perm` |
| 6.1.21 | fs_sticky_world_writable | yes | `fixes/cis-permissions-fix.sh --sticky-bit` |
| 6.1.22 | fs_crontab_perm | 600 | `fixes/cis-permissions-fix.sh --cron-perm` |
| 6.1.39 | fs_sshd_config_perm | 600 | `fixes/cis-permissions-fix.sh --sshd-config-perm` |
| 6.2.1 | user_root_gid_zero | 0 | `fixes/cis-permissions-fix.sh --root-gid` |
| 6.2.20 | user_no_uid_zero_except_root | yes | `fixes/cis-permissions-fix.sh --uid-zero-root` |
| 6.2.22 | user_home_perm | 750 | `fixes/cis-permissions-fix.sh --home-perm` |

---

## Fix Scripts

| Script | CIS Sections | Description |
|---|---|---|
| `fixes/cis-ssh-hardening.sh` | 5.1 | Full SSH daemon hardening (all 5.1.x controls) |
| `fixes/cis-kernel-hardening.sh` | 3.1, 3.2, 1.6 | Sysctl network + IPv6 + ASLR parameters |
| `fixes/cis-firewall-setup.sh` | 3.4 | ufw/iptables firewall configuration with rate limiting |
| `fixes/cis-permissions-fix.sh` | 1.1, 1.4, 1.8, 1.9, 1.10, 1.11, 4.3, 4.4, 5.3, 5.4, 6.1, 6.2 | File permissions, auditd, banners, password policy, accounts |

All fix scripts:
- Are idempotent (safe to re-run)
- Back up original files before modification (`.mb.bak.<timestamp>`)
- Support `--dry-run` to preview changes
- Log all changes to `/var/log/mb-audit/`
- Load expected values from `rules/cis-*.rules` when run with `--all`

---

## Usage

### Run CIS v14.0 compliance scoring

```bash
sudo mb audit run --module lynis-score
```

### Apply all SSH hardening fixes

```bash
sudo fixes/cis-ssh-hardening.sh --all
```

### Apply all kernel hardening fixes

```bash
sudo fixes/cis-kernel-hardening.sh --all
```

### Set up firewall per CIS v14.0

```bash
sudo fixes/cis-firewall-setup.sh --all
```

### Apply a safe subset of permission fixes

```bash
sudo fixes/cis-permissions-fix.sh --all
```

### Preview any fix without applying

```bash
sudo fixes/cis-ssh-hardening.sh --all --dry-run
```

---

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [CIS Ubuntu Linux 24.04 LTS Benchmark v14.0](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux)
- [Lynis](https://cisofy.com/lynis/)
- [Lynis Control IDs](https://cisofy.com/lynis/controls/)
