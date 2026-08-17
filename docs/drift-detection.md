# Drift Detection

How configuration drift detection works in `mb audit` and why it matters.

## What is drift?

Configuration drift is the gradual divergence of a system's configuration from a known-good state. It happens when someone manually edits a config file, a package update changes a default, or an automation run partially fails. Drift is dangerous because:

1. **Silent regressions** — a hardening setting gets reverted and nobody notices.
2. **Inconsistent fleet** — servers that should be identical slowly diverge.
3. **Security holes** — a firewall rule opened "just for testing" stays open forever.

## How it works

### 1. Capture a baseline

```bash
sudo ./mb audit baseline
```

This snapshots the current state of SSH, firewall, kernel, and Docker configuration into a YAML file at `/etc/mb-backup/baseline.yaml`. The baseline also records mtime and sha256 of sensitive files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`).

You should capture a baseline right after initial hardening (e.g. after running vps-bootstrap), when you trust the system state.

### 2. Compare against the baseline

```bash
sudo ./mb audit drift
```

The `drift` module reads the baseline and compares each field against the current live value. Any difference is emitted as a `FAIL` finding with a fix command:

```
FAIL|high|drift|drift_ssh_port|SSH port: drifted from '2222' to '22'|Run `mb audit fix` to restore, or `mb audit baseline` to re-snapshot
```

### 3. Remediate or re-snapshot

- If the drift is unintended → run `sudo mb audit fix` to restore the expected state.
- If the drift is an intentional change → run `sudo mb audit baseline` to capture a new trusted snapshot.

## What gets compared

| Subsystem | Fields |
|---|---|
| SSH | port, permit_root_login, password_authentication, allow_users, max_auth_tries, login_grace_time |
| Firewall | default_incoming, default_outgoing, allowed_ports |
| Kernel | tcp_congestion_control, file_max, somaxconn, ip_forward, syncookies |
| Docker | exposed_daemon, log_rotation, user_namespace |
| Files | mtime + sha256 of /etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config |

## Baseline file location

`/etc/mb-backup/baseline.yaml` — aligned with vps-bootstrap so all mb-suite state lives in one predictable place.

## Scheduling drift checks

Combine drift detection with the daily cron schedule:

```bash
sudo ./mb audit schedule --daily
```

The daily run includes the `drift` module, so you get notified automatically when something changes. Feed the JSON report into your alerting stack (see [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack)) to get paged on drift.
