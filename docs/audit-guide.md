# Audit Guide

How to run audits and interpret the reports produced by `mb audit`.

## Running an audit

A full audit runs every module and writes HTML + JSON reports:

```bash
sudo ./mb audit run
```

To run a subset of modules (comma-separated):

```bash
sudo ./mb audit run --module cis-benchmark,log-audit
```

Available modules: `cis-benchmark`, `lynis`, `log-audit`, `container-scan`, `drift`.

Add `--quiet` to suppress the terminal summary (useful for cron).

## Where reports go

All reports are written to `/var/log/mb-audit/reports/`:

| File | Description |
|---|---|
| `audit-<timestamp>.html` | Human-readable report for a single run |
| `audit-<timestamp>.json` | Machine-readable report for the same run |
| `audit-latest.html` | Symlink to the most recent HTML report |
| `audit-latest.json` | Symlink to the most recent JSON report |
| `status.txt` | Key/value summary of the last run (used by `mb audit status`) |

## Interpreting findings

Each finding is a pipe-delimited record:

```
STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX_COMMAND
```

- **STATUS** — `PASS`, `FAIL`, or `WARN`.
- **SEVERITY** — `info`, `low`, `medium`, `high`, `critical`.
- **MODULE** — which audit module produced the finding.
- **CHECK** — the specific check name (e.g. `ssh_permitrootlogin`).
- **MESSAGE** — human-readable description.
- **FIX_COMMAND** — a ready-to-run command to remediate the finding (empty for PASS).

## The terminal summary

After a run, `mb` prints a summary block:

```
═══════════════════════════════════════════════════════════
 VPS Security Audit Summary
═══════════════════════════════════════════════════════════
  Host:    server01
  Date:    20260117...
  Total:   18
  PASS:  12
  FAIL:   3
  WARN:   3
═══════════════════════════════════════════════════════════
  HTML report: /var/log/mb-audit/reports/audit-latest.html
  JSON report: /var/log/mb-audit/reports/audit-latest.json
═══════════════════════════════════════════════════════════
```

## Applying fixes

Preview first:

```bash
sudo ./mb audit fix --dry-run
```

Then apply:

```bash
sudo ./mb audit fix
```

Every fix script backs up the files it touches (`.mb.bak.<timestamp>`) and only changes directives that differ from the expected value.

## Scheduling

Set up a daily audit via cron:

```bash
sudo ./mb audit schedule --daily
```

Cron output is appended to `/var/log/mb-audit/cron.log`.

## Status

```bash
./mb audit status
```

Reads `status.txt` and shows the date, host, and pass/fail/warn counts of the last run.
