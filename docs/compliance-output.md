# Compliance Output: Multi-Framework Mapping + OSCAL + Auto-Remediation

This document describes the compliance output module, which takes audit results from the CIS Benchmark module and produces three types of compliance artifacts:

1. **Multi-framework mapping** — maps CIS controls to NIST 800-53, ISO 27001, PCI DSS, SOC 2, and HIPAA
2. **OSCAL JSON output** — generates valid OSCAL 1.0.0+ assessment-results JSON
3. **Auto-remediation script** — generates a standalone remediation script from failed checks

---

## Overview

The compliance output module (`modules/compliance-output.sh`) ties together three libraries:

| Component | File | Purpose |
|---|---|---|
| Multi-framework mapping | `lib/multi-framework.sh` | Maps CIS check IDs to framework control IDs |
| OSCAL output | `lib/oscal-output.sh` | Generates OSCAL assessment-results JSON |
| Auto-remediation | `fixes/auto-generate.sh` | Generates standalone remediation scripts |
| Module orchestrator | `modules/compliance-output.sh` | Ties it all together with subcommands |

---

## Multi-Framework Mapping

### Supported Frameworks

| Framework ID | Full Name | Version |
|---|---|---|
| `NIST-800-53` | NIST SP 800-53 | Rev. 5 |
| `ISO-27001` | ISO/IEC 27001 | 2022 |
| `PCI-DSS` | PCI DSS | v4.0 |
| `SOC-2` | SOC 2 Trust Services Criteria | AICPA |
| `HIPAA` | HIPAA Security Rule | 45 CFR 164 |

### How It Works

The mapping library (`lib/multi-framework.sh`) maintains a pipe-delimited mapping table that links each CIS check ID (the `check` field in an mb audit finding) to the corresponding control IDs in each framework.

The mapping table format is:

```
CHECK_ID|NIST-800-53|ISO-27001|PCI-DSS|SOC-2|HIPAA
```

Each framework field contains a space-separated list of control IDs. A field may be empty if the check does not map to that framework.

### Control Mappings

| CIS Check | NIST 800-53 | ISO 27001 | PCI DSS | SOC 2 | HIPAA |
|---|---|---|---|---|---|
| `ssh_permitrootlogin` | AC-6 | A.5.15 | 2.2.4 | CC6.1 | 164.312(a)(2)(i) |
| `ssh_passwordauthentication` | IA-2 | A.5.17 | 8.3.1 | CC6.1 | 164.312(d) |
| `ssh_port` | SC-7 | A.8.22 | 2.2.5 | CC6.6 | |
| `ssh_allowusers` | AC-3 | A.5.15 | 2.2.4 | CC6.1 | 164.308(a)(4) |
| `ssh_maxauthtries` | AC-7 | A.5.17 | 8.3.4 | CC6.1 | |
| `ssh_logingracetime` | AC-12 | A.5.17 | 8.3.5 | CC6.1 | |
| `firewall_default_incoming` | SC-7 | A.8.22 | 1.4.1 | CC6.6 | 164.312(e)(1) |
| `firewall_allowed_ports` | SC-7 | A.8.22 | 1.4.2 | CC6.6 | 164.312(e)(1) |
| `kernel_bbr` | SC-5 | A.8.6 | | CC7.1 | |
| `kernel_file_max` | SC-5 | A.8.6 | | | |
| `kernel_somaxconn` | SC-5 | A.8.6 | | | |
| `kernel_ip_forward` | SC-7 | A.8.22 | 1.4.3 | CC6.6 | |
| `kernel_syncookies` | SC-5 | A.8.23 | 2.2.4 | CC7.1 | |
| `kernel_redirects` | SC-7 | A.8.23 | 1.4.3 | CC6.6 | |
| `docker_exposed_daemon` | AC-3 | A.8.4 | 2.2.7 | CC6.1 | 164.308(a)(3) |
| `docker_log_rotation` | AU-6 | A.8.15 | 10.3.1 | CC7.2 | |
| `docker_user_namespace` | AC-3 | A.8.4 | 2.2.7 | CC6.1 | |
| `autoupdate_enabled` | SI-2 | A.8.8 | 6.3.3 | CC7.1 | 164.308(a)(5)(ii)(B) |

### Adding Custom Mappings

You can add or override mappings at runtime using the `mf_add_mapping()` function:

```bash
source lib/multi-framework.sh
mf_add_mapping "my_custom_check" "AC-2" "A.5.16" "8.2.1" "CC6.1" "164.308(a)(3)"
```

### Library Functions

| Function | Description |
|---|---|
| `mf_list_frameworks` | Print supported framework IDs, one per line. |
| `mf_map_control <check_id> [framework]` | Print mapping for a single check. |
| `mf_get_mappings <findings_file> [framework]` | Print full mapping report for all checks in findings. |
| `mf_framework_summary <findings_file>` | Print per-framework assessed/pass/fail counts. |
| `mf_add_mapping <check> <nist> <iso> <pci> <soc2> <hipaa>` | Add a custom mapping at runtime. |

---

## OSCAL Output

### What is OSCAL?

OSCAL (Open Security Controls Assessment Language) is a NIST-standardized JSON/XML format for representing security control assessment results. It provides a machine-readable, vendor-neutral way to exchange compliance data between tools.

Reference: <https://pages.nist.gov/OSCAL/documentation/>

### Output Format

The OSCAL output generator produces a valid `assessment-results` model in JSON format, conforming to OSCAL 1.0.0+ schema. The output includes:

- **metadata** — title, timestamps, tool version, OSCAL version, hostname
- **results** — one assessment result containing:
  - **reviewed-controls** — the list of CIS controls assessed
  - **observations** — one observation per finding, with:
    - `implementation-status` — mapped from PASS/FAIL/WARN to `implemented`/`not-implemented`/`partial`
    - `risk` — mapped from severity to OSCAL risk level (`high`/`moderate`/`low`/`unknown`)
    - `description` — the finding message
    - `remediation` — the fix command

### Status Mapping

| mb Audit Status | OSCAL Implementation State |
|---|---|
| `PASS` | `implemented` |
| `FAIL` | `not-implemented` |
| `WARN` | `partial` |

### Severity Mapping

| mb Audit Severity | OSCAL Risk Level |
|---|---|
| `critical` | `high` |
| `high` | `high` |
| `medium` | `moderate` |
| `low` | `low` |
| `info` | `unknown` |

### Library Functions

| Function | Description |
|---|---|
| `oscal_generate <findings_file> [output_file]` | Read findings and write complete OSCAL JSON. |
| `oscal_add_result <status> <severity> <module> <check> <message> <fix>` | Add a single finding to the result set. |
| `oscal_write_json [output_file]` | Serialise accumulated results to OSCAL JSON. |

### Example OSCAL Output

```json
{
  "assessment-results": {
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "metadata": {
      "title": "mb Security Audit Assessment Results",
      "last-modified": "2025-08-30T14:48:00+0000",
      "version": "1.0.0",
      "oscal-version": "1.0.6",
      "published": "2025-08-30T14:48:00+0000",
      "props": [
        { "name": "hostname", "value": "web-01" },
        { "name": "tool", "value": "mb-security-audit" },
        { "name": "tool-version", "value": "1.0.0" }
      ]
    },
    "results": [
      {
        "uuid": "...",
        "title": "CIS Benchmark Assessment",
        "start": "2025-08-30T14:48:00+0000",
        "reviewed-controls": { ... },
        "observations": [
          { "control-id": "ssh_permitrootlogin", "implementation-status": { "state": "not-implemented" }, ... }
        ]
      }
    ]
  }
}
```

---

## Auto-Remediation Script Generation

### How It Works

The auto-remediation generator (`fixes/auto-generate.sh`) reads audit findings and produces a standalone bash script that applies all the fix commands from failed and warned checks.

The generated script:

- Is fully standalone (no external dependencies beyond standard system tools)
- Includes a root-privilege check
- Contains deduplicated fix commands (same fix command is not repeated)
- Has descriptive comments for each remediation action
- Is executable (`chmod +x`)

### Dry-Run Mode

Use `--dry-run` to preview what would be fixed without generating a script:

```
═══════════════════════════════════════════════════════════
 Auto-Remediation Dry Run
═══════════════════════════════════════════════════════════
  [FAIL] cis/ssh_permitrootlogin
    → sudo /path/to/fix-ssh.sh --permit-root-login no
  [FAIL] cis/firewall_default_incoming
    → sudo /path/to/fix-firewall.sh --default-incoming deny
═══════════════════════════════════════════════════════════
  Total remediation actions: 2
═══════════════════════════════════════════════════════════
```

### Library Functions

| Function | Description |
|---|---|
| `auto_gen_from_results <findings_file> [output_file]` | Read findings and generate remediation script. |
| `auto_gen_dry_run <findings_file>` | Show what would be fixed (no script generated). |
| `auto_gen_write_script <findings_file> [output_file]` | Write a standalone remediation script. |

---

## Integration with CIS Audit Module

The compliance output module integrates with the CIS Benchmark audit module (`modules/cis-benchmark.sh`) in three ways:

1. **Existing findings** — if `mb audit run` has already been executed, the module reads the latest JSON report from `${MB_AUDIT_REPORTS_DIR}/audit-latest.json` and extracts findings using `jq`.

2. **Custom input** — you can provide a specific findings file with `--input <file>` (pipe-delimited or JSON format).

3. **On-demand audit** — if no existing findings are found, the module runs the CIS benchmark module automatically to generate fresh findings.

### Data Flow

```
mb audit run → findings (pipe-delimited)
                   ↓
    ┌──────────────┼──────────────┐
    ↓              ↓              ↓
  mf_get_mappings  oscal_generate  auto_gen_from_results
    ↓              ↓              ↓
  Framework       OSCAL JSON     Remediation
  mapping report  file           script
```

---

## Usage

### Commands

```bash
# Generate multi-framework mapping report
mb compliance map

# Generate OSCAL JSON output (auto-named file)
mb compliance oscal

# Generate OSCAL JSON to a specific file
mb compliance oscal --output /tmp/oscal-results.json

# Preview remediation actions (dry run)
mb compliance remediate --dry-run

# Generate remediation script
mb compliance remediate --output /tmp/fix.sh

# Generate all outputs at once
mb compliance all

# Use a specific findings file as input
mb compliance all --input /var/log/mb-audit/reports/audit-latest.json
```

### Output Location

All auto-generated compliance artifacts are written to:

```
/var/log/mb-audit/reports/compliance/
```

Files are timestamped:

| Artifact | Filename pattern |
|---|---|
| OSCAL JSON | `oscal-assessment-<timestamp>.json` |
| Remediation script | `remediate-<timestamp>.sh` |

### Direct Library Usage

You can also use the libraries directly in your own scripts:

```bash
#!/usr/bin/env bash
source lib/common.sh
source lib/multi-framework.sh
source lib/oscal-output.sh

# Map a single control
mf_map_control "ssh_permitrootlogin"

# Generate OSCAL from a findings file
oscal_generate findings.txt oscal-output.json

# List supported frameworks
mf_list_frameworks
```

---

## Validation

### Validating OSCAL Output

If `jq` is installed, the compliance module automatically validates the generated OSCAL JSON:

```bash
jq empty /var/log/mb-audit/reports/compliance/oscal-assessment-*.json
```

For full OSCAL schema validation, use the NIST OSCAL validators:

```bash
# Using the NIST OSCAL CLI (optional, not included)
oscal-cli validate assessment-results /path/to/oscal-output.json
```

### Validating Generated Remediation Scripts

Generated remediation scripts can be syntax-checked:

```bash
bash -n /var/log/mb-audit/reports/compliance/remediate-*.sh
```

Always review the generated script before running it on a production system.
