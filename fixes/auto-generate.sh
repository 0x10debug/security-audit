#!/usr/bin/env bash
# auto-generate.sh — auto-remediation script generator.
#
# Reads audit results (pipe-delimited findings or JSON) and generates a
# standalone remediation script that can be run on the target system.
#
# Supports:
#   --input <file>     Audit results file (pipe-delimited or JSON).
#   --output <file>    Path for the generated remediation script (default: stdout).
#   --dry-run          Show what would be fixed without generating a script.
#
# Functions:
#   auto_gen_from_results()  — read findings, generate remediation script
#   auto_gen_dry_run()       — show what would be fixed (no script generated)
#   auto_gen_write_script()  — write a standalone remediation script
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

# ---------------------------------------------------------------------------
# auto_gen_from_results <findings_file> [output_file]
# Read pipe-delimited findings and generate a standalone remediation script.
# If output_file is omitted, the script is written to stdout.
# ---------------------------------------------------------------------------
auto_gen_from_results() {
    local findings_file="$1"
    local output_file="${2:-}"
    [[ -f "$findings_file" ]] || { mb_error "Findings file not found: $findings_file"; return 1; }

    # Collect all failed checks with non-empty fix commands.
    local fix_entries=""
    local count=0
    while IFS='|' read -r status _sev _mod check _msg fix; do
        [[ "$status" != "FAIL" && "$status" != "WARN" ]] && continue
        [[ -z "$fix" ]] && continue
        # Skip duplicate fix commands.
        local key="${check}:${fix}"
        if [[ ",${fix_entries}," == *",${key},"* ]]; then
            continue
        fi
        fix_entries="${fix_entries:+${fix_entries},}${key}"
        count=$((count + 1))
    done < "$findings_file"

    if [[ "$count" -eq 0 ]]; then
        mb_ok "No failed checks with remediation commands found — nothing to generate."
        return 0
    fi

    mb_info "Found ${count} check(s) requiring remediation."

    auto_gen_write_script "$findings_file" "$output_file"
}

# ---------------------------------------------------------------------------
# auto_gen_dry_run <findings_file>
# Show what would be fixed without generating a script.
# ---------------------------------------------------------------------------
auto_gen_dry_run() {
    local findings_file="$1"
    [[ -f "$findings_file" ]] || { mb_error "Findings file not found: $findings_file"; return 1; }

    local count=0
    printf '%b═══════════════════════════════════════════════════════════%b\n' \
        "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '%b Auto-Remediation Dry Run%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '═══════════════════════════════════════════════════════════\n'

    while IFS='|' read -r status _sev _mod check _msg fix; do
        [[ "$status" != "FAIL" && "$status" != "WARN" ]] && continue
        [[ -z "$fix" ]] && continue
        count=$((count + 1))
        printf '  [%s] %s/%s\n' "$status" "$_mod" "$check"
        printf '    → %s\n' "$fix"
    done < "$findings_file"

    printf '═══════════════════════════════════════════════════════════\n'
    printf '  Total remediation actions: %d\n' "$count"
    printf '%b═══════════════════════════════════════════════════════════%b\n\n' \
        "$MB_COLOR_BOLD" "$MB_COLOR_RESET"

    if [[ "$count" -eq 0 ]]; then
        mb_ok "No failed checks with remediation commands found."
    fi
}

# ---------------------------------------------------------------------------
# auto_gen_write_script <findings_file> [output_file]
# Write a standalone remediation script for all failed/warned checks.
# If output_file is empty, write to stdout.
# ---------------------------------------------------------------------------
auto_gen_write_script() {
    local findings_file="$1"
    local output_file="${2:-}"
    local ts host
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    host="$(mb_hostname)"

    # Collect fix commands (deduplicated, FAIL and WARN only).
    local fix_block=""
    local seen_fixes=""
    while IFS='|' read -r status _sev module check message fix; do
        [[ "$status" != "FAIL" && "$status" != "WARN" ]] && continue
        [[ -z "$fix" ]] && continue
        local key="${fix}"
        if [[ ",${seen_fixes}," == *",${key},"* ]]; then
            continue
        fi
        seen_fixes="${seen_fixes:+${seen_fixes},}${key}"
        # Add a comment with the check ID and a descriptive label.
        fix_block+="# [${status}] ${module}/${check}: ${message}"$'\n'
        fix_block+="${fix}"$'\n\n'
    done < "$findings_file"

    if [[ -z "$fix_block" ]]; then
        mb_ok "No remediation commands needed."
        return 0
    fi

    local script
    script=$(cat <<SCRIPT_EOF
#!/usr/bin/env bash
# Auto-generated remediation script — created by mb security audit.
# Generated: ${ts}
# Host: ${host}
# Tool version: ${MB_AUDIT_VERSION}
#
# This script is standalone and can be run on the target system.
# It applies remediation for all failed/warned audit checks.
# Review each command before running. Run with: sudo bash <this-script>
set -euo pipefail

echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Starting auto-remediation on \$(hostname)"

# Ensure root.
if [[ "\$(id -u)" -ne 0 ]]; then
    echo "ERROR: This script requires root privileges. Re-run with sudo." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Remediation actions
# ---------------------------------------------------------------------------
${fix_block}
# ---------------------------------------------------------------------------
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Auto-remediation complete."
echo "Re-run 'mb audit run' to verify fixes were applied."
SCRIPT_EOF
)

    if [[ -n "$output_file" ]]; then
        printf '%s\n' "$script" > "$output_file"
        chmod +x "$output_file"
        mb_ok "Remediation script written to ${output_file}"
    else
        printf '%s\n' "$script"
    fi
}

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
auto_gen_main() {
    local input_file=""
    local output_file=""
    local dry_run=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --input)    input_file="$2"; shift 2 ;;
            --output)   output_file="$2"; shift 2 ;;
            --dry-run)  dry_run=1; shift ;;
            -h|--help)
                cat <<EOF
Usage: auto-generate.sh [options]
Options:
  --input <file>    Audit results file (pipe-delimited findings).
  --output <file>   Path for the generated remediation script (default: stdout).
  --dry-run         Show what would be fixed without generating a script.
  -h, --help        Show this help.
EOF
                exit 0
                ;;
            *) mb_error "Unknown option: $1"; exit 1 ;;
        esac
    done

    [[ -z "$input_file" ]] && { mb_error "--input <file> is required."; exit 1; }

    if [[ "$dry_run" -eq 1 ]]; then
        auto_gen_dry_run "$input_file"
    else
        auto_gen_from_results "$input_file" "$output_file"
    fi
}

# Allow direct execution.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    auto_gen_main "$@"
fi
