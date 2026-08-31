#!/usr/bin/env bash
# compliance-output.sh — compliance output module for the mb audit tool.
#
# Takes audit results from the CIS module and produces:
#   - Multi-framework mapping report (NIST 800-53, ISO 27001, PCI DSS, SOC 2, HIPAA)
#   - OSCAL JSON assessment-results output
#   - Auto-generated remediation script
#
# Subcommands:
#   map       — generate multi-framework mapping report
#   oscal     — generate OSCAL JSON output
#   remediate — generate auto-remediation script
#   all       — generate everything
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

# Source the compliance libraries.
# shellcheck source=../lib/multi-framework.sh
source "${MB_AUDIT_DIR}/lib/multi-framework.sh"
# shellcheck source=../lib/oscal-output.sh
source "${MB_AUDIT_DIR}/lib/oscal-output.sh"
# shellcheck source=../fixes/auto-generate.sh
source "${MB_FIXES_DIR}/auto-generate.sh"

# Default output directory for compliance artifacts.
COMPLIANCE_OUTPUT_DIR="${MB_AUDIT_REPORTS_DIR}/compliance"

# ---------------------------------------------------------------------------
# _compliance_get_findings
# Locate the latest audit findings.  If a findings file is given as an
# argument, use it; otherwise run the CIS module to produce fresh findings.
# Returns the path to a pipe-delimited findings file on stdout.
# ---------------------------------------------------------------------------
_compliance_get_findings() {
    local input_file="${1:-}"

    if [[ -n "$input_file" && -f "$input_file" ]]; then
        printf '%s\n' "$input_file"
        return 0
    fi

    # Try the latest JSON report first — extract findings from it.
    local latest_json="${MB_AUDIT_REPORTS_DIR}/audit-latest.json"
    if [[ -f "$latest_json" ]]; then
        local tmp_findings
        tmp_findings="$(mktemp)"
        # Convert JSON findings back to pipe-delimited format using jq.
        if mb_command_exists jq; then
            jq -r '.findings[] | [.status,.severity,.module,.check,.message,.fix] | join("|")' \
                "$latest_json" > "$tmp_findings" 2>/dev/null || true
            if [[ -s "$tmp_findings" ]]; then
                printf '%s\n' "$tmp_findings"
                return 0
            fi
        fi
        rm -f "$tmp_findings"
    fi

    # No existing findings — run the CIS module to generate fresh ones.
    mb_info "No existing audit findings found — running CIS benchmark module..."
    local fresh_findings
    fresh_findings="$(mktemp)"
    # shellcheck source=cis-benchmark.sh
    source "${MB_MODULES_DIR}/cis-benchmark.sh"
    cis_benchmark_run > "$fresh_findings" 2>/dev/null || true
    printf '%s\n' "$fresh_findings"
}

# ---------------------------------------------------------------------------
# compliance_map <findings_file>
# Generate and display a multi-framework mapping report.
# ---------------------------------------------------------------------------
compliance_map() {
    local findings_file="$1"

    printf '\n%b═══════════════════════════════════════════════════════════%b\n' \
        "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '%b Multi-Framework Compliance Mapping%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '═══════════════════════════════════════════════════════════\n\n'

    # Framework summary.
    printf '%bFramework Summary%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    mf_framework_summary "$findings_file" || true
    printf '\n'

    # Detailed mappings.
    printf '%bDetailed Control Mappings%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '%-30s %-8s %-20s %s\n' "CHECK" "STATUS" "FRAMEWORK" "CONTROLS"
    printf '%-30s %-8s %-20s %s\n' "-----" "------" "----------" "--------"
    mf_get_mappings "$findings_file" | while IFS='|' read -r check status fw_ctrls; do
        local fw="${fw_ctrls%%=*}"
        local ctrls="${fw_ctrls#*=}"
        printf '%-30s %-8s %-20s %s\n' "$check" "$status" "$fw" "$ctrls"
    done || true

    printf '\n%bSupported Frameworks%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    local fw
    for fw in "${MF_FRAMEWORKS[@]}"; do
        printf '  %-14s %s\n' "$fw" "${MF_FRAMEWORK_NAMES[$fw]}"
    done
    printf '═══════════════════════════════════════════════════════════\n\n'
}

# ---------------------------------------------------------------------------
# compliance_oscal <findings_file> [output_file]
# Generate OSCAL JSON output.
# ---------------------------------------------------------------------------
compliance_oscal() {
    local findings_file="$1"
    local output_file="${2:-}"

    if [[ -z "$output_file" ]]; then
        mb_ensure_dir "$COMPLIANCE_OUTPUT_DIR"
        local ts
        ts="$(date '+%Y%m%d%H%M%S')"
        output_file="${COMPLIANCE_OUTPUT_DIR}/oscal-assessment-${ts}.json"
    fi

    oscal_generate "$findings_file" "$output_file"

    # Validate the JSON is well-formed if jq is available.
    if mb_command_exists jq; then
        if jq empty "$output_file" 2>/dev/null; then
            mb_ok "OSCAL JSON validated successfully."
        else
            mb_warn "OSCAL JSON validation failed — check output manually."
        fi
    fi

    printf '\n%bOSCAL Output%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '  File: %s\n' "$output_file"
    printf '  Format: OSCAL 1.0.6 assessment-results JSON\n'
    printf '═══════════════════════════════════════════════════════════\n\n'
}

# ---------------------------------------------------------------------------
# compliance_remediate <findings_file> [output_file] [dry_run]
# Generate an auto-remediation script from audit findings.
# ---------------------------------------------------------------------------
compliance_remediate() {
    local findings_file="$1"
    local output_file="${2:-}"
    local dry_run="${3:-0}"

    if [[ "$dry_run" == "1" ]]; then
        auto_gen_dry_run "$findings_file"
        return 0
    fi

    if [[ -z "$output_file" ]]; then
        mb_ensure_dir "$COMPLIANCE_OUTPUT_DIR"
        local ts
        ts="$(date '+%Y%m%d%H%M%S')"
        output_file="${COMPLIANCE_OUTPUT_DIR}/remediate-${ts}.sh"
    fi

    auto_gen_from_results "$findings_file" "$output_file"

    printf '\n%bRemediation Script%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '  File: %s\n' "$output_file"
    printf '  Usage: sudo bash %s\n' "$output_file"
    printf '═══════════════════════════════════════════════════════════\n\n'
}

# ---------------------------------------------------------------------------
# compliance_all <findings_file>
# Generate all compliance outputs: mapping, OSCAL, and remediation script.
# ---------------------------------------------------------------------------
compliance_all() {
    local findings_file="$1"
    local ts
    ts="$(date '+%Y%m%d%H%M%S')"

    mb_ensure_dir "$COMPLIANCE_OUTPUT_DIR" 2>/dev/null || {
        mb_warn "Cannot create ${COMPLIANCE_OUTPUT_DIR} — using /tmp for output."
        COMPLIANCE_OUTPUT_DIR="/tmp/mb-compliance"
        mb_ensure_dir "$COMPLIANCE_OUTPUT_DIR"
    }

    mb_info "Generating all compliance outputs..."

    # 1. Multi-framework mapping.
    compliance_map "$findings_file"

    # 2. OSCAL JSON.
    compliance_oscal "$findings_file" "${COMPLIANCE_OUTPUT_DIR}/oscal-assessment-${ts}.json"

    # 3. Auto-remediation script.
    compliance_remediate "$findings_file" "${COMPLIANCE_OUTPUT_DIR}/remediate-${ts}.sh" 0

    mb_ok "All compliance outputs generated in ${COMPLIANCE_OUTPUT_DIR}"
}

# ---------------------------------------------------------------------------
# compliance_output_run <subcommand> [options]
# Main entry point for the compliance-output module.
# ---------------------------------------------------------------------------
compliance_output_run() {
    local sub="${1:-help}"
    shift || true

    local input_file=""
    local output_file=""
    local dry_run=0

    # Parse common options.
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --input)  input_file="$2"; shift 2 ;;
            --output) output_file="$2"; shift 2 ;;
            --dry-run) dry_run=1; shift ;;
            -h|--help) sub="help"; shift ;;
            *) mb_error "Unknown option: $1"; exit 1 ;;
        esac
    done

    # Handle help early — no findings needed.
    if [[ "$sub" == "help" || "$sub" == "-h" || "$sub" == "--help" ]]; then
        compliance_output_help
        return 0
    fi

    # Get findings (from input file or by running CIS module).
    local findings_file
    findings_file="$(_compliance_get_findings "$input_file")"

    if [[ ! -s "$findings_file" ]]; then
        mb_error "No audit findings available. Run 'mb audit run' first or provide --input <file>."
        return 1
    fi

    local total
    total="$(wc -l < "$findings_file" | tr -d ' ')"
    mb_info "Processing ${total} audit findings..."

    case "$sub" in
        map)
            compliance_map "$findings_file"
            ;;
        oscal)
            compliance_oscal "$findings_file" "$output_file"
            ;;
        remediate)
            compliance_remediate "$findings_file" "$output_file" "$dry_run"
            ;;
        all)
            compliance_all "$findings_file"
            ;;
        *)
            mb_error "Unknown compliance subcommand: $sub"
            compliance_output_help
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# compliance_output_help
# ---------------------------------------------------------------------------
compliance_output_help() {
    cat <<EOF
${MB_COLOR_BOLD}mb compliance${MB_COLOR_RESET} — Compliance Output Module (v${MB_AUDIT_VERSION})

${MB_COLOR_BOLD}USAGE${MB_COLOR_RESET}
  mb compliance <subcommand> [options]

${MB_COLOR_BOLD}SUBCOMMANDS${MB_COLOR_RESET}
  map        Generate multi-framework compliance mapping report.
             Shows which NIST/ISO/PCI/SOC2/HIPAA controls are covered.
  oscal      Generate OSCAL 1.0.6 assessment-results JSON output.
  remediate  Generate an auto-remediation script from audit findings.
  all        Generate all outputs (mapping + OSCAL + remediation).
  help       Show this help.

${MB_COLOR_BOLD}OPTIONS${MB_COLOR_RESET}
  --input <file>     Use a specific findings file instead of the latest audit.
  --output <file>    Specify output file path (default: auto-generated).
  --dry-run          (remediate only) Show what would be fixed without generating a script.

${MB_COLOR_BOLD}EXAMPLES${MB_COLOR_RESET}
  mb compliance map
  mb compliance oscal --output /tmp/oscal.json
  mb compliance remediate --dry-run
  mb compliance remediate --output /tmp/fix.sh
  mb compliance all
  mb compliance all --input /var/log/mb-audit/reports/audit-latest.json

${MB_COLOR_BOLD}SUPPORTED FRAMEWORKS${MB_COLOR_RESET}
  NIST-800-53, ISO-27001, PCI-DSS, SOC-2, HIPAA

${MB_COLOR_BOLD}OUTPUT DIRECTORY${MB_COLOR_RESET}
  ${COMPLIANCE_OUTPUT_DIR}

EOF
}

# Allow direct execution: `modules/compliance-output.sh <subcommand>`.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        compliance_output_help
        exit 0
    fi
    compliance_output_run "$@"
fi
