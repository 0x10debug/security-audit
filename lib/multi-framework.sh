#!/usr/bin/env bash
# multi-framework.sh — map CIS audit controls to multiple compliance frameworks.
#
# Supported frameworks:
#   NIST 800-53  — NIST SP 800-53 Rev. 5 control identifiers
#   ISO 27001    — ISO/IEC 27001:2022 Annex A control identifiers
#   PCI DSS      — PCI DSS v4.0 requirement identifiers
#   SOC 2        — AICPA SOC 2 Trust Services Criteria
#   HIPAA        — HIPAA Security Rule Safeguard identifiers
#
# The mapping table uses a pipe-delimited format keyed on the CIS check ID
# (the 4th field of an mb audit finding).  Each entry lists the corresponding
# control IDs for every framework, separated by spaces.
#
# Custom mappings can be added at runtime via mf_add_mapping().
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# ---------------------------------------------------------------------------
# Supported frameworks (canonical order)
# ---------------------------------------------------------------------------
MF_FRAMEWORKS=("NIST-800-53" "ISO-27001" "PCI-DSS" "SOC-2" "HIPAA")

declare -A MF_FRAMEWORK_NAMES
MF_FRAMEWORK_NAMES=(
    ["NIST-800-53"]="NIST SP 800-53 Rev. 5"
    ["ISO-27001"]="ISO/IEC 27001:2022"
    ["PCI-DSS"]="PCI DSS v4.0"
    ["SOC-2"]="SOC 2 Trust Services Criteria"
    ["HIPAA"]="HIPAA Security Rule"
)

# ---------------------------------------------------------------------------
# Mapping table
# Format: CHECK_ID|NIST-800-53|ISO-27001|PCI-DSS|SOC-2|HIPAA
# Framework fields are space-separated lists of control IDs (may be empty).
# ---------------------------------------------------------------------------
MF_MAPPING_TABLE=""

_mf_init_table() {
    MF_MAPPING_TABLE=$(cat <<'MAPPING_EOF'
ssh_permitrootlogin|AC-6|A.5.15|2.2.4|CC6.1|164.312(a)(2)(i)
ssh_passwordauthentication|IA-2|A.5.17|8.3.1|CC6.1|164.312(d)
ssh_port|SC-7|A.8.22|2.2.5|CC6.6|
ssh_allowusers|AC-3|A.5.15|2.2.4|CC6.1|164.308(a)(4)
ssh_maxauthtries|AC-7|A.5.17|8.3.4|CC6.1|
ssh_logingracetime|AC-12|A.5.17|8.3.5|CC6.1|
firewall_default_incoming|SC-7|A.8.22|1.4.1|CC6.6|164.312(e)(1)
firewall_allowed_ports|SC-7|A.8.22|1.4.2|CC6.6|164.312(e)(1)
kernel_bbr|SC-5|A.8.6||CC7.1|
kernel_file_max|SC-5|A.8.6|||
kernel_somaxconn|SC-5|A.8.6|||
kernel_ip_forward|SC-7|A.8.22|1.4.3|CC6.6|
kernel_syncookies|SC-5|A.8.23|2.2.4|CC7.1|
kernel_redirects|SC-7|A.8.23|1.4.3|CC6.6|
docker_exposed_daemon|AC-3|A.8.4|2.2.7|CC6.1|164.308(a)(3)
docker_log_rotation|AU-6|A.8.15|10.3.1|CC7.2|
docker_user_namespace|AC-3|A.8.4|2.2.7|CC6.1|
autoupdate_enabled|SI-2|A.8.8|6.3.3|CC7.1|164.308(a)(5)(ii)(B)
MAPPING_EOF
)
}

# ---------------------------------------------------------------------------
# mf_list_frameworks — print supported framework IDs, one per line.
# ---------------------------------------------------------------------------
mf_list_frameworks() {
    local fw
    for fw in "${MF_FRAMEWORKS[@]}"; do
        printf '%s\n' "$fw"
    done
}

# ---------------------------------------------------------------------------
# mf_framework_summary <findings_file>
# Print a per-framework summary: how many assessed controls, pass/fail counts.
# ---------------------------------------------------------------------------
mf_framework_summary() {
    local findings_file="$1"
    [[ -f "$findings_file" ]] || { mb_error "Findings file not found: $findings_file"; return 1; }

    local fw
    for fw in "${MF_FRAMEWORKS[@]}"; do
        local assessed=0 passed=0 failed=0
        # Collect all check IDs that map to this framework.
        local check_ids
        check_ids="$(_mf_checks_for_framework "$fw")"
        if [[ -z "$check_ids" ]]; then
            continue
        fi

        while IFS= read -r cid; do
            if [[ -z "$cid" ]]; then
                continue
            fi
            # Count findings matching this check ID.
            local matches
            matches="$(grep -E "^[A-Z]+\|[^|]+\|[^|]+\|${cid}\|" "$findings_file" 2>/dev/null || true)"
            if [[ -z "$matches" ]]; then
                continue
            fi
            assessed=$((assessed + 1))
            if echo "$matches" | grep -q '^PASS|'; then
                passed=$((passed + 1))
            else
                failed=$((failed + 1))
            fi
        done <<< "$check_ids"

        printf '%-14s  assessed=%-3d  pass=%-3d  fail=%-3d  %s\n' \
            "$fw" "$assessed" "$passed" "$failed" "${MF_FRAMEWORK_NAMES[$fw]}"
    done
}

# ---------------------------------------------------------------------------
# mf_map_control <check_id> [framework]
# Print the mapping for a single CIS check ID.
# If framework is omitted, print all frameworks for that check.
# Output format (no framework): FRAMEWORK=ctrl1 ctrl2 ...
# Output format (with framework): ctrl1 ctrl2 ...
# ---------------------------------------------------------------------------
mf_map_control() {
    local check_id="$1"
    local framework="${2:-}"
    local line

    line="$(printf '%s\n' "$MF_MAPPING_TABLE" | grep -E "^${check_id}\|" || true)"
    if [[ -z "$line" ]]; then
        # Check custom mappings.
        line="$(printf '%s\n' "${MF_CUSTOM_MAPPINGS:-}" | grep -E "^${check_id}\|" || true)"
    fi
    if [[ -z "$line" ]]; then
        printf '\n'
        return 0
    fi

    if [[ -n "$framework" ]]; then
        # Print only the requested framework field.
        _mf_extract_framework "$line" "$framework"
    else
        # Print all frameworks.
        local i
        for i in "${!MF_FRAMEWORKS[@]}"; do
            local fw="${MF_FRAMEWORKS[$i]}"
            local ctrls
            ctrls="$(_mf_extract_framework "$line" "$fw")"
            if [[ -n "$ctrls" ]]; then
                printf '%s=%s\n' "$fw" "$ctrls"
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# mf_get_mappings <findings_file> [framework]
# Print a full mapping report for all checks in the findings file.
# Each line: CHECK_ID|STATUS|FRAMEWORK=controls
# If framework is given, only that framework column is printed.
# ---------------------------------------------------------------------------
mf_get_mappings() {
    local findings_file="$1"
    local framework="${2:-}"
    [[ -f "$findings_file" ]] || { mb_error "Findings file not found: $findings_file"; return 1; }

    local seen_checks=""
    while IFS='|' read -r status _module _sev check _msg _fix; do
        if [[ -z "$check" ]]; then
            continue
        fi
        # Skip duplicates.
        if [[ ",${seen_checks}," == *",${check},"* ]]; then
            continue
        fi
        seen_checks="${seen_checks:+${seen_checks},}${check}"

        if [[ -n "$framework" ]]; then
            local ctrls
            ctrls="$(mf_map_control "$check" "$framework")"
            if [[ -n "$ctrls" ]]; then
                printf '%s|%s|%s=%s\n' "$check" "$status" "$framework" "$ctrls"
            fi
        else
            local fw
            for fw in "${MF_FRAMEWORKS[@]}"; do
                local ctrls
                ctrls="$(mf_map_control "$check" "$fw")"
                if [[ -n "$ctrls" ]]; then
                    printf '%s|%s|%s=%s\n' "$check" "$status" "$fw" "$ctrls"
                fi
            done
        fi
    done < "$findings_file"
}

# ---------------------------------------------------------------------------
# mf_add_mapping <check_id> <NIST> <ISO> <PCI> <SOC2> <HIPAA>
# Add or override a custom mapping at runtime.
# ---------------------------------------------------------------------------
mf_add_mapping() {
    local check_id="$1" nist="$2" iso="$3" pci="$4" soc2="$5" hipaa="$6"
    # Remove any existing custom mapping for this check.
    if [[ -n "${MF_CUSTOM_MAPPINGS:-}" ]]; then
        MF_CUSTOM_MAPPINGS="$(printf '%s\n' "$MF_CUSTOM_MAPPINGS" | grep -vE "^${check_id}\|" || true)"
    fi
    local entry="${check_id}|${nist}|${iso}|${pci}|${soc2}|${hipaa}"
    MF_CUSTOM_MAPPINGS="${MF_CUSTOM_MAPPINGS:+${MF_CUSTOM_MAPPINGS}$'\n'}${entry}"
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Extract a single framework field from a mapping line.
# _mf_extract_framework <line> <framework_id>
_mf_extract_framework() {
    local line="$1" fw="$2"
    local idx=-1
    local i
    for i in "${!MF_FRAMEWORKS[@]}"; do
        if [[ "${MF_FRAMEWORKS[$i]}" == "$fw" ]]; then
            idx=$((i + 2))  # field 1 is check_id; frameworks start at field 2
            break
        fi
    done
    if [[ "$idx" -lt 0 ]]; then
        return 0
    fi
    printf '%s' "$line" | cut -d'|' -f"$idx"
}

# Return newline-separated check IDs that have mappings for a given framework.
# _mf_checks_for_framework <framework_id>
_mf_checks_for_framework() {
    local fw="$1"
    local all_mappings="${MF_MAPPING_TABLE}"
    if [[ -n "${MF_CUSTOM_MAPPINGS:-}" ]]; then
        all_mappings="${all_mappings}"$'\n'"${MF_CUSTOM_MAPPINGS}"
    fi
    while IFS='|' read -r check_id rest; do
        if [[ -z "$check_id" ]]; then
            continue
        fi
        local ctrls
        ctrls="$(_mf_extract_framework "${check_id}|${rest}" "$fw")"
        if [[ -n "$ctrls" ]]; then
            printf '%s\n' "$check_id"
        fi
    done <<< "$all_mappings"
}

# Initialise the mapping table on source.
_mf_init_table

# Allow direct execution: `lib/multi-framework.sh` → list frameworks.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mf_list_frameworks
fi
