#!/usr/bin/env bash
# lynis-scoring.sh — Lynis CIS compliance scoring for the mb audit tool.
#
# Runs a Lynis audit, parses the report to extract CIS-related control items,
# maps them against the CIS Benchmark v14.0 rule set under rules/cis-v14.0/,
# and produces a compliance score (0–100) with per-chapter breakdown.
#
# Outputs:
#   - TXT report:  ${MB_AUDIT_REPORTS_DIR}/cis-score-latest.txt
#   - JSON report: ${MB_AUDIT_REPORTS_DIR}/cis-score-latest.json
#   - Pipe-delimited findings (consumed by the standard report generator)
#
# Scoring model:
#   Each CIS v14.0 control is weighted by severity:
#     critical=4  high=3  medium=2  low=1  info=0
#   Score = (satisfied_weight / applicable_weight) * 100
#   A control is "satisfied" when the corresponding Lynis control passes or
#   the local cis-benchmark check passes; "not_applicable" controls are
#   excluded from the denominator; "unsatisfied" controls contribute 0.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="lynis-score"
LYNIS_BIN="${LYNIS_BIN:-/usr/local/bin/lynis}"
LYNIS_SRC_DIR="${LYNIS_SRC_DIR:-/opt/lynis}"
CIS_V14_DIR="${MB_RULES_DIR}/cis-v14.0"

# Severity → weight (used for weighted compliance score).
declare -A SEVERITY_WEIGHT=(
    [critical]=4 [high]=3 [medium]=2 [low]=1 [info]=0
)

# CIS v14.0 chapter → rule file mapping.
declare -A CHAPTER_FILE=(
    [1-initial-setup]="${CIS_V14_DIR}/1-initial-setup.rules"
    [2-services]="${CIS_V14_DIR}/2-services.rules"
    [3-network]="${CIS_V14_DIR}/3-network.rules"
    [4-logging]="${CIS_V14_DIR}/4-logging.rules"
    [5-access]="${CIS_V14_DIR}/5-access.rules"
    [6-system-maintenance]="${CIS_V14_DIR}/6-system-maintenance.rules"
)

# ---------------------------------------------------------------------------
# Ensure Lynis is available (delegates to lynis.sh installer).
# ---------------------------------------------------------------------------
mb_lynis_scoring_install() {
    if mb_command_exists lynis || [[ -x "$LYNIS_BIN" ]]; then
        return 0
    fi
    # Reuse the installer from lynis.sh.
    # shellcheck source=lynis.sh
    source "${MB_MODULES_DIR}/lynis.sh"
    mb_lynis_install
}

# Resolve the lynis command path.
_lynis_cmd() {
    if mb_command_exists lynis; then
        echo "lynis"
    else
        echo "$LYNIS_BIN"
    fi
}

# ---------------------------------------------------------------------------
# Run Lynis and capture the .dat report file for parsing.
# Returns the path to the .dat file on stdout.
# ---------------------------------------------------------------------------
mb_lynis_scoring_run_audit() {
    local out_dir
    out_dir="$(mktemp -d)"
    local dat="${out_dir}/lynis.dat"
    local raw="${out_dir}/lynis.raw"

    local cmd
    cmd="$(_lynis_cmd)"

    mb_info "Running Lynis audit for CIS compliance scoring..."

    ${cmd} audit system --auditor "mb-audit" \
        --logfile "${out_dir}/lynis.log" \
        --report-file "${dat}" \
        > "$raw" 2>&1 || true

    echo "$dat"
}

# ---------------------------------------------------------------------------
# Parse the Lynis .dat report and build an associative array of control → status.
# Lynis .dat lines look like:
#   control[]=SSH-7408|result|OK
#   control[]=SSH-7408|details|...
# We extract the control id and its result (OK / WARNING / SUGGESTION / ...).
# Globals: LYNIS_CONTROL_STATUS (assoc array: control_id → OK|WARNING|...)
# ---------------------------------------------------------------------------
declare -A LYNIS_CONTROL_STATUS=()

mb_lynis_scoring_parse() {
    local dat="$1"
    [[ -f "$dat" ]] || { mb_error "Lynis .dat report not found: $dat"; return 1; }

    while IFS= read -r line; do
        # Match: control[]=ID|result|VALUE
        if [[ "$line" =~ ^control\[\]=([A-Z]+-[0-9]+)\|result\|([A-Z_]+) ]]; then
            local id="${BASH_REMATCH[1]}"
            local result="${BASH_REMATCH[2]}"
            LYNIS_CONTROL_STATUS["$id"]="$result"
        fi
    done < "$dat"
}

# ---------------------------------------------------------------------------
# Load a CIS v14.0 rule file into parallel arrays.
# Each line: control_id|key|expected|severity|fix_script
# Globals set: CIS_ID[], CIS_KEY[], CIS_EXPECTED[], CIS_SEVERITY[], CIS_FIX[]
# ---------------------------------------------------------------------------
declare -a CIS_ID=() CIS_KEY=() CIS_EXPECTED=() CIS_SEVERITY=() CIS_FIX=()

mb_lynis_scoring_load_rules() {
    local rules_file="$1"
    [[ -f "$rules_file" ]] || { mb_error "CIS rules file not found: $rules_file"; return 1; }
    while IFS='|' read -r id key expected severity fix; do
        # Skip comments and blank lines.
        [[ "$id" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${id// }" ]] && continue
        CIS_ID+=("$id")
        CIS_KEY+=("$key")
        CIS_EXPECTED+=("$expected")
        CIS_SEVERITY+=("$severity")
        CIS_FIX+=("$fix")
    done < "$rules_file"
}

# ---------------------------------------------------------------------------
# Determine the status of a single CIS control.
# Heuristic: map the CIS control key to a Lynis control id prefix when possible;
# otherwise fall back to checking the local sysctl / sshd value.
#
# Returns one of: satisfied | unsatisfied | not_applicable
# (printed on stdout)
# ---------------------------------------------------------------------------
mb_lynis_scoring_eval_control() {
    local id="$1" key="$2" expected="$3" severity="$4"

    # --- Heuristic 1: look up Lynis control results by key prefix ---
    # Lynis control ids are grouped by topic (SSH-*, KRNL-*, FIREWALL-*, etc.).
    # We map common CIS key prefixes to Lynis topic prefixes.
    local lynis_prefix=""
    case "$key" in
        ssh_*)           lynis_prefix="SSH-" ;;
        net_ipv4_*|net_ipv6_*) lynis_prefix="KRNL-" ;;
        firewall_*)      lynis_prefix="FIREWALL-" ;;
        auditd_*|audit_*) lynis_prefix="ACCT-" ;;
        fs_*_perm|fs_*_owner|user_*_perm) lynis_prefix="FILE-" ;;
        kernel_*|fs_*)   lynis_prefix="KRNL-" ;;
    esac

    if [[ -n "$lynis_prefix" ]]; then
        local matched=0
        for lynis_id in "${!LYNIS_CONTROL_STATUS[@]}"; do
            if [[ "$lynis_id" == ${lynis_prefix}* ]]; then
                matched=1
                local res="${LYNIS_CONTROL_STATUS[$lynis_id]}"
                if [[ "$res" == "OK" || "$res" == "DONE" ]]; then
                    echo "satisfied"
                    return 0
                elif [[ "$res" == "WARNING" ]]; then
                    echo "unsatisfied"
                    return 0
                elif [[ "$res" == "SUGGESTION" ]]; then
                    # Suggestions are partial — treat as unsatisfied for scoring.
                    echo "unsatisfied"
                    return 0
                fi
            fi
        done
        # If we matched the topic but no specific result, fall through.
        if [[ $matched -eq 1 ]]; then
            echo "not_applicable"
            return 0
        fi
    fi

    # --- Heuristic 2: local verification for sysctl-based controls ---
    # Keys in v14.0 rules use underscores (net_ipv4_ip_forward); sysctl paths
    # use dots (net.ipv4.ip_forward). Convert underscores to dots for lookup.
    if [[ "$key" == net_ipv4_* || "$key" == net_ipv6_* || "$key" == kernel_* || "$key" == fs_* ]]; then
        local sysctl_key="${key//_/.}"
        if mb_command_exists sysctl; then
            local actual
            actual="$(sysctl -n "$sysctl_key" 2>/dev/null || echo "")"
            if [[ -n "$actual" ]]; then
                if [[ "$actual" == "$expected" ]]; then
                    echo "satisfied"
                else
                    echo "unsatisfied"
                fi
                return 0
            fi
        fi
        # sysctl not available (e.g. macOS dev) — mark not_applicable.
        echo "not_applicable"
        return 0
    fi

    # --- Heuristic 3: services that should be disabled ---
    case "$expected" in
        not_installed|disabled|absent)
            # If the service/binary is absent, it's satisfied.
            local svc="${key%%_*}"
            if ! mb_command_exists "$svc"; then
                echo "satisfied"
                return 0
            fi
            # If systemd is available, check the service state.
            if mb_command_exists systemctl; then
                if ! systemctl is-enabled "$svc" >/dev/null 2>&1; then
                    echo "satisfied"
                    return 0
                fi
            fi
            echo "unsatisfied"
            return 0
            ;;
    esac

    # --- Default: cannot verify automatically → not_applicable ---
    echo "not_applicable"
}

# ---------------------------------------------------------------------------
# Compute the compliance score for a single chapter.
# Args: rules_file
# Prints: <chapter_score> <satisfied> <unsatisfied> <not_applicable> <total>
# Also emits pipe-delimited findings for each control.
# ---------------------------------------------------------------------------
mb_lynis_scoring_score_chapter() {
    local rules_file="$1"
    mb_lynis_scoring_load_rules "$rules_file"

    local satisfied_weight=0
    local unsatisfied_weight=0
    local applicable_weight=0
    local satisfied_count=0
    local unsatisfied_count=0
    local na_count=0
    local total=${#CIS_ID[@]}

    for ((i = 0; i < total; i++)); do
        local id="${CIS_ID[$i]}"
        local key="${CIS_KEY[$i]}"
        local expected="${CIS_EXPECTED[$i]}"
        local severity="${CIS_SEVERITY[$i]}"
        local fix="${CIS_FIX[$i]}"

        local status
        status="$(mb_lynis_scoring_eval_control "$id" "$key" "$expected" "$severity")"

        local weight="${SEVERITY_WEIGHT[$severity]:-1}"

        case "$status" in
            satisfied)
                satisfied_weight=$((satisfied_weight + weight))
                applicable_weight=$((applicable_weight + weight))
                satisfied_count=$((satisfied_count + 1))
                mb_emit_finding PASS "$severity" "$MB_MODULE" "cis_${id}" \
                    "CIS ${id} satisfied (${key}=${expected})" ""
                ;;
            unsatisfied)
                unsatisfied_weight=$((unsatisfied_weight + weight))
                applicable_weight=$((applicable_weight + weight))
                unsatisfied_count=$((unsatisfied_count + 1))
                mb_emit_finding FAIL "$severity" "$MB_MODULE" "cis_${id}" \
                    "CIS ${id} not satisfied (${key}: expected ${expected})" \
                    "${fix:-See docs/cis-v14.0-mapping.md}"
                ;;
            not_applicable)
                na_count=$((na_count + 1))
                mb_emit_finding WARN info "$MB_MODULE" "cis_${id}" \
                    "CIS ${id} not applicable or not verifiable (${key})" ""
                ;;
        esac
    done

    # Reset arrays for the next chapter.
    CIS_ID=() CIS_KEY=() CIS_EXPECTED=() CIS_SEVERITY=() CIS_FIX=()

    local score=0
    if [[ "$applicable_weight" -gt 0 ]]; then
        score=$((satisfied_weight * 100 / applicable_weight))
    fi

    echo "${score} ${satisfied_count} ${unsatisfied_count} ${na_count} ${total}"
}

# ---------------------------------------------------------------------------
# Main scoring entry point.
# Produces TXT + JSON reports and emits findings.
# ---------------------------------------------------------------------------
mb_lynis_scoring_run() {
    mb_lynis_scoring_install

    local dat
    dat="$(mb_lynis_scoring_run_audit)"
    mb_lynis_scoring_parse "$dat"

    # Ensure report dir exists.
    mb_ensure_dir "$MB_AUDIT_REPORTS_DIR"

    local txt_report="${MB_AUDIT_REPORTS_DIR}/cis-score-latest.txt"
    local json_report="${MB_AUDIT_REPORTS_DIR}/cis-score-latest.json"

    local total_satisfied=0
    local total_unsatisfied=0
    local total_na=0
    local total_controls=0
    local total_satisfied_weight=0
    local total_applicable_weight=0

    # Collect chapter results.
    declare -A CHAPTER_SCORE=()
    declare -A CHAPTER_SATISFIED=()
    declare -A CHAPTER_UNSATISFIED=()
    declare -A CHAPTER_NA=()
    declare -A CHAPTER_TOTAL=()

    for chapter in 1-initial-setup 2-services 3-network 4-logging 5-access 6-system-maintenance; do
        local rules_file="${CHAPTER_FILE[$chapter]}"
        if [[ ! -f "$rules_file" ]]; then
            mb_warn "CIS v14.0 rules file missing for chapter ${chapter}: ${rules_file}"
            continue
        fi
        mb_info "Scoring CIS v14.0 chapter: ${chapter}"
        local result
        result="$(mb_lynis_scoring_score_chapter "$rules_file")"
        # Parse: score satisfied unsatisfied na total
        local score sat uns na tot
        read -r score sat uns na tot <<< "$result"
        CHAPTER_SCORE[$chapter]=$score
        CHAPTER_SATISFIED[$chapter]=$sat
        CHAPTER_UNSATISFIED[$chapter]=$uns
        CHAPTER_NA[$chapter]=$na
        CHAPTER_TOTAL[$chapter]=$tot

        total_satisfied=$((total_satisfied + sat))
        total_unsatisfied=$((total_unsatisfied + uns))
        total_na=$((total_na + na))
        total_controls=$((total_controls + tot))

        # Accumulate weighted totals for the overall score.
        # We re-derive weight from the chapter score: sat_weight/app_weight = score/100.
        # For an exact overall score we recompute from the per-control weights,
        # but the chapter score already encodes the ratio. We approximate by
        # weighting each chapter by its applicable control count.
        local applicable=$((sat + uns))
        if [[ "$applicable" -gt 0 ]]; then
            total_satisfied_weight=$((total_satisfied_weight + score * applicable))
            total_applicable_weight=$((total_applicable_weight + applicable * 100))
        fi
    done

    local overall_score=0
    if [[ "$total_applicable_weight" -gt 0 ]]; then
        overall_score=$((total_satisfied_weight / total_applicable_weight))
    fi

    # Extract Lynis hardening index if present.
    local hardening_index=""
    hardening_index="$(grep -E '^hardening_index=' "$dat" 2>/dev/null | cut -d= -f2 || true)"

    # --- TXT report ---
    {
        printf 'CIS Benchmark v14.0 Compliance Score Report\n'
        printf 'Generated: %s\n' "$(mb_now_iso)"
        printf 'Host: %s\n' "$(mb_hostname)"
        printf '========================================\n\n'
        printf 'Overall Compliance Score: %s/100\n' "$overall_score"
        if [[ -n "$hardening_index" ]]; then
            printf 'Lynis Hardening Index:    %s/100\n' "$hardening_index"
        fi
        printf '\nPer-Chapter Breakdown:\n'
        printf '%-28s %8s %10s %12s %12s %8s\n' \
            "Chapter" "Score" "Satisfied" "Unsatisfied" "N/A" "Total"
        printf '%-28s %8s %10s %12s %12s %8s\n' \
            "-------" "-----" "---------" "-----------" "---" "-----"
        for chapter in 1-initial-setup 2-services 3-network 4-logging 5-access 6-system-maintenance; do
            printf '%-28s %7s/100 %10s %12s %12s %8s\n' \
                "$chapter" \
                "${CHAPTER_SCORE[$chapter]:-0}" \
                "${CHAPTER_SATISFIED[$chapter]:-0}" \
                "${CHAPTER_UNSATISFIED[$chapter]:-0}" \
                "${CHAPTER_NA[$chapter]:-0}" \
                "${CHAPTER_TOTAL[$chapter]:-0}"
        done
        printf '\nSummary:\n'
        printf '  Total controls evaluated: %s\n' "$total_controls"
        printf '  Satisfied:                %s\n' "$total_satisfied"
        printf '  Unsatisfied:              %s\n' "$total_unsatisfied"
        printf '  Not applicable:           %s\n' "$total_na"
        printf '\nRemediation:\n'
        printf "  Run 'sudo mb audit fix' to apply available fixes.\n"
        printf '  See docs/cis-v14.0-mapping.md for the full control mapping.\n'
    } > "$txt_report"

    # --- JSON report ---
    {
        printf '{\n'
        printf '  "benchmark": "CIS Benchmark v14.0",\n'
        printf '  "generated": "%s",\n' "$(mb_now_iso)"
        printf '  "host": "%s",\n' "$(mb_hostname)"
        printf '  "overall_score": %s,\n' "$overall_score"
        if [[ -n "$hardening_index" ]]; then
            printf '  "lynis_hardening_index": %s,\n' "$hardening_index"
        fi
        printf '  "summary": {\n'
        printf '    "total_controls": %s,\n' "$total_controls"
        printf '    "satisfied": %s,\n' "$total_satisfied"
        printf '    "unsatisfied": %s,\n' "$total_unsatisfied"
        printf '    "not_applicable": %s\n' "$total_na"
        printf '  },\n'
        printf '  "chapters": [\n'
        local first=1
        for chapter in 1-initial-setup 2-services 3-network 4-logging 5-access 6-system-maintenance; do
            if [[ $first -eq 0 ]]; then
                printf ',\n'
            fi
            first=0
            printf '    {\n'
            printf '      "chapter": "%s",\n' "$chapter"
            printf '      "score": %s,\n' "${CHAPTER_SCORE[$chapter]:-0}"
            printf '      "satisfied": %s,\n' "${CHAPTER_SATISFIED[$chapter]:-0}"
            printf '      "unsatisfied": %s,\n' "${CHAPTER_UNSATISFIED[$chapter]:-0}"
            printf '      "not_applicable": %s,\n' "${CHAPTER_NA[$chapter]:-0}"
            printf '      "total": %s\n' "${CHAPTER_TOTAL[$chapter]:-0}"
            printf '    }'
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$json_report"

    # Emit an overall summary finding.
    mb_emit_finding PASS info "$MB_MODULE" "cis_v14_overall_score" \
        "CIS v14.0 overall compliance score: ${overall_score}/100" ""
    mb_emit_finding PASS info "$MB_MODULE" "cis_v14_report" \
        "CIS compliance score report written to ${txt_report} and ${json_report}" ""

    mb_ok "CIS v14.0 compliance score: ${overall_score}/100"
    mb_info "TXT report:  ${txt_report}"
    mb_info "JSON report: ${json_report}"

    # Clean up the temp .dat directory.
    rm -f "$dat" 2>/dev/null || true
    rm -rf "$(dirname "$dat")" 2>/dev/null || true
}

# Direct execution.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_lynis_scoring_run
fi
