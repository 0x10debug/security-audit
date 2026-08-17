#!/usr/bin/env bash
# report-generator.sh — collect findings from all modules and emit
# HTML + JSON reports plus a terminal summary.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

TEMPLATE="${MB_REPORTS_DIR}/template.html"

# ---------------------------------------------------------------------------
# mb_report_generate <findings_file>
# Reads the pipe-delimited findings file and writes:
#   /var/log/mb-audit/reports/audit-<timestamp>.html
#   /var/log/mb-audit/reports/audit-<timestamp>.json
# Also prints a terminal summary and updates a "latest" symlink.
# ---------------------------------------------------------------------------
mb_report_generate() {
    local findings_file="$1"
    [[ -f "$findings_file" ]] || { mb_error "Findings file not found: $findings_file"; return 1; }

    mb_ensure_dir "$MB_AUDIT_REPORTS_DIR"

    local ts host
    ts="$(date '+%Y%m%d%H%M%S')"
    host="$(mb_hostname)"

    local html_out json_out
    html_out="${MB_AUDIT_REPORTS_DIR}/audit-${ts}.html"
    json_out="${MB_AUDIT_REPORTS_DIR}/audit-${ts}.json"

    # Counts.
    local total pass fail warn
    total="$(wc -l < "$findings_file" | tr -d ' ')"
    pass="$(mb_count_findings "$findings_file" PASS)"
    fail="$(mb_count_findings "$findings_file" FAIL)"
    warn="$(mb_count_findings "$findings_file" WARN)"

    # --- Build JSON ---
    _build_json "$findings_file" "$host" "$ts" "$total" "$pass" "$fail" "$warn" > "$json_out"

    # --- Build HTML ---
    _build_html "$findings_file" "$host" "$ts" "$total" "$pass" "$fail" "$warn" > "$html_out"

    # Update "latest" symlink.
    ln -sf "$(basename "$html_out")" "${MB_AUDIT_REPORTS_DIR}/audit-latest.html"
    ln -sf "$(basename "$json_out")" "${MB_AUDIT_REPORTS_DIR}/audit-latest.json"

    # Write a status file for `mb audit status`.
    cat > "${MB_AUDIT_REPORTS_DIR}/status.txt" <<EOF
last_run=${ts}
hostname=${host}
total=${total}
pass=${pass}
fail=${fail}
warn=${warn}
html=${html_out}
json=${json_out}
EOF

    # --- Terminal summary ---
    _print_summary "$host" "$ts" "$total" "$pass" "$fail" "$warn" "$html_out" "$json_out"
}

# ---------------------------------------------------------------------------
# JSON builder
# ---------------------------------------------------------------------------
_build_json() {
    local findings_file="$1" host="$2" ts="$3" total="$4" pass="$5" fail="$6" warn="$7"
    cat <<EOF
{
  "hostname": "${host}",
  "timestamp": "${ts}",
  "version": "${MB_AUDIT_VERSION}",
  "summary": {
    "total": ${total:-0},
    "pass": ${pass:-0},
    "fail": ${fail:-0},
    "warn": ${warn:-0}
  },
  "findings": [
EOF
    local first=1
    while IFS='|' read -r status severity module check message fix; do
        [[ $first -eq 1 ]] || printf ',\n'
        first=0
        printf '    {"status":"%s","severity":"%s","module":"%s","check":"%s","message":"%s","fix":"%s"}' \
            "$status" "$severity" "$module" "$check" \
            "$(printf '%s' "$message" | sed 's/"/\\"/g')" \
            "$(printf '%s' "$fix" | sed 's/"/\\"/g')"
    done < "$findings_file"
    printf '\n  ]\n}\n'
}

# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------
_build_html() {
    local findings_file="$1" host="$2" ts="$3" total="$4" pass="$5" fail="$6" warn="$7"
    [[ -f "$TEMPLATE" ]] || { mb_error "Template missing: $TEMPLATE"; return 1; }

    local tpl
    tpl="$(cat "$TEMPLATE")"

    # Substitute header placeholders.
    tpl="${tpl//\{\{HOSTNAME\}\}/$host}"
    tpl="${tpl//\{\{AUDIT_DATE\}\}/$ts}"
    tpl="${tpl//\{\{VERSION\}\}/$MB_AUDIT_VERSION}"
    tpl="${tpl//\{\{TOTAL\}\}/$total}"
    tpl="${tpl//\{\{PASS\}\}/$pass}"
    tpl="${tpl//\{\{FAIL\}\}/$fail}"
    tpl="${tpl//\{\{WARN\}\}/$warn}"

    # Group findings by module.
    local modules
    modules="$(awk -F'|' '{print $3}' "$findings_file" | sort -u)"

    local sections=""
    while IFS= read -r mod; do
        [[ -z "$mod" ]] && continue
        local mod_rows=""
        while IFS='|' read -r status severity module check message fix; do
            [[ "$module" != "$mod" ]] && continue
            local esc_msg esc_fix
            esc_msg="$(printf '%s' "$message" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"
            esc_fix="$(printf '%s'  "$fix"     | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"
            mod_rows+="    <tr>"
            mod_rows+="<td><span class=\"badge ${status}\">${status}</span></td>"
            mod_rows+="<td class=\"sev ${severity}\">${severity}</td>"
            mod_rows+="<td class=\"check\">${check}</td>"
            mod_rows+="<td>${esc_msg}</td>"
            mod_rows+="<td class=\"fix\">${esc_fix}</td>"
            mod_rows+="</tr>\n"
        done < "$findings_file"

        sections+="<section>\n  <h2>${mod}</h2>\n  <table>\n"
        sections+="    <thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Message</th><th>Fix Command</th></tr></thead>\n"
        sections+="    <tbody>\n${mod_rows}    </tbody>\n  </table>\n</section>\n"
    done <<< "$modules"

    # Inject sections.
    tpl="${tpl//\{\{MODULE_SECTIONS\}\}/$sections}"

    printf '%s' "$tpl"
}

# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------
_print_summary() {
    local host="$1" ts="$2" total="$3" pass="$4" fail="$5" warn="$6" html="$7" json="$8"
    printf '\n%b═══════════════════════════════════════════════════════════%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '%b VPS Security Audit Summary%b\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    printf '═══════════════════════════════════════════════════════════\n'
    printf '  Host:    %s\n' "$host"
    printf '  Date:    %s\n' "$ts"
    printf '  Total:   %s\n' "$total"
    printf '  %bPASS:%b  %s\n' "$MB_COLOR_GREEN"  "$MB_COLOR_RESET" "$pass"
    printf '  %bFAIL:%b  %s\n' "$MB_COLOR_RED"    "$MB_COLOR_RESET" "$fail"
    printf '  %bWARN:%b  %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$warn"
    printf '═══════════════════════════════════════════════════════════\n'
    printf '  HTML report: %s\n' "$html"
    printf '  JSON report: %s\n' "$json"
    printf '  Open report: mb audit report\n'
    printf '  Apply fixes: sudo mb audit fix\n'
    printf '%b═══════════════════════════════════════════════════════════%b\n\n' "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        mb_error "Usage: report-generator.sh <findings_file>"
        exit 1
    fi
    mb_report_generate "$1"
fi
