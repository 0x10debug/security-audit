#!/usr/bin/env bash
# schedule.sh — cron scheduling helpers for the mb security audit tool.
# Part of the 0x10debug VPS tool suite.
set -euo pipefail

# Source common.sh if not already loaded.
if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# The audit command that the cron entry will run.
MB_CRON_CMD="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ${MB_AUDIT_DIR}/mb audit run --quiet >> ${MB_AUDIT_LOG_DIR}/cron.log 2>&1 ${MB_CRON_MARKER}"

# ---------------------------------------------------------------------------
# mb_schedule_daily — create a daily cron entry for the audit.
#   Usage: mb_schedule_daily [--hour <H>] [--minute <M>]
# ---------------------------------------------------------------------------
mb_schedule_daily() {
    mb_require_root

    local hour="3"
    local minute="15"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hour)   hour="$2"; shift 2 ;;
            --minute) minute="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Remove any existing entry first so we don't duplicate.
    mb_schedule_remove >/dev/null 2>&1 || true

    local entry="${minute} ${hour} * * * ${MB_CRON_CMD}"

    # Add to the root user's crontab.
    local tmp
    tmp="$(mktemp)"
    crontab -l 2>/dev/null | grep -v "${MB_CRON_MARKER}" > "$tmp" || true
    echo "$entry" >> "$tmp"
    crontab "$tmp"
    rm -f "$tmp"

    mb_ok "Daily audit scheduled at ${hour}:${minute} (system local time)."
    mb_info "Logs will be written to ${MB_AUDIT_LOG_DIR}/cron.log"
}

# ---------------------------------------------------------------------------
# mb_schedule_remove — remove the scheduled audit cron entry.
# ---------------------------------------------------------------------------
mb_schedule_remove() {
    mb_require_root

    if ! crontab -l 2>/dev/null | grep -q "${MB_CRON_MARKER}"; then
        mb_info "No scheduled audit found."
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    crontab -l 2>/dev/null | grep -v "${MB_CRON_MARKER}" > "$tmp" || true
    crontab "$tmp"
    rm -f "$tmp"

    mb_ok "Scheduled audit removed."
}

# ---------------------------------------------------------------------------
# mb_schedule_status — show whether a scheduled audit is active.
# ---------------------------------------------------------------------------
mb_schedule_status() {
    if crontab -l 2>/dev/null | grep -q "${MB_CRON_MARKER}"; then
        local entry
        entry="$(crontab -l 2>/dev/null | grep "${MB_CRON_MARKER}")"
        printf '%bScheduled audit: ACTIVE%b\n' "$MB_COLOR_GREEN" "$MB_COLOR_RESET"
        printf '  Entry: %s\n' "$entry"
    else
        printf '%bScheduled audit: INACTIVE%b\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        printf '  Run "%saudit schedule --daily%s" to enable daily audits.\n' \
            "$MB_COLOR_BOLD" "$MB_COLOR_RESET"
    fi
}
