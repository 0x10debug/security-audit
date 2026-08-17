#!/usr/bin/env bash
# log-audit.sh — log and file-integrity checks for the mb audit tool.
# Inspects auth logs for suspicious activity and tracks mtime of sensitive
# config files.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="logaudit"

# Locate the auth log (path varies by distro/init system).
_auth_log() {
    for f in /var/log/auth.log /var/log/secure /var/log/syslog; do
        [[ -r "$f" ]] && { echo "$f"; return; }
    done
    echo ""
}

# Time window for log checks (last 24h by default).
LOG_HOURS="${LOG_HOURS:-24}"

# ---------------------------------------------------------------------------
# Failed SSH logins in the last 24h, grouped by source IP.
# ---------------------------------------------------------------------------
log_audit_failed_ssh() {
    local logfile
    logfile="$(_auth_log)"
    if [[ -z "$logfile" ]]; then
        mb_emit_finding WARN info "$MB_MODULE" "failed_ssh" \
            "No readable auth log found — skipping" ""
        return
    fi

    local since
    since="$(date -d "${LOG_HOURS} hours ago" '+%b %e' 2>/dev/null || date -v-${LOG_HOURS}H '+%b %e' 2>/dev/null || echo "")"

    local fails
    fails="$(awk '/Failed password/ && $0 ~ /ssh/ {for(i=1;i<=NF;i++) if($i=="from"){print $(i+1); break}}' "$logfile" 2>/dev/null \
        | sort | uniq -c | sort -rn || true)"

    if [[ -z "$fails" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "failed_ssh" \
            "No failed SSH logins in the last ${LOG_HOURS}h" ""
        return
    fi

    local total
    total="$(echo "$fails" | awk '{s+=$1} END{print s}')"
    local top_ip
    top_ip="$(echo "$fails" | head -1 | awk '{print $2}')"
    local top_count
    top_count="$(echo "$fails" | head -1 | awk '{print $1}')"

    if [[ "$top_count" -ge 50 ]]; then
        mb_emit_finding FAIL high "$MB_MODULE" "failed_ssh" \
            "${total} failed SSH logins in last ${LOG_HOURS}h; top IP ${top_ip} (${top_count} attempts)" \
            "sudo ufw deny from ${top_ip} && sudo apt-get install -y fail2ban"
    elif [[ "$top_count" -ge 10 ]]; then
        mb_emit_finding WARN medium "$MB_MODULE" "failed_ssh" \
            "${total} failed SSH logins in last ${LOG_HOURS}h; top IP ${top_ip} (${top_count} attempts)" \
            "sudo apt-get install -y fail2ban"
    else
        mb_emit_finding PASS info "$MB_MODULE" "failed_ssh" \
            "${total} failed SSH logins in last ${LOG_HOURS}h (low volume)" ""
    fi
}

# ---------------------------------------------------------------------------
# Successful logins from new/unknown IPs.
# ---------------------------------------------------------------------------
log_audit_successful_logins() {
    local logfile
    logfile="$(_auth_log)"
    if [[ -z "$logfile" ]]; then
        mb_emit_finding WARN info "$MB_MODULE" "successful_logins" \
            "No readable auth log found — skipping" ""
        return
    fi

    local logins
    logins="$(awk '/Accepted password|Accepted publickey/ {for(i=1;i<=NF;i++) if($i=="from"){print $(i+1); break}}' "$logfile" 2>/dev/null \
        | sort -u || true)"

    if [[ -z "$logins" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "successful_logins" \
            "No successful SSH logins recorded in auth log" ""
        return
    fi

    local count
    count="$(echo "$logins" | wc -l | tr -d ' ')"
    local ips
    ips="$(echo "$logins" | tr '\n' ' ')"
    mb_emit_finding PASS info "$MB_MODULE" "successful_logins" \
        "${count} unique source IPs with successful logins: ${ips}" \
        "Review these IPs — if any are unfamiliar, investigate immediately"
}

# ---------------------------------------------------------------------------
# sudo usage events.
# ---------------------------------------------------------------------------
log_audit_sudo_usage() {
    local logfile
    logfile="$(_auth_log)"
    if [[ -z "$logfile" ]]; then
        mb_emit_finding WARN info "$MB_MODULE" "sudo_usage" \
            "No readable auth log found — skipping" ""
        return
    fi

    local events
    events="$(grep -c 'sudo:' "$logfile" 2>/dev/null || echo 0)"
    if [[ "$events" -eq 0 ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "sudo_usage" \
            "No sudo events in auth log" ""
    else
        mb_emit_finding PASS info "$MB_MODULE" "sudo_usage" \
            "${events} sudo events in auth log" \
            "Review sudo events for unexpected privilege escalation"
    fi
}

# ---------------------------------------------------------------------------
# User creation/deletion events.
# ---------------------------------------------------------------------------
log_audit_user_changes() {
    local logfile
    logfile="$(_auth_log)"
    if [[ -z "$logfile" ]]; then
        mb_emit_finding WARN info "$MB_MODULE" "user_changes" \
            "No readable auth log found — skipping" ""
        return
    fi

    local added removed
    added="$(grep -cE 'useradd|new user' "$logfile" 2>/dev/null || echo 0)"
    removed="$(grep -cE 'userdel|delete user' "$logfile" 2>/dev/null || echo 0)"

    if [[ "$added" -eq 0 && "$removed" -eq 0 ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "user_changes" \
            "No user creation/deletion events in auth log" ""
    else
        mb_emit_finding WARN high "$MB_MODULE" "user_changes" \
            "${added} user(s) added, ${removed} user(s) removed — verify these were authorized" \
            "Inspect /var/log/auth.log for useradd/userdel entries"
    fi
}

# ---------------------------------------------------------------------------
# crontab modifications.
# ---------------------------------------------------------------------------
log_audit_crontab_changes() {
    local changes=0
    for user_cron in /var/spool/cron/crontabs/* /var/spool/cron/*; do
        [[ -f "$user_cron" ]] || continue
        # Files modified in the last 24h.
        if [[ -n "$(find "$user_cron" -mtime -${LOG_HOURS##* } 2>/dev/null)" ]]; then
            changes=$((changes + 1))
        fi
    done

    if [[ "$changes" -eq 0 ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "crontab_changes" \
            "No crontab modifications in last ${LOG_HOURS}h" ""
    else
        mb_emit_finding WARN medium "$MB_MODULE" "crontab_changes" \
            "${changes} crontab file(s) modified in last ${LOG_HOURS}h — verify authorized" \
            "sudo ls -la /var/spool/cron/ && sudo crontab -l"
    fi
}

# ---------------------------------------------------------------------------
# File integrity: mtime of sensitive files.
# ---------------------------------------------------------------------------
log_audit_file_integrity() {
    local files=(
        /etc/passwd
        /etc/shadow
        /etc/sudoers
        /etc/ssh/sshd_config
    )

    local changed=0
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        local mtime
        mtime="$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null || echo 'unknown')"
        # Flag if modified in the last 24h.
        if [[ -n "$(find "$f" -mtime -1 2>/dev/null)" ]]; then
            mb_emit_finding WARN high "$MB_MODULE" "file_integrity_${f##*/}" \
                "${f} was modified recently (mtime: ${mtime})" \
                "Verify this change was authorized: sudo diff with backup"
            changed=$((changed + 1))
        else
            mb_emit_finding PASS info "$MB_MODULE" "file_integrity_${f##*/}" \
                "${f} mtime: ${mtime}" ""
        fi
    done

    if [[ "$changed" -gt 0 ]]; then
        mb_emit_finding WARN high "$MB_MODULE" "file_integrity_summary" \
            "${changed} sensitive file(s) modified in last 24h" \
            "Run `mb audit baseline` to capture a trusted snapshot"
    fi
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
log_audit_run() {
    log_audit_failed_ssh
    log_audit_successful_logins
    log_audit_sudo_usage
    log_audit_user_changes
    log_audit_crontab_changes
    log_audit_file_integrity
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    log_audit_run
fi
