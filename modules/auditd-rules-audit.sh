#!/usr/bin/env bash
# auditd-rules-audit.sh — auditd rules security audit for the mb tool.
#
# Read-only audit of auditd (Linux Audit Daemon) configuration and rules.
# Checks auditd service status, rule coverage for critical events (login,
# privilege escalation, file integrity, network changes, module loading),
# log configuration (retention, rotation, remote logging), and rule
# consistency against CIS Benchmark recommendations.
#
# Outputs:
#   - TXT report:  /var/log/auditd-audit/auditd-audit-latest.txt
#   - JSON report: /var/log/auditd-audit/auditd-audit-latest.json
#   - Pipe-delimited findings (consumed by the standard report generator)
#
# This module is strictly read-only: it never modifies auditd configuration.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="auditd"

# Dedicated report directory for auditd audit artefacts.
AUDITD_REPORT_DIR="${AUDITD_REPORT_DIR:-/var/log/auditd-audit}"

# auditd configuration files
AUDITD_CONF="${AUDITD_CONF:-/etc/audit/auditd.conf}"
AUDIT_RULES_DIR="${AUDIT_RULES_DIR:-/etc/audit/rules.d}"
AUDIT_RULES_FILE="${AUDIT_RULES_FILE:-/etc/audit/audit.rules}"

# Counters for the summary (PASS/FAIL/WARN/SKIP).
_ad_pass=0
_ad_fail=0
_ad_warn=0
_ad_skip=0

# Collected findings for the JSON report (STATUS|SEVERITY|CHECK|MESSAGE).
_ad_findings=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Emit a finding and track counters.
# Usage: _ad_emit <status> <severity> <check> <message> <fix>
_ad_emit() {
    local status="$1" severity="$2" check="$3" message="$4" fix="$5"
    mb_emit_finding "$status" "$severity" "$MB_MODULE" "$check" "$message" "$fix"
    case "$status" in
        PASS) _ad_pass=$((_ad_pass + 1)) ;;
        FAIL) _ad_fail=$((_ad_fail + 1)) ;;
        WARN) _ad_warn=$((_ad_warn + 1)) ;;
        SKIP) _ad_skip=$((_ad_skip + 1)) ;;
    esac
    _ad_findings+=("${status}|${severity}|${check}|${message}")
}

# Get all active audit rules as a single string for pattern matching.
_ad_get_rules() {
    if mb_command_exists auditctl; then
        auditctl -l 2>/dev/null || echo ""
    else
        # Fall back to reading rules files
        if [[ -d "$AUDIT_RULES_DIR" ]]; then
            cat "$AUDIT_RULES_DIR"/*.rules 2>/dev/null || echo ""
        elif [[ -f "$AUDIT_RULES_FILE" ]]; then
            cat "$AUDIT_RULES_FILE" 2>/dev/null || echo ""
        else
            echo ""
        fi
    fi
}

# Check if a specific audit rule pattern exists.
_ad_has_rule() {
    local pattern="$1"
    local rules
    rules=$(_ad_get_rules)
    echo "$rules" | grep -qi "$pattern"
}

# ---------------------------------------------------------------------------
# Service Status Checks
# ---------------------------------------------------------------------------

ad_audit_service() {
    mb_info "Auditing auditd service status..."

    # Check if auditd is installed
    if ! mb_command_exists auditctl && ! mb_command_exists auditd; then
        _ad_emit "SKIP" "info" "AUDITD-001" "auditd not installed on this system" "Install auditd: apt install auditd / yum install audit / dnf install audit"
        return
    fi

    # Check if auditd service is running
    if systemctl is-active --quiet auditd 2>/dev/null; then
        _ad_emit "PASS" "info" "AUDITD-002" "auditd service is running" ""
    else
        _ad_emit "FAIL" "high" "AUDITD-002" "auditd service is not running" "Start auditd: systemctl start auditd && systemctl enable auditd"
    fi

    # Check if auditd is enabled on boot
    if systemctl is-enabled --quiet auditd 2>/dev/null; then
        _ad_emit "PASS" "info" "AUDITD-003" "auditd is enabled on boot" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-003" "auditd is not enabled on boot" "Enable auditd: systemctl enable auditd"
    fi

    # Check audit kernel support
    local audit_enabled
    audit_enabled=$(auditctl -s 2>/dev/null | grep "enabled" | awk '{print $2}' || echo "")
    if [[ "$audit_enabled" == "1" ]] || [[ "$audit_enabled" == "2" ]]; then
        _ad_emit "PASS" "info" "AUDITD-004" "Kernel audit is enabled ($audit_enabled)" ""
    elif [[ -n "$audit_enabled" ]]; then
        _ad_emit "FAIL" "high" "AUDITD-004" "Kernel audit is disabled" "Enable audit: auditctl -e 1"
    else
        _ad_emit "WARN" "medium" "AUDITD-004" "Cannot determine kernel audit status" "Check: auditctl -s"
    fi
}

# ---------------------------------------------------------------------------
# Login & Authentication Audit Rules (CIS 4.1.x)
# ---------------------------------------------------------------------------

ad_audit_login_rules() {
    mb_info "Auditing login/authentication audit rules..."

    # CIS 4.1.3: Login events should be audited
    if _ad_has_rule '/var/log/faillog\|/var/log/lastlog\|/var/run/faillock'; then
        _ad_emit "PASS" "info" "AUDITD-101" "Login events are audited" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-101" "Login events are not audited" "Add: -w /var/log/faillog -p wa -k logins"
    fi

    # CIS 4.1.4: Session modification events
    if _ad_has_rule '/var/run/utmp\|/var/log/wtmp\|/var/log/btmp'; then
        _ad_emit "PASS" "info" "AUDITD-102" "Session modification events are audited" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-102" "Session modification events are not audited" "Add: -w /var/run/utmp -p wa -k session"
    fi

    # CIS 4.1.5: Group modification events
    if _ad_has_rule '/etc/group'; then
        _ad_emit "PASS" "info" "AUDITD-103" "Group file modifications are audited" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-103" "Group file modifications are not audited" "Add: -w /etc/group -p wa -k identity"
    fi

    # CIS 4.1.6: Password modification events
    if _ad_has_rule '/etc/passwd'; then
        _ad_emit "PASS" "info" "AUDITD-104" "Password file modifications are audited" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-104" "Password file modifications are not audited" "Add: -w /etc/passwd -p wa -k identity"
    fi

    # CIS 4.1.7: Shadow file modification
    if _ad_has_rule '/etc/shadow'; then
        _ad_emit "PASS" "info" "AUDITD-105" "Shadow file modifications are audited" ""
    else
        _ad_emit "FAIL" "high" "AUDITD-105" "Shadow file modifications are not audited" "Add: -w /etc/shadow -p wa -k identity"
    fi

    # CIS 4.1.8: Gshadow file modification
    if _ad_has_rule '/etc/gshadow'; then
        _ad_emit "PASS" "info" "AUDITD-106" "Gshadow file modifications are audited" ""
    else
        _ad_emit "WARN" "low" "AUDITD-106" "Gshadow file modifications are not audited" "Add: -w /etc/gshadow -p wa -k identity"
    fi

    # CIS 4.1.9: sudoers modification
    if _ad_has_rule '/etc/sudoers'; then
        _ad_emit "PASS" "info" "AUDITD-107" "sudoers file modifications are audited" ""
    else
        _ad_emit "FAIL" "high" "AUDITD-107" "sudoers file modifications are not audited" "Add: -w /etc/sudoers -p wa -k scope"
    fi

    # CIS 4.1.10: sudoers directory modification
    if _ad_has_rule '/etc/sudoers.d'; then
        _ad_emit "PASS" "info" "AUDITD-108" "sudoers.d directory modifications are audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-108" "sudoers.d directory modifications are not audited" "Add: -w /etc/sudoers.d -p wa -k scope"
    fi
}

# ---------------------------------------------------------------------------
# Privilege Escalation Audit Rules (CIS 4.1.x)
# ---------------------------------------------------------------------------

ad_audit_privilege_rules() {
    mb_info "Auditing privilege escalation audit rules..."

    # CIS 4.1.11: setuid/setgid binary execution
    # Check for setuid binary monitoring (at least one of the common paths)
    if _ad_has_rule 'setuid\|setgid\|perm=setuid\|perm=setgid'; then
        _ad_emit "PASS" "info" "AUDITD-201" "setuid/setgid binary execution is audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-201" "setuid/setgid binary execution is not audited" "Add: -a always,exit -F arch=b64 -S setuid -S setgid -k privilege"
    fi

    # CIS 4.1.14: chown/fchmod/lchown system calls
    if _ad_has_rule 'chown\|fchmod\|lchown\|fchown'; then
        _ad_emit "PASS" "info" "AUDITD-202" "File permission change syscalls are audited" ""
    else
        _ad_emit "WARN" "low" "AUDITD-202" "File permission change syscalls are not audited" "Add: -a always,exit -F arch=b64 -S chown -S fchmod -k perm_mod"
    fi

    # CIS 4.1.15: User/group creation events
    if _ad_has_rule 'useradd\|usermod\|userdel\|groupadd\|groupmod\|groupdel'; then
        _ad_emit "PASS" "info" "AUDITD-203" "User/group management commands are audited" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-203" "User/group management commands are not audited" "Add: -w /usr/sbin/useradd -p x -k user_modification"
    fi

    # CIS 4.1.16: su command usage
    if _ad_has_rule '/bin/su\|/usr/bin/su'; then
        _ad_emit "PASS" "info" "AUDITD-204" "su command usage is audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-204" "su command usage is not audited" "Add: -w /usr/bin/su -p x -k privileged"
    fi

    # CIS 4.1.17: sudo command usage
    if _ad_has_rule '/bin/sudo\|/usr/bin/sudo'; then
        _ad_emit "PASS" "info" "AUDITD-205" "sudo command usage is audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-205" "sudo command usage is not audited" "Add: -w /usr/bin/sudo -p x -k privileged"
    fi

    # CIS 4.1.18: passwd command usage
    if _ad_has_rule '/bin/passwd\|/usr/bin/passwd'; then
        _ad_emit "PASS" "info" "AUDITD-206" "passwd command usage is audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-206" "passwd command usage is not audited" "Add: -w /usr/bin/passwd -p x -k privileged"
    fi
}

# ---------------------------------------------------------------------------
# Network & System Configuration Audit Rules (CIS 4.1.x)
# ---------------------------------------------------------------------------

ad_audit_network_rules() {
    mb_info "Auditing network/system configuration audit rules..."

    # CIS 4.1.19: Network environment modification
    if _ad_has_rule 'sethostname\|setdomainname\|/etc/hosts\|/etc/network\|/etc/resolv.conf'; then
        _ad_emit "PASS" "info" "AUDITD-301" "Network environment modifications are audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-301" "Network environment modifications are not audited" "Add: -w /etc/hosts -p wa -k system-locale"
    fi

    # CIS 4.1.20: AppArmor/SELinux modification
    if _ad_has_rule '/etc/apparmor\|/etc/selinux\|setenforce\|apparmor_parser'; then
        _ad_emit "PASS" "info" "AUDITD-302" "MAC policy modifications are audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-302" "MAC policy modifications are not audited" "Add: -w /etc/apparmor -p wa -k MAC-policy"
    fi

    # CIS 4.1.21: Kernel module loading
    if _ad_has_rule 'init_module\|delete_module\|/sbin/insmod\|/sbin/rmmod\|/sbin/modprobe'; then
        _ad_emit "PASS" "info" "AUDITD-303" "Kernel module loading is audited" ""
    else
        _ad_emit "FAIL" "high" "AUDITD-303" "Kernel module loading is not audited" "Add: -a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
    fi

    # CIS 4.1.22: System time modification
    if _ad_has_rule 'adjtimex\|settimeofday\|clock_settime\|/etc/localtime'; then
        _ad_emit "PASS" "info" "AUDITD-304" "System time modifications are audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-304" "System time modifications are not audited" "Add: -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
    fi

    # CIS 4.1.23: Cron configuration modification
    if _ad_has_rule '/etc/cron\|/var/spool/cron\|/etc/crontab'; then
        _ad_emit "PASS" "info" "AUDITD-305" "Cron configuration modifications are audited" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-305" "Cron configuration modifications are not audited" "Add: -w /etc/cron.d -p wa -k cron"
    fi
}

# ---------------------------------------------------------------------------
# Log Configuration Checks
# ---------------------------------------------------------------------------

ad_audit_log_config() {
    mb_info "Auditing auditd log configuration..."

    if [[ ! -f "$AUDITD_CONF" ]]; then
        _ad_emit "WARN" "medium" "AUDITD-401" "auditd.conf not found at $AUDITD_CONF" "Install auditd or check config path"
        return
    fi

    # Log file location
    local log_file
    log_file=$(grep -E '^\s*log_file\s*=' "$AUDITD_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "")
    if [[ -n "$log_file" ]]; then
        _ad_emit "PASS" "info" "AUDITD-401" "Audit log file: $log_file" ""
    else
        _ad_emit "WARN" "low" "AUDITD-401" "Audit log file not configured (default: /var/log/audit/audit.log)" "Set log_file in auditd.conf"
    fi

    # Max log file size
    local max_size
    max_size=$(grep -E '^\s*max_log_file\s*=' "$AUDITD_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "")
    if [[ -n "$max_size" ]] && [[ "$max_size" -ge 8 ]]; then
        _ad_emit "PASS" "info" "AUDITD-402" "Max log file size: ${max_size}MB" ""
    elif [[ -n "$max_size" ]]; then
        _ad_emit "WARN" "low" "AUDITD-402" "Max log file size is ${max_size}MB (recommend 8MB+)" "Set max_log_file = 8 or higher"
    else
        _ad_emit "WARN" "low" "AUDITD-402" "Max log file size not configured" "Set max_log_file in auditd.conf"
    fi

    # Log rotation policy
    local action
    action=$(grep -E '^\s*max_log_file_action\s*=' "$AUDITD_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "")
    if [[ "$action" == "rotate" ]] || [[ "$action" == "keep_logs" ]]; then
        _ad_emit "PASS" "info" "AUDITD-403" "Log rotation action: $action" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-403" "Log rotation action: ${action:-not set} (recommend rotate or keep_logs)" "Set max_log_file_action = rotate"
    fi

    # Number of rotated logs
    local num_logs
    num_logs=$(grep -E '^\s*num_logs\s*=' "$AUDITD_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "")
    if [[ -n "$num_logs" ]] && [[ "$num_logs" -ge 5 ]]; then
        _ad_emit "PASS" "info" "AUDITD-404" "Number of rotated logs: $num_logs" ""
    elif [[ -n "$num_logs" ]]; then
        _ad_emit "WARN" "low" "AUDITD-404" "Number of rotated logs: $num_logs (recommend 5+)" "Set num_logs = 5 or higher"
    else
        _ad_emit "WARN" "low" "AUDITD-404" "Number of rotated logs not configured" "Set num_logs in auditd.conf"
    fi

    # Disk full action
    local disk_full
    disk_full=$(grep -E '^\s*disk_full_action\s*=' "$AUDITD_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "")
    if [[ "$disk_full" == "halt" ]] || [[ "$disk_full" == "single" ]]; then
        _ad_emit "PASS" "info" "AUDITD-405" "Disk full action: $disk_full" ""
    elif [[ -n "$disk_full" ]]; then
        _ad_emit "WARN" "medium" "AUDITD-405" "Disk full action: $disk_full (recommend halt or single)" "Set disk_full_action = halt"
    else
        _ad_emit "WARN" "medium" "AUDITD-405" "Disk full action not configured" "Set disk_full_action = halt in auditd.conf"
    fi

    # Space left action
    local space_left
    space_left=$(grep -E '^\s*space_left\s*=' "$AUDITD_CONF" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "")
    if [[ -n "$space_left" ]] && [[ "$space_left" -ge 50 ]]; then
        _ad_emit "PASS" "info" "AUDITD-406" "Space left threshold: ${space_left}MB" ""
    else
        _ad_emit "WARN" "low" "AUDITD-406" "Space left threshold: ${space_left:-not set} (recommend 50MB+)" "Set space_left = 50"
    fi

    # Remote logging (optional but recommended)
    if grep -qiE '^\s*active\s*=\s*yes' "$AUDITD_CONF" 2>/dev/null && grep -qi 'name_format' "$AUDITD_CONF" 2>/dev/null; then
        _ad_emit "PASS" "info" "AUDITD-407" "Remote audit logging appears configured" ""
    else
        _ad_emit "WARN" "low" "AUDITD-407" "Remote audit logging not configured (optional but recommended for centralized logging)" "Configure audispd or auditbeat for remote logging"
    fi
}

# ---------------------------------------------------------------------------
# Rule File Checks
# ---------------------------------------------------------------------------

ad_audit_rule_files() {
    mb_info "Auditing audit rule files..."

    # Check if rules.d directory exists
    if [[ -d "$AUDIT_RULES_DIR" ]]; then
        local rule_files
        rule_files=$(find "$AUDIT_RULES_DIR" -name "*.rules" 2>/dev/null | wc -l || echo 0)
        if [[ "$rule_files" -gt 0 ]]; then
            _ad_emit "PASS" "info" "AUDITD-501" "Found $rule_files audit rule files in $AUDIT_RULES_DIR" ""
        else
            _ad_emit "FAIL" "medium" "AUDITD-501" "No .rules files found in $AUDIT_RULES_DIR" "Create audit rules in /etc/audit/rules.d/"
        fi
    elif [[ -f "$AUDIT_RULES_FILE" ]]; then
        _ad_emit "PASS" "info" "AUDITD-501" "Audit rules file exists: $AUDIT_RULES_FILE" ""
    else
        _ad_emit "FAIL" "medium" "AUDITD-501" "No audit rules directory or file found" "Create /etc/audit/rules.d/ with audit rules"
    fi

    # Check for immutable rules (-e 2)
    if _ad_has_rule '^\-e 2\|^-e\s*2'; then
        _ad_emit "PASS" "info" "AUDITD-502" "Audit rules are set to immutable (-e 2)" ""
    else
        _ad_emit "WARN" "medium" "AUDITD-502" "Audit rules are not immutable (can be modified at runtime)" "Add -e 2 at end of rules to make them immutable (requires reboot to change)"
    fi

    # Check for buffer size
    if _ad_has_rule '^\-b\|^-b\s'; then
        _ad_emit "PASS" "info" "AUDITD-503" "Audit buffer size is configured" ""
    else
        _ad_emit "WARN" "low" "AUDITD-503" "Audit buffer size not explicitly configured" "Add -b 8192 to rules for adequate buffer"
    fi

    # Check for failure mode (-f)
    if _ad_has_rule '^\-f 2\|^-f\s*2'; then
        _ad_emit "PASS" "info" "AUDITD-504" "Audit failure mode is set to panic (-f 2)" ""
    elif _ad_has_rule '^\-f 1\|^-f\s*1'; then
        _ad_emit "WARN" "low" "AUDITD-504" "Audit failure mode is set to warn (-f 1, recommend -f 2)" "Change -f 1 to -f 2 for stricter failure handling"
    else
        _ad_emit "WARN" "medium" "AUDITD-504" "Audit failure mode not configured" "Add -f 2 to rules to panic on audit failure"
    fi

    # Count total rules
    local total_rules
    total_rules=$(_ad_get_rules | grep -c '^-w\|^-a' || echo 0)
    if [[ "$total_rules" -ge 20 ]]; then
        _ad_emit "PASS" "info" "AUDITD-505" "Comprehensive audit rules ($total_rules rules)" ""
    elif [[ "$total_rules" -ge 10 ]]; then
        _ad_emit "WARN" "low" "AUDITD-505" "Moderate audit rule coverage ($total_rules rules, recommend 20+)" "Add more audit rules for comprehensive coverage"
    elif [[ "$total_rules" -gt 0 ]]; then
        _ad_emit "FAIL" "medium" "AUDITD-505" "Minimal audit rule coverage ($total_rules rules)" "Add comprehensive audit rules per CIS Benchmark"
    else
        _ad_emit "FAIL" "high" "AUDITD-505" "No audit rules configured" "Install CIS-compliant audit rules"
    fi
}

# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

_ad_generate_txt_report() {
    local out="$1"
    {
        printf 'auditd Security Audit Report\n'
        printf 'CIS Benchmark auditd Rules Assessment\n'
        printf 'Generated: %s\n' "$(mb_now_iso)"
        printf 'Host: %s\n' "$(mb_hostname)"
        printf '========================================\n\n'

        printf 'Summary:\n'
        printf '  PASS: %s\n' "$_ad_pass"
        printf '  FAIL: %s\n' "$_ad_fail"
        printf '  WARN: %s\n' "$_ad_warn"
        printf '  SKIP: %s\n' "$_ad_skip"
        printf '  Total checks: %s\n' "$((_ad_pass + _ad_fail + _ad_warn + _ad_skip))"
        printf '\n'

        printf 'Findings:\n'
        printf '%-6s %-8s %-20s %s\n' "STAT" "SEV" "CHECK" "MESSAGE"
        printf '%-6s %-8s %-20s %s\n' "----" "---" "-----" "-------"
        for f in "${_ad_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            printf '%-6s %-8s %-20s %s\n' "$status" "$severity" "$check" "$message"
        done
        printf '\n'

        printf 'Notes:\n'
        printf '  This is a read-only audit. No auditd configuration was modified.\n'
        printf '  CIS Benchmark: https://www.cisecurity.org/benchmark/linux\n'
        printf '  Related: vps-bootstrap auditd module, vps-security-enhancement-scripts\n'
    } > "$out"
}

_ad_generate_json_report() {
    local out="$1"
    {
        printf '{\n'
        printf '  "module": "auditd-rules-audit",\n'
        printf '  "benchmark": "CIS Benchmark auditd Rules",\n'
        printf '  "generated": "%s",\n' "$(mb_now_iso)"
        printf '  "host": "%s",\n' "$(mb_hostname)"
        printf '  "summary": {\n'
        printf '    "pass": %s,\n' "$_ad_pass"
        printf '    "fail": %s,\n' "$_ad_fail"
        printf '    "warn": %s,\n' "$_ad_warn"
        printf '    "skip": %s,\n' "$_ad_skip"
        printf '    "total": %s\n' "$((_ad_pass + _ad_fail + _ad_warn + _ad_skip))"
        printf '  },\n'
        printf '  "findings": [\n'
        local first=1
        for f in "${_ad_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            if [[ $first -eq 0 ]]; then
                printf ',\n'
            fi
            first=0
            local esc_msg esc_check
            esc_msg="${message//\\/\\\\}"
            esc_msg="${esc_msg//\"/\\\"}"
            esc_check="${check//\\/\\\\}"
            esc_check="${esc_check//\"/\\\"}"
            printf '    {\n'
            printf '      "status": "%s",\n' "$status"
            printf '      "severity": "%s",\n' "$severity"
            printf '      "check": "%s",\n' "$esc_check"
            printf '      "message": "%s"\n' "$esc_msg"
            printf '    }'
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

mb_audit_auditd() {
    mb_info "Starting auditd rules security audit..."

    # Service status checks
    ad_audit_service

    # If auditd is not installed, skip remaining checks
    if [[ $_ad_skip -gt 0 ]]; then
        mb_warn "auditd not available — skipping rule checks"
    else
        # Login & authentication rules
        ad_audit_login_rules

        # Privilege escalation rules
        ad_audit_privilege_rules

        # Network & system config rules
        ad_audit_network_rules

        # Log configuration
        ad_audit_log_config

        # Rule file checks
        ad_audit_rule_files
    fi

    # Generate reports
    mb_ensure_dir "$AUDITD_REPORT_DIR" 2>/dev/null || AUDITD_REPORT_DIR="/tmp/auditd-audit"
    mb_ensure_dir "$AUDITD_REPORT_DIR" 2>/dev/null || true
    local txt_report="${AUDITD_REPORT_DIR}/auditd-audit-latest.txt"
    local json_report="${AUDITD_REPORT_DIR}/auditd-audit-latest.json"

    _ad_generate_txt_report "$txt_report"
    _ad_generate_json_report "$json_report"

    # Copy into standard mb-audit reports dir
    if [[ -d "$MB_AUDIT_REPORTS_DIR" ]]; then
        cp -f "$txt_report" "${MB_AUDIT_REPORTS_DIR}/auditd-audit-latest.txt" 2>/dev/null || true
        cp -f "$json_report" "${MB_AUDIT_REPORTS_DIR}/auditd-audit-latest.json" 2>/dev/null || true
    fi

    local total=$((_ad_pass + _ad_fail + _ad_warn + _ad_skip))
    mb_ok "auditd audit complete: ${_ad_pass} PASS, ${_ad_fail} FAIL, ${_ad_warn} WARN, ${_ad_skip} SKIP (${total} checks)"
    mb_info "TXT report:  ${txt_report}"
    mb_info "JSON report: ${json_report}"
}

# Allow direct execution: `modules/auditd-rules-audit.sh` → runs all checks.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_audit_auditd
fi
