#!/usr/bin/env bash
# cis-permissions-fix.sh — CIS Benchmark v14.0 file permissions & system maintenance fixes.
# Covers sections 1.1 (filesystem), 1.4 (auditd), 1.8 (banners), 1.9 (time sync),
# 1.10 (cron), 1.11 (sudo), 4.3/4.4 (log & auditd perms), 5.3 (password policy),
# 5.4 (user accounts), 6.1 (file perms), 6.2 (user/group settings).
# Idempotent. Supports --dry-run.
#
# This is a large remediation surface; each flag maps to a specific CIS control
# or group of controls. Only the requested fixes are applied.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

DRY_RUN=0
LOG_FILE="${LOG_FILE:-/var/log/mb-audit/cis-permissions-fix.log}"

usage() {
    cat <<EOF
Usage: sudo cis-permissions-fix.sh [options]
CIS Benchmark v14.0 — file permissions, system maintenance, and account hardening.
Options:
  --dry-run                 Show changes without applying them.
  --all                     Apply a safe subset of permission fixes.
  Filesystem (section 1.1 / 6.1):
  --sticky-bit              Set sticky bit on all world-writable directories.
  --var-perm                Set /var permissions to 755.
  --var-log-perm            Set /var/log permissions to 750.
  --var-log-audit-perm      Set /var/log/audit permissions to 750.
  --home-perm               Set /home permissions to 750.
  --passwd-perm             Set /etc/passwd permissions to 644.
  --passwd-owner            Set /etc/passwd owner to root:root.
  --group-perm              Set /etc/group permissions to 644.
  --group-owner             Set /etc/group owner to root:root.
  --shadow-perm             Set /etc/shadow permissions to 640.
  --shadow-owner            Set /etc/shadow owner to root:shadow.
  --gshadow-perm            Set /etc/gshadow permissions to 640.
  --gshadow-owner           Set /etc/gshadow owner to root:shadow.
  --unowned-files           Find and report unowned files (no auto-chown).
  --ungrouped-files         Find and report ungrouped files (no auto-chown).
  --world-writable-sticky   Set sticky bit on world-writable dirs.
  Cron (section 1.10):
  --cron-perm               Set /etc/crontab permissions to 600.
  --cron-owner              Set /etc/crontab owner to root:root.
  --cron-dir-perm           Set /etc/cron.{hourly,daily,weekly,monthly,d} to 700.
  Sudo (section 1.11 / 5.6):
  --sudoers-perm            Set /etc/sudoers permissions to 440.
  --sudoers-owner           Set /etc/sudoers owner to root:root.
  --sudoers-d-perm          Set /etc/sudoers.d/* permissions to 440.
  --sudo-pty                Configure sudo to use_pty.
  --sudo-log                Configure sudo log file.
  --sudo-no-nopasswd        Remove NOPASSWD from sudoers (review first!).
  Auditd (section 1.4 / 4.4):
  --install-auditd          Install auditd.
  --enable-auditd           Enable and start auditd.
  --auditd-backlog          Set audit backlog limit to 8192.
  --auditd-log-perm         Set audit log file permissions to 600.
  --auditd-dir-perm         Set /var/log/audit permissions to 750.
  Password policy (section 5.3):
  --pass-max-days <n>       Set PASS_MAX_DAYS in /etc/login.defs.
  --pass-min-days <n>       Set PASS_MIN_DAYS.
  --pass-warn-age <n>       Set PASS_WARN_AGE.
  --pass-min-len <n>        Set min password length (via PAM cracklib/pwquality).
  --pass-complexity         Enable password complexity requirements.
  --pass-enforce-root       Enforce password policy for root.
  User accounts (section 5.4 / 6.2):
  --root-home-perm          Set /root permissions to 700.
  --root-rhosts             Remove /root/.rhosts if present.
  --root-netrc              Remove /root/.netrc if present.
  --system-accounts-shell   Set system accounts shell to /usr/sbin/nologin.
  --default-umask           Set default umask to 027.
  --shell-timeout           Set shell idle timeout (TMOUT=900).
  --session-timeout         Configure session lock timeout.
  Banners (section 1.8):
  --motd-banner             Set /etc/motd to a CIS-compliant banner.
  --login-banner            Set /etc/issue to a CIS-compliant banner.
  --remote-banner           Set /etc/issue.net to a CIS-compliant banner.
  --banner-perm             Set banner files permissions to 644.
  --banner-owner            Set banner files owner to root:root.
  Time sync (section 1.9):
  --install-timesync        Install chrony or ntp.
  --enable-timesync         Enable and start the time sync service.
  --configure-timesync      Configure time sync servers.
  Process hardening (section 1.6):
  --disable-core-dumps      Disable core dumps via limits.conf.
  Misc:
  --enable-apparmor         Enable AppArmor.
  --remove-inetd            Remove inetd if installed.
  --disable-avahi           Disable avahi-daemon.
  --disable-cups            Disable cups.
  -h, --help                Show this help.
EOF
}

# Collect requested actions.
declare -A ACTIONS=()
PASS_MAX_DAYS="" PASS_MIN_DAYS="" PASS_WARN_AGE="" PASS_MIN_LEN=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --all)
                ACTIONS[sticky-bit]=1 ACTIONS[var-perm]=1 ACTIONS[var-log-perm]=1
                ACTIONS[passwd-perm]=1 ACTIONS[passwd-owner]=1
                ACTIONS[group-perm]=1 ACTIONS[group-owner]=1
                ACTIONS[shadow-perm]=1 ACTIONS[shadow-owner]=1
                ACTIONS[gshadow-perm]=1 ACTIONS[gshadow-owner]=1
                ACTIONS[cron-perm]=1 ACTIONS[cron-owner]=1 ACTIONS[cron-dir-perm]=1
                ACTIONS[sudoers-perm]=1 ACTIONS[sudoers-owner]=1
                ACTIONS[root-home-perm]=1 ACTIONS[default-umask]=1
                ACTIONS[banner-perm]=1 ACTIONS[banner-owner]=1
                shift ;;
            --sticky-bit) ACTIONS[sticky-bit]=1; shift ;;
            --var-perm) ACTIONS[var-perm]=1; shift ;;
            --var-log-perm) ACTIONS[var-log-perm]=1; shift ;;
            --var-log-audit-perm) ACTIONS[var-log-audit-perm]=1; shift ;;
            --home-perm) ACTIONS[home-perm]=1; shift ;;
            --passwd-perm) ACTIONS[passwd-perm]=1; shift ;;
            --passwd-owner) ACTIONS[passwd-owner]=1; shift ;;
            --group-perm) ACTIONS[group-perm]=1; shift ;;
            --group-owner) ACTIONS[group-owner]=1; shift ;;
            --shadow-perm) ACTIONS[shadow-perm]=1; shift ;;
            --shadow-owner) ACTIONS[shadow-owner]=1; shift ;;
            --gshadow-perm) ACTIONS[gshadow-perm]=1; shift ;;
            --gshadow-owner) ACTIONS[gshadow-owner]=1; shift ;;
            --unowned-files) ACTIONS[unowned-files]=1; shift ;;
            --ungrouped-files) ACTIONS[ungrouped-files]=1; shift ;;
            --world-writable-sticky) ACTIONS[sticky-bit]=1; shift ;;
            --cron-perm) ACTIONS[cron-perm]=1; shift ;;
            --cron-owner) ACTIONS[cron-owner]=1; shift ;;
            --cron-dir-perm) ACTIONS[cron-dir-perm]=1; shift ;;
            --sudoers-perm) ACTIONS[sudoers-perm]=1; shift ;;
            --sudoers-owner) ACTIONS[sudoers-owner]=1; shift ;;
            --sudoers-d-perm) ACTIONS[sudoers-d-perm]=1; shift ;;
            --sudo-pty) ACTIONS[sudo-pty]=1; shift ;;
            --sudo-log) ACTIONS[sudo-log]=1; shift ;;
            --sudo-no-nopasswd) ACTIONS[sudo-no-nopasswd]=1; shift ;;
            --install-auditd) ACTIONS[install-auditd]=1; shift ;;
            --enable-auditd) ACTIONS[enable-auditd]=1; shift ;;
            --auditd-backlog) ACTIONS[auditd-backlog]=1; shift ;;
            --auditd-log-perm) ACTIONS[auditd-log-perm]=1; shift ;;
            --auditd-dir-perm) ACTIONS[auditd-dir-perm]=1; shift ;;
            --pass-max-days) PASS_MAX_DAYS="$2"; ACTIONS[pass-max-days]=1; shift 2 ;;
            --pass-min-days) PASS_MIN_DAYS="$2"; ACTIONS[pass-min-days]=1; shift 2 ;;
            --pass-warn-age) PASS_WARN_AGE="$2"; ACTIONS[pass-warn-age]=1; shift 2 ;;
            --pass-min-len) PASS_MIN_LEN="$2"; ACTIONS[pass-min-len]=1; shift 2 ;;
            --pass-complexity) ACTIONS[pass-complexity]=1; shift ;;
            --pass-enforce-root) ACTIONS[pass-enforce-root]=1; shift ;;
            --root-home-perm) ACTIONS[root-home-perm]=1; shift ;;
            --root-rhosts) ACTIONS[root-rhosts]=1; shift ;;
            --root-netrc) ACTIONS[root-netrc]=1; shift ;;
            --system-accounts-shell) ACTIONS[system-accounts-shell]=1; shift ;;
            --default-umask) ACTIONS[default-umask]=1; shift ;;
            --shell-timeout) ACTIONS[shell-timeout]=1; shift ;;
            --session-timeout) ACTIONS[session-timeout]=1; shift ;;
            --motd-banner) ACTIONS[motd-banner]=1; shift ;;
            --login-banner) ACTIONS[login-banner]=1; shift ;;
            --remote-banner) ACTIONS[remote-banner]=1; shift ;;
            --banner-perm) ACTIONS[banner-perm]=1; shift ;;
            --banner-owner) ACTIONS[banner-owner]=1; shift ;;
            --install-timesync) ACTIONS[install-timesync]=1; shift ;;
            --enable-timesync) ACTIONS[enable-timesync]=1; shift ;;
            --configure-timesync) ACTIONS[configure-timesync]=1; shift ;;
            --disable-core-dumps) ACTIONS[disable-core-dumps]=1; shift ;;
            --enable-apparmor) ACTIONS[enable-apparmor]=1; shift ;;
            --remove-inetd) ACTIONS[remove-inetd]=1; shift ;;
            --disable-avahi) ACTIONS[disable-avahi]=1; shift ;;
            --disable-cups) ACTIONS[disable-cups]=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# Set permissions on a file (idempotent). chmod_perm <path> <mode>
chmod_perm() {
    local path="$1" mode="$2"
    [[ -e "$path" ]] || return 0
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY-RUN]%b chmod %s %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$mode" "$path"
        return
    fi
    chmod "$mode" "$path"
    mb_ok "${path} → ${mode}"
    log_fix "chmod ${mode} ${path}"
}

# Set owner on a file (idempotent). chown_owner <path> <owner:group>
chown_owner() {
    local path="$1" owner="$2"
    [[ -e "$path" ]] || return 0
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY-RUN]%b chown %s %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$owner" "$path"
        return
    fi
    chown "$owner" "$path"
    mb_ok "${path} → ${owner}"
    log_fix "chown ${owner} ${path}"
}

# Set or replace a key=value line in a config file.
set_config_line() {
    local file="$1" key="$2" value="$3"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY-RUN]%b %s: %s=%s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$file" "$key" "$value"
        return
    fi
    mb_backup_file "$file"
    if [[ -f "$file" ]] && grep -qE "^${key}" "$file"; then
        sed -i "s|^${key}.*|${key}${value}|" "$file"
    else
        echo "${key}${value}" >> "$file"
    fi
    mb_ok "${file}: ${key}${value}"
    log_fix "${file}: ${key}${value}"
}

log_fix() {
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    mb_ensure_dir "$(dirname "$LOG_FILE")"
    printf '[%s] %s\n' "$(mb_now_iso)" "$*" >> "$LOG_FILE"
}

# The CIS-compliant login banner text.
CIS_BANNER="Authorized uses only. All activity may be monitored and reported."

main() {
    parse_args "$@"
    mb_require_root

    if [[ ${#ACTIONS[@]} -eq 0 ]]; then
        mb_warn "No actions specified. Run with --help to see options or --all for a safe subset."
        exit 0
    fi

    if [[ "$DRY_RUN" -eq 0 ]]; then
        log_fix "Starting CIS v14.0 permissions/maintenance fixes"
    fi

    # --- Filesystem permissions ---
    [[ -n "${ACTIONS[sticky-bit]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b set sticky bit on world-writable dirs\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            # Find world-writable directories that are not sticky and set the sticky bit.
            local dirs
            dirs="$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null || true)"
            if [[ -n "$dirs" ]]; then
                while IFS= read -r d; do
                    chmod +t "$d" 2>/dev/null || true
                done <<< "$dirs"
                mb_ok "Sticky bit set on world-writable directories"
                log_fix "Set sticky bit on world-writable directories"
            fi
        fi
    }
    [[ -n "${ACTIONS[var-perm]:-}" ]]           && chmod_perm /var 755
    [[ -n "${ACTIONS[var-log-perm]:-}" ]]       && chmod_perm /var/log 750
    [[ -n "${ACTIONS[var-log-audit-perm]:-}" ]] && chmod_perm /var/log/audit 750
    [[ -n "${ACTIONS[home-perm]:-}" ]]          && chmod_perm /home 750
    [[ -n "${ACTIONS[passwd-perm]:-}" ]]        && chmod_perm /etc/passwd 644
    [[ -n "${ACTIONS[passwd-owner]:-}" ]]       && chown_owner /etc/passwd root:root
    [[ -n "${ACTIONS[group-perm]:-}" ]]         && chmod_perm /etc/group 644
    [[ -n "${ACTIONS[group-owner]:-}" ]]        && chown_owner /etc/group root:root
    [[ -n "${ACTIONS[shadow-perm]:-}" ]]        && chmod_perm /etc/shadow 640
    [[ -n "${ACTIONS[shadow-owner]:-}" ]]       && chown_owner /etc/shadow root:shadow
    [[ -n "${ACTIONS[gshadow-perm]:-}" ]]       && chmod_perm /etc/gshadow 640
    [[ -n "${ACTIONS[gshadow-owner]:-}" ]]      && chown_owner /etc/gshadow root:shadow

    [[ -n "${ACTIONS[unowned-files]:-}" ]] && {
        mb_info "Scanning for unowned files (no auto-chown — review output)..."
        find / -xdev -nouser 2>/dev/null | head -50 || true
        log_fix "Scanned for unowned files"
    }
    [[ -n "${ACTIONS[ungrouped-files]:-}" ]] && {
        mb_info "Scanning for ungrouped files (no auto-chown — review output)..."
        find / -xdev -nogroup 2>/dev/null | head -50 || true
        log_fix "Scanned for ungrouped files"
    }

    # --- Cron ---
    [[ -n "${ACTIONS[cron-perm]:-}" ]]   && chmod_perm /etc/crontab 600
    [[ -n "${ACTIONS[cron-owner]:-}" ]]  && chown_owner /etc/crontab root:root
    [[ -n "${ACTIONS[cron-dir-perm]:-}" ]] && {
        for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
            chmod_perm "$d" 700
        done
    }

    # --- Sudo ---
    [[ -n "${ACTIONS[sudoers-perm]:-}" ]]  && chmod_perm /etc/sudoers 440
    [[ -n "${ACTIONS[sudoers-owner]:-}" ]] && chown_owner /etc/sudoers root:root
    [[ -n "${ACTIONS[sudoers-d-perm]:-}" ]] && {
        if [[ -d /etc/sudoers.d ]]; then
            for f in /etc/sudoers.d/*; do
                [[ -f "$f" ]] && chmod_perm "$f" 440
            done
        fi
    }
    [[ -n "${ACTIONS[sudo-pty]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b add Defaults use_pty to /etc/sudoers\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            if ! grep -qE '^Defaults.*use_pty' /etc/sudoers 2>/dev/null; then
                echo "Defaults use_pty" >> /etc/sudoers
                mb_ok "Added 'Defaults use_pty' to /etc/sudoers"
                log_fix "Added Defaults use_pty"
            fi
        fi
    }
    [[ -n "${ACTIONS[sudo-log]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b add Defaults log to /etc/sudoers\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            if ! grep -qE '^Defaults.*logfile' /etc/sudoers 2>/dev/null; then
                echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
                mb_ok "Added sudo log file to /etc/sudoers"
                log_fix "Added Defaults logfile"
            fi
        fi
    }
    [[ -n "${ACTIONS[sudo-no-nopasswd]:-}" ]] && {
        mb_warn "Review NOPASSWD entries before proceeding — removing them may lock out automation."
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b comment out NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/*\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            if [[ -f /etc/sudoers ]]; then
                sed -i 's/NOPASSWD:/# NOPASSWD:/g' /etc/sudoers
                log_fix "Commented NOPASSWD in /etc/sudoers"
            fi
            if [[ -d /etc/sudoers.d ]]; then
                for f in /etc/sudoers.d/*; do
                    [[ -f "$f" ]] && sed -i 's/NOPASSWD:/# NOPASSWD:/g' "$f"
                done
                log_fix "Commented NOPASSWD in /etc/sudoers.d/*"
            fi
            mb_ok "NOPASSWD entries commented out"
        fi
    }

    # --- Auditd ---
    [[ -n "${ACTIONS[install-auditd]:-}" ]] && {
        if ! mb_command_exists auditd; then
            if mb_command_exists apt-get; then
                mb_apply_or_dryrun "$DRY_RUN" "Install auditd" "apt-get update -qq && apt-get install -y auditd"
            elif mb_command_exists dnf; then
                mb_apply_or_dryrun "$DRY_RUN" "Install auditd" "dnf install -y audit"
            fi
            log_fix "Installed auditd"
        fi
    }
    [[ -n "${ACTIONS[enable-auditd]:-}" ]] && {
        if mb_command_exists systemctl; then
            mb_apply_or_dryrun "$DRY_RUN" "Enable auditd" "systemctl enable auditd && systemctl start auditd"
            log_fix "Enabled auditd"
        fi
    }
    [[ -n "${ACTIONS[auditd-backlog]:-}" ]] && {
        local grub="/etc/default/grub"
        if [[ -f "$grub" ]]; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                printf '%b[DRY-RUN]%b add audit=1 audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
            else
                mb_backup_file "$grub"
                if grep -qE '^GRUB_CMDLINE_LINUX=' "$grub"; then
                    if ! grep -q 'audit_backlog_limit' "$grub"; then
                        sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1 audit_backlog_limit=8192"/' "$grub"
                    fi
                fi
                mb_ok "Set audit backlog limit in GRUB"
                log_fix "Set audit_backlog_limit=8192 in GRUB"
            fi
        fi
    }
    [[ -n "${ACTIONS[auditd-log-perm]:-}" ]] && {
        for f in /var/log/audit/audit.log /var/log/audit/audit.log.*; do
            [[ -f "$f" ]] && chmod_perm "$f" 600
        done
    }
    [[ -n "${ACTIONS[auditd-dir-perm]:-}" ]] && {
        chmod_perm /var/log/audit 750
        chown_owner /var/log/audit root:adm
    }

    # --- Password policy ---
    [[ -n "${ACTIONS[pass-max-days]:-}" ]] && set_config_line /etc/login.defs "PASS_MAX_DAYS" " ${PASS_MAX_DAYS}"
    [[ -n "${ACTIONS[pass-min-days]:-}" ]] && set_config_line /etc/login.defs "PASS_MIN_DAYS" " ${PASS_MIN_DAYS}"
    [[ -n "${ACTIONS[pass-warn-age]:-}" ]] && set_config_line /etc/login.defs "PASS_WARN_AGE" " ${PASS_WARN_AGE}"
    [[ -n "${ACTIONS[pass-min-len]:-}" ]] && {
        # Use pam_pwquality or pam_cracklib depending on what's installed.
        local pam_file=""
        if [[ -f /etc/pam.d/common-password ]]; then
            pam_file="/etc/pam.d/common-password"
        elif [[ -f /etc/security/pwquality.conf ]]; then
            set_config_line /etc/security/pwquality.conf "minlen" " = ${PASS_MIN_LEN}"
            log_fix "Set minlen=${PASS_MIN_LEN} in pwquality.conf"
            pam_file=""
        fi
        if [[ -n "$pam_file" ]]; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                printf '%b[DRY-RUN]%b set minlen=%s in %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$PASS_MIN_LEN" "$pam_file"
            else
                mb_backup_file "$pam_file"
                if grep -q 'pam_pwquality' "$pam_file"; then
                    sed -i "s/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=${PASS_MIN_LEN}/" "$pam_file"
                elif grep -q 'pam_cracklib' "$pam_file"; then
                    sed -i "s/pam_cracklib.so.*/pam_cracklib.so retry=3 minlen=${PASS_MIN_LEN}/" "$pam_file"
                fi
                mb_ok "Set minlen=${PASS_MIN_LEN} in ${pam_file}"
                log_fix "Set minlen=${PASS_MIN_LEN}"
            fi
        fi
    }
    [[ -n "${ACTIONS[pass-complexity]:-}" ]] && {
        if [[ -f /etc/security/pwquality.conf ]]; then
            set_config_line /etc/security/pwquality.conf "dcredit" " = -1"
            set_config_line /etc/security/pwquality.conf "ucredit" " = -1"
            set_config_line /etc/security/pwquality.conf "lcredit" " = -1"
            set_config_line /etc/security/pwquality.conf "ocredit" " = -1"
            set_config_line /etc/security/pwquality.conf "minclass" " = 4"
            log_fix "Enabled password complexity in pwquality.conf"
        fi
    }
    [[ -n "${ACTIONS[pass-enforce-root]:-}" ]] && {
        if [[ -f /etc/security/pwquality.conf ]]; then
            set_config_line /etc/security/pwquality.conf "enforce_for_root" " = 1"
            log_fix "Enforced password policy for root"
        fi
    }

    # --- User accounts ---
    [[ -n "${ACTIONS[root-home-perm]:-}" ]] && chmod_perm /root 700
    [[ -n "${ACTIONS[root-rhosts]:-}" ]] && {
        if [[ -f /root/.rhosts ]]; then
            mb_apply_or_dryrun "$DRY_RUN" "Remove /root/.rhosts" "rm -f /root/.rhosts"
            log_fix "Removed /root/.rhosts"
        fi
    }
    [[ -n "${ACTIONS[root-netrc]:-}" ]] && {
        if [[ -f /root/.netrc ]]; then
            mb_apply_or_dryrun "$DRY_RUN" "Remove /root/.netrc" "rm -f /root/.netrc"
            log_fix "Removed /root/.netrc"
        fi
    }
    [[ -n "${ACTIONS[system-accounts-shell]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b set system accounts shell to /usr/sbin/nologin\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            # Set nologin shell for system accounts (UID < 1000) that have a valid login shell.
            while IFS=':' read -r name _ uid _ _ _ shell; do
                if [[ "$uid" -lt 1000 ]] && [[ "$shell" != "/usr/sbin/nologin" ]] && [[ "$shell" != "/bin/false" ]]; then
                    if [[ "$name" != "root" ]] && [[ "$name" != "sync" ]] && [[ "$name" != "halt" ]] && [[ "$name" != "shutdown" ]]; then
                        usermod -s /usr/sbin/nologin "$name" 2>/dev/null || true
                    fi
                fi
            done < /etc/passwd
            mb_ok "System accounts shell set to /usr/sbin/nologin"
            log_fix "Set system accounts shell to nologin"
        fi
    }
    [[ -n "${ACTIONS[default-umask]:-}" ]] && {
        set_config_line /etc/login.defs "UMASK" " 027"
        set_config_line /etc/profile "umask" " 027"
        log_fix "Set default umask to 027"
    }
    [[ -n "${ACTIONS[shell-timeout]:-}" ]] && {
        set_config_line /etc/profile.d/tmout.sh "TMOUT" "900"
        set_config_line /etc/profile.d/tmout.sh "readonly" " TMOUT"
        set_config_line /etc/profile.d/tmout.sh "export" " TMOUT"
        log_fix "Set shell idle timeout to 900s"
    }
    [[ -n "${ACTIONS[session-timeout]:-}" ]] && {
        # Configure systemd logind idle timeout.
        if [[ -d /etc/systemd/logind.conf.d ]]; then
            :
        else
            mb_apply_or_dryrun "$DRY_RUN" "Create logind conf dir" "mkdir -p /etc/systemd/logind.conf.d"
        fi
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b set StopIdleSessionSec=900 in logind\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            printf '[Login]\nStopIdleSessionSec=900\n' > /etc/systemd/logind.conf.d/99-mb-audit.conf
            mb_ok "Set session idle timeout to 900s"
            log_fix "Set StopIdleSessionSec=900"
        fi
    }

    # --- Banners ---
    [[ -n "${ACTIONS[motd-banner]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b write CIS banner to /etc/motd\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            echo "$CIS_BANNER" > /etc/motd
            mb_ok "Set /etc/motd banner"
            log_fix "Set /etc/motd banner"
        fi
    }
    [[ -n "${ACTIONS[login-banner]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b write CIS banner to /etc/issue\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            echo "$CIS_BANNER" > /etc/issue
            mb_ok "Set /etc/issue banner"
            log_fix "Set /etc/issue banner"
        fi
    }
    [[ -n "${ACTIONS[remote-banner]:-}" ]] && {
        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf '%b[DRY-RUN]%b write CIS banner to /etc/issue.net\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        else
            echo "$CIS_BANNER" > /etc/issue.net
            mb_ok "Set /etc/issue.net banner"
            log_fix "Set /etc/issue.net banner"
        fi
    }
    [[ -n "${ACTIONS[banner-perm]:-}" ]] && {
        for f in /etc/motd /etc/issue /etc/issue.net; do
            chmod_perm "$f" 644
        done
    }
    [[ -n "${ACTIONS[banner-owner]:-}" ]] && {
        for f in /etc/motd /etc/issue /etc/issue.net; do
            chown_owner "$f" root:root
        done
    }

    # --- Time sync ---
    [[ -n "${ACTIONS[install-timesync]:-}" ]] && {
        if ! mb_command_exists chronyd && ! mb_command_exists ntpd; then
            if mb_command_exists apt-get; then
                mb_apply_or_dryrun "$DRY_RUN" "Install chrony" "apt-get update -qq && apt-get install -y chrony"
            elif mb_command_exists dnf; then
                mb_apply_or_dryrun "$DRY_RUN" "Install chrony" "dnf install -y chrony"
            fi
            log_fix "Installed time sync daemon"
        fi
    }
    [[ -n "${ACTIONS[enable-timesync]:-}" ]] && {
        if mb_command_exists systemctl; then
            if mb_command_exists chronyd; then
                mb_apply_or_dryrun "$DRY_RUN" "Enable chrony" "systemctl enable chrony && systemctl start chrony"
            elif mb_command_exists ntpd; then
                mb_apply_or_dryrun "$DRY_RUN" "Enable ntp" "systemctl enable ntp && systemctl start ntp"
            fi
            log_fix "Enabled time sync daemon"
        fi
    }
    [[ -n "${ACTIONS[configure-timesync]:-}" ]] && {
        local chrony_conf="/etc/chrony/chrony.conf"
        if [[ -f "$chrony_conf" ]]; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                printf '%b[DRY-RUN]%b configure chrony servers\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
            else
                mb_backup_file "$chrony_conf"
                if ! grep -q 'pool.ntp.org' "$chrony_conf"; then
                    printf 'server 0.pool.ntp.org iburst\nserver 1.pool.ntp.org iburst\nserver 2.pool.ntp.org iburst\n' >> "$chrony_conf"
                fi
                mb_ok "Configured chrony NTP servers"
                log_fix "Configured chrony NTP servers"
            fi
        fi
    }

    # --- Process hardening ---
    [[ -n "${ACTIONS[disable-core-dumps]:-}" ]] && {
        local limits="/etc/security/limits.conf"
        if [[ -f "$limits" ]]; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                printf '%b[DRY-RUN]%b disable core dumps in %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$limits"
            else
                if ! grep -q 'core.*0.*mb-audit' "$limits"; then
                    echo "* hard core 0 # mb-audit CIS" >> "$limits"
                    echo "* soft core 0 # mb-audit CIS" >> "$limits"
                fi
                mb_ok "Core dumps disabled in ${limits}"
                log_fix "Disabled core dumps"
            fi
        fi
    }

    # --- Misc service disabling ---
    [[ -n "${ACTIONS[enable-apparmor]:-}" ]] && {
        if mb_command_exists apparmor_status; then
            if mb_command_exists systemctl; then
                mb_apply_or_dryrun "$DRY_RUN" "Enable AppArmor" "systemctl enable apparmor && systemctl start apparmor"
                log_fix "Enabled AppArmor"
            fi
        else
            mb_warn "AppArmor not installed — install with: sudo apt-get install -y apparmor apparmor-utils"
        fi
    }
    [[ -n "${ACTIONS[remove-inetd]:-}" ]] && {
        if mb_command_exists inetd; then
            if mb_command_exists apt-get; then
                mb_apply_or_dryrun "$DRY_RUN" "Remove inetd" "apt-get remove -y openbsd-inetd inetutils-inetd"
            elif mb_command_exists dnf; then
                mb_apply_or_dryrun "$DRY_RUN" "Remove inetd" "dnf remove -y xinetd"
            fi
            log_fix "Removed inetd"
        fi
    }
    [[ -n "${ACTIONS[disable-avahi]:-}" ]] && {
        if mb_command_exists systemctl && systemctl list-unit-files 2>/dev/null | grep -q avahi-daemon; then
            mb_apply_or_dryrun "$DRY_RUN" "Disable avahi-daemon" "systemctl disable avahi-daemon && systemctl stop avahi-daemon"
            log_fix "Disabled avahi-daemon"
        fi
    }
    [[ -n "${ACTIONS[disable-cups]:-}" ]] && {
        if mb_command_exists systemctl && systemctl list-unit-files 2>/dev/null | grep -q cups; then
            mb_apply_or_dryrun "$DRY_RUN" "Disable cups" "systemctl disable cups && systemctl stop cups"
            log_fix "Disabled cups"
        fi
    }

    if [[ "$DRY_RUN" -eq 0 ]]; then
        log_fix "CIS v14.0 permissions/maintenance fixes complete"
        mb_ok "Permission and maintenance fixes applied. Log: ${LOG_FILE}"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
