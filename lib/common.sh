#!/usr/bin/env bash
# common.sh — shared functions and constants for the mb security audit tool
# Part of the 0x10debug VPS tool suite.
set -euo pipefail

# ---------------------------------------------------------------------------
# Version and paths
# ---------------------------------------------------------------------------
MB_AUDIT_VERSION="1.0.0"

# Resolve the directory where this script lives so paths work from anywhere.
MB_AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MB_MODULES_DIR="${MB_AUDIT_DIR}/modules"
MB_RULES_DIR="${MB_AUDIT_DIR}/rules"
MB_FIXES_DIR="${MB_AUDIT_DIR}/fixes"
MB_REPORTS_DIR="${MB_AUDIT_DIR}/reports"
MB_BASELINE_DIR="${MB_AUDIT_DIR}/baseline"

# Runtime output directory (reports are persisted here across runs).
MB_AUDIT_LOG_DIR="/var/log/mb-audit"
MB_AUDIT_REPORTS_DIR="${MB_AUDIT_LOG_DIR}/reports"

# Baseline snapshot location — aligned with vps-bootstrap backup layout.
MB_BASELINE_FILE="/etc/mb-backup/baseline.yaml"

# Cron marker used by schedule.sh so we can find/remove our entries reliably.
MB_CRON_MARKER="# mb-audit-schedule"

# ---------------------------------------------------------------------------
# Colors (only applied when stdout is a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    MB_COLOR_RESET="\033[0m"
    MB_COLOR_RED="\033[0;31m"
    MB_COLOR_GREEN="\033[0;32m"
    MB_COLOR_YELLOW="\033[0;33m"
    MB_COLOR_BLUE="\033[0;34m"
    MB_COLOR_MAGENTA="\033[0;35m"
    MB_COLOR_CYAN="\033[0;36m"
    MB_COLOR_BOLD="\033[1m"
else
    MB_COLOR_RESET=""
    MB_COLOR_RED=""
    MB_COLOR_GREEN=""
    MB_COLOR_YELLOW=""
    MB_COLOR_BLUE=""
    MB_COLOR_MAGENTA=""
    MB_COLOR_CYAN=""
    MB_COLOR_BOLD=""
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
mb_log() {
    # mb_log <level> <message>
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$level" in
        INFO)  printf '%b[%s]%b [INFO]  %s\n' "$MB_COLOR_BLUE" "$ts" "$MB_COLOR_RESET" "$msg" ;;
        WARN)  printf '%b[%s]%b [WARN]  %s\n' "$MB_COLOR_YELLOW" "$ts" "$MB_COLOR_RESET" "$msg" ;;
        ERROR) printf '%b[%s]%b [ERROR] %s\n' "$MB_COLOR_RED" "$ts" "$MB_COLOR_RESET" "$msg" >&2 ;;
        OK)    printf '%b[%s]%b [OK]    %s\n' "$MB_COLOR_GREEN" "$ts" "$MB_COLOR_RESET" "$msg" ;;
        *)     printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" ;;
    esac
}

mb_info()  { mb_log INFO "$*"; }
mb_warn()  { mb_log WARN "$*"; }
mb_error() { mb_log ERROR "$*"; }
mb_ok()    { mb_log OK "$*"; }

# ---------------------------------------------------------------------------
# Privilege / capability checks
# ---------------------------------------------------------------------------
mb_require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        mb_error "This command requires root privileges. Re-run with sudo."
        exit 1
    fi
}

mb_command_exists() {
    # mb_command_exists <name> → returns 0 if installed, 1 otherwise.
    command -v "$1" >/dev/null 2>&1
}

mb_ensure_dir() {
    # mb_ensure_dir <path>
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || {
            mb_error "Failed to create directory: $dir"
            return 1
        }
    fi
}

# ---------------------------------------------------------------------------
# Backup helpers (used by fix scripts)
# ---------------------------------------------------------------------------
mb_backup_file() {
    # mb_backup_file <file> → copies to <file>.mb.bak.<timestamp>
    local file="$1"
    [[ -f "$file" ]] || return 0
    local ts
    ts="$(date '+%Y%m%d%H%M%S')"
    cp -a "$file" "${file}.mb.bak.${ts}"
    mb_info "Backed up ${file} → ${file}.mb.bak.${ts}"
}

mb_apply_or_dryrun() {
    # mb_apply_or_dryrun <dry_run_flag> <description> <command...>
    # When dry_run is "1", prints the command instead of executing it.
    local dry_run="$1"; shift
    local desc="$1"; shift
    if [[ "$dry_run" == "1" ]]; then
        printf '%b[DRY-RUN]%b %s\n  → %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$desc" "$*"
    else
        mb_info "$desc"
        eval "$*"
    fi
}

# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------
mb_confirm() {
    # mb_confirm <prompt> → returns 0 on yes, 1 on no. Auto-yes when non-tty.
    local prompt="$1"
    if [[ ! -t 0 ]]; then
        return 0
    fi
    read -r -p "$(printf '%b%s%b [y/N] ' "$MB_COLOR_BOLD" "$prompt" "$MB_COLOR_RESET")" ans
    [[ "${ans:-}" =~ ^[Yy]$ ]]
}

mb_press_enter() {
    if [[ -t 0 ]]; then
        read -r -p "Press Enter to continue..." _
    fi
}

# ---------------------------------------------------------------------------
# Audit finding helpers
# ---------------------------------------------------------------------------
# Findings are emitted as pipe-delimited records:
#   STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX_COMMAND
# STATUS ∈ PASS|FAIL|WARN
# SEVERITY ∈ info|low|medium|high|critical
mb_emit_finding() {
    # mb_emit_finding <status> <severity> <module> <check> <message> <fix_command>
    printf '%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6"
}

# Count findings in a results file by status.
mb_count_findings() {
    # mb_count_findings <file> <status>
    local file="$1" status="$2"
    [[ -f "$file" ]] || { echo 0; return; }
    grep -c "^${status}|" "$file" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# Rule file loader — parses key=value .rules files into an associative array
# ---------------------------------------------------------------------------
mb_load_rules() {
    # mb_load_rules <rules_file> <assoc_array_name>
    local rules_file="$1"
    local arr_name="$2"
    [[ -f "$rules_file" ]] || { mb_error "Rules file not found: $rules_file"; return 1; }
    while IFS='=' read -r key value; do
        # Skip comments and blank lines.
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${key// }" ]] && continue
        # Trim whitespace.
        key="${key// }"
        value="${value# }"; value="${value% }"
        # shellcheck disable=SC2229
        printf -v "${arr_name}[$key]" '%s' "$value"
    done < "$rules_file"
}

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
mb_hostname() {
    hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown"
}

mb_now_iso() {
    date '+%Y-%m-%dT%H:%M:%S%z'
}

mb_now_date() {
    date '+%Y-%m-%d'
}

# Ensure the runtime report directory exists before any module writes to it.
mb_ensure_dir "$MB_AUDIT_REPORTS_DIR" 2>/dev/null || true
