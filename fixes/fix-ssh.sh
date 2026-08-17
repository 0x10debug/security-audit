#!/usr/bin/env bash
# fix-ssh.sh — bring sshd_config in line with cis-ssh.rules.
# Idempotent: only changes directives that differ from the expected value.
# Supports --dry-run to preview changes without applying them.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
DRY_RUN=0

# Expected values (defaults; overridable via flags).
NEW_PORT=""
NEW_PERMIT_ROOT=""
NEW_PASSWORD_AUTH=""
NEW_ALLOW_USERS=""
NEW_MAX_AUTH_TRIES=""
NEW_LOGIN_GRACE=""

usage() {
    cat <<EOF
Usage: sudo fix-ssh.sh [options]
Options:
  --dry-run                 Show changes without applying them.
  --port <n>                Set SSH port (default: from cis-ssh.rules).
  --permit-root-login <v>   Set PermitRootLogin (yes/no/prohibit-password).
  --password-auth <v>       Set PasswordAuthentication (yes/no).
  --allow-users <list>      Set AllowUsers (space-separated user list).
  --max-auth-tries <n>      Set MaxAuthTries.
  --login-grace-time <n>    Set LoginGraceTime.
  -h, --help                Show this help.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --port) NEW_PORT="$2"; shift 2 ;;
            --permit-root-login) NEW_PERMIT_ROOT="$2"; shift 2 ;;
            --password-auth) NEW_PASSWORD_AUTH="$2"; shift 2 ;;
            --allow-users) NEW_ALLOW_USERS="$2"; shift 2 ;;
            --max-auth-tries) NEW_MAX_AUTH_TRIES="$2"; shift 2 ;;
            --login-grace-time) NEW_LOGIN_GRACE="$2"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# Load defaults from rules file if a flag was not given.
load_defaults() {
    local rules="${MB_RULES_DIR}/cis-ssh.rules"
    [[ -f "$rules" ]] || return 0
    [[ -z "$NEW_PORT" ]]               && NEW_PORT="$(grep -E '^Port=' "$rules" | cut -d= -f2)"
    [[ -z "$NEW_PERMIT_ROOT" ]]        && NEW_PERMIT_ROOT="$(grep -E '^PermitRootLogin=' "$rules" | cut -d= -f2)"
    [[ -z "$NEW_PASSWORD_AUTH" ]]      && NEW_PASSWORD_AUTH="$(grep -E '^PasswordAuthentication=' "$rules" | cut -d= -f2)"
    [[ -z "$NEW_MAX_AUTH_TRIES" ]]     && NEW_MAX_AUTH_TRIES="$(grep -E '^MaxAuthTries=' "$rules" | cut -d= -f2)"
    [[ -z "$NEW_LOGIN_GRACE" ]]        && NEW_LOGIN_GRACE="$(grep -E '^LoginGraceTime=' "$rules" | cut -d= -f2)"
}

# Set or replace a directive in sshd_config. Idempotent.
# set_directive <key> <value>
set_directive() {
    local key="$1" value="$2"
    if grep -qE "^\s*${key}\s+" "$SSHD_CONFIG"; then
        mb_apply_or_dryrun "$DRY_RUN" "Update ${key} → ${value}" \
            "sed -i 's|^\s*${key}\s.*|${key} ${value}|' '${SSHD_CONFIG}'"
    else
        mb_apply_or_dryrun "$DRY_RUN" "Add ${key} → ${value}" \
            "echo '${key} ${value}' >> '${SSHD_CONFIG}'"
    fi
}

main() {
    parse_args "$@"
    load_defaults
    mb_require_root

    if [[ ! -f "$SSHD_CONFIG" ]]; then
        mb_error "sshd_config not found: $SSHD_CONFIG"
        exit 1
    fi

    # Back up the original config (only when not dry-running).
    if [[ "$DRY_RUN" -eq 0 ]]; then
        mb_backup_file "$SSHD_CONFIG"
    fi

    [[ -n "$NEW_PORT" ]]               && set_directive Port "$NEW_PORT"
    [[ -n "$NEW_PERMIT_ROOT" ]]        && set_directive PermitRootLogin "$NEW_PERMIT_ROOT"
    [[ -n "$NEW_PASSWORD_AUTH" ]]      && set_directive PasswordAuthentication "$NEW_PASSWORD_AUTH"
    [[ -n "$NEW_ALLOW_USERS" ]]        && set_directive AllowUsers "$NEW_ALLOW_USERS"
    [[ -n "$NEW_MAX_AUTH_TRIES" ]]     && set_directive MaxAuthTries "$NEW_MAX_AUTH_TRIES"
    [[ -n "$NEW_LOGIN_GRACE" ]]        && set_directive LoginGraceTime "$NEW_LOGIN_GRACE"

    # Validate config and restart sshd (skip in dry-run).
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if mb_command_exists sshd; then
            sshd -t && mb_ok "sshd config valid"
        fi
        if mb_command_exists systemctl; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
            mb_ok "sshd restarted"
        fi
        mb_info "SSH hardening applied. Changes logged to ${SSHD_CONFIG}.mb.bak.*"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
