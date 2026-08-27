#!/usr/bin/env bash
# cis-ssh-hardening.sh — CIS Benchmark v14.0 section 5.1 SSH hardening fixes.
# Applies the full set of CIS v14.0 SSH controls on top of the existing
# fix-ssh.sh baseline. Idempotent: only changes directives that differ.
# Supports --dry-run to preview changes without applying them.
#
# Controls covered (CIS v14.0 section 5.1):
#   5.1.1  PermitRootLogin=no
#   5.1.2  PermitEmptyPasswords=no
#   5.1.3  PermitTunnel=no
#   5.1.4  Protocol=2
#   5.1.5  X11Forwarding=no
#   5.1.6  MaxAuthTries=3
#   5.1.7  LoginGraceTime=30
#   5.1.8  Ciphers (strong)
#   5.1.9  MACs (strong)
#   5.1.10 KexAlgorithms (strong)
#   5.1.11 ClientAliveInterval=300
#   5.1.12 ClientAliveCountMax=0
#   5.1.13 LogLevel=VERBOSE
#   5.1.15 GSSAPIAuthentication=no
#   5.1.16 KerberosAuthentication=no
#   5.1.17 StrictModes=yes
#   5.1.22 PasswordAuthentication=no
#   5.1.23 PubkeyAuthentication=yes
#   5.1.24 HostbasedAuthentication=no
#   5.1.25 AllowTcpForwarding=no
#   5.1.26 PermitAgentForwarding=no
#   5.1.27 Port (from rules)
#   5.1.28 Banner
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
DRY_RUN=0
LOG_FILE="${LOG_FILE:-/var/log/mb-audit/cis-ssh-hardening.log}"

# Default values (CIS v14.0 section 5.1). Overridable via flags.
NEW_PORT=""
NEW_PERMIT_ROOT=""
NEW_PERMIT_EMPTY=""
NEW_PERMIT_TUNNEL=""
NEW_PROTOCOL=""
NEW_X11=""
NEW_MAX_AUTH=""
NEW_LOGIN_GRACE=""
NEW_CIPHERS=""
NEW_MACS=""
NEW_KEX=""
NEW_HOSTKEY_ALGOS=""
NEW_CLIENT_ALIVE_INTERVAL=""
NEW_CLIENT_ALIVE_COUNTMAX=""
NEW_LOG_LEVEL=""
NEW_GSSAPI=""
NEW_KERBEROS=""
NEW_STRICT_MODES=""
NEW_PASSWORD_AUTH=""
NEW_PUBKEY_AUTH=""
NEW_HOSTBASED=""
NEW_TCP_FORWARD=""
NEW_AGENT_FORWARD=""
NEW_ALLOW_USERS=""
NEW_BANNER=""
NEW_MAX_STARTUPS=""
NEW_MAX_SESSIONS=""
APPLY_ALL=0

usage() {
    cat <<EOF
Usage: sudo cis-ssh-hardening.sh [options]
CIS Benchmark v14.0 section 5.1 — SSH hardening.
Options:
  --dry-run                 Show changes without applying them.
  --all                     Apply all CIS v14.0 SSH controls from cis-ssh.rules.
  --port <n>                Set SSH port.
  --permit-root-login <v>   Set PermitRootLogin (default: no).
  --permit-empty-passwords <v>  Set PermitEmptyPasswords (default: no).
  --permit-tunnel <v>       Set PermitTunnel (default: no).
  --protocol <n>            Set Protocol (default: 2).
  --x11-forwarding <v>      Set X11Forwarding (default: no).
  --max-auth-tries <n>      Set MaxAuthTries (default: 3).
  --login-grace-time <n>    Set LoginGraceTime (default: 30).
  --ciphers <list>          Set Ciphers (strong set).
  --macs <list>             Set MACs (strong set).
  --kex-algorithms <list>   Set KexAlgorithms (strong set).
  --hostkey-algorithms <list>  Set HostKeyAlgorithms (strong set).
  --client-alive-interval <n>  Set ClientAliveInterval (default: 300).
  --client-alive-countmax <n>  Set ClientAliveCountMax (default: 0).
  --log-level <level>       Set LogLevel (default: VERBOSE).
  --gssapi <v>              Set GSSAPIAuthentication (default: no).
  --kerberos <v>            Set KerberosAuthentication (default: no).
  --strict-modes <v>        Set StrictModes (default: yes).
  --password-auth <v>       Set PasswordAuthentication (default: no).
  --pubkey-auth <v>         Set PubkeyAuthentication (default: yes).
  --hostbased-auth <v>      Set HostbasedAuthentication (default: no).
  --permit-tcp-forwarding <v>  Set AllowTcpForwarding (default: no).
  --permit-agent-forwarding <v>  Set PermitAgentForwarding (default: no).
  --allow-users <list>      Set AllowUsers.
  --banner <path>           Set Banner (default: /etc/issue.net).
  --max-startups <v>        Set MaxStartups (default: 10:30:60).
  --max-sessions <n>        Set MaxSessions (default: 10).
  -h, --help                Show this help.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --all) APPLY_ALL=1; shift ;;
            --port) NEW_PORT="$2"; shift 2 ;;
            --permit-root-login) NEW_PERMIT_ROOT="$2"; shift 2 ;;
            --permit-empty-passwords) NEW_PERMIT_EMPTY="$2"; shift 2 ;;
            --permit-tunnel) NEW_PERMIT_TUNNEL="$2"; shift 2 ;;
            --protocol) NEW_PROTOCOL="$2"; shift 2 ;;
            --x11-forwarding) NEW_X11="$2"; shift 2 ;;
            --max-auth-tries) NEW_MAX_AUTH="$2"; shift 2 ;;
            --login-grace-time) NEW_LOGIN_GRACE="$2"; shift 2 ;;
            --ciphers) NEW_CIPHERS="$2"; shift 2 ;;
            --macs) NEW_MACS="$2"; shift 2 ;;
            --kex-algorithms) NEW_KEX="$2"; shift 2 ;;
            --hostkey-algorithms) NEW_HOSTKEY_ALGOS="$2"; shift 2 ;;
            --client-alive-interval) NEW_CLIENT_ALIVE_INTERVAL="$2"; shift 2 ;;
            --client-alive-countmax) NEW_CLIENT_ALIVE_COUNTMAX="$2"; shift 2 ;;
            --log-level) NEW_LOG_LEVEL="$2"; shift 2 ;;
            --gssapi) NEW_GSSAPI="$2"; shift 2 ;;
            --kerberos) NEW_KERBEROS="$2"; shift 2 ;;
            --strict-modes) NEW_STRICT_MODES="$2"; shift 2 ;;
            --password-auth) NEW_PASSWORD_AUTH="$2"; shift 2 ;;
            --pubkey-auth) NEW_PUBKEY_AUTH="$2"; shift 2 ;;
            --hostbased-auth) NEW_HOSTBASED="$2"; shift 2 ;;
            --permit-tcp-forwarding) NEW_TCP_FORWARD="$2"; shift 2 ;;
            --permit-agent-forwarding) NEW_AGENT_FORWARD="$2"; shift 2 ;;
            --allow-users) NEW_ALLOW_USERS="$2"; shift 2 ;;
            --banner) NEW_BANNER="$2"; shift 2 ;;
            --max-startups) NEW_MAX_STARTUPS="$2"; shift 2 ;;
            --max-sessions) NEW_MAX_SESSIONS="$2"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# Helper: read a value from cis-ssh.rules by key.
_ssh_rules_get() {
    local key="$1"
    grep -E "^${key}=" "${MB_RULES_DIR}/cis-ssh.rules" 2>/dev/null | head -1 | cut -d= -f2-
}

# Load defaults from cis-ssh.rules for any flag not explicitly given.
load_defaults() {
    local rules="${MB_RULES_DIR}/cis-ssh.rules"
    [[ -f "$rules" ]] || return 0
    [[ -z "$NEW_PORT" ]]                   && NEW_PORT="$(_ssh_rules_get Port)"
    [[ -z "$NEW_PERMIT_ROOT" ]]            && NEW_PERMIT_ROOT="$(_ssh_rules_get PermitRootLogin)"
    [[ -z "$NEW_PERMIT_EMPTY" ]]           && NEW_PERMIT_EMPTY="$(_ssh_rules_get PermitEmptyPasswords)"
    [[ -z "$NEW_PERMIT_TUNNEL" ]]          && NEW_PERMIT_TUNNEL="$(_ssh_rules_get PermitTunnel)"
    [[ -z "$NEW_PROTOCOL" ]]               && NEW_PROTOCOL="$(_ssh_rules_get Protocol)"
    [[ -z "$NEW_X11" ]]                    && NEW_X11="$(_ssh_rules_get X11Forwarding)"
    [[ -z "$NEW_MAX_AUTH" ]]               && NEW_MAX_AUTH="$(_ssh_rules_get MaxAuthTries)"
    [[ -z "$NEW_LOGIN_GRACE" ]]            && NEW_LOGIN_GRACE="$(_ssh_rules_get LoginGraceTime)"
    [[ -z "$NEW_CIPHERS" ]]                && NEW_CIPHERS="$(_ssh_rules_get Ciphers)"
    [[ -z "$NEW_MACS" ]]                   && NEW_MACS="$(_ssh_rules_get MACs)"
    [[ -z "$NEW_KEX" ]]                    && NEW_KEX="$(_ssh_rules_get KexAlgorithms)"
    [[ -z "$NEW_HOSTKEY_ALGOS" ]]          && NEW_HOSTKEY_ALGOS="$(_ssh_rules_get HostKeyAlgorithms)"
    [[ -z "$NEW_CLIENT_ALIVE_INTERVAL" ]]  && NEW_CLIENT_ALIVE_INTERVAL="$(_ssh_rules_get ClientAliveInterval)"
    [[ -z "$NEW_CLIENT_ALIVE_COUNTMAX" ]]  && NEW_CLIENT_ALIVE_COUNTMAX="$(_ssh_rules_get ClientAliveCountMax)"
    [[ -z "$NEW_LOG_LEVEL" ]]              && NEW_LOG_LEVEL="$(_ssh_rules_get LogLevel)"
    [[ -z "$NEW_GSSAPI" ]]                 && NEW_GSSAPI="$(_ssh_rules_get GSSAPIAuthentication)"
    [[ -z "$NEW_KERBEROS" ]]               && NEW_KERBEROS="$(_ssh_rules_get KerberosAuthentication)"
    [[ -z "$NEW_STRICT_MODES" ]]           && NEW_STRICT_MODES="$(_ssh_rules_get StrictModes)"
    [[ -z "$NEW_PASSWORD_AUTH" ]]          && NEW_PASSWORD_AUTH="$(_ssh_rules_get PasswordAuthentication)"
    [[ -z "$NEW_PUBKEY_AUTH" ]]            && NEW_PUBKEY_AUTH="$(_ssh_rules_get PubkeyAuthentication)"
    [[ -z "$NEW_HOSTBASED" ]]              && NEW_HOSTBASED="$(_ssh_rules_get HostbasedAuthentication)"
    [[ -z "$NEW_TCP_FORWARD" ]]            && NEW_TCP_FORWARD="$(_ssh_rules_get AllowTcpForwarding)"
    [[ -z "$NEW_AGENT_FORWARD" ]]          && NEW_AGENT_FORWARD="$(_ssh_rules_get PermitAgentForwarding)"
    [[ -z "$NEW_BANNER" ]]                 && NEW_BANNER="$(_ssh_rules_get Banner)"
    [[ -z "$NEW_MAX_STARTUPS" ]]           && NEW_MAX_STARTUPS="$(_ssh_rules_get MaxStartups)"
    [[ -z "$NEW_MAX_SESSIONS" ]]           && NEW_MAX_SESSIONS="$(_ssh_rules_get MaxSessions)"
}

# Set or replace a directive in sshd_config. Idempotent.
# set_directive <key> <value>
set_directive() {
    local key="$1" value="$2"
    if [[ -z "$value" ]]; then
        return 0
    fi
    if grep -qE "^\s*${key}\s+" "$SSHD_CONFIG" 2>/dev/null; then
        mb_apply_or_dryrun "$DRY_RUN" "Update ${key} → ${value}" \
            "sed -i 's|^\s*${key}\s.*|${key} ${value}|' '${SSHD_CONFIG}'"
    else
        mb_apply_or_dryrun "$DRY_RUN" "Add ${key} → ${value}" \
            "echo '${key} ${value}' >> '${SSHD_CONFIG}'"
    fi
}

# Log a message to the fix log file (only when not dry-running).
log_fix() {
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    mb_ensure_dir "$(dirname "$LOG_FILE")"
    printf '[%s] %s\n' "$(mb_now_iso)" "$*" >> "$LOG_FILE"
}

main() {
    parse_args "$@"
    if [[ $APPLY_ALL -eq 1 ]]; then
        # Clear all NEW_* so load_defaults fills them from rules.
        NEW_PORT="" NEW_PERMIT_ROOT="" NEW_PERMIT_EMPTY="" NEW_PERMIT_TUNNEL=""
        NEW_PROTOCOL="" NEW_X11="" NEW_MAX_AUTH="" NEW_LOGIN_GRACE=""
        NEW_CIPHERS="" NEW_MACS="" NEW_KEX="" NEW_HOSTKEY_ALGOS=""
        NEW_CLIENT_ALIVE_INTERVAL="" NEW_CLIENT_ALIVE_COUNTMAX=""
        NEW_LOG_LEVEL="" NEW_GSSAPI="" NEW_KERBEROS="" NEW_STRICT_MODES=""
        NEW_PASSWORD_AUTH="" NEW_PUBKEY_AUTH="" NEW_HOSTBASED=""
        NEW_TCP_FORWARD="" NEW_AGENT_FORWARD="" NEW_BANNER=""
        NEW_MAX_STARTUPS="" NEW_MAX_SESSIONS=""
    fi
    load_defaults
    mb_require_root

    if [[ ! -f "$SSHD_CONFIG" ]]; then
        mb_error "sshd_config not found: $SSHD_CONFIG"
        exit 1
    fi

    # Back up the original config (only when not dry-running).
    if [[ "$DRY_RUN" -eq 0 ]]; then
        mb_backup_file "$SSHD_CONFIG"
        log_fix "Starting CIS v14.0 SSH hardening on ${SSHD_CONFIG}"
    fi

    # Apply all CIS v14.0 section 5.1 controls.
    [[ -n "$NEW_PORT" ]]                   && set_directive Port "$NEW_PORT"
    [[ -n "$NEW_PERMIT_ROOT" ]]            && set_directive PermitRootLogin "$NEW_PERMIT_ROOT"
    [[ -n "$NEW_PERMIT_EMPTY" ]]           && set_directive PermitEmptyPasswords "$NEW_PERMIT_EMPTY"
    [[ -n "$NEW_PERMIT_TUNNEL" ]]          && set_directive PermitTunnel "$NEW_PERMIT_TUNNEL"
    [[ -n "$NEW_PROTOCOL" ]]               && set_directive Protocol "$NEW_PROTOCOL"
    [[ -n "$NEW_X11" ]]                    && set_directive X11Forwarding "$NEW_X11"
    [[ -n "$NEW_MAX_AUTH" ]]               && set_directive MaxAuthTries "$NEW_MAX_AUTH"
    [[ -n "$NEW_LOGIN_GRACE" ]]            && set_directive LoginGraceTime "$NEW_LOGIN_GRACE"
    [[ -n "$NEW_CIPHERS" ]]                && set_directive Ciphers "$NEW_CIPHERS"
    [[ -n "$NEW_MACS" ]]                   && set_directive MACs "$NEW_MACS"
    [[ -n "$NEW_KEX" ]]                    && set_directive KexAlgorithms "$NEW_KEX"
    [[ -n "$NEW_HOSTKEY_ALGOS" ]]          && set_directive HostKeyAlgorithms "$NEW_HOSTKEY_ALGOS"
    [[ -n "$NEW_CLIENT_ALIVE_INTERVAL" ]]  && set_directive ClientAliveInterval "$NEW_CLIENT_ALIVE_INTERVAL"
    [[ -n "$NEW_CLIENT_ALIVE_COUNTMAX" ]]  && set_directive ClientAliveCountMax "$NEW_CLIENT_ALIVE_COUNTMAX"
    [[ -n "$NEW_LOG_LEVEL" ]]              && set_directive LogLevel "$NEW_LOG_LEVEL"
    [[ -n "$NEW_GSSAPI" ]]                 && set_directive GSSAPIAuthentication "$NEW_GSSAPI"
    [[ -n "$NEW_KERBEROS" ]]               && set_directive KerberosAuthentication "$NEW_KERBEROS"
    [[ -n "$NEW_STRICT_MODES" ]]           && set_directive StrictModes "$NEW_STRICT_MODES"
    [[ -n "$NEW_PASSWORD_AUTH" ]]          && set_directive PasswordAuthentication "$NEW_PASSWORD_AUTH"
    [[ -n "$NEW_PUBKEY_AUTH" ]]            && set_directive PubkeyAuthentication "$NEW_PUBKEY_AUTH"
    [[ -n "$NEW_HOSTBASED" ]]              && set_directive HostbasedAuthentication "$NEW_HOSTBASED"
    [[ -n "$NEW_TCP_FORWARD" ]]            && set_directive AllowTcpForwarding "$NEW_TCP_FORWARD"
    [[ -n "$NEW_AGENT_FORWARD" ]]          && set_directive PermitAgentForwarding "$NEW_AGENT_FORWARD"
    [[ -n "$NEW_ALLOW_USERS" ]]            && set_directive AllowUsers "$NEW_ALLOW_USERS"
    [[ -n "$NEW_BANNER" ]]                 && set_directive Banner "$NEW_BANNER"
    [[ -n "$NEW_MAX_STARTUPS" ]]           && set_directive MaxStartups "$NEW_MAX_STARTUPS"
    [[ -n "$NEW_MAX_SESSIONS" ]]           && set_directive MaxSessions "$NEW_MAX_SESSIONS"

    # Validate config and restart sshd (skip in dry-run).
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if mb_command_exists sshd; then
            sshd -t && mb_ok "sshd config valid"
        fi
        if mb_command_exists systemctl; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
            mb_ok "sshd restarted"
        fi
        log_fix "CIS v14.0 SSH hardening complete. Backup at ${SSHD_CONFIG}.mb.bak.*"
        mb_info "SSH hardening applied. Changes logged to ${LOG_FILE}"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
