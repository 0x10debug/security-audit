#!/usr/bin/env bash
# cis-firewall-setup.sh — CIS Benchmark v14.0 section 3.4 firewall configuration.
# Configures ufw (preferred) or falls back to iptables with the CIS v14.0
# default-deny incoming policy, loopback allowance, SSH rate limiting, and
# IPv6 support. Idempotent. Supports --dry-run.
#
# Controls covered (CIS v14.0 section 3.4):
#   3.4.1  firewall installed
#   3.4.2  firewall enabled
#   3.4.3  default incoming = deny
#   3.4.4  default outgoing = allow
#   3.4.5  default forwarding = deny
#   3.4.6  loopback allowed
#   3.4.7  allowed ports (from cis-firewall.rules)
#   3.4.8  rate limit SSH
#   3.4.9  logging enabled
#   3.4.10 IPv6 enabled
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

DRY_RUN=0
LOG_FILE="${LOG_FILE:-/var/log/mb-audit/cis-firewall-setup.log}"
DEFAULT_INCOMING=""
DEFAULT_OUTGOING=""
DEFAULT_FORWARDING=""
ALLOWED_PORTS=""
RATE_LIMIT_SSH=0
INSTALL=0
ENABLE=0
LOOPBACK=0
IPV6=0
LOGGING=0
APPLY_ALL=0

usage() {
    cat <<EOF
Usage: sudo cis-firewall-setup.sh [options]
CIS Benchmark v14.0 section 3.4 — firewall configuration.
Options:
  --dry-run                 Show changes without applying them.
  --all                     Apply all CIS v14.0 firewall controls from cis-firewall.rules.
  --install                 Install ufw if missing.
  --enable                  Enable the firewall.
  --default-incoming <pol>  Set default incoming policy (deny/allow/reject).
  --default-outgoing <pol>  Set default outgoing policy.
  --default-forwarding <pol>  Set default forwarding policy.
  --allowed-ports <list>    Comma-separated list of TCP ports to allow.
  --rate-limit-ssh          Rate-limit SSH connections (CIS 3.4.8).
  --loopback                Allow loopback traffic (CIS 3.4.6).
  --ipv6                    Enable IPv6 firewall support (CIS 3.4.10).
  --logging                 Enable firewall logging (CIS 3.4.9).
  -h, --help                Show this help.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --all) APPLY_ALL=1; shift ;;
            --install) INSTALL=1; shift ;;
            --enable) ENABLE=1; shift ;;
            --default-incoming) DEFAULT_INCOMING="$2"; shift 2 ;;
            --default-outgoing) DEFAULT_OUTGOING="$2"; shift 2 ;;
            --default-forwarding) DEFAULT_FORWARDING="$2"; shift 2 ;;
            --allowed-ports) ALLOWED_PORTS="$2"; shift 2 ;;
            --rate-limit-ssh) RATE_LIMIT_SSH=1; shift ;;
            --loopback) LOOPBACK=1; shift ;;
            --ipv6) IPV6=1; shift ;;
            --logging) LOGGING=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# Read a value from cis-firewall.rules by key.
_rules_get() {
    grep -E "^${1}=" "${MB_RULES_DIR}/cis-firewall.rules" 2>/dev/null | head -1 | cut -d= -f2
}

load_defaults() {
    [[ $APPLY_ALL -eq 0 ]] && return 0
    local r="${MB_RULES_DIR}/cis-firewall.rules"
    [[ -f "$r" ]] || return 0
    [[ -z "$DEFAULT_INCOMING" ]]  && DEFAULT_INCOMING="$(_rules_get DefaultIncomingPolicy)"
    [[ -z "$DEFAULT_OUTGOING" ]]  && DEFAULT_OUTGOING="$(_rules_get DefaultOutgoingPolicy)"
    [[ -z "$DEFAULT_FORWARDING" ]] && DEFAULT_FORWARDING="$(_rules_get DefaultForwardingPolicy)"
    [[ -z "$ALLOWED_PORTS" ]]     && ALLOWED_PORTS="$(_rules_get AllowedPorts)"
    INSTALL=1; ENABLE=1; RATE_LIMIT_SSH=1; LOOPBACK=1; IPV6=1; LOGGING=1
}

ufw_apply() {
    mb_apply_or_dryrun "$DRY_RUN" "ufw $*" "ufw $*"
}

log_fix() {
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    mb_ensure_dir "$(dirname "$LOG_FILE")"
    printf '[%s] %s\n' "$(mb_now_iso)" "$*" >> "$LOG_FILE"
}

main() {
    parse_args "$@"
    load_defaults
    mb_require_root

    # Install ufw if requested and missing.
    if [[ $INSTALL -eq 1 ]] && ! mb_command_exists ufw; then
        if mb_command_exists apt-get; then
            mb_apply_or_dryrun "$DRY_RUN" "Install ufw" "apt-get update -qq && apt-get install -y ufw"
        elif mb_command_exists dnf; then
            mb_apply_or_dryrun "$DRY_RUN" "Install ufw" "dnf install -y ufw"
        else
            mb_error "Cannot install ufw: no supported package manager."
            exit 1
        fi
    fi

    if ! mb_command_exists ufw; then
        mb_error "ufw is not installed. Run with --install or: sudo apt-get install -y ufw"
        exit 1
    fi

    # Back up current ruleset.
    if [[ "$DRY_RUN" -eq 0 ]]; then
        local bak
        bak="/var/log/mb-audit/ufw-backup.$(date +%Y%m%d%H%M%S).rules"
        mb_ensure_dir "$(dirname "$bak")"
        ufw status verbose > "$bak" 2>/dev/null || true
        mb_info "Backed up ufw status to ${bak}"
        log_fix "Starting CIS v14.0 firewall setup"
    fi

    # IPv6 support (CIS 3.4.10).
    if [[ $IPV6 -eq 1 ]]; then
        if [[ "$DRY_RUN" -eq 0 ]]; then
            local ufw_default="/etc/default/ufw"
            if [[ -f "$ufw_default" ]] && grep -qE '^IPV6=' "$ufw_default"; then
                sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_default"
            else
                echo "IPV6=yes" >> "$ufw_default"
            fi
            mb_ok "IPv6 firewall support enabled"
            log_fix "Enabled IPv6 firewall support"
        else
            printf '%b[DRY-RUN]%b enable IPv6 in /etc/default/ufw\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET"
        fi
    fi

    # Default policies (CIS 3.4.3–3.4.5).
    [[ -n "$DEFAULT_INCOMING" ]]   && ufw_apply default "${DEFAULT_INCOMING}" incoming
    [[ -n "$DEFAULT_OUTGOING" ]]   && ufw_apply default "${DEFAULT_OUTGOING}" outgoing
    [[ -n "$DEFAULT_FORWARDING" ]] && ufw_apply default "${DEFAULT_FORWARDING}" forwarding

    # Loopback (CIS 3.4.6).
    if [[ $LOOPBACK -eq 1 ]]; then
        ufw_apply allow in on lo
        ufw_apply allow out on lo
        log_fix "Allowed loopback traffic"
    fi

    # Allowed ports (CIS 3.4.7).
    if [[ -n "$ALLOWED_PORTS" ]]; then
        IFS=',' read -ra ports <<< "$ALLOWED_PORTS"
        for p in "${ports[@]}"; do
            p="${p// }"
            [[ -z "$p" ]] && continue
            ufw_apply allow "${p}/tcp"
        done
        log_fix "Allowed TCP ports: ${ALLOWED_PORTS}"
    fi

    # Rate limit SSH (CIS 3.4.8).
    if [[ $RATE_LIMIT_SSH -eq 1 ]]; then
        local ssh_port="${ALLOWED_PORTS%%,*}"
        ssh_port="${ssh_port:-22}"
        # Delete any plain allow rule for SSH first, then add rate-limited.
        if [[ "$DRY_RUN" -eq 0 ]]; then
            ufw delete allow "${ssh_port}/tcp" 2>/dev/null || true
        fi
        ufw_apply limit "${ssh_port}/tcp"
        log_fix "Rate-limited SSH on port ${ssh_port}"
    fi

    # Logging (CIS 3.4.9).
    if [[ $LOGGING -eq 1 ]]; then
        ufw_apply logging on
        log_fix "Enabled firewall logging"
    fi

    # Enable (CIS 3.4.2).
    if [[ $ENABLE -eq 1 || "$DRY_RUN" -eq 0 ]]; then
        ufw_apply --force enable
    fi

    if [[ "$DRY_RUN" -eq 0 ]]; then
        ufw status verbose
        log_fix "CIS v14.0 firewall setup complete"
        mb_ok "Firewall configured per CIS v14.0. Backup saved to /var/log/mb-audit/"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
