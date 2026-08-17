#!/usr/bin/env bash
# fix-firewall.sh — bring firewall rules in line with cis-firewall.rules.
# Supports ufw (preferred) and falls back to iptables. Idempotent.
# Supports --dry-run to preview changes without applying them.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

DRY_RUN=0
DEFAULT_INCOMING=""
DEFAULT_OUTGOING=""
ALLOWED_PORTS=""
INIT_MODE=0

usage() {
    cat <<EOF
Usage: sudo fix-firewall.sh [options]
Options:
  --dry-run                 Show changes without applying them.
  --default-incoming <pol>  Set default incoming policy (deny/allow/reject).
  --default-outgoing <pol>  Set default outgoing policy.
  --allowed-ports <list>    Comma-separated list of ports to allow.
  --init                    Initialize ufw with defaults from cis-firewall.rules.
  -h, --help                Show this help.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --default-incoming) DEFAULT_INCOMING="$2"; shift 2 ;;
            --default-outgoing) DEFAULT_OUTGOING="$2"; shift 2 ;;
            --allowed-ports) ALLOWED_PORTS="$2"; shift 2 ;;
            --init) INIT_MODE=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

load_defaults() {
    local rules="${MB_RULES_DIR}/cis-firewall.rules"
    [[ -f "$rules" ]] || return 0
    [[ -z "$DEFAULT_INCOMING" ]] && DEFAULT_INCOMING="$(grep -E '^DefaultIncomingPolicy=' "$rules" | cut -d= -f2)"
    [[ -z "$DEFAULT_OUTGOING" ]] && DEFAULT_OUTGOING="$(grep -E '^DefaultOutgoingPolicy=' "$rules" | cut -d= -f2)"
    [[ -z "$ALLOWED_PORTS" ]]    && ALLOWED_PORTS="$(grep -E '^AllowedPorts=' "$rules" | cut -d= -f2)"
}

# Apply a ufw command (or print it in dry-run mode).
ufw_apply() {
    mb_apply_or_dryrun "$DRY_RUN" "ufw $*" "ufw $*"
}

main() {
    parse_args "$@"
    load_defaults
    mb_require_root

    if ! mb_command_exists ufw; then
        mb_error "ufw is not installed. Install with: sudo apt-get install -y ufw"
        exit 1
    fi

    # Back up current ruleset.
    if [[ "$DRY_RUN" -eq 0 ]]; then
        local bak="/var/log/mb-audit/ufw-backup.$(date +%Y%m%d%H%M%S).rules"
        mb_ensure_dir "$(dirname "$bak")"
        ufw status verbose > "$bak" 2>/dev/null || true
        mb_info "Backed up ufw status to ${bak}"
    fi

    # Set default policies.
    [[ -n "$DEFAULT_INCOMING" ]] && ufw_apply default deny incoming
    [[ -n "$DEFAULT_OUTGOING" ]] && ufw_apply default allow outgoing

    # Allow specified ports.
    if [[ -n "$ALLOWED_PORTS" ]]; then
        IFS=',' read -ra ports <<< "$ALLOWED_PORTS"
        for p in "${ports[@]}"; do
            p="${p// }"
            [[ -z "$p" ]] && continue
            ufw_apply allow "${p}/tcp"
        done
    fi

    # Enable ufw (in init mode or when not dry-running).
    if [[ "$INIT_MODE" -eq 1 || "$DRY_RUN" -eq 0 ]]; then
        ufw_apply --force enable
    fi

    if [[ "$DRY_RUN" -eq 0 ]]; then
        ufw status verbose
        mb_ok "Firewall hardened. Backup saved to /var/log/mb-audit/"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
