#!/usr/bin/env bash
# fix-kernel.sh — apply sysctl hardening parameters from cis-kernel.rules.
# Idempotent. Supports --dry-run.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

DRY_RUN=0
SYSCTL_FILE="/etc/sysctl.d/99-mb-audit.conf"
BBR_FLAG=""
FILE_MAX_FLAG=""
SOMAXCONN_FLAG=""
IP_FORWARD_FLAG=""
SYNCOOKIES_FLAG=""
REDIRECTS_FLAG=""

usage() {
    cat <<EOF
Usage: sudo fix-kernel.sh [options]
Options:
  --dry-run            Show changes without applying them.
  --bbr                Enable BBR congestion control.
  --file-max <n>       Set fs.file-max.
  --somaxconn <n>      Set net.core.somaxconn.
  --ip-forward <0|1>   Set net.ipv4.ip_forward.
  --syncookies <0|1>   Set net.ipv4.tcp_syncookies.
  --redirects <0|1>    Set net.ipv4.conf.all.accept_redirects.
  --all                Apply all parameters from cis-kernel.rules.
  -h, --help           Show this help.
EOF
}

parse_args() {
    local apply_all=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --bbr) BBR_FLAG=1; shift ;;
            --file-max) FILE_MAX_FLAG="$2"; shift 2 ;;
            --somaxconn) SOMAXCONN_FLAG="$2"; shift 2 ;;
            --ip-forward) IP_FORWARD_FLAG="$2"; shift 2 ;;
            --syncookies) SYNCOOKIES_FLAG="$2"; shift 2 ;;
            --redirects) REDIRECTS_FLAG="$2"; shift 2 ;;
            --all) apply_all=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    if [[ $apply_all -eq 1 ]]; then
        local rules="${MB_RULES_DIR}/cis-kernel.rules"
        [[ -f "$rules" ]] || { mb_error "Rules file missing: $rules"; exit 1; }
        BBR_FLAG=1
        FILE_MAX_FLAG="$(grep -E '^fs.file-max=' "$rules" | cut -d= -f2)"
        SOMAXCONN_FLAG="$(grep -E '^net.core.somaxconn=' "$rules" | cut -d= -f2)"
        IP_FORWARD_FLAG="$(grep -E '^net.ipv4.ip_forward=' "$rules" | cut -d= -f2)"
        SYNCOOKIES_FLAG="$(grep -E '^net.ipv4.tcp_syncookies=' "$rules" | cut -d= -f2)"
        REDIRECTS_FLAG="$(grep -E '^net.ipv4.conf.all.accept_redirects=' "$rules" | cut -d= -f2)"
    fi
}

# Write a sysctl key=value to the drop-in file and apply it.
apply_sysctl() {
    local key="$1" value="$2"
    # Remove any existing entry for this key, then append.
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY-RUN]%b %s = %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$key" "$value"
        return
    fi
    if [[ -f "$SYSCTL_FILE" ]] && grep -qE "^${key}\s*=" "$SYSCTL_FILE"; then
        sed -i "s|^${key}\s*=.*|${key} = ${value}|" "$SYSCTL_FILE"
    else
        echo "${key} = ${value}" >> "$SYSCTL_FILE"
    fi
    sysctl -w "${key}=${value}" >/dev/null
    mb_ok "${key} = ${value}"
}

main() {
    parse_args "$@"
    mb_require_root

    if [[ "$DRY_RUN" -eq 0 ]]; then
        mb_backup_file "$SYSCTL_FILE"
        mb_ensure_dir "$(dirname "$SYSCTL_FILE")"
    fi

    if [[ -n "${BBR_FLAG:-}" ]]; then
        # BBR requires the module loaded.
        if [[ "$DRY_RUN" -eq 0 ]]; then
            modprobe tcp_bbr 2>/dev/null || true
        fi
        apply_sysctl net.core.default_qdisc fq
        apply_sysctl net.ipv4.tcp_congestion_control bbr
    fi
    [[ -n "$FILE_MAX_FLAG" ]]    && apply_sysctl fs.file-max "$FILE_MAX_FLAG"
    [[ -n "$SOMAXCONN_FLAG" ]]   && apply_sysctl net.core.somaxconn "$SOMAXCONN_FLAG"
    [[ -n "$IP_FORWARD_FLAG" ]]  && apply_sysctl net.ipv4.ip_forward "$IP_FORWARD_FLAG"
    [[ -n "$SYNCOOKIES_FLAG" ]]  && apply_sysctl net.ipv4.tcp_syncookies "$SYNCOOKIES_FLAG"
    [[ -n "$REDIRECTS_FLAG" ]]   && apply_sysctl net.ipv4.conf.all.accept_redirects "$REDIRECTS_FLAG"
    [[ -n "$REDIRECTS_FLAG" ]]   && apply_sysctl net.ipv4.conf.default.accept_redirects "$REDIRECTS_FLAG"

    if [[ "$DRY_RUN" -eq 0 ]]; then
        sysctl --system >/dev/null 2>&1 || true
        mb_ok "Kernel parameters applied to ${SYSCTL_FILE}"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
