#!/usr/bin/env bash
# cis-kernel-hardening.sh — CIS Benchmark v14.0 section 3.1/3.2 + 1.6 kernel fixes.
# Applies the full set of CIS v14.0 sysctl network and process hardening
# parameters on top of the existing fix-kernel.sh baseline.
# Idempotent. Supports --dry-run.
#
# Controls covered (CIS v14.0):
#   3.1.1-3.1.24  IPv4 network parameters
#   3.2.1-3.2.8   IPv6 parameters
#   1.6.3-1.6.4   ASLR / address space layout randomization
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

DRY_RUN=0
SYSCTL_FILE="${SYSCTL_FILE:-/etc/sysctl.d/99-mb-audit-cis-v14.conf}"
LOG_FILE="${LOG_FILE:-/var/log/mb-audit/cis-kernel-hardening.log}"
APPLY_ALL=0

usage() {
    cat <<EOF
Usage: sudo cis-kernel-hardening.sh [options]
CIS Benchmark v14.0 section 3.1/3.2/1.6 — kernel & network hardening.
Options:
  --dry-run            Show changes without applying them.
  --all                Apply all CIS v14.0 kernel parameters from cis-kernel.rules.
  --ip-forward <0|1>   Set net.ipv4.ip_forward.
  --ipv6-forward <0|1> Set net.ipv6.conf.all.forwarding.
  --send-redirects <0|1>   Set net.ipv4.conf.{all,default}.send_redirects.
  --accept-redirects <0|1> Set net.ipv4.conf.{all,default}.accept_redirects.
  --secure-redirects <0|1> Set net.ipv4.conf.{all,default}.secure_redirects.
  --log-martians <0|1>     Set net.ipv4.conf.{all,default}.log_martians.
  --source-route <0|1>     Set net.ipv4.conf.{all,default}.accept_source_route.
  --rp-filter <0|1>        Set net.ipv4.conf.{all,default}.rp_filter.
  --icmp-broadcast <0|1>   Set net.ipv4.icmp_echo_ignore_broadcasts.
  --icmp-bogus <0|1>       Set net.ipv4.icmp_ignore_bogus_error_responses.
  --syncookies <0|1>       Set net.ipv4.tcp_syncookies.
  --syn-backlog <n>        Set net.ipv4.tcp_max_syn_backlog.
  --rfc1337 <0|1>          Set net.ipv4.tcp_rfc1337.
  --tcp-orphans <n>        Set net.ipv4.tcp_max_orphans.
  --tcp-fin-timeout <n>    Set net.ipv4.tcp_fin_timeout.
  --tcp-keepalive-time <n> Set net.ipv4.tcp_keepalive_time.
  --tcp-keepalive-probes <n>  Set net.ipv4.tcp_keepalive_probes.
  --tcp-keepalive-intvl <n>   Set net.ipv4.tcp_keepalive_intvl.
  --ipv6-disable <0|1>     Set net.ipv6.conf.{all,default}.disable_ipv6.
  --ipv6-ra <0|1>          Set net.ipv6.conf.{all,default}.accept_ra.
  --ipv6-redirects <0|1>   Set net.ipv6.conf.{all,default}.accept_redirects.
  --ipv6-source-route <0|1>  Set net.ipv6.conf.{all,default}.accept_source_route.
  --aslr <0|1|2>           Set kernel.randomize_va_space (CIS: 2).
  -h, --help               Show this help.
EOF
}

# Flag values (empty = not specified → load from rules when --all).
F_IP_FORWARD="" F_IPV6_FORWARD="" F_SEND_REDIRECTS="" F_ACCEPT_REDIRECTS=""
F_SECURE_REDIRECTS="" F_LOG_MARTIANS="" F_SOURCE_ROUTE="" F_RP_FILTER=""
F_ICMP_BROADCAST="" F_ICMP_BOGUS="" F_SYNCOOKIES="" F_SYN_BACKLOG=""
F_RFC1337="" F_TCP_ORPHANS="" F_TCP_FIN_TIMEOUT="" F_TCP_KEEPALIVE_TIME=""
F_TCP_KEEPALIVE_PROBES="" F_TCP_KEEPALIVE_INTVL="" F_IPV6_DISABLE=""
F_IPV6_RA="" F_IPV6_REDIRECTS="" F_IPV6_SOURCE_ROUTE="" F_ASLR=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --all) APPLY_ALL=1; shift ;;
            --ip-forward) F_IP_FORWARD="$2"; shift 2 ;;
            --ipv6-forward) F_IPV6_FORWARD="$2"; shift 2 ;;
            --send-redirects) F_SEND_REDIRECTS="$2"; shift 2 ;;
            --accept-redirects) F_ACCEPT_REDIRECTS="$2"; shift 2 ;;
            --secure-redirects) F_SECURE_REDIRECTS="$2"; shift 2 ;;
            --log-martians) F_LOG_MARTIANS="$2"; shift 2 ;;
            --source-route) F_SOURCE_ROUTE="$2"; shift 2 ;;
            --rp-filter) F_RP_FILTER="$2"; shift 2 ;;
            --icmp-broadcast) F_ICMP_BROADCAST="$2"; shift 2 ;;
            --icmp-bogus) F_ICMP_BOGUS="$2"; shift 2 ;;
            --syncookies) F_SYNCOOKIES="$2"; shift 2 ;;
            --syn-backlog) F_SYN_BACKLOG="$2"; shift 2 ;;
            --rfc1337) F_RFC1337="$2"; shift 2 ;;
            --tcp-orphans) F_TCP_ORPHANS="$2"; shift 2 ;;
            --tcp-fin-timeout) F_TCP_FIN_TIMEOUT="$2"; shift 2 ;;
            --tcp-keepalive-time) F_TCP_KEEPALIVE_TIME="$2"; shift 2 ;;
            --tcp-keepalive-probes) F_TCP_KEEPALIVE_PROBES="$2"; shift 2 ;;
            --tcp-keepalive-intvl) F_TCP_KEEPALIVE_INTVL="$2"; shift 2 ;;
            --ipv6-disable) F_IPV6_DISABLE="$2"; shift 2 ;;
            --ipv6-ra) F_IPV6_RA="$2"; shift 2 ;;
            --ipv6-redirects) F_IPV6_REDIRECTS="$2"; shift 2 ;;
            --ipv6-source-route) F_IPV6_SOURCE_ROUTE="$2"; shift 2 ;;
            --aslr) F_ASLR="$2"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# Read a value from cis-kernel.rules by key.
_rules_get() {
    local key="$1"
    grep -E "^${key}=" "${MB_RULES_DIR}/cis-kernel.rules" 2>/dev/null | head -1 | cut -d= -f2
}

# Load defaults from cis-kernel.rules for any flag not given (only with --all).
load_defaults() {
    [[ $APPLY_ALL -eq 0 ]] && return 0
    local r="${MB_RULES_DIR}/cis-kernel.rules"
    [[ -f "$r" ]] || { mb_error "Rules file missing: $r"; exit 1; }
    [[ -z "$F_IP_FORWARD" ]]          && F_IP_FORWARD="$(_rules_get net.ipv4.ip_forward)"
    [[ -z "$F_IPV6_FORWARD" ]]        && F_IPV6_FORWARD="$(_rules_get net.ipv6.conf.all.forwarding)"
    [[ -z "$F_SEND_REDIRECTS" ]]      && F_SEND_REDIRECTS="$(_rules_get net.ipv4.conf.all.send_redirects)"
    [[ -z "$F_ACCEPT_REDIRECTS" ]]    && F_ACCEPT_REDIRECTS="$(_rules_get net.ipv4.conf.all.accept_redirects)"
    [[ -z "$F_SECURE_REDIRECTS" ]]    && F_SECURE_REDIRECTS="$(_rules_get net.ipv4.conf.all.secure_redirects)"
    [[ -z "$F_LOG_MARTIANS" ]]        && F_LOG_MARTIANS="$(_rules_get net.ipv4.conf.all.log_martians)"
    [[ -z "$F_SOURCE_ROUTE" ]]        && F_SOURCE_ROUTE="$(_rules_get net.ipv4.conf.all.accept_source_route)"
    [[ -z "$F_RP_FILTER" ]]           && F_RP_FILTER="$(_rules_get net.ipv4.conf.all.rp_filter)"
    [[ -z "$F_ICMP_BROADCAST" ]]      && F_ICMP_BROADCAST="$(_rules_get net.ipv4.icmp_echo_ignore_broadcasts)"
    [[ -z "$F_ICMP_BOGUS" ]]          && F_ICMP_BOGUS="$(_rules_get net.ipv4.icmp_ignore_bogus_error_responses)"
    [[ -z "$F_SYNCOOKIES" ]]          && F_SYNCOOKIES="$(_rules_get net.ipv4.tcp_syncookies)"
    [[ -z "$F_SYN_BACKLOG" ]]         && F_SYN_BACKLOG="$(_rules_get net.ipv4.tcp_max_syn_backlog)"
    [[ -z "$F_RFC1337" ]]             && F_RFC1337="$(_rules_get net.ipv4.tcp_rfc1337)"
    [[ -z "$F_TCP_ORPHANS" ]]         && F_TCP_ORPHANS="$(_rules_get net.ipv4.tcp_max_orphans)"
    [[ -z "$F_TCP_FIN_TIMEOUT" ]]     && F_TCP_FIN_TIMEOUT="$(_rules_get net.ipv4.tcp_fin_timeout)"
    [[ -z "$F_TCP_KEEPALIVE_TIME" ]]  && F_TCP_KEEPALIVE_TIME="$(_rules_get net.ipv4.tcp_keepalive_time)"
    [[ -z "$F_TCP_KEEPALIVE_PROBES" ]] && F_TCP_KEEPALIVE_PROBES="$(_rules_get net.ipv4.tcp_keepalive_probes)"
    [[ -z "$F_TCP_KEEPALIVE_INTVL" ]]  && F_TCP_KEEPALIVE_INTVL="$(_rules_get net.ipv4.tcp_keepalive_intvl)"
    [[ -z "$F_IPV6_DISABLE" ]]        && F_IPV6_DISABLE="$(_rules_get net.ipv6.conf.all.disable_ipv6)"
    [[ -z "$F_IPV6_RA" ]]             && F_IPV6_RA="$(_rules_get net.ipv6.conf.all.accept_ra)"
    [[ -z "$F_IPV6_REDIRECTS" ]]      && F_IPV6_REDIRECTS="$(_rules_get net.ipv6.conf.all.accept_redirects)"
    [[ -z "$F_IPV6_SOURCE_ROUTE" ]]   && F_IPV6_SOURCE_ROUTE="$(_rules_get net.ipv6.conf.all.accept_source_route)"
    [[ -z "$F_ASLR" ]]                && F_ASLR="$(_rules_get kernel.randomize_va_space)"
}

# Write a sysctl key=value to the drop-in file and apply it.
apply_sysctl() {
    local key="$1" value="$2"
    [[ -z "$value" ]] && return 0
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY-RUN]%b %s = %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$key" "$value"
        return
    fi
    if [[ -f "$SYSCTL_FILE" ]] && grep -qE "^${key}\s*=" "$SYSCTL_FILE"; then
        sed -i "s|^${key}\s*=.*|${key} = ${value}|" "$SYSCTL_FILE"
    else
        echo "${key} = ${value}" >> "$SYSCTL_FILE"
    fi
    sysctl -w "${key}=${value}" >/dev/null 2>&1 || true
    mb_ok "${key} = ${value}"
    log_fix "Set ${key} = ${value}"
}

# Apply a parameter to both .all and .default variants.
apply_sysctl_all_default() {
    local key_base="$1" value="$2"
    apply_sysctl "${key_base}.all" "$value"
    apply_sysctl "${key_base}.default" "$value"
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

    if [[ "$DRY_RUN" -eq 0 ]]; then
        mb_backup_file "$SYSCTL_FILE"
        mb_ensure_dir "$(dirname "$SYSCTL_FILE")"
        log_fix "Starting CIS v14.0 kernel hardening to ${SYSCTL_FILE}"
    fi

    # Section 3.1 — IPv4 network parameters.
    [[ -n "$F_IP_FORWARD" ]]       && apply_sysctl net.ipv4.ip_forward "$F_IP_FORWARD"
    [[ -n "$F_SEND_REDIRECTS" ]]   && apply_sysctl_all_default net.ipv4.conf.send_redirects "$F_SEND_REDIRECTS"
    [[ -n "$F_ACCEPT_REDIRECTS" ]] && apply_sysctl_all_default net.ipv4.conf.accept_redirects "$F_ACCEPT_REDIRECTS"
    [[ -n "$F_SECURE_REDIRECTS" ]] && apply_sysctl_all_default net.ipv4.conf.secure_redirects "$F_SECURE_REDIRECTS"
    [[ -n "$F_LOG_MARTIANS" ]]     && apply_sysctl_all_default net.ipv4.conf.log_martians "$F_LOG_MARTIANS"
    [[ -n "$F_SOURCE_ROUTE" ]]     && apply_sysctl_all_default net.ipv4.conf.accept_source_route "$F_SOURCE_ROUTE"
    [[ -n "$F_RP_FILTER" ]]        && apply_sysctl_all_default net.ipv4.conf.rp_filter "$F_RP_FILTER"
    [[ -n "$F_ICMP_BROADCAST" ]]   && apply_sysctl net.ipv4.icmp_echo_ignore_broadcasts "$F_ICMP_BROADCAST"
    [[ -n "$F_ICMP_BOGUS" ]]       && apply_sysctl net.ipv4.icmp_ignore_bogus_error_responses "$F_ICMP_BOGUS"
    [[ -n "$F_SYNCOOKIES" ]]       && apply_sysctl net.ipv4.tcp_syncookies "$F_SYNCOOKIES"
    [[ -n "$F_SYN_BACKLOG" ]]      && apply_sysctl net.ipv4.tcp_max_syn_backlog "$F_SYN_BACKLOG"
    [[ -n "$F_RFC1337" ]]          && apply_sysctl net.ipv4.tcp_rfc1337 "$F_RFC1337"
    [[ -n "$F_TCP_ORPHANS" ]]      && apply_sysctl net.ipv4.tcp_max_orphans "$F_TCP_ORPHANS"
    [[ -n "$F_TCP_FIN_TIMEOUT" ]]  && apply_sysctl net.ipv4.tcp_fin_timeout "$F_TCP_FIN_TIMEOUT"
    [[ -n "$F_TCP_KEEPALIVE_TIME" ]]    && apply_sysctl net.ipv4.tcp_keepalive_time "$F_TCP_KEEPALIVE_TIME"
    [[ -n "$F_TCP_KEEPALIVE_PROBES" ]]  && apply_sysctl net.ipv4.tcp_keepalive_probes "$F_TCP_KEEPALIVE_PROBES"
    [[ -n "$F_TCP_KEEPALIVE_INTVL" ]]   && apply_sysctl net.ipv4.tcp_keepalive_intvl "$F_TCP_KEEPALIVE_INTVL"

    # Section 3.2 — IPv6.
    [[ -n "$F_IPV6_FORWARD" ]]      && apply_sysctl net.ipv6.conf.all.forwarding "$F_IPV6_FORWARD"
    [[ -n "$F_IPV6_DISABLE" ]]      && apply_sysctl_all_default net.ipv6.conf.disable_ipv6 "$F_IPV6_DISABLE"
    [[ -n "$F_IPV6_RA" ]]           && apply_sysctl_all_default net.ipv6.conf.accept_ra "$F_IPV6_RA"
    [[ -n "$F_IPV6_REDIRECTS" ]]    && apply_sysctl_all_default net.ipv6.conf.accept_redirects "$F_IPV6_REDIRECTS"
    [[ -n "$F_IPV6_SOURCE_ROUTE" ]] && apply_sysctl_all_default net.ipv6.conf.accept_source_route "$F_IPV6_SOURCE_ROUTE"

    # Section 1.6 — process hardening.
    [[ -n "$F_ASLR" ]] && apply_sysctl kernel.randomize_va_space "$F_ASLR"

    if [[ "$DRY_RUN" -eq 0 ]]; then
        sysctl --system >/dev/null 2>&1 || true
        log_fix "CIS v14.0 kernel hardening complete. Backup at ${SYSCTL_FILE}.mb.bak.*"
        mb_ok "Kernel parameters applied to ${SYSCTL_FILE}"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
