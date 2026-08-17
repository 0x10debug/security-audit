#!/usr/bin/env bash
# compare.sh — baseline creation and comparison functions for the mb audit tool.
# A baseline is a YAML snapshot of the trusted system state, saved to
# /etc/mb-backup/baseline.yaml (aligned with vps-bootstrap).
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="drift"

# ---------------------------------------------------------------------------
# Collectors — gather current state of each subsystem.
# ---------------------------------------------------------------------------
_collect_ssh() {
    local port root pwauth allowusers maxauth grace
    if mb_command_exists sshd; then
        port="$(sshd -T 2>/dev/null | awk '$1=="port:"{print $2; exit}')"
        root="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin:"{print $2; exit}')"
        pwauth="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication:"{print $2; exit}')"
        allowusers="$(sshd -T 2>/dev/null | awk '$1=="allowusers:"{$1=""; print; exit}' | sed 's/^ *//')"
        maxauth="$(sshd -T 2>/dev/null | awk '$1=="maxauthtries:"{print $2; exit}')"
        grace="$(sshd -T 2>/dev/null | awk '$1=="logingracetime:"{print $2; exit}')"
    else
        port="22"; root=""; pwauth=""; allowusers=""; maxauth=""; grace=""
    fi
    printf 'ssh:\n'
    printf '  port: %s\n' "${port:-22}"
    printf '  permit_root_login: "%s"\n' "${root:-unset}"
    printf '  password_authentication: "%s"\n' "${pwauth:-unset}"
    printf '  allow_users: "%s"\n' "${allowusers:-}"
    printf '  max_auth_tries: %s\n' "${maxauth:-}"
    printf '  login_grace_time: %s\n' "${grace:-}"
}

_collect_firewall() {
    local incoming outgoing ports
    if mb_command_exists ufw; then
        incoming="$(ufw status verbose 2>/dev/null | awk '/Default:/{print $2; exit}')"
        outgoing="$(ufw status verbose 2>/dev/null | awk '/Default:/{print $4; exit}')"
        ports="$(ufw status 2>/dev/null | awk '/^[0-9]+\/[a-z]+/{print $1}' | cut -d/ -f1 | sort -u | tr '\n' ' ')"
    else
        incoming="unknown"; outgoing="unknown"; ports=""
    fi
    # Format ports as a YAML inline list.
    local port_list="[]"
    if [[ -n "${ports// }" ]]; then
        port_list="[$(echo "$ports" | tr ' ' '\n' | grep -v '^$' | sort -u | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//')]"
    fi
    printf 'firewall:\n'
    printf '  default_incoming: "%s"\n' "${incoming:-unknown}"
    printf '  default_outgoing: "%s"\n' "${outgoing:-unknown}"
    printf '  allowed_ports: %s\n' "$port_list"
}

_collect_kernel() {
    printf 'kernel:\n'
    printf '  tcp_congestion_control: "%s"\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    printf '  file_max: %s\n' "$(sysctl -n fs.file-max 2>/dev/null || echo 0)"
    printf '  somaxconn: %s\n' "$(sysctl -n net.core.somaxconn 2>/dev/null || echo 0)"
    printf '  ip_forward: %s\n' "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
    printf '  syncookies: %s\n' "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo 0)"
}

_collect_docker() {
    local exposed="false" logrot="false" userns="false"
    if [[ -f /etc/docker/daemon.json ]]; then
        grep -qE '"hosts".*0\.0\.0\.0' /etc/docker/daemon.json 2>/dev/null && exposed="true"
        grep -q 'log-rotation\|"log-opts"' /etc/docker/daemon.json 2>/dev/null && logrot="true"
        grep -q 'userns-remap' /etc/docker/daemon.json 2>/dev/null && userns="true"
    fi
    printf 'docker:\n'
    printf '  exposed_daemon: %s\n' "$exposed"
    printf '  log_rotation: %s\n' "$logrot"
    printf '  user_namespace: %s\n' "$userns"
}

_collect_files() {
    printf 'files:\n'
    for f in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
        [[ -f "$f" ]] || continue
        local mtime sha
        mtime="$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1 || stat -f '%Sm' "$f" 2>/dev/null || echo unknown)"
        sha="$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$f" 2>/dev/null | awk '{print $1}' || echo unknown)"
        printf '  %s:\n' "$f"
        printf '    mtime: "%s"\n' "$mtime"
        printf '    sha256: "%s"\n' "$sha"
    done
}

# ---------------------------------------------------------------------------
# mb_baseline_create — capture current config into baseline.yaml.
# ---------------------------------------------------------------------------
mb_baseline_create() {
    mb_require_root

    local out_dir
    out_dir="$(dirname "$MB_BASELINE_FILE")"
    mb_ensure_dir "$out_dir"

    # Back up any existing baseline.
    if [[ -f "$MB_BASELINE_FILE" ]]; then
        mb_backup_file "$MB_BASELINE_FILE"
    fi

    {
        printf 'hostname: %s\n' "$(mb_hostname)"
        printf 'date: %s\n' "$(mb_now_date)"
        printf '\n'
        _collect_ssh
        printf '\n'
        _collect_firewall
        printf '\n'
        _collect_kernel
        printf '\n'
        _collect_docker
        printf '\n'
        _collect_files
    } > "$MB_BASELINE_FILE"

    mb_ok "Baseline snapshot saved to ${MB_BASELINE_FILE}"
    mb_info "Run \`mb audit drift\` later to detect configuration drift."
}

# ---------------------------------------------------------------------------
# mb_baseline_compare — compare current state against baseline.
# Delegates to modules/drift.sh which emits standard findings.
# ---------------------------------------------------------------------------
mb_baseline_compare() {
    # shellcheck source=../modules/drift.sh
    source "${MB_MODULES_DIR}/drift.sh"
    mb_drift_run
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        create)  mb_baseline_create ;;
        compare) mb_baseline_compare ;;
        *)
            echo "Usage: compare.sh {create|compare}"
            exit 1
            ;;
    esac
fi
