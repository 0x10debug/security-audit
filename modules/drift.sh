#!/usr/bin/env bash
# drift.sh — configuration drift detection for the mb audit tool.
# Compares the current system state against a baseline snapshot stored at
# /etc/mb-backup/baseline.yaml (aligned with vps-bootstrap).
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="drift"

# ---------------------------------------------------------------------------
# Helpers to read YAML values (simple grep-based parser, no deps required).
# ---------------------------------------------------------------------------
yaml_get() {
    # yaml_get <file> <top.key> → prints value for a flat or one-level-nested key.
    local file="$1" key="$2"
    [[ -f "$file" ]] || { echo ""; return; }
    # Try nested (two-level) first: key:\n  subkey: value
    awk -v k="$key" '
        $0 ~ "^"k":" {
            in_block=1; next
        }
        in_block && /^[^[:space:]]/ { in_block=0 }
        in_block && /:/ {
            sub(/^[[:space:]]+/,"")
            split($0,a,":")
            gsub(/^[[:space:]]+/,"",a[2])
            gsub(/["'"'"']/,"",a[2])
            print a[1]"="a[2]
        }
    ' "$file"
}

yaml_get_scalar() {
    # yaml_get_scalar <file> <key> → prints scalar value at top level.
    local file="$1" key="$2"
    [[ -f "$file" ]] || { echo ""; return; }
    awk -v k="$key" '
        $0 ~ "^"k":" {
            split($0,a,":")
            gsub(/^[[:space:]]+/,"",a[2])
            gsub(/["'"'"']/,"",a[2])
            print a[2]
            exit
        }
    ' "$file"
}

# ---------------------------------------------------------------------------
# Current-state collectors (mirror baseline/compare.sh).
# ---------------------------------------------------------------------------
_current_ssh_port() {
    if mb_command_exists sshd; then
        sshd -T 2>/dev/null | awk '$1=="port:"{print $2; exit}'
    else
        awk '/^Port/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || echo "22"
    fi
}
_current_ssh_root() { sshd -T 2>/dev/null | awk '$1=="permitrootlogin:"{print $2; exit}' || echo ""; }
_current_ssh_pwauth() { sshd -T 2>/dev/null | awk '$1=="passwordauthentication:"{print $2; exit}' || echo ""; }
_current_fw_incoming() {
    if mb_command_exists ufw; then
        ufw status verbose 2>/dev/null | awk '/Default:/{print $2; exit}'
    else echo ""; fi
}
_current_fw_ports() {
    if mb_command_exists ufw; then
        ufw status 2>/dev/null | awk '/^[0-9]+\/[a-z]+/{print $1}' | cut -d/ -f1 | sort -u | tr '\n' ','
    else echo ""; fi
}
_current_kernel_cc() { sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ""; }
_current_kernel_filemax() { sysctl -n fs.file-max 2>/dev/null || echo ""; }
_current_docker_exposed() {
    grep -qE '"hosts".*0\.0\.0\.0' /etc/docker/daemon.json 2>/dev/null && echo "true" || echo "false"
}
_current_docker_logrot() {
    grep -q 'log-rotation\|"log-opts"' /etc/docker/daemon.json 2>/dev/null && echo "true" || echo "false"
}

# ---------------------------------------------------------------------------
# mb_drift_run — compare current state against baseline, emit drift findings.
# ---------------------------------------------------------------------------
mb_drift_run() {
    if [[ ! -f "$MB_BASELINE_FILE" ]]; then
        mb_emit_finding WARN medium "$MB_MODULE" "baseline_missing" \
            "No baseline snapshot found at ${MB_BASELINE_FILE}" \
            "Run `mb audit baseline` to capture a trusted snapshot"
        return
    fi

    mb_info "Comparing current state against baseline: ${MB_BASELINE_FILE}"

    # --- SSH ---
    local b_ssh_port b_ssh_root b_ssh_pwauth
    b_ssh_port="$(yaml_get "$MB_BASELINE_FILE" ssh | awk -F= '$1=="port"{print $2}')"
    b_ssh_root="$(yaml_get "$MB_BASELINE_FILE" ssh | awk -F= '$1=="permit_root_login"{print $2}')"
    b_ssh_pwauth="$(yaml_get "$MB_BASELINE_FILE" ssh | awk -F= '$1=="password_authentication"{print $2}')"

    _drift_compare "ssh_port"            "$b_ssh_port"   "$(_current_ssh_port)"   "SSH port"
    _drift_compare "ssh_permitroot"      "$b_ssh_root"   "$(_current_ssh_root)"   "SSH PermitRootLogin"
    _drift_compare "ssh_passwordauth"    "$b_ssh_pwauth" "$(_current_ssh_pwauth)" "SSH PasswordAuthentication"

    # --- Firewall ---
    local b_fw_in b_fw_ports
    b_fw_in="$(yaml_get "$MB_BASELINE_FILE" firewall | awk -F= '$1=="default_incoming"{print $2}')"
    b_fw_ports="$(yaml_get "$MB_BASELINE_FILE" firewall | awk -F= '$1=="allowed_ports"{print $2}')"

    _drift_compare "firewall_incoming" "$b_fw_in"    "$(_current_fw_incoming)" "Firewall default incoming"
    _drift_compare "firewall_ports"    "$b_fw_ports" "$(_current_fw_ports)"    "Firewall allowed ports"

    # --- Kernel ---
    local b_kcc b_kfm
    b_kcc="$(yaml_get "$MB_BASELINE_FILE" kernel | awk -F= '$1=="tcp_congestion_control"{print $2}')"
    b_kfm="$(yaml_get "$MB_BASELINE_FILE" kernel | awk -F= '$1=="file_max"{print $2}')"

    _drift_compare "kernel_cc"      "$b_kcc" "$(_current_kernel_cc)"      "Kernel tcp_congestion_control"
    _drift_compare "kernel_filemax" "$b_kfm" "$(_current_kernel_filemax)" "Kernel fs.file-max"

    # --- Docker ---
    local b_dk_exp b_dk_log
    b_dk_exp="$(yaml_get "$MB_BASELINE_FILE" docker | awk -F= '$1=="exposed_daemon"{print $2}')"
    b_dk_log="$(yaml_get "$MB_BASELINE_FILE" docker | awk -F= '$1=="log_rotation"{print $2}')"

    _drift_compare "docker_exposed"  "$b_dk_exp" "$(_current_docker_exposed)" "Docker exposed daemon"
    _drift_compare "docker_logrot"   "$b_dk_log" "$(_current_docker_logrot)"  "Docker log rotation"
}

# Emit a drift finding if baseline != current.
_drift_compare() {
    local check="$1" baseline="$2" current="$3" label="$4"
    if [[ -z "$baseline" ]]; then
        return  # No baseline value for this key — skip.
    fi
    if [[ "$baseline" == "$current" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "drift_${check}" \
            "${label}: matches baseline (${current})" ""
    else
        mb_emit_finding FAIL high "$MB_MODULE" "drift_${check}" \
            "${label}: drifted from '${baseline}' to '${current:-unset}'" \
            "Run `mb audit fix` to restore, or `mb audit baseline` to re-snapshot"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_drift_run
fi
