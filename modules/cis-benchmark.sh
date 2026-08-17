#!/usr/bin/env bash
# cis-benchmark.sh — CIS Benchmark compliance checks for the mb audit tool.
# Each check function emits a pipe-delimited finding:
#   STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX_COMMAND
# STATUS ∈ PASS|FAIL|WARN
set -euo pipefail

# Source common.sh if not already loaded.
if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="cis"

# Path to the SSH daemon config and the fix script.
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
FIX_SSH="${MB_FIXES_DIR}/fix-ssh.sh"
FIX_FIREWALL="${MB_FIXES_DIR}/fix-firewall.sh"
FIX_KERNEL="${MB_FIXES_DIR}/fix-kernel.sh"
FIX_DOCKER="${MB_FIXES_DIR}/fix-docker.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Read a single sshd_config directive value (first match, effective value).
_sshd_get() {
    local key="$1"
    # Use sshd -T when possible (resolves Match blocks & includes).
    if mb_command_exists sshd; then
        sshd -T 2>/dev/null | awk -v k="${key}" '$1==k":" {print $2; exit}'
    else
        awk -v k="${key}" '
            $1==k {gsub(/"/,"",$2); print $2; exit}
        ' "$SSHD_CONFIG" 2>/dev/null
    fi
}

# Get a sysctl value safely.
_sysctl_get() {
    sysctl -n "$1" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# SSH checks
# ---------------------------------------------------------------------------
check_ssh_permitrootlogin() {
    local expected="no"
    local actual
    actual="$(_sshd_get PermitRootLogin)"
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "ssh_permitrootlogin" \
            "PermitRootLogin is ${actual}" ""
    else
        mb_emit_finding FAIL high "$MB_MODULE" "ssh_permitrootlogin" \
            "PermitRootLogin is '${actual:-unset}', expected 'no' (root login over SSH is dangerous)" \
            "sudo ${FIX_SSH} --permit-root-login no"
    fi
}

check_ssh_passwordauthentication() {
    local expected="no"
    local actual
    actual="$(_sshd_get PasswordAuthentication)"
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "ssh_passwordauthentication" \
            "PasswordAuthentication is ${actual}" ""
    else
        mb_emit_finding FAIL high "$MB_MODULE" "ssh_passwordauthentication" \
            "PasswordAuthentication is '${actual:-unset}', expected 'no' (password auth allows brute force)" \
            "sudo ${FIX_SSH} --password-auth no"
    fi
}

check_ssh_port() {
    local expected
    expected="$(grep -E '^Port=' "${MB_RULES_DIR}/cis-ssh.rules" 2>/dev/null | cut -d= -f2)"
    expected="${expected:-2222}"
    local actual
    actual="$(_sshd_get Port)"
    if [[ -z "$actual" ]]; then actual="22"; fi
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "ssh_port" \
            "SSH port is ${actual}" ""
    else
        mb_emit_finding FAIL medium "$MB_MODULE" "ssh_port" \
            "SSH port is ${actual}, expected ${expected} (default port 22 is heavily scanned)" \
            "sudo ${FIX_SSH} --port ${expected}"
    fi
}

check_ssh_allowusers() {
    local actual
    actual="$(_sshd_get AllowUsers)"
    if [[ -n "$actual" && "$actual" != "*" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "ssh_allowusers" \
            "AllowUsers is set: ${actual}" ""
    else
        mb_emit_finding WARN medium "$MB_MODULE" "ssh_allowusers" \
            "AllowUsers is not set — any valid account may connect via SSH" \
            "sudo ${FIX_SSH} --allow-users '<your-user>'"
    fi
}

check_ssh_maxauthtries() {
    local expected="3"
    local actual
    actual="$(_sshd_get MaxAuthTries)"
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "ssh_maxauthtries" \
            "MaxAuthTries is ${actual}" ""
    else
        mb_emit_finding WARN low "$MB_MODULE" "ssh_maxauthtries" \
            "MaxAuthTries is '${actual:-unset}', expected ${expected}" \
            "sudo ${FIX_SSH} --max-auth-tries ${expected}"
    fi
}

check_ssh_logingracetime() {
    local expected="30"
    local actual
    actual="$(_sshd_get LoginGraceTime)"
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "ssh_logingracetime" \
            "LoginGraceTime is ${actual}" ""
    else
        mb_emit_finding WARN low "$MB_MODULE" "ssh_logingracetime" \
            "LoginGraceTime is '${actual:-unset}', expected ${expected}" \
            "sudo ${FIX_SSH} --login-grace-time ${expected}"
    fi
}

# ---------------------------------------------------------------------------
# Firewall checks
# ---------------------------------------------------------------------------
check_firewall_default_incoming() {
    local expected="deny"
    local actual=""
    if mb_command_exists ufw; then
        actual="$(ufw status verbose 2>/dev/null | awk '/Default:/{print $2; exit}')"
    elif mb_command_exists iptables; then
        actual="$(iptables -L INPUT -n 2>/dev/null | awk '/^Chain INPUT/{print $4}' | tr -d ')')"
        case "$actual" in DROP|REJECT) actual="deny";; ACCEPT) actual="allow";; *) actual="unknown";; esac
    fi
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "firewall_default_incoming" \
            "Default incoming policy is ${actual}" ""
    else
        mb_emit_finding FAIL high "$MB_MODULE" "firewall_default_incoming" \
            "Default incoming policy is '${actual:-unknown}', expected 'deny'" \
            "sudo ${FIX_FIREWALL} --default-incoming deny"
    fi
}

check_firewall_allowed_ports() {
    local expected
    expected="$(grep -E '^AllowedPorts=' "${MB_RULES_DIR}/cis-firewall.rules" 2>/dev/null | cut -d= -f2)"
    expected="${expected:-22,80,443}"
    local open_ports=""
    if mb_command_exists ufw; then
        open_ports="$(ufw status 2>/dev/null | awk '/^[0-9]+\/[a-z]+/{print $1}' | cut -d/ -f1 | sort -u | tr '\n' ',')"
    elif mb_command_exists iptables; then
        open_ports="$(iptables -L INPUT -n 2>/dev/null | awk '/dpt:/{for(i=1;i<=NF;i++) if($i~/dpt:/){split($i,a,":");print a[2]}}' | sort -u | tr '\n' ',')"
    fi
    open_ports="${open_ports%,}"
    if [[ -z "$open_ports" ]]; then
        mb_emit_finding WARN medium "$MB_MODULE" "firewall_allowed_ports" \
            "Could not determine open ports (no supported firewall found)" \
            "sudo ${FIX_FIREWALL} --init"
    elif [[ ",${open_ports}," == *",${expected//,/,},"* ]] || [[ "$open_ports" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "firewall_allowed_ports" \
            "Open ports: ${open_ports}" ""
    else
        mb_emit_finding WARN medium "$MB_MODULE" "firewall_allowed_ports" \
            "Open ports [${open_ports}] differ from expected [${expected}]" \
            "sudo ${FIX_FIREWALL} --allowed-ports ${expected}"
    fi
}

# ---------------------------------------------------------------------------
# Kernel checks
# ---------------------------------------------------------------------------
check_kernel_bbr() {
    local expected="bbr"
    local actual
    actual="$(_sysctl_get net.ipv4.tcp_congestion_control)"
    if [[ "$actual" == *"$expected"* ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "kernel_bbr" \
            "tcp_congestion_control is ${actual}" ""
    else
        mb_emit_finding WARN medium "$MB_MODULE" "kernel_bbr" \
            "tcp_congestion_control is '${actual}', expected 'bbr' (better throughput on lossy links)" \
            "sudo ${FIX_KERNEL} --bbr"
    fi
}

check_kernel_file_max() {
    local expected
    expected="$(grep -E '^fs.file-max=' "${MB_RULES_DIR}/cis-kernel.rules" 2>/dev/null | cut -d= -f2)"
    expected="${expected:-1048576}"
    local actual
    actual="$(_sysctl_get fs.file-max)"
    if [[ -n "$actual" && "$actual" -ge "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "kernel_file_max" \
            "fs.file-max is ${actual}" ""
    else
        mb_emit_finding WARN low "$MB_MODULE" "kernel_file_max" \
            "fs.file-max is '${actual}', expected >= ${expected}" \
            "sudo ${FIX_KERNEL} --file-max ${expected}"
    fi
}

check_kernel_somaxconn() {
    local expected
    expected="$(grep -E '^net.core.somaxconn=' "${MB_RULES_DIR}/cis-kernel.rules" 2>/dev/null | cut -d= -f2)"
    expected="${expected:-4096}"
    local actual
    actual="$(_sysctl_get net.core.somaxconn)"
    if [[ -n "$actual" && "$actual" -ge "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "kernel_somaxconn" \
            "net.core.somaxconn is ${actual}" ""
    else
        mb_emit_finding WARN low "$MB_MODULE" "kernel_somaxconn" \
            "net.core.somaxconn is '${actual}', expected >= ${expected}" \
            "sudo ${FIX_KERNEL} --somaxconn ${expected}"
    fi
}

check_kernel_ip_forward() {
    local expected="0"
    local actual
    actual="$(_sysctl_get net.ipv4.ip_forward)"
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "kernel_ip_forward" \
            "net.ipv4.ip_forward is ${actual}" ""
    else
        mb_emit_finding WARN medium "$MB_MODULE" "kernel_ip_forward" \
            "net.ipv4.ip_forward is '${actual}', expected 0 (disable unless this is a router)" \
            "sudo ${FIX_KERNEL} --ip-forward 0"
    fi
}

check_kernel_syncookies() {
    local expected="1"
    local actual
    actual="$(_sysctl_get net.ipv4.tcp_syncookies)"
    if [[ "$actual" == "$expected" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "kernel_syncookies" \
            "tcp_syncookies is enabled" ""
    else
        mb_emit_finding FAIL high "$MB_MODULE" "kernel_syncookies" \
            "tcp_syncookies is '${actual}', expected 1 (SYN flood protection)" \
            "sudo ${FIX_KERNEL} --syncookies 1"
    fi
}

check_kernel_redirects() {
    local actual
    actual="$(_sysctl_get net.ipv4.conf.all.accept_redirects)"
    if [[ "$actual" == "0" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "kernel_redirects" \
            "ICMP redirects are disabled" ""
    else
        mb_emit_finding FAIL medium "$MB_MODULE" "kernel_redirects" \
            "net.ipv4.conf.all.accept_redirects is '${actual}', expected 0 (redirect spoofing risk)" \
            "sudo ${FIX_KERNEL} --redirects 0"
    fi
}

# ---------------------------------------------------------------------------
# Docker checks
# ---------------------------------------------------------------------------
_docker_daemon_json() {
    cat /etc/docker/daemon.json 2>/dev/null || echo "{}"
}

check_docker_exposed_daemon() {
    if ! mb_command_exists docker; then
        mb_emit_finding WARN info "$MB_MODULE" "docker_exposed_daemon" \
            "Docker is not installed — skipping" ""
        return
    fi
    local hosts
    hosts="$(_docker_daemon_json | grep -oE '"hosts"\s*:\s*\[[^]]*\]' || true)"
    if echo "$hosts" | grep -qE '0\.0\.0\.0|tcp://' && ! echo "$hosts" | grep -q '127.0.0.1'; then
        mb_emit_finding FAIL critical "$MB_MODULE" "docker_exposed_daemon" \
            "Docker daemon appears exposed to public addresses" \
            "sudo ${FIX_DOCKER} --no-exposed-daemon"
    else
        mb_emit_finding PASS info "$MB_MODULE" "docker_exposed_daemon" \
            "Docker daemon is not publicly exposed" ""
    fi
}

check_docker_log_rotation() {
    if ! mb_command_exists docker; then
        mb_emit_finding WARN info "$MB_MODULE" "docker_log_rotation" \
            "Docker is not installed — skipping" ""
        return
    fi
    local cfg
    cfg="$(_docker_daemon_json)"
    if echo "$cfg" | grep -q 'log-rotation\|"log-opts"'; then
        mb_emit_finding PASS info "$MB_MODULE" "docker_log_rotation" \
            "Docker log rotation is configured" ""
    else
        mb_emit_finding WARN medium "$MB_MODULE" "docker_log_rotation" \
            "Docker log rotation not found in daemon.json (logs can fill the disk)" \
            "sudo ${FIX_DOCKER} --log-rotation"
    fi
}

check_docker_user_namespace() {
    if ! mb_command_exists docker; then
        mb_emit_finding WARN info "$MB_MODULE" "docker_user_namespace" \
            "Docker is not installed — skipping" ""
        return
    fi
    local cfg
    cfg="$(_docker_daemon_json)"
    if echo "$cfg" | grep -q 'userns-remap'; then
        mb_emit_finding PASS info "$MB_MODULE" "docker_user_namespace" \
            "User namespace remapping is enabled" ""
    else
        mb_emit_finding WARN low "$MB_MODULE" "docker_user_namespace" \
            "User namespace remapping not enabled (container root == host root)" \
            "sudo ${FIX_DOCKER} --user-namespace"
    fi
}

# ---------------------------------------------------------------------------
# Auto-update check
# ---------------------------------------------------------------------------
check_autoupdate_enabled() {
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        if grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
            mb_emit_finding PASS info "$MB_MODULE" "autoupdate_enabled" \
                "unattended-upgrades is enabled" ""
            return
        fi
    fi
    if mb_command_exists dnf && systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
        mb_emit_finding PASS info "$MB_MODULE" "autoupdate_enabled" \
            "dnf-automatic timer is enabled" ""
        return
    fi
    mb_emit_finding FAIL high "$MB_MODULE" "autoupdate_enabled" \
        "Automatic security updates are not enabled" \
        "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -f noninteractive unattended-upgrades"
}

# ---------------------------------------------------------------------------
# Runner — executes all check_* functions in this file.
# ---------------------------------------------------------------------------
cis_benchmark_run() {
    local funcs=()
    while IFS= read -r fn; do
        funcs+=("$fn")
    done < <(declare -F | awk '{print $3}' | grep '^check_')
    for fn in "${funcs[@]}"; do
        "$fn" || true
    done
}

# Allow direct execution: `modules/cis-benchmark.sh` → emits all findings.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cis_benchmark_run
fi
