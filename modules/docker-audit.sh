#!/usr/bin/env bash
# docker-audit.sh — Docker security audit for the mb tool.
#
# Read-only audit of a Docker deployment based on CIS Docker Benchmark v1.6.0.
# Checks Docker daemon configuration (daemon.json), running container security
# posture (privileged, capabilities, namespace sharing, root user, readonly
# rootfs, healthcheck, resource limits, sensitive mounts), image security
# (tag pinning, content trust, dangling images), and Docker Compose security
# (privileged/cap_add/network_mode, port binding, sensitive env vars).
#
# Outputs:
#   - TXT report:  /var/log/docker-audit/docker-audit-latest.txt
#   - JSON report: /var/log/docker-audit/docker-audit-latest.json
#   - Pipe-delimited findings (consumed by the standard report generator)
#
# This module is strictly read-only: it never modifies any Docker configuration.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="docker"

# Dedicated report directory for Docker audit artefacts.
DOCKER_REPORT_DIR="${DOCKER_REPORT_DIR:-/var/log/docker-audit}"

# Docker daemon configuration file.
DOCKER_DAEMON_JSON="${DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"

# Docker socket path.
DOCKER_SOCK="${DOCKER_SOCK:-/var/run/docker.sock}"

# Dangerous capabilities that should not be added to containers.
DOCKER_DANGEROUS_CAPS=(SYS_ADMIN NET_ADMIN SYS_PTRACE SYS_MODULE DAC_READ_SEARCH DAC_OVERRIDE SETUID SETGID CHOWN FOWNER MKNOD AUDIT_WRITE AUDIT_CONTROL MAC_ADMIN MAC_OVERRIDE NET_RAW NET_BROADCAST IPC_LOCK IPC_OWNER SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG)

# Sensitive host directories that should not be mounted into containers.
DOCKER_SENSITIVE_MOUNTS=(/etc /root /var/run/docker.sock /boot /proc /sys /dev)

# Sensitive ports that should not be bound to 0.0.0.0.
DOCKER_SENSITIVE_PORTS=(22 2375 2376 3306 5432 6379 27017 9200)

# Counters for the summary (PASS/FAIL/WARN/SKIP).
_dk_pass=0
_dk_fail=0
_dk_warn=0
_dk_skip=0

# Collected findings for the JSON report (STATUS|SEVERITY|CHECK|MESSAGE).
_dk_findings=()

# Per-container findings for the detailed report (CONTAINER|STATUS|SEVERITY|CHECK|MESSAGE).
_dk_container_findings=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Run docker safely, swallowing stderr. Returns 0 if docker exists & command
# succeeds, non-zero otherwise. Output on stdout.
_docker() {
    if ! mb_command_exists docker; then
        return 127
    fi
    docker "$@" 2>/dev/null || true
}

# Emit a finding and track counters. Also records into the JSON findings array.
# Usage: _dk_emit <status> <severity> <check> <message> <fix>
_dk_emit() {
    local status="$1" severity="$2" check="$3" message="$4" fix="$5"
    mb_emit_finding "$status" "$severity" "$MB_MODULE" "$check" "$message" "$fix"
    case "$status" in
        PASS) _dk_pass=$((_dk_pass + 1)) ;;
        FAIL) _dk_fail=$((_dk_fail + 1)) ;;
        WARN) _dk_warn=$((_dk_warn + 1)) ;;
        SKIP) _dk_skip=$((_dk_skip + 1)) ;;
    esac
    _dk_findings+=("${status}|${severity}|${check}|${message}")
}

# Emit a container-specific finding (tracked in the per-container array).
# Usage: _dk_emit_container <container> <status> <severity> <check> <message> <fix>
_dk_emit_container() {
    local container="$1" status="$2" severity="$3" check="$4" message="$5" fix="$6"
    mb_emit_finding "$status" "$severity" "$MB_MODULE" "${check}:${container}" "$message" "$fix"
    case "$status" in
        PASS) _dk_pass=$((_dk_pass + 1)) ;;
        FAIL) _dk_fail=$((_dk_fail + 1)) ;;
        WARN) _dk_warn=$((_dk_warn + 1)) ;;
        SKIP) _dk_skip=$((_dk_skip + 1)) ;;
    esac
    _dk_findings+=("${status}|${severity}|${check}:${container}|${message}")
    _dk_container_findings+=("${container}|${status}|${severity}|${check}|${message}")
}

# Skip a check because Docker is not installed.
_dk_skip_not_installed() {
    local check="$1" label="$2"
    _dk_emit SKIP info "$check" \
        "Docker is not installed — ${label} skipped" \
        "sudo apt-get install -y docker.io"
}

# Read a value from daemon.json using grep (no jq dependency).
# Usage: _dk_daemon_json_get <key> → echoes the value or empty string.
_dk_daemon_json_get() {
    local key="$1"
    [[ -f "$DOCKER_DAEMON_JSON" ]] || return 0
    # Match "key": value or "key":value patterns.
    grep -oE "\"${key}\"\s*:\s*[^,}]+" "$DOCKER_DAEMON_JSON" 2>/dev/null \
        | sed -E "s/\"${key}\"\s*:\s*//" | tr -d ' "' || true
}

# Check if a boolean key in daemon.json is set to true.
_dk_daemon_json_is_true() {
    local key="$1"
    local val
    val="$(_dk_daemon_json_get "$key")"
    [[ "$val" == "true" ]]
}

# Check if a boolean key in daemon.json is set to false.
_dk_daemon_json_is_false() {
    local key="$1"
    local val
    val="$(_dk_daemon_json_get "$key")"
    [[ "$val" == "false" ]]
}

# ---------------------------------------------------------------------------
# Docker daemon configuration checks
# ---------------------------------------------------------------------------

dk_audit_daemon_json_exists() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "daemon_json_exists" "daemon.json check"
        return
    fi

    if [[ -f "$DOCKER_DAEMON_JSON" ]]; then
        _dk_emit PASS info "daemon_json_exists" \
            "Docker daemon config exists: ${DOCKER_DAEMON_JSON}" ""
    else
        _dk_emit WARN medium "daemon_json_exists" \
            "Docker daemon config not found: ${DOCKER_DAEMON_JSON} — using defaults" \
            "Create /etc/docker/daemon.json with security settings"
    fi
}

dk_audit_userland_proxy() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "userland_proxy" "userland-proxy check"
        return
    fi

    if _dk_daemon_json_is_false "userland-proxy"; then
        _dk_emit PASS info "userland_proxy" \
            "userland-proxy is disabled in daemon.json" ""
    else
        _dk_emit WARN medium "userland_proxy" \
            "userland-proxy is not explicitly disabled — it should be off" \
            "Set \"userland-proxy\": false in /etc/docker/daemon.json"
    fi
}

dk_audit_live_restore() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "live_restore" "live-restore check"
        return
    fi

    if _dk_daemon_json_is_true "live-restore"; then
        _dk_emit PASS info "live_restore" \
            "live-restore is enabled in daemon.json" ""
    else
        _dk_emit WARN medium "live_restore" \
            "live-restore is not enabled — containers stop when daemon restarts" \
            "Set \"live-restore\": true in /etc/docker/daemon.json"
    fi
}

dk_audit_no_new_privileges() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "no_new_privileges" "no-new-privileges check"
        return
    fi

    if _dk_daemon_json_is_true "no-new-privileges"; then
        _dk_emit PASS info "no_new_privileges" \
            "no-new-privileges is enabled in daemon.json" ""
    else
        _dk_emit WARN medium "no_new_privileges" \
            "no-new-privileges is not set at daemon level — containers may escalate privileges" \
            "Set \"no-new-privileges\": true in /etc/docker/daemon.json"
    fi
}

dk_audit_user_namespace() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "user_namespace" "user namespace remapping check"
        return
    fi

    local userns
    userns="$(_dk_daemon_json_get "userns-remap")"
    if [[ -n "$userns" ]]; then
        _dk_emit PASS info "user_namespace" \
            "User namespace remapping is enabled: ${userns}" ""
    else
        _dk_emit WARN medium "user_namespace" \
            "User namespace remapping is not configured — containers run as host root by default" \
            "Set \"userns-remap\": \"default\" in /etc/docker/daemon.json"
    fi
}

dk_audit_default_ulimit() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "default_ulimit" "default ulimit check"
        return
    fi

    local ulimits
    ulimits="$(_dk_daemon_json_get "default-ulimits")"
    if [[ -n "$ulimits" ]]; then
        _dk_emit PASS info "default_ulimit" \
            "Default ulimits are configured in daemon.json" ""
    else
        _dk_emit WARN low "default_ulimit" \
            "No default ulimits configured — containers have no resource guardrails" \
            "Set \"default-ulimits\" in /etc/docker/daemon.json"
    fi
}

dk_audit_auth_plugin() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "auth_plugin" "authorization plugin check"
        return
    fi

    local plugin
    plugin="$(_dk_daemon_json_get "authorization-plugins")"
    if [[ -n "$plugin" ]]; then
        _dk_emit PASS info "auth_plugin" \
            "Authorization plugin is configured: ${plugin}" ""
    else
        _dk_emit WARN low "auth_plugin" \
            "No authorization plugin configured — all docker commands are unrestricted" \
            "Consider configuring an authorization plugin for granular access control"
    fi
}

dk_audit_log_driver() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "log_driver" "log driver check"
        return
    fi

    local driver
    driver="$(_dk_daemon_json_get "log-driver")"
    if [[ -n "$driver" ]]; then
        _dk_emit PASS info "log_driver" \
            "Log driver is configured: ${driver}" ""
    else
        _dk_emit WARN medium "log_driver" \
            "No log driver configured in daemon.json — using default json-file without rotation" \
            "Set \"log-driver\": \"json-file\" with log-opts max-size and max-file"
    fi
}

dk_audit_log_rotation() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "log_rotation" "log rotation check"
        return
    fi

    local max_size max_file
    max_size="$(_dk_daemon_json_get "max-size")"
    max_file="$(_dk_daemon_json_get "max-file")"

    if [[ -n "$max_size" && -n "$max_file" ]]; then
        _dk_emit PASS info "log_rotation" \
            "Log rotation configured: max-size=${max_size}, max-file=${max_file}" ""
    else
        _dk_emit WARN medium "log_rotation" \
            "Log rotation not configured — container logs can fill the disk" \
            "Set \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"} in daemon.json"
    fi
}

dk_audit_iptables() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "iptables" "iptables check"
        return
    fi

    if _dk_daemon_json_is_false "iptables"; then
        _dk_emit WARN high "iptables" \
            "iptables is disabled in daemon.json — Docker firewall rules are not managed" \
            "Remove \"iptables\": false from /etc/docker/daemon.json"
    else
        _dk_emit PASS info "iptables" \
            "iptables is not disabled (Docker manages firewall rules)" ""
    fi
}

dk_audit_ssh_in_containers() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "ssh_in_containers" "SSH port exposure check"
        return
    fi

    # Check if any running container exposes port 22.
    local containers
    containers="$(_docker ps -q 2>/dev/null || true)"
    if [[ -z "$containers" ]]; then
        _dk_emit SKIP info "ssh_in_containers" \
            "No running containers — SSH port exposure check skipped" ""
        return
    fi

    local ssh_exposed=0
    while IFS= read -r cid; do
        [[ -n "$cid" ]] || continue
        local ports
        ports="$(_docker port "$cid" 2>/dev/null || true)"
        if echo "$ports" | grep -qE ':22\b|22/tcp'; then
            ssh_exposed=$((ssh_exposed + 1))
        fi
    done <<< "$containers"

    if [[ "$ssh_exposed" -eq 0 ]]; then
        _dk_emit PASS info "ssh_in_containers" \
            "No running containers expose SSH (port 22)" ""
    else
        _dk_emit FAIL high "ssh_in_containers" \
            "${ssh_exposed} container(s) expose SSH port 22 — should use host SSH only" \
            "Remove port 22 mapping from container run/compose config"
    fi
}

dk_audit_docker_sock_permissions() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "docker_sock_permissions" "Docker socket permissions"
        return
    fi

    if [[ ! -e "$DOCKER_SOCK" ]]; then
        _dk_emit SKIP info "docker_sock_permissions" \
            "Docker socket not found: ${DOCKER_SOCK}" ""
        return
    fi

    local mode owner group
    mode="$(stat -c '%a' "$DOCKER_SOCK" 2>/dev/null || stat -f '%Lp' "$DOCKER_SOCK" 2>/dev/null || echo "000")"
    owner="$(stat -c '%U' "$DOCKER_SOCK" 2>/dev/null || stat -f '%Su' "$DOCKER_SOCK" 2>/dev/null || echo "unknown")"
    group="$(stat -c '%G' "$DOCKER_SOCK" 2>/dev/null || stat -f '%Sg' "$DOCKER_SOCK" 2>/dev/null || echo "unknown")"

    if [[ "$mode" == "660" && "$owner" == "root" && "$group" == "docker" ]]; then
        _dk_emit PASS info "docker_sock_permissions" \
            "Docker socket permissions correct: ${mode} ${owner}:${group}" ""
    else
        _dk_emit FAIL high "docker_sock_permissions" \
            "Docker socket permissions unsafe: ${mode} ${owner}:${group} (expected 660 root:docker)" \
            "sudo chmod 660 ${DOCKER_SOCK} && sudo chown root:docker ${DOCKER_SOCK}"
    fi
}

# ---------------------------------------------------------------------------
# Container configuration checks (per running container)
# ---------------------------------------------------------------------------

dk_audit_container_privileged() {
    local cid="$1" cname="$2"
    local priv
    priv="$(_docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null || echo "false")"
    if [[ "$priv" == "true" ]]; then
        _dk_emit_container "$cname" FAIL high "container_privileged" \
            "Container '${cname}' is running in privileged mode" \
            "Remove --privileged; grant only specific capabilities with --cap-add"
    else
        _dk_emit_container "$cname" PASS info "container_privileged" \
            "Container '${cname}' is not privileged" ""
    fi
}

dk_audit_container_capabilities() {
    local cid="$1" cname="$2"
    local caps
    caps="$(_docker inspect --format '{{join .HostConfig.CapAdd " "}}' "$cid" 2>/dev/null || echo "")"

    if [[ -z "$caps" || "$caps" == "<no value>" ]]; then
        _dk_emit_container "$cname" PASS info "container_capabilities" \
            "Container '${cname}' has no extra capabilities added" ""
        return
    fi

    local dangerous=()
    for cap in "${DOCKER_DANGEROUS_CAPS[@]}"; do
        if echo "$caps" | grep -qw "$cap"; then
            dangerous+=("$cap")
        fi
    done

    if [[ "${#dangerous[@]}" -eq 0 ]]; then
        _dk_emit_container "$cname" PASS info "container_capabilities" \
            "Container '${cname}' caps: ${caps} (no dangerous caps)" ""
    else
        _dk_emit_container "$cname" FAIL high "container_capabilities" \
            "Container '${cname}' has dangerous cap(s): ${dangerous[*]}" \
            "Remove dangerous capabilities: docker stop ${cname} && docker run --cap-drop ALL ..."
    fi
}

dk_audit_container_network_host() {
    local cid="$1" cname="$2"
    local net
    net="$(_docker inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null || echo "")"

    if [[ "$net" == "host" ]]; then
        _dk_emit_container "$cname" FAIL high "container_network_host" \
            "Container '${cname}' uses host network mode" \
            "Use bridge or custom network instead of --network host"
    else
        _dk_emit_container "$cname" PASS info "container_network_host" \
            "Container '${cname}' network mode: ${net}" ""
    fi
}

dk_audit_container_pid_ipc_host() {
    local cid="$1" cname="$2"
    local pid_mode ipc_mode
    pid_mode="$(_docker inspect --format '{{.HostConfig.PidMode}}' "$cid" 2>/dev/null || echo "")"
    ipc_mode="$(_docker inspect --format '{{.HostConfig.IpcMode}}' "$cid" 2>/dev/null || echo "")"

    local issues=0
    if [[ "$pid_mode" == "host" ]]; then
        _dk_emit_container "$cname" FAIL high "container_pid_host" \
            "Container '${cname}' shares host PID namespace (--pid host)" \
            "Remove --pid host from container configuration"
        issues=$((issues + 1))
    else
        _dk_emit_container "$cname" PASS info "container_pid_host" \
            "Container '${cname}' PID mode: ${pid_mode}" ""
    fi

    if [[ "$ipc_mode" == "host" ]]; then
        _dk_emit_container "$cname" FAIL high "container_ipc_host" \
            "Container '${cname}' shares host IPC namespace (--ipc host)" \
            "Remove --ipc host from container configuration"
        issues=$((issues + 1))
    else
        _dk_emit_container "$cname" PASS info "container_ipc_host" \
            "Container '${cname}' IPC mode: ${ipc_mode}" ""
    fi
}

dk_audit_container_restart_policy() {
    local cid="$1" cname="$2"
    local policy
    policy="$(_docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$cid" 2>/dev/null || echo "")"

    if [[ -n "$policy" && "$policy" != "no" && "$policy" != "<no value>" ]]; then
        _dk_emit_container "$cname" PASS info "container_restart_policy" \
            "Container '${cname}' restart policy: ${policy}" ""
    else
        _dk_emit_container "$cname" WARN low "container_restart_policy" \
            "Container '${cname}' has no restart policy" \
            "Set --restart unless-stopped for production containers"
    fi
}

dk_audit_container_root_user() {
    local cid="$1" cname="$2"
    local user
    user="$(_docker inspect --format '{{.Config.User}}' "$cid" 2>/dev/null || echo "")"

    if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
        _dk_emit_container "$cname" WARN high "container_root_user" \
            "Container '${cname}' runs as root (no USER specified)" \
            "Add USER directive in Dockerfile or --user flag in docker run"
    else
        _dk_emit_container "$cname" PASS info "container_root_user" \
            "Container '${cname}' runs as user: ${user}" ""
    fi
}

dk_audit_container_readonly_rootfs() {
    local cid="$1" cname="$2"
    local ro
    ro="$(_docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid" 2>/dev/null || echo "false")"

    if [[ "$ro" == "true" ]]; then
        _dk_emit_container "$cname" PASS info "container_readonly_rootfs" \
            "Container '${cname}' has read-only root filesystem" ""
    else
        _dk_emit_container "$cname" WARN medium "container_readonly_rootfs" \
            "Container '${cname}' root filesystem is writable" \
            "Use --read-only with --tmpfs for writable directories"
    fi
}

dk_audit_container_healthcheck() {
    local cid="$1" cname="$2"
    local hc
    hc="$(_docker inspect --format '{{.Config.Healthcheck.Test}}' "$cid" 2>/dev/null || echo "")"

    if [[ -n "$hc" && "$hc" != "<no value>" && "$hc" != "[]" ]]; then
        _dk_emit_container "$cname" PASS info "container_healthcheck" \
            "Container '${cname}' has a healthcheck configured" ""
    else
        _dk_emit_container "$cname" WARN low "container_healthcheck" \
            "Container '${cname}' has no healthcheck" \
            "Add HEALTHCHECK in Dockerfile or --health-cmd in docker run"
    fi
}

dk_audit_container_resource_limits() {
    local cid="$1" cname="$2"
    local mem cpu
    mem="$(_docker inspect --format '{{.HostConfig.Memory}}' "$cid" 2>/dev/null || echo "0")"
    cpu="$(_docker inspect --format '{{.HostConfig.NanoCpus}}' "$cid" 2>/dev/null || echo "0")"

    local mem_set=0 cpu_set=0
    [[ "$mem" != "0" && "$mem" != "<no value>" ]] && mem_set=1
    [[ "$cpu" != "0" && "$cpu" != "<no value>" ]] && cpu_set=1

    if [[ "$mem_set" -eq 1 && "$cpu_set" -eq 1 ]]; then
        _dk_emit_container "$cname" PASS info "container_resource_limits" \
            "Container '${cname}' has memory + CPU limits" ""
    elif [[ "$mem_set" -eq 1 || "$cpu_set" -eq 1 ]]; then
        _dk_emit_container "$cname" WARN medium "container_resource_limits" \
            "Container '${cname}' has partial resource limits (mem=${mem_set}, cpu=${cpu_set})" \
            "Set both --memory and --cpus for complete resource limits"
    else
        _dk_emit_container "$cname" WARN medium "container_resource_limits" \
            "Container '${cname}' has no resource limits" \
            "Set --memory and --cpus to prevent resource exhaustion"
    fi
}

dk_audit_container_sensitive_mounts() {
    local cid="$1" cname="$2"
    local mounts
    mounts="$(_docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null || echo "")"

    if [[ -z "$mounts" || "$mounts" == "<no value>" ]]; then
        _dk_emit_container "$cname" PASS info "container_sensitive_mounts" \
            "Container '${cname}' has no bind mounts" ""
        return
    fi

    local dangerous=()
    for sm in "${DOCKER_SENSITIVE_MOUNTS[@]}"; do
        if echo "$mounts" | grep -qw "$sm"; then
            dangerous+=("$sm")
        fi
    done

    if [[ "${#dangerous[@]}" -eq 0 ]]; then
        _dk_emit_container "$cname" PASS info "container_sensitive_mounts" \
            "Container '${cname}' mounts look safe (no sensitive host dirs)" ""
    else
        _dk_emit_container "$cname" FAIL high "container_sensitive_mounts" \
            "Container '${cname}' mounts sensitive host dir(s): ${dangerous[*]}" \
            "Remove sensitive host directory mounts from container configuration"
    fi
}

# Run all container-level checks for each running container.
dk_audit_containers() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "containers" "container checks"
        return
    fi

    local containers
    containers="$(_docker ps -q 2>/dev/null || true)"
    if [[ -z "$containers" ]]; then
        _dk_emit SKIP info "containers" \
            "No running containers — container checks skipped" ""
        return
    fi

    local count=0
    while IFS= read -r cid; do
        [[ -n "$cid" ]] || continue
        count=$((count + 1))
        local cname
        cname="$(_docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||' || echo "$cid")"

        dk_audit_container_privileged "$cid" "$cname"
        dk_audit_container_capabilities "$cid" "$cname"
        dk_audit_container_network_host "$cid" "$cname"
        dk_audit_container_pid_ipc_host "$cid" "$cname"
        dk_audit_container_restart_policy "$cid" "$cname"
        dk_audit_container_root_user "$cid" "$cname"
        dk_audit_container_readonly_rootfs "$cid" "$cname"
        dk_audit_container_healthcheck "$cid" "$cname"
        dk_audit_container_resource_limits "$cid" "$cname"
        dk_audit_container_sensitive_mounts "$cid" "$cname"
    done <<< "$containers"

    _dk_emit PASS info "containers_summary" \
        "Audited ${count} running container(s)" ""
}

# ---------------------------------------------------------------------------
# Image security checks
# ---------------------------------------------------------------------------

dk_audit_image_tags_pinned() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "image_tags_pinned" "image tag pinning check"
        return
    fi

    local containers
    containers="$(_docker ps -q 2>/dev/null || true)"
    if [[ -z "$containers" ]]; then
        _dk_emit SKIP info "image_tags_pinned" \
            "No running containers — image tag check skipped" ""
        return
    fi

    local latest_count=0
    while IFS= read -r cid; do
        [[ -n "$cid" ]] || continue
        local image
        image="$(_docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || echo "")"
        if [[ "$image" == *":latest" || "$image" != *":"* ]]; then
            latest_count=$((latest_count + 1))
        fi
    done <<< "$containers"

    if [[ "$latest_count" -eq 0 ]]; then
        _dk_emit PASS info "image_tags_pinned" \
            "All running containers use pinned image tags" ""
    else
        _dk_emit WARN high "image_tags_pinned" \
            "${latest_count} container(s) use ':latest' or untagged images" \
            "Pin image tags to specific versions (e.g. nginx:1.25.3 not nginx:latest)"
    fi
}

dk_audit_image_content_trust() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "image_content_trust" "content trust check"
        return
    fi

    if [[ "${DOCKER_CONTENT_TRUST:-}" == "1" ]]; then
        _dk_emit PASS info "image_content_trust" \
            "DOCKER_CONTENT_TRUST is enabled" ""
    else
        _dk_emit WARN medium "image_content_trust" \
            "DOCKER_CONTENT_TRUST is not enabled — image signatures are not verified" \
            "export DOCKER_CONTENT_TRUST=1 or set in daemon environment"
    fi
}

dk_audit_image_scanning() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "image_scanning" "image scanning check"
        return
    fi

    if mb_command_exists trivy; then
        _dk_emit PASS info "image_scanning" \
            "Trivy is installed — image scanning is available (use mb audit run --module container-scan)" ""
    else
        _dk_emit WARN medium "image_scanning" \
            "No image scanner (Trivy) found — images are not scanned for vulnerabilities" \
            "Install Trivy: see container-scan module documentation"
    fi
}

dk_audit_dangling_images() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "dangling_images" "dangling image check"
        return
    fi

    local dangling
    dangling="$(_docker images -f "dangling=true" -q 2>/dev/null || true)"
    local dcount=0
    if [[ -n "$dangling" ]]; then
        dcount="$(echo "$dangling" | wc -l | tr -d ' ')"
    fi

    if [[ "$dcount" -eq 0 ]]; then
        _dk_emit PASS info "dangling_images" \
            "No dangling images found" ""
    else
        _dk_emit WARN low "dangling_images" \
            "${dcount} dangling image(s) found — wasting disk space" \
            "docker image prune -f"
    fi
}

# ---------------------------------------------------------------------------
# Docker Compose security checks
# ---------------------------------------------------------------------------

dk_audit_compose_files() {
    if ! mb_command_exists docker; then
        _dk_skip_not_installed "compose_files" "compose file check"
        return
    fi

    # Search for docker-compose.yml / compose.yaml in common locations.
    local compose_files=()
    local search_dirs=("/opt" "/srv" "/home" "/root" "/etc" "/usr/local/src")
    for dir in "${search_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r f; do
            [[ -n "$f" ]] && compose_files+=("$f")
        done < <(find "$dir" -maxdepth 4 \( -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" \) -type f 2>/dev/null || true)
    done

    if [[ "${#compose_files[@]}" -eq 0 ]]; then
        _dk_emit SKIP info "compose_files" \
            "No Docker Compose files found in common directories" ""
        return
    fi

    _dk_emit PASS info "compose_files" \
        "Found ${#compose_files[@]} compose file(s) to audit" ""

    for f in "${compose_files[@]}"; do
        _dk_audit_compose_privileged "$f"
        _dk_audit_compose_cap_add "$f"
        _dk_audit_compose_network_mode "$f"
        _dk_audit_compose_port_binding "$f"
        _dk_audit_compose_sensitive_env "$f"
    done
}

_dk_audit_compose_privileged() {
    local f="$1"
    local basename
    basename="$(basename "$f")"

    if [[ ! -r "$f" ]]; then
        _dk_emit SKIP info "compose_privileged:${basename}" \
            "Cannot read ${f} — skipping privileged check" ""
        return
    fi

    if grep -qiE 'privileged:\s*true' "$f" 2>/dev/null; then
        _dk_emit FAIL high "compose_privileged:${basename}" \
            "${f} contains privileged: true" \
            "Remove privileged: true from compose file"
    else
        _dk_emit PASS info "compose_privileged:${basename}" \
            "${basename}: no privileged containers" ""
    fi
}

_dk_audit_compose_cap_add() {
    local f="$1"
    local basename
    basename="$(basename "$f")"

    if [[ ! -r "$f" ]]; then
        _dk_emit SKIP info "compose_cap_add:${basename}" \
            "Cannot read ${f} — skipping cap_add check" ""
        return
    fi

    local cap_section
    cap_section="$(grep -A5 -iE 'cap_add:' "$f" 2>/dev/null || true)"
    local dangerous=()
    for cap in "${DOCKER_DANGEROUS_CAPS[@]}"; do
        if echo "$cap_section" | grep -qi "$cap"; then
            dangerous+=("$cap")
        fi
    done

    if [[ "${#dangerous[@]}" -eq 0 ]]; then
        _dk_emit PASS info "compose_cap_add:${basename}" \
            "${basename}: no dangerous cap_add entries" ""
    else
        _dk_emit FAIL high "compose_cap_add:${basename}" \
            "${f} adds dangerous cap(s): ${dangerous[*]}" \
            "Remove dangerous capabilities from cap_add in compose file"
    fi
}

_dk_audit_compose_network_mode() {
    local f="$1"
    local basename
    basename="$(basename "$f")"

    if [[ ! -r "$f" ]]; then
        _dk_emit SKIP info "compose_network_mode:${basename}" \
            "Cannot read ${f} — skipping network_mode check" ""
        return
    fi

    if grep -qiE 'network_mode:\s*host' "$f" 2>/dev/null; then
        _dk_emit FAIL high "compose_network_mode:${basename}" \
            "${f} uses network_mode: host" \
            "Use bridge or custom network instead of network_mode: host"
    else
        _dk_emit PASS info "compose_network_mode:${basename}" \
            "${basename}: no host network_mode" ""
    fi
}

_dk_audit_compose_port_binding() {
    local f="$1"
    local basename
    basename="$(basename "$f")"

    if [[ ! -r "$f" ]]; then
        _dk_emit SKIP info "compose_port_binding:${basename}" \
            "Cannot read ${f} — skipping port binding check" ""
        return
    fi

    local unsafe=0
    for port in "${DOCKER_SENSITIVE_PORTS[@]}"; do
        # Match patterns like "0.0.0.0:22:" or "22:22" without host IP.
        if grep -qE "0\.0\.0\.0:${port}[:/]|\"${port}:" "$f" 2>/dev/null; then
            unsafe=$((unsafe + 1))
        fi
    done

    if [[ "$unsafe" -eq 0 ]]; then
        _dk_emit PASS info "compose_port_binding:${basename}" \
            "${basename}: no sensitive ports bound to 0.0.0.0" ""
    else
        _dk_emit FAIL high "compose_port_binding:${basename}" \
            "${f} binds sensitive port(s) to all interfaces" \
            "Bind sensitive ports to 127.0.0.1 only (e.g. 127.0.0.1:22:22)"
    fi
}

_dk_audit_compose_sensitive_env() {
    local f="$1"
    local basename
    basename="$(basename "$f")"

    if [[ ! -r "$f" ]]; then
        _dk_emit SKIP info "compose_sensitive_env:${basename}" \
            "Cannot read ${f} — skipping env check" ""
        return
    fi

    # Check for common secret patterns in environment variables.
    local secret_patterns='PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL'
    local matches
    matches="$(grep -iE "^\s*${secret_patterns}:" "$f" 2>/dev/null | head -5 || true)"

    if [[ -z "$matches" ]]; then
        _dk_emit PASS info "compose_sensitive_env:${basename}" \
            "${basename}: no obvious secrets in environment variables" ""
    else
        _dk_emit WARN high "compose_sensitive_env:${basename}" \
            "${f} may contain secrets in environment variables" \
            "Use Docker secrets or .env files (gitignored) instead of inline env vars"
    fi
}

# ---------------------------------------------------------------------------
# Report generation (TXT + JSON)
# ---------------------------------------------------------------------------

_dk_generate_txt_report() {
    local out="$1"
    {
        printf 'Docker Security Audit Report\n'
        printf 'CIS Docker Benchmark v1.6.0\n'
        printf 'Generated: %s\n' "$(mb_now_iso)"
        printf 'Host: %s\n' "$(mb_hostname)"
        printf '========================================\n\n'

        printf 'Summary:\n'
        printf '  PASS: %s\n' "$_dk_pass"
        printf '  FAIL: %s\n' "$_dk_fail"
        printf '  WARN: %s\n' "$_dk_warn"
        printf '  SKIP: %s\n' "$_dk_skip"
        printf '  Total checks: %s\n' "$((_dk_pass + _dk_fail + _dk_warn + _dk_skip))"
        printf '\n'

        printf 'Findings:\n'
        printf '%-6s %-8s %-36s %s\n' "STAT" "SEV" "CHECK" "MESSAGE"
        printf '%-6s %-8s %-36s %s\n' "----" "---" "-----" "-------"
        for f in "${_dk_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            printf '%-6s %-8s %-36s %s\n' "$status" "$severity" "$check" "$message"
        done
        printf '\n'

        # Per-container detail section.
        if [[ "${#_dk_container_findings[@]}" -gt 0 ]]; then
            printf 'Per-Container Details:\n'
            printf '%-20s %-6s %-8s %-28s %s\n' "CONTAINER" "STAT" "SEV" "CHECK" "MESSAGE"
            printf '%-20s %-6s %-8s %-28s %s\n' "--------" "----" "---" "-----" "-------"
            for f in "${_dk_container_findings[@]}"; do
                IFS='|' read -r container status severity check message <<< "$f"
                printf '%-20s %-6s %-8s %-28s %s\n' "$container" "$status" "$severity" "$check" "$message"
            done
            printf '\n'
        fi

        printf 'Notes:\n'
        printf '  This is a read-only audit. No configuration was modified.\n'
        printf '  CIS Docker Benchmark v1.6.0: https://www.cisecurity.org/benchmark/docker\n'
        printf '  Related: dockerfile_hardener.sh, compose-recipes socket-proxy\n'
    } > "$out"
}

_dk_generate_json_report() {
    local out="$1"
    {
        printf '{\n'
        printf '  "module": "docker-audit",\n'
        printf '  "benchmark": "CIS Docker Benchmark v1.6.0",\n'
        printf '  "generated": "%s",\n' "$(mb_now_iso)"
        printf '  "host": "%s",\n' "$(mb_hostname)"
        printf '  "summary": {\n'
        printf '    "pass": %s,\n' "$_dk_pass"
        printf '    "fail": %s,\n' "$_dk_fail"
        printf '    "warn": %s,\n' "$_dk_warn"
        printf '    "skip": %s,\n' "$_dk_skip"
        printf '    "total": %s\n' "$((_dk_pass + _dk_fail + _dk_warn + _dk_skip))"
        printf '  },\n'
        printf '  "findings": [\n'
        local first=1
        for f in "${_dk_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            if [[ $first -eq 0 ]]; then
                printf ',\n'
            fi
            first=0
            # Escape double quotes and backslashes in message for JSON safety.
            local esc_msg esc_check
            esc_msg="${message//\\/\\\\}"
            esc_msg="${esc_msg//\"/\\\"}"
            esc_check="${check//\\/\\\\}"
            esc_check="${esc_check//\"/\\\"}"
            printf '    {\n'
            printf '      "status": "%s",\n' "$status"
            printf '      "severity": "%s",\n' "$severity"
            printf '      "check": "%s",\n' "$esc_check"
            printf '      "message": "%s"\n' "$esc_msg"
            printf '    }'
        done
        printf '\n  ],\n'

        # Per-container findings.
        printf '  "containers": [\n'
        first=1
        for f in "${_dk_container_findings[@]}"; do
            IFS='|' read -r container status severity check message <<< "$f"
            if [[ $first -eq 0 ]]; then
                printf ',\n'
            fi
            first=0
            local esc_msg esc_check esc_container
            esc_msg="${message//\\/\\\\}"
            esc_msg="${esc_msg//\"/\\\"}"
            esc_check="${check//\\/\\\\}"
            esc_check="${esc_check//\"/\\\"}"
            esc_container="${container//\\/\\\\}"
            esc_container="${esc_container//\"/\\\"}"
            printf '    {\n'
            printf '      "container": "%s",\n' "$esc_container"
            printf '      "status": "%s",\n' "$status"
            printf '      "severity": "%s",\n' "$severity"
            printf '      "check": "%s",\n' "$esc_check"
            printf '      "message": "%s"\n' "$esc_msg"
            printf '    }'
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

# ---------------------------------------------------------------------------
# Runner — executes all dk_audit_* functions and generates reports.
# ---------------------------------------------------------------------------
mb_audit_docker() {
    mb_info "Running Docker security audit module (CIS Docker Benchmark v1.6.0)..."

    # Docker daemon configuration checks.
    dk_audit_daemon_json_exists
    dk_audit_userland_proxy
    dk_audit_live_restore
    dk_audit_no_new_privileges
    dk_audit_user_namespace
    dk_audit_default_ulimit
    dk_audit_auth_plugin
    dk_audit_log_driver
    dk_audit_log_rotation
    dk_audit_iptables
    dk_audit_ssh_in_containers
    dk_audit_docker_sock_permissions

    # Container configuration checks (per running container).
    dk_audit_containers

    # Image security checks.
    dk_audit_image_tags_pinned
    dk_audit_image_content_trust
    dk_audit_image_scanning
    dk_audit_dangling_images

    # Docker Compose security checks.
    dk_audit_compose_files

    # Generate TXT + JSON reports.
    mb_ensure_dir "$DOCKER_REPORT_DIR"
    local txt_report="${DOCKER_REPORT_DIR}/docker-audit-latest.txt"
    local json_report="${DOCKER_REPORT_DIR}/docker-audit-latest.json"

    _dk_generate_txt_report "$txt_report"
    _dk_generate_json_report "$json_report"

    # Also copy into the standard mb-audit reports dir for unified access.
    if [[ -d "$MB_AUDIT_REPORTS_DIR" ]]; then
        cp -f "$txt_report" "${MB_AUDIT_REPORTS_DIR}/docker-audit-latest.txt" 2>/dev/null || true
        cp -f "$json_report" "${MB_AUDIT_REPORTS_DIR}/docker-audit-latest.json" 2>/dev/null || true
    fi

    local total=$((_dk_pass + _dk_fail + _dk_warn + _dk_skip))
    mb_ok "Docker audit complete: ${_dk_pass} PASS, ${_dk_fail} FAIL, ${_dk_warn} WARN, ${_dk_skip} SKIP (${total} checks)"
    mb_info "TXT report:  ${txt_report}"
    mb_info "JSON report: ${json_report}"
}

# Allow direct execution: `modules/docker-audit.sh` → runs all checks.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_audit_docker
fi
