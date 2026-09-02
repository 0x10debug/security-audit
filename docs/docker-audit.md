# Docker Audit

`modules/docker-audit.sh` — Read-only audit of Docker deployment security configuration, based on CIS Docker Benchmark v1.6.0.

## Audit Objectives

In Docker containerized deployments, issues such as improper daemon configuration, excessive container privileges, untrusted image sources, and Compose files leaking sensitive information all expose the host machine and the entire container cluster to attack surfaces. CIS Docker Benchmark v1.6.0 is a community-recognized Docker security configuration baseline covering four layers: daemon, containers, images, and Compose.

This module performs a comprehensive read-only health check on the installed Docker instance, covering daemon.json configuration, the security posture of each running container, image security (tag pinning, content trust, dangling images), and Docker Compose file security (privileged, cap_add, port binding, sensitive environment variables). It outputs both TXT + JSON reports with PASS/FAIL/WARN/SKIP summary counts. The module does not modify any configuration.

## Check Items Detail

### Docker daemon configuration (/etc/docker/daemon.json)

| Check Item | Description |
|---|---|
| `daemon_json_exists` | Whether `daemon.json` exists. Not found → WARN (using defaults, missing security configuration). |
| `userland_proxy` | Whether `userland-proxy` is disabled. Not disabled → WARN. |
| `live_restore` | Whether `live-restore` is enabled. Not enabled → WARN (containers stop on daemon restart). |
| `no_new_privileges` | Whether `no-new-privileges` is enabled. Not enabled → WARN (containers may escalate privileges). |
| `user_namespace` | Whether user namespace remapping (`userns-remap`) is configured. Not configured → WARN. |
| `default_ulimit` | Whether default ulimit is configured. Not configured → WARN (containers have no resource guardrails). |
| `auth_plugin` | Whether authorization plugins (`authorization-plugins`) are configured. Not configured → WARN (all docker commands unrestricted). |
| `log_driver` | Whether a log driver is configured. Not configured → WARN (uses default json-file without rotation). |
| `log_rotation` | Whether log rotation (`max-size` + `max-file`) is configured. Not configured → WARN (logs may fill up disk). |
| `iptables` | Whether `iptables` is disabled. Disabled → WARN (Docker firewall rules unmanaged). |
| `ssh_in_containers` | Whether any running container exposes SSH port 22. Exposed → FAIL. |
| `docker_sock_permissions` | Whether Docker socket (`/var/run/docker.sock`) permissions are `660 root:docker`. Incorrect → FAIL. |

### Container configuration (checked for each running container)

| Check Item | Description |
|---|---|
| `container_privileged` | Whether the `--privileged` flag is used. Used → FAIL. |
| `container_capabilities` | Whether dangerous caps are added (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, etc.). Added → FAIL. |
| `container_network_host` | Whether `--network host` is used. Used → FAIL. |
| `container_pid_host` | Whether `--pid host` is used (shares host PID namespace). Used → FAIL. |
| `container_ipc_host` | Whether `--ipc host` is used (shares host IPC namespace). Used → FAIL. |
| `container_restart_policy` | Whether a restart policy is configured. Not configured → WARN. |
| `container_root_user` | Whether running as root user. Running as root → WARN. |
| `container_readonly_rootfs` | Whether the root filesystem is read-only. Writable → WARN. |
| `container_healthcheck` | Whether a healthcheck is configured. Not configured → WARN. |
| `container_resource_limits` | Whether memory and CPU limits are configured. Not configured → WARN. |
| `container_sensitive_mounts` | Whether sensitive host directories are mounted (`/etc`, `/root`, `/var/run/docker.sock`, `/boot`, `/proc`, `/sys`, `/dev`). Mounted → FAIL. |

### Image security

| Check Item | Description |
|---|---|
| `image_tags_pinned` | Whether running containers use pinned tags (not `:latest`, not untagged). Using latest → WARN. |
| `image_content_trust` | Whether `DOCKER_CONTENT_TRUST` is enabled. Not enabled → WARN (image signatures not verified). |
| `image_scanning` | Whether an image scanning tool (Trivy) is installed. Not installed → WARN. |
| `dangling_images` | Whether dangling images exist. Exist → WARN (wastes disk space). |

### Docker Compose security

| Check Item | Description |
|---|---|
| `compose_privileged` | Whether the Compose file contains `privileged: true`. Contains → FAIL. |
| `compose_cap_add` | Whether the Compose file adds dangerous caps. Added → FAIL. |
| `compose_network_mode` | Whether the Compose file uses `network_mode: host`. Used → FAIL. |
| `compose_port_binding` | Whether the Compose file binds sensitive ports to `0.0.0.0`. Bound → FAIL. |
| `compose_sensitive_env` | Whether the Compose file environment variables contain suspected secrets (`PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`, etc.). Contains → WARN. |

## Output

- **TXT report**: `/var/log/docker-audit/docker-audit-latest.txt`
- **JSON report**: `/var/log/docker-audit/docker-audit-latest.json`
- Reports are also copied to `/var/log/mb-audit/reports/` for unified access.
- Summary: PASS / FAIL / WARN / SKIP counts.
- Detailed findings grouped by container (TXT report includes Per-Container Details section, JSON report includes `containers` array).
- Pipe-delimited findings (`STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX`) for consumption by the standard report generator.

## Usage

```bash
# Run the Docker audit module standalone
sudo mb audit run --module docker

# Run with other modules
sudo mb audit run --module cis-benchmark,docker,container-scan

# Execute the script directly
sudo modules/docker-audit.sh
```

## Common Issues and Remediation

### daemon.json does not exist

```
WARN | medium | daemon_json_exists | Docker daemon config not found: /etc/docker/daemon.json
```
Remediation: Create `daemon.json` and add security configuration:
```json
{
  "userland-proxy": false,
  "live-restore": true,
  "no-new-privileges": true,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
```

### Container running in privileged mode

```
FAIL | high | container_privileged:web | Container 'web' is running in privileged mode
```
`--privileged` grants the container nearly all host capabilities, equivalent to root-level access. Remediation: Remove `--privileged` and grant only necessary `--cap-add`.

### Container adds dangerous caps

```
FAIL | high | container_capabilities:web | Container 'web' has dangerous cap(s): SYS_ADMIN NET_ADMIN
```
Remediation: Remove dangerous caps, apply least-privilege principle:
```bash
docker stop web
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE ...
```

### Container uses host network

```
FAIL | high | container_network_host:web | Container 'web' uses host network mode
```
`--network host` makes the container directly use the host network stack, bypassing network isolation. Remediation: Use bridge or a custom network.

### Container runs as root

```
WARN | high | container_root_user:web | Container 'web' runs as root (no USER specified)
```
Remediation: Add a `USER` instruction in the Dockerfile, or specify `--user` when running `docker run`.

### Docker socket permissions incorrect

```
FAIL | high | docker_sock_permissions | Docker socket permissions unsafe: 666 root:root
```
The Docker socket is equivalent to host root access. Overly permissive permissions (e.g., 666) allow any user to control Docker. Remediation:
```bash
sudo chmod 660 /var/run/docker.sock
sudo chown root:docker /var/run/docker.sock
```

### Image uses :latest tag

```
WARN | high | image_tags_pinned | 2 container(s) use ':latest' or untagged images
```
The `:latest` tag points to different images over time, leading to non-reproducible deployments. Remediation: Pin to a specific version (e.g., `nginx:1.25.3`).

### Compose file contains sensitive environment variables

```
WARN | high | compose_sensitive_env:docker-compose.yml | may contain secrets in environment variables
```
Remediation: Use Docker secrets or a `.env` file (add to `.gitignore`); do not hardcode secrets in the Compose file.

### Log rotation not configured

```
WARN | medium | log_rotation | Log rotation not configured
```
Container logs without rotation will gradually fill up the disk. Remediation: Configure in `daemon.json`:
```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
```

## Relationship with the gold-standard project dockerfile_hardener.sh

[dockerfile_hardener.sh](https://github.com/0x10debug/dockerfile_hardener) is the gold-standard project's Dockerfile hardening tool, responsible for **build-time** static hardening of Dockerfiles: removing unnecessary packages, adding non-root USER, configuring HEALTHCHECK, setting readonly rootfs, minimizing layers, etc.

This module is responsible for **runtime auditing**: verifying that deployed containers follow the security posture after Dockerfile hardening (non-root user, healthcheck present, readonly rootfs, no dangerous caps, etc.). Together they form a "build hardening → runtime verification" closed loop:

1. dockerfile_hardener.sh hardens the Dockerfile
2. Build and deploy the image
3. `mb audit run --module docker` verifies the runtime security posture
4. Drift detection (`mb audit drift`) captures subsequent configuration changes
5. After issues are found, return to step 1 to fix the Dockerfile or adjust runtime parameters

## Relationship with compose-recipes socket-proxy

The [compose-recipes](https://github.com/0x10debug/compose-recipes) socket-proxy solution places a reverse proxy (e.g., Tecnativa/docker-socket-proxy) in front of the Docker socket, exposing only whitelisted API endpoints, preventing containers from obtaining host root privileges by mounting the Docker socket.

This module's `container_sensitive_mounts` check detects whether a container directly mounts `/var/run/docker.sock` (FAIL level). If this mount is detected, using socket-proxy instead of direct mounting is recommended:

1. Deploy the compose-recipes socket-proxy service
2. Change containers that need Docker API access to connect via socket-proxy (e.g., `DOCKER_HOST=tcp://socket-proxy:2375`)
3. Open only the necessary API endpoints in socket-proxy (e.g., `CONTAINERS=1`, `POST=0`)
4. Re-run `mb audit run --module docker` to confirm the sensitive mount is eliminated

This preserves the container's limited access to the Docker API while avoiding the privilege escalation risk of directly mounting the socket.
