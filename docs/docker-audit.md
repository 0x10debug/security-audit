# Docker Audit

`modules/docker-audit.sh` — 只读审计 Docker 部署的安全配置，基于 CIS Docker Benchmark v1.6.0。

## 审计目标

Docker 容器化部署中，daemon 配置不当、容器权限过大、镜像来源不可信、Compose 文件泄露敏感信息等问题，都会将宿主机和整个容器集群暴露在攻击面下。CIS Docker Benchmark v1.6.0 是社区公认的 Docker 安全配置基线，覆盖 daemon、容器、镜像、Compose 四个层面。

本模块对已安装的 Docker 实例做全面只读体检，覆盖 daemon.json 配置、每个运行中容器的安全姿态、镜像安全（tag pinning、内容信任、dangling 镜像）、以及 Docker Compose 文件安全（privileged、cap_add、端口绑定、敏感环境变量），输出 TXT + JSON 双报告与 PASS/FAIL/WARN/SKIP 摘要计数。模块不修改任何配置。

## 检查项详解

### Docker daemon 配置（/etc/docker/daemon.json）

| 检查项 | 说明 |
|---|---|
| `daemon_json_exists` | `daemon.json` 是否存在。不存在 → WARN（使用默认值，缺少安全配置）。 |
| `userland_proxy` | `userland-proxy` 是否已禁用。未禁用 → WARN。 |
| `live_restore` | `live-restore` 是否已启用。未启用 → WARN（daemon 重启时容器会停止）。 |
| `no_new_privileges` | `no-new-privileges` 是否已启用。未启用 → WARN（容器可能提权）。 |
| `user_namespace` | 用户命名空间重映射（`userns-remap`）是否配置。未配置 → WARN。 |
| `default_ulimit` | 默认 ulimit 是否配置。未配置 → WARN（容器无资源护栏）。 |
| `auth_plugin` | 授权插件（`authorization-plugins`）是否配置。未配置 → WARN（所有 docker 命令无限制）。 |
| `log_driver` | 日志驱动是否配置。未配置 → WARN（使用默认 json-file 无轮转）。 |
| `log_rotation` | 日志轮转（`max-size` + `max-file`）是否配置。未配置 → WARN（日志可能撑满磁盘）。 |
| `iptables` | `iptables` 是否被禁用。被禁用 → WARN（Docker 防火墙规则不受管理）。 |
| `ssh_in_containers` | 是否有运行中容器暴露 SSH 端口 22。暴露 → FAIL。 |
| `docker_sock_permissions` | Docker socket（`/var/run/docker.sock`）权限是否为 `660 root:docker`。不正确 → FAIL。 |

### 容器配置（对每个运行中容器检查）

| 检查项 | 说明 |
|---|---|
| `container_privileged` | 是否使用 `--privileged` 标志。使用 → FAIL。 |
| `container_capabilities` | 是否添加了危险 cap（`SYS_ADMIN`、`NET_ADMIN`、`SYS_PTRACE` 等）。添加 → FAIL。 |
| `container_network_host` | 是否使用 `--network host`。使用 → FAIL。 |
| `container_pid_host` | 是否使用 `--pid host`（共享宿主 PID 命名空间）。使用 → FAIL。 |
| `container_ipc_host` | 是否使用 `--ipc host`（共享宿主 IPC 命名空间）。使用 → FAIL。 |
| `container_restart_policy` | 是否配置了重启策略。未配置 → WARN。 |
| `container_root_user` | 是否以 root 用户运行。以 root 运行 → WARN。 |
| `container_readonly_rootfs` | 根文件系统是否只读。可写 → WARN。 |
| `container_healthcheck` | 是否配置了 healthcheck。未配置 → WARN。 |
| `container_resource_limits` | 是否配置了内存和 CPU 限制。未配置 → WARN。 |
| `container_sensitive_mounts` | 是否挂载了敏感宿主目录（`/etc`、`/root`、`/var/run/docker.sock`、`/boot`、`/proc`、`/sys`、`/dev`）。挂载 → FAIL。 |

### 镜像安全

| 检查项 | 说明 |
|---|---|
| `image_tags_pinned` | 运行中容器是否使用 pinned tag（非 `:latest`、非无 tag）。使用 latest → WARN。 |
| `image_content_trust` | `DOCKER_CONTENT_TRUST` 是否启用。未启用 → WARN（镜像签名不验证）。 |
| `image_scanning` | 是否安装了镜像扫描工具（Trivy）。未安装 → WARN。 |
| `dangling_images` | 是否存在 dangling 镜像。存在 → WARN（浪费磁盘空间）。 |

### Docker Compose 安全

| 检查项 | 说明 |
|---|---|
| `compose_privileged` | Compose 文件中是否包含 `privileged: true`。包含 → FAIL。 |
| `compose_cap_add` | Compose 文件中是否添加了危险 cap。添加 → FAIL。 |
| `compose_network_mode` | Compose 文件中是否使用 `network_mode: host`。使用 → FAIL。 |
| `compose_port_binding` | Compose 文件中是否将敏感端口绑定到 `0.0.0.0`。绑定 → FAIL。 |
| `compose_sensitive_env` | Compose 文件环境变量中是否包含疑似密钥（`PASSWORD`、`SECRET`、`API_KEY`、`TOKEN` 等）。包含 → WARN。 |

## 输出

- **TXT 报告**：`/var/log/docker-audit/docker-audit-latest.txt`
- **JSON 报告**：`/var/log/docker-audit/docker-audit-latest.json`
- 报告同时复制到 `/var/log/mb-audit/reports/` 便于统一访问。
- 摘要：PASS / FAIL / WARN / SKIP 计数。
- 按容器分组的详细发现（TXT 报告含 Per-Container Details 段，JSON 报告含 `containers` 数组）。
- 管道分隔的 findings（`STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX`）供标准报告生成器消费。

## 运行

```bash
# 单独运行 Docker 审计模块
sudo mb audit run --module docker

# 与其他模块一起运行
sudo mb audit run --module cis-benchmark,docker,container-scan

# 直接执行脚本
sudo modules/docker-audit.sh
```

## 常见问题与修复建议

### daemon.json 不存在

```
WARN | medium | daemon_json_exists | Docker daemon config not found: /etc/docker/daemon.json
```
修复：创建 `daemon.json` 并添加安全配置：
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

### 容器以 privileged 模式运行

```
FAIL | high | container_privileged:web | Container 'web' is running in privileged mode
```
`--privileged` 赋予容器几乎所有宿主能力，等同于 root 级别访问。修复：移除 `--privileged`，仅授予必要的 `--cap-add`。

### 容器添加了危险 cap

```
FAIL | high | container_capabilities:web | Container 'web' has dangerous cap(s): SYS_ADMIN NET_ADMIN
```
修复：移除危险 cap，使用最小权限原则：
```bash
docker stop web
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE ...
```

### 容器使用 host 网络

```
FAIL | high | container_network_host:web | Container 'web' uses host network mode
```
`--network host` 让容器直接使用宿主网络栈，绕过网络隔离。修复：使用 bridge 或自定义网络。

### 容器以 root 运行

```
WARN | high | container_root_user:web | Container 'web' runs as root (no USER specified)
```
修复：在 Dockerfile 中添加 `USER` 指令，或在 `docker run` 时指定 `--user`。

### Docker socket 权限不当

```
FAIL | high | docker_sock_permissions | Docker socket permissions unsafe: 666 root:root
```
Docker socket 等同于宿主 root 访问权。权限过宽（如 666）允许任何用户控制 Docker。修复：
```bash
sudo chmod 660 /var/run/docker.sock
sudo chown root:docker /var/run/docker.sock
```

### 镜像使用 :latest tag

```
WARN | high | image_tags_pinned | 2 container(s) use ':latest' or untagged images
```
`:latest` 标签会随时间指向不同镜像，导致不可重现部署。修复：pin 到具体版本（如 `nginx:1.25.3`）。

### Compose 文件包含敏感环境变量

```
WARN | high | compose_sensitive_env:docker-compose.yml | may contain secrets in environment variables
```
修复：使用 Docker secrets 或 `.env` 文件（加入 `.gitignore`），不要在 Compose 文件中硬编码密钥。

### 日志轮转未配置

```
WARN | medium | log_rotation | Log rotation not configured
```
容器日志无轮转会逐渐撑满磁盘。修复：在 `daemon.json` 中配置：
```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
```

## 与金牌项目 dockerfile_hardener.sh 的关系

[dockerfile_hardener.sh](https://github.com/0x10debug/dockerfile_hardener) 是金牌项目的 Dockerfile 加固工具，负责在**构建时**对 Dockerfile 做静态加固：移除不必要的包、添加非 root USER、配置 HEALTHCHECK、设置 readonly rootfs、最小化层数等。

本模块负责**运行时审计**：验证已部署的容器是否遵循了 Dockerfile 加固后的安全姿态（非 root 用户、healthcheck 存在、readonly rootfs、无危险 cap 等）。两者形成"构建加固 → 运行验证"闭环：

1. dockerfile_hardener.sh 加固 Dockerfile
2. 构建并部署镜像
3. `mb audit run --module docker` 验证运行时安全姿态
4. 漂移检测（`mb audit drift`）捕获后续配置变化
5. 发现问题后回到步骤 1 修复 Dockerfile 或调整运行参数

## 与 compose-recipes socket-proxy 的关系

[compose-recipes](https://github.com/0x10debug/compose-recipes) 的 socket-proxy 方案通过在 Docker socket 前放置一个反向代理（如 Tecnativa/docker-socket-proxy），仅暴露白名单 API 端点，防止容器通过挂载 Docker socket 获得宿主 root 权限。

本模块的 `container_sensitive_mounts` 检查项会检测容器是否直接挂载了 `/var/run/docker.sock`（FAIL 级别）。如果检测到该挂载，推荐使用 socket-proxy 替代直接挂载：

1. 部署 compose-recipes 的 socket-proxy 服务
2. 将需要 Docker API 访问的容器改为连接 socket-proxy（如 `DOCKER_HOST=tcp://socket-proxy:2375`）
3. 在 socket-proxy 中仅开放必要的 API 端点（如 `CONTAINERS=1`，`POST=0`）
4. 重新运行 `mb audit run --module docker` 确认敏感挂载已消除

这样既保留了容器对 Docker API 的有限访问能力，又避免了直接挂载 socket 带来的提权风险。
