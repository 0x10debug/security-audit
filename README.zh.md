# VPS 安全审计 — CIS Benchmark、漂移检测与自动修复

一个自托管的 VPS 安全审计工具：按 CIS Benchmark 控制项检查服务器、分析 auth 日志中的可疑活动、扫描运行中 Docker 容器的已知 CVE、并基于可信基线检测配置漂移。每一条发现都附带可直接执行的修复命令——从"发现问题"到"解决问题"只需一步。

为自建 Linux VPS、希望持续自动加固安全但又不想引入商业 SIEM 的运维人员设计。与 [0x10debug/vps-bootstrap](https://github.com/0x10debug/vps-bootstrap)（初始服务器加固）和 [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack)（监控与告警）配套使用。纯 Bash 实现，除标准系统工具外无运行时依赖，所有脚本幂等可重复执行。

---

## 审计模块

| 模块 | 检查内容 | 附带修复命令 |
|---|---|---|
| `cis-benchmark` | SSH 加固、防火墙默认策略、内核 sysctl 参数、Docker daemon 配置、自动更新 | 是 |
| `cis-v14` | CIS Benchmark v14.0 检查（与 cis-benchmark 相同，显式指定 v14.0 运行的别名） | 是 |
| `lynis` | 通过 Lynis 进行全系统加固扫描（缺失时自动安装） | Lynis 建议 |
| `lynis-score` | Lynis CIS 合规评分 — 运行 Lynis，将结果映射到 CIS v14.0 控制项，生成 0–100 合规评分及按章节分组的报告（TXT + JSON） | 是 |
| `log-audit` | SSH 失败登录、来自新 IP 的成功登录、sudo 事件、用户增删、crontab 修改、敏感文件 mtime 完整性 | 是 |
| `container-scan` | 用 Trivy 扫描所有运行中 Docker 镜像，按 Critical/High/Medium/Low 分组 | 是 |
| `crowdsec` | CrowdSec 部署与安全配置审计 — 安装状态、采集源、场景、bouncer、决策/告警、威胁情报、API 暴露、配置文件权限（TXT + JSON） | 是 |
| `docker` | Docker 安全审计（CIS Docker Benchmark v1.6.0）— daemon 配置、容器安全姿态（privileged、cap、命名空间共享、root 用户、只读 rootfs、healthcheck、资源限制、敏感挂载）、镜像安全（tag pinning、内容信任、dangling 镜像）、Compose 安全（TXT + JSON） | 是 |
| `drift` | 将当前 SSH、防火墙、内核、Docker 状态与基线快照对比 | 是 |

---

## 快速开始

```bash
# 克隆
git clone https://github.com/0x10debug/security-audit.git
cd security-audit

# 运行完整审计（生成 HTML + JSON 报告）
sudo ./mb audit run

# 查看上次运行摘要
./mb audit status

# 打开最新 HTML 报告
./mb audit report

# 预览修复内容但不实际执行
sudo ./mb audit fix --dry-run

# 应用所有修复
sudo ./mb audit fix
```

报告保存在 `/var/log/mb-audit/reports/`：
- `audit-latest.html` — 人类可读报告（指向最新运行的符号链接）
- `audit-latest.json` — 机器可读报告，便于集成

---

## 用法

### 只运行指定模块

```bash
sudo ./mb audit run --module cis-benchmark,log-audit
```

### 运行 CIS v14.0 合规评分

```bash
# 运行基于 Lynis 的 CIS v14.0 合规评分模块
sudo ./mb audit run --module lynis-score

# 评分报告保存到：
#   /var/log/mb-audit/reports/cis-score-latest.txt
#   /var/log/mb-audit/reports/cis-score-latest.json
```

评分模块运行 Lynis，将结果映射到完整的 CIS Benchmark v14.0 控制项集
（6 个章节、300+ 控制项），生成加权合规评分（0–100）及按章节分组的报告。
完整的控制项→修复脚本映射见
[`docs/cis-v14.0-mapping.md`](docs/cis-v14.0-mapping.md)。

### 应用 CIS v14.0 修复脚本

```bash
# SSH 加固（CIS v14.0 第 5.1 节）
sudo fixes/cis-ssh-hardening.sh --all

# 内核与网络加固（CIS v14.0 第 3.1/3.2/1.6 节）
sudo fixes/cis-kernel-hardening.sh --all

# 防火墙配置（CIS v14.0 第 3.4 节）
sudo fixes/cis-firewall-setup.sh --all

# 文件权限与系统维护（CIS v14.0 第 1.1/6.1/6.2 节）
sudo fixes/cis-permissions-fix.sh --all

# 预览修复内容但不实际执行
sudo fixes/cis-ssh-hardening.sh --all --dry-run
```

### 创建基线快照

捕获当前可信状态，以便日后检测漂移：

```bash
sudo ./mb audit baseline
```

基线保存到 `/etc/mb-backup/baseline.yaml`（与 vps-bootstrap 对齐）。

### 检查配置漂移

```bash
sudo ./mb audit drift
```

### 设置每日定时审计（cron）

```bash
sudo ./mb audit schedule --daily        # 默认 03:15
sudo ./mb audit schedule --daily --hour 4 --minute 30
sudo ./mb audit schedule --remove
sudo ./mb audit schedule                # 查看当前状态
```

### 更新工具

```bash
sudo ./mb audit update      # git pull
```

---

## 自定义规则

规则文件位于 `rules/*.rules`，采用简单的 `key=value` 格式。按你的环境修改：

```bash
# rules/cis-ssh.rules
Port=2222
PermitRootLogin=no
PasswordAuthentication=no
```

编写自定义检查请见 [`docs/custom-rules.md`](docs/custom-rules.md)，将 `rules/custom.rules.example` 复制为 `rules/custom.rules` 即可开始。

---

## 常见问题

**1. 需要联网吗？**
仅首次运行时（若需安装 Lynis 或 Trivy）需要联网。之后审计可完全离线运行。`mb audit update`（git pull）需要联网。

**2. 在生产服务器上运行 `mb audit fix` 安全吗？**
请务必先加 `--dry-run` 预览。修复脚本会备份每个被修改的文件（`.mb.bak.<时间戳>`），且只修改与期望值不同的指令。SSH 重启会自动处理。

**3. 支持哪些发行版？**
任何带 Bash 4+ 的 Debian/Ubuntu 或 RHEL 系（CentOS、Rocky、Alma、Fedora）Linux。防火墙检查优先使用 ufw，回退到 iptables。

**4. 与直接运行 Lynis 有什么区别？**
Lynis 只是其中一个模块。本工具还做日志分析、容器 CVE 扫描、基线漂移检测，并且——关键在于——为每条发现输出具体修复命令，让你一步完成修复，而不是读完报告再自己查命令。

**5. 基线存在哪里，为什么？**
存在 `/etc/mb-backup/baseline.yaml`，与 vps-bootstrap 的备份目录一致。这样所有 mb 套件状态都在一个可预测的位置，且能在包升级后保留。

---

## 文档

- [审计指南](docs/audit-guide.md) — 如何运行审计并解读报告
- [CIS Benchmark](docs/cis-benchmark.md) — 检查了哪些控制项及原因
- [CIS v14.0 映射](docs/cis-v14.0-mapping.md) — 完整的 CIS v14.0 控制项→审计规则→修复脚本映射及评分方法说明
- [漂移检测](docs/drift-detection.md) — 漂移检测的工作原理与意义
- [CrowdSec 审计](docs/crowdsec-audit.md) — CrowdSec 部署与安全配置审计
- [Docker 审计](docs/docker-audit.md) — Docker 安全审计（CIS Docker Benchmark v1.6.0）
- [自定义规则](docs/custom-rules.md) — 如何编写自定义审计规则

---

## 相关仓库

- [0x10debug/vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) — VPS 初始加固与配置
- [0x10debug/monitor-stack](https://github.com/0x10debug/monitor-stack) — 监控与告警栈

---

## 许可证

MIT — 见 [LICENSE](LICENSE)。Copyright (c) 2026 [0x10debug](https://github.com/0x10debug)。
