# CrowdSec Audit

`modules/crowdsec-audit.sh` — 只读审计 CrowdSec 部署状态与安全配置。

## 审计目标

CrowdSec 是一个协作式入侵防御系统：通过采集日志、运行场景（scenario）检测攻击行为、并通过 bouncer 执行封禁决策，同时将威胁情报贡献到社区 API（CAPI）。任何一个环节缺失或配置错误都会让防护形同虚设。

本模块对已安装的 CrowdSec 实例做全面只读体检，覆盖从安装到威胁情报的完整链路，输出 TXT + JSON 双报告与 PASS/FAIL/WARN/SKIP 摘要计数。模块不修改任何配置。

## 检查项详解

### 安装与服务状态

| 检查项 | 说明 |
|---|---|
| `installation` | CrowdSec 是否安装（`cscli version`）。未安装直接 FAIL。 |
| `service` | `crowdsec` systemd 服务是否 active + enabled。 |
| `bouncer_service` | 是否存在 `crowdsec-bouncer-*` 服务且全部 active。无 bouncer → WARN。 |
| `database_backend` | 数据库后端类型（SQLite / MySQL / PostgreSQL），通过 `cscli config show` 或 `config.yaml` 推断。 |

### 采集源（acquisition）

| 检查项 | 说明 |
|---|---|
| `acquisition_file` | `/etc/crowdsec/acquis.yaml` 是否存在且可读。 |
| `acquisition_sources` | 枚举已配置的日志源类型（file / journalctl / docker）及数量。 |
| `critical_sources` | 检查关键日志源是否覆盖：SSH、auth.log、syslog、nginx、apache。缺失 → WARN。 |
| `docker_acquisition` | Docker 已安装时，检查容器日志采集是否配置。 |

### 场景（scenarios）

| 检查项 | 说明 |
|---|---|
| `scenarios_installed` | 已安装场景总数（`cscli scenarios list`）。零场景 → FAIL。 |
| `key_scenarios` | 关键场景是否启用：`ssh-bf`、`http-bf`、`crawl`、`scan`。缺失 → WARN。 |
| `custom_scenarios` | 检测非 `crowdsecurity/` 命名空间的自定义场景，提示审查。 |
| `scenario_updates` | Hub 更新状态，提示定期 `cscli hub update`。 |

### Bouncer 配置

| 检查项 | 说明 |
|---|---|
| `bouncers_list` | 已注册 bouncer 数量（`cscli bouncers list`）。零 → FAIL。 |
| `bouncer_types` | 识别 bouncer 类型（iptables / nginx / cfwall / appsec）。 |
| `bouncer_decisions` | bouncer 是否处于 active 状态并在应用决策。 |

### 决策与告警

| 检查项 | 说明 |
|---|---|
| `active_decisions` | 当前活跃决策数量（`cscli decisions list`）。 |
| `recent_alerts` | 最近告警数量（`cscli alerts list`）。 |
| `banned_ips` | 当前被封禁 IP 列表（提取 IPv4 地址，取前 5 个样本）。 |
| `whitelist` | 白名单配置是否存在，降低误封风险。无白名单 → WARN。 |

### 威胁情报

| 检查项 | 说明 |
|---|---|
| `capi_status` | CAPI（CrowdSec Central API）注册与推送状态（`cscli metrics`）。未注册 → WARN。 |
| `community_ti` | 社区威胁情报订阅是否活跃。 |
| `local_blocklist` | 手动添加的本地封禁决策数量。 |

### 安全配置

| 检查项 | 说明 |
|---|---|
| `api_port_exposure` | LAPI 端口（默认 8080）是否绑定到 `0.0.0.0`（公网暴露 → FAIL）。 |
| `lapi_auth` | LAPI bouncer 认证是否配置（bouncer token 存在）。 |
| `config_permissions` | 配置文件权限，特别是 `*_credentials.yaml` 不可被其他用户读取。 |
| `bouncer_token_security` | bouncer 配置文件（`bouncer-*.yaml`）不可被其他用户读取。 |

## 输出

- **TXT 报告**：`/var/log/crowdsec-audit/crowdsec-audit-latest.txt`
- **JSON 报告**：`/var/log/crowdsec-audit/crowdsec-audit-latest.json`
- 报告同时复制到 `/var/log/mb-audit/reports/` 便于统一访问。
- 摘要：PASS / FAIL / WARN / SKIP 计数。
- 管道分隔的 findings（`STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX`）供标准报告生成器消费。

## 运行

```bash
# 单独运行 CrowdSec 审计模块
sudo mb audit run --module crowdsec

# 与其他模块一起运行
sudo mb audit run --module cis-benchmark,crowdsec,log-audit

# 直接执行脚本
sudo modules/crowdsec-audit.sh
```

## 常见问题与修复建议

### CrowdSec 未安装

```
FAIL | high | installation | CrowdSec (cscli) is not installed
```
修复：`sudo apt-get install -y crowdsec`（Debian/Ubuntu）或参考 [CrowdSec 安装文档](https://docs.crowdsec.net/getting_started/installation/)。

### crowdsec 服务未运行

```
FAIL | high | service | crowdsec service is 'inactive'
```
修复：`sudo systemctl start crowdsec && sudo systemctl enable crowdsec`

### 无 bouncer 注册

```
FAIL | high | bouncers_list | No bouncers registered
```
CrowdSec 检测到攻击但无 bouncer 执行封禁，等于只报警不阻断。修复：
```bash
sudo cscli bouncers install iptables   # 系统防火墙 bouncer
sudo cscli bouncers install nginx      # Nginx bouncer
sudo cscli bouncers install cfwall     # Cloudflare bouncer
```

### 关键场景缺失

```
WARN | high | key_scenarios | Missing key scenario(s): ssh-bf
```
修复：`sudo cscli scenarios install crowdsecurity/ssh-bf`（或对应 collection）。

### LAPI 端口公网暴露

```
FAIL | high | api_port_exposure | LAPI port 8080 is bound to all interfaces
```
这是高危项：LAPI 暴露到公网意味着任何人都能查询/操作你的 CrowdSec。修复：
```bash
sudo sed -i 's/listen_uri:.*/listen_uri: 127.0.0.1:8080/' /etc/crowdsec/config.yaml
sudo systemctl restart crowdsec
```

### 凭证文件权限过宽

```
FAIL | high | config_permissions_local_api_credentials.yaml | world-readable
```
修复：`sudo chmod 600 /etc/crowdsec/local_api_credentials.yaml`

### CAPI 未注册

```
WARN | high | capi_status | CAPI registration not detected
```
未注册 CAPI 意味着你既不贡献也不获取社区威胁情报。修复：
```bash
sudo cscli api register --email <your-email>
```

### 无白名单配置

```
WARN | medium | whitelist | No whitelist configuration found
```
无白名单可能导致合法 IP 被场景误封。建议为可信 IP（如管理出口、CI runner）配置白名单，参见 [CrowdSec whitelist 文档](https://docs.crowdsec.net/whitelist/create/)。

## 与 vps-bootstrap crowdsec 模块的关系

[vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) 的 crowdsec 模块负责**初始安装与配置**：安装 CrowdSec 主程序、注册默认 acquisition、安装基础场景与 bouncer、注册 CAPI。

本模块负责**持续审计**：验证 vps-bootstrap 部署的 CrowdSec 是否仍然健康运行、场景是否过期、bouncer 是否存活、安全配置是否被后续操作破坏。两者形成"部署 → 验证"闭环：

1. vps-bootstrap 部署 CrowdSec
2. `mb audit run --module crowdsec` 验证部署状态
3. 漂移检测（`mb audit drift`）捕获后续配置变化
4. 修复脚本或手动干预后重新审计确认

## 与 monitor-stack CrowdSec 监控的关系

[monitor-stack](https://github.com/0x10debug/monitor-stack) 提供运行时监控：CrowdSec 服务存活、bouncer 状态、决策速率、告警趋势等指标通过 Prometheus 采集并在 Grafana 展示，异常时触发告警。

本模块提供**深度配置审计**：监控栈回答"CrowdSec 现在是否在运行"，本模块回答"CrowdSec 的配置是否安全且完整"。两者互补：

- monitor-stack：实时指标 + 告警（运行态）
- crowdsec-audit：周期性配置与覆盖度审计（配置态）

建议将 `mb audit run --module crowdsec` 纳入每日定时审计（`mb audit schedule --daily`），与 monitor-stack 的实时告警形成纵深防御。
