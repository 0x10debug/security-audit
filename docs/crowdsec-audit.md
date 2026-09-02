# CrowdSec Audit

`modules/crowdsec-audit.sh` — Read-only audit of CrowdSec deployment status and security configuration.

## Audit Objectives

CrowdSec is a collaborative intrusion prevention system: it collects logs, runs scenarios to detect attack behavior, and executes ban decisions through bouncers, while contributing threat intelligence to the community API (CAPI). Any missing or misconfigured component renders the protection ineffective.

This module performs a comprehensive read-only health check on the installed CrowdSec instance, covering the complete chain from installation to threat intelligence, and outputs both TXT + JSON reports with PASS/FAIL/WARN/SKIP summary counts. The module does not modify any configuration.

## Check Items Detail

### Installation and service status

| Check Item | Description |
|---|---|
| `installation` | Whether CrowdSec is installed (`cscli version`). Not installed → FAIL. |
| `service` | Whether the `crowdsec` systemd service is active + enabled. |
| `bouncer_service` | Whether `crowdsec-bouncer-*` services exist and are all active. No bouncer → WARN. |
| `database_backend` | Database backend type (SQLite / MySQL / PostgreSQL), inferred via `cscli config show` or `config.yaml`. |

### Acquisition sources

| Check Item | Description |
|---|---|
| `acquisition_file` | Whether `/etc/crowdsec/acquis.yaml` exists and is readable. |
| `acquisition_sources` | Enumerate configured log source types (file / journalctl / docker) and their counts. |
| `critical_sources` | Check whether critical log sources are covered: SSH, auth.log, syslog, nginx, apache. Missing → WARN. |
| `docker_acquisition` | When Docker is installed, check whether container log collection is configured. |

### Scenarios

| Check Item | Description |
|---|---|
| `scenarios_installed` | Total number of installed scenarios (`cscli scenarios list`). Zero scenarios → FAIL. |
| `key_scenarios` | Whether key scenarios are enabled: `ssh-bf`, `http-bf`, `crawl`, `scan`. Missing → WARN. |
| `custom_scenarios` | Detect custom scenarios outside the `crowdsecurity/` namespace, prompt for review. |
| `scenario_updates` | Hub update status, prompt to regularly run `cscli hub update`. |

### Bouncer configuration

| Check Item | Description |
|---|---|
| `bouncers_list` | Number of registered bouncers (`cscli bouncers list`). Zero → FAIL. |
| `bouncer_types` | Identify bouncer types (iptables / nginx / cfwall / appsec). |
| `bouncer_decisions` | Whether bouncers are active and applying decisions. |

### Decisions and alerts

| Check Item | Description |
|---|---|
| `active_decisions` | Current number of active decisions (`cscli decisions list`). |
| `recent_alerts` | Number of recent alerts (`cscli alerts list`). |
| `banned_ips` | Current list of banned IPs (extract IPv4 addresses, take first 5 samples). |
| `whitelist` | Whether a whitelist configuration exists to reduce false ban risk. No whitelist → WARN. |

### Threat intelligence

| Check Item | Description |
|---|---|
| `capi_status` | CAPI (CrowdSec Central API) registration and push status (`cscli metrics`). Not registered → WARN. |
| `community_ti` | Whether the community threat intelligence subscription is active. |
| `local_blocklist` | Number of manually added local ban decisions. |

### Security configuration

| Check Item | Description |
|---|---|
| `api_port_exposure` | Whether the LAPI port (default 8080) is bound to `0.0.0.0` (public exposure → FAIL). |
| `lapi_auth` | Whether LAPI bouncer authentication is configured (bouncer token exists). |
| `config_permissions` | Configuration file permissions, especially `*_credentials.yaml` must not be readable by other users. |
| `bouncer_token_security` | Bouncer configuration files (`bouncer-*.yaml`) must not be readable by other users. |

## Output

- **TXT report**: `/var/log/crowdsec-audit/crowdsec-audit-latest.txt`
- **JSON report**: `/var/log/crowdsec-audit/crowdsec-audit-latest.json`
- Reports are also copied to `/var/log/mb-audit/reports/` for unified access.
- Summary: PASS / FAIL / WARN / SKIP counts.
- Pipe-delimited findings (`STATUS|SEVERITY|MODULE|CHECK|MESSAGE|FIX`) for consumption by the standard report generator.

## Usage

```bash
# Run the CrowdSec audit module standalone
sudo mb audit run --module crowdsec

# Run with other modules
sudo mb audit run --module cis-benchmark,crowdsec,log-audit

# Execute the script directly
sudo modules/crowdsec-audit.sh
```

## Common Issues and Remediation

### CrowdSec not installed

```
FAIL | high | installation | CrowdSec (cscli) is not installed
```
Remediation: `sudo apt-get install -y crowdsec` (Debian/Ubuntu) or refer to the [CrowdSec installation documentation](https://docs.crowdsec.net/getting_started/installation/).

### crowdsec service not running

```
FAIL | high | service | crowdsec service is 'inactive'
```
Remediation: `sudo systemctl start crowdsec && sudo systemctl enable crowdsec`

### No bouncer registered

```
FAIL | high | bouncers_list | No bouncers registered
```
CrowdSec detects attacks but without a bouncer to execute bans, it only alerts without blocking. Remediation:
```bash
sudo cscli bouncers install iptables   # System firewall bouncer
sudo cscli bouncers install nginx      # Nginx bouncer
sudo cscli bouncers install cfwall     # Cloudflare bouncer
```

### Key scenarios missing

```
WARN | high | key_scenarios | Missing key scenario(s): ssh-bf
```
Remediation: `sudo cscli scenarios install crowdsecurity/ssh-bf` (or the corresponding collection).

### LAPI port publicly exposed

```
FAIL | high | api_port_exposure | LAPI port 8080 is bound to all interfaces
```
This is a high-risk item: exposing LAPI to the public network means anyone can query/manipulate your CrowdSec. Remediation:
```bash
sudo sed -i 's/listen_uri:.*/listen_uri: 127.0.0.1:8080/' /etc/crowdsec/config.yaml
sudo systemctl restart crowdsec
```

### Credential file permissions too permissive

```
FAIL | high | config_permissions_local_api_credentials.yaml | world-readable
```
Remediation: `sudo chmod 600 /etc/crowdsec/local_api_credentials.yaml`

### CAPI not registered

```
WARN | high | capi_status | CAPI registration not detected
```
Not registering with CAPI means you neither contribute to nor receive community threat intelligence. Remediation:
```bash
sudo cscli api register --email <your-email>
```

### No whitelist configuration

```
WARN | medium | whitelist | No whitelist configuration found
```
Without a whitelist, legitimate IPs may be falsely banned by scenarios. It is recommended to configure a whitelist for trusted IPs (e.g., admin egress, CI runners), see the [CrowdSec whitelist documentation](https://docs.crowdsec.net/whitelist/create/).

## Relationship with vps-bootstrap crowdsec module

The [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) crowdsec module is responsible for **initial installation and configuration**: installing the CrowdSec main program, registering default acquisition, installing base scenarios and bouncers, and registering with CAPI.

This module is responsible for **continuous auditing**: verifying that the CrowdSec deployed by vps-bootstrap is still running healthily, whether scenarios are outdated, whether bouncers are alive, and whether security configuration has been disrupted by subsequent operations. Together they form a "deploy → verify" closed loop:

1. vps-bootstrap deploys CrowdSec
2. `mb audit run --module crowdsec` verifies the deployment status
3. Drift detection (`mb audit drift`) captures subsequent configuration changes
4. After remediation scripts or manual intervention, re-audit to confirm

## Relationship with monitor-stack CrowdSec monitoring

[monitor-stack](https://github.com/0x10debug/monitor-stack) provides runtime monitoring: CrowdSec service liveness, bouncer status, decision rate, alert trends and other metrics are collected via Prometheus and displayed in Grafana, triggering alerts when anomalies occur.

This module provides **deep configuration auditing**: the monitoring stack answers "is CrowdSec running right now", while this module answers "is CrowdSec's configuration secure and complete". They complement each other:

- monitor-stack: real-time metrics + alerts (runtime state)
- crowdsec-audit: periodic configuration and coverage audit (configuration state)

It is recommended to include `mb audit run --module crowdsec` in the daily scheduled audit (`mb audit schedule --daily`), forming defense-in-depth with monitor-stack's real-time alerts.
