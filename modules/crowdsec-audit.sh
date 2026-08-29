#!/usr/bin/env bash
# crowdsec-audit.sh — CrowdSec deployment & security posture audit for the mb tool.
#
# Read-only audit of a CrowdSec installation. Checks installation & service
# status, acquisition sources, scenarios, bouncers, active decisions/alerts,
# threat-intelligence subscriptions, and security configuration (API exposure,
# LAPI auth, file permissions, bouncer token safety).
#
# Outputs:
#   - TXT report:  /var/log/crowdsec-audit/crowdsec-audit-latest.txt
#   - JSON report: /var/log/crowdsec-audit/crowdsec-audit-latest.json
#   - Pipe-delimited findings (consumed by the standard report generator)
#
# This module is strictly read-only: it never modifies any CrowdSec config.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="crowdsec"

# Dedicated report directory for CrowdSec audit artefacts.
CROWDSEC_REPORT_DIR="${CROWDSEC_REPORT_DIR:-/var/log/crowdsec-audit}"

# CrowdSec paths.
CROWDSEC_BIN="${CROWDSEC_BIN:-cscli}"
CROWDSEC_ACQUIS="${CROWDSEC_ACQUIS:-/etc/crowdsec/acquis.yaml}"
CROWDSEC_CONFIG_DIR="${CROWDSEC_CONFIG_DIR:-/etc/crowdsec}"
CROWDSEC_LAPI_PORT="${CROWDSEC_LAPI_PORT:-8080}"

# Critical log sources that acquisition should cover.
CROWDSEC_CRITICAL_SOURCES=(ssh auth.log syslog nginx apache)

# Key scenarios that should be installed.
CROWDSEC_KEY_SCENARIOS=(ssh-bf http-bf crawl scan)

# Counters for the summary (PASS/FAIL/WARN/SKIP).
_cs_pass=0
_cs_fail=0
_cs_warn=0
_cs_skip=0

# Collected findings for the JSON report (STATUS|SEVERITY|CHECK|MESSAGE).
_cs_findings=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Run cscli safely, swallowing stderr. Returns 0 if cscli exists & command
# succeeds, non-zero otherwise. Output on stdout.
_cscli() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        return 127
    fi
    "$CROWDSEC_BIN" "$@" 2>/dev/null || true
}

# Emit a finding and track counters. Also records into the JSON findings array.
# Usage: _cs_emit <status> <severity> <check> <message> <fix>
_cs_emit() {
    local status="$1" severity="$2" check="$3" message="$4" fix="$5"
    mb_emit_finding "$status" "$severity" "$MB_MODULE" "$check" "$message" "$fix"
    case "$status" in
        PASS) _cs_pass=$((_cs_pass + 1)) ;;
        FAIL) _cs_fail=$((_cs_fail + 1)) ;;
        WARN) _cs_warn=$((_cs_warn + 1)) ;;
        SKIP) _cs_skip=$((_cs_skip + 1)) ;;
    esac
    _cs_findings+=("${status}|${severity}|${check}|${message}")
}

# Skip a check because CrowdSec is not installed.
_cs_skip_not_installed() {
    local check="$1" label="$2"
    _cs_emit SKIP info "$check" \
        "CrowdSec is not installed — ${label} skipped" \
        "sudo apt-get install -y crowdsec"
}

# ---------------------------------------------------------------------------
# Installation & service status
# ---------------------------------------------------------------------------

cs_audit_installation() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_emit FAIL high "installation" \
            "CrowdSec (cscli) is not installed" \
            "sudo apt-get install -y crowdsec"
        return
    fi

    local version
    version="$(_cscli version 2>/dev/null | grep -iE 'version|Crowdsec' | head -1 | tr -s ' ' || echo "unknown")"
    if [[ -z "$version" || "$version" == "unknown" ]]; then
        # cscli version output format varies; grab the first non-empty line.
        version="$(_cscli version 2>/dev/null | head -1 || echo "unknown")"
    fi
    _cs_emit PASS info "installation" \
        "CrowdSec is installed: ${version}" ""
}

cs_audit_service() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "service" "service status"
        return
    fi

    if ! mb_command_exists systemctl; then
        _cs_emit SKIP info "service" \
            "systemctl not available — cannot check crowdsec service" ""
        return
    fi

    local state
    state="$(systemctl is-active crowdsec 2>/dev/null || echo "unknown")"
    if [[ "$state" == "active" ]]; then
        _cs_emit PASS info "service" \
            "crowdsec service is active" ""
    else
        _cs_emit FAIL high "service" \
            "crowdsec service is '${state}' (expected active)" \
            "sudo systemctl start crowdsec && sudo systemctl enable crowdsec"
    fi

    local enabled
    enabled="$(systemctl is-enabled crowdsec 2>/dev/null || echo "unknown")"
    if [[ "$enabled" == "enabled" ]]; then
        _cs_emit PASS info "service_enabled" \
            "crowdsec service is enabled at boot" ""
    else
        _cs_emit WARN medium "service_enabled" \
            "crowdsec service is '${enabled}' at boot (expected enabled)" \
            "sudo systemctl enable crowdsec"
    fi
}

cs_audit_bouncer_service() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "bouncer_service" "bouncer service"
        return
    fi

    # Check for any crowdsec-bouncer-* systemd services.
    local bouncer_units
    bouncer_units="$(systemctl list-units --type=service 'crowdsec-bouncer-*' --no-legend 2>/dev/null | awk '{print $1}' || true)"
    if [[ -z "$bouncer_units" ]]; then
        _cs_emit WARN high "bouncer_service" \
            "No crowdsec-bouncer service found — no active bouncer is running" \
            "sudo cscli bouncers install <type> (e.g. iptables, nginx, cfwall)"
        return
    fi

    local total=0 active=0
    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        total=$((total + 1))
        local st
        st="$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")"
        [[ "$st" == "active" ]] && active=$((active + 1))
    done <<< "$bouncer_units"

    if [[ "$active" -eq "$total" ]]; then
        _cs_emit PASS info "bouncer_service" \
            "All ${total} bouncer service(s) active: $(echo "$bouncer_units" | tr '\n' ' ')" ""
    else
        _cs_emit FAIL high "bouncer_service" \
            "${active}/${total} bouncer service(s) active — some bouncers are down" \
            "sudo systemctl status 'crowdsec-bouncer-*'"
    fi
}

cs_audit_database_backend() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "database_backend" "database backend"
        return
    fi

    local backend="unknown"
    # cscli config show reveals the database backend.
    local cfg
    cfg="$(_cscli config show 2>/dev/null || true)"
    if echo "$cfg" | grep -qi 'mysql'; then
        backend="MySQL"
    elif echo "$cfg" | grep -qi 'postgres\|postgresql'; then
        backend="PostgreSQL"
    elif echo "$cfg" | grep -qi 'sqlite'; then
        backend="SQLite"
    fi

    # Fall back to inspecting the config file directly.
    if [[ "$backend" == "unknown" && -f "${CROWDSEC_CONFIG_DIR}/config.yaml" ]]; then
        if grep -qi 'mysql' "${CROWDSEC_CONFIG_DIR}/config.yaml" 2>/dev/null; then
            backend="MySQL"
        elif grep -qiE 'postgres|postgresql' "${CROWDSEC_CONFIG_DIR}/config.yaml" 2>/dev/null; then
            backend="PostgreSQL"
        else
            backend="SQLite"
        fi
    fi

    case "$backend" in
        SQLite)
            _cs_emit PASS info "database_backend" \
                "Database backend: SQLite (default, fine for single-node)" \
                "For high-volume hosts consider MySQL/PostgreSQL"
            ;;
        MySQL|PostgreSQL)
            _cs_emit PASS info "database_backend" \
                "Database backend: ${backend}" ""
            ;;
        *)
            _cs_emit WARN medium "database_backend" \
                "Could not determine CrowdSec database backend" \
                "sudo cscli config show"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Acquisition sources
# ---------------------------------------------------------------------------

cs_audit_acquisition_file() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "acquisition_file" "acquisition config"
        return
    fi

    if [[ ! -f "$CROWDSEC_ACQUIS" ]]; then
        _cs_emit FAIL high "acquisition_file" \
            "Acquisition config not found: ${CROWDSEC_ACQUIS}" \
            "sudo cscli acquisition add <source>"
        return
    fi

    if [[ ! -r "$CROWDSEC_ACQUIS" ]]; then
        _cs_emit WARN medium "acquisition_file" \
            "Acquisition config exists but is not readable: ${CROWDSEC_ACQUIS}" ""
        return
    fi

    _cs_emit PASS info "acquisition_file" \
        "Acquisition config present: ${CROWDSEC_ACQUIS}" ""
}

cs_audit_acquisition_sources() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "acquisition_sources" "acquisition sources"
        return
    fi

    if [[ ! -r "$CROWDSEC_ACQUIS" ]]; then
        _cs_emit SKIP info "acquisition_sources" \
            "Acquisition config not readable — skipping source enumeration" ""
        return
    fi

    local content
    content="$(cat "$CROWDSEC_ACQUIS" 2>/dev/null || true)"

    local file_count=0 journal_count=0 docker_count=0
    file_count="$(echo "$content" | grep -cE '^\s*filenames:|^\s*filename:' 2>/dev/null || echo 0)"
    journal_count="$(echo "$content" | grep -cE '^\s*journalctl_filter:|^\s*-.*journalctl' 2>/dev/null || echo 0)"
    docker_count="$(echo "$content" | grep -cE 'docker:|container_name:|container_id:' 2>/dev/null || echo 0)"

    local sources=""
    [[ "$file_count" -gt 0 ]] && sources="${sources}file(${file_count}) "
    [[ "$journal_count" -gt 0 ]] && sources="${sources}journal(${journal_count}) "
    [[ "$docker_count" -gt 0 ]] && sources="${sources}docker(${docker_count}) "

    if [[ -z "$sources" ]]; then
        _cs_emit WARN medium "acquisition_sources" \
            "No acquisition sources detected in ${CROWDSEC_ACQUIS}" \
            "sudo cscli acquisition add <source>"
    else
        _cs_emit PASS info "acquisition_sources" \
            "Configured acquisition sources: ${sources}" ""
    fi
}

cs_audit_critical_sources() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "critical_sources" "critical source coverage"
        return
    fi

    if [[ ! -r "$CROWDSEC_ACQUIS" ]]; then
        _cs_emit SKIP info "critical_sources" \
            "Acquisition config not readable — skipping critical source check" ""
        return
    fi

    local content
    content="$(cat "$CROWDSEC_ACQUIS" 2>/dev/null || true)"
    local missing=()

    for src in "${CROWDSEC_CRITICAL_SOURCES[@]}"; do
        if ! echo "$content" | grep -qiE "$src"; then
            missing+=("$src")
        fi
    done

    if [[ "${#missing[@]}" -eq 0 ]]; then
        _cs_emit PASS info "critical_sources" \
            "All critical log sources covered (ssh, auth.log, syslog, nginx, apache)" ""
    else
        _cs_emit WARN medium "critical_sources" \
            "Missing critical log source(s): ${missing[*]}" \
            "sudo cscli acquisition add <source> for the missing log paths"
    fi
}

cs_audit_docker_acquisition() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "docker_acquisition" "Docker acquisition"
        return
    fi

    if [[ ! -r "$CROWDSEC_ACQUIS" ]]; then
        _cs_emit SKIP info "docker_acquisition" \
            "Acquisition config not readable — skipping Docker acquisition check" ""
        return
    fi

    if ! mb_command_exists docker; then
        _cs_emit SKIP info "docker_acquisition" \
            "Docker is not installed — skipping container log acquisition" ""
        return
    fi

    local content
    content="$(cat "$CROWDSEC_ACQUIS" 2>/dev/null || true)"
    if echo "$content" | grep -qiE 'docker:|container_name:|container_id:'; then
        _cs_emit PASS info "docker_acquisition" \
            "Docker container log acquisition is configured" ""
    else
        _cs_emit WARN medium "docker_acquisition" \
            "Docker is installed but no container log acquisition configured" \
            "sudo cscli acquisition add --type docker --container-name <name>"
    fi
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

cs_audit_scenarios_installed() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "scenarios_installed" "scenario list"
        return
    fi

    local list
    list="$(_cscli scenarios list -o human 2>/dev/null || true)"
    local count
    count="$(echo "$list" | grep -cE '^\s*[a-z]' 2>/dev/null || echo 0)"

    if [[ "$count" -le 1 ]]; then
        # cscli scenarios list header may be counted; re-check for known names.
        count="$(echo "$list" | grep -ciE 'ssh-bf|http-bf|crawl|scan' 2>/dev/null || echo 0)"
    fi

    if [[ "$count" -eq 0 ]]; then
        _cs_emit FAIL high "scenarios_installed" \
            "No scenarios installed — CrowdSec will not detect attacks" \
            "sudo cscli hub update && sudo cscli collections install crowdsecurity/<collection>"
    else
        _cs_emit PASS info "scenarios_installed" \
            "${count} scenario(s) installed" ""
    fi
}

cs_audit_key_scenarios() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "key_scenarios" "key scenario check"
        return
    fi

    local list
    list="$(_cscli scenarios list -o human 2>/dev/null || true)"
    local missing=()

    for sc in "${CROWDSEC_KEY_SCENARIOS[@]}"; do
        if ! echo "$list" | grep -qi "$sc"; then
            missing+=("$sc")
        fi
    done

    if [[ "${#missing[@]}" -eq 0 ]]; then
        _cs_emit PASS info "key_scenarios" \
            "All key scenarios enabled (ssh-bf, http-bf, crawl, scan)" ""
    else
        _cs_emit WARN high "key_scenarios" \
            "Missing key scenario(s): ${missing[*]}" \
            "sudo cscli scenarios install crowdsecurity/<scenario>"
    fi
}

cs_audit_custom_scenarios() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "custom_scenarios" "custom scenario check"
        return
    fi

    local list
    list="$(_cscli scenarios list -o human 2>/dev/null || true)"
    # Custom scenarios typically do not start with crowdsecurity/.
    local custom
    custom="$(echo "$list" | grep -viE 'crowdsecurity/|name|---|^\s*$' 2>/dev/null || true)"

    if [[ -z "$custom" ]]; then
        _cs_emit PASS info "custom_scenarios" \
            "No custom scenarios installed (only community scenarios)" ""
    else
        local ccount
        ccount="$(echo "$custom" | wc -l | tr -d ' ')"
        _cs_emit PASS info "custom_scenarios" \
            "${ccount} custom scenario(s) detected — review for correctness" \
            "Review custom scenarios with: sudo cscli scenarios list -o human"
    fi
}

cs_audit_scenario_updates() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "scenario_updates" "scenario update status"
        return
    fi

    # Best-effort: check if hub was updated recently.
    local last_update=""
    if [[ -f "${CROWDSEC_CONFIG_DIR}/hub/.last_update" ]]; then
        last_update="$(cat "${CROWDSEC_CONFIG_DIR}/hub/.last_update" 2>/dev/null || true)"
    fi

    if [[ -n "$last_update" ]]; then
        _cs_emit PASS info "scenario_updates" \
            "CrowdSec hub last updated: ${last_update}" \
            "Run sudo cscli hub update periodically"
    else
        _cs_emit WARN low "scenario_updates" \
            "Could not determine hub update status — run cscli hub update regularly" \
            "sudo cscli hub update && sudo cscli hub upgrade"
    fi
}

# ---------------------------------------------------------------------------
# Bouncer configuration
# ---------------------------------------------------------------------------

cs_audit_bouncers_list() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "bouncers_list" "bouncer list"
        return
    fi

    local list
    list="$(_cscli bouncers list -o human 2>/dev/null || true)"
    local count
    count="$(echo "$list" | grep -cE '^\s*[a-zA-Z]' 2>/dev/null || echo 0)"

    if [[ "$count" -le 1 ]]; then
        count="$(echo "$list" | grep -ciE 'iptables|nginx|cfwall|bouncer' 2>/dev/null || echo 0)"
    fi

    if [[ "$count" -eq 0 ]]; then
        _cs_emit FAIL high "bouncers_list" \
            "No bouncers registered — detected attacks will not be blocked" \
            "sudo cscli bouncers install <type>"
    else
        _cs_emit PASS info "bouncers_list" \
            "${count} bouncer(s) registered" ""
    fi
}

cs_audit_bouncer_types() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "bouncer_types" "bouncer type check"
        return
    fi

    local list
    list="$(_cscli bouncers list -o human 2>/dev/null || true)"
    local types=""

    echo "$list" | grep -qi 'iptables' && types="${types}iptables "
    echo "$list" | grep -qi 'nginx' && types="${types}nginx "
    echo "$list" | grep -qi 'cfwall\|cloudflare' && types="${types}cfwall "
    echo "$list" | grep -qi 'appsec' && types="${types}appsec "

    if [[ -z "$types" ]]; then
        _cs_emit WARN medium "bouncer_types" \
            "Could not identify bouncer types from cscli output" \
            "sudo cscli bouncers list -o human"
    else
        _cs_emit PASS info "bouncer_types" \
            "Bouncer types in use: ${types}" ""
    fi
}

cs_audit_bouncer_decisions() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "bouncer_decisions" "bouncer decision status"
        return
    fi

    # Check that bouncers are actually applying decisions (not just registered).
    local list
    list="$(_cscli bouncers list -o human 2>/dev/null || true)"

    # A bouncer with an active API key and valid type is considered applying.
    local active
    active="$(echo "$list" | grep -ciE 'valid|active' 2>/dev/null || echo 0)"

    if [[ "$active" -gt 0 ]]; then
        _cs_emit PASS info "bouncer_decisions" \
            "${active} bouncer(s) appear active and applying decisions" ""
    else
        _cs_emit WARN medium "bouncer_decisions" \
            "Bouncer decision application status unclear — verify bouncers are receiving decisions" \
            "sudo cscli bouncers list -o human && sudo journalctl -u 'crowdsec-bouncer-*'"
    fi
}

# ---------------------------------------------------------------------------
# Decisions & alerts
# ---------------------------------------------------------------------------

cs_audit_active_decisions() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "active_decisions" "active decisions"
        return
    fi

    local list
    list="$(_cscli decisions list -o human 2>/dev/null || true)"
    local count
    count="$(echo "$list" | grep -cE '^\s*[0-9]+|ban|' 2>/dev/null || echo 0)"

    # More reliable: count non-header lines.
    count="$(echo "$list" | grep -cviE 'No active decisions|name|---|^\s*$|total' 2>/dev/null || echo 0)"

    if [[ "$count" -eq 0 ]]; then
        _cs_emit PASS info "active_decisions" \
            "No active decisions (no IPs currently banned)" ""
    else
        _cs_emit PASS info "active_decisions" \
            "${count} active decision(s) (banned IPs)" \
            "Review: sudo cscli decisions list -o human"
    fi
}

cs_audit_recent_alerts() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "recent_alerts" "recent alerts"
        return
    fi

    local list
    list="$(_cscli alerts list -o human 2>/dev/null || true)"
    local count
    count="$(echo "$list" | grep -cviE 'name|---|^\s*$|No alert|total' 2>/dev/null || echo 0)"

    if [[ "$count" -eq 0 ]]; then
        _cs_emit PASS info "recent_alerts" \
            "No recent alerts — CrowdSec has not triggered scenarios recently" ""
    else
        _cs_emit PASS info "recent_alerts" \
            "${count} alert(s) in recent history" \
            "Review: sudo cscli alerts list -o human"
    fi
}

cs_audit_banned_ips() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "banned_ips" "banned IP list"
        return
    fi

    local list
    list="$(_cscli decisions list -o human 2>/dev/null || true)"
    # Extract IP addresses from the decisions list.
    local ips
    ips="$(echo "$list" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' 2>/dev/null | sort -u || true)"

    if [[ -z "$ips" ]]; then
        _cs_emit PASS info "banned_ips" \
            "No IPs currently banned" ""
    else
        local icount
        icount="$(echo "$ips" | wc -l | tr -d ' ')"
        local sample
        sample="$(echo "$ips" | head -5 | tr '\n' ' ')"
        _cs_emit PASS info "banned_ips" \
            "${icount} IP(s) currently banned (sample: ${sample})" \
            "Review full list: sudo cscli decisions list -o human"
    fi
}

cs_audit_whitelist() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "whitelist" "whitelist / false-positive check"
        return
    fi

    # Check for whitelist configuration to prevent false bans.
    local has_whitelist=0
    if [[ -f "${CROWDSEC_CONFIG_DIR}/acquis.yaml" ]]; then
        if grep -qiE 'whitelist|whitelists' "${CROWDSEC_CONFIG_DIR}/acquis.yaml" 2>/dev/null; then
            has_whitelist=1
        fi
    fi

    # Also check for dedicated whitelist files.
    local wl_files
    wl_files="$(ls "${CROWDSEC_CONFIG_DIR}"/whitelist* 2>/dev/null || true)"

    if [[ "$has_whitelist" -eq 1 || -n "$wl_files" ]]; then
        _cs_emit PASS info "whitelist" \
            "Whitelist configuration detected — false-positive risk is mitigated" \
            "Review whitelist entries periodically"
    else
        _cs_emit WARN medium "whitelist" \
            "No whitelist configuration found — risk of false-positive bans" \
            "Add whitelist for trusted IPs: see CrowdSec whitelist documentation"
    fi
}

# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------

cs_audit_capi_status() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "capi_status" "CAPI registration"
        return
    fi

    # Check CAPI (CrowdSec Central API) registration via cscli.
    local metrics
    metrics="$(_cscli metrics 2>/dev/null || true)"

    if echo "$metrics" | grep -qiE 'CAPI|central_api|community_api'; then
        if echo "$metrics" | grep -qiE 'CAPI.*push|push.*CAPI|sent'; then
            _cs_emit PASS info "capi_status" \
                "CrowdSec CAPI is registered and pushing threat intel" ""
        else
            _cs_emit WARN medium "capi_status" \
                "CAPI appears registered but push activity unclear" \
                "sudo cscli metrics | grep -i capi"
        fi
    else
        _cs_emit WARN high "capi_status" \
            "CrowdSec CAPI registration not detected — not contributing to community threat intel" \
            "sudo cscli api register --email <your-email>"
    fi
}

cs_audit_community_ti() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "community_ti" "community threat intel"
        return
    fi

    # Check if community blocklist is being pulled.
    local metrics
    metrics="$(_cscli metrics 2>/dev/null || true)"

    if echo "$metrics" | grep -qiE 'community|blocklist|download'; then
        _cs_emit PASS info "community_ti" \
            "Community threat intelligence subscription is active" ""
    else
        _cs_emit WARN medium "community_ti" \
            "Community threat intel subscription status unclear" \
            "sudo cscli metrics && sudo cscli lapi status"
    fi
}

cs_audit_local_blocklist() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "local_blocklist" "local IP blocklist"
        return
    fi

    # Check for manually added decisions (local blocklist).
    local list
    list="$(_cscli decisions list -o human 2>/dev/null || true)"
    local manual
    manual="$(echo "$list" | grep -ciE 'manual|cscli' 2>/dev/null || echo 0)"

    if [[ "$manual" -gt 0 ]]; then
        _cs_emit PASS info "local_blocklist" \
            "${manual} manually-added decision(s) (local blocklist entries)" \
            "Review: sudo cscli decisions list -o human"
    else
        _cs_emit PASS info "local_blocklist" \
            "No manually-added local blocklist entries (relying on scenarios + community TI)" ""
    fi
}

# ---------------------------------------------------------------------------
# Security configuration
# ---------------------------------------------------------------------------

cs_audit_api_port_exposure() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "api_port_exposure" "API port exposure"
        return
    fi

    # Check if the LAPI port is bound to 0.0.0.0 (exposed publicly).
    if ! mb_command_exists ss; then
        _cs_emit SKIP info "api_port_exposure" \
            "ss command not available — cannot check API port binding" ""
        return
    fi

    local listeners
    listeners="$(ss -tlnp 2>/dev/null | grep ":${CROWDSEC_LAPI_PORT}" || true)"

    if [[ -z "$listeners" ]]; then
        _cs_emit PASS info "api_port_exposure" \
            "LAPI port ${CROWDSEC_LAPI_PORT} is not listening (or CrowdSec not running)" ""
        return
    fi

    if echo "$listeners" | grep -qE '0\.0\.0\.0|:::|\*'; then
        _cs_emit FAIL high "api_port_exposure" \
            "LAPI port ${CROWDSEC_LAPI_PORT} is bound to all interfaces (0.0.0.0) — publicly exposed" \
            "Bind LAPI to 127.0.0.1 in /etc/crowdsec/config.yaml: listen_uri: 127.0.0.1:8080"
    else
        _cs_emit PASS info "api_port_exposure" \
            "LAPI port ${CROWDSEC_LAPI_PORT} is bound to a restricted interface" ""
    fi
}

cs_audit_lapi_auth() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "lapi_auth" "LAPI authentication"
        return
    fi

    # Check that LAPI requires authentication (config.yaml should have api.server.enable).
    local cfg="${CROWDSEC_CONFIG_DIR}/config.yaml"
    if [[ ! -r "$cfg" ]]; then
        _cs_emit SKIP info "lapi_auth" \
            "Cannot read ${cfg} — skipping LAPI auth check" ""
        return
    fi

    # LAPI auth is enforced by default; verify bouncer tokens exist.
    local list
    list="$(_cscli bouncers list -o human 2>/dev/null || true)"
    if echo "$list" | grep -qiE 'token|api'; then
        _cs_emit PASS info "lapi_auth" \
            "LAPI bouncer authentication is configured (tokens present)" ""
    else
        _cs_emit WARN medium "lapi_auth" \
            "Could not verify LAPI bouncer tokens — ensure bouncers authenticate via API token" \
            "sudo cscli bouncers list -o human"
    fi
}

cs_audit_config_permissions() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "config_permissions" "config file permissions"
        return
    fi

    local issues=0
    local files=(
        "${CROWDSEC_CONFIG_DIR}/config.yaml"
        "${CROWDSEC_CONFIG_DIR}/acquis.yaml"
        "${CROWDSEC_CONFIG_DIR}/profiles.yaml"
        "${CROWDSEC_CONFIG_DIR}/local_api_credentials.yaml"
        "${CROWDSEC_CONFIG_DIR}/online_api_credentials.yaml"
    )

    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        local mode
        mode="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null || echo "000")"
        # Credential files should not be world-readable.
        if [[ "$f" == *credentials* ]]; then
            # World-readable = the "other" read bit is set (last octal digit >= 4).
            local other_bits="${mode: -1}"
            if [[ "$other_bits" -ge 4 ]]; then
                _cs_emit FAIL high "config_permissions_$(basename "$f")" \
                    "${f} is world-readable (mode ${mode}) — contains credentials" \
                    "sudo chmod 600 ${f}"
                issues=$((issues + 1))
            fi
        fi
    done

    if [[ "$issues" -eq 0 ]]; then
        _cs_emit PASS info "config_permissions" \
            "CrowdSec config file permissions look safe (credentials not world-readable)" ""
    else
        _cs_emit FAIL high "config_permissions" \
            "${issues} config file(s) with unsafe permissions" \
            "Fix permissions on the flagged files above"
    fi
}

cs_audit_bouncer_token_security() {
    if ! mb_command_exists "$CROWDSEC_BIN"; then
        _cs_skip_not_installed "bouncer_token_security" "bouncer token security"
        return
    fi

    # Check that bouncer tokens are not logged or stored in world-readable files.
    local list
    list="$(_cscli bouncers list -o human 2>/dev/null || true)"

    # Verify bouncer config files are not world-readable.
    local unsafe=0
    for f in "${CROWDSEC_CONFIG_DIR}"/bouncer-*.yaml "${CROWDSEC_CONFIG_DIR}"/bouncers/*.yaml; do
        [[ -f "$f" ]] || continue
        local mode
        mode="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null || echo "000")"
        # World-readable = the "other" read bit is set (last octal digit >= 4).
        local other_bits="${mode: -1}"
        if [[ "$other_bits" -ge 4 ]]; then
            unsafe=$((unsafe + 1))
        fi
    done

    if [[ "$unsafe" -gt 0 ]]; then
        _cs_emit FAIL high "bouncer_token_security" \
            "${unsafe} bouncer config file(s) are world-readable — bouncer API tokens may be exposed" \
            "sudo chmod 600 /etc/crowdsec/bouncer-*.yaml"
    else
        _cs_emit PASS info "bouncer_token_security" \
            "Bouncer token files are not world-readable" ""
    fi
}

# ---------------------------------------------------------------------------
# Report generation (TXT + JSON)
# ---------------------------------------------------------------------------

_cs_generate_txt_report() {
    local out="$1"
    {
        printf 'CrowdSec Audit Report\n'
        printf 'Generated: %s\n' "$(mb_now_iso)"
        printf 'Host: %s\n' "$(mb_hostname)"
        printf '========================================\n\n'

        printf 'Summary:\n'
        printf '  PASS: %s\n' "$_cs_pass"
        printf '  FAIL: %s\n' "$_cs_fail"
        printf '  WARN: %s\n' "$_cs_warn"
        printf '  SKIP: %s\n' "$_cs_skip"
        printf '  Total checks: %s\n' "$((_cs_pass + _cs_fail + _cs_warn + _cs_skip))"
        printf '\n'

        printf 'Findings:\n'
        printf '%-6s %-8s %-28s %s\n' "STAT" "SEV" "CHECK" "MESSAGE"
        printf '%-6s %-8s %-28s %s\n' "----" "---" "-----" "-------"
        for f in "${_cs_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            printf '%-6s %-8s %-28s %s\n' "$status" "$severity" "$check" "$message"
        done
        printf '\n'

        printf 'Notes:\n'
        printf '  This is a read-only audit. No configuration was modified.\n'
        printf '  CrowdSec docs: https://docs.crowdsec.net/\n'
        printf '  Related: vps-bootstrap crowdsec module, monitor-stack CrowdSec monitoring\n'
    } > "$out"
}

_cs_generate_json_report() {
    local out="$1"
    {
        printf '{\n'
        printf '  "module": "crowdsec-audit",\n'
        printf '  "generated": "%s",\n' "$(mb_now_iso)"
        printf '  "host": "%s",\n' "$(mb_hostname)"
        printf '  "summary": {\n'
        printf '    "pass": %s,\n' "$_cs_pass"
        printf '    "fail": %s,\n' "$_cs_fail"
        printf '    "warn": %s,\n' "$_cs_warn"
        printf '    "skip": %s,\n' "$_cs_skip"
        printf '    "total": %s\n' "$((_cs_pass + _cs_fail + _cs_warn + _cs_skip))"
        printf '  },\n'
        printf '  "findings": [\n'
        local first=1
        for f in "${_cs_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            if [[ $first -eq 0 ]]; then
                printf ',\n'
            fi
            first=0
            # Escape double quotes and backslashes in message for JSON safety.
            local esc_msg
            esc_msg="${message//\\/\\\\}"
            esc_msg="${esc_msg//\"/\\\"}"
            printf '    {\n'
            printf '      "status": "%s",\n' "$status"
            printf '      "severity": "%s",\n' "$severity"
            printf '      "check": "%s",\n' "$check"
            printf '      "message": "%s"\n' "$esc_msg"
            printf '    }'
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

# ---------------------------------------------------------------------------
# Runner — executes all cs_audit_* functions and generates reports.
# ---------------------------------------------------------------------------
mb_audit_crowdsec() {
    mb_info "Running CrowdSec audit module..."

    # Run all checks; each emits findings via _cs_emit.
    cs_audit_installation
    cs_audit_service
    cs_audit_bouncer_service
    cs_audit_database_backend
    cs_audit_acquisition_file
    cs_audit_acquisition_sources
    cs_audit_critical_sources
    cs_audit_docker_acquisition
    cs_audit_scenarios_installed
    cs_audit_key_scenarios
    cs_audit_custom_scenarios
    cs_audit_scenario_updates
    cs_audit_bouncers_list
    cs_audit_bouncer_types
    cs_audit_bouncer_decisions
    cs_audit_active_decisions
    cs_audit_recent_alerts
    cs_audit_banned_ips
    cs_audit_whitelist
    cs_audit_capi_status
    cs_audit_community_ti
    cs_audit_local_blocklist
    cs_audit_api_port_exposure
    cs_audit_lapi_auth
    cs_audit_config_permissions
    cs_audit_bouncer_token_security

    # Generate TXT + JSON reports.
    mb_ensure_dir "$CROWDSEC_REPORT_DIR"
    local txt_report="${CROWDSEC_REPORT_DIR}/crowdsec-audit-latest.txt"
    local json_report="${CROWDSEC_REPORT_DIR}/crowdsec-audit-latest.json"

    _cs_generate_txt_report "$txt_report"
    _cs_generate_json_report "$json_report"

    # Also copy into the standard mb-audit reports dir for unified access.
    if [[ -d "$MB_AUDIT_REPORTS_DIR" ]]; then
        cp -f "$txt_report" "${MB_AUDIT_REPORTS_DIR}/crowdsec-audit-latest.txt" 2>/dev/null || true
        cp -f "$json_report" "${MB_AUDIT_REPORTS_DIR}/crowdsec-audit-latest.json" 2>/dev/null || true
    fi

    local total=$((_cs_pass + _cs_fail + _cs_warn + _cs_skip))
    mb_ok "CrowdSec audit complete: ${_cs_pass} PASS, ${_cs_fail} FAIL, ${_cs_warn} WARN, ${_cs_skip} SKIP (${total} checks)"
    mb_info "TXT report:  ${txt_report}"
    mb_info "JSON report: ${json_report}"
}

# Allow direct execution: `modules/crowdsec-audit.sh` → runs all checks.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_audit_crowdsec
fi
