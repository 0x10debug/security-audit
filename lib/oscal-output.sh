#!/usr/bin/env bash
# oscal-output.sh — generate OSCAL (Open Security Controls Assessment Language)
# assessment-results JSON from mb audit findings.
#
# Produces valid OSCAL 1.0.0+ "assessment-results" model JSON.
# Reference: https://pages.nist.gov/OSCAL/documentation/
#
# Functions:
#   oscal_generate()    — top-level: read findings, write OSCAL JSON file
#   oscal_add_result()  — add a single finding to the in-memory result set
#   oscal_write_json()  — serialise accumulated results to a JSON file
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# OSCAL assessment-results are accumulated in this temp file as JSON lines.
_OSCAL_RESULTS_FILE=""

# ---------------------------------------------------------------------------
# oscal_generate <findings_file> [output_file]
# Read pipe-delimited findings and write a complete OSCAL assessment-results
# JSON document.  If output_file is omitted, write to stdout.
# ---------------------------------------------------------------------------
oscal_generate() {
    local findings_file="$1"
    local output_file="${2:-}"
    [[ -f "$findings_file" ]] || { mb_error "Findings file not found: $findings_file"; return 1; }

    # Initialise the result accumulator.
    _oscal_reset

    # Read each finding and add it as an OSCAL result.
    while IFS='|' read -r status severity module check message fix; do
        [[ -z "$check" ]] && continue
        oscal_add_result "$status" "$severity" "$module" "$check" "$message" "$fix"
    done < "$findings_file"

    # Write the complete document.
    if [[ -n "$output_file" ]]; then
        oscal_write_json "$output_file"
        mb_ok "OSCAL assessment-results written to ${output_file}"
    else
        oscal_write_json ""
    fi
}

# ---------------------------------------------------------------------------
# oscal_add_result <status> <severity> <module> <check> <message> <fix>
# Append a single finding to the in-memory OSCAL result set.
# ---------------------------------------------------------------------------
oscal_add_result() {
    local status="$1" severity="$2" module="$3" check="$4" message="$5" fix="$6"

    # Map mb status to OSCAL implementation-status state.
    local oscal_state
    case "$status" in
        PASS) oscal_state="implemented" ;;
        FAIL) oscal_state="not-implemented" ;;
        WARN) oscal_state="partial" ;;
        *)    oscal_state="unknown" ;;
    esac

    # Map mb severity to OSCAL risk level.
    local oscal_risk
    case "$severity" in
        critical) oscal_risk="high" ;;
        high)     oscal_risk="high" ;;
        medium)   oscal_risk="moderate" ;;
        low)      oscal_risk="low" ;;
        *)        oscal_risk="unknown" ;;
    esac

    # Escape JSON special characters in free-text fields.
    local esc_check esc_message esc_fix
    esc_check="$(_oscal_json_escape "$check")"
    esc_message="$(_oscal_json_escape "$message")"
    esc_fix="$(_oscal_json_escape "$fix")"

    # Write a JSON object line for this result.
    cat >> "$_OSCAL_RESULTS_FILE" <<JSONL
{"control-id":"${esc_check}","module":"${module}","implementation-status":{"state":"${oscal_state}"},"risk":{"level":"${oscal_risk}"},"description":"${esc_message}","remediation":"${esc_fix}"}
JSONL
}

# ---------------------------------------------------------------------------
# oscal_write_json [output_file]
# Serialise the accumulated results into a complete OSCAL assessment-results
# JSON document.  If output_file is empty, write to stdout.
# ---------------------------------------------------------------------------
oscal_write_json() {
    local output_file="${1:-}"
    local host ts uuid_str
    host="$(mb_hostname)"
    ts="$(mb_now_iso)"
    uuid_str="$(_oscal_uuid)"

    local total pass fail warn
    total=0; pass=0; fail=0; warn=0
    if [[ -f "$_OSCAL_RESULTS_FILE" ]]; then
        total="$(wc -l < "$_OSCAL_RESULTS_FILE" | tr -d ' ')"
        pass="$(grep -c '"state":"implemented"' "$_OSCAL_RESULTS_FILE" 2>/dev/null || echo 0)"
        fail="$(grep -c '"state":"not-implemented"' "$_OSCAL_RESULTS_FILE" 2>/dev/null || echo 0)"
        warn="$(grep -c '"state":"partial"' "$_OSCAL_RESULTS_FILE" 2>/dev/null || echo 0)"
    fi

    # Build the results array from accumulated JSON lines.
    local results_json=""
    if [[ -f "$_OSCAL_RESULTS_FILE" && -s "$_OSCAL_RESULTS_FILE" ]]; then
        # Join lines with commas, indent each by 12 spaces.
        results_json="$(sed 's/^/            /' "$_OSCAL_RESULTS_FILE" | paste -sd ',' -)"
    fi

    # Assemble the full OSCAL assessment-results document.
    local doc
    doc=$(cat <<OSCAL_EOF
{
  "assessment-results": {
    "uuid": "${uuid_str}",
    "metadata": {
      "title": "mb Security Audit Assessment Results",
      "last-modified": "${ts}",
      "version": "${MB_AUDIT_VERSION}",
      "oscal-version": "1.0.6",
      "published": "${ts}",
      "props": [
        { "name": "hostname", "value": "${host}" },
        { "name": "tool", "value": "mb-security-audit" },
        { "name": "tool-version", "value": "${MB_AUDIT_VERSION}" }
      ]
    },
    "results": [
      {
        "uuid": "$(_oscal_uuid)",
        "title": "CIS Benchmark Assessment",
        "description": "Automated security assessment of ${host} using CIS Benchmark controls.",
        "start": "${ts}",
        "end": "${ts}",
        "props": [
          { "name": "total-findings", "value": "${total}" },
          { "name": "pass-count", "value": "${pass}" },
          { "name": "fail-count", "value": "${fail}" },
          { "name": "warn-count", "value": "${warn}" }
        ],
        "reviewed-controls": {
          "control-selections": [
            {
              "description": "CIS Benchmark controls assessed by the mb audit tool.",
              "include-controls": [
                { "control-id": "ssh_permitrootlogin" },
                { "control-id": "ssh_passwordauthentication" },
                { "control-id": "ssh_port" },
                { "control-id": "ssh_allowusers" },
                { "control-id": "ssh_maxauthtries" },
                { "control-id": "ssh_logingracetime" },
                { "control-id": "firewall_default_incoming" },
                { "control-id": "firewall_allowed_ports" },
                { "control-id": "kernel_bbr" },
                { "control-id": "kernel_file_max" },
                { "control-id": "kernel_somaxconn" },
                { "control-id": "kernel_ip_forward" },
                { "control-id": "kernel_syncookies" },
                { "control-id": "kernel_redirects" },
                { "control-id": "docker_exposed_daemon" },
                { "control-id": "docker_log_rotation" },
                { "control-id": "docker_user_namespace" },
                { "control-id": "autoupdate_enabled" }
              ]
            }
          ]
        },
        "observations": [
${results_json}
        ]
      }
    ]
  }
}
OSCAL_EOF
)

    if [[ -n "$output_file" ]]; then
        printf '%s\n' "$doc" > "$output_file"
    else
        printf '%s\n' "$doc"
    fi
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Reset the result accumulator (create a fresh temp file).
_oscal_reset() {
    if [[ -n "$_OSCAL_RESULTS_FILE" && -f "$_OSCAL_RESULTS_FILE" ]]; then
        rm -f "$_OSCAL_RESULTS_FILE"
    fi
    _OSCAL_RESULTS_FILE="$(mktemp)"
}

# Escape a string for safe inclusion in JSON double-quoted strings.
# _oscal_json_escape <string>
_oscal_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"   # backslash first
    s="${s//\"/\\\"}"   # double quote
    s="${s//$'\n'/\\n}" # newline
    s="${s//$'\r'/\\r}" # carriage return
    s="${s//$'\t'/\\t}" # tab
    printf '%s' "$s"
}

# Generate a simple UUID v4 (or a fallback if uuidgen is unavailable).
_oscal_uuid() {
    if mb_command_exists uuidgen; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        # Fallback: pseudo-UUID from date + random.
        printf '00000000-0000-4000-8000-%012x' "$((RANDOM * RANDOM))"
    fi
}

# Initialise the accumulator on source so oscal_add_result works standalone.
_oscal_reset

# Allow direct execution: `lib/oscal-output.sh <findings_file>` → OSCAL JSON to stdout.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        mb_error "Usage: oscal-output.sh <findings_file> [output_file]"
        exit 1
    fi
    oscal_generate "$1" "${2:-}"
fi
