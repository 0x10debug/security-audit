#!/usr/bin/env bash
# lynis.sh — wrapper around Lynis for the mb audit tool.
# Installs Lynis if missing, runs a quick audit, and parses the output into
# the standard pipe-delimited finding format.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="lynis"
LYNIS_BIN="${LYNIS_BIN:-/usr/local/bin/lynis}"
LYNIS_SRC_DIR="${LYNIS_SRC_DIR:-/opt/lynis}"

# ---------------------------------------------------------------------------
# mb_lynis_install — install Lynis from git (preferred) or package manager.
# ---------------------------------------------------------------------------
mb_lynis_install() {
    mb_require_root

    if mb_command_exists lynis || [[ -x "$LYNIS_BIN" ]]; then
        return 0
    fi

    mb_info "Lynis not found — installing..."

    # Try package manager first (faster, maintained by distro).
    if mb_command_exists apt-get; then
        apt-get update -qq && apt-get install -y lynis
        return 0
    elif mb_command_exists dnf; then
        dnf install -y lynis
        return 0
    elif mb_command_exists yum; then
        yum install -y lynis
        return 0
    fi

    # Fall back to cloning from git.
    if ! mb_command_exists git; then
        mb_error "git is required to install Lynis but is not installed."
        return 1
    fi
    git clone --depth 1 https://github.com/CISOfy/lynis.git "$LYNIS_SRC_DIR"
    ln -sf "${LYNIS_SRC_DIR}/lynis" "$LYNIS_BIN"
    mb_ok "Lynis installed from git to ${LYNIS_BIN}"
}

# ---------------------------------------------------------------------------
# mb_lynis_run — run `lynis audit system --quick` and parse findings.
# Emits findings in the standard format.
# ---------------------------------------------------------------------------
mb_lynis_run() {
    mb_lynis_install

    local lynis_cmd
    if mb_command_exists lynis; then
        lynis_cmd="lynis"
    else
        lynis_cmd="$LYNIS_BIN"
    fi

    mb_info "Running Lynis quick audit..."

    local out
    out="$(mktemp -d)"
    local raw
    raw="${out}/lynis.raw"
    local dat
    dat="${out}/lynis.dat"

    # Run Lynis; capture both raw output and the .dat report.
    ${lynis_cmd} audit system --quick --auditor "mb-audit" \
        --logfile "${out}/lynis.log" \
        --report-file "${dat}" \
        > "$raw" 2>&1 || true

    # Parse warnings (high severity) and suggestions (lower severity).
    # Lynis lines look like:
    #   - Warning [CSSH-7270]: ...
    #   - Suggestion [CSSH-7270]: ...
    local count=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^-\ Warning\ \[([A-Z]+-[0-9]+)\]:\ (.*)$ ]]; then
            local id="${BASH_REMATCH[1]}"
            local msg="${BASH_REMATCH[2]}"
            mb_emit_finding FAIL high "$MB_MODULE" "lynis_${id}" \
                "Lynis warning: ${msg}" \
                "See Lynis report ${id} for remediation steps"
            count=$((count + 1))
        elif [[ "$line" =~ ^-\ Suggestion\ \[([A-Z]+-[0-9]+)\]:\ (.*)$ ]]; then
            local id="${BASH_REMATCH[1]}"
            local msg="${BASH_REMATCH[2]}"
            # Extract the fix hint after the colon if present.
            local fix=""
            if [[ "$msg" =~ :\ (.*)$ ]]; then
                fix="${BASH_REMATCH[1]}"
            fi
            mb_emit_finding WARN low "$MB_MODULE" "lynis_${id}" \
                "Lynis suggestion: ${msg}" \
                "${fix}"
            count=$((count + 1))
        fi
    done < "$raw"

    if [[ "$count" -eq 0 ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "lynis_summary" \
            "Lynis quick audit completed with no warnings or suggestions" ""
    fi

    # Emit a hardening index line if available.
    local index
    index="$(grep -E '^hardening_index=' "$dat" 2>/dev/null | cut -d= -f2 || true)"
    if [[ -n "$index" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "lynis_hardening_index" \
            "Lynis hardening index: ${index}" ""
    fi

    rm -rf "$out"
}

# Direct execution.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_lynis_run
fi
