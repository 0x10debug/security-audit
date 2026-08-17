#!/usr/bin/env bash
# container-scan.sh — container image vulnerability scanning for the mb audit tool.
# Uses Trivy to scan all running container images and categorizes CVEs by severity.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="container"
TRIVY_BIN="${TRIVY_BIN:-/usr/local/bin/trivy}"

# ---------------------------------------------------------------------------
# mb_container_install_trivy — install Trivy if not present.
# ---------------------------------------------------------------------------
mb_container_install_trivy() {
    mb_require_root

    if mb_command_exists trivy || [[ -x "$TRIVY_BIN" ]]; then
        return 0
    fi

    mb_info "Trivy not found — installing..."

    # Prefer the official install script.
    if mb_command_exists curl; then
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b /usr/local/bin
        mb_ok "Trivy installed to ${TRIVY_BIN}"
        return 0
    fi

    # Fall back to package managers.
    if mb_command_exists apt-get; then
        apt-get update -qq && apt-get install -y trivy
    elif mb_command_exists dnf; then
        dnf install -y trivy
    else
        mb_error "Could not install Trivy automatically. See https://aquasecurity.github.io/trivy/"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# mb_container_list_images — list images of all running containers.
# ---------------------------------------------------------------------------
mb_container_list_images() {
    if ! mb_command_exists docker; then
        return 0
    fi
    docker ps --format '{{.Image}}' 2>/dev/null | sort -u || true
}

# ---------------------------------------------------------------------------
# mb_container_scan — scan all running container images with Trivy.
# Emits one finding per image with a severity breakdown.
# ---------------------------------------------------------------------------
mb_container_scan() {
    if ! mb_command_exists docker; then
        mb_emit_finding WARN info "$MB_MODULE" "docker_available" \
            "Docker is not installed — skipping container scan" ""
        return
    fi

    if ! docker info >/dev/null 2>&1; then
        mb_emit_finding WARN info "$MB_MODULE" "docker_running" \
            "Docker daemon is not running — skipping container scan" ""
        return
    fi

    mb_container_install_trivy

    local images
    images="$(mb_container_list_images)"
    if [[ -z "$images" ]]; then
        mb_emit_finding PASS info "$MB_MODULE" "running_containers" \
            "No running containers to scan" ""
        return
    fi

    local trivy_cmd
    if mb_command_exists trivy; then trivy_cmd="trivy"; else trivy_cmd="$TRIVY_BIN"; fi

    local total_critical=0 total_high=0 total_medium=0 total_low=0

    while IFS= read -r image; do
        [[ -z "$image" ]] && continue
        mb_info "Scanning image: ${image}"

        local json_out
        json_out="$(${trivy_cmd} image --quiet --format json "$image" 2>/dev/null || echo '{}')"

        # Count vulnerabilities by severity from the JSON.
        local crit high med low
        crit="$(echo "$json_out" | grep -oE '"Severity":\s*"CRITICAL"' | wc -l | tr -d ' ')"
        high="$(echo "$json_out" | grep -oE '"Severity":\s*"HIGH"'     | wc -l | tr -d ' ')"
        med="$(echo "$json_out"  | grep -oE '"Severity":\s*"MEDIUM"'   | wc -l | tr -d ' ')"
        low="$(echo "$json_out"  | grep -oE '"Severity":\s*"LOW"'      | wc -l | tr -d ' ')"

        total_critical=$((total_critical + crit))
        total_high=$((total_high + high))
        total_medium=$((total_medium + med))
        total_low=$((total_low + low))

        local msg="Image ${image}: ${crit} Critical, ${high} High, ${med} Medium, ${low} Low"
        if [[ "$crit" -gt 0 ]]; then
            mb_emit_finding FAIL critical "$MB_MODULE" "scan_${image}" \
                "$msg" \
                "docker pull ${image} && docker restart \$(docker ps -q --filter ancestor=${image})"
        elif [[ "$high" -gt 0 ]]; then
            mb_emit_finding FAIL high "$MB_MODULE" "scan_${image}" \
                "$msg" \
                "Update base image: docker pull ${image}"
        elif [[ "$med" -gt 0 ]]; then
            mb_emit_finding WARN medium "$MB_MODULE" "scan_${image}" \
                "$msg" \
                "Plan an image update to resolve ${med} medium-severity CVEs"
        else
            mb_emit_finding PASS info "$MB_MODULE" "scan_${image}" \
                "$msg" ""
        fi
    done <<< "$images"

    # Summary finding.
    mb_emit_finding PASS info "$MB_MODULE" "scan_summary" \
        "Total across all images: ${total_critical} Critical, ${total_high} High, ${total_medium} Medium, ${total_low} Low" \
        ""
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_container_scan
fi
