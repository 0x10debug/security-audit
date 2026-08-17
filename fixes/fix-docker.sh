#!/usr/bin/env bash
# fix-docker.sh — bring Docker daemon.json in line with cis-docker.rules.
# Idempotent. Supports --dry-run.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

DAEMON_JSON="${DAEMON_JSON:-/etc/docker/daemon.json}"
DRY_RUN=0
NO_EXPOSED=0
LOG_ROTATION=0
USER_NAMESPACE=0

usage() {
    cat <<EOF
Usage: sudo fix-docker.sh [options]
Options:
  --dry-run              Show changes without applying them.
  --no-exposed-daemon    Ensure the daemon only listens on a unix socket.
  --log-rotation         Configure log rotation (max-size 10m, max-file 3).
  --user-namespace       Enable user namespace remapping.
  --all                  Apply all fixes from cis-docker.rules.
  -h, --help             Show this help.
EOF
}

parse_args() {
    local apply_all=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1; shift ;;
            --no-exposed-daemon) NO_EXPOSED=1; shift ;;
            --log-rotation) LOG_ROTATION=1; shift ;;
            --user-namespace) USER_NAMESPACE=1; shift ;;
            --all) apply_all=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) mb_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
    if [[ $apply_all -eq 1 ]]; then
        NO_EXPOSED=1; LOG_ROTATION=1; USER_NAMESPACE=1
    fi
}

# Minimal JSON merge: writes/updates a top-level key with a JSON value.
# Uses python3 if available, otherwise falls back to a sed-based approach.
json_set() {
    local key="$1" value="$2"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%b[DRY-RUN]%b set %s = %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$key" "$value"
        return
    fi
    if mb_command_exists python3; then
        python3 - "$DAEMON_JSON" "$key" "$value" <<'PY'
import json, sys
path, key, raw = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path) as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}
try:
    data[key] = json.loads(raw)
except json.JSONDecodeError:
    data[key] = raw
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PY
    else
        # Fallback: append/replace a line. Not robust but works for simple cases.
        if [[ -f "$DAEMON_JSON" ]] && grep -q "\"${key}\":" "$DAEMON_JSON"; then
            sed -i "s|\"${key}\":[^,}]*|\"${key}\": ${value}|" "$DAEMON_JSON"
        else
            echo "  \"${key}\": ${value}," >> "$DAEMON_JSON"
        fi
    fi
}

main() {
    parse_args "$@"
    mb_require_root

    if ! mb_command_exists docker; then
        mb_warn "Docker is not installed — nothing to fix."
        exit 0
    fi

    mb_ensure_dir "$(dirname "$DAEMON_JSON")"
    if [[ ! -f "$DAEMON_JSON" ]]; then
        if [[ "$DRY_RUN" -eq 0 ]]; then
            echo "{}" > "$DAEMON_JSON"
        else
            printf '%b[DRY-RUN]%b create %s\n' "$MB_COLOR_YELLOW" "$MB_COLOR_RESET" "$DAEMON_JSON"
        fi
    fi

    if [[ "$DRY_RUN" -eq 0 ]]; then
        mb_backup_file "$DAEMON_JSON"
    fi

    if [[ $NO_EXPOSED -eq 1 ]]; then
        # Remove any tcp:// hosts binding to public addresses.
        json_set hosts '["unix:///var/run/docker.sock"]'
    fi

    if [[ $LOG_ROTATION -eq 1 ]]; then
        json_set log-driver '"json-file"'
        json_set log-opts '{"max-size":"10m","max-file":"3"}'
    fi

    if [[ $USER_NAMESPACE -eq 1 ]]; then
        json_set userns-remap '"default"'
    fi

    if [[ "$DRY_RUN" -eq 0 ]]; then
        if mb_command_exists systemctl; then
            systemctl restart docker && mb_ok "Docker daemon restarted"
        fi
        mb_ok "Docker daemon.json updated. Backup at ${DAEMON_JSON}.mb.bak.*"
    else
        mb_info "Dry run complete — no changes applied."
    fi
}

main "$@"
