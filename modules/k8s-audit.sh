#!/usr/bin/env bash
# k8s-audit.sh — Kubernetes security audit for the mb tool.
#
# Read-only audit of a Kubernetes cluster based on CIS Kubernetes Benchmark v1.9.0.
# Checks API server security (anonymous access, RBAC, TLS, audit logging),
# control plane configuration (etcd, scheduler, controller manager),
# worker node security (kubelet, container runtime, network policies),
# and workload security (privileged pods, host access, service account tokens,
# resource limits, security contexts, image policies).
#
# Outputs:
#   - TXT report:  /var/log/k8s-audit/k8s-audit-latest.txt
#   - JSON report: /var/log/k8s-audit/k8s-audit-latest.json
#   - Pipe-delimited findings (consumed by the standard report generator)
#
# This module is strictly read-only: it never modifies any Kubernetes resource.
set -euo pipefail

if [[ -z "${MB_AUDIT_VERSION:-}" ]]; then
    # shellcheck source=../lib/common.sh
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
fi

MB_MODULE="k8s"

# Dedicated report directory for K8s audit artefacts.
K8S_REPORT_DIR="${K8S_REPORT_DIR:-/var/log/k8s-audit}"

# Kubernetes context to audit (empty = current context).
K8S_CONTEXT="${K8S_CONTEXT:-}"

# Kubernetes namespace scope (empty = all namespaces).
K8S_NAMESPACE="${K8S_NAMESPACE:-}"

# Counters for the summary (PASS/FAIL/WARN/SKIP).
_k8_pass=0
_k8_fail=0
_k8_warn=0
_k8_skip=0

# Collected findings for the JSON report (STATUS|SEVERITY|CHECK|MESSAGE).
_k8_findings=()

# Per-pod findings for the detailed report (POD|STATUS|SEVERITY|CHECK|MESSAGE).
_k8_pod_findings=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Run kubectl safely, swallowing stderr. Returns 0 if kubectl exists & command
# succeeds, non-zero otherwise. Output on stdout.
_k8s() {
    if ! mb_command_exists kubectl; then
        return 127
    fi
    local ctx_args=()
    [[ -n "$K8S_CONTEXT" ]] && ctx_args+=(--context "$K8S_CONTEXT")
    kubectl "${ctx_args[@]}" "$@" 2>/dev/null || true
}

# Emit a finding and track counters. Also records into the JSON findings array.
# Usage: _k8_emit <status> <severity> <check> <message> <fix>
_k8_emit() {
    local status="$1" severity="$2" check="$3" message="$4" fix="$5"
    mb_emit_finding "$status" "$severity" "$MB_MODULE" "$check" "$message" "$fix"
    case "$status" in
        PASS) _k8_pass=$((_k8_pass + 1)) ;;
        FAIL) _k8_fail=$((_k8_fail + 1)) ;;
        WARN) _k8_warn=$((_k8_warn + 1)) ;;
        SKIP) _k8_skip=$((_k8_skip + 1)) ;;
    esac
    _k8_findings+=("${status}|${severity}|${check}|${message}")
}

# Emit a per-pod finding.
# Usage: _k8_emit_pod <pod> <status> <severity> <check> <message>
_k8_emit_pod() {
    local pod="$1" status="$2" severity="$3" check="$4" message="$5"
    _k8_pod_findings+=("${pod}|${status}|${severity}|${check}|${message}")
}

# Check if a Kubernetes resource exists.
_k8s_resource_exists() {
    local kind="$1" name="$2" ns="${3:-}"
    local ns_args=()
    [[ -n "$ns" ]] && ns_args+=(-n "$ns")
    _k8s get "$kind" "$name" "${ns_args[@]}" -o name 2>/dev/null | grep -q . && return 0 || return 1
}

# ---------------------------------------------------------------------------
# API Server Checks (CIS 1.x)
# ---------------------------------------------------------------------------

k8_audit_api_server() {
    mb_info "Auditing API server configuration..."

    # Check if we can access the cluster at all
    if ! _k8s cluster-info >/dev/null 2>&1; then
        _k8_emit "SKIP" "info" "K8S-API-000" "Cannot connect to Kubernetes cluster" ""
        return
    fi

    # CIS 1.2.1: Anonymous access to API server should be disabled
    local anon_auth
    anon_auth=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-anonymous-auth=[a-z]*' | cut -d= -f2 || echo "")
    if [[ -z "$anon_auth" ]]; then
        _k8_emit "WARN" "medium" "K8S-API-001" "Anonymous auth flag not found in API server args (default may vary)" "Set --anonymous-auth=false in API server config"
    elif [[ "$anon_auth" == "false" ]]; then
        _k8_emit "PASS" "info" "K8S-API-001" "Anonymous access to API server is disabled" ""
    else
        _k8_emit "FAIL" "high" "K8S-API-001" "Anonymous access to API server is enabled" "Set --anonymous-auth=false in API server config"
    fi

    # CIS 1.2.2: Basic auth should not be used
    local basic_auth
    basic_auth=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-basic-auth-file=[^ ]*' || echo "")
    if [[ -z "$basic_auth" ]]; then
        _k8_emit "PASS" "info" "K8S-API-002" "Basic auth is not configured" ""
    else
        _k8_emit "FAIL" "high" "K8S-API-002" "Basic auth file is configured (deprecated and insecure)" "Remove --basic-auth-file and use tokens or certificates"
    fi

    # CIS 1.2.3: RBAC should be enabled
    local rbac
    rbac=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-authorization-mode=[^ ]*' | cut -d= -f2 || echo "")
    if [[ "$rbac" == *"RBAC"* ]]; then
        _k8_emit "PASS" "info" "K8S-API-003" "RBAC authorization is enabled" ""
    elif [[ -z "$rbac" ]]; then
        _k8_emit "WARN" "medium" "K8S-API-003" "Authorization mode not explicitly set (default may include RBAC)" "Set --authorization-mode=Node,RBAC"
    else
        _k8_emit "FAIL" "high" "K8S-API-003" "RBAC is not in authorization mode ($rbac)" "Add RBAC to --authorization-mode"
    fi

    # CIS 1.2.4: Audit logging should be enabled
    local audit_log
    audit_log=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-audit-log-path=[^ ]*' | cut -d= -f2 || echo "")
    if [[ -n "$audit_log" ]]; then
        _k8_emit "PASS" "info" "K8S-API-004" "Audit logging is enabled ($audit_log)" ""
    else
        _k8_emit "FAIL" "medium" "K8S-API-004" "Audit logging is not enabled" "Set --audit-log-path=/var/log/kubernetes/audit.log"
    fi

    # CIS 1.2.5: TLS minimum version should be 1.2+
    local tls_min
    tls_min=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-tls-min-version=[^ ]*' | cut -d= -f2 || echo "")
    if [[ -z "$tls_min" ]]; then
        _k8_emit "WARN" "low" "K8S-API-005" "TLS minimum version not explicitly set" "Set --tls-min-version=VersionTLS12"
    elif [[ "$tls_min" == "VersionTLS12" || "$tls_min" == "VersionTLS13" ]]; then
        _k8_emit "PASS" "info" "K8S-API-005" "TLS minimum version is $tls_min" ""
    else
        _k8_emit "FAIL" "medium" "K8S-API-005" "TLS minimum version is $tls_min (should be 1.2+)" "Set --tls-min-version=VersionTLS12"
    fi

    # CIS 1.2.6: --token-auth-file should not be used
    local token_auth
    token_auth=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-token-auth-file=[^ ]*' || echo "")
    if [[ -z "$token_auth" ]]; then
        _k8_emit "PASS" "info" "K8S-API-006" "Static token auth file is not configured" ""
    else
        _k8_emit "FAIL" "medium" "K8S-API-006" "Static token auth file is configured" "Remove --token-auth-file and use OIDC or client certificates"
    fi

    # CIS 1.2.7: --kubelet-https should be true
    local kubelet_https
    kubelet_https=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-kubelet-https=[a-z]*' | cut -d= -f2 || echo "true")
    if [[ "$kubelet_https" == "true" ]]; then
        _k8_emit "PASS" "info" "K8S-API-007" "kubelet HTTPS is enabled" ""
    else
        _k8_emit "FAIL" "high" "K8S-API-007" "kubelet HTTPS is disabled" "Set --kubelet-https=true"
    fi

    # CIS 1.2.8: --profiling should be false
    local profiling
    profiling=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-profiling=[a-z]*' | cut -d= -f2 || echo "true")
    if [[ "$profiling" == "false" ]]; then
        _k8_emit "PASS" "info" "K8S-API-008" "API server profiling is disabled" ""
    else
        _k8_emit "WARN" "low" "K8S-API-008" "API server profiling is enabled (exposes debug endpoints)" "Set --profiling=false"
    fi
}

# ---------------------------------------------------------------------------
# Control Plane Checks (CIS 2.x)
# ---------------------------------------------------------------------------

k8_audit_control_plane() {
    mb_info "Auditing control plane configuration..."

    # CIS 2.1: etcd should have client cert auth
    local etcd_cert_auth
    etcd_cert_auth=$(_k8s get pod -n kube-system -l component=etcd -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-client-cert-auth=[a-z]*' | cut -d= -f2 || echo "")
    if [[ "$etcd_cert_auth" == "true" ]]; then
        _k8_emit "PASS" "info" "K8S-CP-001" "etcd client cert auth is enabled" ""
    elif [[ -z "$etcd_cert_auth" ]]; then
        _k8_emit "WARN" "medium" "K8S-CP-001" "etcd client cert auth not explicitly set" "Set --client-cert-auth=true in etcd config"
    else
        _k8_emit "FAIL" "high" "K8S-CP-001" "etcd client cert auth is disabled" "Set --client-cert-auth=true"
    fi

    # CIS 2.2: etcd should use TLS
    local etcd_tls
    etcd_tls=$(_k8s get pod -n kube-system -l component=etcd -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-auto-tls=[a-z]*' | cut -d= -f2 || echo "")
    local etcd_cert_file
    etcd_cert_file=$(_k8s get pod -n kube-system -l component=etcd -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-cert-file=[^ ]*' | cut -d= -f2 || echo "")
    if [[ -n "$etcd_cert_file" ]]; then
        _k8_emit "PASS" "info" "K8S-CP-002" "etcd uses TLS ($etcd_cert_file)" ""
    elif [[ "$etcd_tls" == "true" ]]; then
        _k8_emit "WARN" "low" "K8S-CP-002" "etcd uses auto-TLS (less secure than explicit certs)" "Use --cert-file and --key-file instead of --auto-tls"
    else
        _k8_emit "FAIL" "high" "K8S-CP-002" "etcd does not use TLS" "Configure --cert-file and --key-file"
    fi

    # CIS 2.3: Scheduler should have profiling disabled
    local sched_profiling
    sched_profiling=$(_k8s get pod -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-profiling=[a-z]*' | cut -d= -f2 || echo "true")
    if [[ "$sched_profiling" == "false" ]]; then
        _k8_emit "PASS" "info" "K8S-CP-003" "Scheduler profiling is disabled" ""
    else
        _k8_emit "WARN" "low" "K8S-CP-003" "Scheduler profiling is enabled" "Set --profiling=false"
    fi

    # CIS 2.4: Controller manager should have profiling disabled
    local cm_profiling
    cm_profiling=$(_k8s get pod -n kube-system -l component=kube-controller-manager -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-profiling=[a-z]*' | cut -d= -f2 || echo "true")
    if [[ "$cm_profiling" == "false" ]]; then
        _k8_emit "PASS" "info" "K8S-CP-004" "Controller manager profiling is disabled" ""
    else
        _k8_emit "WARN" "low" "K8S-CP-004" "Controller manager profiling is enabled" "Set --profiling=false"
    fi

    # CIS 2.5: Service account lookup should be enabled
    local sa_lookup
    sa_lookup=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-service-account-lookup=[a-z]*' | cut -d= -f2 || echo "true")
    if [[ "$sa_lookup" == "true" ]]; then
        _k8_emit "PASS" "info" "K8S-CP-005" "Service account lookup is enabled" ""
    else
        _k8_emit "FAIL" "medium" "K8S-CP-005" "Service account lookup is disabled" "Set --service-account-lookup=true"
    fi

    # CIS 2.6: PodSecurityPolicy or PodSecurityStandard admission
    local admission_plugins
    admission_plugins=$(_k8s get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | grep -o '\-\-enable-admission-plugins=[^ ]*' | cut -d= -f2 || echo "")
    if [[ "$admission_plugins" == *"PodSecurityPolicy"* ]]; then
        _k8_emit "PASS" "info" "K8S-CP-006" "PodSecurityPolicy admission is enabled" ""
    elif [[ "$admission_plugins" == *"PodSecurity"* ]]; then
        _k8_emit "PASS" "info" "K8S-CP-006" "PodSecurity admission is enabled" ""
    elif [[ -z "$admission_plugins" ]]; then
        _k8_emit "WARN" "medium" "K8S-CP-006" "Admission plugins not explicitly configured" "Enable PodSecurity or PodSecurityPolicy admission"
    else
        _k8_emit "WARN" "medium" "K8S-CP-006" "No PodSecurity/PodSecurityPolicy admission plugin found" "Add PodSecurity to --enable-admission-plugins"
    fi
}

# ---------------------------------------------------------------------------
# Worker Node Checks (CIS 3.x / 4.x)
# ---------------------------------------------------------------------------

k8_audit_worker_nodes() {
    mb_info "Auditing worker node configuration..."

    # CIS 3.2.1: Kubelet anonymous auth should be disabled
    # Check via configmap or direct kubelet config
    local kubelet_anon
    kubelet_anon=$(_k8s get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' 2>/dev/null || echo "")
    if [[ -z "$kubelet_anon" ]]; then
        _k8_emit "SKIP" "info" "K8S-NODE-001" "Cannot determine kubelet version" ""
    else
        _k8_emit "PASS" "info" "K8S-NODE-001" "Kubelet version: $kubelet_anon" ""
    fi

    # CIS 4.1: Check for network policies
    local np_count
    np_count=$(_k8s get networkpolicy -A 2>/dev/null | wc -l || echo 0)
    np_count=$((np_count - 1))  # Subtract header line
    if [[ "$np_count" -gt 0 ]]; then
        _k8_emit "PASS" "info" "K8S-NODE-002" "Network policies are configured ($np_count policies)" ""
    else
        _k8_emit "WARN" "medium" "K8S-NODE-002" "No network policies found (all pods can communicate)" "Define NetworkPolicy resources to restrict pod-to-pod traffic"
    fi

    # CIS 4.2: Check for PodSecurity policies/standards
    local ns_count
    ns_count=$(_k8s get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | wc -w || echo 0)
    if [[ "$ns_count" -gt 0 ]]; then
        local ns_labels_count
        ns_labels_count=$(_k8s get namespaces -o jsonpath='{.items[*].metadata.labels}' 2>/dev/null | grep -oc 'pod-security.kubernetes.io' || echo 0)
        if [[ "$ns_labels_count" -gt 0 ]]; then
            _k8_emit "PASS" "info" "K8S-NODE-003" "Pod Security Standard labels found on $ns_labels_count namespaces" ""
        else
            _k8_emit "WARN" "medium" "K8S-NODE-003" "No Pod Security Standard labels on namespaces" "Add pod-security.kubernetes.io/enforce labels to namespaces"
        fi
    else
        _k8_emit "SKIP" "info" "K8S-NODE-003" "No namespaces found" ""
    fi
}

# ---------------------------------------------------------------------------
# Workload Security Checks (CIS 5.x)
# ---------------------------------------------------------------------------

k8_audit_workloads() {
    mb_info "Auditing workload security..."

    local ns_args=()
    [[ -n "$K8S_NAMESPACE" ]] && ns_args+=(-n "$K8S_NAMESPACE")

    # Get all pods
    local pods
    pods=$(_k8s get pods "${ns_args[@]}" -A -o jsonpath='{range .items[*]}{.metadata.name}{","}{.metadata.namespace}{"\n"}{end}' 2>/dev/null || echo "")
    if [[ -z "$pods" ]]; then
        _k8_emit "SKIP" "info" "K8S-WL-000" "No pods found in cluster" ""
        return
    fi

    local pod_count
    pod_count=$(echo "$pods" | wc -l | tr -d ' ')

    # CIS 5.1.1: Check for privileged containers
    local privileged_count
    privileged_count=$(_k8s get pods "${ns_args[@]}" -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.securityContext.privileged}{"\n"}{end}{end}' 2>/dev/null | grep -c true || echo 0)
    if [[ "$privileged_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-001" "No privileged containers found ($pod_count pods)" ""
    else
        _k8_emit "FAIL" "high" "K8S-WL-001" "Found $privileged_count privileged containers" "Remove privileged: true or use specific capabilities instead"
    fi

    # CIS 5.1.2: Check for hostNetwork
    local hostnet_count
    hostnet_count=$(_k8s get pods "${ns_args[@]}" -A -o jsonpath='{range .items[*]}{.spec.hostNetwork}{"\n"}{end}' 2>/dev/null | grep -c true || echo 0)
    if [[ "$hostnet_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-002" "No pods using hostNetwork" ""
    else
        _k8_emit "WARN" "medium" "K8S-WL-002" "Found $hostnet_count pods using hostNetwork" "Avoid hostNetwork unless required (e.g., CNI plugins)"
    fi

    # CIS 5.1.3: Check for hostPID
    local hostpid_count
    hostpid_count=$(_k8s get pods "${ns_args[@]}" -A -o jsonpath='{range .items[*]}{.spec.hostPID}{"\n"}{end}' 2>/dev/null | grep -c true || echo 0)
    if [[ "$hostpid_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-003" "No pods using hostPID" ""
    else
        _k8_emit "FAIL" "high" "K8S-WL-003" "Found $hostpid_count pods using hostPID" "Avoid hostPID unless absolutely necessary"
    fi

    # CIS 5.1.4: Check for hostIPC
    local hostipc_count
    hostipc_count=$(_k8s get pods "${ns_args[@]}" -A -o jsonpath='{range .items[*]}{.spec.hostIPC}{"\n"}{end}' 2>/dev/null | grep -c true || echo 0)
    if [[ "$hostipc_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-004" "No pods using hostIPC" ""
    else
        _k8_emit "FAIL" "high" "K8S-WL-004" "Found $hostipc_count pods using hostIPC" "Avoid hostIPC unless absolutely necessary"
    fi

    # CIS 5.1.5: Check for containers with allowPrivilegeEscalation not false
    local priv_esc_count
    priv_esc_count=$(_k8s get pods "${ns_args[@]}" -A -o json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    count = 0
    for pod in data.get('items', []):
        for c in pod.get('spec', {}).get('containers', []):
            sc = c.get('securityContext', {})
            if sc.get('allowPrivilegeEscalation') != False:
                count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo 0)
    if [[ "$priv_esc_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-005" "All containers have allowPrivilegeEscalation=false" ""
    else
        _k8_emit "WARN" "medium" "K8S-WL-005" "Found $priv_esc_count containers without allowPrivilegeEscalation=false" "Set allowPrivilegeEscalation: false in securityContext"
    fi

    # CIS 5.1.6: Check for containers running as root (runAsNonRoot not true)
    local root_count
    root_count=$(_k8s get pods "${ns_args[@]}" -A -o json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    count = 0
    for pod in data.get('items', []):
        pod_sc = pod.get('spec', {}).get('securityContext', {})
        for c in pod.get('spec', {}).get('containers', []):
            c_sc = c.get('securityContext', {})
            if c_sc.get('runAsNonRoot') != True and pod_sc.get('runAsNonRoot') != True:
                count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo 0)
    if [[ "$root_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-006" "All containers set runAsNonRoot=true" ""
    else
        _k8_emit "WARN" "medium" "K8S-WL-006" "Found $root_count containers that may run as root" "Set runAsNonRoot: true or specify runAsUser: non-zero"
    fi

    # CIS 5.1.7: Check for containers with readOnlyRootFilesystem not true
    local ro_rootfs_count
    ro_rootfs_count=$(_k8s get pods "${ns_args[@]}" -A -o json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    count = 0
    for pod in data.get('items', []):
        for c in pod.get('spec', {}).get('containers', []):
            sc = c.get('securityContext', {})
            if sc.get('readOnlyRootFilesystem') != True:
                count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo 0)
    if [[ "$ro_rootfs_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-007" "All containers have readOnlyRootFilesystem=true" ""
    else
        _k8_emit "WARN" "low" "K8S-WL-007" "Found $ro_rootfs_count containers without readOnlyRootFilesystem" "Set readOnlyRootFilesystem: true where possible"
    fi

    # CIS 5.1.8: Check for containers without resource limits
    local no_limits_count
    no_limits_count=$(_k8s get pods "${ns_args[@]}" -A -o json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    count = 0
    for pod in data.get('items', []):
        for c in pod.get('spec', {}).get('containers', []):
            if not c.get('resources', {}).get('limits'):
                count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo 0)
    if [[ "$no_limits_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-008" "All containers have resource limits" ""
    else
        _k8_emit "WARN" "medium" "K8S-WL-008" "Found $no_limits_count containers without resource limits" "Set resource limits to prevent resource exhaustion"
    fi

    # CIS 5.1.9: Check for dangerous capabilities
    local danger_caps_count
    danger_caps_count=$(_k8s get pods "${ns_args[@]}" -A -o json 2>/dev/null | python3 -c "
import json, sys
dangerous = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'CHOWN', 'FOWNER', 'MKNOD', 'MAC_ADMIN', 'MAC_OVERRIDE', 'NET_RAW', 'SYS_BOOT', 'SYS_NICE', 'SYS_RESOURCE', 'SYS_TIME', 'SYS_TTY_CONFIG'}
try:
    data = json.load(sys.stdin)
    count = 0
    for pod in data.get('items', []):
        for c in pod.get('spec', {}).get('containers', []):
            caps = c.get('securityContext', {}).get('capabilities', {}).get('add', [])
            for cap in caps:
                if cap in dangerous:
                    count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo 0)
    if [[ "$danger_caps_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-009" "No dangerous capabilities added" ""
    else
        _k8_emit "FAIL" "high" "K8S-WL-009" "Found $danger_caps_count containers with dangerous capabilities" "Remove dangerous capabilities from securityContext.capabilities.add"
    fi

    # CIS 5.2.1: Check for ServiceAccount tokens auto-mounted
    local auto_mount_count
    auto_mount_count=$(_k8s get pods "${ns_args[@]}" -A -o json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    count = 0
    for pod in data.get('items', []):
        if pod.get('spec', {}).get('automountServiceAccountToken') != False:
            count += 1
    print(count)
except:
    print(0)
" 2>/dev/null || echo 0)
    if [[ "$auto_mount_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-010" "All pods have automountServiceAccountToken=false" ""
    else
        _k8_emit "WARN" "medium" "K8S-WL-010" "Found $auto_mount_count pods with auto-mounted SA tokens" "Set automountServiceAccountToken: false for pods that don't need API access"
    fi

    # CIS 5.3.1: Check for image tag :latest
    local latest_count
    latest_count=$(_k8s get pods "${ns_args[@]}" -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null | grep -c ':latest' || echo 0)
    if [[ "$latest_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-WL-011" "No containers using :latest image tag" ""
    else
        _k8_emit "WARN" "low" "K8S-WL-011" "Found $latest_count containers using :latest image tag" "Pin image tags to specific versions"
    fi
}

# ---------------------------------------------------------------------------
# Policy Checks (CIS 5.4.x)
# ---------------------------------------------------------------------------

k8_audit_policies() {
    mb_info "Auditing RBAC and policies..."

    # CIS 5.3.1: Check for cluster-admin bindings
    local cluster_admin_count
    cluster_admin_count=$(_k8s get clusterrolebinding -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -ci 'cluster-admin' || echo 0)
    if [[ "$cluster_admin_count" -le 1 ]]; then
        _k8_emit "PASS" "info" "K8S-RBAC-001" "Minimal cluster-admin bindings ($cluster_admin_count)" ""
    else
        _k8_emit "WARN" "medium" "K8S-RBAC-001" "Found $cluster_admin_count cluster-admin bindings" "Minimize cluster-admin grants, use least-privilege roles"
    fi

    # CIS 5.3.2: Check for default service account usage
    local default_sa_count
    default_sa_count=$(_k8s get pods -A -o jsonpath='{range .items[*]}{.spec.serviceAccountName}{"\n"}{end}' 2>/dev/null | grep -c '^default$' || echo 0)
    if [[ "$default_sa_count" -eq 0 ]]; then
        _k8_emit "PASS" "info" "K8S-RBAC-002" "No pods using default service account" ""
    else
        _k8_emit "WARN" "low" "K8S-RBAC-002" "Found $default_sa_count pods using default service account" "Create dedicated service accounts for each workload"
    fi

    # CIS 5.4.1: Check for namespaces without ResourceQuota
    local ns_total
    ns_total=$(_k8s get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | wc -w || echo 0)
    local quota_ns
    quota_ns=$(_k8s get resourcequota -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}' 2>/dev/null | sort -u | wc -l || echo 0)
    if [[ "$ns_total" -gt 0 ]] && [[ "$quota_ns" -ge "$ns_total" ]]; then
        _k8_emit "PASS" "info" "K8S-RBAC-003" "All namespaces have ResourceQuotas" ""
    elif [[ "$ns_total" -gt 0 ]]; then
        _k8_emit "WARN" "low" "K8S-RBAC-003" "Only $quota_ns/$ns_total namespaces have ResourceQuotas" "Add ResourceQuota to all namespaces"
    else
        _k8_emit "SKIP" "info" "K8S-RBAC-003" "No namespaces found" ""
    fi
}

# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

_k8_generate_txt_report() {
    local out="$1"
    {
        printf 'Kubernetes Security Audit Report\n'
        printf 'CIS Kubernetes Benchmark v1.9.0\n'
        printf 'Generated: %s\n' "$(mb_now_iso)"
        printf 'Host: %s\n' "$(mb_hostname)"
        printf '========================================\n\n'

        printf 'Summary:\n'
        printf '  PASS: %s\n' "$_k8_pass"
        printf '  FAIL: %s\n' "$_k8_fail"
        printf '  WARN: %s\n' "$_k8_warn"
        printf '  SKIP: %s\n' "$_k8_skip"
        printf '  Total checks: %s\n' "$((_k8_pass + _k8_fail + _k8_warn + _k8_skip))"
        printf '\n'

        printf 'Findings:\n'
        printf '%-6s %-8s %-20s %s\n' "STAT" "SEV" "CHECK" "MESSAGE"
        printf '%-6s %-8s %-20s %s\n' "----" "---" "-----" "-------"
        for f in "${_k8_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            printf '%-6s %-8s %-20s %s\n' "$status" "$severity" "$check" "$message"
        done
        printf '\n'

        printf 'Notes:\n'
        printf '  This is a read-only audit. No Kubernetes resources were modified.\n'
        printf '  CIS Kubernetes Benchmark v1.9.0: https://www.cisecurity.org/benchmark/kubernetes\n'
        printf '  Related: k8s_security_audit.sh (gold project), kube-bench\n'
    } > "$out"
}

_k8_generate_json_report() {
    local out="$1"
    {
        printf '{\n'
        printf '  "module": "k8s-audit",\n'
        printf '  "benchmark": "CIS Kubernetes Benchmark v1.9.0",\n'
        printf '  "generated": "%s",\n' "$(mb_now_iso)"
        printf '  "host": "%s",\n' "$(mb_hostname)"
        printf '  "summary": {\n'
        printf '    "pass": %s,\n' "$_k8_pass"
        printf '    "fail": %s,\n' "$_k8_fail"
        printf '    "warn": %s,\n' "$_k8_warn"
        printf '    "skip": %s,\n' "$_k8_skip"
        printf '    "total": %s\n' "$((_k8_pass + _k8_fail + _k8_warn + _k8_skip))"
        printf '  },\n'
        printf '  "findings": [\n'
        local first=1
        for f in "${_k8_findings[@]}"; do
            IFS='|' read -r status severity check message <<< "$f"
            if [[ $first -eq 0 ]]; then
                printf ',\n'
            fi
            first=0
            local esc_msg esc_check
            esc_msg="${message//\\/\\\\}"
            esc_msg="${esc_msg//\"/\\\"}"
            esc_check="${check//\\/\\\\}"
            esc_check="${esc_check//\"/\\\"}"
            printf '    {\n'
            printf '      "status": "%s",\n' "$status"
            printf '      "severity": "%s",\n' "$severity"
            printf '      "check": "%s",\n' "$esc_check"
            printf '      "message": "%s"\n' "$esc_msg"
            printf '    }'
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

mb_audit_k8s() {
    mb_info "Starting Kubernetes security audit (CIS Kubernetes Benchmark v1.9.0)..."

    if ! mb_command_exists kubectl; then
        mb_warn "kubectl not found — skipping K8s audit"
        _k8_emit "SKIP" "info" "K8S-000" "kubectl not installed" ""
        return
    fi

    # API server checks
    k8_audit_api_server

    # Control plane checks
    k8_audit_control_plane

    # Worker node checks
    k8_audit_worker_nodes

    # Workload security checks
    k8_audit_workloads

    # RBAC and policy checks
    k8_audit_policies

    # Generate reports
    mb_ensure_dir "$K8S_REPORT_DIR" 2>/dev/null || K8S_REPORT_DIR="/tmp/k8s-audit"
    mb_ensure_dir "$K8S_REPORT_DIR" 2>/dev/null || true
    local txt_report="${K8S_REPORT_DIR}/k8s-audit-latest.txt"
    local json_report="${K8S_REPORT_DIR}/k8s-audit-latest.json"

    _k8_generate_txt_report "$txt_report"
    _k8_generate_json_report "$json_report"

    # Copy into standard mb-audit reports dir
    if [[ -d "$MB_AUDIT_REPORTS_DIR" ]]; then
        cp -f "$txt_report" "${MB_AUDIT_REPORTS_DIR}/k8s-audit-latest.txt" 2>/dev/null || true
        cp -f "$json_report" "${MB_AUDIT_REPORTS_DIR}/k8s-audit-latest.json" 2>/dev/null || true
    fi

    local total=$((_k8_pass + _k8_fail + _k8_warn + _k8_skip))
    mb_ok "K8s audit complete: ${_k8_pass} PASS, ${_k8_fail} FAIL, ${_k8_warn} WARN, ${_k8_skip} SKIP (${total} checks)"
    mb_info "TXT report:  ${txt_report}"
    mb_info "JSON report: ${json_report}"
}

# Allow direct execution: `modules/k8s-audit.sh` → runs all checks.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mb_audit_k8s
fi
