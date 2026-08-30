# Kubernetes Security Audit

The `k8s` audit module performs a read-only security assessment of a Kubernetes
cluster based on the **CIS Kubernetes Benchmark v1.9.0**.

## Usage

```bash
# Run K8s audit via mb CLI
mb audit run --module k8s

# Run directly
./modules/k8s-audit.sh

# Audit a specific context
K8S_CONTEXT=my-cluster mb audit run --module k8s

# Audit a specific namespace
K8S_NAMESPACE=production mb audit run --module k8s
```

## What It Checks

### API Server (CIS 1.x) — 8 checks

| Check | Description |
|---|---|
| K8S-API-001 | Anonymous access disabled |
| K8S-API-002 | Basic auth not used |
| K8S-API-003 | RBAC authorization enabled |
| K8S-API-004 | Audit logging enabled |
| K8S-API-005 | TLS minimum version 1.2+ |
| K8S-API-006 | Static token auth not used |
| K8S-API-007 | kubelet HTTPS enabled |
| K8S-API-008 | Profiling disabled |

### Control Plane (CIS 2.x) — 6 checks

| Check | Description |
|---|---|
| K8S-CP-001 | etcd client cert auth enabled |
| K8S-CP-002 | etcd uses TLS |
| K8S-CP-003 | Scheduler profiling disabled |
| K8S-CP-004 | Controller manager profiling disabled |
| K8S-CP-005 | Service account lookup enabled |
| K8S-CP-006 | PodSecurity/PodSecurityPolicy admission |

### Worker Nodes (CIS 3.x/4.x) — 3 checks

| Check | Description |
|---|---|
| K8S-NODE-001 | Kubelet version check |
| K8S-NODE-002 | Network policies configured |
| K8S-NODE-003 | Pod Security Standard labels |

### Workload Security (CIS 5.x) — 11 checks

| Check | Description |
|---|---|
| K8S-WL-001 | No privileged containers |
| K8S-WL-002 | No hostNetwork |
| K8S-WL-003 | No hostPID |
| K8S-WL-004 | No hostIPC |
| K8S-WL-005 | allowPrivilegeEscalation=false |
| K8S-WL-006 | runAsNonRoot=true |
| K8S-WL-007 | readOnlyRootFilesystem=true |
| K8S-WL-008 | Resource limits set |
| K8S-WL-009 | No dangerous capabilities |
| K8S-WL-010 | automountServiceAccountToken=false |
| K8S-WL-011 | No :latest image tags |

### RBAC & Policies (CIS 5.3-5.4) — 3 checks

| Check | Description |
|---|---|
| K8S-RBAC-001 | Minimal cluster-admin bindings |
| K8S-RBAC-002 | No default service account usage |
| K8S-RBAC-003 | ResourceQuotas on all namespaces |

## Reports

- **TXT**: `/var/log/k8s-audit/k8s-audit-latest.txt`
- **JSON**: `/var/log/k8s-audit/k8s-audit-latest.json`

Both are also copied to the unified `mb-audit` reports directory.

## Requirements

- `kubectl` installed and configured with cluster access
- Sufficient RBAC permissions to read pods, namespaces, RBAC resources, and
  control plane pods in `kube-system`

## Related

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [kube-bench](https://github.com/aquasecurity/kube-bench) — aquasecurity's
  CIS benchmark tool (complementary, runs on nodes directly)
- `k8s_security_audit.sh` — gold project's standalone K8s audit script
