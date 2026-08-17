# CIS Benchmark Checks

This document describes the CIS Benchmark-aligned controls that `cis-benchmark.sh` checks and why each matters.

## SSH

| Check | Expected | Why |
|---|---|---|
| `ssh_permitrootlogin` | `no` | Root login over SSH is the highest-value target for attackers. Disabling it forces authentication as a normal user with sudo. |
| `ssh_passwordauthentication` | `no` | Password auth allows brute-force attacks. Key-only auth eliminates that attack surface. |
| `ssh_port` | `2222` (configurable) | The default port 22 is scanned constantly. Changing it reduces log noise and opportunistic attacks (not security by itself, but hygiene). |
| `ssh_allowusers` | set | Restricting which accounts can connect via SSH limits the blast radius if a low-privilege account is compromised. |
| `ssh_maxauthtries` | `3` | Limits how many authentication attempts a connection may make before being disconnected. |
| `ssh_logingracetime` | `30` | Short grace time reduces the window for slow brute-force attempts. |

## Firewall

| Check | Expected | Why |
|---|---|---|
| `firewall_default_incoming` | `deny` | A default-deny incoming policy means only explicitly allowed ports are reachable. This is the single most effective network-level control. |
| `firewall_allowed_ports` | `22,80,443` | Only the ports you actually use should be open. Unexpected open ports are a common misconfiguration. |

## Kernel

| Check | Expected | Why |
|---|---|---|
| `kernel_bbr` | `bbr` | BBR congestion control improves throughput on lossy links and is the modern default for production servers. |
| `kernel_file_max` | `1048576` | A low file descriptor limit can cause "too many open files" errors under load. |
| `kernel_somaxconn` | `4096` | The default backlog is often too small for high-connection-rate services. |
| `kernel_ip_forward` | `0` | IP forwarding should be off unless the server is a router or VPN gateway. |
| `kernel_syncookies` | `1` | SYN cookies protect against SYN flood denial-of-service attacks. |
| `kernel_redirects` | `0` | Accepting ICMP redirects allows man-in-the-middle attacks via route spoofing. |

## Docker

| Check | Expected | Why |
|---|---|---|
| `docker_exposed_daemon` | `false` | A Docker daemon exposed to public addresses gives anyone root-level access to the host. This is a critical misconfiguration. |
| `docker_log_rotation` | `true` | Without log rotation, container logs can fill the disk and take down the host. |
| `docker_user_namespace` | enabled | User namespace remapping maps container root to an unprivileged host user, limiting the impact of container escapes. |

## Auto-update

| Check | Expected | Why |
|---|---|---|
| `autoupdate_enabled` | enabled | Unpatched systems are the most common entry point for attackers. Automatic security updates ensure critical patches are applied promptly. |

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
