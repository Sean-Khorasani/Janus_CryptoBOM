# Linux Support Contract

Contract version: **2026-06-10 / Linux Gate L0**

## Platform And Evidence Matrix

Only entries marked **supported** are release targets. Experimental entries are
not release-blocking and must not be presented as supported.

| Platform | Tier | Native | Package/systemd | Container/Compose | Browser | Helm | E2E | Release artifact |
|---|---|---|---|---|---|---|---|---|
| Ubuntu Server 24.04 LTS, glibc, systemd, x86_64 | Supported | `Native / ubuntu-24.04-x86_64-glibc / supported` | `Staged package and systemd static / ubuntu-24.04-x86_64 / supported` | `Containers and compose / ubuntu-24.04-x86_64 / supported` | `Browser / chromium / ubuntu-24.04-x86_64 / supported` | `Helm render / ubuntu-24.04-x86_64 / supported` | `E2E smoke / ubuntu-24.04-x86_64 / supported` | `Release evidence / ubuntu-24.04-x86_64 / supported` |
| Ubuntu Server 24.04 LTS, glibc, systemd, arm64 | Experimental | `Native / ubuntu-24.04-arm64-glibc / experimental` | Missing | Missing | Missing | Architecture-neutral render only | Missing | Missing |
| Debian 12, RHEL 9, musl, non-systemd init, Podman | Unsupported | Missing | Missing | Missing | Missing | Missing | Missing | Missing |

The required aggregate CI check is `Linux Gate L0 / required`. Release evidence
is produced by `.github/workflows/linux-release-evidence.yml`. Branch
protection is repository-host configuration and must separately require the
aggregate check.

## Capability And Permission Matrix

Every privileged mode is opt-in in both agent TOML and deployment permissions.
Permission profiles do not enable a feature by themselves.

| Capability | Required Linux access / profile | Deployment status | Evidence status |
|---|---|---|---|
| Passive source/binary/dependency scan; privileged flags remain `false` | Read-only configured scan roots; writable `/var/lib/janus-agent`; base `janus-agent.service` | Supported systemd and Helm default | Native unit tests, staged package/systemd static job, and E2E smoke job |
| Active TLS probing; `enable_active_tls_probing = true` | Outbound network access to explicit targets; base service | Experimental | No target allow-list enforcement or dedicated denial evidence |
| Runtime process metadata/maps; `enable_runtime_discovery = true` | Host PID namespace and readable `/proc/<pid>/{exe,maps}`; `profiles/runtime-discovery.conf` | Experimental systemd; unsupported Helm | Drop-in static analysis only; permission-denial and runtime E2E missing |
| Process-memory scraping; runtime plus `enable_process_memory_scraping = true` | Runtime access plus `CAP_SYS_PTRACE`; `profiles/process-memory.conf`; privacy approval | Experimental systemd; unsupported Helm | Drop-in static analysis only; privacy, denial, and runtime E2E missing |
| Plugin execution; `enable_plugin_discovery = true` | Writable delegated `cpu` and `memory` cgroup v2 subtree with `cgroup.kill`; `profiles/plugin-cgroup.conf` | Experimental systemd; unsupported Helm | Rust fail-closed tests; delegated-systemd runtime E2E missing |
| Active migration; `execution_mode = "active"` | Service-specific config writes and service control; no supported profile | Unsupported on Linux | No supported-profile evidence |
| Interception; `intercept_mode` other than `disabled` | Unsafe runtime interception; no profile | Unsupported on Linux | Disabled on Linux |

The runtime scanner currently skips inaccessible processes rather than
reporting a hard permission failure. Treat runtime and memory results as
incomplete unless deployment-specific denial tests prove visibility. Memory
scraping handles sensitive process contents and requires explicit privacy and
security approval.

## Privilege Profiles

The packaged base service is the supported passive profile. To opt in under
systemd, copy only the required file from `packaging/systemd/profiles/` to
`/etc/systemd/system/janus-agent.service.d/`, enable the matching TOML flag,
then run:

```bash
sudo systemctl daemon-reload
sudo systemctl restart janus-agent
systemctl show janus-agent -p AmbientCapabilities -p Delegate -p ProtectProc
```

`runtime-discovery.conf` exposes only ptraceable `/proc` entries.
`process-memory.conf` additionally grants only `CAP_SYS_PTRACE`.
`plugin-cgroup.conf` delegates only the `cpu` and `memory` controllers. Plugin
execution fails closed if limits, attachment, or cleanup cannot be applied.
The drop-ins are currently source-tree reference artifacts; the release
archive and install script do not install them.

For Kubernetes, use `values-passive-linux.yaml`. No elevated Helm example is
provided: current chart templates keep privileged discovery flags disabled and
share one container security context between server and agent. Using that
global context to add `SYS_PTRACE` would unnecessarily elevate the server.

## Toolchains And Deployment

- Go 1.25.x; Rust 1.96.0 with `rustfmt` and `clippy`
- Node.js 22.x and npm using `ui/package-lock.json`
- Protobuf compiler 3.21.x; PostgreSQL 16.x

Dependency lockfiles are required release inputs and must not change during
builds. Root-only provisioning is in `docs/linux-root-prerequisites.md`.

The root `docker-compose.yml` is the canonical local Linux deployment and the
Compose definition exercised by Linux CI. Internal ports are HTTP 8080 and
gRPC 9443.
