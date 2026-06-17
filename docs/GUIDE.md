# Janus CryptoBOM — Complete Guide

The end-to-end operator guide: what ships, how to deploy it, every setting, what
each user role can do, use cases and production playbooks, crypto-agility and
maturity measurement, migration wave planning, interoperability, and day-2
maintenance.

For a fast install, start with **[QUICKSTART.md](QUICKSTART.md)**. For the
technical/architecture reference, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Contents

1. [What ships (as-built)](#1-what-ships-as-built)
2. [Deployment topologies](#2-deployment-topologies)
3. [Installation playbooks](#3-installation-playbooks)
4. [Settings reference](#4-settings-reference)
5. [Roles & user manual](#5-roles--user-manual)
6. [Platform support](#6-platform-support)
7. [HSM setup](#7-hsm-setup)
8. [Crypto-agility scorecard](#8-crypto-agility-scorecard)
9. [Capability maturity framework](#9-capability-maturity-framework)
10. [Migration wave planning](#10-migration-wave-planning)
11. [Interoperability reference](#11-interoperability-reference)
12. [Use cases & case studies](#12-use-cases--case-studies)
13. [Observability & maintenance](#13-observability--maintenance)
14. [Versioning & release artifacts](#14-versioning--release-artifacts)

---

## 1. What ships (as-built)

Janus CryptoBOM has four components connected by one protobuf contract:

- **Go server** (`janus-server`) — gRPC ingest (:9443) + HTTP/REST/WS API (:8080), PostgreSQL-backed, policy engine, orchestrator, HSM, sandbox simulator.
- **React dashboard** (`ui/`) — static SPA; nine tabs (Overview, CBOM, Compliance, Policy Studio, Migrations, Fleet Command, Agility, Wave Plans, LLM Analysis); dark mode, i18n (en/fa/zh/es), WCAG 2.1 AA.
- **Rust agent** (`janus-agent`) — endpoint scanner + active migration engine; passive by default; CLI `--once`, daemon, and `check` (CI gate) modes.
- **Interceptor** (`janus_interceptor`) — optional OpenSSL hook cdylib.

Delivery formats: portable copy-and-run bundles (server+UI zip, agent zip — Windows
and Linux), native Linux `.deb`/`.rpm` agent packages + server/UI tarballs, Docker
images, and a Helm chart. Release archives intentionally exclude credentials, signing
keys, TLS private keys, databases, logs, and generated endpoint identity/state.

The current capability posture is **Level 3** across most maturity dimensions
(see §9) — suitable for evaluation and controlled deployments. Row-level
multi-tenancy (WP-020) isolates tenant data across reads, the migration write
path, and real-time events, but the control plane is still single-replica
(no HA/failover) and lacks an external penetration test.

---

## 2. Deployment topologies

### 2.1 Single-server (Docker Compose)

```
+--------------------------+
|       Docker Host         |
|  janus-server :8080:9443  |
|  janus-agent  (passive)   |
|  postgres      :5432      |
+--------------------------+
```

### 2.2 Distributed HA

```
 Agent Fleet → Load Balancer → [Controller-A, Controller-B, Controller-C]
                                      ↓
                               pgpool-II / pgBouncer
                                      ↓
                          [PostgreSQL Primary → Replica]
```

> Note: HA/failover coordination is not yet release-verified — run multi-replica
> setups as evaluation deployments and validate failover in your environment.

### 2.3 Kubernetes (Helm)

The chart at `deploy/helm/janus/` ships a Deployment (server), DaemonSet (agent),
ConfigMap, Service, Ingress, PostgreSQL StatefulSet, and Secrets.

```bash
helm install janus ./deploy/helm/janus \
  --set server.replicaCount=3 \
  --set postgres.persistence.enabled=true \
  --set ingress.enabled=true \
  --set secrets.commandSigningKey=$(openssl rand -hex 32)
```

For Linux with privileged discovery disabled, use `values-passive-linux.yaml`. The
chart shares one security context between server and agent, so it does not ship an
elevated example (that would over-privilege the server).

---

## 3. Installation playbooks

### 3.1 Portable bundle (no package manager)

Unzip → edit `janus.env` → run the launcher. See the README inside each bundle.
- Server+UI: `run.ps1` / `run.sh` starts the API/gRPC server (it does **not** serve the UI — host `ui/` with any SPA-capable static server).
- Agent: `run.ps1` / `run.sh` renders `janus-agent.toml` from the template on first run, then launches the agent.

### 3.2 Docker Compose

The root `docker-compose.yml` is the canonical local deployment (and the one Linux
CI exercises). Internal ports HTTP 8080, gRPC 9443.

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment: { POSTGRES_USER: janus, POSTGRES_PASSWORD: janus, POSTGRES_DB: janus }
    ports: ["5432:5432"]
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U janus -d janus"] }
  janus-server:
    build: { context: ., dockerfile: server/Dockerfile }
    ports: ["8080:8080", "9443:9443"]
    environment:
      JANUS_DATABASE_URL: "postgres://janus:janus@postgres:5432/janus?sslmode=disable"
      JANUS_GRPC_ADDR: "0.0.0.0:9443"
      JANUS_HTTP_ADDR: "0.0.0.0:8080"
      JANUS_COMMAND_SIGNING_KEY: "change-me-32-byte-hex-key"
    depends_on: { postgres: { condition: service_healthy } }
  janus-agent:
    build: { context: ./agent, dockerfile: Dockerfile }
    volumes: ["./:/scan:ro", "agent-data:/data"]
    depends_on: [janus-server]
volumes: { janus-postgres: , janus-agent-data: }
```

### 3.3 Linux systemd

The packaged base service is the **supported passive profile**. Privileged modes
are opt-in drop-ins under `packaging/systemd/profiles/` (see §6).

```ini
[Unit]
Description=Janus CryptoBOM Endpoint Agent
After=network.target
[Service]
Type=simple
User=janusagent
WorkingDirectory=/var/lib/janus-agent
ExecStart=/usr/local/bin/janus-agent --config /var/lib/janus-agent/janus-agent.toml
Restart=on-failure
RestartSec=10
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/janus-agent/
[Install]
WantedBy=multi-user.target
```

### 3.4 Windows service

```powershell
.\scripts\install-agent-windows-service.ps1 `
  -AgentExe "D:\janus\bin\janus-agent.exe" `
  -ConfigPath "D:\janus\agent\janus-agent.example.toml" -Start
```

---

## 4. Settings reference

### 4.1 Server environment variables

`JANUS_COMMAND_SIGNING_KEY` is **required** — the server panics if it is unset.
Generate with `openssl rand -hex 32`. Use a different key per environment.

Settings resolve with precedence **environment variable > config file > built-in default**.
The config file (`JANUS_CONFIG_FILE`) is a `KEY=VALUE` file using these same keys; defaults are
the `Default*` constants in `server/internal/config`. A documented template ships at
`server/janus-server.env.example`. Secrets are better supplied via the `*_FILE` variants or real
env vars; if kept in the config file, restrict its permissions.

This precedence applies to **every** setting — including the HSM (`JANUS_HSM_*`) and
command-signing (`JANUS_COMMAND_SIG_*`) settings, which are resolved through the same
env > file > default chain — so a single config file can fully configure the server.

| Variable | Default | Purpose |
|---|---|---|
| `JANUS_CONFIG_FILE` | — | Path to a `KEY=VALUE` config file (env vars override it) |
| **`JANUS_COMMAND_SIGNING_KEY`** | **(required)** | 32-byte hex key for HMAC command signing + agent tokens (also signs JWTs unless `JANUS_JWT_SECRET` is set) |
| `JANUS_JWT_SECRET` | (= command key) | Separate signing key for dashboard session JWTs (AUTH-03); `_FILE` variant supported |
| `JANUS_DATABASE_URL` | `postgres://janus:janus@localhost:5432/janus?sslmode=disable` | PostgreSQL DSN |
| `JANUS_GRPC_ADDR` | `127.0.0.1:9443` | gRPC listen address |
| `JANUS_HTTP_ADDR` | `127.0.0.1:8080` | HTTP/REST/WS listen address |
| `JANUS_TLS_CERT_FILE` / `JANUS_TLS_KEY_FILE` | — | Enable TLS for gRPC (both required together) |
| `JANUS_CLIENT_CA_FILE` | — | Enable mTLS (client CA; empty allowed for dev) |
| `JANUS_REQUIRE_TLS` | `false` | Fail startup unless gRPC TLS cert+key are configured (AUTH-01) |
| `JANUS_REQUIRE_MTLS` | `false` | Fail startup unless a client CA is configured (implies `JANUS_REQUIRE_TLS`) |
| `JANUS_DISABLE_AUTH` | `false` | Skip JWT auth (dev only) |
| `JANUS_JWT_TTL` | `24h` | Access-token lifetime / session timeout (Go duration; clamped 5m–720h) |
| `JANUS_<ROLE>_PASSWORD` | — | Dev login password for `admin`/`operator`/`viewer` (hashed at startup; no compiled-in defaults) |
| `JANUS_<ROLE>_PASSWORD_HASH` | — | bcrypt hash for a role login (preferred over plaintext) |
| `JANUS_<ROLE>_USERNAME` | role name | Override the username for a role login |
| `JANUS_<ROLE>_TENANT` | `default` | Tenant a role login is scoped to (WP-020); rides in the JWT and filters all reads, the migration write path, and WS events. Manage tenants via `GET/POST /api/tenants`; map agents with `janus-server agent enroll --tenant <id>` |
| `JANUS_CORS_ORIGIN` | `http://localhost:5173` | Dashboard origin for CORS |
| `JANUS_API_RATE_LIMIT_PER_MIN` | `600` | Global per-client-IP REST rate limit (OPS-002); `0` disables. Auth endpoints keep a stricter 20/min. Raise/disable behind a shared proxy |
| `JANUS_NOTIFY_SLACK_WEBHOOK_URL` | — | Slack incoming webhook for critical-finding alerts (OPS-003) |
| `JANUS_NOTIFY_SMTP_ADDR` / `_FROM` / `_TO` | — | SMTP `host:port`, sender, comma-separated recipients (all three enable email alerts) |
| `JANUS_NOTIFY_SMTP_USERNAME` / `_PASSWORD` | — | Optional SMTP PLAIN auth |
| `JANUS_NOTIFY_PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API v2 routing key (enables PagerDuty alerts) |
| `JANUS_NOTIFY_MIN_SEVERITY` | `5` | Minimum severity (1–5) that triggers a notification |
| `JANUS_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `JANUS_DB_MAX_CONNS` / `JANUS_DB_MIN_CONNS` | `25` / `5` | Pool sizing |
| `JANUS_DB_MAX_CONN_LIFETIME` / `JANUS_DB_MAX_CONN_IDLE_TIME` | `30m` / `5m` | Pool connection ages |
| `JANUS_AGENT_STALL_SECONDS` | `300` | Stalled-agent detection threshold |
| `JANUS_GRPC_MAX_RECV_BYTES` | `33554432` (32 MiB) | gRPC max recv message size |
| `JANUS_GRACEFUL_SHUTDOWN_SECONDS` | `30` | Drain window on SIGTERM/SIGINT (clamped 1–300) |
| `JANUS_METRICS_ADDR` | — | Serve `/metrics` on a dedicated listener in addition to the main HTTP server |
| `JANUS_METRICS_TOKEN` | — | When set, `/metrics` requires it as a bearer token; otherwise `/metrics` is open |
| `JANUS_AGENT_AUTH_MODE` | `shared` | Agent→server auth: `shared` (legacy) or `per-agent` (per-agent HMAC keys + revocation, WP-029 P1) |
| `JANUS_AGENT_KEY_MASTER` / `_FILE` | — | Master key deriving per-agent keys; required when mode is `per-agent` |
| `JANUS_AGENT_AUTH_WINDOW_SECONDS` | `300` | Per-agent request-token freshness window (replay guard) |
| `JANUS_HSM_MODE` | `software` | HSM backend: `disabled` / `software` (in-process, real ML-DSA) / `pkcs11` (real token, fail-closed) |
| `JANUS_HSM_MODULE_PATH` | — | PKCS#11 module path (`pkcs11` mode) |
| `JANUS_HSM_TOKEN_LABEL` / `JANUS_HSM_SLOT` | — | Token selection by label (preferred) or slot id |
| `JANUS_HSM_PIN` / `JANUS_HSM_PIN_FILE` | — | Token user PIN (file variant preferred) |
| `JANUS_HSM_SIGN_COMMANDS` | `false` | Hold the migration-command signing key in the HSM (HMAC-SHA256 computed in the token) |
| `JANUS_HSM_COMMAND_KEY_LABEL` | `janus-command-signing` | HSM object label for the command key |
| `JANUS_LLM_BASE_URL` | — | LLM provider base URL (https; enables LLM features) |
| `JANUS_LLM_CAPABILITY_MODE` | `analysis_only` | `disabled` / `analysis_only` / `suggest_remediation` — active only when a base URL is set |
| `JANUS_LLM_API_KEY_FILE` | — | Path to a file holding the LLM API key (preferred) |
| `JANUS_LLM_API_KEY_ENV` | `JANUS_LLM_API_KEY` | Env var name holding the LLM API key |
| `JANUS_LLM_MODEL_ANALYSIS` / `JANUS_LLM_MODEL_REMEDIATION` | `gpt-4o-mini` / `gpt-4o` | Models for analysis / remediation |
| `JANUS_LLM_TIMEOUT_SECONDS` | `30` | LLM request timeout (5–300) |
| `JANUS_LLM_MAX_RETRIES` | `2` | LLM retries (0–5) |
| `JANUS_LLM_MAX_CONCURRENT` | `4` | LLM concurrent requests (1–32) |

### 4.2 Agent configuration (`janus-agent.toml`)

`command_signing_key` has **no default** — it must be set (shared with the server).
All invasive discovery modes are off by default.

```toml
controller_endpoint = "http://127.0.0.1:9443"
http_controller_endpoint = "http://127.0.0.1:8080"
execution_mode = "passive"          # passive | active
cache_path = "janus-agent.sqlite3"
host_uuid_path = "janus-host-id"
scan_interval_seconds = 900
max_file_bytes = 2097152            # 2 MiB (range 1 KiB–10 GiB)
max_binary_bytes = 16777216         # 16 MiB
max_command_age_seconds = 300       # reject migration commands older than this — replay guard (0 disables)
# command_pqc_fingerprint = "<64-hex>"  # optional ML-DSA trust anchor; must be empty or 64 hex chars
# agent_id  = "<uuid>"                # per-agent identity (WP-029 P1) from `janus-server agent enroll`
# agent_key = "<hex>"                 # per-agent HMAC key; sent to agent endpoints when server is per-agent mode
# plugin_signing_key = "<hex>"        # require signed plugin.toml.sig sidecars (SEC-02)

# REQUIRED — no fallback. Generate: openssl rand -hex 32
# On Windows may be a DPAPI blob ("dpapi:" prefix); on Linux prefer a key file.
command_signing_key = "your-32-byte-hex-key"

scan_roots = ["."]
exclude_dirs = [".git", "target", "node_modules", "dist", ".venv"]
network_targets = ["127.0.0.1:443"]
plugin_dirs = ["plugins"]
# plugin_signing_key = "<hex>"      # optional: require each plugin.toml to ship a valid
                                    # plugin.toml.sig (HMAC) or refuse to load it (SEC-02)
intercept_mode = "disabled"         # disabled | passive (log) | active (modify ciphers)

# Invasive modes — all default false:
enable_runtime_discovery = false
enable_process_memory_scraping = false   # also requires enable_runtime_discovery
enable_plugin_discovery = false
enable_active_tls_probing = false

[[plugin_commands]]
name = "windows-cng-capabilities"
command = "certutil"
args = ["-csplist"]
timeout_seconds = 20
max_memory_mb = 512
max_cpu_percent = 50

[active]
allowed_services = ["nginx", "apache", "ssh", "windows-trust-store", "windows-schannel-policy"]
allowed_config_roots = ["."]
backup_dir = ".janus-backups"
```

Agent logging is controlled by `RUST_LOG` (e.g. `RUST_LOG=debug`). On Linux,
provide `JANUS_CACHE_KEY_FILE` (≥32 bytes) for the SQLite cache key rather than
relying on the `/etc/machine-id` fallback. mTLS is configured via `tls_client_cert`
and `tls_client_key`.

---

## 5. Roles & user manual

Dashboard logins are env-configured (no compiled-in defaults — login is disabled
until a password or bcrypt hash is set per role). Three roles exist
(`viewer`/`operator`/`admin`), but **`RequireRole` enforcement is applied only to the
elevated routes below** — every other authenticated endpoint is reachable by any
logged-in user regardless of role:

| Action | Minimum role |
|---|---|
| Enqueue migrations; create / activate / cancel wave plans | operator |
| PQC CSR generation; HSM sign / verify | operator |
| LLM analyze / analyze-batch; run the agility-exercise harness | operator |
| Probe the LLM provider (`/api/llm/test-connection`); release-evidence check | admin |
| Everything else — view dashboards/exports, **triage finding status, author policies, edit fleet config / webhooks / retention, run dry-run simulations** | any authenticated user |

> **Hardening note:** policy authoring, fleet configuration, webhook/retention
> management, and finding-status changes are **not** role-gated today — any
> authenticated account can perform them. Scope who may authenticate accordingly;
> per-route role tightening is a tracked item (ARCHITECTURE.md §9.2).

**Passwords & sessions.** Logins start from env-configured bcrypt hashes
(`JANUS_<ROLE>_PASSWORD[_HASH]`). An authenticated user can change their own password
via `POST /api/auth/change-password` (current password required; 12-char minimum; no
reuse) — the new hash is persisted and supersedes the env hash, and the change
**invalidates that user's existing tokens**. Session lifetime is the JWT TTL
(`JANUS_JWT_TTL`, default 24h); there is no idle/inactivity timeout.

**Dashboard tabs (nine):** **Overview** (fleet stats, quantum-readiness score,
stalled agents, crypto-exposure graph), **CBOM** (paginated component catalog +
CycloneDX/CSV/SARIF exports), **Compliance** (NIST/CNSA assessment matrix +
exception workflow), **Policy Studio** (profile authoring + activation),
**Migrations** (enqueue, simulate, history), **Fleet Command** (agent inventory,
per-agent scan config, diagnostics), **Agility** (crypto-agility scorecard —
hardcode index, blast radius, negotiation coverage), **Wave Plans** (phased
migration planning with readiness checklist + dependency ordering), and **LLM
Analysis** (provider status, per-model usage/cost, analysis jobs — active only
when an LLM provider is configured). All data shown is scoped to the signed-in
user's tenant (WP-020).

**Typical workflows:** an *operator* triages critical/high findings → runs a dry-run
simulation → creates a wave plan → records approval → enqueues signed migrations and
watches the live status. By convention an *admin* manages policy profiles, fleet
config, webhooks, and retention (note: these are not yet role-restricted — see the
hardening note above). A *viewer* (auditor/CISO) reads the readiness score, compliance
matrix, and exports.

---

## 6. Platform support

Only **supported** entries are release targets; experimental entries must not be
presented as supported.

| Platform | Tier |
|---|---|
| Ubuntu Server 24.04 LTS, glibc, systemd, x86_64 | **Supported** (native, package/systemd, compose, browser, Helm, E2E, release evidence) |
| Ubuntu 24.04 LTS, arm64 | Experimental (native + arch-neutral Helm render only) |
| Debian 12 / RHEL 9 / musl / non-systemd / Podman | Unsupported |
| Windows 10/11, x86_64 | Supported (primary dev platform; portable agent + server zips, Windows service) |

The required Linux CI gate is `Linux Gate L0`. Pinned toolchains: Go 1.25.x,
Rust 1.96.0 (+ rustfmt, clippy), Node.js 22.x, protobuf 3.21.x, PostgreSQL 16.x.

**Linux privilege profiles.** The packaged base service is the supported passive
profile. To opt into a privileged mode under systemd, copy only the needed drop-in
from `packaging/systemd/profiles/` to `/etc/systemd/system/janus-agent.service.d/`,
enable the matching TOML flag, then `sudo systemctl daemon-reload && sudo systemctl
restart janus-agent`. `runtime-discovery.conf` exposes ptraceable `/proc` entries;
`process-memory.conf` additionally grants only `CAP_SYS_PTRACE` (and requires privacy
approval); `plugin-cgroup.conf` delegates only the `cpu`/`memory` cgroup v2 controllers
(plugin execution fails closed if limits can't be applied). Active migration and
interception are **unsupported on Linux** (no supported profile). Treat runtime/memory
results as incomplete unless deployment-specific denial tests prove visibility.

**Root provisioning (Ubuntu 24.04 dev host):**

```bash
apt-get update && apt-get install -y \
  build-essential ca-certificates clang cmake curl git jq make ninja-build rsync \
  openssl pkg-config protobuf-compiler shellcheck strace unzip xz-utils zip \
  libclang-dev libpq-dev libsqlite3-dev libssl-dev \
  postgresql-client-16 softhsm2 opensc
rustup toolchain install 1.96.0 --component clippy,rustfmt && rustup default 1.96.0
cd ui && npx playwright install --with-deps chromium     # browser tests
make bootstrap-check && make linux-gate                  # verify
```

Install Go, Rust, and Node from upstream (not Ubuntu's older packages). Docker group
membership grants root-equivalent daemon access — do not add untrusted users.

---

## 7. HSM setup

The HSM backend is **configurable** via `JANUS_HSM_MODE` and is **fail-closed**:

| Mode | Behavior |
|---|---|
| `disabled` | No HSM. `/api/hsm/*` return 501; migration-command signing stays in-process. |
| `software` (default) | In-process keystore. Asymmetric signing is **real ML-DSA (FIPS 204)** via `circl`; RSA/ECDSA are refused. Keys are process-local (lost on restart) — for dev/eval. |
| `pkcs11` | A real PKCS#11 token (SoftHSM2 or hardware). Startup **aborts** if the token can't be opened — there is no silent fallback to software. |

**Signatures are PQC-only.** Asymmetric HSM signing uses ML-DSA/SLH-DSA — never RSA or
ECDSA (Shor's algorithm breaks those). Migration-command signing uses HMAC-SHA256, a
quantum-resistant *symmetric* MAC (CNSA 2.0-accepted), and can be made **HSM-resident**
with `JANUS_HSM_SIGN_COMMANDS=true` so the command key never sits in server memory — the
MAC value and the agent's verification are unchanged.

**SoftHSM2 on Linux (with real ML-DSA):** SoftHSM2 only does ML-DSA when built against
OpenSSL 3.5+. The vendored source under `HSM/tools/SoftHSMv2-source` builds it; the helper
script provisions a token and prints the env (it prefers that PQC build, else the system
SoftHSM2 for HMAC-only):

```bash
eval "$(./scripts/hsm-softhsm-init.sh)"   # sets SOFTHSM2_CONF, JANUS_HSM_MODULE_PATH, label, pin, LD_LIBRARY_PATH
export JANUS_HSM_MODE=pkcs11
export JANUS_HSM_SIGN_COMMANDS=true        # optional: HSM-resident command signing
./bin/janus-server                          # pkcs11 mode; aborts if the token is unavailable
```

**SoftHSM2 on Windows (development):**

```powershell
.\HSM\setup-softHSM2.ps1            # inits a token under HSM/
$env:JANUS_HSM_MODE = "pkcs11"; $env:JANUS_HSM_MODULE_PATH = ".\HSM\bin\softhsm2.dll"
$env:JANUS_HSM_TOKEN_LABEL = "JanusTestToken"; $env:JANUS_HSM_PIN = "1234"
```

**Production HSM** — point `JANUS_HSM_MODULE_PATH` at your vendor PKCS#11 library
(e.g. Thales Luna `cryptoki.dll`, Utimaco `cs_pkcs11_R3.dll`, nCipher `cknfast.dll`) and
select the token with `JANUS_HSM_TOKEN_LABEL` or `JANUS_HSM_SLOT_INDEX`. REST operations:
`/api/hsm/keys` (list), `/api/hsm/keys/generate`, `/api/hsm/sign`, `/api/hsm/verify`
(operator/admin). For PQC asymmetric signing the token must support the ML-DSA mechanisms
(`CKM_ML_DSA*`).

The PKCS#11 client is built into the standard binary on both platforms — Janus treats any
module the same whether it's software, hardware, or a network HSM:
- **Windows**: a native `syscall`-based client (loads the DLL via `golang.org/x/sys/windows`),
  so the normal MSVC/Go build includes it — **no cgo, no mingw**.
- **Linux/macOS**: a cgo client (`miekg/pkcs11`); the system C compiler (the Go default)
  builds it. A deliberately static `CGO_ENABLED=0` Linux binary supports only
  `software`/`disabled` — build normally to include `pkcs11`.

To build a real ML-DSA-capable SoftHSM2 on Windows (the system SoftHSM lacks ML-DSA), run
`scripts\windows\build-hsm-deps.ps1` from a *x64 Native Tools Command Prompt for VS 2022*
(needs Strawberry Perl); it builds OpenSSL 3.5 + SoftHSMv2 (`-DENABLE_MLDSA=ON`) and inits
a token. On Linux, `scripts/hsm-softhsm-init.sh` does the equivalent.

### 7.1 Admin key-management CLI

The `janus-server` binary doubles as an admin CLI — no openssl or vendor tools needed:

```bash
janus-server gen-hmac-key                              # 32-byte hex HMAC command key (baseline)
janus-server hsm info   --module /usr/lib/softhsm/libsofthsm2.so   # list slots: INDEX, slot-id, token
janus-server hsm keygen --module ... --slot-index 0 --pin 1234 --algorithm ML-DSA-65
janus-server hsm pubkey --module ... --slot-index 0 --pin 1234 --label janus-command-mldsa
janus-server hsm list   --module ... --slot-index 0 --pin 1234
janus-server hsm rm     --module ... --slot-index 0 --pin 1234 --label NAME
```

Slots are selected by **index** (`--slot-index`, the 0-based position from `hsm info`),
not the raw slot id, which can be a huge number. `keygen`/`pubkey` print the public key and
its **SHA-256 fingerprint** (hex).

### 7.2 ML-DSA-signed migration commands (server signs, agents verify)

HMAC is the mandatory baseline. To add an asymmetric layer so a compromised agent cannot
forge commands:

1. On the server, generate the ML-DSA command key in the HSM and note its fingerprint:
   `janus-server hsm keygen --module ... --slot-index 0 --pin ... --label janus-command-mldsa`
2. Start the server with `JANUS_COMMAND_SIG_SCHEME=ml-dsa` (+ `JANUS_HSM_MODE=pkcs11` for a
   persistent key). The startup log prints the fingerprint to pin.
3. On each agent, set `command_pqc_fingerprint = "<hex fingerprint>"` in `janus-agent.toml`,
   delivered through your normal trusted config channel.

The agent then verifies HMAC **and** the ML-DSA signature, confirming the public key
embedded in the command matches the pinned fingerprint (TLS-cert-pinning model — the key
needs no secret channel). A fingerprint-pinned agent rejects any command without the
ML-DSA signature (downgrade-resistant). The agent's ML-DSA verification is pure Rust
(`fips204`), so it works on Linux and Windows with no extra dependencies.

**CA-chained command trust (`janus-sig-v2`, WP-029 P3).** Instead of pinning a single key
fingerprint, the command can carry the server's *leaf command certificate* (chained to an
ML-DSA Root CA). The agent bundles that root (`command_root_ca` in `janus-agent.toml`) and
verifies the leaf chains to it — so the signing key can rotate without re-pinning every
agent, and a command without a valid v2 envelope is rejected (downgrade-resistant). ML-DSA
X.509 issuance is pure Go (`cloudflare/circl`, `certmanager.IssueMLDSAChain`); the agent
verifies the chain with `x509-parser` + `fips204`. This is the trust anchor for command
*signing* — distinct from the ECDSA-P384 *transport* cert (§7.3), since Go's TLS stack
cannot serve ML-DSA.

Setup: `janus-server pki command-ca` generates the command Root CA + leaf + key. On the
controller set `JANUS_COMMAND_SIG_SCHEME=ml-dsa`, `JANUS_COMMAND_SIG_CERT_FILE=command.crt`,
and `JANUS_COMMAND_SIG_KEY_FILE=command.key` (the server validates the cert matches the key and
fails closed otherwise). Bundle `command-root-ca.crt` into the agent package and set
`command_root_ca` in `janus-agent.toml`. Keep `command-root-ca.key` offline.

**Revocation.** The supported strategy is short-lived command certificates: issue with a
short `--days` window and re-issue on a schedule — agents reject any leaf past its validity
(tested). Live OCSP/CRL revocation is not yet wired (the Rust OCSP crate is immature and the
agent's TLS stack does not expose CRL injection); short validity is the interim posture.

### 7.3 One-way TLS with a bundled Root CA (WP-029 P2)

`janus-server pki init` issues a self-signed **Root CA** plus a **leaf server certificate**
so the controller can serve gRPC + HTTP over TLS and agents validate it against a bundled
trust anchor (no public CA, no fingerprint pinning):

```bash
janus-server pki init --cn janus.example.com \
  --dns janus.example.com,controller.internal --ip 10.0.0.5 \
  --alg ECDSA-P384 --out ./pki
# writes: root-ca.crt (agent trust anchor) · root-ca.key (keep offline)
#         server.crt + server.key (controller TLS)
```

- **Algorithm:** `ECDSA-P384` (default, CNSA 2.0 transitional, issued in-process) or
  `ML-DSA-65` / `ML-DSA-87` (FIPS 204, requires **OpenSSL 3.5+** on the host — the command
  fails with a clear error otherwise, since Go's stdlib X.509 cannot sign ML-DSA yet).
- **Controller:** set `JANUS_TLS_CERT_FILE=./pki/server.crt` and
  `JANUS_TLS_KEY_FILE=./pki/server.key`.
- **Agent:** bundle `root-ca.crt` into the agent package and set `tls_ca_cert` (and an
  `https://` `controller_endpoint` / `http_controller_endpoint`) in `janus-agent.toml`. The
  agent validates the server cert chain against this root on **both** the gRPC channel and
  the HTTP endpoints (config, scan-command, heartbeat, diagnostics). Keep `root-ca.key`
  offline — it is only needed to issue more certs.

This is the server→agent transport trust anchor; it composes with the per-agent HMAC
identity (§ agent→server auth) and the optional ML-DSA command signatures above.

---

## 8. Crypto-agility scorecard

Measures how cheaply the fleet can swap any algorithm — a property of architecture,
not of the algorithm in use. Computed over persisted findings (no re-scan) by
`server/internal/agility/scorecard.go`; surfaced at `GET /api/agility/scorecard`
(fleet aggregate + per-host).

| Metric | Target | Meaning |
|---|---|---|
| **HardcodeIndex** | < 5% | Fraction of findings whose asset is a source file (call sites needing a code change to migrate) |
| **NegotiationCoverage** | > 90% | Fraction of services that can negotiate algorithms without a redeploy |
| **BlastRadiusScore** | lower better | Normalized count of distinct assets using the most-widespread algorithm |
| **TTSA** | < 30 d planned / < 7 d emergency | Wall-clock from profile change to ≥99% fleet compliance |
| **ProfileAdoptionLatency** | < 14 d | Days from policy switch to the last in-scope finding remediated |

**Maturity levels** (`computeMaturity`, both conditions strict, highest tier first):

| Level | Name | HardcodeIndex | NegotiationCoverage |
|---|---|---|---|
| 4 | crypto_agile | < 0.02 | > 0.90 |
| 3 | agile | < 0.05 | > 0.80 |
| 2 | planned | < 0.20 | > 0.60 |
| 1 | reactive | < 0.50 | > 0.20 |
| 0 | none | otherwise / no findings | — |

`top_blast_radius` identifies the highest-concentration algorithms — migrate those
first. Read maturity as a **trend, not a grade**: a single Level-0 snapshot is an
inventory signal, not a condemnation. Improve HardcodeIndex via provider abstraction
(JCA/CNG/PKCS#11/Tink-style APIs) and NegotiationCoverage via configurable cipher-group
TLS termination.

> Implementation note: the scorecard computes `NegotiationCoverage` from finding data
> only (no service-discovery counts are passed in), so it reads 0.0 and the maturity
> level derived from it stays low. A separate per-adapter **negotiation harness**
> (`/api/agility/exercise`, also folded into the scorecard response) populates a
> `negotiation` field and a labeled **TTSA estimate**; `ProfileAdoptionLatency` is
> filled only when a policy-switch timestamp is supplied. Read the current scorecard
> primarily through its HardcodeIndex and blast-radius signals.

---

## 9. Capability maturity framework

Five dimensions; overall maturity is the **minimum across all five** — one weak
dimension bounds the program. No feature is "supported" without passing its release
gates.

| # | Dimension | Measures | Current status |
|---|---|---|---|
| 1 | Discovery Coverage | breadth + precision of detection | **Level 3** (regex source + binary + dependency + network, directive-aware config parsing, confidence floors, published precision/recall corpus; Level 4 needs full multi-language AST + field FP budget) |
| 2 | Assessment Accuracy | confidence in severity/compliance | **Level 2–3** (CNSA/NIST rules, context-aware severity, ConfidenceAnalyzer, schema-validated LLM triage; Level 4 needs versioned signed control packs + independent corpus) |
| 3 | Agility Metrics | measure + act on agility | **Level 3** (all five metrics, per-adapter negotiation harness, dashboard; Level 4 needs live end-to-end drills + CRQC-deadline TTSA) |
| 4 | Migration Safety | correctness + reversibility | **Level 3** (HMAC + atomic rollback, sandbox simulation, wave state machine + readiness checklist, dependency-graph gating; Level 4 needs canary execution automation + golden repos) |
| 5 | LLM Trustworthiness | authority-inversion enforcement | **Level 3** when enabled — all 8 invariants, immutable provenance, abstention, opt-in binary policy, schema-validated remediation suggestions with deterministic patch validation (human approval always required), request/token budget enforcement, an injection-defense test suite + labeled regression corpus (`server/internal/llm/testdata`). Level 4 needs published precision/recall from a live-provider run over that corpus. **Level 4 if LLM is disabled** (the safest config). |

**Reversibility classification** (Level 3+): config changes are reversible (backup is
the rollback); certificate issuance is semi-reversible; root-key destruction or
signed-artifact publication is irreversible and requires m-of-n approval with
proposer ≠ approver ≠ key custodian.

**Advancing:** to Level 2 — signing key set, a policy profile loaded, multi-source
scans active. To Level 3 — scheduled scans, confidence stored, ≥2 sensor classes on
≥85% of the estate, `analysis_only` LLM with all invariants verified, at least one
wave plan + dry run, one planned-swap game-day with recorded TTSA. To Level 4 —
published FP-budget corpus, signed control packs, canary automation, LLM eval gate,
annual emergency-swap game-day with dormant dual-control SLH-DSA root keys.

**Assessment cadence:** metrics recompute every scan; weekly regression review;
per-policy-switch and per-wave-close-out re-scoring; quarterly governance-board review;
recalibration on every LLM model-pin change; annual emergency-swap game-day + external
review; immediate re-score on any incident. Outputs are archived as signed evidence —
maturity is a continuously updated, auditable view, not a point-in-time certificate.

---

## 10. Migration wave planning

A **wave plan** groups assets + algorithm targets into a named, sequenced batch to
reduce blast radius: Wave 1 proves the rollout pattern on representative assets before
later waves touch critical ones. Sequence by QRisk (data lifetime + migration lead
time vs the CRQC horizon) and blast radius. **Wave plans do not drive automated
execution** — they are coordination/audit artifacts; actual changes still go through
HMAC-signed `MigrationCommand`s with human approval.

**Lifecycle** (terminal states have no outbound transitions):

```
planned ── activate ─► active ── complete ─► completed (terminal)
   │                      │
   └─ cancel ─► cancelled └─ cancel ─► cancelled (terminal)
```

Only `planned`/`cancelled` waves may be deleted; a `completed` wave is a permanent,
undeletable audit record. There is no pause state — an active wave in difficulty must
be cancelled.

**Create** via `POST /api/waves` (operator/admin): `name` (non-empty), `wave_number`
(≥1), optional `description`, `asset_ids[]`, `algorithm_targets[]`, `start_date`,
`target_date` (not before start). The server enforces exactly those three validation
rules; `asset_ids`/`algorithm_targets` are operator-populated and not server-validated.
`PUT /api/waves/{id}` changes status only; `DELETE` honors the deletion constraints.
Every create/status-change/delete writes an audit log entry.

**Pre-activation readiness checklist** (surfaced under `checklist` in `GET /api/waves`):

1. All in-scope assets have a completed discovery scan.
2. Critical/high findings reviewed and triaged.
3. Dry-run simulation (`POST /api/sandbox/simulate`) passed for a representative asset.
4. Rollback plan documented (config inverse + tested atomic rollback; dual-validity windows for cert/key changes).
5. Stakeholder/governance approval recorded in the audit log (separation of duties for key/anchor/protocol-default changes).
6. Monitoring alerts configured (negotiation-failure rate, downgrade events, handshake-latency p99, error-class delta).

**Execution flow:** discovery → wave planning → simulation → human approval → wave
activation (records intent) → enqueue HMAC-signed commands → agent applies
(backup → write → validate → reload → TLS verify → auto-rollback) → wave close-out
when all in-scope findings are confirmed remediated and monitoring is clean. The safety
gates operate independently of wave status and are never bypassed by activation.

---

## 11. Interoperability reference

Shipped profile targets: `nist-pqc-2026.1` → X25519MLKEM768 / ML-DSA-65;
`cnsa-2.0` → ML-KEM-1024 / ML-DSA-87; `custom-enterprise` → X25519 / ECDSA-P256.

**Key/signature sizes (bytes):** ML-KEM-768 pk 1184 / ct 1088; ML-KEM-1024 pk 1568 /
ct 1568; X25519MLKEM768 pk 1216 / ct 1120; ML-DSA-65 pk 1952 / sig 3309; ML-DSA-87
pk 2592 / sig 4627; SLH-DSA-128s pk 32 / sig 7856; X25519 32/32; ECDSA-P256 64/72.

**Library/adapter support (highlights):** OpenSSL 3.5+ native for ML-KEM/ML-DSA/SLH-DSA
and X25519MLKEM768; OpenSSL 3.3/3.4 via oqs-provider; rustls 0.23+ via oqs; BoringSSL
ships X25519MLKEM768 to Chrome/Android; OpenSSH 9.9+ `mlkem768x25519-sha256`; Go via
cloudflare/circl; **Windows SChannel has no hybrid TLS group (as of 2025-08)** — treat
Windows TLS endpoints as a compensating-control case and migrate at the reverse proxy.

**Known failure modes & mitigations:**

| Failure mode | Mitigation |
|---|---|
| ClientHello fragmentation (hybrid key shares exceed one packet) | Verify path MTU + middlebox behavior; fall back to classical group on failure |
| Silent downgrade to classical | Assert the negotiated group post-handshake (agent `verify_post_migration`) |
| Library/provider group-ID mismatch | Pin the IANA codepoint (X25519MLKEM768 = 0x11EC) on both ends |
| Oversized ML-DSA certificate chains | Stage PQC leaf + classical intermediate; validate against target clients first |
| SChannel lacks a hybrid group | Migrate at nginx/apache reverse proxy instead |

**Adapter certification checklist:** target negotiates against a reference peer →
negotiated group asserted post-handshake → rollback exercised → cert chain validates
on the client set → handshake-size increase within MTU/middlebox tolerance → §failure
modes reviewed.

---

## 12. Use cases & case studies

Twelve production playbooks spanning passive compliance, active migration, HSM, and
observability:

| # | Scenario | Core technology |
|---|---|---|
| 1 | Passive CI/CD compliance check | CLI `check` → SARIF upload + compliance gate |
| 2 | Host certificate-store audit | certutil/PowerShell, CNSA curve checks |
| 3 | Open listening-socket discovery | Socket API / `ss`, FHE library detection |
| 4 | Fleet TLS policy sweeping | Schannel registry mutator, profile-aware targets |
| 5 | Shadow crypto-DLL auditing | symbol audit + side-channel detection |
| 6 | Supply-chain OSV.dev sync | OSV API, CVSS parsing, confidence thresholds |
| 7 | Nginx PQC migration with rollback | sandbox simulation, runtime interception |
| 8 | Schannel policy failover rollback | registry backup, regex DWORD parsing |
| 9 | Memory scraping for plaintext keys | ReadProcessMemory / `/proc/PID/mem` PEM headers |
| 10 | Remote CA root rotation | PowerShell + ML-DSA, HSM signing |
| 11 | HSM-protected key lifecycle | PKCS#11 / SoftHSM2 full lifecycle |
| 12 | Real-time fleet observability | WebSocket hub, structured logging, i18n |

**Selected detail:**

- **CI gate (1):** `janus-agent check ./src --format sarif --output janus-findings.sarif` (exit 0 clean, 1 on findings; scans source + binary + dependencies). Upload via `github/codeql-action/upload-sarif`, or `./scripts/janus-ci.sh ./src --fail-on critical`.
- **Side-channel detection (5):** `discovery/sidechannel.rs` flags secret-dependent branches (CRITICAL), non-constant-time MAC/hash comparison (HIGH), secret-indexed table lookups (MEDIUM), ciphertext equality (LOW).
- **OSV severity (6):** CVSS → Janus level — 9.0+ Critical, 7.0–8.9 High, 4.0–6.9 Medium, 0.0–3.9 Low.
- **Sandbox simulation (7):** `POST /api/sandbox/simulate` returns recommended KEM/signature, a unified-diff patch, impact estimate, and validation checklist — no execution.
- **Memory scan (9, Linux):** reads `/proc/PID/maps` then `/proc/PID/mem` via `pread` for PEM private-key headers (PKCS#8/RSA/EC/DSA/OpenSSH).

---

## 13. Observability & maintenance

### 13.1 Logging

- **Server:** JSON via `log/slog`; level `JANUS_LOG_LEVEL`.
- **Agent:** JSON via `tracing`; level `RUST_LOG`.
- **SIEM:** `GET /api/export/siem` streams JSON-lines; webhook dispatch has a circuit breaker (3 retries, 5-failure → 60 s cooldown); audit export at `GET /api/export/audit?format=csv`.

### 13.2 Real-time & metrics

- **WebSocket** `ws://HOST:8080/api/ws`: `telemetry_update`, `finding_status`, `migration_enqueued`, `migration_status`, `policy_switched`, `lab_simulation`. 15 s ping keepalive; UI falls back to 10 s polling.
- **Prometheus** `GET /metrics`: `janus_assets_total`, `janus_components_total`, `janus_findings_total`, `janus_critical_findings_total`, `janus_high_findings_total`, `janus_open_migrations_total`, plus LLM usage (`janus_llm_calls_total`, `janus_llm_tokens_total`, `janus_llm_avg_latency_ms`, `janus_llm_jobs_total` — by model/status), HTTP request counters + latency histogram, webhook-dispatch outcomes + dispatch-duration summary, migration-duration summary (by terminal state), and DB-pool gauges.
- **Agent health:** 5 s heartbeats carry scan progress, CPU, memory, phase; agents with `last_seen > JANUS_AGENT_STALL_SECONDS` count as stalled in `/api/overview`. The diagnostics buffer is capped and cleared after successful upload.
- **Quantum-readiness score** (`/api/overview` + compliance report): `100 − (critical×18 + high×8 + stalled×15) + remediation_bonus`.

### 13.3 Maintenance routines

- **DB schema** upgrades run automatically on server start (`EnsureSchema`, transactional). Take a PostgreSQL backup before upgrading the server binary.
- **Agent queue:** encrypted payloads persist in SQLite until acknowledged; `VACUUM` runs every 24 h. No automatic TTL — monitor queue depth (failed uploads accumulate).
- **Retention:** the server imposes no default retention — apply PostgreSQL-level policies (e.g. `pg_cron`) sized to your compliance needs. Use `GET/POST /api/retention` for managed purge.
- **Secret rotation:** rotating `JANUS_COMMAND_SIGNING_KEY` invalidates buffered commands signed with the old key (they fail HMAC and are rejected) — drain or re-issue. Rotate LLM keys on the secret schedule; recalibrate on any model-pin change.
- **Wiping agent data:** delete the SQLite cache file; the agent recreates schema on next start.

### 13.4 Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Server exits immediately at startup | `JANUS_COMMAND_SIGNING_KEY` unset — it is required, no default |
| Agent refuses to start | `command_signing_key` empty in TOML/`janus.env` — set it (`openssl rand -hex 32`) |
| `503` from `/api/llm/analyze` (or other `/api/llm/*`) | LLM disabled (`JANUS_LLM_BASE_URL` unset) — expected unless LLM features are enabled |
| Dashboard can't reach API (CORS) | Set `JANUS_CORS_ORIGIN` to the origin hosting `ui/` |
| Agent shows offline | Heartbeat older than `JANUS_AGENT_STALL_SECONDS`; check network path to the HTTP endpoint |
| gRPC bind error "address in use" | Another server is on :9443; stop it or change `JANUS_GRPC_ADDR` |
| PQC migration "downgraded to classical" | Peer lacks the hybrid group — assert post-handshake; see §11 failure modes |
| Runtime/memory scan returns little on Linux | Needs the privileged profile + capability (`CAP_SYS_PTRACE`); results are incomplete otherwise |

---

## 14. Versioning & release artifacts

`VERSION.env` is the canonical release contract. Component manifests use the base
SemVer `JANUS_VERSION`; release builds append `+YYMMDD.sequence` for display and use
`-YYMMDD.sequence` in artifact names. Increment `JANUS_BUILD_SEQUENCE` for every build
published on the same date.

Compatibility is independent of product version: `JANUS_API_VERSION` is exposed at
`/api/health`; `JANUS_UI_REQUIRED_API_VERSION` is compiled into the UI (it rejects a
mismatched server); `JANUS_AGENT_PROTOCOL_VERSION` / `JANUS_AGENT_MIN_SERVER_VERSION`
describe agent/server compatibility.

**Build artifacts:**
- Linux: `make release-linux` → server+UI and portable-agent tarballs, native DEB/RPM agent packages, and SHA-256 checksums under `dist/packages/`.
- Windows: `win-build.bat package` or `.\win-build.ps1 -Package` → equivalent server+UI and agent ZIPs.
- Portable copy-and-run bundles: `make portable` (Linux) / MSBuild `Portable` target (Windows) → `dist/portable/`.

Release archives intentionally exclude credentials, signing keys, TLS private keys,
databases, logs, and generated endpoint identity/state.

### CI/CD integration

```yaml
# .github/workflows/janus-scan.yml
- uses: actions/checkout@v4
- run: janus-agent check . --format sarif --output janus-findings.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: janus-findings.sarif }
```

---

*Technical/architecture details: **[ARCHITECTURE.md](ARCHITECTURE.md)**. Fast install:
**[QUICKSTART.md](QUICKSTART.md)**.*
