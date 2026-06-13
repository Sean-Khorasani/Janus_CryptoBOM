# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Janus CryptoBOM is an enterprise post-quantum cryptographic posture management platform. It discovers legacy cryptography across codebases, binaries, network services, and OS trust stores; assesses quantum readiness against NIST FIPS 203/204/205 and CNSA 2.0; and orchestrates safe, HMAC-signed, atomic migrations to PQC.

## Build & Run Commands

### Prerequisites (Linux gate)

```bash
make bootstrap-check   # Verifies go, cargo, rustfmt, npm, docker, shellcheck, protoc are present
make linux-gate        # Full CI gate: bootstrap-check + fmt-check + lint + proto-check + test + compose-check
```

### Windows (primary development platform)

```powershell
# Full build (bootstraps portable Go+Rust toolchains locally if needed)
msbuild JanusCryptoBOM.msbuild.proj /t:Build

# Full build using system-installed Go, Rust, and npm
msbuild JanusCryptoBOM.msbuild.proj /t:BuildNoTools

# End-to-end validation (requires PostgreSQL)
.\scripts\test-e2e-windows.ps1 -SkipBuild

# Run the server (JANUS_COMMAND_SIGNING_KEY is REQUIRED — no default)
$env:JANUS_DATABASE_URL="postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable"
$env:JANUS_GRPC_ADDR="127.0.0.1:9443"
$env:JANUS_HTTP_ADDR="127.0.0.1:8080"
$env:JANUS_COMMAND_SIGNING_KEY="<32-byte-hex-key>"
# Dashboard credentials are env-configured (no compiled-in defaults). Set a
# password per role you need (or a bcrypt hash via JANUS_<ROLE>_PASSWORD_HASH).
$env:JANUS_ADMIN_PASSWORD="<admin-password>"
.\bin\janus-server.exe

# Run the agent (CI gate — exits 0 if clean, 1 with findings)
.\bin\janus-agent.exe check ./path/to/code

# Run the agent (single scan)
.\bin\janus-agent.exe --config .\agent\janus-agent.example.toml --once

# Run the agent in daemon mode
.\bin\janus-agent.exe --config .\agent\janus-agent.example.toml
```

### Unix (Linux/macOS)

```bash
make build      # Compile everything (UI + Server + Agent), no tests
make test       # Build + run all tests (ui → server → agent)
make ui         # npm ci && npm run build (injects VITE_JANUS_VERSION from VERSION.env)
make server     # go test ./... && go build ./cmd/janus-server
make agent      # cargo test --locked --all-targets && cargo build --locked --release
make vuln       # Dependency vulnerability scan (govulncheck + cargo audit + npm audit)
```

### Running a single test

```bash
# Go — run a specific package's tests
cd server && go test ./internal/policy/...
cd server && go test -run TestAssessCNSA ./internal/policy/...

# Rust — run a specific test or module
cd agent && cargo test discovery::source
cd agent && cargo test -- --nocapture scan_crypto_patterns
```

### Linting and formatting

```bash
make fmt-check  # gofmt check (Go) + cargo fmt --check (Rust)
make lint       # go vet (Go) + cargo clippy -D warnings (Rust) + shellcheck (scripts)
make proto-check  # Verifies generated protobuf files match proto/janus.proto
```

### Database

```bash
# Docker PostgreSQL
docker compose up -d postgres

# Manual setup
# CREATE ROLE janus WITH LOGIN PASSWORD 'janus';
# CREATE DATABASE janus OWNER janus;
```

### UI dev server

```bash
cd ui
npm install && npm run dev   # http://127.0.0.1:5173, proxies API to :8080
```

## Versioning

`VERSION.env` is the canonical release contract. Build scripts, MSBuild, and `make` all source it. Go server binaries inject version/build info via `-ldflags -X` from this file. Agent reads `JANUS_BUILD_DATE`, `JANUS_BUILD_SEQUENCE`, and `JANUS_AGENT_PROTOCOL_VERSION` env vars at cargo build time.

## Environment Variables (Server)

| Variable | Default | Purpose |
|---|---|---|
| `JANUS_DATABASE_URL` | `postgres://janus:janus@localhost:5432/janus?sslmode=disable` | PostgreSQL connection |
| `JANUS_GRPC_ADDR` | `127.0.0.1:9443` | gRPC listen address |
| `JANUS_HTTP_ADDR` | `127.0.0.1:8080` | HTTP/REST/WS listen address |
| `JANUS_TLS_CERT_FILE` | (empty) | Enable TLS for gRPC |
| `JANUS_TLS_KEY_FILE` | (empty) | Required with TLS_CERT_FILE |
| `JANUS_CLIENT_CA_FILE` | (empty) | Enable mTLS (allow empty for dev) |
| **`JANUS_COMMAND_SIGNING_KEY`** | **(required — no default)** | 32-byte hex key for JWT + HMAC signing |
| `JANUS_DISABLE_AUTH` | `false` | Skip JWT auth (dev only) |
| `JANUS_<ROLE>_PASSWORD` | (empty) | Dev login password for `admin`/`operator`/`viewer` (hashed at startup). No compiled-in defaults (S1) |
| `JANUS_<ROLE>_PASSWORD_HASH` | (empty) | bcrypt hash for a role login (preferred over plaintext) |
| `JANUS_<ROLE>_USERNAME` | role name | Override the username for a role login |
| `JANUS_CORS_ORIGIN` | `http://localhost:5173` | Dashboard origin for CORS |
| `JANUS_LOG_LEVEL` | `info` | Structured log level (debug/info/warn/error) |
| `JANUS_DB_MAX_CONNS` | `25` | PostgreSQL pool max connections |
| `JANUS_DB_MIN_CONNS` | `5` | PostgreSQL pool min connections |
| `JANUS_DB_MAX_CONN_LIFETIME` | `30m` | Max connection lifetime |
| `JANUS_DB_MAX_CONN_IDLE_TIME` | `5m` | Max connection idle time |
| `JANUS_AGENT_STALL_SECONDS` | `300` | Stalled agent detection threshold |
| `JANUS_GRPC_MAX_RECV_BYTES` | `33554432` (32 MiB) | gRPC max recv message size |
| `JANUS_GRACEFUL_SHUTDOWN_SECONDS` | `30` | Drain window on SIGTERM/SIGINT (clamped 1–300): health reports `draining`, new HTTP requests get 503, gRPC streams + webhooks drain |
| `JANUS_LLM_BASE_URL` | (empty) | LLM provider base URL (https required; enables LLM features) |
| `JANUS_LLM_API_KEY_FILE` | (empty) | Path to file containing the LLM API key (takes precedence) |
| `JANUS_LLM_API_KEY_ENV` | `JANUS_LLM_API_KEY` | Env var name holding the LLM API key |
| `JANUS_LLM_MODEL_ANALYSIS` | `gpt-4o-mini` | Model used for finding analysis |
| `JANUS_LLM_MODEL_REMEDIATION` | `gpt-4o` | Model used for remediation suggestions |
| `JANUS_LLM_TIMEOUT_SECONDS` | `30` | LLM request timeout (5–300) |
| `JANUS_LLM_MAX_RETRIES` | `2` | LLM request retries (0–5) |
| `JANUS_LLM_MAX_CONCURRENT` | `4` | LLM concurrent requests (1–32) |

Agent structured logging is controlled by `RUST_LOG` env var (e.g. `RUST_LOG=debug`).

## High-Level Architecture

Four layers connected via a single protobuf contract (`proto/janus.proto`):

### 1. Protobuf Contract (`proto/janus.proto`)

Service `JanusTelemetry` with three RPCs:
- `RegisterAgent` — agent registration with capability negotiation
- `StreamTelemetry` — **bidirectional stream**: agent pushes CBOM payloads, server pushes signed `MigrationCommand`s
- `ReportMigrationStatus` — agent reports migration outcomes (stream → single ack)

Key types: `CbomTelemetryPayload`, `MigrationCommand` (HMAC-signed), `CryptoFinding`, `NetworkObservation`, `Evidence`.

Regenerate Go/Rust bindings after editing the proto: `make proto-check` verifies they match.

### 2. Go Server (`server/`, entry: `server/cmd/janus-server/main.go`)

Starts a gRPC server (default :9443) and HTTP/WS server (default :8080). Uses structured JSON logging via `log/slog`.

**Package layout:**
- `server/internal/config/` — All config from env vars. Validates `JANUS_COMMAND_SIGNING_KEY` is set (panics on empty). Includes DB pool config, CORS origin, log level, stall threshold.
- `server/internal/store/` — PostgreSQL persistence behind a `Store` interface with **versioned schema migrations**. `EnsureSchema()` runs pending migrations transactionally. `advanced_settings` table (JSONB) for admin-configurable values. Add new migrations to the `migrations` slice in `store.go`.
- `server/internal/grpcserver/` — gRPC handler. On telemetry ingest, runs `policy.Assess()`, persists to DB, dispatches critical-finding webhooks with **circuit breaker** (3-retry exponential backoff, 5-failure cooldown), drains migration commands. Broadcasts `telemetry_update` and `migration_status` to WebSocket hub.
- `server/internal/httpapi/` — REST API consumed by the React dashboard. JWT auth (HS256). **CORS restricted** to configurable origin, includes DELETE method. **Paginated components endpoint** (`?limit=&offset=&search=`). Finding status endpoint syncs to DB with WebSocket broadcast. Migration enqueue uses active policy profile values for KEM/signature targets. LLM proxy forwards to OpenAI or generates offline remediation patches. `createPolicy` validates version against path traversal (sanitized to `[a-zA-Z0-9._-]`).
- `server/internal/policy/` — Policy engine loading YAML profiles from `policies/`. **OSV severity parsing** maps actual CVSS scores to Janus levels. **CNSA 2.0 assessment** (`assessCNSA`): flags ECDSA <P-384, SHA-256, AES-128. Context-aware severity adjustment for verify/parse/negotiate usage.
- `server/internal/orchestrator/` — Migration command queuing. `BuildCommand` takes `preferredKEM` and `preferredSignature` from active profile (no hardcoded defaults). HMAC-SHA256 signing.
- `server/internal/sandbox/` — Dry-run migration simulation (`Simulator`). Generates patch, impact estimate, validation checklist, and warnings without executing anything. Used by the `/api/migrations/simulate` endpoint.
- `server/internal/certmanager/` — PQC CSR generation (ML-DSA, SLH-DSA, ECDSA-P384) via OpenSSL or Go crypto.
- `server/internal/hsm/` — HSM interface (`HSM`) with PKCS#11 implementation via SoftHSM2 (Windows syscall-based) and a software fallback. Key operations: `ListKeys`, `Sign`, `Verify`, `GenerateKeyPair`.
- `server/internal/scanconfig/` — Canonical scan parameter schema (defaults and min/max limits for scan interval and file size limits). Consumed by fleet config endpoints.
- `server/internal/ws/` — **WebSocket hub** with stdlib-only RFC 6455 implementation. Broadcasts JSON events for `telemetry_update`, `finding_status`, `migration_enqueued`, `migration_status`, `policy_switched`. 15-second ping keepalive. Mounted at `/api/ws`.
- `server/internal/version/` — Version constants injected at build time via `-ldflags -X`. `version.Full()` formats the release string.
- `server/internal/pb/` — Generated Go protobuf types.

### 3. Rust Agent (`agent/`, entry: `agent/src/main.rs`)

Dual-binary crate: `janus-agent` (CLI daemon) and `janus_interceptor` (cdylib for DLL injection).

**Module layout:**
- `agent/src/main.rs` — CLI with `--once` (single scan) and `check` subcommand (CI gate — source + binary + dependency scanning). Heartbeat loop uses `watch::channel` for **graceful shutdown** in `--once` mode. Policy assessment only runs locally when generating reports.
- `agent/src/config.rs` — TOML config with plugin system. **`command_signing_key` has no default** — must be set. Supports DPAPI/encrypted key prefixes. Plugin configs include `max_memory_mb` (default 512) and `max_cpu_percent` (default 50).
- `agent/src/discovery/` — Scan pipeline:
  - `source.rs` — Regex-based crypto API detection with **comment/string stripping** state machine. Optional LLM intent classification. **Path-component exclusion matching** (directory name equality, not substring). Pattern-based auto-remediation patch generation.
  - `binary.rs` — PE/ELF/Mach-O import/export table inspection.
  - `dependency.rs` — Package manifest parsing for npm, Go, Python, Rust, Maven. **Deduplicated** crypto package list.
  - `network.rs` — TLS handshake probing with STARTTLS support (SMTP, LDAP, PostgreSQL, MySQL). Custom X.509 DER parser for certificate chain analysis.
  - `runtime.rs` — Process metadata scanning. **Linux**: reads `/proc/PID/maps` → `/proc/PID/mem` via `pread` for PEM private key headers. **Windows**: `ReadProcessMemory` + `VirtualQueryEx`.
  - `sidechannel.rs` — Static source analysis for side-channel / constant-time violation patterns (e.g. secret-dependent branches, timing leaks). Returns `CryptoFinding` results like other discovery modules.
  - `windows.rs` — certutil, netsh, reg, PowerShell command output parsing for Windows crypto posture.
  - `cbom.rs` — CycloneDX v1.6 renderer.
  - `plugin.rs` — External plugin command runner with **resource limits**: cgroups v2 (Linux) for memory.max/cpu.max, `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (Windows).
  - `status.rs` — Shared atomic scan progress state, self-test diagnostics, dynamic fleet config exclusions.
- `agent/src/comms.rs` — gRPC client (tonic) with optional mTLS. HTTP heartbeat (5s) pushes scan progress, CPU/memory, diagnostics (cleared after successful POST). Fleet config exclusions fetched dynamically.
- `agent/src/mutation.rs` — Active migration engine. HMAC signature verification. File extension allowlist. **Regex-based registry DWORD parsing** (locale-independent). `verify_post_migration` TLS handshake check. Atomic rollback on failure.
- `agent/src/storage.rs` — SQLite offline queue. Windows: DPAPI encryption. **Non-Windows**: AES-CTR with machine-identity-derived key. **`scan_state` table** for content-hash-based scan diffing. **Periodic VACUUM** (24-hour interval).
- `agent/src/policy.rs` — Offline policy assessment (used by `check` subcommand only).
- `agent/src/report.rs` — HTML and SARIF report generation.
- `agent/src/interceptor.rs` — OpenSSL `EVP_EncryptInit`/`EVP_EncryptInit_ex` hook cdylib.

### 4. React Dashboard (`ui/`)

Vite + React + TypeScript + Tailwind SPA. Entry: `ui/src/main.tsx`.
- **Dark mode**: CSS custom properties with `[data-theme='dark']` selector. Tailwind `darkMode: ['selector', '[data-theme="dark"]']`.
- **Real-time**: `useWebSocket` hook on `/api/ws`. 10s polling as fallback.
- **Finding status sync**: `PUT /api/findings/{id}/status` with optimistic UI update and failure revert.
- **Components pagination**: `?limit=&offset=&search=&sort=` params with `X-Total-Count` header.
- Six tabs: Overview, CBOM, Compliance Matrix, Policy Studio, Migrations, Fleet Command.

### Agent-Server Communication Flow

1. Agent registers via gRPC `RegisterAgent`
2. Agent collects telemetry (all scan stages) → enqueues to encrypted SQLite
3. Agent calls `StreamTelemetry` bidirectional stream → pushes payloads, receives `MigrationCommand`s
4. For each command: validate HMAC sig → backup → apply patch → validate → reload → TLS verify → rollback on failure
5. Agent reports status via `ReportMigrationStatus`
6. HTTP heartbeats every 5s with scan progress, CPU/mem, phase, diagnostics
7. Agent fetches fleet config exclusions dynamically
8. Server broadcasts updates to WebSocket clients

### Safety Model

Active migration is **off by default** (`passive` mode). All mutation commands require:
- HMAC-SHA256 signature verification against shared `command_signing_key`
- Path traversal sandboxing (`allowed_config_roots`)
- File extension allowlist (`.conf`, `.config`, `.json`, `.toml`, `.yaml`, `.xml`)
- Atomic rollback: backup → write → validate → reload → TLS verify → auto-restore
- Config drift detection via SHA-256 checksum comparison

### Policy Profiles

YAML files in `policies/` directory. Active profile selected via HTTP API or UI.
- `nist-pqc-2026.yaml`: RSA ≥3072, DH ≥3072, TLS 1.3, hybrid PQC, X25519MLKEM768, ML-DSA-65
- `cnsa-2.0.yaml`: RSA ≥3072, DH ≥3072, TLS 1.3, hybrid PQC, **ML-KEM-1024**, **ML-DSA-87** + CNSA-specific rules
- `custom.yaml`: Enterprise-defined thresholds

### Key Design Decisions

- **`JANUS_COMMAND_SIGNING_KEY` is required at startup** — server panics if unset, agent validates non-empty. Generate with `openssl rand -hex 32`.
- **Policy assessment is server-authoritative** — agent only assesses offline for `check` subcommand and local reports
- **Schema migrations are versioned** — add new migrations to the `migrations` slice in `store.go`
- **Webhook dispatch has circuit breaker** — 3 retries, 5 failures → 60s cooldown
- **CORS is origin-restricted** — not wildcard in production
- **Secrets are encrypted at rest** — DPAPI on Windows, AES-CTR on Linux, encrypt/decrypt helpers for Go
- **Diagnostics buffer cleared after upload** — no unbounded growth or retransmission
- **VACUUM runs every 24 hours** — not every scan
- **Path exclusions use component matching** — not substring matching
- **Protobuf bindings are checked into the repo** — `make proto-check` fails if they drift from `proto/janus.proto`
- **Version is injected at build time** — never hardcode version strings; use `server/internal/version` package or read from `VERSION.env`
