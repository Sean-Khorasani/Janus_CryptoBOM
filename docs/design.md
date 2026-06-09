# Janus CryptoBOM System Design Manual

This document provides the technical blueprint for Janus CryptoBOM, an enterprise post-quantum cryptographic posture management and automated migration suite.

---

## 1. Core System Architecture

```
+----------------------------------------------------------------------------------+
|                                  React SPA (ui/)                                 |
|  Dark mode · i18n (en/fa/zh/es) · WCAG 2.1 AA · WebSocket real-time             |
+----------------------------------------------------------------------------------+
                                         |
                                         | HTTPS REST + WebSocket
                                         v
+----------------------------------------------------------------------------------+
|                     Go REST & gRPC Controller (server/)                          |
|  slog JSON logging · JWT auth · Rate limiting · WebSocket hub · Circuit breaker |
+----------------------------------------------------------------------------------+
                     |                                           |
                     | PostgreSQL (pgxpool)                      | gRPC over TLS 1.3
                     v                                           v
+----------------------------------------+   +-------------------------------------+
|      PostgreSQL Database (store/)      |   |     Rust Endpoint Agent (agent/)    |
|  Versioned migrations (v1-v9)          |   |  reqwest HTTP · tracing · dpapi     |
|  Connection pool (configurable)        |   |  Side-channel detection (F16)       |
+----------------------------------------+   |  FHE library detection (F23)        |
                                             |  Runtime TLS interception (F5)     |
                                             +-------------------------------------+
```

### 1.1 Go Server — Package Layout

| Package | Purpose |
|---------|---------|
| `cmd/janus-server/` | Entrypoint, signal handling, server orchestration |
| `internal/config/` | Environment config with validation (14 vars) |
| `internal/store/` | PostgreSQL persistence, versioned migrations (v1-v9), connection pooling |
| `internal/grpcserver/` | gRPC handler, webhook dispatch with circuit breaker, WS broadcasts |
| `internal/httpapi/` | REST API, JWT auth, CORS, rate limiting, feature endpoints |
| `internal/policy/` | NIST/CNSA policy assessment, OSV.dev integration, confidence analysis |
| `internal/orchestrator/` | HMAC-signed migration command queuing, profile-aware targets |
| `internal/certmanager/` | PQC CSR generation (ML-DSA, SLH-DSA, ECDSA) |
| `internal/ws/` | WebSocket hub — stdlib-only RFC 6455, event broadcasting |
| `internal/hsm/` | PKCS#11 HSM integration — syscall-based loader, SoftHSM2 mock |
| `internal/sandbox/` | PQC migration simulator — dry-run preview without execution |
| `internal/pb/` | Generated protobuf types |

### 1.2 React SPA

- **Vite + React 19 + TypeScript** — type-safe component architecture
- **Tailwind CSS** — utility-first styling with `dark:` variant support
- **Lucide React** — vector iconography
- **i18n** — 4 locales (English, Persian, Chinese, Spanish) via React context
- **a11y** — FocusTrap, SkipLink, A11yAnnouncer, keyboard navigation
- **WebSocket** — real-time updates at `/api/ws`

### 1.3 Rust Agent — Module Layout

| Module | Purpose |
|--------|---------|
| `main.rs` | CLI with `--once`, daemon, and `check` subcommand (now source+binary+deps) |
| `config.rs` | TOML config with plugin loading, `intercept_mode`, resource limits |
| `discovery/source.rs` | Static source analysis, comment/string stripping, LLM intent, FHE patterns |
| `discovery/binary.rs` | PE/ELF/Mach-O import/export symbol scanning |
| `discovery/dependency.rs` | 8 package managers + 8 FHE libraries |
| `discovery/network.rs` | TLS probing with STARTTLS, X.509 DER parsing |
| `discovery/runtime.rs` | Process memory scanning (Windows + Linux) |
| `discovery/windows.rs` | certutil, netsh, reg, PowerShell output parsing |
| `discovery/plugin.rs` | External plugins with cgroups/Job object resource limits |
| `discovery/sidechannel.rs` | Timing side-channel vulnerability detection (8 patterns) |
| `discovery/cbom.rs` | CycloneDX v1.6 renderer |
| `comms.rs` | gRPC telemetry + HTTP heartbeat with watch::channel shutdown |
| `mutation.rs` | Active migration engine with regex reg parsing, atomic rollback |
| `storage.rs` | SQLite with DPAPI (Win) / AES-CTR (Linux), scan_state diffing, periodic VACUUM |
| `policy.rs` | Offline assessment for `check` subcommand |
| `interceptor.rs` | OpenSSL TLS cipher/group hook injection (active/passive modes) |

---

## 2. Database Schema

### Versioned Migrations

| Version | Description |
|---------|-------------|
| v1 | Initial schema: assets, telemetry_payloads, crypto_findings, migration_transactions |
| v2 | Finding status/metadata columns (status, updated_by, confidence) |
| v3 | Asset telemetry columns (scan_progress, cpu_usage, mem_usage, status) |
| v4 | Fleet management tables (fleet_configs, config_profiles, agent_profile_mappings) |
| v5 | Audit, diagnostics, webhooks, retention tables |
| v6 | Advanced settings table (JSONB) |
| v7 | Webhook failure tracking columns |
| v8 | Finding outcomes table (confidence feedback) |
| v9 | Advisory cache table |

### Key Tables

**assets** — Registered agents with heartbeat telemetry
**telemetry_payloads** — Raw CBOM telemetry as JSONB
**crypto_findings** — Deduplicated findings (UNIQUE on asset_ref, algorithm, policy_rule_id)
**migration_transactions** — Migration command lifecycle tracking
**schema_version** — Migration history

---

## 3. API Reference

### HTTP REST (Port 8080)

All endpoints require Bearer token unless `JANUS_DISABLE_AUTH=true`.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | DB connectivity check |
| POST | `/api/auth/login` | JWT token issuance |
| GET | `/api/overview` | Fleet stats + readiness score + stalled agents |
| GET | `/api/assets` | Agent inventory with heartbeat data |
| GET | `/api/components` | Paginated CBOM catalog (`?limit=&offset=&search=`) |
| GET | `/api/findings` | Paginated findings (`?limit=&offset=&search=&sort=&order=`) |
| PUT | `/api/findings/{id}/status` | Update finding status (WS broadcast) |
| GET | `/api/migrations` | Migration history |
| POST | `/api/migrations/enqueue` | Enqueue signed migration (operator/admin) |
| GET/POST | `/api/policies` | List/create policy profiles |
| POST | `/api/policies/active` | Switch active profile (WS broadcast) |
| GET/POST | `/api/fleet/config` | Fleet configuration |
| GET/POST/DELETE | `/api/fleet/profiles` | Config profile CRUD |
| GET/POST | `/api/fleet/profiles/mapping` | Agent-to-profile mappings |
| GET/POST/DELETE | `/api/webhooks` | SIEM webhook management |
| GET/POST | `/api/retention` | Data retention + manual purge |
| GET | `/api/audit-logs` | Operator audit trail |
| GET | `/api/export/audit?format=csv` | Audit log export |
| GET/POST | `/api/agent/diagnostics` | Agent diagnostics |
| POST | `/api/agent/heartbeat` | Agent heartbeat telemetry |
| GET | `/api/agent/upgrade` | Agent version + download info |
| POST | `/api/certificates/csr` | PQC CSR generation |
| POST | `/api/llm/proxy` | LLM API proxy |
| POST | `/api/sandbox/simulate` | PQC migration sandbox simulation (F1) |
| GET | `/api/confidence/report` | Finding confidence analysis (F7) |
| POST | `/api/lab/simulate` | PQC lab algorithm migration preview (F9) |
| GET | `/api/sla/metrics` | Crypto health SLA dashboard (F10) |
| GET | `/api/report/compliance` | HTML compliance report (F4) |
| GET | `/api/hsm/keys` | List HSM keys (F13) |
| POST | `/api/hsm/keys/generate` | Generate HSM key pair (F13) |
| POST | `/api/hsm/sign` | Sign with HSM key (F13) |
| POST | `/api/hsm/verify` | Verify HSM signature (F13) |
| GET | `/api/export/cyclonedx` | CycloneDX v1.6 CBOM |
| GET | `/api/export/csv` | CSV findings |
| GET | `/api/export/sarif` | SARIF v2.1.0 |
| GET | `/api/export/siem` | JSON-lines SIEM stream |
| GET | `/metrics` | Prometheus metrics |
| WS | `/api/ws` | WebSocket real-time events |

### gRPC Service (Port 9443)

Defined in `proto/janus.proto`. Service `JanusTelemetry`:
- `RegisterAgent` — Agent registration with capability negotiation
- `StreamTelemetry` — Bidirectional stream: agent → CBOM payloads, server → MigrationCommands
- `ReportMigrationStatus` — Agent reports migration outcomes

---

## 4. Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| **`JANUS_COMMAND_SIGNING_KEY`** | **(required)** | 32-byte hex key for JWT + HMAC (panics if unset) |
| `JANUS_DATABASE_URL` | `postgres://janus:janus@localhost:5432/janus?sslmode=disable` | PostgreSQL connection |
| `JANUS_GRPC_ADDR` | `127.0.0.1:9443` | gRPC listen address |
| `JANUS_HTTP_ADDR` | `127.0.0.1:8080` | HTTP/WS listen address |
| `JANUS_TLS_CERT_FILE` | — | TLS certificate (enables TLS for gRPC) |
| `JANUS_TLS_KEY_FILE` | — | TLS private key |
| `JANUS_CLIENT_CA_FILE` | — | Client CA for mTLS |
| `JANUS_DISABLE_AUTH` | `false` | Skip JWT (dev only) |
| `JANUS_CORS_ORIGIN` | `http://localhost:5173` | Dashboard origin |
| `JANUS_LOG_LEVEL` | `info` | debug/info/warn/error |
| `JANUS_DB_MAX_CONNS` | `25` | Pool max connections |
| `JANUS_DB_MIN_CONNS` | `5` | Pool min connections |
| `JANUS_DB_MAX_CONN_LIFETIME` | `30m` | Connection lifetime |
| `JANUS_DB_MAX_CONN_IDLE_TIME` | `5m` | Idle timeout |
| `JANUS_AGENT_STALL_SECONDS` | `300` | Stall detection threshold |
| `JANUS_HSM_MODULE_PATH` | — | PKCS#11 module path (F13) |
| `JANUS_HSM_PIN` | — | HSM user PIN |

---

## 5. Security Architecture

### Command Signing
Migration commands signed with HMAC-SHA256 using `JANUS_COMMAND_SIGNING_KEY`. Both server and agent require this key — no default fallback.

### Webhook Circuit Breaker
3 retries with exponential backoff (1s, 2s, 4s). Circuit opens after 5 consecutive failures to a URL → 60s cooldown.

### Secret Storage
- **Windows:** DPAPI (`CryptProtectData`/`CryptUnprotectData`)
- **Linux:** AES-CTR with machine-identity-derived key (SHA-256 keystream XOR)
- **Server:** LLM API keys encrypted via AES-256-GCM in PostgreSQL

### CORS
Origin-restricted to `JANUS_CORS_ORIGIN`. Wildcard `*` only when `JANUS_DISABLE_AUTH=true`.

### Rate Limiting
Configurable per-endpoint rate limiting middleware (sliding window, Retry-After header).

### Plugin Sandboxing
External plugins run with OS-enforced resource limits:
- **Linux:** cgroups v2 (`memory.max`, `cpu.max`)
- **Windows:** `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`

---

## 6. Policy Engine

### Profiles
YAML files in `policies/`:
- `nist-pqc-2026.1`: RSA≥3072, DH≥3072, TLS 1.3, hybrid PQC, X25519MLKEM768, ML-DSA-65
- `cnsa-2.0`: RSA≥3072, DH≥3072, TLS 1.3, hybrid PQC, ML-KEM-1024, ML-DSA-87 + CNSA-specific rules
- `custom.yaml`: Enterprise-defined thresholds

Each profile supports `minimum_confidence` (default 0.4) for finding filtering (F28).

### CNSA 2.0 Rules
- **JANUS-CNSA-001:** ECDSA curves below P-384 → HIGH
- **JANUS-CNSA-002:** SHA-256 for hash operations → MEDIUM
- **JANUS-CNSA-003:** AES-128 for symmetric encryption → HIGH

### Context-Aware Severity
- `verify`/`parse` usage: -2 severity levels
- `negotiate` usage: -1 severity level
- `protect` usage: no adjustment

---

## 7. Document References
- [Deployment Guide](deployment.md) — HA topologies, systemd/GPO/Docker/Helm
- [Case Studies](case_studies.md) — 12 production playbooks
- [Competitive Analysis](competitive-analysis.md) — 10-competitor comparison
- [Feature Inventory](feature-inventory.md) — 32-feature status tracking
- [Main README](../README.md) — Overview, quickstart, API reference
