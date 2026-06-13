# Janus CryptoBOM: Enterprise Post-Quantum Cryptographic Posture Management & Migration Suite

Janus CryptoBOM is an enterprise post-quantum cryptographic posture management (PQC-PM), discovery, and automated migration platform. It enables organizations to discover legacy cryptographic vulnerabilities, assess quantum readiness, align with emerging standards, and orchestrate safe, automated migrations to Post-Quantum Cryptography (PQC).

---

## Table of Contents
- [Executive Briefing: The Post-Quantum Business Risk](#executive-briefing-the-post-quantum-business-risk)
- [The Janus Value Proposition](#the-janus-value-proposition)
- [Enterprise Dashboard Previews](#enterprise-dashboard-previews)
- [Direct Comparison Matrix](#direct-comparison-matrix)
- [Competitive Analysis & Strategic Roadmap](#competitive-analysis--strategic-roadmap)
- [Platform Architecture](#platform-architecture)
- [Building from Source](#building-from-source)
- [Quickstart & Running Instructions](#quickstart--running-instructions)
- [Safety Model & Security Controls](#safety-model--security-controls)
- [Platform Support & Windows Coverage](#platform-support--windows-coverage)
- [Observability & Real-Time Updates](#observability--real-time-updates)
- [API Reference](#api-reference)
- [License](#license)

---

## Executive Briefing: The Post-Quantum Business Risk

### The Quantum Threat (Shor's Algorithm)
Symmetric and asymmetric encryption form the bedrock of trust for modern enterprise infrastructure. However, the development of cryptanalytically relevant quantum computers (CRQCs) threatens to dismantle this foundation. Shor's algorithm demonstrates that a quantum computer of sufficient scale will solve prime factorization and discrete logarithms in polynomial time, rendering legacy public-key cryptosystems — including RSA, Diffie-Hellman, ECDH, and ECDSA — completely obsolete.

### Harvest Now, Decrypt Later (HNDL)
This threat is not futuristic; it is active today. Hostile state actors and sophisticated syndicates are executing "Harvest Now, Decrypt Later" (HNDL) operations. Adversaries intercept and store encrypted enterprise and government communications today, waiting to decrypt them once quantum computers reach sufficient capability.

### Regulatory Alignment (NIST FIPS 203/204/205 + CNSA 2.0)
Global standards are rapidly adapting to enforce PQC transition timelines:
- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) for key establishment.
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for digital signatures.
- **NIST FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) for digital signatures.
- **CNSA 2.0**: Mandates ML-KEM-1024, ML-DSA-87, AES-256, SHA-384 minimums, and P-384 minimum for ECDSA.

Janus supports both NIST PQC 2026.1 and CNSA 2.0 compliance profiles, with CNSA-specific assessment rules that flag insufficient curves, hash algorithms, and symmetric ciphers.

---

## The Janus Value Proposition

1. **Post-Quantum Cryptographic Posture Management (PQC-PM)**: Complete visibility across codebases, compiled binaries, OS trust stores, network protocol suites, and process memory footprints.
2. **Context-Aware Semantic Intent Analysis**: AST-based semantic analysis distinguishes active cryptographic protection from legacy verification-only paths, reducing SOC alert fatigue. Optional LLM-powered intent classification provides higher confidence.

   > **Experimental (not production-ready):** LLM intent classification requires a separately configured OpenAI-compatible provider (`JANUS_LLM_API_KEY` / `JANUS_LLM_API_URL`). When no provider is configured the agent falls back to offline heuristics only. LLM-generated results are proposals requiring human review and must not be used as the sole basis for production remediation decisions.
3. **Automated Sandboxed Migration**: Signed, atomic migration directives with automated backup, validation, reload, TLS verification, and rollback.

---

## Enterprise Dashboard Previews

### Centralized CISO Fleet Safety Dashboard
Real-time posture reporting with aggregated Fleet Safety Scores, active monitored assets, real-time cryptographic vulnerability alerts, and overall NIST FIPS / CNSA compliance index.

![Centralized CISO Fleet Safety Dashboard](docs/images/dashboard_preview_1780620392773.png)

### Interactive Crypto Exposure Graph & Live Scan Status
Interactive Crypto Exposure Graph maps host-to-host and component-to-component cryptographic dependencies. Below the graph, the active scanning status banner displays client-side telemetry throughput and queue status.

![Interactive Crypto Exposure Graph & Live Scan Status](docs/images/dashboard_preview_1780512832245.png)

---

## Direct Comparison Matrix

| Competitor / Suite | Discovery Mode | Network Sweep | Cert Management | Active Migration | Memory Scraping | EDR Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Janus CryptoBOM** | **Yes** (Source, binary, dependencies, configurations) | **Yes** (Agent-based + agentless network socket + STARTTLS probing) | **Yes** (Schannel, Java TrustStore, Windows certutil/CAPI/CNG) | **Yes** (Atomic with HMAC-signed directives, validation, reload, rollback) | **Yes** (Windows ReadProcessMemory + Linux /proc/PID/mem) | **High** (Whitelisting recommended for active mode) |
| **PQCA CBOMkit** | **Yes** (Source via SonarQube) | **No** | **No** | **No** | **No** | **None** |
| **cdxgen** | **Yes** (Source + dependency SCA) | **No** | **No** | **No** | **No** | **None** |
| **QRAMM CSNP** | **Yes** (CLI source for 50+ algos) | **Yes** (TLS-Analyzer active sweep) | **No** | **No** | **No** | **Low** |
| **SandboxAQ AQtive Guard** | **Yes** (Source, filesystem, binary) | **Yes** (Cloud/network sensors) | **No** | **Partial** (Config alerts) | **Yes** (Runtime env inspection) | **Medium** |
| **Keyfactor AgileSec** | **Partial** (Weak key detection) | **Yes** (Network/endpoint scanner) | **Yes** (Certificate lifecycle) | **Yes** (PKI upgrade, hybrid certs) | **No** | **Low-Medium** |
| **IBM zCDI** | **No** | **Yes** (Mainframe network analysis) | **Partial** (Audit log aggregation) | **No** | **No** | **None** |
| **Thales PQC Agility** | **No** | **No** | **Yes** (HSM + KM connectors) | **Partial** (HSM key transitions) | **No** | **Low** |

---

## Competitive Analysis & Strategic Roadmap

A comprehensive competitive analysis of 10 enterprise PQC platforms (SandboxAQ, Keyfactor, IBM, Thales, PQShield, QuSecure, Crypto4A, DigiCert, Entrust, ISARA/Cisco) plus open-source alternatives is maintained in **[docs/competitive-analysis.md](docs/competitive-analysis.md)**.

Key findings:
- **Janus has the broadest discovery surface** (7 modalities vs. max 4 for competitors)
- **Only platform with HMAC-signed safe migration** with atomic rollback
- **Only open-source PQC posture management platform** (Apache 2.0)
- **Only platform with process memory private key detection** (Windows + Linux)
- 24 prioritized feature recommendations across 4 tiers to extend the lead

---

## Platform Architecture

Janus CryptoBOM is divided into four main layers connected via a single protobuf contract:

- **React SPA Dashboard (`ui/`)**: TypeScript SPA using React, Tailwind CSS, and CSS custom properties for light/dark theming. Provides real-time posture monitoring via WebSocket, policy configuration, migration orchestration, fleet management, and advanced settings.
- **Go Server (`server/` and `cmd/janus-server/`)**: Control plane managing agent registration, CBOM telemetry aggregation over gRPC, policy evaluation against PostgreSQL, migration command queuing with HMAC-signed directives, REST API with JWT authentication, WebSocket hub for real-time updates, structured logging via `log/slog`, and SIEM webhook dispatch with circuit breaker and retry logic.
- **Rust Endpoint Agent (`agent/`)**: High-performance daemon running on Windows, Linux, and macOS. Executes scheduled passive scans (source, binary, dependency, runtime memory, Windows registry, plugin), generates CycloneDX v1.6 CBOM outputs, enforces resource limits on plugins via cgroups/Job objects, and executes signed active mutation instructions with atomic rollback.
- **Protobuf Contracts (`proto/janus.proto`)**: Canonical definitions of the bidirectional streaming gRPC protocol linking agents to the server, with cryptographically signed directives for secure control transactions.

### Internal Server Packages
| Package | Purpose |
|---|---|
| `server/internal/config/` | Environment-based configuration with validation |
| `server/internal/store/` | PostgreSQL persistence with versioned schema migrations, connection pooling |
| `server/internal/grpcserver/` | gRPC handler for agent telemetry and webhook dispatch |
| `server/internal/httpapi/` | REST API with JWT auth, CORS control, paginated endpoints |
| `server/internal/policy/` | Policy engine with NIST/CNSA profiles, OSV.dev vulnerability queries |
| `server/internal/orchestrator/` | HMAC-signed migration command queuing |
| `server/internal/certmanager/` | PQC CSR generation (ML-DSA, SLH-DSA, hybrid) |
| `server/internal/pb/` | Generated protobuf types |
| `server/internal/ws/` | WebSocket hub for real-time dashboard updates |

### Agent Module Layout
| Module | Purpose |
|---|---|
| `agent/src/main.rs` | CLI entry with `--once`, daemon, and `check` subcommand |
| `agent/src/config.rs` | TOML-based configuration with plugin manifest loading |
| `agent/src/discovery/source.rs` | Static source analysis with comment/string stripping, LLM intent classification (experimental — requires configured provider) |
| `agent/src/discovery/binary.rs` | PE/ELF/Mach-O import/export symbol scanning |
| `agent/src/discovery/dependency.rs` | Package manifest parsing (npm, Go, Python, Rust, Maven) |
| `agent/src/discovery/network.rs` | TLS handshake probing (SMTP/LDAP/PgSQL/MySQL STARTTLS) |
| `agent/src/discovery/runtime.rs` | Process memory scanning (Windows + Linux private key detection) |
| `agent/src/discovery/windows.rs` | Windows cert store, Schannel, CNG, GPO, HTTP.sys inspection |
| `agent/src/discovery/plugin.rs` | External plugin execution with resource limits |
| `agent/src/comms.rs` | gRPC telemetry streaming + HTTP heartbeat with shutdown signal |
| `agent/src/mutation.rs` | Active migration engine with HMAC verification, atomic rollback |
| `agent/src/storage.rs` | SQLite offline store with DPAPI (Windows) / AES-CTR (Linux) encryption |
| `agent/src/policy.rs` | Offline policy assessment for `check` subcommand |
| `agent/src/interceptor.rs` | OpenSSL function hooking cdylib for DLL injection |

---

## Building from Source

### Prerequisites
- **Go 1.21+** (for building the server)
- **Rust & Cargo** (for building the agent)
- **Node.js v18+ & npm** (for building the dashboard)
- **MSBuild** or **make** (based on operating system)

### Windows Build (via MSBuild)
From a Visual Studio 2022 Developer PowerShell or Developer Command Prompt:

1. **Standard Build** (bootstraps portable Go and Rust toolchains locally):
   ```powershell
   msbuild JanusCryptoBOM.msbuild.proj /t:Build
   ```
2. **System Toolchain Build** (uses system-installed Go, Rust, npm):
   ```powershell
   msbuild JanusCryptoBOM.msbuild.proj /t:BuildNoTools
   ```

Built binaries: `bin/janus-server.exe`, `bin/janus-agent.exe`, `bin/janus_interceptor.dll`, `bin/janus-cli.exe`. Static frontend: `ui/dist`.

End-to-end testing:
```powershell
.\scripts\test-e2e-windows.ps1 -SkipBuild
```

### Linux & macOS Build (via Makefile)
```bash
make test       # Build everything (UI + Server + Agent)
make ui         # npm install && npm run build
make server     # go mod tidy && go test ./... && go build
make agent      # cargo test && cargo build --release
```

---

## Quickstart & Running Instructions

### 1. Database Setup (PostgreSQL)

#### Option A: Local Setup
```sql
CREATE ROLE janus WITH LOGIN PASSWORD 'janus';
CREATE DATABASE janus OWNER janus;
GRANT ALL PRIVILEGES ON DATABASE janus TO janus;
```
Ensure `pg_hba.conf` allows password authentication from localhost.

#### Option B: Docker
```bash
docker compose -f docker-compose.yml up -d postgres
```

### 2. Launching the Go Server

**Required environment variables:**
```powershell
$env:JANUS_DATABASE_URL="postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable"
$env:JANUS_GRPC_ADDR="127.0.0.1:9443"
$env:JANUS_HTTP_ADDR="127.0.0.脸上:8080"
$env:JANUS_COMMAND_SIGNING_KEY="<32-byte-random-hex-key>"
```

**Optional configuration:**
```powershell
# Logging
$env:JANUS_LOG_LEVEL="debug"            # info, debug, warn, error

# Database pool
$env:JANUS_DB_MAX_CONNS=25
$env:JANUS_DB_MIN_CONNS=5

# CORS
$env:JANUS_CORS_ORIGIN="https://dashboard.example.com"

# TLS/mTLS
$env:JANUS_TLS_CERT_FILE="./certs/server.crt"
$env:JANUS_TLS_KEY_FILE="./certs/server.key"
$env:JANUS_CLIENT_CA_FILE="./certs/ca.crt"

# Auth
$env:JANUS_DISABLE_AUTH="false"

# Agent stall detection
$env:JANUS_AGENT_STALL_SECONDS=300

# LLM integration (experimental — not required for core operation)
# Enables optional intent classification in the agent and the /api/llm/proxy endpoint.
# Results are proposals; require human review before acting on them.
$env:JANUS_LLM_API_KEY="sk-..."
$env:JANUS_LLM_API_URL="https://api.openai.com/v1"

# Run
.\bin\janus-server.exe
```

**Important:** `JANUS_COMMAND_SIGNING_KEY` has no default fallback — the server will refuse to start if unset. Generate with `openssl rand -hex 32`.

### 3. Deploying the Rust Agent

1. Copy and customize the configuration:
   ```powershell
   copy .\agent\janus-agent.example.toml .\janus-agent.toml
   # Edit: set command_signing_key, controller_endpoint, scan_roots
   ```
2. Run a single scan (CI-friendly gate):
   ```powershell
   .\bin\janus-agent.exe check ./path/to/code    # exit 0 if clean, exit 1 with findings
   ```
3. Run one full scan cycle and sync:
   ```powershell
   .\bin\janus-agent.exe --once
   ```
4. Run as daemon (continuous monitoring):
   ```powershell
   .\bin\janus-agent.exe
   ```
5. Install as Windows service:
   ```powershell
   .\scripts\install-agent-windows-service.ps1 -Start
   ```

### 4. Running the Dashboard

```bash
cd ui
npm install
npm run dev        # Starts on http://127.0.0.1:5173, proxies API to :8080
```
Production build: `npm run build` → static output in `ui/dist/`.

---

## Safety Model & Security Controls

1. **Explicit Opt-in**: Agent runs passive-only unless `execution_mode = "active"` in `janus-agent.toml`.
2. **No Default Secrets**: `JANUS_COMMAND_SIGNING_KEY` is required at server startup (no fallback). Agent config also validates key presence.
3. **Cryptographic Directives**: All active mutation commands are validated against the `signed_directive` field using HMAC-SHA256.
4. **Sandbox Whitelisting**: Path traversal protection restricts config alterations to approved paths (`allowed_config_roots`) with file extension allowlisting.
5. **Atomic Rollbacks**: Every migration executes inside a transaction: backup → write → validate → reload → TLS verify → auto-restore on failure.
6. **Encrypted Storage**: Agent offline queue encrypted via Windows DPAPI or AES-CTR (Linux). LLM API keys encrypted at rest in PostgreSQL.
7. **Webhook Resilience**: Critical finding webhook dispatch uses 3-retry exponential backoff with circuit breaker (5 consecutive failures → 60s cooldown).
8. **Session Security**: JWT authentication with configurable expiry. CORS restricted to configured dashboard origin. Auth-disabled mode only for local development.
9. **Plugin Sandboxing**: External plugins run with OS-enforced resource limits (cgroups v2 on Linux, Job objects on Windows).

---

## Platform Support & Windows Coverage

Janus provides deep integrations for Microsoft Windows:
- **Windows Certificate Stores**: Discovery using `certutil` and PowerShell bindings.
- **Crypto Abstraction Parsing**: Active CNG and CryptoAPI (CAPI) provider mapping via `certutil -csplist`.
- **HTTP.sys SSL Binding Sweeps**: Active HTTPS binding inspection via `netsh http show sslcert`.
- **Schannel Registry Enforcements**: Parsing and updating `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`.
- **DPAPI Data Shielding**: Windows Data Protection API for encrypting local configuration secrets and telemetry.
- **Process Memory Scanning**: `ReadProcessMemory` for unencrypted private key detection in running processes.

Linux coverage:
- `/proc/PID/maps`-based memory region enumeration
- `/proc/PID/mem` reading via `pread` for PEM private key detection
- `/etc/machine-id`-based encryption key derivation
- cgroups v2 resource limits for plugin execution

---

## Observability & Real-Time Updates

### Structured Logging
- **Server**: `log/slog` with JSON handler. Configurable via `JANUS_LOG_LEVEL` (debug, info, warn, error).
- **Agent**: `tracing` crate with JSON output. Configurable via `RUST_LOG` env.
- **SIEM Export**: `/api/export/siem` endpoint streams compliance findings as JSON lines.
- **Prometheus Metrics**: `/metrics` endpoint exposes asset/finding/migration gauges.

### WebSocket Real-Time Updates
The dashboard maintains a persistent WebSocket connection at `/api/ws` receiving events for:
- `telemetry_update` — new scan data ingested
- `finding_status` — operator triage actions
- `migration_enqueued` / `migration_status` — migration lifecycle
- `policy_switched` — active compliance profile changes

### Agent Health Monitoring
- HTTP heartbeat every 5 seconds reports scan progress, CPU, memory, and current phase.
- Server detects stalled agents (no heartbeat in configurable interval, default 300s) and exposes count in `/api/overview`.
- Diagnostics logs streamed from agent to server with auto-clear after successful upload.

---

## API Reference

### Authentication
All dashboard endpoints require `Authorization: Bearer <jwt>` header. Obtain tokens via `POST /api/auth/login`.

### Core Endpoints
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Database connectivity check |
| GET | `/api/overview` | Aggregated fleet stats (assets, findings, stalled agents, algorithm histogram) |
| GET | `/api/assets` | All registered agents with heartbeat telemetry |
| GET | `/api/components` | Paginated CBOM component catalog (`?limit=&offset=&search=&sort=`) |
| GET | `/api/findings` | Paginated crypto findings with status (`?limit=&offset=&search=&sort=&order=`) |
| PUT | `/api/findings/{id}/status` | Update finding status (open, accepted_risk, false_positive, remediated) |
| GET | `/api/findings/{id}/timeline` | Ordered lifecycle event history for a finding |
| GET | `/api/hosts/{uuid}/findings` | All findings scoped to a specific host UUID |
| GET | `/api/migrations` | Migration transaction history |
| POST | `/api/migrations/enqueue` | Enqueue a migration command (operator/admin role) |
| POST | `/api/migrations/simulate` | Dry-run migration simulation with compatibility analysis |
| GET/POST | `/api/policies` | List policies / create custom profile |
| POST | `/api/policies/active` | Switch active compliance profile |
| GET | `/api/policy/rules` | Versioned control pack (12 PQC/CNSA rules with framework mappings) |
| GET | `/api/policy/rules/{id}` | Single control rule by ID (e.g. JANUS-PQC-001) |
| GET/POST | `/api/waves` | Migration wave plans (CRUD) |
| GET | `/api/agility/scorecard` | Per-host crypto agility scores (6 dimensions) |
| POST | `/api/agility/exercise` | Dry-run agility assessment across fleet |
| GET | `/api/sla/metrics` | SLA metrics including real cert health (expired/expiring counts) |
| GET | `/api/admin/release-check` | Release readiness check (admin role) |
| GET/POST | `/api/fleet/config` | Global fleet configuration |
| GET/POST/DELETE | `/api/fleet/profiles` | Configuration profile CRUD |
| GET/POST | `/api/fleet/profiles/mapping` | Agent-to-profile mappings |
| GET/POST | `/api/webhooks` | SIEM webhook URL management |
| GET/POST | `/api/retention` | Data retention policy + manual purge |
| GET | `/api/audit-logs` | Operator audit trail |
| GET/POST | `/api/agent/diagnostics` | Agent diagnostic log retrieval |
| POST | `/api/agent/heartbeat` | Agent heartbeat telemetry |
| POST | `/api/auth/login` | JWT token issuance |
| POST | `/api/certificates/csr` | PQC certificate signing request generation |
| POST | `/api/llm/proxy` | LLM API proxy for agent-side intent classification (experimental — forwards to configured provider; no structured output or evidence citation) |
| GET | `/api/export/cyclonedx` | CycloneDX v1.6 CBOM export |
| GET | `/api/export/csv` | CSV findings export |
| GET | `/api/export/sarif` | SARIF v2.1.0 findings export |
| GET | `/api/export/siem` | JSON-lines SIEM export |
| GET | `/metrics` | Prometheus metrics endpoint |
| WS | `/api/ws` | WebSocket real-time event stream |

---

## Capability Maturity

Features are classified by operational maturity. Do not use `experimental` or lower features for production remediation decisions without manual review.

| Feature | Maturity | Notes |
|---|---|---|
| **Source crypto detection** (regex + comment stripping) | Experimental | Precision/recall measured; no AST flow analysis yet |
| **Binary import/export scanning** | Experimental | Import table only; no disassembly |
| **Dependency manifest scanning** | Experimental | npm/go/cargo/pip/maven; no transitive graph |
| **TLS/PKI network probing** | Experimental | 9 assessment categories; no live OCSP/CRL |
| **Windows cert-store scanning** | Experimental | certutil/CNG/SChannel/CAPI; Windows agent only |
| **Process memory scanning** | Experimental | Linux `/proc/mem`; Windows `ReadProcessMemory`; elevated privilege required |
| **CycloneDX 1.6 CBOM export** | Experimental | cryptoProperties included; schema validation pending |
| **SARIF 2.1.0 export** | Experimental | Source locations and rules list included |
| **Versioned compliance control pack** | Experimental | 12 JANUS-PQC/CNSA rules; exception workflow pending |
| **Migration wave planning** | Prototype | CRUD + state machine; dependency graph pending |
| **Crypto agility scorecard** | Prototype | 6 dimensions; no live negotiation tests |
| **LLM finding analysis** | Prototype | Async job queue with provenance; provider config required; **not for autonomous remediation** |
| **Sandbox migration simulation** | Prototype | Compatibility analysis + dependency hints; no compiler-aware transforms |
| **Active migration execution** | Prototype | HMAC-signed, atomic, rollback-tested; requires explicit operator enablement |
| **HSM/PKCS#11 key operations** | Prototype | SoftHSM2 via syscall; production HSM wiring pending |

Full maturity definitions and per-dimension breakdowns: [`docs/CAPABILITY_MATURITY.md`](docs/CAPABILITY_MATURITY.md).  
Security policy and supported versions: [`SECURITY.md`](SECURITY.md).  
Support tiers and deprecation policy: [`SUPPORT.md`](SUPPORT.md).  
Privacy and data governance: [`docs/PRIVACY_DATA_GOVERNANCE.md`](docs/PRIVACY_DATA_GOVERNANCE.md).

---

## License

Janus CryptoBOM is distributed under the Apache License, Version 2.0. See the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) for full details.
