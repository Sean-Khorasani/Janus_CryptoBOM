# Janus CryptoBOM — Architecture & Technical Reference

The complete technical blueprint for Janus CryptoBOM: an enterprise post-quantum
cryptographic posture-management and automated-migration platform. It discovers
legacy cryptography across source, binaries, dependencies, network services, and
OS trust stores; assesses quantum readiness against NIST FIPS 203/204/205 and
CNSA 2.0; and orchestrates safe, HMAC-signed, atomic migrations to PQC.

This document is the authoritative reference for *how the system is built and why*.
For installing and operating it, see **[GUIDE.md](GUIDE.md)**; for a fast start,
see **[QUICKSTART.md](QUICKSTART.md)**.

## Contents

1. [System architecture](#1-system-architecture)
2. [Agent–server protocol & fleet contract](#2-agentserver-protocol--fleet-contract)
3. [Data model](#3-data-model)
4. [HTTP REST API](#4-http-rest-api)
5. [Policy engine](#5-policy-engine)
6. [Network & PKI assessment](#6-network--pki-assessment)
7. [Algorithm compatibility & migration matrix](#7-algorithm-compatibility--migration-matrix)
8. [LLM capability & safety contract](#8-llm-capability--safety-contract)
9. [Security architecture & threat model](#9-security-architecture--threat-model)
10. [Privacy & data governance](#10-privacy--data-governance)

---

## 1. System architecture

```
+----------------------------------------------------------------------------------+
|                                  React SPA (ui/)                                 |
|  Dark mode · i18n (en/fa/zh/es) · WCAG 2.1 AA · WebSocket real-time              |
+----------------------------------------------------------------------------------+
                                         |
                                         | HTTPS REST + WebSocket
                                         v
+----------------------------------------------------------------------------------+
|                       Go REST & gRPC Controller (server/)                        |
|  slog JSON logging · JWT auth · Rate limiting · WebSocket hub · Circuit breaker  |
+----------------------------------------------------------------------------------+
                     |                                           |
                     | PostgreSQL (pgxpool)                      | gRPC over TLS 1.3
                     v                                           v
+----------------------------------------+   +-------------------------------------+
|      PostgreSQL Database (store/)       |   |     Rust Endpoint Agent (agent/)    |
|  Versioned migrations · Connection pool |   |  reqwest HTTP · tracing · dpapi     |
+----------------------------------------+   |  Side-channel / FHE detection       |
                                             |  Runtime TLS interception (opt-in)  |
                                             +-------------------------------------+
```

Four layers connected by a single protobuf contract (`proto/janus.proto`).

### 1.1 Go server — package layout

| Package | Purpose |
|---------|---------|
| `cmd/janus-server/` | Entrypoint, signal handling, server orchestration |
| `internal/config/` | Environment config with validation (panics if signing key unset) |
| `internal/store/` | PostgreSQL persistence, versioned transactional migrations, connection pooling |
| `internal/grpcserver/` | gRPC handler, webhook dispatch with circuit breaker, WS broadcasts |
| `internal/httpapi/` | REST API, JWT auth, CORS, rate limiting, feature endpoints, LLM proxy |
| `internal/policy/` | NIST/CNSA policy assessment, OSV.dev integration, confidence analysis |
| `internal/orchestrator/` | HMAC-signed migration command queuing, profile-aware targets |
| `internal/llm/` | LLM pipeline — schema-validated verdicts, async jobs, provenance (§8) |
| `internal/agility/` | Crypto-agility scorecard + per-adapter negotiation harness (GUIDE §8) |
| `internal/waveplan/` | Migration wave-plan state machine + readiness checklist |
| `internal/scanconfig/` | Canonical scan-parameter schema (defaults + min/max limits) |
| `internal/certmanager/` | PQC CSR generation (ML-DSA, SLH-DSA, ECDSA-P384) |
| `internal/sandbox/` | PQC migration simulator — dry-run preview without execution |
| `internal/ws/` | WebSocket hub — stdlib-only RFC 6455, event broadcasting |
| `internal/hsm/` | Configurable HSM (`disabled`/`software`/`pkcs11`): software keystore with real ML-DSA (circl); real-token PKCS#11 via a **cgo-free native `syscall` client on Windows** + a cgo `miekg` client on Linux/macOS; slot-by-index; PQC-only signing; HMAC `MACSigner` for HSM-resident command signing; admin CLI (`janus-server hsm …`) |
| `internal/version/` | Build-time version constants (`-ldflags -X`) |
| `internal/pb/` | Generated protobuf types |

### 1.2 React SPA

- **Vite + React + TypeScript** — type-safe component architecture.
- **Tailwind CSS** — utility-first styling with `dark:` variant (`[data-theme='dark']`).
- **i18n** — English, Persian, Chinese, Spanish via React context.
- **a11y** — FocusTrap, SkipLink, A11yAnnouncer, keyboard navigation (WCAG 2.1 AA).
- **Real-time** — `useWebSocket` hook on `/api/ws`, 10s polling fallback.
- Nine tabs: Overview, CBOM, Compliance, Policy Studio, Migrations, Fleet Command, Agility, Wave Plans, LLM Analysis.

### 1.3 Rust agent — module layout

Dual-binary crate: `janus-agent` (CLI daemon) and `janus_interceptor` (cdylib).

| Module | Purpose |
|--------|---------|
| `main.rs` | CLI with `--once`, daemon, and `check` subcommand (source + binary + deps CI gate) |
| `config.rs` | TOML config with plugin loading, `intercept_mode`, resource limits |
| `discovery/source.rs` | Static source analysis, comment/string stripping, optional LLM intent |
| `discovery/binary.rs` | PE/ELF/Mach-O import/export symbol scanning; optional static x86/x64 `.text` disassembly evidence via `iced-x86` (no execution), gated by the binary-analysis policy (LLM-007) |
| `discovery/dependency.rs` | Package-manifest parsing (npm, Go, Python, Rust, Maven), deduplicated |
| `discovery/network.rs` | TLS probing with STARTTLS, custom X.509 DER parsing |
| `discovery/runtime.rs` | Process-memory scanning (Windows `ReadProcessMemory`, Linux `/proc/PID/mem`) |
| `discovery/windows.rs` | certutil, netsh, reg, PowerShell output parsing |
| `discovery/plugin.rs` | External plugins with cgroups v2 / Job Object resource limits |
| `discovery/sidechannel.rs` | Static timing/constant-time side-channel pattern detection |
| `discovery/cbom.rs` | CycloneDX v1.6 renderer — standards `cryptoProperties` (one cryptographic-asset component per algorithm: primitive, parameter set, NIST PQ level) + RFC 3339 timestamps |
| `comms.rs` | gRPC telemetry + 5s HTTP heartbeat with `watch::channel` shutdown |
| `mutation.rs` | Active migration engine: HMAC verify, atomic rollback, regex registry parsing |
| `storage.rs` | SQLite queue: DPAPI (Win) / AES-256-GCM (Linux), scan-state diffing, periodic VACUUM |
| `policy.rs` | Offline assessment for the `check` subcommand only |
| `report.rs` | HTML and SARIF report generation |
| `interceptor.rs` | OpenSSL `EVP_EncryptInit*` hook cdylib (active/passive) |

---

## 2. Agent–server protocol & fleet contract

### 2.1 gRPC service (`proto/janus.proto`, default :9443)

Service `JanusTelemetry`:

- **`RegisterAgent`** — agent registration with capability negotiation.
- **`StreamTelemetry`** — bidirectional stream: agent pushes `CbomTelemetryPayload`s, server pushes HMAC-signed `MigrationCommand`s.
- **`ReportMigrationStatus`** — agent reports migration outcomes (stream → single ack).

Key types: `CbomTelemetryPayload`, `MigrationCommand` (HMAC-signed), `CryptoFinding`,
`NetworkObservation`, `Evidence`. Bindings for Go and Rust are checked into the repo;
`make proto-check` fails the build if they drift from the `.proto`.

**Communication flow:** register → collect telemetry (all scan stages) → enqueue to
encrypted SQLite → open `StreamTelemetry` → for each command: verify HMAC → backup →
apply patch → validate → reload → TLS verify → rollback on failure → report status.
HTTP heartbeats every 5 s carry scan progress, CPU/memory, phase, and diagnostics;
fleet-config exclusions are fetched dynamically; the server broadcasts updates to
WebSocket clients.

### 2.2 Canonical records

- **Agent** — stable endpoint identity keyed by `host_uuid`; mutable fields hold the latest registration and heartbeat.
- **Connection session** — starts on registration/re-registration; records controller-observed IP, agent version, last heartbeat, disconnection.
- **Scan run / report** — immutable telemetry receipt keyed by `scan_id` (`telemetry_id`); retains agent/OS/network identity at scan time.
- **Finding occurrence** — immutable evidence that a finding appeared in one scan; separate from the mutable current-finding lifecycle status.
- **Progress event** — durable heartbeat snapshot: phase/status, current path, percentage, processed files, CPU, memory.

### 2.3 State rules

- An agent is `offline` when its last heartbeat is older than the configured stall threshold; other states come from the latest heartbeat.
- A scan is `completed` only after its telemetry payload is durably stored.
- Repeated findings create new occurrences while updating the current open finding; historical occurrences are never overwritten.
- **Controller-observed source IP is authoritative.** DNS and endpoint-reported addresses are descriptive and MUST NOT be used for authorization.
- Fleet lists, histories, findings, and components are server-paginated and deterministically sorted with a stable identity tie-breaker.

### 2.4 Contextual findings (exposure graph)

- No graph selection → highest-priority current findings.
- Agent node → findings from that agent's latest completed scan.
- Component/file node → findings for that exact component/file.
- Algorithm node → findings for that algorithm in the active scope.
- The exposure graph is bounded and never represents the complete fleet.

---

## 3. Data model

PostgreSQL persistence sits behind a `Store` interface with **versioned schema
migrations** (38 as of this writing). `EnsureSchema()` runs pending migrations
transactionally; new migrations are appended to the `migrations` slice in `store.go`.

| Area | Tables |
|------|--------|
| Inventory | `assets` (agents + heartbeat telemetry; `tenant_id` per WP-020), `telemetry_payloads` (raw CBOM as JSONB), `crypto_findings` (deduplicated, UNIQUE on `asset_ref, algorithm, policy_rule_id`) |
| Migration | `migration_transactions` (command lifecycle) |
| Fleet | `fleet_configs`, `config_profiles`, `agent_profile_mappings` |
| Identity & tenancy | `agent_credentials` (per-agent identity + `tenant_id`, WP-029/WP-020), `tenants` (WP-020) |
| Governance | `audit_logs`, `finding_lifecycle_events`, `compliance_exceptions`, diagnostics, webhooks (+ failure tracking), retention |
| Settings | `advanced_settings` (JSONB, admin-configurable) |
| Feedback | finding outcomes (confidence feedback), advisory cache |
| Meta | `schema_version` (migration history) |

### 3.1 Multi-tenancy (WP-020)

Tenancy is **row-level**, not schema- or database-per-tenant. A `tenants` table holds the
tenant registry; `assets.tenant_id` and `agent_credentials.tenant_id` carry the owning
tenant. A login's tenant (`JANUS_<ROLE>_TENANT`, default `default`) rides in the JWT
`tenant` claim and is resolved server-side by `httpapi.TenantFromContext`. That tenant flows
into a `WHERE tenant_id = …` filter (directly on `assets`, or via
`host_uuid IN (SELECT host_uuid FROM assets WHERE tenant_id=…)` for child tables) on **every**
authoritative read — overview, assets, findings, components, migrations, exports, reports,
and the per-host/per-scan routes. The migration write path (`enqueueMigration` and the
per-agent command route) refuses a target host outside the caller's tenant via
`store.AssetTenant`. Real-time isolation is enforced in `ws.Hub.BroadcastTenant`: each
WebSocket connection is tagged with the tenant from its single-use ticket and only receives
its tenant's events (a tenant-less connection receives all, preserving single-tenant deploys).
An agent's tenant is fixed at enrollment (`janus-server agent enroll --tenant <id>`) and
stamped onto the asset on first registration only. The `default` tenant is transparent, so
existing single-tenant deployments are unaffected. **Not yet:** HA/failover for a
multi-replica control plane.

---

## 4. HTTP REST API

REST/WS server defaults to :8080. `/api/health`, `/api/auth/login`, and `/metrics`
are open (`/metrics` additionally requires `Authorization: Bearer <JANUS_METRICS_TOKEN>`
when that env var is set); all other endpoints require a Bearer JWT (HS256) unless
`JANUS_DISABLE_AUTH=true` (dev only). `/api/ws` bypasses JWT but is authorized by a
short-lived, single-use ticket minted via `POST /api/ws/ticket`. The
**Role** column is the *enforced* elevation: blank = any authenticated user;
`op/admin` = `RequireRole(operator, admin)`; `admin` = admin only; `agent` =
per-agent HMAC token.

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/health` | public | DB connectivity (reports `draining` during shutdown) |
| POST | `/api/auth/login` | public | JWT token issuance |
| POST | `/api/auth/change-password` | — | Change own password (persists override; invalidates the user's prior sessions) |
| GET | `/metrics` | public\* | Prometheus metrics (\*bearer `JANUS_METRICS_TOKEN` required when set) |
| GET | `/api/overview` | — | Fleet stats + readiness score + stalled agents |
| GET | `/api/assets`, `/api/agents/{id}` | — | Agent inventory + detail |
| GET | `/api/components` | — | Paginated CBOM catalog (`?limit=&offset=&search=&sort=`, `X-Total-Count`) |
| GET | `/api/findings`, `/api/findings/{id}/timeline` | — | Paginated findings + occurrence timeline |
| PUT | `/api/findings/{id}/status` | — | Update finding status (WS broadcast) |
| GET | `/api/hosts/{id}/findings` | — | Findings from a host's latest scan |
| GET | `/api/migrations` | — | Migration history |
| POST | `/api/migrations/enqueue` | op/admin | Enqueue HMAC-signed migration |
| POST | `/api/sandbox/simulate` | — | Dry-run migration preview (patch + impact + checklist) |
| POST | `/api/lab/simulate` | — | PQC lab algorithm-migration preview |
| GET/POST | `/api/policies`, `/api/policies/create` | — | List / create policy profiles (version sanitized to `[A-Za-z0-9._-]`) |
| POST | `/api/policies/active` | — | Switch active profile (WS broadcast) |
| GET | `/api/policy/rules`, `/api/policy/rules/{id}` | — | Policy rule catalog |
| GET/POST/DELETE | `/api/fleet/config`, `/api/fleet/profiles`, `/api/fleet/profiles/mapping` | — | Fleet config + profile CRUD + agent mapping |
| GET | `/api/scan-config/schema` | — | Canonical scan-parameter schema |
| GET/POST/DELETE | `/api/webhooks` | — | SIEM webhook management |
| GET/POST | `/api/retention` | — | Data retention + manual purge |
| GET | `/api/audit-logs`, `/api/export/audit?format=csv` | — | Audit trail + export |
| GET | `/api/audit-logs/verify` | admin | Verify the audit-log hash chain (tamper-evidence) |
| GET | `/api/confidence/report` | — | Finding confidence analysis |
| GET | `/api/agility/scorecard` | — | Crypto-agility scorecard (fleet + per-host) |
| POST | `/api/agility/exercise` | op/admin | Run the negotiation/agility exercise harness |
| GET | `/api/sla/metrics` | — | Crypto-health SLA dashboard |
| GET | `/api/report/compliance`, `/api/report.html` | — | HTML compliance report |
| GET/POST | `/api/waves`; PUT/DELETE `/api/waves/{id}` | op/admin | Migration wave-plan CRUD + state machine |
| POST | `/api/certificates/csr` | op/admin | PQC CSR generation |
| POST | `/api/hsm/sign`, `/api/hsm/verify` | op/admin | HSM sign / verify |
| POST | `/api/llm/analyze`, `/api/llm/analyze/batch` | op/admin | LLM finding analysis (async jobs) |
| GET | `/api/llm/status`, `/api/llm/usage`, `/api/llm/jobs`, `/api/llm/verdicts/{id}`, `/api/llm/provenance/{id}`, `/api/llm/batches/{id}` | — | LLM status, usage/cost rollup, job/verdict/provenance retrieval |
| POST | `/api/llm/verdicts/{id}/review` | op/admin | Record an approve/reject decision on a verdict (audit only — no finding-state change) |
| POST | `/api/llm/test-connection` | admin | Probe the configured LLM provider |
| POST | `/api/llm/proxy` | — | Raw LLM proxy passthrough |
| GET/POST | `/api/agent/heartbeat`, `/api/agent/config`, `/api/agent/scan-command`, `/api/agent/diagnostics` | agent | Agent heartbeat / config / command / diagnostics |
| GET | `/api/agent/upgrade` | — | Agent version + download info |
| POST | `/api/admin/release-check` | admin | Release-evidence gate check |
| GET | `/api/export/cyclonedx`, `/csv`, `/sarif`, `/siem` | — | CBOM / findings exports |
| POST | `/api/ws/ticket` | — | Mint a short-lived, single-use WebSocket ticket (bearer JWT in header) |
| WS | `/api/ws?ticket=<ticket>` | — | Real-time events (`telemetry_update`, `finding_status`, `migration_enqueued`, `migration_status`, `policy_switched`, `lab_simulation`); 15 s ping keepalive |

**Only the `op/admin` and `admin` routes are role-gated.** Every other authenticated
route — including policy authoring, fleet config, webhook/retention management, and
finding-status triage — is reachable by **any** authenticated user regardless of role;
per-route role tightening is a tracked hardening item (§9.2). CORS is restricted to
`JANUS_CORS_ORIGIN` (wildcard only when auth is disabled). HSM key listing/generation
exist at the `internal/hsm` interface (`ListKeys`, `GenerateKeyPair`) but are **not**
exposed as REST routes — only sign/verify are.

---

## 5. Policy engine

YAML profiles in `policies/`, selected via HTTP API or UI. **Assessment is
server-authoritative**; the agent assesses offline only for its `check` subcommand
and local reports.

| Profile | Preferred KEM | Preferred signature | Min RSA | Min DH | TLS |
|---|---|---|---|---|---|
| `nist-pqc-2026.yaml` | X25519MLKEM768 | ML-DSA-65 | 3072 | 3072 | 1.3 + hybrid PQC |
| `cnsa-2.0.yaml` | ML-KEM-1024 | ML-DSA-87 | 3072 | 3072 | 1.3 + hybrid PQC + CNSA rules |
| `custom.yaml` | enterprise-defined | enterprise-defined | — | — | — |

The orchestrator's `BuildCommand()` reads `preferredKEM`/`preferredSignature` from the
active profile — there are no hardcoded algorithm defaults; the profile is the single
source of truth. Each profile supports `minimum_confidence` (default 0.4) for finding
filtering.

**CNSA 2.0 rules** (`assessCNSA`):

| Rule | Condition | Severity |
|------|-----------|----------|
| JANUS-CNSA-001 | ECDSA curve below P-384 | HIGH |
| JANUS-CNSA-002 | SHA-256 for hashing | MEDIUM |
| JANUS-CNSA-003 | AES-128 symmetric encryption | HIGH |

**Context-aware severity adjustment:** `verify`/`parse` usage −2 levels; `negotiate`
−1 level; `protect` no adjustment. OSV severity parsing maps actual CVSS scores to
Janus levels.

---

## 6. Network & PKI assessment

Derived from `agent/src/discovery/network.rs` — what the scanner does today, not
roadmap. The agent performs active TCP probing against `network_targets`: TCP connect
(3 s timeout) → optional STARTTLS → `rustls` handshake (reconnaissance verifier that
skips chain validation) → extract parameters from the handshake and raw ServerHello.

**STARTTLS variants:** SMTP (25/587: banner → EHLO → STARTTLS), LDAP (389: extended
request OID 1.3.6.1.4.1.1466.20037), PostgreSQL (5432: 8-byte SSLRequest, expects `S`),
MySQL (3306: handshake → SSLRequest flags). Port 80 is short-circuited as cleartext.

**Evidence captured** — protocol parameters stored as a pipe-delimited string
`<tls_version>|<cipher_suite>|<alpn>|ocsp:<status>` (e.g.
`TLSv1.3|TLS13_AES_256_GCM_SHA384|h2|ocsp:unchecked`); the negotiated named group from
the `key_share` extension (hybrid PQC groups X25519MLKEM768=4588, SecP256r1MLKEM768=4605,
X448MLKEM1024=4590 set `pqc_hybrid=true`); end-entity certificate subject/issuer DN,
`not_after`, and signature algorithm. Intermediate CAs (chain index ≥ 1) become
`certificate` CBOM components, flagged weak on SHA-1/MD5 signatures or RSA < 2048.

**Finding classification** (`TlsAssessmentCategory`, highest priority first):

| Category | Confidence | Condition |
|---|---|---|
| `tls-hybrid-pqc` | 0.95 | PQC hybrid group negotiated |
| `tls-cert-expired` | 0.85 | `not_after` in the past |
| `tls-cert-self-signed` | 0.85 | subject == issuer (both non-empty) |
| `tls-tls13-classical` | 0.90 | TLS 1.3, no hybrid PQC |
| `tls-tls12-weak` | 0.90 | TLS 1.2 |
| `tls-classical-only` | 0.90 | TLS < 1.2 or unrecognized |
| `tls-no-tls` | 0.95 | port 80 cleartext |
| `tls-unreachable` | 0.50 | TCP connect failed/timed out |
| `tls-handshake-failed` | 0.50 | TCP OK, TLS handshake error |

**Current limitations:** no live OCSP/stapling check (`ocsp_status` always `unchecked`),
no CRL download, no HPKP/DANE, no Certificate Transparency check; chain validation is
deliberately disabled during scanning; TLS 1.0/1.1 are not probed (rustls floor is 1.2,
so they surface as `tls-handshake-failed`).

---

## 7. Algorithm compatibility & migration matrix

A technical reference for planning PQC migrations. Policy targets are drawn from the
profiles in §5.

### 7.1 NIST security levels & standards

| Level | Benchmark | Algorithms |
|---|---|---|
| 1 | break AES-128 | ML-KEM-512, ML-DSA-44, SLH-DSA-128s |
| 3 | break AES-192 | ML-KEM-768, ML-DSA-65, SLH-DSA-192s |
| 5 | break AES-256 | ML-KEM-1024, ML-DSA-87, SLH-DSA-256s |

NIST profile targets Level 3 (FIPS 203/204/205); CNSA 2.0 sets Level 5 as the floor.
Standards: **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), **FIPS 205** (SLH-DSA),
**CNSA 2.0** (ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512), **SP 800-131A Rev.3**
(deprecation timelines).

### 7.2 Source → target matrix

| Source | Target | Notes |
|---|---|---|
| RSA-2048/3072 signing | ML-DSA-65 (NIST) / ML-DSA-87 (CNSA) | RSA-2048 deprecated under CNSA 2.0 → critical |
| RSA-4096 signing | ML-DSA-87 | Not quantum-safe; ML-DSA-87 = Level 5, smaller sigs |
| ECDSA P-256 | ML-DSA-65 | P-256 deprecated under CNSA → high |
| ECDSA P-384 | ML-DSA-65/87 | Classical transitional only; not quantum-safe |
| ECDH P-256 / X25519 | X25519MLKEM768 (hybrid) | NIST profile TLS KEM group |
| ECDH P-384 | ML-KEM-1024 (or P-384+ML-KEM-1024) | CNSA profile target |
| RSA-OAEP-2048/4096 | ML-KEM-768 / ML-KEM-1024 | KEM replacement; HPKE (RFC 9180) for non-TLS |
| AES-128-* | AES-256-GCM | Grover halves key strength; AES-128 < CNSA floor |
| SHA-1 | SHA-384/512 | SHA-1 classically broken → critical |
| SHA-256 | SHA-384/512 | CNSA 2.0 requires SHA-384 minimum |
| TLS 1.0/1.1 | TLS 1.3 | Deprecated by RFC 8996 → critical |
| TLS 1.2 | TLS 1.3 + hybrid KEM | 1.2 can't negotiate hybrid PQC groups |
| CMS/PKCS#7 RSA/ECDSA | CMS ML-DSA-65/87 | Requires `id-ml-dsa` OIDs (RFC 9629) |

**Key/signature sizes (selected):** RSA-2048 sig 256 B vs ML-DSA-65 sig 3,293 B /
ML-DSA-87 sig 4,627 B; X25519 pubkey 32 B vs X25519MLKEM768 1,216 B / ML-KEM-1024
1,568 B. The size increase grows TLS handshakes — watch MTU/fragmentation on DTLS/QUIC
and older middleboxes that reject oversized ClientHellos.

**Why hybrid?** During transition, hybrid KEM protects the session key if *either*
the classical or the PQC component is compromised.

### 7.3 Library support

| Library | ML-KEM | ML-DSA | SLH-DSA | X25519MLKEM768 | TLS 1.3 PQC |
|---|---|---|---|---|---|
| OpenSSL 3.5+ | Native | Native | Native | Native | Yes |
| OpenSSL 3.3–3.4 | oqs-provider | oqs-provider | oqs-provider | oqs-provider | with oqs-provider |
| BoringSSL | Chromium fork | upstream: no | no | Chrome | Chrome only |
| libOQS | Yes | Yes | Yes | KEM combiner | via oqs-provider |
| rustls + rustls-post-quantum | ML-KEM-768 | cert only | no | Yes | Yes |
| Go crypto/tls | no | no | no | no | needs cloudflare/circl |

Janus `certmanager.GenerateCSR()` invokes `openssl genpkey` for ML-DSA/SLH-DSA profiles,
requiring OpenSSL 3.5+ (or an oqs-provider-patched 3.3/3.4).

### 7.4 Recommended sequencing

1. **Critical classical risks first** — TLS 1.0/1.1 and SHA-1.
2. **Key agreement** — TLS 1.3 + X25519MLKEM768 (NIST) / ML-KEM-1024 (CNSA): a config change, no key management.
3. **Symmetric sizes** — AES-128 → AES-256.
4. **Certificate signatures** — migrate CA + end-entity certs to ML-DSA (coordinate relying parties).
5. **Application signatures** — CMS/PKCS#7, code-signing.
6. **RSA key transport** — RSA-OAEP → HPKE/ML-KEM.

Commands are dispatched per-finding, but plan the sequence at the deployment level.

---

## 8. LLM capability & safety contract

This is a **normative contract** governing all LLM use in Janus. Absent these controls,
"AI-powered crypto migration" claims are marketing, not engineering. LLM features are
optional and default-off.

### 8.1 Architecture invariants (binding; no flag may relax them)

1. **Bounded evidence input** — LLM calls operate only on structured `BoundedEvidencePackage` inputs (algorithm name + ≤512-byte snippet). Raw source files, binaries, full configs, and memory dumps are never sent (prompt-injection / secret-exposure defense).
2. **Schema-validated output** — every response is validated against the applicable schema before use; failures are discarded as abstentions. Free-form LLM text never becomes inventory truth, finding state, or migration instructions.
3. **Mandatory confidence + abstention** — every output carries `confidence` ∈ [0,1]; `abstain` is a first-class output routed to human review; outputs lacking confidence are rejected.
4. **Mandatory evidence citation** — every verdict/suggestion cites `finding_id`/`evidence_id` values that a citation checker confirms exist in the input set; uncited claims are discarded.
5. **Deterministic verification before state change** — no inventory/queue/endpoint change is triggered solely by LLM output; a deterministic verifier (policy engine, config validator, TLS probe, schema checker) is authoritative.
6. **Authority inversion** — LLMs annotate and propose; they do not authorize, sign, execute, or remove deterministic findings.
7. **Prompt-injection defense** — analyzed content goes only in the USER turn with delimiter quarantine; the SYSTEM prompt is static, developer-authored; the pipeline is red-teamed with seeded injection payloads as a release gate.
8. **Full provenance** — every call persists an immutable `LLMProvenanceRecord` (model, prompt version, input/output hashes) before the output is consumed.

### 8.2 Capability modes

LLM features are **off whenever `JANUS_LLM_BASE_URL` is unset** (the default) — the
`/api/llm/*` endpoints then return `503`. When a base URL is set, the active mode is
fixed at startup by `JANUS_LLM_CAPABILITY_MODE` (default `analysis_only`):

| `JANUS_LLM_CAPABILITY_MODE` | Permitted |
|------|-----------|
| `disabled` | No LLM calls (also the effective state whenever `JANUS_LLM_BASE_URL` is empty) |
| `analysis_only` *(default)* | Intent classification, false-positive triage, severity-adjustment *proposals*, explanations — read-only verdicts |
| `suggest_remediation` | Analysis + candidate patches (source/config only); `human_approval_required` is unconditionally `true` |
| `automated_remediation` | **NOT IMPLEMENTED** — requires sandboxed validation + per-agent PQ signing of LLM-derived commands and independent security review; must not be enabled until then |

### 8.3 Schemas (normative)

- **`BoundedEvidencePackage`** (only permitted input): `finding_id`, `evidence_type`, `algorithm_detected`, `detection_method`, `confidence_floor`, sanitized relative `file_path`, optional `line_range`, `context_snippet` (≤512 bytes, secret-scanned), `intent_labels`, `sensitivity_label`, `collection_timestamp`. The snippet is the matching line ±1 line, truncated — never a full function/file. `sensitivity_label` gates which providers may receive it; `restricted` evidence requires residency-compliant, tenant-isolated endpoints. For `binary_import`/`process_memory`, the snippet is the symbol/pattern name only.
- **Verdict** (required: `job_id`, `finding_id`, `verdict` ∈ {`false_positive`,`confirmed`,`severity_adjusted`,`needs_review`,`abstain`}, `confidence`, `reasoning` ≤1000 chars, `evidence_citations` ≥1; `adjusted_severity` 1–5 or null; `abstention_reason` when abstaining). Downstream: `false_positive`/`severity_adjusted` are re-evaluated by the policy engine before any DB write; `needs_review`/`abstain` escalate without modification. Operators record an explicit approve/reject **review** of a verdict (`POST /api/llm/verdicts/{id}/review`, operator/admin); the decision is audit metadata and does not itself change finding state — applying it stays an explicit operator action (invariant 6).
- **Remediation suggestion** (`suggest_remediation` only): `recommendation_type` ∈ {`config_change`,`dependency_upgrade`,`api_refactor`,`compensating_control`,`binary_not_supported`}, `target_algorithm`, `candidate_patch` (unified diff ≤4096 chars, or null), `assumptions`, `compatibility_notes`, `validation_required`, `human_approval_required` (`const true`), `confidence`. Patch gates — **current implementation (LLM-013):** deterministic structural validation only (valid unified-diff shape, repo-relative path boundary rejecting absolute/`..`/`~` targets, ≤4096 bytes, no NUL bytes); a patch that fails is dropped (not surfaced as actionable) while the suggestion's guidance is retained. **Target (not yet built):** apply-cleanly check against the current file, compile/test in simulation, and an optional bounded repair loop of ≤3 iterations, then exit to human review.
- **`LLMProvenanceRecord`** (immutable): `job_id`, `provider`, exact `model`, `prompt_name`/`prompt_version`, `input_hash`, `output_hash`, token counts, `latency_ms`, `finding_id`, `verdict_or_suggestion`, `schema_valid`, `timestamp`. Retained for the finding's audit period; `restricted` records use field-level encryption; recalibration against a frozen labeled corpus uses these records.

### 8.4 Binary remediation policy

Janus never rewrites binaries. For `binary_import`/`process_memory` findings,
`candidate_patch` is null and `recommendation_type` is `binary_not_supported`. The five
permitted LLM-assisted responses (all human-actioned): vendor upgrade, rebuild-from-source
guidance, runtime interposition (advice only), network compensating control, and
isolate-and-risk-accept (with governance review).

### 8.5 Operator responsibilities & non-goals

Before `analysis_only`: provider data-residency due diligence; key via
`JANUS_LLM_API_KEY_FILE`/`_ENV` (never inline); model pinning; baseline calibration
(precision/recall/abstention per evidence type); injection red-team; secret-scan
verification. Before `suggest_remediation`: a documented human patch-review process,
an operational simulation environment, and governance notification.

**Non-goals:** no autonomous migration execution; no training-data contribution; no PII
in prompts; no raw source submission; LLM output is never authoritative inventory; no
accuracy guarantee — operators must run their own calibration corpus.

---

## 9. Security architecture & threat model

### 9.1 Controls

- **Command signing & key separation** — migration commands and agent tokens are HMAC-SHA256-keyed by `JANUS_COMMAND_SIGNING_KEY` (required, no default; the **root of trust** for migration authorization). HMAC-SHA256 is a quantum-resistant symmetric MAC (CNSA 2.0-accepted) — deliberately not an asymmetric RSA/ECDSA signature. With `JANUS_HSM_SIGN_COMMANDS=true` the key is provisioned into the HSM and the MAC is computed there, so it never resides in server memory; the wire value and the agent's verification are identical. Dashboard session JWTs are signed by `JANUS_JWT_SECRET`, which defaults to the command key but can be set separately (AUTH-03) so a leaked session secret cannot forge agent/command auth.
- **PQC-only asymmetric signatures** — HSM key generation and `/api/hsm/sign` use ML-DSA (FIPS 204) / SLH-DSA (FIPS 205); RSA and ECDSA are refused at both the software and PKCS#11 backends. The `pkcs11` mode is fail-closed (startup aborts if the token can't be opened).
- **Optional ML-DSA command signing (server signs, agents verify)** — with `JANUS_COMMAND_SIG_SCHEME=ml-dsa`, the server *additionally* signs each migration command with an ML-DSA key (HSM-resident or software). `signed_directive` becomes a `janus-sig-v1` envelope carrying the HMAC, the ML-DSA signature, and the public key. An agent that pins the key's hex SHA-256 fingerprint (`command_pqc_fingerprint`, distributed out-of-band) verifies the embedded public key against the pin (TLS-cert-pinning model — no secret channel needed) and then the ML-DSA signature (pure-Rust `fips204`, cross-platform). A compromised agent cannot forge commands (it holds no private key), and a fingerprint-pinned agent rejects any command lacking the ML-DSA envelope (downgrade-resistant). HMAC remains the mandatory baseline.
- **Transport enforcement** — `JANUS_REQUIRE_TLS` / `JANUS_REQUIRE_MTLS` fail startup if gRPC TLS / client-cert verification is not configured (AUTH-01), preventing a silent plaintext / unauthenticated-agent fallback in production.
- **Webhooks** — destinations are SSRF-validated on insert (no metadata/private/loopback IPs; remote must be https); dispatched payloads carry `X-Janus-Signature: sha256=HMAC(secret, body)` so receivers verify authenticity. Dispatch has a circuit breaker — 3 retries with exponential backoff (1/2/4 s); circuit opens after 5 consecutive failures to a URL → 60 s cooldown.
- **Secret storage** — Windows DPAPI; Linux AES-256-GCM (`aead-v1:`), machine-identity-derived; server LLM keys AES-256-GCM in PostgreSQL.
- **CORS** — origin-restricted to `JANUS_CORS_ORIGIN` (wildcard only when auth disabled).
- **Request hardening** — per-IP sliding-window rate limit on the credential endpoints (`/api/auth/login`, `/api/auth/change-password`; 20/min, `Retry-After` on 429); 8 MiB request-body cap (`http.MaxBytesReader`, `/api/ws` exempt); `ReadHeaderTimeout` + `IdleTimeout` + `MaxHeaderBytes` on the HTTP server (`ReadTimeout`/`WriteTimeout` intentionally unset to not break the hijacked WS connection); gRPC keepalive (server pings idle peers 60s/20s, `MaxConnectionIdle` 15m) so a wedged or vanished agent cannot hold a stream goroutine indefinitely (REM-7).
- **Plugin sandboxing** — Linux cgroups v2 (`memory.max`, `cpu.max`); Windows `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`.
- **Graceful shutdown** — drain window (`JANUS_GRACEFUL_SHUTDOWN_SECONDS`, 1–300): health reports `draining`, new HTTP gets 503, gRPC `GracefulStop`, webhooks drain.

### 9.2 STRIDE by trust surface

```
 operator browser ──TLS──▶ HTTP/REST/WS API ─┐
                                             ├─ Controller (Go) ──▶ PostgreSQL
 agent (Rust) ──gRPC(mTLS opt)──▶ Telemetry ─┘            │
        │                                                 └──▶ LLM provider (egress, optional)
        ├─ scans host fs / processes / network (passive by default)
        └─ applies signed MigrationCommands (active mode, opt-in)
 plugins ◀── spawned by agent with resource limits
```

**Controller** — JWT (HS256) per request, env-configured bcrypt creds (no compiled-in
defaults); per-agent HMAC token + optional gRPC mTLS; SQL parameterized via pgx; policy
version path-sanitized; `audit_logs` + immutable `finding_lifecycle_events`; LLM key
never returned + SSRF guard on the base URL (blocks private IPs/metadata); gRPC
`MaxRecvMsgSize` 32 MiB + pagination + pool caps; `RequireRole` on privileged routes.
*Residual:* single shared JWT secret (no refresh rotation). **Per-agent agent→server auth** is available opt-in (`JANUS_AGENT_AUTH_MODE=per-agent`, WP-029 P1): per-agent HMAC keys (HKDF from a server master) with per-agent revocation via `agent_credentials`, replacing the shared agent token on `/api/agent/config` and `/api/agent/scan-command`. The audit log is now **tamper-evident** — each entry carries a SHA-256 hash chained over its predecessor, verifiable via `GET /api/audit-logs/verify` (WP-028).

**Agent** — MigrationCommand HMAC verified before any mutation; passive/read-only by
default (snapshot tests prove no mutation); telemetry queued in encrypted SQLite until
the stream succeeds; evidence bounded (512 B), classified, and `redact_secrets()`-scrubbed
before egress; cgroups/Job-Object caps. Per-agent identity (`JANUS_AGENT_AUTH_MODE=per-agent`,
WP-029 P1) authenticates both the HTTP and gRPC agent→server channels with per-agent HMAC
keys and supports per-agent revocation; the legacy shared key remains the default. *Residual:*
shared-key default; mTLS optional in dev; process-memory/runtime stages opt-in.

**Plugins** — operator-configured paths, discovery off by default, resource-limited,
no implicit network grant. *Residual:* no plugin signature verification; resource- not
syscall-isolation.

**Migration path** — HMAC verify (+ optional ML-DSA) with a replay window (`max_command_age_seconds`, default 300s, rejecting stale/future commands); `allowed_config_roots` sandbox + extension allowlist
(`.conf/.config/.cnf/.json/.toml/.yaml/.yml/.xml/.ini/.properties`, plus the well-known
extensionless configs `sshd_config`/`ssh_config`; anything else — including other
extensionless files — is rejected); atomic backup→write→validate→reload→TLS-verify
with automatic rollback; SHA-256 drift detection; off by default. *Residual:* canary
automation pending.

**Supply chain** — pinned lockfiles + `make vuln` (govulncheck + cargo-audit + npm audit);
`make proto-check` blocks contract drift; versioned detection benchmark with
precision/recall gate. *Residual:* no reproducible-build attestation / artifact signing.

### 9.3 Verification program

Unit (Go + Rust), property/fuzz (`policy.FuzzAssess`), race/concurrency (`make race`,
`-race`-clean), partial fault injection, detection benchmark (precision/recall by detector
& language), performance baseline (`BenchmarkAssess`), and Linux migration-adapter tests
(nginx/apache/ssh validate+reload+rollback). **Not yet:** HA/failover, systematic chaos,
external penetration test.

**Residual-risk posture:** unresolved critical/high items concentrate in the security
phase (per-agent identity is now available opt-in but not yet default; CA-chained command
trust / PQC X.509 verification, authenticated secret storage, full plugin sandboxing,
enterprise IAM) and HA/scale. Row-level multi-tenancy (WP-020, §3.1) isolates tenant data
across the read, write, and real-time planes, but the control plane is still **single-replica
(no HA/failover)** and lacks an external penetration test. Until those land, Janus suits
evaluation and controlled deployments — **not yet an internet-exposed, highly-available
control plane.**

---

## 10. Privacy & data governance

Derived from the agent source; code paths cited where they matter.

### 10.1 Data classification

Every evidence item carries a `DataClassification` (`agent/src/evidence.rs`):

| Classification | Contents | External LLM? |
|---|---|---|
| `CryptoMetadata` | algorithm names, key sizes, cipher-suite IDs | Yes (with policy enabled) |
| `CodeSnippet` | ≤512-byte source excerpt, relative path, line range | explicit opt-in only |
| `ConfigContent` | config excerpt (may reference hosts/ports/creds) | explicit opt-in only |
| `NetworkEndpoint` | host, port, TLS version, cipher suite | Yes (with policy enabled) |
| `KeyFingerprint` | hash / truncated key id (never raw key) | Yes (with policy enabled) |

A separate `SensitivityLabel` (`Public`/`Internal`/`Confidential`/`Restricted`) defaults
to `Internal`. `ProcessMemory` evidence is `Restricted` and never sent to an LLM.

### 10.2 Collection minimization

**Collected:** algorithm identifiers, relative paths, line ranges, ≤512-byte context
snippets, TLS negotiation metadata, crypto-matching binary symbols, dependency
name+version, process exe name/path (runtime opt-in only). **Not collected:** raw key
material, certificate private keys, plaintext credentials, file contents beyond the
512-byte window, absolute paths, heap contents beyond PEM-header detection, network
payloads. Scan-depth limits (`AgentConfig::validate()`): `max_file_bytes` 2 MiB (1 KiB–10 GiB),
`max_binary_bytes` 16 MiB, snippet cap 512 B (fixed).

### 10.3 Consent — invasive modes are off by default

| Capability | Config key | Requirement |
|---|---|---|
| Runtime process scanning | `enable_runtime_discovery` | opt-in |
| Process-memory scraping | `enable_process_memory_scraping` | opt-in; also needs runtime discovery; elevated privilege |
| External plugins | `enable_plugin_discovery` | opt-in |
| Active TLS probing | `enable_active_tls_probing` | opt-in |

LLM-assisted binary analysis is gated by `[binary_llm_policy]` (`enabled=false` by
default; `require_audit_consent=true` records consent in the SQLite `sync_audit` table
before the first call). The LLM API key is loaded by the **server**, never the agent.

### 10.4 Data flow, redaction, retention, residency

Scan → discovery modules (≤512-byte snippets, relative paths) → `redact_secrets()`
(caller-invoked; strips PEM private-key blocks, `password=`, `secret=`, `api_key=`) →
`BoundedEvidencePackage` (classification applied) → optional LLM path (bounded fields
only) / main path → `CbomTelemetryPayload` → encrypted SQLite (DPAPI / AES-256-GCM) →
gRPC `StreamTelemetry` (mTLS optional) → server → PostgreSQL.

`redact_secrets()` is best-effort and does not catch unlabeled base64/hex secrets or
non-standard token names — treat `ConfigContent` evidence with extra care.

**Retention:** agent queue holds encrypted payloads until acknowledged then deletes them;
`scan_state` hashes can be purged; `VACUUM` runs every 24 h. The server imposes **no
default retention** — operators apply PostgreSQL-level policies (e.g. `pg_cron`).
Server-side Postgres is not encrypted at rest by default; use TDE/filesystem encryption.

**Residency:** Janus is self-hosted; no data leaves operator infrastructure by default.
**No Anthropic API is used at runtime** — Claude Code (this dev tooling) is not the
runtime LLM. When `JANUS_LLM_BASE_URL` points at a cloud provider, bounded evidence
packages reach that provider; point it at an on-prem/Ollama endpoint to keep residency.

### 10.5 Operator responsibilities

Signing key: ≥16 B (32 B recommended, `openssl rand -hex 32`), per-environment, rotated
if compromised, never logged/committed; on the agent it may be a `dpapi:` blob (Windows)
or `JANUS_COMMAND_SIGNING_KEY_FILE` (preferred on Linux). Enable **mTLS** in production
(`tls_client_cert`/`tls_client_key` verified against `JANUS_CLIENT_CA_FILE`). Provide
`JANUS_CACHE_KEY_FILE` (≥32 B) on Linux rather than relying on the `/etc/machine-id`
fallback, and migrate legacy `aes256ctr:` cache blobs to `aead-v1:`. Keep LLM keys in a
file, least-privilege scoped, and rotated. Export the agent `sync_audit` trail centrally.

---

*For deployment, settings reference, role-based operation, maintenance, and case studies,
see **[GUIDE.md](GUIDE.md)**.*
