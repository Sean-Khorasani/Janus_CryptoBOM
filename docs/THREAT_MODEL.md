# Janus CryptoBOM — Threat Model (WP-019)

Formal threat models for the five trust surfaces required by WP-019: the
**controller** (Go server), the **agent** (Rust), **plugins**, the **migration**
path, and the **supply chain**. Each surface is analyzed with STRIDE (Spoofing,
Tampering, Repudiation, Information disclosure, Denial of service, Elevation of
privilege), listing the threat, the existing control, and residual risk.

This document is maintained per release alongside `docs/SECURITY.md`
(disclosure + operator requirements) and `docs/CAPABILITY_MATURITY.md` (the LLM
Trustworthiness dimension). Items marked **[security phase]** are tracked work
packages (WP-003…012) not yet implemented.

## Trust boundaries

```
 operator browser ──TLS──▶ HTTP/REST/WS API ─┐
                                             ├─ Controller (Go) ──▶ PostgreSQL
 agent (Rust) ──gRPC(mTLS opt)──▶ Telemetry ─┘            │
        │                                                 └──▶ LLM provider (egress, optional)
        ├─ scans host filesystem / processes / network (passive by default)
        └─ applies signed MigrationCommands (active mode, opt-in)
 plugins ◀── spawned by agent with resource limits
```

The HMAC `command_signing_key` is the root of trust for migration authorization
and JWT signing; it is shared controller↔agent and required at startup.

---

## 1. Controller (Go server)

| STRIDE | Threat | Control | Residual |
|---|---|---|---|
| Spoofing | Forged dashboard user | JWT (HS256) verified per request; credentials are env-configured bcrypt hashes, no compiled-in defaults (S1) | Single shared JWT secret; no per-user keys / refresh rotation **[AUTH-001]** |
| Spoofing | Forged agent | Per-agent HMAC token on `/api/agent/config`,`/scan-command`; optional gRPC mTLS | Heartbeat/CSR historically public — CSR now operator-gated (AUTH-003); per-agent identity bootstrap **[WP-003]** |
| Tampering | Malicious API input / path traversal | Policy version sanitized to `[A-Za-z0-9._-]`; parameterized SQL via pgx; CORS origin-restricted | — |
| Tampering | DB row manipulation | Versioned transactional migrations; FK cascades | DB-level auth is the operator's responsibility |
| Repudiation | Unattributed privileged action | `audit_logs` for policy/migration/wave/CSR actions with actor identity; immutable `finding_lifecycle_events` | Audit log not tamper-evident (no signing) |
| Information disclosure | Secrets in responses | LLM API key never returned (file/env only); SSRF guard on `JANUS_LLM_BASE_URL` (blocks private IPs/metadata) | — |
| Denial of service | Unbounded ingest / requests | gRPC `MaxRecvMsgSize` (32 MiB); paginated endpoints; DB pool caps | API-wide rate limiting **[OPS-002]** |
| Denial of service | SIGTERM mid-request drops data | **Graceful shutdown (OPS-001)**: drain window, health=draining+503, gRPC `GracefulStop`, webhook WaitGroup drain | Bounded by `JANUS_GRACEFUL_SHUTDOWN_SECONDS` |
| Elevation of privilege | Viewer invokes privileged op | `RequireRole` on migrations/HSM/CSR/LLM/waves/release-check; admin hierarchy | Continuous audit that every privileged route is guarded **[WP-011]** |

## 2. Agent (Rust)

| STRIDE | Threat | Control | Residual |
|---|---|---|---|
| Spoofing | Rogue controller issues commands | MigrationCommand HMAC-SHA256 verified against shared key before any mutation | Shared (not per-agent) key **[WP-004]** |
| Tampering | Scan mutates the target | Passive by default; discovery is read-only; deterministic snapshot tests prove no mutation (WP-LNX-004) | Process-memory/runtime stages are opt-in |
| Tampering | Telemetry tampered in transit | gRPC channel; optional mTLS; payloads queued in SQLite until stream succeeds | mTLS optional in dev |
| Repudiation | Agent actions unlogged | Local audit log; controller-side scan/connection history | — |
| Information disclosure | Secrets leave the endpoint | Evidence is bounded (`MAX_CONTEXT_BYTES=512`), classified, and `redact_secrets()` (PEM/password/api-key/AWS) before any egress; LLM is server-side and admin-initiated only | Redaction is caller-invoked; corpus is finite **[WP-026]** |
| Information disclosure | Offline queue at rest | SQLite encrypted: DPAPI (Windows) / AES-CTR machine-derived (Linux) | Key derivation tied to machine identity **[WP-008]** |
| Denial of service | Plugin/scan exhausts host | cgroups v2 (Linux) / Job Objects (Windows) memory+cpu caps; file-size limits | — |
| Elevation of privilege | Agent runs over-privileged | Runs non-root in compose; elevated discovery stages explicit opt-in | Privileged-capability engineering **[WP-005]** |

## 3. Plugins

| STRIDE | Threat | Control | Residual |
|---|---|---|---|
| Spoofing | Untrusted plugin loaded | Plugins are operator-configured paths in `plugin_dirs`; discovery off unless `enable_plugin_discovery` | No plugin signature verification **[security phase]** |
| Tampering | Plugin output forges findings | Plugin output is ingested as evidence with its own source attribution | Output not schema-validated end-to-end |
| Information disclosure | Plugin exfiltrates data | Runs under the agent's resource/isolation limits; no implicit network grant | Sandbox is resource-, not syscall-, isolation |
| Denial of service | Plugin hangs/forks | `max_memory_mb`/`max_cpu_percent` via cgroups/Job Objects; fail-closed isolation | — |
| Elevation of privilege | Plugin escalates | Inherits the agent's (non-root) privileges only | Full syscall sandbox **[security phase]** |

## 4. Migration path

| STRIDE | Threat | Control | Residual |
|---|---|---|---|
| Spoofing | Unauthorized migration command | HMAC signature verification before apply | Shared key **[WP-004]** |
| Tampering | Path traversal / arbitrary write | `allowed_config_roots` sandbox; file-extension allowlist (`.conf/.config/.json/.toml/.yaml/.xml`) | — |
| Tampering | Checklist/adapter tampering | Validation checklist tamper rejected; unsupported adapters fail before mutation (WP-LNX-006) | — |
| Repudiation | Silent config change | Atomic backup→write→validate→reload→verify; SHA-256 drift detection; audit log | — |
| Information disclosure | Migration leaks config | Backups local; no config content egressed | — |
| Denial of service | Bad migration breaks a service | Post-migration TLS handshake check; **automatic rollback** to backup on failure; passive default | Canary deployment automation pending **[WP-022]** |
| Elevation of privilege | Migration as escalation vector | Off by default; HMAC + sandbox + allowlist; dependency-safe wave activation (WP-022) | — |

## 5. Supply chain

| STRIDE | Threat | Control | Residual |
|---|---|---|---|
| Tampering | Compromised dependency | Pinned lockfiles (`go.sum`, `Cargo.lock`, `package-lock.json`); `make vuln` (govulncheck + cargo-audit + npm audit) | No reproducible-build attestation **[WP-001]** |
| Tampering | Protobuf contract drift | `make proto-check` fails the build on descriptor drift | — |
| Tampering | Doc/claim inflation | `verify-claims` linter ties claims to maturity (WP-025) | — |
| Information disclosure | Build leaks secrets | Signing key is runtime env, never built in | — |
| Denial of service | Detection regression ships | Versioned benchmark corpus with precision/recall gate (WP-014); fuzz + race tests | Field-scale corpus pending |
| Elevation of privilege | Malicious release artifact | Release-evidence bundle records gate outcomes per release (WP-025) | Artifact signing **[WP-001]** |

---

## Test & verification program (WP-019)

| Class | Status | Where |
|---|---|---|
| Unit | ✅ | Go (12 pkgs), Rust (80 tests) |
| Property / fuzz | ✅ | `policy.FuzzAssess` (seeded corpus) |
| Race / concurrency | ✅ | `make race`; ws hub broadcast, webhook circuit breaker, graceful-shutdown drain — all `-race` clean |
| Fault injection | ✅ (partial) | `WaitWebhooks` timeout drain; store-error paths via `writeError` |
| Detection benchmark | ✅ | `detection_benchmark` — precision/recall by detector & language (`docs/analysis/DETECTION-BENCHMARK.md`) |
| Performance baseline | ✅ | `BenchmarkAssess` (~110 µs/op, 200-component payload) — recorded in release evidence |
| Migration adapter | ✅ (Linux) | nginx/apache/ssh validate+reload+rollback (WP-LNX-006) |
| HA / failover | ❌ | requires multi-replica coordination **[WP-020]** |
| Chaos | ⚠️ partial | fault injection above; no systematic chaos harness yet |
| External penetration | ❌ | not yet commissioned |

### Running the security gates

```bash
make race            # -race across the server; serialized Rust tests
make vuln            # dependency vulnerability scan
make verify-claims   # documentation-claim lint (WP-025)
make release-evidence  # bundle gate outcomes + maturity snapshot (WP-025)
cd agent && cargo test detection_benchmark::benchmark_by_language_and_detector -- --nocapture
cd server && go test -bench=BenchmarkAssess -benchmem ./internal/policy/
```

## Residual risk summary

The unresolved **critical/high** items are concentrated in the **security phase**
(WP-003…012: per-agent identity, authenticated secret storage, full plugin
sandboxing, enterprise IAM) and in **HA/scale** (WP-020). Until those land,
Janus is suitable for evaluation and controlled deployments, not as an internet-
exposed multi-tenant control plane. See `docs/CAPABILITY_MATURITY.md` for the
per-dimension self-assessment.
