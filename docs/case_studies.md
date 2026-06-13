# Janus CryptoBOM: Enterprise Case Studies & Playbooks

This document contains 12 production-grade deployment case studies covering passive compliance, active PQC migration, HSM integration, side-channel detection, and real-time fleet observability.

---

## Scenario Summary Matrix

| ID | Title | Complexity | Core Technology | New in v0.2 |
|:---|:---|:---|:---|:---|
| **1** | [Passive CI/CD Compliance Check](#1-passive-cicd-compliance-check) | Simple | CLI / GitHub Action | SARIF upload, compliance gate |
| **2** | [Host Certificate Store Audit](#2-host-certificate-store-audit) | Simple | certutil / PowerShell | CNSA 2.0 curve checks |
| **3** | [Open Listening Sockets Discovery](#3-open-listening-sockets-discovery) | Simple | Socket API / Get-NetTCPConnection | FHE library detection |
| **4** | [Fleet TLS Policy Sweeping](#4-fleet-tls-policy-sweeping) | Medium | Schannel Registry Mutator | CNSA-aware profiles |
| **5** | [Shadow Crypto DLL Auditing](#5-shadow-crypto-dll-auditing) | Medium | Toolhelp32 / Symbol Audit | Side-channel detection (F16) |
| **6** | [Supply Chain OSV.dev Sync](#6-supply-chain-osvdev-sync) | Medium | OSV.dev API | CVSS 3.x score parsing, confidence thresholds (F28) |
| **7** | [Nginx PQC Migration with Rollback](#7-nginx-pqc-migration-with-rollback) | Complex | EST/ACME, Diff, Nginx | Sandbox simulation (F1), confidence scoring (F7) |
| **8** | [Schannel Policy Failover Rollback](#8-schannel-policy-failover-rollback) | Complex | Registry Backup / Loopback | Regex-based reg query (F3.10) |
| **9** | [Memory Scraping for Plaintext Keys](#9-memory-scraping-for-plaintext-keys) | Complex | ReadProcessMemory / /proc/PID/mem | Linux memory scanning (F9) |
| **10** | [Remote CA Root Rotation](#10-remote-ca-root-rotation) | Complex | PowerShell / ML-DSA | HSM-based signing (F13) |
| **11** | [HSM-Protected Key Lifecycle](#11-hsm-protected-key-lifecycle) | Complex | PKCS#11 / SoftHSM2 | Full HSM integration (F13) |
| **12** | [Real-Time Fleet Observability](#12-real-time-fleet-observability) | Medium | WebSocket / slog / i18n | WS hub, structured logging (F4.1-F4.3) |

---

## 1. Passive CI/CD Compliance Check

**Objective:** Integrate `janus-agent check` into CI/CD to block non-compliant commits.

**Execution:**
```bash
janus-agent check ./src --format sarif --output janus-findings.sarif
```

**CI Pipeline** (`.github/workflows/janus-scan.yml`):
```yaml
- name: Run Janus Crypto Scan
  run: janus-cli check . --format sarif --output janus-findings.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: janus-findings.sarif }
```

**Exit codes:** 0 = clean, 1 = findings detected. Now scans source + binary + dependencies.

---

## 2. Host Certificate Store Audit

**Objective:** Audit Windows certificate stores for weak algorithms (SHA-1, RSA <2048) and CNSA non-compliance.

**Commands:**
```powershell
certutil -store My
certutil -store Root
```

**CNSA 2.0 checks:** ECDSA curves below P-384 flagged as JANUS-CNSA-001. SHA-256 in hash roles flagged as JANUS-CNSA-002 when CNSA profile active.

---

## 3. Open Listening Sockets Discovery

**Objective:** Identify cleartext/unencrypted listening ports.

**Windows:** `Get-NetTCPConnection -State Listen`
**Linux:** `ss -tlnp`

**New in v0.2:** FHE library detection (F23) — detects TFHE-rs, Concrete, OpenFHE, SEAL, Lattigo, HElib in process dependencies.

---

## 4. Fleet TLS Policy Sweeping

**Objective:** Enforce TLS 1.3 across Windows fleet via Schannel registry.

**Profile-aware:** Migration commands now use active policy's `preferred_kem` and `preferred_signature` (e.g., CNSA 2.0: ML-KEM-1024 + ML-DSA-87).

**Confidence thresholds (F28):** Findings below `minimum_confidence` (default 0.4) are filtered. Configurable per policy profile YAML.

---

## 5. Shadow Crypto DLL Auditing

**Objective:** Detect unapproved crypto DLLs in running processes.

**Side-channel detection (F16):** New `agent/src/discovery/sidechannel.rs` module detects timing side-channel vulnerabilities:
- **CRITICAL:** Branching on raw key bytes, switch on secret-derived values
- **HIGH:** Non-constant-time comparison of MACs/hashes
- **MEDIUM:** Table lookups indexed by secret data
- **LOW:** Direct equality on ciphertext

---

## 6. Supply Chain OSV.dev Sync

**Objective:** Query OSV.dev for known CVEs in cryptographic dependencies.

**OSV severity parsing (fixed):** CVSS 3.x/4.x scores now properly parsed via `strconv.ParseFloat` and mapped to Janus severity:
- 9.0+ → Critical (5)
- 7.0-8.9 → High (4)
- 4.0-6.9 → Medium (3)
- 0.0-3.9 → Low (2)

**Confidence analysis (F7):** `GET /api/confidence/report` returns aggregate confidence stats per rule.

---

## 7. Nginx PQC Migration with Rollback

**Objective:** Migrate Nginx from RSA-2048/TLS 1.2 to hybrid PQC TLS 1.3 with automated rollback.

**Sandbox simulation (F1):** `POST /api/sandbox/simulate` previews migration without execution:
```json
{
  "simulation_id": "sim-...",
  "recommended_kem": "ML-KEM-1024",
  "recommended_signature": "ML-DSA-87",
  "migration_patch": "--- nginx.conf\n+++ nginx.conf\n...",
  "estimated_impact": "LOW",
  "validation_checklist": ["config-syntax","daemon-reload","tls13-handshake"]
}
```

**Runtime interception (F5):** `agent/src/interceptor.rs` hooks `SSL_CTX_set_cipher_list` to inject PQC ciphers in active mode.

---

## 8. Schannel Policy Failover Rollback

**Objective:** Update Windows Schannel registry with PQC parameters, auto-rollback on failure.

**Regex-based reg parsing (F3.10):** `REG_DWORD\s+0x([0-9a-fA-F]+)` pattern replaces fragile whitespace splitting for locale-independent parsing.

---

## 9. Memory Scraping for Plaintext Keys

**Objective:** Detect unencrypted private keys in process memory.

**Linux memory scanning (F3.9):** Reads `/proc/PID/maps` for readable regions, then `/proc/PID/mem` via `pread` searching for PEM headers:
- `-----BEGIN PRIVATE KEY-----`
- `-----BEGIN RSA PRIVATE KEY-----`
- `-----BEGIN EC PRIVATE KEY-----`
- `-----BEGIN DSA PRIVATE KEY-----`
- `-----BEGIN OPENSSH PRIVATE KEY-----`

---

## 10. Remote CA Root Rotation

**Objective:** Deploy ML-DSA root CA certificate with atomic rollback.

**HSM integration (F13):** `POST /api/hsm/keys/generate` generates keys in SoftHSM2 or hardware HSM. `POST /api/hsm/sign` signs with HSM-protected keys.

---

## 11. HSM-Protected Key Lifecycle

**Objective:** Full PKCS#11 key lifecycle management for PQC and classical keys.

**HSM endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/hsm/keys` | List all keys |
| POST | `/api/hsm/keys/generate` | Generate key pair |
| POST | `/api/hsm/sign` | Sign data |
| POST | `/api/hsm/verify` | Verify signature |

**SoftHSM2 setup:** `HSM/setup-softHSM2.ps1` auto-detects vcpkg/Chocolatey/GitHub source and initializes tokens.

**Mock mode:** In-memory SoftHSM2 implementation for development/testing without hardware.

---

## 12. Real-Time Fleet Observability

**Objective:** Live dashboard updates via WebSocket with structured logging and i18n.

**WebSocket hub (F4.2):** `server/internal/ws/hub.go` — stdlib-only RFC 6455 implementation. Events:
- `telemetry_update` — new scan data ingested
- `finding_status` — operator triage changes
- `migration_enqueued` / `migration_status` — lifecycle
- `policy_switched` — active profile change
- `lab_simulation` — PQC lab results

**Structured logging (F4.1):** Server: `log/slog` JSON handler. Agent: `tracing` crate. Configurable via `JANUS_LOG_LEVEL`/`RUST_LOG`.

**Dark mode (F30):** CSS custom properties with comprehensive `dark:` Tailwind variants across all components. Semantic color variables, glass-morphism, shimmer skeletons.

**i18n (F31):** 4 locales (en, fa, zh, es), 42 translation keys, locale switcher in header.

**Accessibility (F32):** WCAG 2.1 AA — FocusTrap, SkipLink, A11yAnnouncer, keyboard navigation, ARIA attributes everywhere.

**SIEM Export:** `GET /api/export/siem` streams JSON-lines. Webhook dispatch with circuit breaker (3 retries, 5-failure cooldown). Audit log CSV/JSON export at `GET /api/export/audit`.

---

## Document References

- [Design Manual](design.md) — Architecture, DB schema, API contracts, sequence diagrams
- [Deployment Guide](deployment.md) — HA topologies, env vars, systemd/GPO/Docker
- [Competitive Analysis](competitive-analysis.md) — 10-competitor comparison, 24-feature roadmap
- [Main README](../README.md) — Platform overview, quickstart, API reference
