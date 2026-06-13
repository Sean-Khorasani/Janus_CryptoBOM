# Privacy and Data Governance

**WP-026 — Privacy and Data Governance Reference**

This document describes what data the Janus CryptoBOM agent collects, how it is classified, where it flows, how it is protected, and what operators must do to comply with their own privacy obligations. It is derived directly from the source code and configuration contracts; code paths are cited throughout.

---

## 1. Data Classification

Every evidence item produced by the agent carries a `DataClassification` label (`agent/src/evidence.rs`, `DataClassification` enum). This label drives LLM consent decisions and retention policy.

| Classification | What it contains | Sensitivity | External LLM allowed? |
|---|---|---|---|
| `CryptoMetadata` | Algorithm names, key sizes, cipher suite identifiers. No source code, config values, or PII. | Low | Yes (with `BinaryLLMPolicy.enabled`) |
| `CodeSnippet` | Source file excerpt (≤512 bytes), relative file path, line range. May contain code that references endpoints or internal names. | Internal | Only with explicit opt-in |
| `ConfigContent` | Configuration file excerpt. May contain hostnames, ports, algorithm choices, credential references. | Confidential | Only with explicit opt-in |
| `NetworkEndpoint` | Hostname, port, TLS version, negotiated cipher suite. No certificate private material. | Internal | Yes (with `BinaryLLMPolicy.enabled`) |
| `KeyFingerprint` | Hash or truncated key identifier. Never raw key material. | Internal | Yes (with `BinaryLLMPolicy.enabled`) |

The sensitivity tier (`SensitivityLabel`) is a separate but related enum: `Public`, `Internal`, `Confidential`, `Restricted`. All `BoundedEvidencePackage` constructors default to `SensitivityLabel::Internal` unless overridden by the caller.

### Classification by Discovery Module

| Discovery module | `EvidenceSource` | Default `DataClassification` |
|---|---|---|
| Source code pattern scan (`discovery/source.rs`) | `SourceCodePattern` | `CodeSnippet` |
| Configuration file scan | `ConfigFile` | `ConfigContent` |
| Binary import table (`discovery/binary.rs`) | `BinaryImport` | `CryptoMetadata` |
| TLS handshake probe (`discovery/network.rs`) | `TlsHandshake` | `NetworkEndpoint` |
| Dependency manifest (`discovery/dependency.rs`) | `DependencyManifest` | `CryptoMetadata` |
| Process memory scan (`discovery/runtime.rs`) | `ProcessMemory` | `Restricted` (inferred; not transmitted to LLM) |
| Windows registry / netsh / certutil (`discovery/windows.rs`) | `WindowsRegistry` | `CryptoMetadata` |
| Side-channel pattern analysis (`discovery/sidechannel.rs`) | `SideChannelPattern` | `CodeSnippet` |

---

## 2. Collection Minimization

### What the agent collects

- Algorithm identifiers (names, key sizes, cipher suite strings)
- Relative file paths where a crypto pattern was detected
- Source line ranges (start and end line numbers)
- Context snippets: at most **512 bytes** of source context around a match (`MAX_CONTEXT_BYTES` in `agent/src/evidence.rs`, line 80)
- TLS negotiation metadata: protocol version, cipher suite, certificate subject/issuer DN, certificate fingerprint, expiry
- Binary import/export symbol names that match crypto library patterns
- Dependency package name and version (no package contents)
- Process executable name and path (runtime discovery only, when opted in)

### What the agent does NOT collect

- Raw cryptographic key material (private keys, symmetric keys, session keys)
- Certificate private keys (PEM private key blocks are redacted; see §5)
- Plaintext passwords or credentials (redacted; see §5)
- File contents beyond the 512-byte context window
- Absolute file paths (constructors use relative paths; `BoundedEvidencePackage.file_path` is documented as "relative file path (sanitized, no absolute paths)")
- Process heap contents beyond PEM private key header detection (`/proc/PID/mem` is searched only for PEM private key header bytes; matching memory windows are reported as findings, not transmitted in full)
- Network traffic payloads (TLS probing reads negotiated parameters only, not application data)

### Scan depth limits

| Parameter | Default | Configurable range |
|---|---|---|
| `max_file_bytes` | 2 MiB | 1 KiB – 10 GiB |
| `max_binary_bytes` | 16 MiB | 1 KiB – 10 GiB |
| Context snippet cap | 512 bytes | Fixed (code constant) |

These limits are validated at startup in `AgentConfig::validate()` (`agent/src/config.rs`, line 247).

---

## 3. Consent Requirements

### 3.1 Invasive Discovery Modes

The following capabilities are **disabled by default** and require explicit operator opt-in in the agent TOML configuration:

| Capability | Config key | Default | Requirement |
|---|---|---|---|
| Runtime process scanning | `enable_runtime_discovery` | `false` | Opt-in |
| Process memory scraping | `enable_process_memory_scraping` | `false` | Opt-in; also requires `enable_runtime_discovery = true` |
| External plugin commands | `enable_plugin_discovery` | `false` | Opt-in |
| Active TLS probing | `enable_active_tls_probing` | `false` | Opt-in |

Attempting to set `enable_process_memory_scraping = true` without `enable_runtime_discovery = true` causes a startup validation error (`agent/src/config.rs`, line 262–267). Process memory scraping on Linux reads `/proc/PID/maps` and uses `pread` on `/proc/PID/mem` which requires elevated privilege (typically root or `CAP_SYS_PTRACE`).

### 3.2 LLM-Assisted Analysis

LLM-assisted binary analysis is controlled by `BinaryLLMPolicy` (`agent/src/config.rs`, lines 76–117). All fields default to `false` or the most restrictive setting. The struct has no values set in the `Default` implementation that would enable transmission.

```toml
[binary_llm_policy]
enabled = false                 # Master switch — must be true for any LLM analysis
allow_string_extraction = false # PE/ELF/Mach-O extracted strings
allow_import_table = true       # Import/export table entries (enabled by default when master enabled)
allow_hexdump_window = false    # Bounded hexdump window around suspicious bytes
max_context_bytes = 1024        # Per-section context cap for LLM (overrides evidence 512-byte cap)
require_audit_consent = true    # Log consent to audit trail before first use
```

`BinaryLLMPolicy.enabled` must be explicitly set to `true` for any LLM analysis to run. The `require_audit_consent` flag (default `true`) requires that the consent decision be recorded in the agent's SQLite audit trail (`sync_audit` table) before the first LLM request is made.

### 3.3 LLM API Key Security

The LLM API key is loaded by the server, not the agent. On the server side:
- `JANUS_LLM_API_KEY_FILE` (path to a file) takes precedence over `JANUS_LLM_API_KEY` environment variable.
- The key is never logged or included in error messages.
- LLM features are entirely disabled when `JANUS_LLM_BASE_URL` is empty (the default).

---

## 4. Data Flows

```
[Scan target files/binaries/processes/network]
         |
         v
[Agent discovery modules]
  - Produces CryptoFinding records
  - Context snippets capped at 512 bytes
  - Paths sanitized to relative form
         |
         v
[redact_secrets() — caller responsibility]
  Must be called before including context_snippet
  in BoundedEvidencePackage sent externally.
         |
         v
[BoundedEvidencePackage]
  - DataClassification label applied
  - context_snippet <= 512 bytes (enforced by from_source())
         |
    [Optional LLM path — requires BinaryLLMPolicy.enabled = true]
    |    |
    |    v
    | [JANUS_LLM_BASE_URL (operator-configured)]
    |   Only bounded evidence package fields are sent.
    |   Raw file contents are never transmitted.
    |
    v (main path)
[CbomTelemetryPayload (proto/janus.proto)]
         |
         v
[OfflineStore — agent/src/storage.rs]
  - SQLite database (default: janus-agent.sqlite3)
  - Windows: CryptProtectData (DPAPI) — user/machine-scoped
  - Linux:   AES-256-GCM (ring), key derived from JANUS_CACHE_KEY_FILE
             or /etc/machine-id fallback; prefix "aead-v1:"
             (Legacy AES-CTR with prefix "aes256ctr:" retained for
              upgrade compatibility only — no authentication tag)
         |
         v
[gRPC StreamTelemetry (proto/janus.proto)]
  - mTLS optional (tls_client_cert + tls_client_key config)
  - Default: TLS with server cert only
         |
         v
[Server — server/internal/grpcserver/]
         |
         v
[PostgreSQL — server/internal/store/]
  - Retention: operator-controlled
  - Schema migrations versioned (EnsureSchema)
```

No telemetry is sent to Anthropic, any cloud provider, or any third party unless `JANUS_LLM_BASE_URL` is set by the operator.

---

## 5. Redaction

`redact_secrets()` in `agent/src/evidence.rs` (line 218) strips known secret patterns from a source context string. It is a standalone helper — it is **not called automatically** by the `BoundedEvidencePackage` constructors. Callers that build evidence packages from source context (particularly `from_source()`) are responsible for passing the snippet through `redact_secrets()` before inclusion.

### Patterns detected and redacted

| Pattern | Regex (simplified) | Replacement |
|---|---|---|
| PEM private key block | `-----BEGIN * PRIVATE KEY-----` ... `-----END * PRIVATE KEY-----` | `[REDACTED]` |
| Password assignment | `password[:=]<value>` (case-insensitive) | `password[:=][REDACTED]` |
| Secret assignment | `secret[:=]<value>` (case-insensitive) | `secret[:=][REDACTED]` |
| API key assignment | `api_key[:=]<value>` or `apikey[:=]<value>` (case-insensitive) | `api_key[:=][REDACTED]` |

The PEM regex uses dotall mode (`(?s)`) so it spans newlines, matching multiline key blocks. All patterns use case-insensitive matching.

### Limitations

`redact_secrets()` is a best-effort pattern matcher. It does not detect:
- Base64-encoded credentials that are not prefixed with a recognizable key name
- JWT tokens or bearer tokens not named `api_key` or `secret`
- Hex-encoded keys or secrets without recognizable prefix labels
- Custom credential naming conventions outside the four patterns above

Operators should treat config-file evidence (`ConfigContent` classification) with additional care and consider whether `enable_active_tls_probing` and config-file scanning scope is appropriate for their environment.

---

## 6. LLM and External Transmission

When `JANUS_LLM_BASE_URL` is set on the server and `BinaryLLMPolicy.enabled = true` on the agent, the following rules govern what may leave the local environment:

1. Only `BoundedEvidencePackage` fields are transmitted. This struct explicitly excludes raw file contents.
2. The `context_snippet` field is capped at `MAX_CONTEXT_BYTES` (512 bytes in `evidence.rs`; the binary LLM policy has its own `max_context_bytes` default of 1024 bytes — the tighter limit from the evidence package cap applies for source findings).
3. `file_path` is a relative sanitized path, not an absolute system path.
4. `sensitivity` and `data_classification` fields are included so the receiving LLM context can be constrained by the server's prompt.
5. `ConfigContent`-classified evidence requires operator acknowledgment of the risk before the LLM send path is permitted.
6. The server's LLM proxy (`server/internal/httpapi/`) enforces `JANUS_LLM_TIMEOUT_SECONDS` (default 30s), `JANUS_LLM_MAX_RETRIES` (default 2), and `JANUS_LLM_MAX_CONCURRENT` (default 4).

### Prompt injection defense

Source code snippets submitted to LLM analysis could contain adversarial content (prompt injection payloads embedded in source comments or string literals). Mitigations:

- Evidence packages carry pre-computed `data_classification` and `evidence_source` labels. The server's system prompt includes these labels to constrain the LLM's interpretation frame.
- `context_snippet` is limited to 512 bytes, reducing the attack surface for large embedded payloads.
- The LLM is accessed only by the server (not directly by the agent). The server acts as a trust boundary: agent-submitted evidence is structured protobuf data, not free-form prompts.
- Raw source files are never transmitted; only the bounded, structured evidence package reaches the LLM.
- `redact_secrets()` should be called before populating `context_snippet` to remove any accidental credential material that could be exploited in a crafted response.

These mitigations reduce but do not eliminate prompt injection risk. Operators should review `JANUS_LLM_MODEL_ANALYSIS` and `JANUS_LLM_MODEL_REMEDIATION` configuration and apply least-privilege API key scoping.

---

## 7. Retention and Deletion

### Agent (SQLite)

The agent's offline queue (`telemetry_queue` table) retains encrypted payloads until they are successfully uploaded to the server and acknowledged. After acknowledgment, `delete_payload()` removes the record.

The `scan_state` table stores per-file SHA-256 content hashes used for change detection. Stale entries (files that no longer exist) can be purged via `purge_stale_scan_state()`.

SQLite `VACUUM` runs every 24 hours (tracked via the `scan_stats` table with key `last_vacuum_unix`; see `storage.rs` lines 71–86). This compacts freed pages and removes deleted row data from the SQLite file on disk.

**Operator guidance:**
- To fully wipe agent local data: delete the SQLite file (default: `janus-agent.sqlite3`). The agent will recreate schema on next start.
- To remove specific findings from the queue: use `delete_payload()` (programmatic) or delete and recreate the database.
- No automated TTL is applied to `telemetry_queue` — payloads that fail to upload indefinitely accumulate. Operators should monitor queue depth via the server's fleet health endpoint.

### Server (PostgreSQL)

The server does not impose a default retention period. All data is stored until deleted by an operator or by application-level DELETE operations via the REST API.

**Operator guidance:**
- Implement PostgreSQL-level retention policies appropriate to your compliance requirements (e.g., `pg_cron` jobs to delete findings older than N days).
- The `findings` table stores `CryptoFinding` records including file paths and context. Review the schema (`server/internal/store/`) before scoping retention.
- Backup and restore procedures should account for the encrypted nature of agent-side data (DPAPI/AES-256-GCM) — server-side PostgreSQL data is not encrypted at rest by default; use PostgreSQL transparent data encryption or filesystem encryption at the infrastructure level.

---

## 8. Data Residency

Janus CryptoBOM is **self-hosted**. No data leaves the operator's infrastructure by default.

| Component | Default residency |
|---|---|
| Agent SQLite cache | Local disk of the scanned host |
| Server PostgreSQL | Operator's PostgreSQL instance |
| gRPC stream | Internal network (agent → server, operator-controlled) |
| LLM calls | None by default; only when `JANUS_LLM_BASE_URL` is set |

When LLM features are enabled:
- `JANUS_LLM_BASE_URL` is fully operator-controlled. Point to an on-premises LLM (e.g., a local Ollama instance or private OpenAI-compatible endpoint) to maintain residency.
- If pointed at a cloud LLM provider (e.g., OpenAI, Azure OpenAI), bounded evidence packages will be transmitted to that provider's infrastructure. Operators must ensure their privacy agreements with that provider cover this data.
- No Anthropic API is used by Janus CryptoBOM. The AI powering this development tooling (Claude Code) is not the same as the LLM called at runtime.

---

## 9. Operator Responsibilities

### Command signing key

`JANUS_COMMAND_SIGNING_KEY` (server) / `command_signing_key` (agent TOML) is the shared secret used for HMAC-SHA256 signing of migration commands. It must be:
- At least 16 bytes; recommended 32 bytes (256-bit) generated with `openssl rand -hex 32`
- Different per deployment environment (dev/staging/production)
- Rotated if compromised; any buffered migration commands signed with the old key will fail HMAC verification and be rejected
- Never logged, embedded in code, or committed to version control

On the agent side, the key can be stored as a DPAPI-encrypted blob (`dpapi:` prefix) on Windows, or read from a file via `JANUS_COMMAND_SIGNING_KEY_FILE`. The file-based approach is preferred for Linux deployments.

### mTLS

The agent supports mutual TLS via `tls_client_cert` and `tls_client_key` in the TOML config. When configured:
- The gRPC channel is mutually authenticated; the server verifies the agent's certificate against `JANUS_CLIENT_CA_FILE`.
- Without mTLS, any process that can reach the gRPC port can attempt to stream telemetry or receive migration commands.
- Production deployments should enable mTLS, especially when agents run on untrusted networks.

### Encryption at rest

| Platform | Mechanism | Key source |
|---|---|---|
| Windows | DPAPI (`CryptProtectData`) | Windows user/machine credentials |
| Linux (current) | AES-256-GCM (`aead-v1:` prefix) | `JANUS_CACHE_KEY_FILE` (≥32 bytes) or `/etc/machine-id` fallback |
| Linux (legacy) | AES-256-CTR (`aes256ctr:` prefix, unauthenticated) | `/etc/machine-id` |

Operators on Linux should provide `JANUS_CACHE_KEY_FILE` pointing to a 32-byte random key stored outside the scan path. The machine-id fallback provides encryption but the key derivation depends on a value that may be predictable or accessible to other local processes. The legacy `aes256ctr:` format lacks an authentication tag; upgrading to the `aead-v1:` format (done by re-encrypting) is recommended.

### LLM API key security

- Use `JANUS_LLM_API_KEY_FILE` rather than `JANUS_LLM_API_KEY` env var to keep the key out of process environment listings.
- Scope the API key to the minimum permissions required (read access to the models in use; no fine-tuning or admin access).
- Rotate the key immediately if any LLM provider request logs the full API key value (some providers log headers on error).

### Audit trail

The agent's `sync_audit` table in SQLite records synchronization events. Operators should:
- Periodically export `sync_audit` entries to a centralized log store before database rotation.
- Monitor for `consent` events confirming LLM opt-in was recorded before first use (when `require_audit_consent = true`).

---

## 10. Summary: Data Protection Controls Matrix

| Control | Mechanism | Location |
|---|---|---|
| Context size cap | 512 bytes hard limit | `evidence.rs:80`, `BoundedEvidencePackage::from_source()` |
| Secret redaction | `redact_secrets()` — caller must invoke | `evidence.rs:218` |
| Encryption at rest (Windows) | DPAPI | `storage.rs:211–247` |
| Encryption at rest (Linux) | AES-256-GCM | `storage.rs:291–319` |
| LLM opt-in gate | `BinaryLLMPolicy.enabled = false` (default) | `config.rs:76–117` |
| Invasive discovery opt-in | All disabled by default | `config.rs:168–205` |
| Migration command authentication | HMAC-SHA256 | `mutation.rs`, `orchestrator/` |
| No absolute paths in evidence | Relative path in `file_path` | `evidence.rs:67` |
| mTLS support | Operator-configured | `comms.rs`, `grpcserver/` |
| Audit consent logging | `require_audit_consent = true` (default) | `config.rs:94` |
