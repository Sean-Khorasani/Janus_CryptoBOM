# Security Policy

## Supported Versions

Janus CryptoBOM is currently pre-1.0 research software. Security updates are provided on a best-effort basis for the **latest published 0.x release only**. There are no long-term support branches, no backport commitments, and no patch releases for prior 0.x lines. Breaking changes between minor versions are possible.

| Version range | Security update status |
|---|---|
| 0.14.x (current) | Best-effort security updates |
| < 0.14 | No updates — upgrade to current |
| 1.0 and above | Not yet released |

The overall capability maturity of this platform across all five dimensions sits at **Level 2–3 (Planned/Agile)**, which maps to the **experimental** product tier. See [`docs/GUIDE.md`](docs/GUIDE.md) §9 for the per-dimension breakdown. No component is claimed as production-certified at this time.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report security issues by email to:

```
security@janus-cbom.example
```

> **Note for maintainers:** Replace `security@janus-cbom.example` with the actual security contact address before publishing this document.

### What to include

- A description of the vulnerability and the affected component
- Steps to reproduce or a proof-of-concept (can be a private gist)
- Your assessment of the impact and severity
- Any suggested remediation, if known

### Response SLAs

| Milestone | Target |
|---|---|
| Initial acknowledgment | 5 business days |
| Triage and severity determination | 10 business days |
| Patch — critical (CVSS ≥ 9.0) | 30 days from disclosure |
| Patch — high (CVSS 7.0–8.9) | 90 days from disclosure |
| Patch — medium/low | Best-effort; no guaranteed deadline pre-1.0 |

We follow coordinated disclosure. We will notify you when a fix is ready, agree on a disclosure date, and credit you in the release notes unless you prefer otherwise.

## Security Considerations for Operators

These requirements must be met before deploying Janus in any environment where it has access to production systems or sensitive cryptographic material.

### Command Signing Key

`JANUS_COMMAND_SIGNING_KEY` is the shared secret that authorizes active migration commands. It must be:

- Generated with sufficient entropy:
  ```sh
  openssl rand -hex 32
  ```
- Set via environment variable or a secrets manager — **never committed to version control or stored in a config file that is checked in**.
- Rotated if it is ever exposed or if a principal who knew the key is offboarded.

The server will panic at startup if this variable is unset. The agent will refuse to start if `command_signing_key` is absent from its TOML config.

### Transport Security

- **mTLS is strongly recommended for production gRPC** (`:9443`). Set `JANUS_TLS_CERT_FILE`, `JANUS_TLS_KEY_FILE`, and `JANUS_CLIENT_CA_FILE`. Without mTLS, any client that can reach the gRPC port can register as an agent.
- The HTTP/WebSocket API (`:8080`) should be placed behind a TLS-terminating reverse proxy in production. The built-in server does not handle TLS on the HTTP port.

### Authentication

- `JANUS_DISABLE_AUTH` **must be `false` in production**. Setting it to `true` bypasses JWT verification on all HTTP endpoints. It exists only for local development.
- The JWT signing secret is derived from `JANUS_COMMAND_SIGNING_KEY`. Rotating the signing key invalidates all active sessions.
- **Least privilege:** state-changing admin actions (policy authoring/activation, fleet config & profiles, webhooks, retention, finding comments/assignment) require the `operator` or `admin` role. `viewer` accounts are read-only for these; finding-status triage is intentionally open to any authenticated user.

### LLM Features

LLM features are disabled by default (`JANUS_LLM_BASE_URL` unset). When enabling them:

- The `suggest_remediation` capability mode (`JANUS_LLM_CAPABILITY_MODE=suggest_remediation`) allows the LLM to propose config patch content. Enable this mode **only in airgapped deployments or where the model endpoint is fully trusted**, because analyzed source code is included in prompts. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §8 for the eight architectural invariants that govern LLM integration.
- `analysis_only` mode restricts LLM output to advisory annotations; it does not generate patch proposals and is safer for internet-connected deployments.
- LLM verdicts never directly modify database state — deterministic verification is required before any state change (ARCHITECTURE.md §8, Invariant 5).

### SQLite Encryption at Rest

The agent's offline queue and scan state are stored in an encrypted SQLite database:

- **Windows:** DPAPI (key bound to the machine identity and the user account running the agent).
- **Linux/macOS:** authenticated AES-256-GCM with a key derived from machine identity (or a key file via `JANUS_CACHE_KEY_FILE`).

The database file should be stored on an encrypted filesystem in addition to this application-layer encryption.

### CORS

`JANUS_CORS_ORIGIN` defaults to `http://localhost:5173`. In production, set this to the exact origin of your dashboard deployment. Wildcard origins are not permitted.

### Plugin Resource Limits

External plugins run with resource limits: cgroups v2 memory and CPU quotas on Linux; Windows Job Objects on Windows. Do not load plugins from untrusted sources. Plugin binaries are not code-signed by the platform.

## Out of Scope

The following configurations and scenarios are explicitly out of scope for this security policy:

- Deployments with `JANUS_DISABLE_AUTH=true` — this flag disables security controls by design and is documented as dev-only.
- The `software` HSM mode (`JANUS_HSM_MODE=software`, the default) — it does real ML-DSA crypto but keys are process-local and offer no stronger protection than the filesystem. Use `JANUS_HSM_MODE=pkcs11` with a real token for hardware-backed key protection.
- Issues that require physical access to the machine running the agent.
- Vulnerabilities in third-party dependencies that have no published CVE and no available upstream patch.
- LLM provider infrastructure (the model endpoint is outside Janus's trust boundary).
- Source-code findings generated by Janus — Janus reports on your code's crypto, not on its own.

## Security Architecture Notes

The following design properties are enforced by the implementation:

**Passive-by-default.** Active migration is off by default. The agent will scan and report, but will not mutate config files or certificate stores unless the operator explicitly enables active mode and the server issues a properly signed command.

**HMAC-signed migration commands.** Every `MigrationCommand` is HMAC-SHA256 signed with `command_signing_key`. The agent verifies the signature before acting on any command and rejects commands with invalid, missing, or replayed signatures. HMAC-SHA256 is a quantum-resistant symmetric MAC (not an RSA/ECDSA signature). Setting `JANUS_HSM_SIGN_COMMANDS=true` provisions the command key into the HSM and computes the MAC inside the token, so the key never resides in server memory — the wire value and agent verification are unchanged.

**Optional ML-DSA command signing.** With `JANUS_COMMAND_SIG_SCHEME=ml-dsa`, the server additionally signs each command with an ML-DSA (FIPS 204) key and the agent verifies it against an operator-pinned public-key fingerprint (`command_pqc_fingerprint`). Because agents hold only the public key, a compromised agent cannot forge commands; a fingerprint-pinned agent also rejects any command lacking the ML-DSA signature (downgrade protection). HMAC remains the mandatory baseline.

**Per-agent authentication (opt-in).** With `JANUS_AGENT_AUTH_MODE=per-agent`, each agent authenticates to the server's agent endpoints with its own HMAC key (derived from a server master via HKDF; the master stays server-side) and a replay-windowed request token, instead of a single shared token. Identities live in `agent_credentials` with a status, so a compromised agent can impersonate only itself and can be revoked instantly (`janus-server agent revoke`) without rotating the fleet. The default `shared` mode preserves the legacy single-key behaviour.

**Command replay window.** Independently of signing, the agent rejects a migration command whose `issued_at_unix` is older than `max_command_age_seconds` (default 300; 0 disables) or more than that far in the future. This bounds how long a captured, still-validly-signed command remains usable.

**Tamper-evident audit log.** Each audit entry stores a SHA-256 hash chained over the previous entry's hash and its own content, so editing, deleting, inserting, or reordering any row breaks the chain. Admins verify integrity on demand via `GET /api/audit-logs/verify`.

**Atomic rollback.** The mutation engine follows a backup → write → validate → reload → TLS verify sequence. If any step fails, the backup is restored automatically. No partial migration is left in place.

**Path traversal sandbox.** Mutations are restricted to paths under `allowed_config_roots` and a file-extension allowlist (`.conf`, `.config`, `.cnf`, `.json`, `.toml`, `.yaml`, `.yml`, `.xml`, `.ini`, `.properties`), plus the well-known extensionless configs `sshd_config`/`ssh_config`. Anything else — including other files with no extension — is rejected at the agent.

**Configurable HSM.** The HSM backend is selected by `JANUS_HSM_MODE` (`disabled`/`software`/`pkcs11`) and is fail-closed — `pkcs11` aborts startup if the token cannot be opened, so an operator who requires hardware-backed keys cannot silently fall back to software. Asymmetric signing is PQC-only (ML-DSA/SLH-DSA; RSA/ECDSA are refused). The PKCS#11 client is built into the standard binary on both platforms (a native `syscall` client on Windows, a cgo `miekg` client on Linux/macOS) and treats software/hardware/network HSMs identically. Production deployments should set `JANUS_HSM_MODE=pkcs11` against a hardware token.

**Config drift detection.** The agent computes SHA-256 checksums of config files before and after mutation and detects out-of-band changes. Drift causes the migration to abort.
