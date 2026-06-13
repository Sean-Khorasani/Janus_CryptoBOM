# Security Policy

## Supported Versions

Janus CryptoBOM is currently pre-1.0 research software. Security updates are provided on a best-effort basis for the **latest published 0.x release only**. There are no long-term support branches, no backport commitments, and no patch releases for prior 0.x lines. Breaking changes between minor versions are possible.

| Version range | Security update status |
|---|---|
| 0.14.x (current) | Best-effort security updates |
| < 0.14 | No updates — upgrade to current |
| 1.0 and above | Not yet released |

The overall capability maturity of this platform across all five dimensions sits at **Level 2–3 (Planned/Agile)**, which maps to the **experimental** product tier. See `docs/CAPABILITY_MATURITY.md` for the per-dimension breakdown. No component is claimed as production-certified at this time.

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

### LLM Features

LLM features are disabled by default (`JANUS_LLM_BASE_URL` unset). When enabling them:

- The `suggest_remediation` capability mode (`JANUS_LLM_CAPABILITY_MODE=suggest_remediation`) allows the LLM to propose config patch content. Enable this mode **only in airgapped deployments or where the model endpoint is fully trusted**, because analyzed source code is included in prompts. See `docs/LLM_CAPABILITY_CONTRACT.md` for the eight architectural invariants that govern LLM integration.
- `analysis_only` mode restricts LLM output to advisory annotations; it does not generate patch proposals and is safer for internet-connected deployments.
- LLM verdicts never directly modify database state — deterministic verification is required before any state change (LLM_CAPABILITY_CONTRACT.md Invariant 5).

### SQLite Encryption at Rest

The agent's offline queue and scan state are stored in an encrypted SQLite database:

- **Windows:** DPAPI (key bound to the machine identity and the user account running the agent).
- **Linux/macOS:** AES-CTR with a key derived from machine identity.

The database file should be stored on an encrypted filesystem in addition to this application-layer encryption.

### CORS

`JANUS_CORS_ORIGIN` defaults to `http://localhost:5173`. In production, set this to the exact origin of your dashboard deployment. Wildcard origins are not permitted.

### Plugin Resource Limits

External plugins run with resource limits: cgroups v2 memory and CPU quotas on Linux; Windows Job Objects on Windows. Do not load plugins from untrusted sources. Plugin binaries are not code-signed by the platform.

## Out of Scope

The following configurations and scenarios are explicitly out of scope for this security policy:

- Deployments with `JANUS_DISABLE_AUTH=true` — this flag disables security controls by design and is documented as dev-only.
- The SoftHSM2 software HSM fallback used in development — it provides no stronger key protection than the filesystem.
- Issues that require physical access to the machine running the agent.
- Vulnerabilities in third-party dependencies that have no published CVE and no available upstream patch.
- LLM provider infrastructure (the model endpoint is outside Janus's trust boundary).
- Source-code findings generated by Janus — Janus reports on your code's crypto, not on its own.

## Security Architecture Notes

The following design properties are enforced by the implementation:

**Passive-by-default.** Active migration is off by default. The agent will scan and report, but will not mutate config files or certificate stores unless the operator explicitly enables active mode and the server issues a properly signed command.

**HMAC-signed migration commands.** Every `MigrationCommand` is HMAC-SHA256 signed with `command_signing_key`. The agent verifies the signature before acting on any command and rejects commands with invalid, missing, or replayed signatures.

**Atomic rollback.** The mutation engine follows a backup → write → validate → reload → TLS verify sequence. If any step fails, the backup is restored automatically. No partial migration is left in place.

**Path traversal sandbox.** Mutations are restricted to paths under `allowed_config_roots` and a file-extension allowlist (`.conf`, `.config`, `.json`, `.toml`, `.yaml`, `.xml`). Paths outside the allowlist are rejected at the agent.

**HSM interface.** The server exposes an HSM interface (`server/internal/hsm/`) backed by PKCS#11 via SoftHSM2 (Windows syscall path) or a software fallback. Production deployments should bind this interface to a hardware HSM.

**Config drift detection.** The agent computes SHA-256 checksums of config files before and after mutation and detects out-of-band changes. Drift causes the migration to abort.
