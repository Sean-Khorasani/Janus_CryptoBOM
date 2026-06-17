# Janus CryptoBOM — Troubleshooting Runbook (DOC-004)

Common failures, what they mean, and how to fix them. Errors are grouped by component.
Most server messages are structured JSON (`log/slog`); the agent uses `tracing` (set
`RUST_LOG=debug` for detail). Every server HTTP response carries an `X-Correlation-ID` —
quote it when reporting an issue; it appears in the server logs for the same request.

---

## Server won't start (startup panics)

The server **fails closed**: a misconfiguration aborts startup rather than running insecurely.

| Symptom (log/panic) | Cause | Fix |
|---|---|---|
| `JANUS_COMMAND_SIGNING_KEY environment variable is required` | No command-signing key set | `export JANUS_COMMAND_SIGNING_KEY=$(janus-server gen-hmac-key)` (or `*_FILE`) |
| `JANUS_COMMAND_SIGNING_KEY must be at least 16 bytes` | Key too short | Use a 32-byte hex key (`janus-server gen-hmac-key`) |
| `JANUS_JWT_SECRET must be at least 16 bytes` | Explicit JWT secret too short | Unset it (defaults to the command key) or set ≥16 bytes |
| `JANUS_AGENT_AUTH_MODE=per-agent requires JANUS_AGENT_KEY_MASTER` | Per-agent mode without a master key | Set `JANUS_AGENT_KEY_MASTER`(`_FILE`), or use `JANUS_AGENT_AUTH_MODE=shared` |
| `JANUS_AGENT_AUTH_MODE must be 'shared' or 'per-agent'` | Typo | Use one of the two values |
| `JANUS_REQUIRE_TLS is set but JANUS_TLS_CERT_FILE and JANUS_TLS_KEY_FILE are not both configured` | TLS required but not configured | Provide both cert + key (see `janus-server pki init`) or unset `JANUS_REQUIRE_TLS` |
| `JANUS_REQUIRE_MTLS is set but JANUS_CLIENT_CA_FILE is not configured` | mTLS required without a client CA | Set `JANUS_CLIENT_CA_FILE` or unset `JANUS_REQUIRE_MTLS` |
| `HSM backend initialization failed` (`mode=pkcs11`) | PKCS#11 token/module unreachable | Check `JANUS_HSM_MODULE_PATH`, slot (`hsm info`), and PIN. `pkcs11` is fail-closed by design — it will not fall back to software |
| `read JANUS_CONFIG_FILE ...: no such file` | `JANUS_CONFIG_FILE` points nowhere | Fix the path; see `server/janus-server.env.example` |
| `connect postgres` then exit | DB unreachable / bad URL | Verify `JANUS_DATABASE_URL`, that PostgreSQL is up, and the role/db exist (see QUICKSTART) |

**Config precedence reminder:** environment variable **>** config file (`JANUS_CONFIG_FILE`)
**>** built-in default. If a setting "won't take", an env var of the same name is overriding
your file. This applies to *all* settings, including `JANUS_HSM_*` and `JANUS_COMMAND_SIG_*`.

---

## Login / dashboard auth

| Symptom | Cause | Fix |
|---|---|---|
| Login always returns 401 with correct password | No credentials configured (fail-closed) | Set `JANUS_ADMIN_PASSWORD` (or `_PASSWORD_HASH`); there are **no** compiled-in defaults |
| `429 Too Many Requests` on `/api/auth/login` | Rate limit (per-IP, brute-force guard) | Wait ~1 min; the limit is per client IP |
| 403 on an admin/operator action | Role too low | Use an `operator`/`admin` login; viewers are read-only |
| Session expires quickly | `JANUS_JWT_TTL` too low | Raise it (clamped 5m–720h) |
| Browser blocked by CORS | `JANUS_CORS_ORIGIN` mismatch | Set it to the dashboard origin (default `http://localhost:5173`) |

---

## Agent ↔ server connectivity

| Symptom | Cause | Fix |
|---|---|---|
| Agent: `connect <endpoint>` / gRPC unavailable | Wrong endpoint or server down | Check `controller_endpoint` in `janus-agent.toml`; confirm `JANUS_GRPC_ADDR` is reachable |
| Agent: TLS handshake / cert verify error | Server cert not trusted | Point `tls_ca_cert` at the Root CA (`pki init` → `root-ca.crt`); use an `https://` endpoint |
| gRPC `Unauthenticated` (per-agent mode) | Missing/wrong per-agent credentials, or revoked | Re-run `janus-server agent enroll`; set `agent_id`/`agent_key`; check `agent list` for status |
| Agent registers but no telemetry appears | Scan not run / offline queue not draining | Check agent logs (`RUST_LOG=debug`); telemetry is queued in encrypted SQLite until the stream succeeds |
| HTTP heartbeat fails under TLS | Private CA not trusted by the HTTP client | Set `tls_ca_cert` (now honored on the HTTP endpoints too) + an `https://` `http_controller_endpoint` |
| Agent won't start: `command_signing_key` error | Key unset in `janus-agent.toml` | Set it to the same value as the server's `JANUS_COMMAND_SIGNING_KEY` |

---

## Migration commands rejected by the agent

The agent refuses any command it cannot verify — by design. Causes:

- **HMAC mismatch** — the agent's `command_signing_key` differs from the server's. Make them equal.
- **`command_too_old` / replay window** — the command's `issued_at_unix` is outside
  `max_command_age_seconds` (default 300). Check clock skew between server and agent.
- **Missing ML-DSA envelope (downgrade)** — the agent pins `command_pqc_fingerprint` (or
  `command_root_ca`) but the command lacks the `janus-sig-v1`/`v2` envelope. Either enable
  `JANUS_COMMAND_SIG_SCHEME=ml-dsa` on the server or clear the pin on the agent.
- **Fingerprint / chain mismatch** — the pinned fingerprint (or bundled command Root CA)
  doesn't match the server's command-signing key/cert. Re-pin from `hsm pubkey` /
  `pki command-ca`.
- **Path/extension rejected** — the target isn't under `allowed_config_roots` or its extension
  isn't in the mutation allowlist. Active migration is also off unless `execution_mode` allows it.

---

## HSM / PQC command signing

| Symptom | Cause | Fix |
|---|---|---|
| `/api/hsm/*` returns 501 | `JANUS_HSM_MODE=disabled` | Set `software` (default) or `pkcs11` |
| HSM keygen refuses RSA/ECDSA | PQC-only platform | Use ML-DSA / SLH-DSA; classical asymmetric keys are intentionally refused |
| ML-DSA command fingerprint changes every restart | Software signer with no persistent key | Use `JANUS_HSM_MODE=pkcs11`, or `JANUS_COMMAND_SIG_KEY_FILE` (`pki command-ca`) for a stable key |
| `JANUS_COMMAND_SIG_CERT_FILE public key does not match the signing key` | Cert/key mismatch | Regenerate the pair with `janus-server pki command-ca`; point CERT_FILE/KEY_FILE at the same set |
| `ML-DSA issuance requires OpenSSL 3.5+` (transport `pki init --alg ML-DSA`) | ML-DSA not usable for transport | Transport certs stay ECDSA-P384; ML-DSA is for command signing (`pki command-ca`) |

---

## Build & CI

| Symptom | Cause | Fix |
|---|---|---|
| `make linux-gate` fails on `cargo clippy -D warnings` | A new warning | Fix it; clippy warnings are denied in the gate |
| Windows-only clippy lints in `interceptor.rs` | `#[cfg(windows)]` FFI code | Expected on Windows clippy; the Linux gate doesn't compile it |
| `make proto-check` fails | Generated bindings drift from `proto/janus.proto` | Regenerate the Go/Rust bindings and recommit |
| `verify-claims.py` fails | Docs claim something unsupported | Reconcile the doc with the maturity framework (`docs/GUIDE.md` §9) |
| Windows build: go/cargo "not found" | Toolchains live under `.tools/`, not PATH | Use `msbuild JanusCryptoBOM.msbuild.proj /t:Build` (bootstraps them) |

---

## Observability

- **`/metrics`** (Prometheus) — if it returns 401, set the scraper's bearer token to
  `JANUS_METRICS_TOKEN` (when set, the endpoint requires it).
- **Audit chain** — `GET /api/audit-logs/verify` (admin) detects any edit/delete/reorder of the
  tamper-evident audit log; a failure there indicates tampering or DB corruption.
- **Correlation IDs** — pass `X-Correlation-ID` on a request to thread it through the logs.

If a problem isn't covered here, capture the correlation ID (server) or run the agent with
`RUST_LOG=debug`, and check `docs/GUIDE.md` (operations) and `docs/ARCHITECTURE.md` (design).
