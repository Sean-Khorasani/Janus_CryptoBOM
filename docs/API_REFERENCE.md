# Janus CryptoBOM — API Reference (DOC-002)

The complete HTTP/REST + WebSocket contract for the control plane
(`server/internal/httpapi`). The gRPC agent contract is separate — see
`proto/janus.proto` and [ARCHITECTURE.md §2](ARCHITECTURE.md).

- Base URL: the HTTP server (`JANUS_HTTP_ADDR`, default `127.0.0.1:8080`).
- Content type: JSON in and out unless noted (exports stream CSV / SARIF / JSON-lines).
- This file tracks the route registrations in `server/internal/httpapi/server.go`.
- A machine-readable **OpenAPI 3.0** spec is maintained alongside this doc at
  [`openapi.yaml`](openapi.yaml) (OPS-005) — import it into Swagger UI / Postman / codegen.

## Authentication

Janus issues an **HS256 JWT** (signed with `JANUS_JWT_SECRET`, which defaults to
`JANUS_COMMAND_SIGNING_KEY`). Obtain one, then send it as a Bearer token.

```bash
# 1. Log in (no auth required)
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<password>"}'
# -> {"token":"<jwt>","role":"admin"}

# 2. Call an authenticated endpoint
curl -s http://localhost:8080/api/overview -H "Authorization: Bearer <jwt>"
```

For `/api/ws`, first `POST /api/ws/ticket` (with the normal `Authorization: Bearer` header) to
obtain a short-lived, single-use ticket, then connect to `/api/ws?ticket=<ticket>`. The session
JWT is never placed in the URL (where it would leak into proxy/access logs and browser history).
Token lifetime is `JANUS_JWT_TTL` (default 24h). Changing your password via
`/api/auth/change-password` invalidates tokens issued before the change.

### Roles

The **Role** column below is the *enforced* minimum (`RequireRole`):

- *(blank)* — any authenticated user.
- `op/admin` — `operator` or `admin`.
- `admin` — admin only.
- `public` — no auth (`/api/health`, `/api/auth/login`, `/metrics`). `/metrics` additionally requires `Authorization: Bearer <JANUS_METRICS_TOKEN>` when that env var is set.
- `agent` — per-agent HMAC token, not a JWT (see below).

> **Note:** state-changing admin routes — policy authoring/activation, fleet config &
> profiles, webhooks, retention, and finding comments/assignment — require `operator`/`admin`
> (REM-1 / FEAT-ROLE-COVERAGE); their read (GET) paths stay open to any authenticated user.
> Finding-status triage (`PUT /api/findings/{id}/status`) remains open to any authenticated
> user by design — scope who may authenticate accordingly (ARCHITECTURE.md §9.2).

### Agent authentication

`/api/agent/config` and `/api/agent/scan-command` require the header
`X-Janus-Agent-Token: HMAC-SHA256(JANUS_COMMAND_SIGNING_KEY, host_uuid)` with a
`?host_uuid=` query param. When the server runs `JANUS_AGENT_AUTH_MODE=per-agent` (WP-029 P1),
these endpoints instead require per-agent headers `X-Janus-Agent-Id`, `X-Janus-Agent-Ts`, and
`X-Janus-Agent-Auth` = `HMAC(agent_key, agent_id\nMETHOD\nPATH\nts)` from an active, enrolled
agent within the freshness window. `/api/agent/heartbeat` is currently unauthenticated for
compatibility with older agents.

In `per-agent` mode the same identity also guards the gRPC telemetry channel
(`RegisterAgent`/`StreamTelemetry`/`ReportMigrationStatus`): each RPC carries
`janus-agent-id`, `janus-agent-ts`, and `janus-agent-auth` metadata, where the token is
`HMAC(agent_key, agent_id\nGRPC\njanus.telemetry\nts)`. A server interceptor rejects calls
from unknown, revoked, or stale-timestamped agents with `Unauthenticated`. Agents are
issued credentials with `janus-server agent enroll`.

### Multi-tenancy (WP-020)

Every login belongs to a **tenant** (set via `JANUS_<ROLE>_TENANT`, default `default`),
carried in the JWT `tenant` claim. The server scopes **all** reads (overview, assets,
findings, components, migrations, exports, reports, per-host and per-scan routes) to the
caller's tenant, rejects migration enqueue against a host outside the caller's tenant, and
filters WebSocket events so a client only sees its tenant's activity. A tenant is purely
additive: the `default` tenant is transparent, so single-tenant deployments behave exactly as
before. Agents are bound to a tenant at enrollment (`janus-server agent enroll --tenant <id>`),
which stamps the tenant onto the asset on first registration.

## Conventions

- **Correlation ID** — every response carries `X-Correlation-ID` (echoed from a valid
  inbound `X-Correlation-ID`/`X-Request-ID`, else generated). It appears in server logs;
  quote it when reporting issues.
- **Error shape** — 4xx: `{"error":"<message>"}`. 5xx: `{"error":"internal server
  error","correlation_id":"<id>"}` (detail is logged server-side, never returned).
- **Common status codes** — `200` ok, `201` created, `204` no content, `400` bad request,
  `401` unauthenticated/expired, `403` insufficient role, `404` not found, `422`
  validation, `429` rate-limited (with `Retry-After`), `500` internal, `503` draining or
  LLM-disabled.
- **Pagination** — list endpoints accept `?limit=&offset=&search=&sort=&order=` and return
  `X-Total-Count`.
- **Rate limits** — `/api/auth/login` and `/api/auth/change-password` are throttled to
  20/min/IP; request bodies are capped at 8 MiB.
- **CORS** — restricted to `JANUS_CORS_ORIGIN`.

---

## Auth & session

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | public | `{username,password}` → `{token,role}`; `401` on bad creds |
| POST | `/api/auth/change-password` | — | `{current_password,new_password}` (new ≥12 chars, ≠ current) → `204`; invalidates the user's prior tokens |

## Fleet & inventory (read)

| Method | Path | Role | Purpose / response |
|---|---|---|---|
| GET | `/api/health` | public | `{status,api_version,...}`; `status:"draining"` during shutdown |
| GET | `/api/overview` | — | fleet counts, readiness score, stalled agents, algorithm histogram |
| GET | `/api/assets` | — | `Asset[]` — agents + heartbeat (incl. `total_files_scanned`, `files_skipped`) |
| GET | `/api/agents/{id}/...` | — / op/admin | per-agent detail, scans, connections; scan-control commands (op/admin) |
| GET | `/api/components` | — | paginated CBOM components (`X-Total-Count`) |
| GET | `/api/findings` | — | paginated findings |
| GET | `/api/hosts/{id}/findings` | — | findings from a host's latest scan |
| GET | `/api/reports/{scan_id}/findings` | — | findings of a specific scan |
| GET | `/api/scan-config/schema` | — | canonical scan-parameter schema (defaults + limits) |
| GET | `/api/confidence/report` | — | per-rule finding confidence stats |
| GET | `/api/sla/metrics` | — | crypto-health SLA dashboard data |
| GET | `/api/report/compliance`, `/api/report.html` | — | HTML compliance report |

## Findings (mutate)

| Method | Path | Role | Purpose |
|---|---|---|---|
| PUT | `/api/findings/{id}/status` | — | `{status,updated_by}` → updated finding (WS `finding_status`) |
| POST/GET | `/api/findings/{id}/timeline`, `/comments` | — | occurrence timeline; comments + assignment (UX-003) |
| POST | `/api/findings/bulk-update` | op/admin | bulk status change over a set/filter of findings (UX-002) |

```bash
curl -X PUT http://localhost:8080/api/findings/$ID/status \
  -H "Authorization: Bearer $JWT" -H 'content-type: application/json' \
  -d '{"status":"accepted_risk","updated_by":"alice"}'
```

## Policies

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/policies` | — | `{active, available:[PolicyProfile]}` |
| POST | `/api/policies/active` | — | `{version}` → switch active profile (WS `policy_switched`) |
| POST | `/api/policies/create` | — | create a profile (version sanitized to `[A-Za-z0-9._-]`) |
| PUT/DELETE | `/api/policies/{version}` | op/admin | update / delete a profile (UX-006) |
| POST | `/api/policies/import` | op/admin | import a profile (UX-006) |
| GET | `/api/policy/rules`, `/api/policy/rules/{id}` | — | versioned compliance control pack (with a tamper-evident `attestation`, WP-017) |
| GET | `/api/compliance/exceptions` | op/admin | list compliance exceptions (WP-017) |
| POST | `/api/compliance/exceptions` | op/admin | grant an exception (`rule_id`, `reason`, optional `asset_ref`, `ttl_hours`) → `201`; audit-logged |
| DELETE | `/api/compliance/exceptions/{id}` | op/admin | revoke an exception; audit-logged |

## Migrations

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/migrations` | — | migration history |
| POST | `/api/migrations/enqueue` | op/admin | enqueue an HMAC-signed migration (`dry_run` default true) |
| POST | `/api/sandbox/simulate` | — | dry-run preview: recommended KEM/sig, unified-diff patch, impact, checklist |
| POST | `/api/lab/simulate` | — | PQC lab algorithm-migration preview |

```bash
curl -X POST http://localhost:8080/api/migrations/enqueue \
  -H "Authorization: Bearer $JWT" -H 'content-type: application/json' \
  -d '{"host_uuid":"...","target_service":"nginx","config_path":"/etc/nginx/nginx.conf","patch_unified_diff":"...","dry_run":true}'
```

## Wave planning (op/admin)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/waves` | op/admin | wave plans + readiness checklist |
| POST | `/api/waves` | op/admin | create (`name`, `wave_number≥1`, optional asset/target/dates) → `201` |
| PUT | `/api/waves/{id}` | op/admin | `{status}` state transition (planned→active→completed; →cancelled) |
| DELETE | `/api/waves/{id}` | op/admin | delete (only `planned`/`cancelled`) |

## Crypto-agility (AGILE-01)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/agility/scorecard` | — | fleet + per-host scorecard (`?host_uuid=` for one host) |
| POST | `/api/agility/exercise` | op/admin | run the per-adapter negotiation/agility exercise |

## LLM (optional — `503` when `JANUS_LLM_BASE_URL` unset)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/llm/status` | — | capability mode, models, config source |
| GET | `/api/llm/usage` | — | token/cost rollup + job success rate (OPS/LLM-023) |
| POST | `/api/llm/analyze`, `/analyze/batch` | op/admin | submit finding analysis (async job) |
| GET | `/api/llm/jobs`, `/jobs/{id}` | — | list / fetch analysis jobs (+verdict) |
| GET | `/api/llm/verdicts/{finding_id}` | — | latest verdict for a finding (`404` if none yet) |
| POST | `/api/llm/verdicts/{verdict_id}/review` | op/admin | `{decision:"approved"\|"rejected",note}` — audit only, no finding-state change |
| GET | `/api/llm/provenance/{finding_id}`, `/batches/{id}` | — | provenance records; batch status |
| POST | `/api/llm/test-connection` | admin | probe the provider (`{ok,error?}`) |
| POST | `/api/llm/proxy` | — | raw provider passthrough |

## HSM (op/admin)

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/hsm/keys` | op/admin | List keys on the configured HSM backend |
| POST | `/api/hsm/keys/generate` | op/admin | Generate a PQC key pair (ML-DSA; RSA/ECDSA refused) |
| POST | `/api/hsm/sign`, `/api/hsm/verify` | op/admin | Sign / verify with an HSM key (PQC ML-DSA). Returns 501 when `JANUS_HSM_MODE=disabled` |

HSM backend is selected by `JANUS_HSM_MODE` (`disabled`/`software`/`pkcs11`); see GUIDE §7.
Key provisioning (token discovery, ML-DSA keygen, fingerprint) is done with the bundled
**CLI**, not REST: `janus-server hsm info|keygen|list|pubkey|rm` and `janus-server gen-hmac-key`
(GUIDE §7.1).

## Certificates

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/certificates/csr` | op/admin | generate a PQC CSR (ML-DSA / SLH-DSA / ECDSA-P384) |

## Fleet config, webhooks, retention, audit

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET/POST | `/api/fleet/config` | — | fleet defaults; `?host_uuid=` for an agent's effective config. `llm_api_key` is masked on GET |
| GET/POST/DELETE | `/api/fleet/profiles`, `/profiles/mapping` | — | config-profile CRUD + agent→profile mapping |
| GET/POST/DELETE | `/api/webhooks` | — | SIEM webhooks (URLs SSRF-validated on insert; payloads HMAC-signed) |
| GET/POST | `/api/retention` | — | retention policy + manual purge |
| GET | `/api/audit-logs` | — | operator audit trail (each entry hash-chained) |
| GET | `/api/audit-logs/verify` | admin | verify the audit-log hash chain → `{valid, entries_checked, broken_at_log_id?, reason?}` |
| GET/POST | `/api/tenants` | admin | list / create tenants (WP-020); `id` slug-validated `^[a-z0-9][a-z0-9_-]{0,62}$`, audit-logged |
| POST | `/api/admin/release-check` | admin | release-evidence gate check |

## Exports

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/export/cyclonedx` | — | CycloneDX v1.6 CBOM (JSON) |
| GET | `/api/export/sarif` | — | SARIF v2.1.0 |
| GET | `/api/export/csv` | — | findings CSV |
| GET | `/api/export/siem` | — | JSON-lines SIEM stream |
| GET | `/api/export/audit?format=csv` | — | audit log export |

## Agent ingest

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/agent/heartbeat` | agent | scan progress, CPU/mem, phase, `files_skipped` |
| GET | `/api/agent/config` | agent | dynamic fleet config (HMAC token + `?host_uuid=`) |
| GET | `/api/agent/scan-command` | agent | pending scan command |
| GET/POST | `/api/agent/diagnostics` | — | agent diagnostics buffer |
| GET | `/api/agent/upgrade` | — | server version + protocol; pass `?agent_version=&agent_protocol=` for a compatibility advisory (`agent_outdated`, `upgrade_recommended`, `recommended_version`, `reason`) |

## Observability

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/metrics` | public\* | Prometheus text — request rate/latency, findings, agents, webhooks, DB pool ([GUIDE.md §13](GUIDE.md)). \*Requires `Authorization: Bearer <JANUS_METRICS_TOKEN>` when that env var is set. |
| POST | `/api/ws/ticket` | — | mint a short-lived, single-use WebSocket ticket (bearer JWT in the header) |
| WS | `/api/ws?ticket=<ticket>` | — | real-time events: `telemetry_update`, `finding_status`, `migration_enqueued`, `migration_status`, `policy_switched`, `lab_simulation`; 15 s ping |

---

*This reference is hand-maintained against the route table in `server.go`. When you add or
change a route, update this file (a future OPS-005 OpenAPI spec would automate the check).*
