# Migration Wave Planning Guide

**Document type:** Operator reference  
**Status:** Active  
**Applies to:** Janus CryptoBOM server — `server/internal/waveplan/planner.go`, `server/internal/httpapi/agility_waves.go`  
**Research basis:** RESEARCH.md §7.4 (Remediation Lifecycle), §10 (Crypto Agility), §11 (Governance)

---

## 1. Overview

A **wave plan** is a planning artifact that groups a set of assets and algorithm migration targets into a named, sequenced batch with associated dates and a lifecycle status. Wave plans are how operators organize the PQC migration portfolio into manageable, reviewable units of work.

Waves exist to reduce blast radius. Attempting to migrate every service to ML-KEM-768 simultaneously means that if a rollout problem occurs — a peer that rejects the new cipher, a misconfigured TLS terminator, an HSM that doesn't support the target algorithm — the impact is fleet-wide. Dividing the migration into sequential waves means problems surface early and are contained: Wave 1 proves the rollout pattern on a representative set of assets before Wave 2 touches more critical ones.

Wave sequencing should follow QRisk prioritization (RESEARCH.md §2.4): assets whose `X + Y` (data lifetime + migration lead time) most exceeds the expected CRQC horizon go first, not last. The blast-radius data from the agility scorecard (AGILITY_SCORECARD.md §2.3) guides which algorithms to target first. High blast radius combined with a quantum-vulnerable algorithm classification (V(a) = 1.0) defines the first-wave candidate set.

**Wave plans do not drive automated execution.** Activating a wave does not enqueue migration commands or trigger any automated config changes on endpoints. A wave plan is a coordination and audit artifact. Actual migration commands are HMAC-signed `MigrationCommand` protobuf messages enqueued through the orchestrator (RESEARCH.md §12), which require human approval through the standard migration lifecycle. Wave plans record the intended scope and sequencing; they do not bypass any safety gate.

---

## 2. Wave Lifecycle

A wave plan follows a state machine with four states and four allowed transitions. Terminal states have no outbound transitions.

```
planned ──── activate ───► active ──── complete ───► completed (terminal)
   │                          │
   └── cancel ───► cancelled  └── cancel ───► cancelled (terminal)
                  (terminal)                   (terminal)
```

### States

| State | Meaning |
|---|---|
| `planned` | Wave has been created and validated. Assets and targets are defined. Not yet being executed. |
| `active` | Wave execution has begun. The wave scope is locked; assets within it are being migrated through the standard migration lifecycle. |
| `completed` | All migrations in the wave scope have been verified complete. Terminal — no further transitions are possible. |
| `cancelled` | Wave was abandoned before or during execution. Terminal — no further transitions are possible. |

### Allowed Transitions

| From | To | Meaning |
|---|---|---|
| `planned` | `active` | Operator activates the wave after confirming readiness (§4). |
| `planned` | `cancelled` | Wave is abandoned before any execution begins. |
| `active` | `completed` | All assets in scope have been migrated and verified. |
| `active` | `cancelled` | Wave is abandoned during execution; rollback of any in-progress changes is operator-managed. |

### Forbidden Transitions (rejected by the server)

Any transition not in the allowed table above is rejected with an error. In particular:

- `completed → anything`: A completed wave is a permanent audit record. It cannot be re-opened, re-activated, or cancelled.
- `cancelled → anything`: A cancelled wave cannot be re-opened. Create a new wave if the effort should resume.
- `planned → completed`: A wave cannot be marked complete without having been activated. Activation is the gate.
- `active → planned`: There is no "pause" state; an active wave in difficulty must be cancelled.

### Deletion

Only `planned` and `cancelled` waves may be deleted. Active and completed waves cannot be deleted.

A `completed` wave is a permanent, undeletable audit record — it cannot be cancelled (terminal state has no outbound transitions) and it cannot be deleted. This is by design: completed waves are compliance evidence.

An `active` wave must be cancelled first, then deleted if deletion is desired.

---

## 3. Planning a Wave

### Inputs

A wave plan is created by `POST /api/waves`. The request body is a JSON object with the following fields:

| Field | Type | Required | Constraints |
|---|---|---|---|
| `name` | string | Yes | Non-empty. Human-readable label (e.g., "Wave 1 — External TLS Services"). |
| `wave_number` | integer | Yes | Must be ≥ 1. Used for display ordering; does not enforce execution order. |
| `description` | string | No | Free text. Intended audience and scope summary. |
| `asset_ids` | string[] | No | List of asset identifiers in scope. Not validated by the server — operators populate this from agility scorecard and fleet data. An empty or absent list is accepted; it is a planning placeholder. |
| `algorithm_targets` | string[] | No | Algorithm migration targets for this wave (e.g., `["ML-KEM-768", "ML-DSA-65"]`). Not validated by the server. |
| `start_date` | string (ISO 8601) | No | Planned start date. |
| `target_date` | string (ISO 8601) | No | Planned completion date. Must not be before `start_date` if both are provided. |

The server assigns `plan_id` (UUID), `status = "planned"`, `created_by` (from the authenticated user), `created_at`, and `updated_at`. These fields in the request body are ignored.

### Validation Rules

The server enforces exactly three validation rules, implemented in `validate()` in `planner.go`:

1. `name` must not be empty.
2. `wave_number` must be ≥ 1.
3. `target_date`, if provided, must not be before `start_date` (when `start_date` is also provided).

`asset_ids` and `algorithm_targets` are not validated. An operator may create a wave with an empty asset list as a planning stub and populate it later by editing the record, or they may use external tooling to assemble the asset set from scorecard data before submitting.

### Audit Logging

Every successful `POST /api/waves` call writes a `WAVE_PLAN_CREATE` audit log entry recording the `plan_id`, name, and creating user. Every status change writes a `WAVE_PLAN_STATUS` entry. Every deletion writes a `WAVE_PLAN_DELETE` entry.

---

## 4. Pre-Activation Readiness Checklist

Before transitioning a wave from `planned` to `active`, the operator should confirm all six readiness items. The `GET /api/waves` response includes this checklist under the `checklist` key so it is always visible alongside the wave list.

The six items, verbatim from `waveplan.ReadinessChecklist()`:

1. **All assets in wave have completed a discovery scan.**  
   Every `asset_id` in the wave's scope must have at least one completed scan in the Janus database. Operating on stale or missing inventory means the migration may miss affected services or act on outdated findings.

2. **Critical and high findings reviewed and triaged.**  
   Open findings of severity critical or high on in-scope assets should be reviewed and dispositioned (confirmed, accepted-risk, or false-positive) before migration begins. Attempting to migrate while a critical finding is unreviewed makes it unclear whether the post-migration state closes the actual risk.

3. **Dry-run migration simulation passed for a representative asset.**  
   At least one asset in the wave should have been run through the Janus sandbox simulation (`POST /api/migrations/simulate`) and passed. The simulation validates the proposed configuration delta, generates a blast-radius estimate, and checks for interoperability impacts without applying any change. One passing simulation does not guarantee all assets will succeed, but it validates the migration recipe for the target technology stack.

4. **Rollback plan documented.**  
   Every asset in scope should have a documented rollback procedure. For config changes, this is the inverse config plus the tested atomic-rollback mechanism in the agent (backup → write → validate → reload → TLS verify → auto-restore on failure). For certificate/key changes, dual-validity windows (old anchor retained dormant) must be confirmed. The rollback plan is a required field in the audit evidence chain for this wave (RESEARCH.md §7.4, step 7).

5. **Stakeholder approval recorded in audit log.**  
   The governance approval for this wave — from the Cryptographic Governance Board or its delegated authority per the active governance model — must be recorded as an audit log entry before activation. Key material changes, trust anchor updates, and protocol-default changes always require human approval with separation of duties (RESEARCH.md §11). Low-risk config changes in pre-approved classes may use delegated approval.

6. **Monitoring alerts configured for target services.**  
   Negotiation-failure rate, downgrade-event rate, handshake-latency p99, and error-class delta monitors must be configured and verified active for all services in scope before activation. These are the golden signals used to detect rollout problems and trigger automatic halt (RESEARCH.md §7.4, step 6). Activating a wave without monitoring in place removes the ability to detect and contain a problem before it becomes fleet-wide.

---

## 5. API Reference

### GET /api/waves

Returns all wave plans plus the readiness checklist.

**Authentication:** JWT required. Roles: `operator`, `admin`.

**Response:**

```json
{
  "plans": [
    {
      "plan_id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Wave 1 — External TLS Services",
      "description": "Migrate all public-facing TLS endpoints to X25519MLKEM768 hybrid KEM.",
      "wave_number": 1,
      "asset_ids": ["svc-web-01", "svc-api-02", "svc-gateway-03"],
      "algorithm_targets": ["ML-KEM-768"],
      "start_date": "2026-07-01T00:00:00Z",
      "target_date": "2026-07-28T00:00:00Z",
      "status": "planned",
      "created_by": "operator@example.com",
      "created_at": "2026-06-10T14:30:00Z",
      "updated_at": "2026-06-10T14:30:00Z"
    }
  ],
  "checklist": [
    "All assets in wave have completed a discovery scan",
    "Critical and high findings reviewed and triaged",
    "Dry-run migration simulation passed for a representative asset",
    "Rollback plan documented",
    "Stakeholder approval recorded in audit log",
    "Monitoring alerts configured for target services"
  ]
}
```

Plans are ordered by `wave_number`, then `created_at`.

---

### POST /api/waves

Creates a new wave plan.

**Authentication:** JWT required. Roles: `operator`, `admin`.

**Request body:** See §3 Inputs. Fields `plan_id`, `status`, `created_by`, `created_at`, and `updated_at` are server-assigned and ignored if present.

**Success response:** `201 Created` with the full wave plan object including server-assigned fields.

**Error response:** `422 Unprocessable Entity` with `{"error": "<reason>"}` for validation failures.

**Example request:**

```json
{
  "name": "Wave 1 — External TLS Services",
  "wave_number": 1,
  "description": "Migrate all public-facing TLS endpoints to X25519MLKEM768 hybrid KEM.",
  "asset_ids": ["svc-web-01", "svc-api-02", "svc-gateway-03"],
  "algorithm_targets": ["ML-KEM-768"],
  "start_date": "2026-07-01T00:00:00Z",
  "target_date": "2026-07-28T00:00:00Z"
}
```

---

### PUT /api/waves/{id}

Updates the status of a wave plan. This is the only field that can be updated; name, asset_ids, dates, and other fields are not mutable through this endpoint.

**Authentication:** JWT required. Roles: `operator`, `admin`.

**Path parameter:** `id` — the `plan_id` UUID of the wave plan.

**Request body:**

```json
{"status": "active"}
```

Valid values: `planned`, `active`, `completed`, `cancelled`. Transitions not in the allowed set (§2) return `422 Unprocessable Entity`.

**Success response:** `200 OK` with `{"plan_id": "...", "status": "active"}`.

---

### DELETE /api/waves/{id}

Deletes a wave plan.

**Authentication:** JWT required. Roles: `operator`, `admin`.

**Path parameter:** `id` — the `plan_id` UUID of the wave plan.

**Constraints:** Only `planned` and `cancelled` wave plans may be deleted. Attempting to delete an `active` or `completed` wave returns `422 Unprocessable Entity` with an error message instructing the operator to cancel it first. Note that a `completed` wave cannot be cancelled (terminal state) and therefore cannot be deleted. Completed waves are permanent audit records.

**Success response:** `204 No Content`.

---

## 6. Integration with PQC Migration Execution

Wave plans are sequencing and audit artifacts, not execution drivers. The migration execution path is:

1. **Discovery** — agents scan assets and report findings via `StreamTelemetry`. Findings are stored in the Janus database and surfaced in the UI.
2. **Wave planning** — operators use agility scorecard data and QRisk scores to identify which findings and assets belong in which wave, create wave plans via `POST /api/waves`, and confirm readiness per §4.
3. **Simulation** — operators run `POST /api/migrations/simulate` for representative assets to validate migration recipes and estimate impact before any change is attempted.
4. **Human approval** — governance approval is recorded (§4 item 5). For key material, trust anchors, and protocol defaults, approval with separation of duties is required regardless of wave status (RESEARCH.md §11).
5. **Wave activation** — operator transitions wave to `active` via `PUT /api/waves/{id}`. This records intent; it does not enqueue commands.
6. **Migration command enqueue** — operators (or orchestrator logic with appropriate approval) enqueue `MigrationCommand` messages for assets in the active wave. Commands are HMAC-SHA256 signed with `JANUS_COMMAND_SIGNING_KEY` before dispatch. Agents verify the signature before applying any change.
7. **Execution and monitoring** — agents apply the command: backup → write → validate → reload → TLS handshake probe → auto-rollback on failure. Findings with `status = "remediated"` confirm successful migration. Monitoring alerts (§4 item 6) watch for negotiation failures and handshake regressions.
8. **Wave close-out** — when all assets in scope have confirmed-remediated findings and monitoring shows clean, operator transitions wave to `completed`.

This path enforces the RESEARCH.md §7.4 remediation lifecycle (evidence validation → recommendation → simulation → deterministic validation → approval → dry run → progressive rollout → monitoring → audit evidence) at every stage. Wave plans provide the sequencing structure; the safety mechanisms (HMAC signing, atomic rollback, sandbox simulation, human approval gates) operate independently of the wave plan status and are not bypassed by wave activation.
