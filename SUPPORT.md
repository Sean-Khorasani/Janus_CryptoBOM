# Support Policy

## Maturity Tiers

Janus CryptoBOM features are governed by a four-tier product maturity system. **No feature is described as "supported" without passing the defined release gates** (WP-025).

| Tier | Description | What it means for operators |
|---|---|---|
| **Prototype** | Proof-of-concept; may be incomplete, unsafe, or removed without notice | Do not use in any environment with real data |
| **Experimental** | Functional and testable; interfaces may change; no backport or patch SLA | Suitable for evaluation and pre-production integration testing; not for production |
| **Supported** | Stable interfaces; breaking changes require a major version bump and 90-day deprecation notice; security patches provided | Suitable for production use |
| **Certified** | All release gates passed; external review completed; benchmark corpus published; interoperability matrix verified | Suitable for regulated or high-assurance deployments |

**Current overall status (v0.14.x):** The platform is **experimental**. All five capability dimensions sit at Level 2–3 on the 0–4 scale defined in `docs/CAPABILITY_MATURITY.md`. Because the overall maturity is the minimum across all dimensions (CAPABILITY_MATURITY.md §1), the platform is experimental across the board, regardless of individual dimensions that have reached Level 3.

| Capability dimension | Current level | Tier |
|---|---|---|
| Discovery Coverage | 2–3 | Experimental |
| Assessment Accuracy | 2–3 | Experimental |
| Agility Metrics | 3 | Experimental |
| Migration Safety | 3 | Experimental |
| LLM Trustworthiness | 3 (or Level 4 if LLM disabled) | Experimental / N/A |

Definitions and advancement criteria for each dimension are in `docs/CAPABILITY_MATURITY.md`.

## Supported Versions

| Version | Status | Notes |
|---|---|---|
| 0.14.x (current) | Active development; best-effort support | Latest release line |
| < 0.14 | End of life — no updates | Upgrade to 0.14.x |
| 1.0+ | Not yet released | Planned first stable release |

There are no long-term support (LTS) branches at this time. Security and bug fixes are applied only to the current release line. No backports are made to prior 0.x versions.

Pre-1.0 minor version bumps (e.g., 0.14 → 0.15) may introduce breaking changes to the HTTP API, protobuf contract, config schema, or database schema. The migration path will be documented in the release notes and the `IMPLEMENTATION_PLAN.md` entry for the relevant work package.

The protobuf contract version is tracked separately as `JANUS_AGENT_PROTOCOL_VERSION` in `VERSION.env`.

## Deprecation Policy

### Minimum notice period

Operator-facing interfaces — HTTP API endpoints, environment variable names, config keys, protobuf field names, policy profile schema keys — are deprecated with a **minimum 90-day notice** before removal. This notice period starts on the date the deprecation is first published.

### How deprecation is communicated

1. **`IMPLEMENTATION_PLAN.md`:** The work package entry for the change notes the deprecation, the removal target version, and the replacement.
2. **Release notes / CHANGELOG:** Each release that advances a deprecation includes the interface name, the planned removal version, and migration instructions.
3. **HTTP response headers:** Where technically feasible, deprecated API endpoints return a `Deprecation` response header with the planned removal date.
4. **Breaking changes in major versions:** Once the project reaches 1.0, breaking changes to stable interfaces require a major version bump. Pre-1.0, breaking changes may occur in minor versions but must still be announced 90 days in advance.

Prototype-tier features may be removed without a notice period.

## Feature Flags and Capability Modes

### Execution mode

The agent operates in one of two execution modes, set in the agent TOML config:

| Mode | Behavior | Stable |
|---|---|---|
| `passive` | Scan and report only; no config mutations | Yes (default) |
| `active` | Execute server-issued migration commands | Experimental |

Active mode is experimental. An operator enabling active mode accepts that the agent will modify config files and reload services based on server-signed commands. See `SECURITY.md` for the safety controls that govern active migration.

### LLM capability mode

Controlled by `JANUS_LLM_CAPABILITY_MODE` (server-side). Default: `disabled`.

| Mode | Behavior | Stable |
|---|---|---|
| `disabled` | No LLM calls; all LLM API endpoints return `503 Service Unavailable` | Stable |
| `analysis_only` | LLM provides advisory annotations on findings; no patch proposals | Experimental |
| `suggest_remediation` | LLM may propose config patch content | Experimental |

All LLM modes at or above `analysis_only` require `JANUS_LLM_BASE_URL` to be set to an `https://` endpoint. The LLM subsystem enforces the eight architectural invariants defined in `docs/LLM_CAPABILITY_CONTRACT.md`; in particular, LLM output cannot directly modify database state or authorize migration commands.

LLM capability modes are versioned alongside the platform. Changes to LLM prompt schemas or the structured-output contract follow the same deprecation policy as other interfaces.

## Filing Issues

Report bugs and feature requests at:

```
https://github.com/janus-cbom/janus/issues
```

### What to include in a bug report

- **Version:** output of `janus-server --version` and/or `janus-agent --version`
- **Platform:** OS, architecture, Go/Rust/Node versions if built from source
- **Reproduction steps:** the minimal sequence of actions that triggers the problem
- **Expected behavior:** what you expected to happen
- **Actual behavior:** what happened, including full log output (`RUST_LOG=debug` for the agent; `JANUS_LOG_LEVEL=debug` for the server)
- **Configuration:** your `janus-agent.toml` with secrets redacted; relevant environment variables with secret values replaced by `[REDACTED]`

**Do not include `JANUS_COMMAND_SIGNING_KEY`, database credentials, or LLM API keys in issue reports.**

For security vulnerabilities, see `SECURITY.md` — do not file a public issue.
