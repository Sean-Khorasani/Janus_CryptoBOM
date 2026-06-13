# Janus CryptoBOM Implementation Plan

## Active Work: Repository Structure Consolidation

**Status:** Implemented; verification in progress on June 12, 2026. Continue
from this section if interrupted.

- [x] Rename `Test/` to conventional `tests/` and update every fixture/suite
  reference.
- [x] Rename `native-test/` to `dev/native-deployment/`, preserving source
  scripts while keeping generated runtime state ignored.
- [x] Keep root `docker-compose.yml` as the only canonical Compose stack.
- [x] Move the Compose agent configuration to `config/janus-agent.compose.toml`.
- [x] Remove the duplicate `infra/docker-compose.yml` and obsolete
  `infra/postgres/schema.sql`; server migrations remain authoritative.
- [ ] Verify Compose, scripts, CI references, documentation, and focused tests.

## Active Review: Optional LLM Analysis And Remediation

**Status:** Requirements reviewed on June 11, 2026. Do not describe the current
LLM capability as implemented or production-ready. No implementation was
started during this review.

### Current Capability Truth

- **Partially implemented:** An authenticated `POST /api/llm/proxy` forwards an
  arbitrary OpenAI-style chat-completions request using the global fleet URL
  and API key. Fleet UI can save those two values in PostgreSQL.
- **Not implemented:** Server configuration-file/environment activation,
  provider/model/temperature/task settings, connection testing, finding-level
  or bulk LLM analysis, persisted verdicts, replacement generation workflow,
  CLI workflow, autonomous remediation, and advanced binary disassembly.
- **Misleading/placeholders:** Advanced Settings model, temperature, and prompt
  fields are not persisted; prompt YAML files are not loaded; the agent does
  not call the proxy; source scanning ignores its legacy LLM flag.
- **Security blockers:** API keys are stored and returned as plaintext; the
  provider URL lacks SSRF controls; arbitrary proxy requests are accepted; no
  redaction, prompt-injection defense, budgets, audit provenance, or result
  schema validation exists. The no-key proxy returns hard-coded fake patches
  and must not be used for remediation.
- **Evidence gap:** Source findings can carry a context snippet, but evidence
  persistence and APIs do not provide a complete bounded analysis package.
  Binary scanning reports imports/exports/symbol strings only; it sends neither
  hexdumps nor disassembly.

### Mandatory LLM Tasks

All tasks below are mandatory and have the same priority. LLM features must
remain disabled by default until every security prerequisite for the requested
mode passes.

| Task | Status | Required outcome |
| --- | --- | --- |
| LLM-001 Define capability and safety contract | **Implemented** | `docs/LLM_CAPABILITY_CONTRACT.md` (409 lines) defines 8 architectural invariants, `disabled`/`analysis_only`/`suggest_remediation` modes, evidence package schema, verdict schema, binary remediation policy (never patch compiled binaries), provenance schema, operator responsibilities, and non-goals. |
| LLM-002 Implement server-side provider configuration | Partially implemented | `LLMConfig` in `server/internal/config/config.go` loads `JANUS_LLM_BASE_URL`, `JANUS_LLM_API_KEY_FILE`/`JANUS_LLM_API_KEY_ENV`, `JANUS_LLM_CAPABILITY_MODE`, model per task, timeout, retries, concurrency. Missing: TLS/proxy settings, token/cost budgets. |
| LLM-003 Protect provider secrets | Not started (security phase) | Deferred. |
| LLM-004 Build provider validation and health checks | Partially implemented | `validateLLMBaseURL()` blocks private IPs, metadata endpoints, non-HTTPS. Admin `GET /api/llm/status` returns capability mode, enabled state, model names, key/URL configured flags (no key values). Missing: model compatibility check, allowlist for private-network overrides. |
| LLM-005 Build versioned prompt and response registry | Partially implemented | `PromptRegistry` in `agent/src/prompts.rs` loads TOML templates. Missing: JSON schema validation, evaluation corpus, server-side registry. |
| LLM-006 Define privacy-safe analysis evidence | **Implemented** | `agent/src/evidence.rs` (281 lines): `BoundedEvidencePackage` struct with `MAX_CONTEXT_BYTES=512`, `SensitivityLabel` enum, `EvidenceSource` enum, constructors for source/TLS/dependency/binary evidence, `validate()` enforcing invariants. 7 tests passing. |
| LLM-007 Implement advanced binary-analysis policy end to end | **Scaffolded** | `BinaryLLMPolicy` struct in `agent/src/config.rs` with fields: `enabled` (default false), `allow_string_extraction`, `allow_import_table`, `allow_hexdump_window`, `max_context_bytes` (default 1024), `require_audit_consent` (default true). Example config in `janus-agent.example.toml`. Full binary analysis execution engine deferred (requires sandboxed disassembly toolchain). |
| LLM-008 Implement asynchronous finding analysis jobs | **Implemented** | DB migrations 18–20: `llm_analysis_jobs`, `llm_verdicts`, `llm_provenance` tables. `store.Store` interface: 7 new methods. `server/internal/llm/service.go`: `SubmitAnalysisJob`, `AnalyzeFinding`, `GetJobResult`. HTTP API: `POST /api/llm/analyze`, `GET /api/llm/jobs`, `GET /api/llm/jobs/{id}`. |
| LLM-009 Implement structured false-positive/severity review | **Implemented** | `ValidateVerdict()` in `server/internal/llm/types.go` enforces schema: valid verdict enum, confidence 0–1, abstention requires reason, high confidence requires citations. `LLMVerdict` struct with `EvidenceCitations`, `AdjustedSeverity` (proposed only, never auto-applied), `AbstentionReason`. 15 tests passing. |
| LLM-010 Persist complete LLM provenance and feedback | **Implemented** | `llm_provenance` table (immutable audit trail) persists: provider, model, prompt name/version, input/output hashes (SHA-256), token counts, latency. `RecordProvenance` + `ListProvenance` in store. `GET /api/llm/provenance/{finding_id}` endpoint. |
| LLM-011 Implement remediation suggestion generation | **Scaffolded** | `RemediationSuggestion` struct in `server/internal/llm/types.go` with `HumanApprovalRequired: true` always. `ValidateSuggestion()` enforces approval gate. `ModeSuggestRemediation` capability mode. Full suggestion pipeline (LLM call → patch generation) deferred to security phase. |
| LLM-012 Define practical binary remediation | **Documented** | `docs/LLM_CAPABILITY_CONTRACT.md` §7: binary remediation policy — never patch compiled binaries via LLM; provide disassembly-backed reports, source/library upgrade guidance, vendor escalation, compensating controls, rebuild instructions. |
| LLM-013 Build deterministic remediation validation | Not started (security phase) | Deferred. |
| LLM-014 Integrate governed execution with agents/server | Not started (security phase) | Deferred. |
| LLM-015 Build complete admin UI | **Implemented** | `ui/src/components/LLMAnalysis.tsx`: LLM status card (capability mode badge, model names, configuration state), analysis jobs table with verdict expansion, submit analysis form. |
| LLM-016 Build API and CLI automation | **Implemented** | REST endpoints: `POST /api/llm/analyze` (submit job, sync if evidence provided), `GET /api/llm/jobs` + `GET /api/llm/jobs/{id}` (list/get with verdict), `GET /api/llm/verdicts/{finding_id}`, `GET /api/llm/provenance/{finding_id}`, `GET /api/llm/status`. All require JWT auth. |
| LLM-017 Enforce autonomous-remediation policy | Not started (security phase) | Deferred. |
| LLM-018 Add LLM security and reliability controls | Not started (security phase) | Deferred. |
| LLM-019 Add evaluation and release gates | Partially implemented | `server/internal/llm/llm_test.go`: 15 tests covering ValidateVerdict (valid + invalid cases), ValidateSuggestion, HashString determinism. Missing: false-positive corpus, provider-contract tests, prompt-injection defense. |
| LLM-020 Correct documentation and product claims | Partially implemented | `CLAUDE.md` updated. `docs/LLM_CAPABILITY_CONTRACT.md` written. Missing: `README.md` capability-maturity section, per-feature experimental/supported labels. |

### Research-Backed Practical Suggestions For A: Finding Validation

These are suggested implementation techniques, not claims about current
capability. Prefer the simplest technique that passes measured evaluation
gates.

- **Use a neuro-symbolic review cascade:** deterministic scanners remain the
  source of findings; conventional AST/data-flow/call-graph/configuration
  analysis builds a compact evidence graph; the LLM interprets intent and
  proposes a verdict; deterministic policy and human review decide status.
- **Build context by program slicing, not arbitrary file windows:** include the
  finding site, definitions, callers/callees, sanitized data flow, guards,
  reachable entry points, configuration overlays, dependency versions, test
  classification, and deployment context. Explicitly mark unknown or truncated
  context. Extended code-property-graph slicing and file-reference graphs are
  practical candidates for precise interprocedural context.
- **Verify path feasibility separately:** for warnings dependent on complex
  branches or sanitizers, ask the model only for targeted constraint hypotheses
  and verify them with conventional path analysis, symbolic execution, or
  executable tests before suppressing a finding.
- **Require claim-evidence structured output:** every verdict must cite supplied
  evidence IDs and return `confirmed`, `likely`, `unlikely`, or `insufficient
  evidence`, proposed severity/confidence, assumptions, counter-evidence, and
  requested additional evidence. Unsupported citations invalidate the result.
- **Add calibrated abstention and selective automation:** measure calibration
  and coverage; route uncertain, novel, high-impact, or conflicting cases to a
  human. Never translate model confidence directly into scanner confidence.
- **Use bounded independent review for high-risk findings:** optionally compare
  two prompts/models or a proposer and critic, but accept a conclusion only
  when deterministic evidence checks pass. Do not use an LLM judge as the sole
  verifier.
- **Use retrieval with strict trust boundaries:** retrieve version-matched API
  documentation, policy controls, prior operator-confirmed outcomes, accepted
  exceptions, and repository conventions. Scope retrieval by tenant and
  version, preserve citations, and treat all retrieved text as untrusted data.
- **Learn from feedback through evaluations, not online self-modification:**
  maintain rule/language/project-specific labeled corpora, measure precision,
  recall, calibration, cost, and drift, then promote prompt/model changes
  through versioned release gates.
- **For advanced binaries, lift before asking:** use sandboxed Ghidra
  decompiler/P-code or another supported intermediate representation to produce
  bounded function summaries, call graphs, imports, constants, and call-site
  slices. Use symbolic execution such as angr only for targeted questions and
  validate claims against addresses and hashes. Do not send whole binaries.

### Research-Backed Practical Suggestions For B: Remediation

- **Prefer constrained repair over unconstrained generation:** use
  language-aware transformations, structured configuration adapters, approved
  recipes, and dependency-manager operations first. Ask the LLM to select and
  parameterize known-safe transformations before allowing free-form patches.
- **Use repository-aware retrieval:** provide exact library/framework versions,
  build files, coding conventions, supported PQC provider APIs, policy target,
  similar reviewed fixes, and relevant tests. Reject suggestions based on
  unavailable APIs or incompatible versions.
- **Generate a plan and tests before a patch:** require assumptions, affected
  interfaces, interoperability impact, key/certificate lifecycle changes,
  rollback strategy, and a failing security/regression test before editing.
- **Generate several minimal candidates:** rank bounded candidates by
  successful deterministic verification, behavioral preservation, smallest
  change, compatibility, and operational risk rather than model preference.
- **Start with a simple localization-repair-validation pipeline:** hierarchical
  file/function/edit localization and multiple candidate diffs are easier to
  audit and can outperform complex autonomous agents. Add AST-aware search and
  spectrum-based fault localization when a trustworthy test suite exists.
- **Run a bounded repair loop:** apply candidates only in isolated worktrees or
  sandboxes; feed concise compiler/test/static-analysis failures back for a
  limited number of attempts; stop on budget, repeated failure, or scope
  expansion.
- **Use layered verification:** formatting and parsing, compile/type checks,
  unit/integration/property tests, original-finding elimination, broad security
  rescans, dependency/ABI checks, differential behavior, performance limits,
  secret scanning, and target-specific migration validation. LLM review may
  supplement but never replace these checks.
- **Separate source, configuration, and secret operations:** source changes
  should normally become reviewable commits/PRs; service/OS configuration must
  use typed idempotent adapters and desired-state diffs; keys and certificates
  must be generated and installed by dedicated lifecycle systems, never by the
  model.
- **Treat binaries as report-and-rebuild targets:** recommend source/library
  fixes, upgrades, vendor actions, runtime mitigations, or compensating
  controls. Binary rewriting requires a separately supported adapter,
  reproducible build/signature handling, equivalence checks, and rollback.
- **Stage execution progressively:** suggestion, dry-run, validated candidate,
  human approval, canary, monitored rollout, and automatic rollback. Autonomous
  execution is suitable only for allowlisted low-risk transformations with
  proven validators.

### Suggested Technical Foundations

- Use CodeQL-style data-flow/path evidence and SARIF identities to connect
  findings, evidence, LLM reviews, candidate fixes, and verification results.
- Adopt SWE-agent/OpenHands-style isolated tool interfaces only with explicit
  command allowlists, resource budgets, immutable logs, and no direct
  production access.
- Follow GitHub Copilot Autofix's practical pattern of combining code-scanning
  alerts with contextual code and presenting fixes as reviewable suggestions,
  while adding Janus-specific deterministic migration and rollback gates.
- Apply NIST AI RMF Generative AI Profile and OWASP LLM guidance to provider
  governance, prompt-injection defense, privacy, monitoring, and human
  oversight.

Research starting points:
[CodeQL data flow](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/),
[GitHub Copilot Autofix](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/responsible-use-autofix-code-scanning),
[SWE-agent](https://arxiv.org/abs/2405.15793),
[SWE-bench](https://arxiv.org/abs/2310.06770),
[Agentless](https://arxiv.org/abs/2407.01489),
[AutoCodeRover](https://arxiv.org/abs/2404.05427),
[LLM4FPM](https://arxiv.org/abs/2411.03079),
[LLM4PFA](https://arxiv.org/abs/2506.10322),
[Vul-RAG](https://arxiv.org/abs/2406.11147),
[Ghidra P-code](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html),
[angr symbolic execution](https://docs.angr.io/en/latest/core-concepts/symbolic.html),
[NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), and
[OWASP LLM Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).

### Current Experimental Proxy Test

This tests only OpenAI-compatible proxy connectivity, not requirements A, B,
advanced binary analysis, UI analysis, or autonomous remediation.

1. Log in as admin, open **Fleet Management**, enter the provider base URL
   ending in `/v1` and a disposable restricted API key under **LLM AI Context
   Analysis**, then choose **Deploy Configuration Profile**. Do not use
   **Advanced Settings** for model/prompts; those controls are currently
   nonfunctional.
2. Obtain the login token and call `POST /api/llm/proxy` directly with an
   OpenAI chat-completions body containing the provider's model name. Confirm
   the provider response manually.
3. Remove/rotate the disposable key after testing. The current database/API
   handling exposes it in plaintext.

Do not use the current proxy response to change finding status, generate an
approved migration, or apply changes to an agent.

## Active Work: Component Versioning And Release Package Naming

**Status:** Implemented and verified on Linux on June 11, 2026; Windows package
verification pending.
Continue from this section if work is
interrupted. Preserve the currently running native Linux test deployment.

- [x] Define one release/version contract for server, UI, Linux agent, Windows
  agent, protocol compatibility, build date, and daily build sequence.
- [x] Replace component release literals with build-injected values and
  expose versions in binaries/UI/API/package metadata.
- [x] Enforce explicit UI-required/server API compatibility through
  `/api/health`; keep agent protocol/minimum-server compatibility explicit.
- [x] Standardize Linux package names with component, version, OS/distribution, and
  architecture.
- [x] Improve Windows build scripts to produce conventionally named server+UI and
  agent deployment ZIPs. Windows artifacts cannot be built or verified from the
  current Linux/WSL environment.
- [x] Document release artifact contents and verification commands.
- [x] Complete Linux build/artifact verification.
- [ ] Verify Windows ZIPs on a Windows build host.

Verification: all Go server tests, 41 Rust agent tests and release build, and
the metadata-injected UI production build pass. Portable Linux server+UI and
agent tarballs, `janus-agent_0.14.0-260611.1_amd64.deb`, and
`janus-agent-0.14.0-260611.1.x86_64.rpm` were generated successfully. Their
contents and SHA-256 checksums were verified. Windows package scripts were
implemented but cannot be executed from WSL; `pwsh` is unavailable on this
host, so Windows script syntax and ZIP contents also require Windows-host
verification.

## Phase Zero: Linux Readiness

Linux server, UI, and agent readiness is the first release milestone. Do not begin the broader security, migration, or product roadmap until **Linux Gate L0** passes. The agent is the highest-risk area because its build, configuration, permissions, discovery behavior, service operation, and active adapters have not been proven on Linux.

## How To Reprioritize

Each `WP-*` section is a self-contained work package. Move whole sections with cut/paste to change execution order, but complete every `WP-LNX-*` package before `WP-001`. Keep `Depends on` constraints intact. Priority meanings: **P0 release blocker**, **P1 production requirement**, **P2 scale/quality**, **P3 category leadership**.

## Release Gates

- Linux Gate L0 passes on every declared distro and architecture.
- All P0 packages complete.
- Clean builds and tests on Windows and Linux.
- No unauthenticated agent/control-plane actions.
- Every migration is durable, authorized, replay-resistant, observable, and rollback-tested.
- Product claims map to passing automated evidence.

## Linux Gate L0

- A clean Linux clone builds the server, UI, agent, protobufs, containers, and packages without Windows tools.
- The canonical compose stack starts healthy and exposes a working API, UI, database, and connected agent.
- Agent `check`, passive scan, daemon, cache, telemetry, restart, and upgrade paths pass under systemd and containers.
- Unprivileged passive, privileged runtime-discovery, and active-migration profiles have explicit permissions and tests.
- Linux discovery and migration tests prove no undocumented target mutation and verify rollback.
- Browser smoke tests pass with Linux-supported Playwright browsers.
- CI publishes evidence for the declared distro/libc and x86_64/arm64 support matrix.

## Implementation Status

Status is updated while work and verification proceed. `Implemented` means the
repository change exists; a work package becomes `Complete` only after all of
its acceptance criteria and verification requirements pass.

**Fresh-session handoff:** This implementation plan is the canonical durable
handoff. Historical session-specific handoff and audit notes are kept outside
the repository under `Temp/`.

**Manual testing checkpoint:** Implementation is paused at the user's request
on June 10, 2026. The Linux server, production UI, and passive Linux agent are
ready for hands-on testing through the canonical `docker-compose.yml` stack.
An additive `dev/native-deployment/` deployment is being prepared for native Linux
server/Vite UI/Linux agent testing and a separately staged Windows agent. This
does not replace or modify the container deployment path.
Resume roadmap implementation after manual server/agent/Web UI feedback.

| Work package | Status | Current evidence and remaining work |
| --- | --- | --- |
| WP-LNX-001 | Implemented, verification pending | Versioned support, capability, permission, and CI matrices are in `docs/linux-support.md`; hosted matrix evidence is pending. |
| WP-LNX-002 | Implemented, verification pending | Native Go/Rust/UI builds, container builds, and protobuf drift tooling pass locally; clean-clone hosted evidence is pending. |
| WP-LNX-003 | In progress | Linux config, staged lifecycle verification, generated file-mounted compose secrets, meaningful agent initialization health, and non-root state initialization exist; live systemd install/upgrade and native deb/rpm proof are pending. |
| WP-LNX-004 | Implemented, verification pending | Deterministic filesystem/process/network snapshots prove passive scans do not mutate targets, and a bounded container agent registers and uploads telemetry. Hosted discovery evidence remains. |
| WP-LNX-005 | Implemented, verification pending | Passive systemd exposure is 2.8; process-memory denial and fail-closed plugin isolation evidence exist alongside explicit elevated profiles. Hosted profile evidence remains. |
| WP-LNX-006 | Implemented, verification pending | Migration writes and rollback are hardened, checklist tampering is rejected, unsupported adapters fail before mutation, and deterministic nginx/Apache/SSH validation/reload rollback tests pass. Hosted supported-matrix evidence remains. |
| WP-LNX-007 | Implemented, verification pending | Canonical compose serves UI/API/database, runs the agent non-root, and persists a connected agent's asset and telemetry rows; hosted compose/Helm/browser evidence remains. |
| WP-LNX-008 | In progress | Required Linux CI and release-evidence workflows exist; hosted runs, release signatures, and full declared-matrix evidence remain. |
| Native manual-test deployment | Ready for manual testing | Additive isolated Linux server/UI/agent and Windows-agent bundles are staged under `dev/native-deployment/`; native server/UI/Linux-agent startup, shutdown, LAN API/UI access, login, registration, and telemetry upload pass locally. |
| CR-AFM-001 through CR-AFM-014 | Implemented, verification in progress | Fleet contracts, immutable history, indexed APIs, real scan commands, paginated fleet/detail UI, home-page agent status/actions, provenance, contextual graph reports, live events, and scale tooling exist; full 5,000-agent and security evidence remains. |
| WP-001 | Not started | Blocked by Linux Gate L0. |
| WP-002 | Not started | Blocked by Linux Gate L0. |
| WP-003 through WP-012 | Deferred | Security phase — implement after all functional/UI work is complete. |
| WP-013 | Partially implemented | Lifecycle events, auto-reopen on recurrence, `GET /api/findings/{id}/timeline`, `GET /api/hosts/{uuid}/findings`. See WP-013 section. |
| WP-014 | Not started | Requires large new deps (AST parsers per language). |
| WP-015 | Partially implemented | CompatibilityAnalysis/DependencyUpdate in sandbox, HumanApprovalRequired. See WP-015 section. |
| WP-016 | Partially implemented | TLS probing, STARTTLS, 9 assessment categories, OCSP placeholder, `docs/NETWORK_ASSESSMENT.md`. See WP-016 section. |
| WP-017 | Partially implemented | 12 versioned ControlRules, BuiltinControlPack, profile EffectiveDate/FrameworkMappings, REST API, compliance rules UI. See WP-017 section. |
| WP-018 | Partially implemented | Real cert health from DB, real SLA metrics, no fabricated values. UI cert-health card. See WP-018 section. |
| WP-019 | Partially implemented | 71 Rust + 18 Go packages green, fuzz test, store interface assertion, race CI step. See WP-019 section. |
| WP-020 | Not started | HA/tenancy infrastructure — P2, skip until functional complete. |
| WP-021 | Partially implemented | CycloneDX 1.6 cryptoProperties, SARIF 2.1.0 with source locations. See WP-021 section. |
| WP-022 | Extended | WavePlan CRUD + CanaryTargets/MaintenanceWindow/ApprovalPolicy/BudgetHours fields, DB migrations 22/25/27. 15+ tests. See WP-022 section. |
| WP-023 | Scaffolded + exercise EP | Agility scorecard, REST API, UI dashboard, dry-run exercise endpoint. See WP-023 section. |
| WP-024 | Partially implemented | SIEM-compatible webhook payload (event_type, source, finding, remediation fields). See WP-024 section. |
| WP-025 | Partially implemented | SECURITY.md, SUPPORT.md, CAPABILITY_MATURITY.md, release readiness check endpoint. See WP-025 section. |
| WP-026 | Substantially implemented | DataClassification enum, redact_secrets (5 patterns), 11 tests, PRIVACY_DATA_GOVERNANCE.md. See WP-026 section. |
| WP-027 | Partially implemented | ALGORITHM_COMPATIBILITY.md migration matrix and library support table. See WP-027 section. |

### Latest Local Verification

Verified through June 12, 2026:

- `make linux-gate`, protobuf drift, Go race/vet, Rust fmt/clippy/tests, and scoped diff checks pass.
- Canonical compose serves UI/API/database; a non-root one-shot agent registers and persists one asset and telemetry payload.
- A full-repository Linux agent scan produced and uploaded an 18 MB telemetry message after adding the bounded, configurable 32 MiB gRPC receive limit.
- Playwright Chromium passes 74/74 scenarios; controlled Linux E2E and staged package lifecycle checks pass.
- Passive systemd static exposure is 2.8 and is enforced below a threshold of 4.
- CR-AFM component verification passes: Go server tests, 41 Rust agent tests,
  UI production build, all 75 Playwright scenarios, live
  native fleet/history/provenance/contextual-graph checks, and an isolated
  5,000-agent PostgreSQL query exercise (indexed offline query: 0.221 ms;
  compound wildcard search: 2.659 ms on this host). A signed scan command was
  also proven to remain queued across a server restart, deliver afterward, and
  trigger new immutable scan runs; viewer command submission is rejected.
- The Overview home page now shows a bounded operational agent summary with
  connectivity, last contact/report, current work/progress, rescan, and detail
  actions. The native Linux agent heartbeat and completed-scan idle state were
  corrected and verified against the live server API.
- Synthetic `ci-cd-runner` scan history is separated from managed endpoint
  inventory, preventing shift-left scans from appearing as duplicate agents.
- Rescan actions now expose durable lifecycle states (`queued`, `executing`,
  `completed`, or `failed`) instead of stopping at queue acceptance. Connected
  agents poll for passive scan requests every five seconds; offline requests
  remain queued until reconnection.
- Each home-page agent row now provides authenticated per-agent scan
  configuration for assessment policy, roots, exclusions, source extensions,
  scan interval, source/binary size limits, network targets, and explicit
  runtime/plugin/process-memory/active-TLS discovery opt-ins. Agents fetch and
  apply configured values before scanning.
- Agent configuration uses reversible Close/Restore/Apply behavior, field-level
  accepted-value guidance, unit-aware KB/MB/GB limits, and matching server-side
  validation. Protected HTML and scan-history JSON reports are opened through
  authenticated fetches rather than unauthenticated new-tab links.
- Scan configuration defaults and supported ranges are centralized in explicit
  server and agent contracts. The authenticated schema endpoint drives UI
  validation and guidance, removing duplicated UI limits; deployment TOMLs
  remain the explicit place for installation-specific values.
- The centralized scan-configuration change passes all Go tests, 28 Rust agent
  tests, the UI production build, and focused Playwright agent-fleet scenarios.
  The restaged native server returns the authenticated schema and the restarted
  Linux agent registers and uploads telemetry successfully.
- Authenticated HTML and findings-JSON reports open in populated new tabs
  without navigating the dashboard. Report tabs include Back and Home controls,
  and all dashboard report entry points use the authenticated report opener.
- Dashboard refresh failures preserve the last known good fleet, findings, and
  graph data instead of wiping the page. Agent Details prioritizes latest-scan
  findings with explicit empty/error states; repeated telemetry synchronization
  no longer manufactures connection sessions, and agent progress baselines are
  updated after each completed scan.
- Live stability verification after migrations 16 and 17: UbuntuHost retained
  exactly one active connection session; duplicate idle progress records were
  compacted from 4,205 to 14; a real rescan completed with deterministic
  `Starting scan`, `Uploading results (100%)`, and `Idle` transitions; the
  dashboard retained two agents after refresh and Details showed the correct
  latest-scan no-findings state.
- Native Linux command/config behavior is live-verified. The staged Windows
  agent executable predates these source changes and must be rebuilt with the
  Windows MSVC toolchain before Shahin-Desktop can consume the new polling and
  per-agent configuration behavior.

June 12, 2026 additions verified locally: `DetectionMethod` enum (DISC-02,
`source.rs`) and `TlsAssessmentCategory` enum (DISC-03, `network.rs`) each
have dedicated behavioral unit test suites (5 tests each). `PromptRegistry`
migrated from deprecated `serde_yaml` (RUSTSEC-2024-0370) to `toml`; prompt
files converted to `config/prompts/*.toml`; `JANUS_PROMPTS_DIR` env-var
override wired into `default_prompts_dir()` and Dockerfile. Go server tests (5
packages), 41 Rust agent tests, and 0 clippy warnings confirmed after all
changes.

Still required before Linux Gate L0 can pass: hosted clean-clone/matrix
evidence, live systemd restart/upgrade tests, full discovery snapshots, and
destructive supported-adapter rollback tests.

## Agent Fleet Management And Contextual Findings Change Plan

All tasks in this section are mandatory and have the same priority. They are
flat implementation tasks rather than optional phases. The fleet inventory is
the primary interface for large deployments; the exposure graph is a bounded,
contextual visualization and must never attempt to render an entire fleet.

Current gaps that drive this plan:

- `/api/assets` and the fleet UI load every agent without server pagination.
- Stored agent records omit agent version, observed IP, DNS names, first
  registration, and connection/session history.
- Telemetry payloads contain scan timestamps, but no scan-history/report API
  exposes them.
- Finding deduplication updates `telemetry_id`, which overwrites historical
  provenance instead of preserving each scan's finding occurrences.
- Graph selection is private to `CryptoGraph` and does not filter or retitle
  the adjacent findings report.
- Some fleet actions and progress behavior are simulated in the browser rather
  than backed by durable server commands and events.

## CR-AFM-001 Define Fleet, Connection, Scan, And Finding Semantics

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Define canonical meanings for agent, connection session, heartbeat, scan run, scan report, finding occurrence, current finding state, online/offline/stalled, progress, and scan risk severity. Define graph-selection behavior for agent, component/file, and algorithm nodes.  
**Acceptance criteria:** API, database, and UI field definitions use the same identities, timestamps, status transitions, and severity rules.  
**Verification:** Approved contract examples cover reconnects, overlapping scans, repeated findings, offline agents, and empty reports.

## CR-AFM-002 Preserve Immutable Scan And Finding History

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Add normalized `scan_runs`, `finding_occurrences`, and report metadata while retaining a separate current-finding lifecycle record. Stop overwriting scan provenance during finding deduplication and migrate existing telemetry safely.  
**Acceptance criteria:** Every received telemetry payload has one immutable scan record and immutable finding occurrences linked to its agent and report; lifecycle status remains independently manageable.  
**Verification:** Migration and ingestion tests prove repeated findings remain queryable in every historical scan without duplicating current open findings.

## CR-AFM-003 Capture Complete Agent Identity And Network Presence

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Persist agent version, first registration, last registration, observed source IP, reported addresses, DNS/FQDN, OS/version/architecture, capabilities, execution mode, and last heartbeat. Prefer controller-observed source IP over untrusted reported values.  
**Acceptance criteria:** Agent detail responses expose the complete identity and clearly identify observed versus reported network values.  
**Verification:** Linux, Windows, address-change, DNS-missing, NAT, and agent-upgrade registration tests pass.

## CR-AFM-004 Record Connection Sessions And Detailed Progress

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Record durable connection sessions and scan progress snapshots/events, including connected/disconnected times, current stage/path, files processed/total, percentage, status message, last error, resource usage, and associated scan run.  
**Acceptance criteria:** Operators can inspect current progress and historical connections without inferring history from the mutable `assets.last_seen` row.  
**Verification:** Reconnect, interrupted scan, completed scan, stalled agent, and server-restart scenarios retain correct timelines.

## CR-AFM-005 Build Scalable Fleet Query APIs

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Replace unbounded asset loading with server-side paginated agent list/detail APIs supporting indexed filtering and sorting across every displayed field, including agent identity, OS, version, IP/DNS, state, dates, scan progress, last-scan severity, and finding counts.  
**Acceptance criteria:** Compound queries such as agent plus date range plus severity return deterministic pages and totals; unsupported sort/filter fields fail clearly.  
**Verification:** API contract and PostgreSQL query-plan tests pass with at least 5,000 agents and representative history.

## CR-AFM-006 Build Scan, Connection, Report, And Findings Query APIs

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Add paginated endpoints for agent connections, scan history, scan-report summaries/details, and finding occurrences. Support filters for agent, telemetry/scan ID, time range, severity, algorithm, component, file path, policy, and status.  
**Acceptance criteria:** Every fleet/detail/history/report view can retrieve only its required server-filtered data and deep-link to a stable scan report.  
**Verification:** Cross-agent isolation, compound filter, sort, pagination, empty-result, and retention tests pass.

## CR-AFM-007 Implement Real Fleet Management Commands

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Replace browser-simulated scan actions with durable authorized commands for scan request, cancellation where supported, profile assignment, and diagnostics retrieval. Show command acceptance, delivery, execution, failure, and audit state.  
**Acceptance criteria:** Fleet actions survive refresh and server restart, cannot target unauthorized agents, and never imply success before agent acknowledgement.  
**Verification:** End-to-end command lifecycle, offline-agent, retry, authorization, and audit tests pass.

## CR-AFM-008 Build The Primary Agent Inventory UI

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Create a virtualized or server-paginated fleet table designed for 5,000 agents with configurable columns, all-field search/filter/sort, date-range controls, status/severity indicators, bulk selection, progress bars, and stable URLs for query state.  
**Home-page summary:** The Overview includes a bounded ten-agent operational summary with connectivity, last contact/report, current work/progress, real rescan commands, and navigation to the full fleet inventory.  
**Acceptance criteria:** Operators can locate and compare agents without using the graph, including compound date/agent/severity searches and sorting by every visible field.  
**Verification:** Browser tests and usability checks pass with 100, 1,000, and 5,000-agent datasets.

## CR-AFM-009 Build Agent Detail And Historical Timeline UI

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Add an agent detail view with identity/network/version data, current connection and scan progress, last scan summary, findings summary, connection history, scan history, reports, diagnostics, profile, and authorized actions.  
**Acceptance criteria:** Each connection and scan-history row links to its exact report and displays timestamps, duration, completion state, and severity summary.  
**Verification:** Deep-link, date filtering, sorting, offline, in-progress, failed, and completed scan browser scenarios pass.

## CR-AFM-010 Make Scan Reports Provenance-Complete

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Add report headers and finding fields for agent name/UUID, agent version, OS/version, IP/DNS, scan/telemetry ID, scan start/finish/receive times, duration, report severity summary, component/file path, and evidence linkage.  
**Acceptance criteria:** The default findings view and every historical report identify exactly which agent and scan produced each result.  
**Verification:** API, UI, CSV, JSON, CycloneDX, SARIF, and HTML report provenance tests pass.

## CR-AFM-011 Connect Graph Selection To Contextual Findings

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Lift graph selection into shared overview state and request the corresponding findings scope. Agent selection shows that agent's latest completed scan; component/file selection shows only that component/file; algorithm selection shows that algorithm within the active scope; clearing selection restores the default report.  
**Acceptance criteria:** The findings title and content update together, for example `Latest findings from AGENT-NAME`, `RSA findings from AGENT-NAME`, or `Findings for FILE-PATH`, with an explicit scope breadcrumb and clear action.  
**Verification:** Selection, scope intersection, stale-selection, empty-result, keyboard, and accessibility browser tests pass.

## CR-AFM-012 Bound And Rework The Exposure Graph For Scale

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Never render the complete fleet. Populate the graph from a bounded server query based on an explicitly selected agent, scan, report, or filtered high-risk subset; show truncation/count indicators and provide navigation back to the fleet list.  
**Acceptance criteria:** Graph node/edge limits are enforced, selection remains deterministic, and a 5,000-agent deployment cannot freeze the browser or silently omit context.  
**Verification:** Graph performance, truncation, high-risk subset, selected-agent, and selected-scan tests pass.

## CR-AFM-013 Add Live Updates, Deep Links, And Consistent Exports

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Publish agent state, connection, scan progress, and scan-completion events through the existing WebSocket/event path with polling fallback. Preserve fleet filters, selected agent/scan/graph node, and report scope in URLs; make exports honor the same scope.  
**Acceptance criteria:** Live changes update the relevant row/detail/report without full-page reload, and shared URLs/exports reproduce the same filtered context.  
**Verification:** Disconnect/reconnect, event-loss fallback, browser refresh, shared-link, and scoped-export tests pass.

## CR-AFM-014 Prove Security, Correctness, And 5,000-Agent Scale

**Priority:** Mandatory  
**Status:** Implemented, verification pending  
**Scope:** Add authorization and audit coverage for fleet/history/report APIs and actions; index and benchmark all query paths; define retention behavior; add migration rollback, API, UI, accessibility, and load tests.  
**Acceptance criteria:** Authorized users can operate the fleet within defined latency budgets, tenant/user boundaries do not leak data, and retention never leaves broken report links or inconsistent current state.  
**Verification:** Automated evidence includes 5,000-agent load results, large scan-history queries, concurrent progress events, security tests, and migration rollback results.

## WP-LNX-001 Define Linux Support Contract

**Priority:** P0  
**Depends on:** None  
**Scope:** Declare supported distributions, versions, init systems, libc, x86_64/arm64 architectures, privilege profiles, and pinned Go/Rust/Node/protobuf toolchains. Select one canonical compose stack and document unsupported capabilities.  
**Acceptance criteria:** A versioned Linux support matrix and capability/permission matrix are approved and enforced by build configuration.  
**Verification:** Matrix entries map to named CI jobs and release evidence.

## WP-LNX-002 Restore Native Linux Compilation

**Priority:** P0  
**Depends on:** WP-LNX-001  
**Scope:** Fix the Rust storage syntax error and UI TSX issue; align Docker Go version with `go.mod`; isolate Windows HSM APIs with build tags and implement or explicitly disable Linux PKCS#11 loading; regenerate protobufs using pinned tools.  
**Acceptance criteria:** Native and container builds complete from a clean Linux clone with no repository-local Windows executables.  
**Verification:** Rust fmt/clippy/test, Go fmt/vet/test/race, UI build, protobuf drift, and container builds pass.

## WP-LNX-003 Make Linux Agent Installable And Configurable

**Priority:** P0  
**Depends on:** WP-LNX-002  
**Scope:** Define TOML plus environment-overlay behavior, provide Linux-specific examples, converge compose/Helm configuration, define writable state paths, and create systemd plus deb/rpm install, upgrade, and uninstall flows.  
**Acceptance criteria:** Fresh installs start, enroll, persist state, restart, and uninstall cleanly without Windows-only defaults or plaintext shared secrets.  
**Verification:** Package and lifecycle tests on every supported distribution.

## WP-LNX-004 Prove Linux Agent Discovery

**Priority:** P0  
**Depends on:** WP-LNX-003  
**Scope:** Validate source, binary, dependency, network, runtime, plugin, cache, and telemetry behavior on Linux. Correct platform-specific logs and ensure passive scans never write into scanned roots.  
**Acceptance criteria:** Each supported discovery mode has documented permissions, deterministic fixtures, and measured results.  
**Verification:** Native/container E2E tests and before/after filesystem, process, and network snapshots.

## WP-LNX-005 Engineer Linux Privileged Capabilities

**Priority:** P0  
**Depends on:** WP-LNX-003, WP-LNX-004  
**Scope:** Design explicit opt-in profiles for `/proc` memory access, host PID visibility, ptrace, plugins, and cgroup v2 isolation. Fail closed when permissions or isolation cannot be applied.  
**Acceptance criteria:** Default passive deployment is unprivileged; elevated capabilities are narrowly scoped, auditable, and never silently degraded.  
**Verification:** Capability-denial, cgroup, container, systemd-hardening, and privacy tests.

## WP-LNX-006 Correct Linux Migration And Interception

**Priority:** P0  
**Depends on:** WP-LNX-003, WP-LNX-005  
**Scope:** Disable the Linux interceptor until it safely resolves and calls original symbols. Build distro/init-aware nginx, Apache, and SSH adapters with validation, service discovery, transactional apply, and rollback.  
**Acceptance criteria:** Unsupported adapters fail before mutation; supported adapters survive validation/reload failures and restore the original service.  
**Verification:** Destructive sandbox tests across the supported Linux matrix.

## WP-LNX-007 Fix Linux Server And UI Deployment

**Priority:** P0  
**Depends on:** WP-LNX-002  
**Scope:** Choose and implement UI delivery through the server or a separate web container; provide runtime dependencies for supported PQ CSR behavior or disable it; replace invalid healthchecks; converge ports/configuration across Docker, compose, and Helm.  
**Acceptance criteria:** The canonical stack becomes healthy, serves the UI/API, connects agents, and reports unavailable optional capabilities truthfully.  
**Verification:** Container/compose/Helm smoke tests and browser/API E2E tests.

## WP-LNX-008 Establish Linux CI And Release Evidence

**Priority:** P0  
**Depends on:** WP-LNX-004, WP-LNX-005, WP-LNX-006, WP-LNX-007  
**Scope:** Add native, container, package, systemd, browser, and E2E jobs for the supported distro/libc/architecture matrix. Publish logs, test results, SBOMs, and signed artifacts.  
**Acceptance criteria:** Linux Gate L0 is required for merge and release; failures identify the affected platform/capability.  
**Verification:** Clean-clone and deliberately broken release-candidate exercises.

## WP-001 Restore Reproducible Builds

**Priority:** P0  
**Depends on:** WP-LNX-008  
**Scope:** Consolidate Linux and Windows build entrypoints, remove dependence on developer-machine tool layouts, pin generators and dependencies, and add format/lint configuration.  
**Acceptance criteria:** `make test`, Windows `BuildNoTools`, UI build, protobuf drift check, and documentation verifier pass from clean clones using documented toolchains.  
**Verification:** Hosted CI artifacts for Linux and Windows.

## WP-002 Establish Mandatory CI Quality Gates

**Priority:** P0  
**Depends on:** WP-001  
**Scope:** Add CI for Go tests/race/vet, Rust test/clippy/fmt, TypeScript build, Playwright, Helm lint/template, protobuf generation drift, dependency/license/secret scans, and docs verification. Replace or correct `scripts/janus-ci.sh`.  
**Acceptance criteria:** Protected branches require all gates; release builds are reproducible and signed.  
**Verification:** A deliberately broken build, lint issue, secret, and proto drift each fail CI.

## WP-003 Build Agent Identity And Trust Bootstrap

**Priority:** P0  
**Depends on:** WP-001  
**Scope:** Require mTLS for gRPC, bind certificate identity to `host_uuid`, implement enrollment tokens/certificate rotation/revocation, and authenticate agent HTTP calls with scoped credentials.  
**Acceptance criteria:** An agent cannot register, upload, fetch config, post diagnostics, retrieve commands, or report status as another host.  
**Verification:** Negative integration tests for spoofing, expired/revoked certs, and cross-host access.

## WP-004 Replace Shared Command HMAC With Per-Agent Authorization

**Priority:** P0  
**Depends on:** WP-003  
**Scope:** Use controller-held asymmetric signing keys or per-agent keys; sign the complete deterministic command envelope, including validation checks, target identity, nonce, expiry, policy version, and patch hash. Separate JWT/session keys from command keys.  
**Acceptance criteria:** Modified, replayed, expired, wrong-host, and previously executed commands are rejected and audited.  
**Verification:** Cryptographic test vectors and adversarial end-to-end tests.

## WP-005 Make Migration Delivery Durable

**Priority:** P0  
**Depends on:** WP-003, WP-004  
**Scope:** Replace in-memory queues with database-backed state transitions, leases, acknowledgements, retries, idempotency keys, cancellation, expiry, and reconnect delivery independent of telemetry upload.  
**Acceptance criteria:** Commands survive restart, HA failover, disconnects, and duplicate delivery without duplicate execution.  
**Verification:** Fault-injection tests kill controller/agent at every state transition.

## WP-006 Engineer Transactional Migration And Rollback

**Priority:** P0  
**Depends on:** WP-004, WP-005  
**Scope:** Use atomic writes, preserve ownership/mode/ACL/SELinux metadata, fsync, validate before replace where possible, reload after rollback, capture rollback failures, and implement service-specific transaction adapters.  
**Acceptance criteria:** Every supported adapter has tested pre-check, apply, validate, verify, rollback, and post-rollback verification behavior.  
**Verification:** Destructive sandbox tests for disk-full, permission, invalid config, reload failure, timeout, and health-check failure.

## WP-007 Enforce Truly Passive Discovery

**Priority:** P0  
**Depends on:** WP-001  
**Scope:** Remove all writes from discovery/check paths. Generate remediation artifacts only in an explicit output directory after user request. Gate memory scanning and active probing behind policy and consent.  
**Acceptance criteria:** Passive/check scans cause no file, registry, process, or network mutation in scanned targets.  
**Verification:** Filesystem/process/network side-effect tests and before/after snapshots.

## WP-008 Replace Cache Protection With Authenticated Secret Storage

**Priority:** P0  
**Depends on:** WP-001  
**Scope:** Use OS key stores/TPM/KMS-backed envelope encryption and AEAD for telemetry cache. Add key rotation, tamper detection, secure deletion policy, and migration from legacy formats.  
**Acceptance criteria:** Cache alteration is detected; keys are not derivable from public machine identifiers.  
**Verification:** Cryptographic test vectors, tamper tests, rotation tests, and threat-model review.

## WP-009 Remove Placeholder HSM And Crypto Claims

**Priority:** P0  
**Depends on:** WP-001, WP-002  
**Scope:** Disable placeholder HSM endpoints and claims until real PKCS#11 operations exist. Implement session/login/object lifecycle, mechanism discovery, signing/verification/key generation, health checks, and provider-specific conformance tests.  
**Acceptance criteria:** Verification fails for invalid signatures; operations use actual HSM keys; unavailable mechanisms fail closed.  
**Verification:** SoftHSM integration plus at least two real/vendor-compatible PKCS#11 test profiles.

## WP-010 Make Helm Deployment Production-Valid

**Priority:** P0  
**Depends on:** WP-003, WP-008  
**Scope:** Generate/mount agent TOML, writable state volumes, mTLS materials, external secrets, secure database TLS, NetworkPolicies, restricted RBAC, disruption budgets, anti-affinity, and fail-fast production values validation.  
**Acceptance criteria:** Default production profile rejects placeholder secrets/plaintext; server and agent run successfully with read-only roots.  
**Verification:** `helm lint`, schema tests, kind-based install/upgrade/rollback, and security-policy tests.

## WP-011 Implement Enterprise IAM And RBAC

**Priority:** P1  
**Depends on:** WP-003  
**Scope:** Replace static credentials with OIDC/SAML, short-lived sessions, refresh/revocation, MFA policy hooks, CSRF protection, secure cookies, and endpoint-level permissions.  
**Acceptance criteria:** Viewer/operator/admin/custom roles have explicit least-privilege permissions; every mutation records the authenticated actor.  
**Verification:** Authorization matrix tests for every route and WebSocket connection.

## WP-012 Harden HTTP, WebSocket, And Outbound Requests

**Priority:** P1  
**Depends on:** WP-011  
**Scope:** Enforce configured CORS/origin policy, use a maintained WebSocket library, apply rate/body/time limits, sanitize errors, validate webhook/LLM destinations, block metadata/private-network SSRF, and sign webhook payloads.  
**Acceptance criteria:** Cross-origin, oversized, flood, malformed WebSocket, and SSRF tests fail safely.  
**Verification:** DAST and focused adversarial integration tests.

## WP-013 Correct Data Model And Inventory History

**Priority:** P1  
**Depends on:** WP-001  
**Scope:** Scope findings by host/tenant, model occurrence lifecycle and reopen behavior, persist normalized components/algorithms/certificates/keys/protocols/evidence, and retain immutable scan snapshots/diffs.  
**Acceptance criteria:** Cross-host findings never collide; resolved findings reappear on recurrence; inventory history is queryable and attributable.  
**Verification:** Migration tests and multi-host lifecycle scenarios.  
**Current status (2026-06-12):** **Partially implemented.** DB migration 23 added `detection_method`, `resolved_at`, `reopened_at`, `reopen_count` to `finding_occurrences` and created `finding_lifecycle_events` table. `Store` interface has `RecordLifecycleEvent`/`ListLifecycleEvents`; `UpdateFindingStatus` now records lifecycle events transactionally. REST API: `GET /api/findings/{id}/timeline` returns ordered event history. Missing: automatic reopen-on-recurrence logic, multi-host/tenant scoping, full inventory diff snapshots.

## WP-014 Build Trustworthy Discovery Engines

**Priority:** P1  
**Depends on:** WP-007, WP-013  
**Scope:** Replace broad regex heuristics with language-aware AST/data-flow/call-graph analysis where supported; parse configuration formats structurally; add confidence provenance, reachability, ownership, environment, and data-lifetime context.  
**Acceptance criteria:** Published benchmark corpus reports precision/recall by detector and language; no detector labels heuristic reachability as proven.  
**Verification:** Versioned benchmark suite with false-positive/false-negative budgets.

## WP-015 Build Safe Remediation Generation

**Priority:** P1  
**Depends on:** WP-006, WP-014  
**Scope:** Replace token substitution with adapter/compiler-aware transformations, dependency updates, compatibility analysis, generated tests, human approval, and signed provenance. Treat LLM output as untrusted suggestions.  
**Acceptance criteria:** No generated patch can enter execution without parse/build/test validation and approval policy.  
**Verification:** Golden migration repositories and mutation testing.  
**Current status (2026-06-12):** **Partially implemented.** `server/internal/sandbox/simulator.go` now includes `CompatibilityAnalysis` and `DependencyUpdate` structs; `SimulationResult` has `HumanApprovalRequired: true` (hardcoded) and `CompatibilityAnalysis` field; `buildCompatibilityAnalysis()` generates breaking-change lists, dependency update hints (cargo/npm/go/pip), rollback risk, and hybrid TLS requirements based on algorithm migration path. `simulator_test.go` with 5+ tests. Missing: compiler-aware transform adapters, golden migration repos, mutation testing, signed provenance.

## WP-016 Make Network And PKI Assessment Evidence-Grade

**Priority:** P1  
**Depends on:** WP-014  
**Scope:** Add bounded protocol probes, trust and hostname validation, chain/expiry/revocation analysis, SNI/STARTTLS coverage, negotiated-group evidence, and target-specific post-migration checks.  
**Acceptance criteria:** Results distinguish reachability, untrusted TLS, protocol weakness, classical-only, and proven hybrid PQC.  
**Verification:** Controlled TLS/PKI interoperability lab and packet-level assertions.  
**Current status (2026-06-12):** **Partially implemented.** `agent/src/discovery/network.rs` probes TLS 1.x and STARTTLS (SMTP/LDAP/PostgreSQL/MySQL); produces 9 `TlsAssessmentCategory` variants with calibrated confidence values; collects cert subject/issuer/not_after/cipher/protocol into `BoundedEvidencePackage`. TLS metadata string now includes `ocsp:unchecked` fourth field (structural placeholder for WP-016 follow-on). `docs/NETWORK_ASSESSMENT.md` added (185 lines) documenting evidence schema, finding categories, and limitations. Missing: live OCSP stapling, CRL distribution point checks, CT log verification, TLS 1.0/1.1 detection, full chain validation.

## WP-017 Replace Heuristic Compliance With Versioned Controls

**Priority:** P1  
**Depends on:** WP-013, WP-016  
**Scope:** Define signed/versioned control packs with effective dates, evidence requirements, applicability, exceptions, expiry, and framework mappings. Remove unsupported “COMPLIANT” labels.  
**Acceptance criteria:** Every compliance result links to exact evidence, rule version, evaluation time, and exception state.  
**Verification:** Golden evidence bundles independently reproduce report outcomes.  
**Current status (2026-06-12):** **Partially implemented.** `server/internal/policy/control_pack.go` defines `ControlRule`/`ControlPack` structs and `BuiltinControlPack()` with 12 versioned rules (all rule IDs emitted by the engine), NIST/CNSA framework references, and effective dates. `Profile` struct now has `EffectiveDate`/`FrameworkMappings`. REST API: `GET /api/policy/rules` (pack list) and `GET /api/policy/rules/{id}` (single rule). 7 tests. Missing: exception workflow, evidence requirement fields, signed pack attestations, removal of remaining heuristic COMPLIANT labels.

## WP-018 Implement Real Metrics, Upgrade, And HSM Features

**Priority:** P1  
**Depends on:** WP-002, WP-009, WP-013  
**Scope:** Replace hard-coded SLA/certificate/upgrade data; implement signed update manifests, phased rollout, rollback, certificate health queries, and operational SLO calculations. Remove unavailable endpoints until implemented.  
**Acceptance criteria:** UI/API never presents fabricated operational values.  
**Verification:** Contract tests and signed-update end-to-end tests.  
**Current status (2026-06-12):** **Partially implemented.** DB migration 24 added `tls_certificates` table; `InsertTelemetry` now persists certificate expiry data from network observations; `GET /api/sla/metrics` `cert_health` field is now populated from real data (expired/expiring-30/expiring-90/total counts). SLA migration and finding remediation fields compute from real data. Agent upgrade endpoint correctly returns `auto_upgrade_available: false` (no fabricated values). Missing: signed update manifests, phased rollout, HSM cert queries (security phase), operational SLO trend data.

## WP-019 Create Full-System Test And Security Program

**Priority:** P1  
**Depends on:** WP-002 through WP-018  
**Scope:** Add unit, property, fuzz, race, integration, migration-adapter, HA, performance, chaos, and security tests. Maintain threat models for controller, agent, plugins, migration, and supply chain.  
**Acceptance criteria:** Critical paths meet defined coverage and fault-injection gates; external penetration testing has no unresolved critical/high findings.  
**Verification:** Release evidence package with test results, SBOMs, signatures, and remediation status.  
**Current status (2026-06-12):** **Partially implemented.** Go server: 18 test packages green (agility, config, httpapi, llm, orchestrator, policy, sandbox, scanconfig, store, waveplan — 37+ tests). Rust agent: 71 tests green across discovery, mutation, storage, evidence modules. New additions: `server/internal/policy/engine_fuzz_test.go` (FuzzAssess with 10 seeds), `server/internal/store/store_test.go` (migration version uniqueness, compile-time interface assertions, integration test skeleton). Missing: race tests (`-race` flag), chaos tests, HA failover tests, performance baselines, formal threat models, penetration test evidence.

## WP-020 Add HA, Tenancy, And Scale Architecture

**Priority:** P2  
**Depends on:** WP-005, WP-013  
**Scope:** Move process-local state to durable coordination, add tenant boundaries, row-level authorization, queue workers, backpressure, partitioning, observability, and disaster recovery.  
**Acceptance criteria:** Multiple controller replicas behave consistently and tenant data/actions cannot cross boundaries.  
**Verification:** Load, failover, restore, and tenant-isolation tests.

## WP-021 Deliver Standards-Compliant CBOM And Evidence Exports

**Priority:** P2  
**Depends on:** WP-013, WP-017  
**Scope:** Validate CycloneDX/SARIF outputs against schemas, model cryptographic assets and dependencies accurately, use RFC 3339 timestamps/source locations, sign attestations, and export immutable evidence bundles.  
**Acceptance criteria:** Exports pass schema validation and round-trip without losing identity/provenance.  
**Verification:** Automated schema/conformance tests and third-party consumer tests.  
**Current status (2026-06-12):** **Partially implemented.** CycloneDX 1.6 export now includes `cryptoProperties` (assetType, algorithmProperties with primitive, parameterSetIdentifier, nistQuantumSecurityLevel, mode) for all known algorithm types; `serialNumber` (urn:uuid); `tools` metadata with server version. SARIF 2.1.0 export now uses `version.Version` (no more hardcoded "0.1.0"), parses source locations from AssetRef (`file:line` → `region.startLine`), adds `properties` block (algorithm, confidence, status), and emits a `rules` list from unique policy rule IDs. Both exports tested with 26 unit tests. Missing: schema validation against upstream JSON schemas, signed attestations, immutable evidence bundles. WP-013 and WP-017 scaffolding now done.

## WP-022 Build Migration Portfolio And Wave Planning

**Priority:** P3  
**Depends on:** WP-013, WP-017, WP-020  
**Scope:** Add business owners, data-retention/HNDL risk, dependency graph, interoperability constraints, target states, exception workflow, waves, canaries, maintenance windows, approvals, budgets, and rollback SLA.  
**Acceptance criteria:** Operators can move from inventory to an approved, risk-ranked, dependency-safe migration program.  
**Verification:** End-to-end reference programs for web PKI, internal PKI, SSH, code signing, and application crypto.  
**Current status (2026-06-12):** **Extended.** `WavePlan` struct now has `CanaryTargets []string`, `MaintenanceWindow string`, `ApprovalPolicy string` (validated: auto/operator/admin/empty). DB migration 25 adds these columns with `CHECK` constraint on approval_policy. 15 tests passing (3 new: approval policy validation, canary targets, default policy). Missing: budget tracking, dependency graph, automated exercise harness.

## WP-023 Measure And Enforce Crypto Agility

**Priority:** P3  
**Depends on:** WP-015, WP-016, WP-022  
**Scope:** Define agility dimensions and continuously test algorithm negotiation, replacement, rollback, observability, provider portability, and policy response time.  
**Acceptance criteria:** Each asset receives an evidence-backed agility score and actionable blockers.  
**Verification:** Automated agility exercises across supported adapters.  
**Current status (2026-06-12):** **Scaffolded.** `server/internal/agility/` package computes: HardcodeIndex, NegotiationCoverage, BlastRadiusScore, ProfileAdoptionLatency, TTSA (when available), MaturityLevel (0–4). DB migration 21: `agility_metrics` table. REST API: `GET /api/agility/scorecard` (fleet + per-host). React UI: `ui/src/components/AgilityDashboard.tsx`. Documentation: `docs/AGILITY_SCORECARD.md`. 10 tests passing. Missing: automated agility exercise harness, per-adapter negotiation tests.

## WP-024 Add Enterprise Ecosystem Integrations

**Priority:** P3  
**Depends on:** WP-011, WP-013, WP-020  
**Scope:** Add cloud KMS/certificate managers, enterprise PKI/HSMs, CMDB, ticketing, SIEM/SOAR, CI systems, container/Kubernetes/cloud inventory, and vendor/supply-chain intake.  
**Acceptance criteria:** Integrations are scoped, authenticated, rate-limited, observable, and covered by contract tests.  
**Verification:** Certified integration test suites and reference deployments.

## WP-025 Establish Product Truth And Release Governance

**Priority:** P1  
**Depends on:** WP-002, ongoing  
**Scope:** Maintain a capability maturity matrix: `prototype`, `experimental`, `supported`, `certified`. Tie documentation and marketing claims to automated release evidence; publish security policy, support matrix, deprecation policy, and release notes.  
**Acceptance criteria:** No feature is described as supported without passing its release gates.  
**Verification:** Release review checklist and documentation-claim linter.  
**Current status (2026-06-12):** **Partially implemented.** `docs/CAPABILITY_MATURITY.md` written (maturity levels 0–4 per dimension). `IMPLEMENTATION_PLAN.md` updated to reflect actual implementation status for all LLM-* and WP-* items. `SECURITY.md` written: responsible disclosure process, operator security requirements (signing key, mTLS, auth, LLM modes, SQLite encryption), supported versions, and security architecture summary. `SUPPORT.md` written: maturity tier definitions (prototype/experimental/supported/certified), version support table, 90-day deprecation policy, execution and LLM capability mode tables, and issue filing guidance. Missing: automated documentation-claim linter, formal release evidence package.

## WP-026 Establish Privacy And Data Governance

**Priority:** P1  
**Depends on:** WP-003, WP-013, WP-014  
**Scope:** Classify telemetry/source snippets, minimize collection, require explicit LLM/memory-scan consent, redact secrets, enforce residency/retention policies, defend against prompt injection, and provide customer-controlled model endpoints.  
**Acceptance criteria:** Sensitive source or memory content cannot leave an endpoint without an explicit, auditable policy; operators can prove deletion and residency.  
**Verification:** Data-flow threat model, redaction corpus, prompt-injection tests, and privacy control audit.  
**Current status (2026-06-12):** **Substantially implemented.** `agent/src/evidence.rs` has `DataClassification` enum, all constructors populated, `redact_secrets()` covers 5 patterns (PEM, password, secret, api_key/apikey, AWS access key `AKIA...`). 11 tests cover classification, redaction, 512-byte cap, prompt injection input hardening, and network endpoint classification. `docs/PRIVACY_DATA_GOVERNANCE.md` written (323 lines): 10 sections covering data flows, classification, LLM consent (`BinaryLLMPolicy`), redaction (caller-must-invoke pattern), Linux AES-256-GCM encryption, key derivation, residency, and operator responsibilities. Missing: residency/retention enforcement in DB, customer-controlled model endpoints (security phase).

## WP-027 Build Interoperability And Certification Lab

**Priority:** P3  
**Depends on:** WP-009, WP-015, WP-016, WP-021  
**Scope:** Maintain repeatable interoperability matrices for TLS, PKI, HSM/KMS, SSH, code signing, libraries, and hybrid/PQC algorithm variants across supported platforms and vendors.  
**Acceptance criteria:** Supported migration targets have published compatibility evidence, performance baselines, failure modes, and rollback procedures.  
**Verification:** Automated lab reports attached to each release and adapter certification.  
**Current status (2026-06-12):** **Partially implemented.** `docs/ALGORITHM_COMPATIBILITY.md` (329 lines): NIST Quantum Security Level reference table, source-to-PQC migration matrix (RSA/ECDSA/ECDH/AES/SHA/TLS/PKCS7), key size comparisons, library support table (OpenSSL 3.5+ native, oqs-provider for 3.3/3.4, rustls, BoringSSL, libOQS, Go circl), migration sequencing guidance. Targets drawn from live `policies/nist-pqc-2026.yaml` and `policies/cnsa-2.0.yaml`. Missing: automated lab reports, performance baselines, failure-mode documentation, adapter certification process.

## Recommended Execution Order

1. **Prove Linux:** WP-LNX-001 through WP-LNX-008; pass Linux Gate L0.
2. **Stabilize cross-platform builds:** WP-001, WP-002.
3. **Secure the control plane:** WP-003 through WP-012.
4. **Make results and migrations trustworthy:** WP-013 through WP-019, WP-026.
5. **Scale and standardize:** WP-020, WP-021, WP-025.
6. **Lead the category:** WP-022 through WP-024, WP-027.
