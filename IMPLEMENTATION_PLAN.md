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
| LLM-021 Remove agent-initiated LLM from the scan path | **Implemented** | `agent/src/discovery/source.rs`: removed `analyze_snippet_llm_sync` and `generate_remediation_patch_llm` and their per-match call sites (commit 92d539a). Scanning is fully deterministic; the agent reports findings + bounded evidence only. `scan()` flag retained but ignored. 15 source tests pass. |
| LLM-022 Server-side admin-initiated batch analysis | **In progress** | Batch + filter selection endpoint, server-side evidence assembly, background worker, and findings-list UI selection + inline verdicts. See "Corrected LLM Analysis Flow" below for the normative design and acceptance criteria. |

### Corrected LLM Analysis Flow (LLM-021 / LLM-022)

**Problem identified.** Two defects broke the intended architecture:

1. *Agent initiated LLM during scanning (wrong).* The Rust source scanner called
   `POST /api/llm/proxy` synchronously **once per crypto match** — for intent
   classification and patch generation. The agent must never initiate LLM
   analysis; its responsibility ends at reporting findings + evidence. (Fixed in
   LLM-021.)
2. *Server analysis was one-finding-at-a-time (incomplete).* `POST /api/llm/analyze`
   accepts a single `finding_id`. There is no batch submission, no filter-based
   selection ("all", "all critical", by host/algorithm/status), no findings-list
   selection UI, and no inline verdict display. Queued jobs (no inline evidence)
   are never processed — there is no background worker.

**Normative corrected flow.** The only correct sequence is:

```
agents scan per policy → report findings (+ bounded evidence) → server stores findings
   → ADMIN selects findings in the UI: individual (checkbox) | subset | scope
     (all / all-critical / all-of-an-algorithm / per-host)
   → admin submits ONE batch request → server creates one analysis job per finding
   → background worker (bounded concurrency = JANUS_LLM_MAX_CONCURRENT) assembles
     evidence SERVER-SIDE from the stored finding + component context, calls the
     LLM, validates + persists the verdict and provenance
   → UI polls batch/job status → renders inline verdict per finding (real /
     false-positive / abstain, proposed adjusted severity, reasoning, citations)
   → admin acts on the verdict (accept / mark false-positive / remediate) — the
     LLM never mutates finding state; it only proposes (Invariant: authority
     inversion, LLM_CAPABILITY_CONTRACT §9).
```

**Work items (LLM-022):**

- **API — batch submit.** `POST /api/llm/analyze/batch` (role: operator/admin),
  accepting EITHER `finding_ids: ["…"]` OR a `filter` object
  (`severity_gte`, `status`, `algorithm`, `host_uuid`, `scope ∈ {all, all_critical}`).
  Server resolves the set, dedups against fresh existing verdicts (skip unless
  `force: true`), creates one job per finding, returns a `batch_id` + per-finding
  job ids. Caps batch size (e.g. ≤500) and logs an audit entry.
- **API — batch status.** `GET /api/llm/batches/{batch_id}` returns counts
  (queued/running/completed/failed) and per-finding verdict refs.
- **Worker.** A bounded-concurrency background worker drains queued jobs:
  assembles a `BoundedEvidencePackage` **server-side** from the stored finding
  (algorithm, context, file/host, detection method) — never trusting agent- or
  client-supplied evidence for control flow — then calls `AnalyzeFinding`.
  Respects `JANUS_LLM_MAX_CONCURRENT`, retries, and timeout from config.
- **UI — selection.** Findings list (Overview "Highest Priority Findings" and the
  CBOM findings grid) gains row checkboxes, select-all, and quick scopes
  ("Select all critical"). An "Analyze selected with AI" button (operator/admin
  only; hidden when LLM disabled) submits the batch.
- **UI — inline verdict.** Each finding row shows its latest verdict badge
  (real / false-positive / abstain + confidence), expandable to reasoning +
  citations + proposed severity, with accept / mark-false-positive / remediate
  actions wired to the existing finding-status endpoint.

**Acceptance criteria:**

- Agent performs zero LLM calls during a scan (grep: no `/api/llm/` in agent scan
  paths). ✅ (LLM-021)
- Selecting N findings and clicking "Analyze" creates N jobs from ONE request and
  processes them asynchronously with bounded concurrency.
- Filter scope "all critical" analyses exactly the open critical findings.
- Verdicts render inline in the findings list; LLM never changes finding status
  automatically.
- LLM disabled → batch endpoint returns 503 and the UI control is hidden.
- Server builds evidence; no endpoint requires the client to supply analysis
  evidence for the batch path.

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

## UI/UX Audit (UX-001 … UX-009)

Deep UI/UX pass 2026-06-13. Items marked **Implemented** shipped this pass;
**Coordinate** items overlap the CR-AFM fleet work / the in-flight `agents`→`hosts`
endpoint rename and must not be built in parallel.

| Task | Severity | Status | Detail |
| --- | --- | --- | --- |
| **UX-001** Stale scan progress on offline agents | Bug (user-reported) | **Implemented** | `scan_progress`/`current_scan_path` are live heartbeat values that freeze on disconnect — a finished agent shows 100%, a never-scanned one 0% — rendered as misleading "current work" (two offline agents at 100% and 0%). Server now zeroes both for offline agents in `assetSelect` (commit 11679d5), honest for every consumer. **Remaining (UI polish, in teammate's untracked HomeAgentStatus.tsx / AgentFleetInventory.tsx):** suppress the live progress bar entirely for offline/idle agents and show the state label instead of a 0% bar. |
| **UX-002** Dead agent-management endpoints | Broken flow | **Implemented** | Added `agent_routes.go` serving the full `/api/agents/{id}` subtree — detail (`AgentByID`), `/scans` (`ScanRuns`), `/connections` (`ConnectionHistory`), `/config` GET+PUT (`Get/UpdateAgentScanConfig`), `/commands` POST + `/commands/{id}` GET (`EnqueueAgentCommand`/`AgentCommand`) (commit f6e0ff1). Every handler is backed by an existing Store method — no schema changes. **Rescan is genuinely end-to-end:** the server enqueues a `scan-now` MigrationCommand the agent already recognizes (`comms.rs`) and acts on before the HMAC/mutation path, then reports status back which the UI polls. Mutations gated to operator/admin + audited. The Rescan button, Configure modal, and agent-detail drawer now work. |
| **UX-003** `/api/reports/{scanId}/findings` unregistered | Broken flow | **Implemented** | "Findings JSON" downloads (agent status + fleet inventory) and the drawer's latest-findings 404'd. Registered, backed by `store.ReportFindings` (commit 7edf24f). |
| **UX-004** `/api/scan-config/schema` unregistered | Broken flow | **Implemented** | The per-agent Configure modal requires the schema to validate; without it Apply stayed permanently disabled. Registered, returns `scanconfig.CurrentSchema()` (commit 7edf24f). |
| **UX-005** Unbounded rescan status polling | Reliability | **Implemented** | `HomeAgentStatus.requestScan` polled every 1 s with no cap; an offline-queued command looped forever. Now bounded to ~2 min then stops with a "still pending" note (commit b2e892a). |
| **UX-006** Configure modal has no focus trap | A11y | **Implemented** | The login modal uses `FocusTrap`; the per-agent Configure modal does not — focus isn't trapped and there's no Escape handler. Add both. |
| **UX-010** Unbounded agent list on the home page | Layout | **Implemented** | `HomeAgentStatus` rendered up to 10 agent cards in an unbounded vertical stack; a large fleet made the home page extremely tall. Now a bounded `max-h-[28rem]` scroll region with a "Showing X of N agents" header (commit b2e892a). |
| **UX-011** Unbounded Asset Remediation Status grid | Layout | **Implemented** | Rendered one card per asset with no bound. Now `max-h-72` scroll (commit 7a19cb9). |
| **UX-012** Unbounded Algorithm Exposure Distribution | Layout | **Implemented** | All histogram rows rendered unbounded. Now `max-h-80` scroll (commit 7a19cb9). |
| **UX-013** Unbounded active-scan banners | Layout | **Implemented** | One full-width banner per scanning agent stacked without bound. Now `max-h-72` scroll (commit 7a19cb9). |
| **UX-016** Honest-coverage table unbounded + no sticky header | Layout | **Implemented** | All asset rows rendered; header scrolled away. Now `max-h-80` scroll with a sticky header (commit 7a19cb9). |
| **UX-014** Long tables lack sticky headers | UX | **Implemented** | Added to the honest-coverage table (UX-016). `FindingsGrid` and `AgentFleetInventory` tables still scroll their headers off; apply sticky `thead` there too. |
| **UX-015** Branch did not build from a clean checkout | Build | **Fixed** | Seven UI source files (auth, authenticatedResource, version, vite-env, i18n, AgentFleetInventory, HomeAgentStatus) were untracked yet imported by tracked code. Tracked in commit b2e892a. |
| **UX-007** Fleet status filter mismatches data model | Bug | **Implemented** | `AgentFleetInventory` status filter offers `Scanning` (value `"Scanning"`) and `Connected` (value `"Idle"`), but a scanning agent's `status` is the **phase name** ("Static Source Analysis", "Uploading results"), never literally "Scanning" — so the Scanning filter never matches. Normalize status to a stable enum (scanning/idle/offline) server-side, or map phase→scanning in the filter. |
| **UX-008** Transient feedback lost on poll re-render | Consistency | **Implemented** | Rescan/config/export status is inline component state that disappears on the next 10–30 s poll re-render. Route through the existing `A11yAnnouncer`/a lightweight toast so confirmations persist and are announced. |
| **UX-009** No responsive fallback for fleet tables | UX | **Partial** | Inventory/coverage tables force `min-w-[1200px]` horizontal scroll on small screens; add column-priority or card layout at narrow widths. |

Several UX-00x UI items live in `HomeAgentStatus.tsx` / `AgentFleetInventory.tsx`, which are currently the Linux teammate's **untracked** working-tree files; their fixes are staged for that side to commit to avoid taking authorship (see JOURNAL.md).

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

---

## New Requirements — Operational Experience Audit (2026-06-12)

Identified through systematic codebase audit and hands-on operator testing. These are gaps not covered by the existing WP-* / LLM-* work packages.

### Status Table

| Work package | Priority | Status | Description |
| --- | --- | --- | --- |
| UX-001 | P1 | Not started | Agent scan control: pause, stop, resume, target path |
| UX-002 | P2 | Not started | Bulk finding actions: accept, remediate, assign |
| UX-003 | P2 | Not started | Finding assignment, comments, per-finding SLA |
| UX-004 | P2 | Not started | LLM configuration and testing panel in dashboard |
| UX-005 | P3 | Not started | Empty states and React error boundaries |
| UX-006 | P2 | Not started | Policy create/edit/import/export from UI |
| UX-007 | P2 | Not started | Wave plan visual editor and dependency graph |
| OPS-001 | P1 | Not started | Graceful server shutdown with drain period |
| OPS-002 | P2 | Not started | API-wide rate limiting (login, findings, migrations) |
| OPS-003 | P2 | Not started | Multi-channel notifications: email, Slack, PagerDuty |
| OPS-004 | P3 | Not started | Correlation IDs and distributed tracing |
| OPS-005 | P2 | Not started | OpenAPI 3.0 specification |
| OPS-006 | P2 | Not started | Prometheus metrics endpoint |
| OPS-007 | P2 | Not started | Incremental / changed-files-only scanning |
| AUTH-001 | P2 | Not started | Configurable JWT TTL and refresh-token flow |
| AUTH-002 | P2 | Not started | Password change and session revocation |
| AUTH-003 | P1 | Not started | Unauthenticated `/api/certificates/csr` endpoint (access-control bug) |
| AUTH-004 | P1 | Not started | HSM sign/verify endpoints lack role guard (access-control bug) |
| DOC-001 | P1 | Not started | Operator quick-start: default credentials, build outputs, env vars |
| DOC-002 | P2 | Not started | API reference with all endpoints, auth, request/response shapes |
| DOC-003 | P2 | Not started | Plugin development guide |
| DOC-004 | P2 | Not started | Troubleshooting runbook: common errors, log interpretation |
| LLM-021 | P2 | Not started | LLM config unification: reconcile env-var config with fleet-DB UI fields |
| LLM-022 | P2 | Not started | Interactive verdict review: accept/reject LLM verdicts from findings UI |
| LLM-023 | P2 | Not started | LLM usage dashboard: token spend, cost estimate, job success rate |

---

## UX-001 Agent Scan Control

**Priority:** P1
**Scope:** Operators need to pause, resume, cancel, and re-target an in-progress scan without restarting the agent process. A scan of a large codebase can take minutes to hours; the only current option is to kill and restart the agent.

**Evidence of gap:**
- `agent/src/main.rs:143` — outer scan loop has no interrupt path; `tokio::time::sleep` waits are not cancellable via API
- `agent/src/comms.rs` — only polls for `scan-now` command; no `PAUSE`, `RESUME`, `CANCEL`, `TARGET_PATH` command types
- `server/internal/httpapi/server.go` — no endpoint for scan control commands

**Acceptance criteria:**
- `POST /api/agents/{uuid}/command` accepts `{"command": "scan_cancel" | "scan_pause" | "scan_resume" | "scan_now" | "scan_target", "path": "..." }` (operator+ role)
- Agent polls this endpoint and acts within one heartbeat cycle (≤ 5 s)
- Fleet Command tab in UI shows per-agent control buttons: Scan Now, Pause, Resume, Cancel
- Cancelled scans upload partial results; paused scans resume from file-walk position
- Command delivery and outcome are logged in `agent_command_log` table

**Verification:** Agent integration test: send cancel command mid-scan, verify partial telemetry uploaded and scan stops.

---

## UX-002 Bulk Finding Actions

**Priority:** P2
**Scope:** Operators managing hundreds of findings need batch triage operations. Current UI updates one finding at a time; no server endpoint for batch updates.

**Evidence of gap:**
- `server/internal/httpapi/server.go:219` — `findingStatus()` handles one finding per request; no batch variant
- `ui/src/components/FindingsGrid.tsx` — no multi-select checkbox or bulk-action toolbar
- No `POST /api/findings/bulk-update` endpoint

**Acceptance criteria:**
- `POST /api/findings/bulk-update` accepts `[{finding_id, status}]` array (max 100); runs in a single DB transaction; returns per-item success/failure
- Findings table adds row checkboxes and a "Apply to selected" dropdown (Accept Risk / Mark Remediated / Assign)
- Bulk actions are recorded in `finding_lifecycle_events` with actor identity
- Bulk accept/remediate respects the same auto-reopen logic as individual updates

**Verification:** Bulk-update 50 findings in a single call; verify lifecycle events and DB state match.

---

## UX-003 Finding Assignment, Comments, and Per-Finding SLA

**Priority:** P2
**Scope:** Enterprise operators need to assign findings to owners, add investigation notes, and track remediation deadlines. None of this exists today.

**Evidence of gap:**
- `server/internal/store/store.go:148` — `Finding` struct has no `assigned_to`, `due_date`, or comment link
- `server/internal/httpapi/server.go` — no `/api/findings/{id}/comments` or `/api/findings/{id}/assign` endpoints
- `ui/src/components/FindingTimeline.tsx` — shows lifecycle events but no comment input or assignee display

**Acceptance criteria:**
- DB migration: `finding_comments` table (finding_id, actor, body, created_at); `assigned_to` + `due_date` columns on `finding_occurrences`
- `POST /api/findings/{id}/comments`, `GET /api/findings/{id}/comments` (paginated)
- `POST /api/findings/{id}/assign` (body: `{assigned_to, due_date}`)
- Finding timeline UI shows comments inline with lifecycle events; comment input box at bottom
- SLA breach (due_date < today, status != remediated) surfaces as a filter in findings view and contributes to `/api/sla/metrics`

**Verification:** Assign finding to user, add comment, verify both appear in timeline. Breach SLA and verify metric appears.

---

## UX-004 LLM Configuration and Testing Panel

**Priority:** P2
**Scope:** LLM settings are server env vars only; operators cannot change model, mode, timeout, or test connectivity from the UI. The LLM Analysis tab shows job history but no controls.

**Evidence of gap:**
- `server/internal/httpapi/llm_analysis.go:168` — `llmStatus()` returns read-only config summary; no write endpoint
- `ui/src/components/LLMAnalysis.tsx` — shows status card and jobs table; no settings form, no "Test Connection" button
- `server/internal/httpapi/server.go:82` — `/api/llm/test-connection` endpoint exists but is not wired to any UI element

**Acceptance criteria:**
- LLM Analysis tab gains a "Settings" sub-panel (operator+ role) showing: capability mode toggle, model names, timeout, max tokens/min, configured key status (masked)
- "Test Connection" button calls `GET /api/llm/test-connection` and shows latency + model response
- Settings are read-only display (env-var-sourced); panel includes a callout: "To change these values, update `JANUS_LLM_*` env vars and restart the server"
- LLM job list shows token usage and cost-estimate column (tokens × configurable rate)
- Verdict review inline: each job row expands to show verdict fields with Accept/Override buttons that call `PUT /api/findings/{id}/status`

**Verification:** Test connection shows success with latency. Submit analysis job; expand row; accept verdict; verify finding status updated.

---

## UX-005 Empty States and React Error Boundaries

**Priority:** P3
**Scope:** When there are no findings, agents, or components, the UI shows empty tables with no guidance. Unhandled render errors crash the entire app silently.

**Evidence of gap:**
- `ui/src/App.tsx` — no `<ErrorBoundary>` wrapper; a single component exception white-screens the app
- `ui/src/components/FindingsGrid.tsx` — empty array renders empty table rows, no "no findings" message
- Overview shows "Highest Priority Findings" heading even when the list is empty

**Acceptance criteria:**
- Root `App.tsx` and each tab panel wrapped in `ErrorBoundary` (shows "Something went wrong" + retry + report link)
- All list/table views show illustrated empty state with context-sensitive message and action button: e.g., "No agents registered — run `janus-agent --once`", "No findings — a scan hasn't completed yet"
- First-run experience: dashboard detects no agents registered and shows onboarding banner linking to quickstart

**Verification:** Disconnect DB mid-session; error boundary catches and shows recovery UI rather than white screen.

---

## UX-006 Policy Create, Edit, Import, Export From UI

**Priority:** P2
**Scope:** Policy profiles are YAML files on disk. Operators cannot create or edit a policy from the dashboard; they must SSH into the server and edit files directly. The Policy Studio tab shows policies read-only.

**Evidence of gap:**
- `server/internal/httpapi/server.go:63-65` — policies endpoints are GET-only; no POST/PUT/DELETE for policy CRUD
- `server/internal/policy/engine.go` — loads profiles from `policies/` directory at startup; no hot-reload
- `ui/src/components/PolicyStudio.tsx` — renders profile details as read-only fields

**Acceptance criteria:**
- `POST /api/policies` (create), `PUT /api/policies/{version}` (update), `DELETE /api/policies/{version}` (admin only) — writes to `policies/` directory and triggers engine reload
- `GET /api/policies/{version}/export` — returns validated YAML for download
- `POST /api/policies/import` — accepts YAML, validates schema, saves as new version
- Policy Studio gains edit form for threshold fields (min RSA bits, require TLS 1.3, etc.) and "Save as New Version" + "Export YAML" buttons
- Policy changes emit `policy_switched` WebSocket event and appear in compliance report immediately

**Verification:** Create a policy via UI, verify it appears in profile list and takes effect on next finding assessment.

---

## UX-007 Wave Plan Visual Editor and Dependency Graph

**Priority:** P2
**Scope:** Wave plans exist in the DB with full CRUD but there is no dependency graph between plans, no visual timeline, and no progress tracking per wave. Operators must use the API directly.

**Evidence of gap:**
- `server/internal/store/store.go:370` — `WavePlan` struct has all fields but no `DependsOn []string` dependency graph
- `server/internal/httpapi/agility_waves.go` — CRUD endpoints exist; no `/api/waves/{id}/dependency-graph` or progress endpoint
- `ui/src/components/AgilityDashboard.tsx` — scorecard only; no wave plan editor or Gantt view

**Acceptance criteria:**
- DB migration: `wave_plan_dependencies` table (plan_id, depends_on_plan_id); cycle detection on save
- `GET /api/waves/dependency-graph` returns nodes + edges for visualization
- Wave plans UI sub-tab: Gantt-style timeline showing plans, their windows, and status
- Per-wave progress: `component_count` used as denominator; findings by status per wave component as numerator
- Topological execution order displayed; blocked plans shown with blocker name

**Verification:** Create two waves with dependency; verify graph endpoint returns correct edge; verify blocked wave cannot start until dependency is complete.

---

## OPS-001 Graceful Server Shutdown

**Priority:** P1
**Scope:** `SIGTERM` kills the server immediately, dropping in-flight gRPC streams, HTTP requests, and pending webhook dispatches. Kubernetes rolling updates lose telemetry from agents mid-upload.

**Evidence of gap:**
- `server/cmd/janus-server/main.go` — no `signal.NotifyContext` or graceful shutdown handler visible
- `server/internal/grpcserver/server.go` — gRPC `StreamTelemetry` streams have no drain mechanism
- `server/internal/grpcserver/server.go:315` — webhook goroutines are fire-and-forget with no wait group

**Acceptance criteria:**
- On `SIGTERM` / `SIGINT`: stop accepting new HTTP connections (return 503), wait up to `JANUS_GRACEFUL_SHUTDOWN_SECONDS` (default 30) for in-flight requests to complete, close gRPC server with `GracefulStop()`, flush pending webhook goroutines, close DB pool
- Health endpoint returns `{"status": "draining"}` during shutdown
- Agent detects 503 and queues payloads to SQLite for retry after reconnect

**Verification:** Send SIGTERM during active telemetry upload; verify payload lands in DB (not dropped); verify agent retried from SQLite queue on reconnect.

---

## OPS-002 API-Wide Rate Limiting

**Priority:** P2
**Scope:** Rate limiting middleware exists (`features.go:302`) but is only applied to `/api/llm/proxy`. Login endpoint, findings queries, and migration enqueue have no protection against brute-force or flooding.

**Evidence of gap:**
- `server/internal/httpapi/server.go:81` — `RateLimit()` applied only to one route
- `server/internal/httpapi/auth.go:200` — login handler has no attempt throttling; brute-force of the 3 hardcoded accounts is trivial
- No `429 Too Many Requests` responses observed on any other endpoint

**Acceptance criteria:**
- `JANUS_RATE_LIMIT_GLOBAL_PER_MINUTE` (default 300/IP/min) applied to all routes via middleware
- `JANUS_RATE_LIMIT_LOGIN_PER_MINUTE` (default 5/IP/min) applied specifically to `/api/auth/login`
- Migration enqueue: max 10/min/operator
- Returns `429` with `Retry-After` header; logs at WARN with IP
- Rate limit counters reset on server restart (in-memory; no Redis dep for prototype)

**Verification:** Exceed login limit; verify 429 returned on 6th attempt within one minute.

---

## OPS-003 Multi-Channel Notifications

**Priority:** P2
**Scope:** Critical findings only dispatch to SIEM webhooks. No email, Slack, or PagerDuty support. Operators miss events unless they run a separate SIEM.

**Evidence of gap:**
- `server/internal/httpapi/server.go:78` — only `/api/webhooks` (generic SIEM webhook)
- No `notification_channels` table in store; no send-email/send-slack helper
- README.md does not list any notification channel beyond webhooks

**Acceptance criteria:**
- `notification_channels` table: (id, type [email|slack|pagerduty|webhook], destination, event_filter, active)
- `POST /api/notifications/channels`, `GET /api/notifications/channels`, `DELETE /api/notifications/channels/{id}`
- Email: SMTP config via `JANUS_SMTP_*` env vars; sends HTML summary for critical findings
- Slack: incoming webhook URL; sends formatted attachment with finding + remediation link
- PagerDuty: Events API v2; severity mapping (critical=P1, high=P2)
- All channels share the same circuit-breaker logic already in `grpcserver/server.go`
- UI: Notifications tab in Settings showing channel list, add/edit form, test-send button

**Verification:** Configure Slack channel; trigger critical finding; verify message delivered with correct fields.

---

## OPS-004 Correlation IDs and Structured Log Tracing

**Priority:** P3
**Scope:** Multi-component flows (agent → gRPC → server → DB → webhook) cannot be traced end-to-end. Debugging requires manual cross-service log grepping.

**Evidence of gap:**
- `server/internal/httpapi/auth.go` middleware — no `X-Correlation-ID` injection
- All `slog.Info()` calls in `grpcserver/server.go` log without a request-scoped trace ID
- Agent logs (`eprintln!` / Rust `log`) have no correlation to server-side request IDs

**Acceptance criteria:**
- Auth middleware injects `X-Correlation-ID` (UUID) into request context and response header; passes to DB calls via `pgx` context
- `host_uuid` included in every server-side log line touching that agent
- Agent logs include `telemetry_id` from `CbomTelemetryPayload` in all relevant lines
- Optional: `JANUS_OTLP_ENDPOINT` config for OpenTelemetry trace export (disabled by default)

**Verification:** Trace a single telemetry upload across agent log, gRPC server log, and DB audit log by correlation ID.

---

## OPS-005 OpenAPI 3.0 Specification

**Priority:** P2
**Scope:** 40+ REST endpoints with no machine-readable contract. Integrators and tool vendors must reverse-engineer the API from README markdown or source code. No SDK generation, no client validation, no breaking-change detection in CI.

**Evidence of gap:**
- `README.md:325` — API reference is a hand-written markdown table
- No `/api/openapi.json` or `/api/swagger.json` endpoint
- No spec file in repo; no CI diff check

**Acceptance criteria:**
- `GET /api/openapi.json` returns OpenAPI 3.0 spec (hand-authored or generated)
- Spec covers all endpoints: path, method, request schema, response schema, auth requirement, error codes
- CI step: `make api-spec-check` diffs committed spec against current routes and fails if they diverge
- Spec linked from README "API Reference" section

**Verification:** Generate a Go client from the spec; call `/api/overview` and `/api/findings` successfully.

---

## OPS-006 Prometheus Metrics Endpoint

**Priority:** P2
**Scope:** No operational metrics are exported. Operators cannot monitor request latency, finding ingestion rate, DB pool health, or webhook failure rate from their existing monitoring stack.

**Evidence of gap:**
- No `GET /metrics` endpoint; no `prometheus/client_golang` dependency
- `server/internal/grpcserver/server.go` — webhook failure is logged but not counted
- No DB pool utilization visible externally

**Acceptance criteria:**
- `GET /metrics` (Prometheus text format, no auth required for scraping) exposes:
  - `janus_http_requests_total{method,path,status}` — request counter
  - `janus_http_request_duration_seconds{path}` — latency histogram
  - `janus_findings_total{severity,status}` — finding gauge
  - `janus_agents_connected` — connected agent gauge
  - `janus_webhook_dispatches_total{status}` — webhook success/failure counter
  - `janus_db_pool_connections{state}` — DB pool stats
- `JANUS_METRICS_ADDR` (default empty = disabled) configures a separate listen address for metrics scraping

**Verification:** Scrape `/metrics` with `curl`; parse output with `promtool check metrics`; verify counters increment on request.

---

## OPS-007 Incremental / Changed-Files-Only Scanning

**Priority:** P2
**Scope:** Every scan re-processes all files from scratch. For large repositories (100k+ files) this means scans take tens of minutes even when only a handful of files changed. The `scan_state` table in SQLite was built for this but is not used to skip unchanged files.

**Evidence of gap:**
- `agent/src/storage.rs` — `scan_state` table stores `content_hash` per file path
- `agent/src/discovery/source.rs:scan()` — walks all files unconditionally; no skip-on-hash-match logic
- `agent/src/main.rs` — no diff-only mode or changed-set argument

**Acceptance criteria:**
- `scan()` computes SHA-256 of each file before parsing; skips if hash matches `scan_state` entry and entry is < `max_cache_age_hours` old
- Full re-scan forced when: hash mismatch, cache miss, policy version changed since last scan, or operator sends `scan_now` command with `force_full=true`
- `--changed-since <git-ref>` flag for `check` subcommand: only scans files modified between `git-ref` and HEAD
- Progress reporting reflects skipped files (count shown separately from scanned)
- `scan_state` entries pruned for deleted files on each full scan

**Verification:** Run full scan; modify 2 files; run incremental scan; verify only 2 files re-analyzed; verify findings still reflect full picture (unchanged findings retained from prior scan).

---

## AUTH-001 Configurable JWT TTL and Refresh Flow

**Priority:** P2
**Scope:** JWT expiry is hardcoded to 24 hours (`auth.go:45`). No refresh mechanism means long-running operator sessions expire mid-workflow. Compliance environments often require shorter TTLs.

**Evidence of gap:**
- `server/internal/httpapi/auth.go:45` — `time.Now().Add(24 * time.Hour)`
- No `JANUS_JWT_TTL_SECONDS` env var
- No `POST /api/auth/refresh` endpoint
- Long-running operations (batch migrations, agility exercises) may span the 24h window

**Acceptance criteria:**
- `JANUS_JWT_TTL_SECONDS` (default 86400, range 900–2592000) controls access token lifetime
- `POST /api/auth/refresh` — accepts a valid (non-expired) token, returns a new token with reset TTL; rate-limited to 10/hour/user
- Token expiry shown in UI (countdown or "expires in X hours" in header)
- Agent uses separate long-lived API key (not JWT); not affected by this change

**Verification:** Set TTL to 1800; verify token expires after 30 min; verify refresh returns new valid token.

---

## AUTH-002 Password Change and Session Revocation

**Priority:** P2
**Scope:** Users cannot change their password. Admin cannot revoke a compromised session. Offboarded users' sessions persist until expiry. This is a gap even for the static-credential prototype.

**Evidence of gap:**
- No `POST /api/auth/password-change` endpoint
- No session table; no revocation mechanism
- `auth.go:214` — credential check is against compile-time constants; no runtime update path

**Acceptance criteria:**
- `POST /api/auth/password-change` (authenticated) — accepts `{current_password, new_password}`; new password min 12 chars; bcrypt-hashed in DB
- `POST /api/admin/revoke-sessions/{username}` (admin only) — adds token hash to a `revoked_tokens` blacklist table; checked in `VerifyToken`
- Blacklist entries pruned when their original TTL would have expired
- UI: "Change Password" option in user menu (top-right header)

**Verification:** Change password; verify old password no longer works. Revoke session; verify next API call returns 401.

---

## AUTH-003 Unauthenticated CSR Endpoint (Access-Control Bug)

**Priority:** P1
**Scope:** `/api/certificates/csr` is in the public allowlist — any network client can generate PQC certificate signing requests without authentication. This bypasses operator control over certificate issuance.

**Evidence of gap:**
- `server/internal/httpapi/auth.go:122` — `/api/certificates/csr` explicitly allowed without JWT
- `server/internal/httpapi/server.go:58` — route registered without `RequireRole()`

**Acceptance criteria:**
- Remove `/api/certificates/csr` from the unauthenticated allowlist in `auth.go`
- Apply `RequireRole([]string{"operator", "admin"})` guard at route registration
- CSR generation attempts are logged with actor identity
- Test: unauthenticated POST returns 401; operator POST succeeds

**Verification:** Unit test in `httpapi/handlers_test.go` confirms unauthenticated request returns 401.

---

## AUTH-004 HSM Sign/Verify Endpoints Lack Role Guard (Access-Control Bug)

**Priority:** P1
**Scope:** `/api/hsm/sign` and `/api/hsm/verify` are registered without `RequireRole()`, allowing any authenticated user (including viewers) to invoke HSM cryptographic operations.

**Evidence of gap:**
- `server/internal/httpapi/server.go:109-110` — both routes use bare `mux.HandleFunc()` with no role middleware
- `/api/migrations/enqueue` (line 61) correctly uses `RequireRole([]string{"operator", "admin"})` — HSM endpoints should match

**Acceptance criteria:**
- Both HSM routes wrapped with `RequireRole([]string{"operator", "admin"})`
- Test: viewer-role token returns 403; operator-role token succeeds

**Verification:** Unit test confirms viewer token returns 403 for both endpoints.

---

## DOC-001 Operator Quick-Start Guide

**Priority:** P1
**Scope:** The README does not document: default login credentials, actual binary output paths after `make build`, what `JANUS_DISABLE_AUTH` actually does to the login flow, minimum required env vars to start, or what the agent config fields mean. First-time operators get blocked on each of these.

**Evidence of gap:**
- `README.md` "Running" section lists commands but not binary output paths (`server/janus-server`, `agent/target/release/janus-agent`)
- Default credentials (`admin`/`janus-admin-pass`) appear only in `auth.go:214` — not documented anywhere
- `JANUS_DISABLE_AUTH` behavior (bypasses server JWT but not UI login screen) not explained
- Agent config fields (`enable_runtime_discovery`, TLS probing, `command_signing_key` required) not explained outside the example TOML comments

**Acceptance criteria:**
- `docs/QUICKSTART.md` (≤ 2 pages) covering: prerequisites, 5-command startup (postgres + server + UI + agent), default credentials table, binary paths, minimum env vars, first-scan verification
- README "Quick Start" section links to `docs/QUICKSTART.md` and shows the 5-command sequence
- Each agent config field in `janus-agent.example.toml` has an inline comment explaining its effect and whether it requires elevated privileges

**Verification:** A new engineer can go from zero to first finding displayed in < 15 minutes following only `docs/QUICKSTART.md`.

---

## DOC-002 API Reference

**Priority:** P2
**Scope:** The README has a partial API endpoint table with no request/response schemas, no auth requirements per endpoint, and no error codes. Integrators cannot write clients without reading server source code.

**Acceptance criteria:**
- `docs/API_REFERENCE.md` covering every endpoint: method, path, auth role required, request body schema, response schema, example `curl` call, common error codes
- Kept in sync with `server/internal/httpapi/server.go` route registrations (CI check)
- Alternatively, superseded by OPS-005 (OpenAPI spec)

---

## DOC-003 Plugin Development Guide

**Priority:** P2
**Scope:** Janus supports external plugins via `plugin_commands` config, but there is no documentation on how to write one, what output format is expected, what resource limits apply, or how to test one.

**Acceptance criteria:**
- `docs/PLUGIN_GUIDE.md`: plugin contract (stdin/stdout JSON schema), resource limits (memory_mb, cpu_percent), supported OS environments, example plugin (Python + shell), testing with `janus-agent check --plugin-only`, error handling

---

## DOC-004 Troubleshooting Runbook

**Priority:** P2
**Scope:** Common failure modes have no documented resolution path. Users must read source code or ask for help to diagnose issues.

**Acceptance criteria:**
- `docs/TROUBLESHOOTING.md` covering at minimum: "Incompatible API version" error (rebuild server), agent flood log (LLM timeout — now fixed), login loop, agent won't register (signing key mismatch), database migration failures, gRPC connection refused, scan finds nothing (exclusion list too broad)
- Each entry: symptom, likely cause, diagnostic command, resolution

---

## LLM-021 LLM Configuration Unification

**Priority:** P2
**Scope:** LLM config exists in two places: server env vars (`JANUS_LLM_*`) and fleet-DB UI fields (saved by FleetManagement.tsx but never read by the service). The UI fields are misleading — operators think they're configuring LLM but the server ignores those values.

**Evidence of gap:**
- `ui/src/components/FleetManagement.tsx:31-46` — `llmApiKey`, `llmApiUrl` fields saved to fleet DB
- `server/internal/llm/service.go:44` — only reads `cfg.LLM` from env; never queries fleet DB
- Two sources of truth creates confusion about which value is authoritative

**Acceptance criteria:**
- Either: (a) remove the DB-stored LLM fields from FleetManagement and replace with read-only display of env-var-sourced config (simpler), OR (b) move all LLM config to DB and hot-reload on change
- Chosen approach documented in `CLAUDE.md` and in the UI with a callout
- No silent config divergence: if DB fields exist but env vars disagree, server logs a warning at startup

---

## LLM-022 Interactive Verdict Review in Findings UI

**Priority:** P2
**Scope:** LLM verdicts are visible only in the LLM Analysis tab. Operators cannot review a verdict in context while looking at a finding's detail panel. Accepting or overriding a verdict requires navigating away from the finding.

**Acceptance criteria:**
- Finding detail panel shows LLM verdict (if exists): verdict label, confidence bar, reasoning, evidence citations
- "Accept Verdict" button: if `confirmed` → no-op; if `false_positive` → sets finding status to `accepted_risk`; if `severity_adjusted` → prompts to apply adjusted severity
- "Override" button: opens dialog to set manual status regardless of verdict
- Verdict acceptance is recorded in `finding_lifecycle_events` with `actor` = logged-in user

---

## LLM-023 LLM Usage Dashboard

**Priority:** P2
**Scope:** No visibility into LLM token consumption, cost, or job success rate. Operators cannot track spend or identify runaway analysis jobs.

**Acceptance criteria:**
- `GET /api/llm/usage/summary` returns: total jobs (by status), total tokens in/out, estimated cost (configurable $/1k tokens), avg latency, top-5 models used
- LLM Analysis tab gains a "Usage" sub-panel with these metrics, updated on each job completion via WebSocket
- `JANUS_LLM_COST_PER_1K_TOKENS_IN` / `_OUT` env vars for cost estimation (default 0 = not shown)
- Token budget enforcement: if `JANUS_LLM_MAX_TOKENS_PER_REQUEST` exceeded, job is rejected before calling provider

---

## Recommended Execution Order

1. **Prove Linux:** WP-LNX-001 through WP-LNX-008; pass Linux Gate L0.
2. **Stabilize cross-platform builds:** WP-001, WP-002.
3. **Secure the control plane:** WP-003 through WP-012.
4. **Make results and migrations trustworthy:** WP-013 through WP-019, WP-026.
5. **Scale and standardize:** WP-020, WP-021, WP-025.
6. **Lead the category:** WP-022 through WP-024, WP-027.
7. **Operational experience (new):** AUTH-003, AUTH-004, OPS-001 (P1 fixes first), then DOC-001, UX-001, OPS-002, UX-002, UX-003, UX-004, LLM-021, LLM-022, AUTH-001, OPS-003, OPS-005, OPS-006, OPS-007, UX-006, UX-007, LLM-023, OPS-004, AUTH-002, DOC-002, DOC-003, DOC-004, UX-005.
