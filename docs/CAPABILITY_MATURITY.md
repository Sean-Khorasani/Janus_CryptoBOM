# Capability Maturity Framework — Janus CryptoBOM

This document defines the five-dimension capability maturity framework for Janus CryptoBOM (WP-025 / TRUTH-01). No feature is described as "supported" without passing its defined release gates.

---

## §1 Overview

Janus CryptoBOM tracks maturity across five dimensions that together determine whether a deployment can be trusted to drive post-quantum migration decisions:

| # | Dimension | What it measures |
|---|---|---|
| 1 | **Discovery Coverage** | Breadth and precision of cryptographic asset detection |
| 2 | **Assessment Accuracy** | Confidence in severity and compliance determinations |
| 3 | **Agility Metrics** | Ability to measure and act on cryptographic agility |
| 4 | **Migration Safety** | Correctness and reversibility of active changes |
| 5 | **LLM Trustworthiness** | Authority-inversion enforcement in AI-assisted workflows |

Each dimension has five levels (0–4). An organization's overall maturity is the minimum across all five dimensions — a single weak dimension bounds the whole program.

---

## §2 Maturity Levels by Dimension

### Dimension 1: Discovery Coverage

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No systematic crypto discovery; findings are ad-hoc or manual |
| 1 | Reactive | Regex-based source scan on a subset of the codebase; no binary, network, or dependency analysis |
| 2 | Planned | Multi-source discovery (source + binary + dependency + network); scheduled scans; path exclusions configured |
| 3 | Agile | Confidence scoring with detection method provenance; test-file exclusion; multi-pattern corroboration; scan diffing against baseline |
| 4 | CryptoAgile | Language-aware AST analysis for primary languages; false-positive budget measured and within thresholds; benchmark corpus with precision/recall report published |

**Current Janus status (2026-06-12):** Level 2–3. Regex source + binary + dependency + network scan implemented. `DetectionMethod` enum with confidence floors. `BoundedEvidencePackage` for evidence provenance. Missing: AST analysis, published benchmark corpus.

### Dimension 2: Assessment Accuracy

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No policy assessment; all findings have identical severity |
| 1 | Reactive | YAML policy profiles with hardcoded rules; severity mapped to 1–5 scale |
| 2 | Planned | CNSA 2.0 and NIST FIPS 203/204/205 assessment; context-aware severity (verify/parse/negotiate adjust confidence); OSV CVSS score mapping |
| 3 | Agile | Statistical confidence analysis; QRisk scoring; `ConfidenceAnalyzer` with per-finding confidence intervals; LLM-assisted triage with schema-validated output (human approval required) |
| 4 | CryptoAgile | Versioned signed control packs (WP-017); every compliance result links to exact evidence, rule version, and evaluation time; independent review confirms results |

**Current Janus status (2026-06-12):** Level 2–3. Policy profiles with CNSA 2.0/NIST rules. Context-aware severity in `policy.Assess()`. `ConfidenceAnalyzer` implemented. LLM verdict schema validation with 15 passing tests. Missing: versioned signed control packs, independent verification corpus.

### Dimension 3: Agility Metrics

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No measurement of cryptographic agility |
| 1 | Reactive | Manual inventory of algorithm usage; no automated measurement |
| 2 | Planned | HardcodeIndex and NegotiationCoverage computed from findings; BlastRadiusScore per algorithm |
| 3 | Agile | Automated scorecard via API; TTSA measurement; ProfileAdoptionLatency tracking; per-host and fleet views; maturity level (0–4) assignment |
| 4 | CryptoAgile | Automated agility exercises per adapter; negotiation tested end-to-end; TTSA measured under simulated CRQC deadline; continuous agility monitoring |

**Current Janus status (2026-06-12):** Level 3. `server/internal/agility/` package computes all five metrics. DB migration 21 (`agility_metrics`). `GET /api/agility/scorecard` fleet + per-host API. React UI (`AgilityDashboard.tsx`). `docs/AGILITY_SCORECARD.md` published. Missing: automated exercises, end-to-end negotiation tests.

### Dimension 4: Migration Safety

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No migration capability; manual ad-hoc changes only |
| 1 | Reactive | Manual migration commands generated; no automated execution |
| 2 | Planned | HMAC-signed migration commands; atomic backup → write → validate → rollback on failure; file extension allowlist; path traversal sandbox |
| 3 | Agile | Dry-run simulation (`/api/sandbox/simulate`); wave planning with state machine; pre-activation readiness checklist; post-migration TLS verification; audit trail |
| 4 | CryptoAgile | Canary deployment with automatic promotion/rollback; maintenance window enforcement; dependency-graph-aware ordering; golden migration repositories; mutation testing |

**Current Janus status (2026-06-12):** Level 3. Full mutation engine with HMAC verification and atomic rollback. `sandbox.Simulator` for dry runs. Wave plan CRUD with state machine and readiness checklist (WP-022). Audit logging. `docs/WAVE_PLANNING_GUIDE.md` published. Missing: canary deployment, dependency graph, golden repositories.

### Dimension 5: LLM Trustworthiness

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No LLM integration; or LLM output applied directly without review |
| 1 | Reactive | LLM proxy available; no schema validation; no provenance; results may overwrite scanner facts |
| 2 | Planned | Capability mode gating (`disabled`/`analysis_only`/`suggest_remediation`); schema-validated verdicts; `HumanApprovalRequired: true` on all suggestions; LLM output cannot directly modify finding status |
| 3 | Agile | Full provenance chain (provider, model, prompt version, input/output hashes, token counts, latency); immutable audit trail; abstention mechanism; binary analysis opt-in policy per agent; 8 architectural invariants enforced |
| 4 | CryptoAgile | Published precision/recall on representative corpus; prompt-injection test suite; provider-contract tests; cost/token budget enforcement; automated evaluation gates block release on regression |

**Current Janus status (2026-06-12):** Level 3. `docs/LLM_CAPABILITY_CONTRACT.md` defines 8 invariants. `server/internal/llm/` pipeline with schema-validated verdicts (15 tests). `llm_provenance` table (immutable). `BinaryLLMPolicy` in agent config (all false by default). Missing: published evaluation corpus, prompt-injection tests, cost budget enforcement.

---

## §3 Advancing Maturity

### To reach Level 2 (Planned) in all dimensions

- Configure at least one scan root in `janus-agent.example.toml` with `enable_active_tls_probing = true`
- Deploy the server with `JANUS_COMMAND_SIGNING_KEY` set
- Load either the `nist-pqc-2026` or `cnsa-2.0` policy profile

### To reach Level 3 (Agile) in all dimensions

- Complete Level 2
- Enable scheduled scans (default 15-minute interval)
- Set `JANUS_LLM_CAPABILITY_MODE=analysis_only` with a valid provider key
- Create at least one wave plan and run a dry-run simulation before any active migration
- Review `GET /api/agility/scorecard` and address findings in the top blast-radius algorithms

### To reach Level 4 (CryptoAgile) in all dimensions

- Complete Level 3
- Publish a discovery benchmark corpus with false-positive budget < 5% for each supported language
- Implement versioned signed control packs (WP-017 full implementation)
- Build canary deployment harness for migrations (WP-022 full implementation)
- Publish LLM evaluation corpus and set release gate on precision/recall regression (LLM-19)
- Complete WP-019 (full-system test program)

---

## §4 Assessment Cadence

| Cadence | Activity |
|---|---|
| Every scan | Update HardcodeIndex, NegotiationCoverage, BlastRadiusScore |
| Weekly | Review agility scorecard for maturity regression |
| Per policy switch | Measure ProfileAdoptionLatency against 14-day target |
| Per Janus release | Re-run capability maturity assessment; update this document |
| Annually | External security review; update threat model |

---

## §5 Integration with the Agility Scorecard

The agility scorecard (see `docs/AGILITY_SCORECARD.md`) provides continuous metric tracking for **Dimension 3**. Maturity levels from the scorecard (`none`/`reactive`/`planned`/`agile`/`crypto_agile`) map directly to levels 0–4 in this framework.

When the scorecard shows a maturity regression (e.g., HardcodeIndex rises above 5%), treat it as a maturity-level downgrade and investigate before the next scheduled wave activation.

The `GET /api/agility/scorecard` endpoint provides fleet and per-host views with `top_blast_radius` algorithms — use these to prioritize migration waves (see `docs/WAVE_PLANNING_GUIDE.md`).

---

## §6 Relationship to WP Items

| WP Item | Maturity Impact |
|---|---|
| WP-013 | Discovery Coverage 2→3 (occurrence lifecycle) |
| WP-014 | Discovery Coverage 3→4 (AST analysis, benchmark corpus) |
| WP-015 | Migration Safety 3→4 (compiler-aware transforms) |
| WP-016 | Assessment Accuracy 3→4 (evidence-grade network PKI) |
| WP-017 | Assessment Accuracy 3→4 (versioned signed control packs) |
| WP-019 | All dimensions 3→4 (full test program) |
| WP-022 | Migration Safety 3→4 (canary, dependency graph) |
| WP-023 | Agility Metrics 3→4 (automated exercises) |
| LLM-13/14 | LLM Trustworthiness 3→4 (deterministic validation, governed execution) |
| LLM-19 | LLM Trustworthiness 3→4 (evaluation corpus, release gates) |
