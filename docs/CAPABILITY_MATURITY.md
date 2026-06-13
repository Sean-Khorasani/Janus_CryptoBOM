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

Each dimension has five levels (0–4). An organization's overall maturity is the **minimum across all five dimensions** — a single weak dimension bounds the whole program. This minimum rule prevents an organization from claiming meaningful PQC migration capability while operating on incomplete inventory, uncalibrated assessments, or unvalidated changes.

### Why these five dimensions

**Discovery Coverage** is the binding constraint on every other dimension. A high agility scorecard computed from 30% coverage is a lower bound, not a reliable number. A migration safety Level 4 that acts on stale or incomplete findings may migrate the wrong things or miss the highest-risk assets entirely. No migration program can exceed the reliability of its inventory. (RESEARCH.md §4: "the inventory is a fused, versioned belief state with confidence, never a checklist.")

**Assessment Accuracy** determines whether findings are worth acting on. Pattern-matching at scale produces a high false-positive rate without calibration; acting on uncalibrated findings wastes engineering effort on non-issues and may leave actual risks unclosed. Severity context matters: a RSA-2048 call in a test fixture and a RSA-2048 call in a TLS server key-exchange are not the same risk, and an assessment engine that treats them identically will misroute migration resources.

**Agility Metrics** answer whether the migration being attempted is the last one or the first of many. The harvest-now-decrypt-later (HNDL) threat (RESEARCH.md §2.2) is already active. Data whose confidentiality lifetime exceeds migration time plus CRQC arrival time (Mosca's inequality: X + Y > Z) is already at risk. Reducing Y — the migration time — is the lever available to the platform. Agility metrics make Y measurable; without measurement, the claim that "we can migrate in 30 days" is unfounded.

**Migration Safety** determines whether the platform can be trusted to change production cryptography without causing an outage or a security regression. A badly deployed ML-KEM configuration that breaks a peer's TLS handshake is an availability incident. A trust-store change without a tested rollback path is irreversible if it goes wrong. The remediation lifecycle (RESEARCH.md §7.4) exists to make each change auditable, reversible, and validated before it reaches production.

**LLM Trustworthiness** bounds the reliability of AI-assisted analysis. If an LLM can directly modify inventory facts without deterministic confirmation, or can influence migration command generation without human approval gates, then an adversary who controls code in a repository being analyzed can inject instructions that alter findings or generate malicious change proposals (RESEARCH.md §9.2 prompt injection). The neuro-symbolic architecture (deterministic analyzers own facts; LLMs annotate and propose) is the only deployment pattern under which AI-assisted crypto migration claims are substantiated. (LLM_CAPABILITY_CONTRACT.md, Section 1.)

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

**Evidence model requirements by level.** At Level 3 and above, every finding is an evidence record with: sensor identity, collection timestamp, confidence score (calibrated per sensor on a known-answer corpus), and detection method. Negative evidence ("scanned, none found") is a first-class database entry — the absence of a finding on a scanned asset is different from no scan having been run. At Level 4, evidence records carry cryptographic signatures, conflicts between sensors surface as typed conflict objects, and coverage SLOs (p95 evidence age < 30 days; ≥ 85% of known estate at ≥ 2 sensor classes) are monitored. (RESEARCH.md §4.4.)

**Current Janus status (2026-06-13):** Level 3. Regex source + binary + dependency + network scan, plus **directive-aware structural parsing** for nginx/sshd_config/openssl.cnf (WP-014). `DetectionMethod` enum with confidence floors; `BoundedEvidencePackage` for evidence provenance. Reachability is reported honestly (textual/import matches set `reachable=false`; config directives `reachable=true`). **Published benchmark corpus** with precision/recall by detector and language (`docs/analysis/DETECTION-BENCHMARK.md`, 1.000/1.000 on the labeled corpus). Missing for Level 4: full multi-language AST/data-flow analysis (deferred — tree-sitter toolchain cost) and a measured false-positive budget on a large field corpus.

---

### Dimension 2: Assessment Accuracy

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No policy assessment; all findings have identical severity |
| 1 | Reactive | YAML policy profiles with hardcoded rules; severity mapped to 1–5 scale |
| 2 | Planned | CNSA 2.0 and NIST FIPS 203/204/205 assessment; context-aware severity (verify/parse/negotiate adjust confidence); OSV CVSS score mapping |
| 3 | Agile | Statistical confidence analysis; QRisk scoring; `ConfidenceAnalyzer` with per-finding confidence intervals; LLM-assisted triage with schema-validated output (human approval required) |
| 4 | CryptoAgile | Versioned signed control packs (WP-017); every compliance result links to exact evidence, rule version, and evaluation time; independent review confirms results |

**Context-awareness.** Level 2 and above distinguishes usage context: a `verify`-only usage of RSA (checking an old signature, not producing new ones) is a different migration class than a `protect` usage (wrapping a DEK). The former requires "preserve verify, stop producing"; the latter is the primary HNDL target. An assessment engine that conflates them misroutes migration urgency. (RESEARCH.md §4.2: "verification-only RSA is a different migration class and must be labeled, not deleted.")

**LLM assessment constraint.** LLM-assisted severity proposals (Level 3) are hypotheses, not facts. They require deterministic policy re-evaluation before any database write (LLM_CAPABILITY_CONTRACT.md Invariant 5). The policy engine verdict is authoritative; the LLM verdict is advisory metadata. Wrong-confident LLM outputs are penalized over abstentions in calibration evaluation (LLM_CAPABILITY_CONTRACT.md Invariant 3).

**Current Janus status (2026-06-12):** Level 2–3. Policy profiles with CNSA 2.0/NIST rules. Context-aware severity in `policy.Assess()`. `ConfidenceAnalyzer` implemented. LLM verdict schema validation with 15 passing tests. Missing: versioned signed control packs, independent verification corpus.

---

### Dimension 3: Agility Metrics

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No measurement of cryptographic agility |
| 1 | Reactive | Manual inventory of algorithm usage; no automated measurement |
| 2 | Planned | HardcodeIndex and NegotiationCoverage computed from findings; BlastRadiusScore per algorithm |
| 3 | Agile | Automated scorecard via API; TTSA measurement; ProfileAdoptionLatency tracking; per-host and fleet views; maturity level (0–4) assignment |
| 4 | CryptoAgile | Automated agility exercises per adapter; negotiation tested end-to-end; TTSA measured under simulated CRQC deadline; continuous agility monitoring |

**Metric definitions.** The five metrics computed in `server/internal/agility/scorecard.go` are fully documented in `docs/AGILITY_SCORECARD.md`. In brief:

- **HardcodeIndex** (target < 5%): fraction of findings whose asset reference is a source file — a proxy for call sites that require code changes to migrate.
- **NegotiationCoverage** (target > 90%): fraction of services that can negotiate algorithms without a redeploy. Currently not wired to service-discovery data from the HTTP endpoint; see AGILITY_SCORECARD.md §2.2.
- **BlastRadiusScore**: normalized count of distinct assets for the most-widespread algorithm — how much of the fleet would need remediation if that algorithm were deprecated or broken.
- **TTSA** (target < 30d planned / < 7d emergency): wall-clock time from profile change to ≥ 99% fleet compliance. Not yet computed by the server; requires drill measurement.
- **ProfileAdoptionLatency** (target < 14d): days from policy profile switch to last open finding remediated for in-scope assets.

**Maturity level thresholds.** The agility scorecard maturity levels (none/reactive/planned/agile/crypto_agile) map to 0–4. Thresholds from `computeMaturity()`:

| Level | HardcodeIndex (hi) | NegotiationCoverage (nc) |
|---|---|---|
| 4 (crypto_agile) | hi < 0.02 | nc > 0.90 |
| 3 (agile) | hi < 0.05 | nc > 0.80 |
| 2 (planned) | hi < 0.20 | nc > 0.60 |
| 1 (reactive) | hi < 0.50 | nc > 0.20 |
| 0 (none) | otherwise | — |

Both conditions must hold at the target tier. Conditions are evaluated highest-tier-first with strict inequalities.

**Current Janus status (2026-06-13):** Level 3. `server/internal/agility/` package computes all five metrics. DB migration 21 (`agility_metrics`, now populated per-exercise). `GET /api/agility/scorecard` fleet + per-host API. **Automated agility exercise harness with per-adapter negotiation evaluation** (WP-023): `RunNegotiationHarness` grades nginx/apache/ssh/Windows adapters against the active profile's PQC targets, with a labeled TTSA estimate. React UI (`AgilityDashboard.tsx`). `docs/AGILITY_SCORECARD.md` published. Missing for Level 4: live end-to-end negotiation drills (current harness is an offline capability evaluation) and TTSA measured under a real CRQC-deadline exercise.

---

### Dimension 4: Migration Safety

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No migration capability; manual ad-hoc changes only |
| 1 | Reactive | Manual migration commands generated; no automated execution |
| 2 | Planned | HMAC-signed migration commands; atomic backup → write → validate → rollback on failure; file extension allowlist; path traversal sandbox |
| 3 | Agile | Dry-run simulation (`/api/sandbox/simulate`); wave planning with state machine; pre-activation readiness checklist; post-migration TLS verification; audit trail |
| 4 | CryptoAgile | Canary deployment with automatic promotion/rollback; maintenance window enforcement; dependency-graph-aware ordering; golden migration repositories; mutation testing |

**Reversibility classification.** Level 3 and above requires distinguishing reversible from semi-reversible from irreversible changes. Config file changes (reversible: backup is the rollback), certificate issuance (semi-reversible: old cert can be retained but new issuance is a fact), and root key destruction or signed-artifact publication (irreversible) all require different approval and rollback handling. Irreversible changes require m-of-n human approval with proposer ≠ approver ≠ key custodian. (RESEARCH.md §7.4, §11.)

**Wave planning.** Level 3 migration safety requires wave plans with the six-item pre-activation readiness checklist (WAVE_PLANNING_GUIDE.md §4): all assets discovery-scanned, critical/high findings triaged, dry-run simulation passed, rollback plan documented, stakeholder approval recorded, monitoring alerts configured. The wave plan state machine (planned → active → completed; planned/active → cancelled) enforces sequencing. Wave plans do not drive automated execution — they are sequencing and audit artifacts.

**Current Janus status (2026-06-13):** Level 3. Full mutation engine with HMAC verification and atomic rollback. `sandbox.Simulator` for dry runs. Wave plan CRUD with state machine, readiness checklist, canary/maintenance/approval fields, **dependency graph with cycle detection + dependency-safe activation gating, and budget/effort rollup** (WP-022). Audit logging. `docs/WAVE_PLANNING_GUIDE.md` published. Missing for Level 4: canary *deployment automation* (fields exist; execution does not) and golden migration repositories for end-to-end validation.

---

### Dimension 5: LLM Trustworthiness

This dimension applies when `JANUS_LLM_BASE_URL` is set (LLM mode other than `disabled`). If LLM features are permanently disabled, score this dimension at Level 4 — the absence of LLM features is the safest configuration and imposes no constraint on the overall maturity minimum.

| Level | Name | Criteria |
|---|---|---|
| 0 | None | No LLM integration; or LLM output applied directly without review |
| 1 | Reactive | LLM proxy available; no schema validation; no provenance; results may overwrite scanner facts |
| 2 | Planned | Capability mode gating (`disabled`/`analysis_only`/`suggest_remediation`); schema-validated verdicts; `HumanApprovalRequired: true` on all suggestions; LLM output cannot directly modify finding status |
| 3 | Agile | Full provenance chain (provider, model, prompt version, input/output hashes, token counts, latency); immutable audit trail; abstention mechanism; binary analysis opt-in policy per agent; 8 architectural invariants enforced |
| 4 | CryptoAgile | Published precision/recall on representative corpus; prompt-injection test suite; provider-contract tests; cost/token budget enforcement; automated evaluation gates block release on regression |

**The eight invariants.** Level 3 requires all eight invariants from LLM_CAPABILITY_CONTRACT.md §1 to be enforced:

1. Bounded evidence input — only `BoundedEvidencePackage` (max 512-byte snippet); no raw source files, binaries, or memory dumps.
2. Schema-validated structured output — all LLM responses schema-validated before any downstream use; malformed responses discarded.
3. Mandatory confidence scores and abstention — `abstain` is a first-class output; wrong-confident outputs penalized over abstentions in calibration.
4. Mandatory evidence citation — every verdict cites `finding_id`/`evidence_id` values; citation checker verifies existence; uncited claims discarded.
5. Deterministic verification before state change — no state change from LLM output alone; deterministic verifier must confirm the proposal.
6. Authority inversion — LLMs annotate and propose; they do not authorize, execute, sign, or remove deterministic findings.
7. Prompt injection defense — analyzed content in USER turn, delimiter-quarantined; red-team test with seeded injection repos is a release gate.
8. Full provenance recording — every LLM call produces and persists a `LLMProvenanceRecord` before output is consumed.

**Current Janus status (2026-06-12):** Level 3. `docs/LLM_CAPABILITY_CONTRACT.md` defines 8 invariants. `server/internal/llm/` pipeline with schema-validated verdicts (15 tests). `llm_provenance` table (immutable). `BinaryLLMPolicy` in agent config (all false by default). Missing: published evaluation corpus, prompt-injection tests, cost budget enforcement.

---

## §3 Advancing Maturity

### To reach Level 2 (Planned) in all dimensions

- Configure at least one scan root in `janus-agent.example.toml` with `enable_active_tls_probing = true`
- Deploy the server with `JANUS_COMMAND_SIGNING_KEY` set
- Load either the `nist-pqc-2026` or `cnsa-2.0` policy profile
- Binary and dependency scans must be active alongside source scanning

### To reach Level 3 (Agile) in all dimensions

- Complete Level 2
- Enable scheduled scans (default 15-minute interval)
- Confirm that confidence scores are stored for all findings and that at least two independent sensor classes have been applied to ≥ 85% of the known estate
- Set `JANUS_LLM_CAPABILITY_MODE=analysis_only` with a valid provider key and verify all 8 LLM_CAPABILITY_CONTRACT.md invariants are enforced before enabling on production findings
- Create at least one wave plan and run a dry-run simulation before any active migration
- Review `GET /api/agility/scorecard` and address findings in the top blast-radius algorithms
- Run the first planned-swap game-day (RESEARCH.md §10.4) and record TTSA for at least one technology domain

### To reach Level 4 (CryptoAgile) in all dimensions

- Complete Level 3
- Publish a discovery benchmark corpus with false-positive budget < 5% for each supported language
- Implement versioned signed control packs (WP-017 full implementation) with every compliance result linked to exact evidence, rule version, and evaluation time
- Build canary deployment harness for migrations (WP-022 full implementation) with auto-halt on negotiation-failure regression
- Publish LLM evaluation corpus and set release gate on precision/recall regression (LLM-19)
- Run emergency-swap game-day (RESEARCH.md §10.5) annually; store pre-generated dormant SLH-DSA root keys under dual control for break-glass use
- Complete WP-019 (full-system test program)

---

## §4 Assessment Cadence

| Cadence | Event / Trigger | Activity | Owner |
|---|---|---|---|
| Every scan | Findings updated | HardcodeIndex, NegotiationCoverage, BlastRadiusScore recomputed | Automated |
| Weekly | Calendar | Review agility scorecard for maturity regression; check that no dimension has regressed | Platform lead |
| Per policy switch | Active profile changed | ProfileAdoptionLatency measurement starts; re-score Dimension 3 after 14-day window closes | Platform lead |
| Per wave close-out | Wave marked `completed` | Post-wave maturity delta: which dimensions moved; blast-radius re-rank | Wave owner + platform lead |
| Per Janus release | CI gate | Re-run capability maturity assessment; update this document's current-status annotations | Platform lead |
| Quarterly | Calendar | Full five-dimension review by Cryptographic Governance Board; trend against prior quarter; exceptions reviewed | Board |
| Per LLM model pin change | `JANUS_LLM_MODEL_ANALYSIS` or `_REMEDIATION` changed | Recalibration run against frozen labeled corpus; Dimension 5 re-scored; provenance records updated | LLM subsystem operator |
| Annually | Calendar | Emergency-swap game-day (RESEARCH.md §10.5) with recorded TTSA; external security review; threat model updated | Engineering + governance |
| Incident | Bad migration, cryptanalytic event, HBS state compromise, HNDL exposure | Immediate re-score of affected dimensions; root cause trace through audit chain; root cause recorded in evidence store | Incident response team |

Assessment outputs are archived as signed evidence records. The maturity score is a continuously updated view backed by auditable evidence, not a point-in-time certification.

---

## §5 Integration with the Agility Scorecard

The agility scorecard (`docs/AGILITY_SCORECARD.md`) provides continuous metric tracking for **Dimension 3**. The maturity level names from `computeMaturity()` in `server/internal/agility/scorecard.go` — `none`, `reactive`, `planned`, `agile`, `crypto_agile` — map directly to Dimension 3 levels 0–4, but the Dimension 3 level is not identical to the scorecard maturity level alone. It also requires:

- Level 3: TTSA measured in at least one drill (scorecard maturity `agile` does not require a measured drill; Dimension 3 Level 3 does)
- Level 4: Emergency runbook exercised annually with recorded TTSA; continuous monitoring operational

**Scorecard inputs are constrained by Dimensions 1 and 2.** HardcodeIndex is meaningful only when discovery coverage is sufficient to have found the actual source call sites (Dimension 1 ≥ 2). NegotiationCoverage is meaningful only when service discovery is complete and findings are accurate (Dimensions 1 and 2 ≥ 2). A HardcodeIndex of 0.03 computed from 30% discovery coverage is a lower bound, not the true value. The overall maturity minimum rule prevents claiming agility-level maturity while operating on partial inventory.

**BlastRadiusScore drives wave sequencing.** The `top_blast_radius` array from `GET /api/agility/scorecard` identifies the highest-concentration algorithms. Combined with the algorithm vulnerability factor V(a) from QRisk scoring (RESEARCH.md §2.4; V(a) = 1.0 for quantum-broken key exchange), the top blast-radius quantum-vulnerable algorithms define the first-wave candidate set in Dimension 4 migration planning.

**Maturity regression trigger.** If the scorecard shows a maturity regression between assessments — for example, HardcodeIndex rises above 5% because new source-file findings arrived from a freshly scanned codebase — treat this as a Dimension 3 regression event. Investigate before the next scheduled wave activation: the new findings may represent an asset class that was not in prior wave scope.

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
