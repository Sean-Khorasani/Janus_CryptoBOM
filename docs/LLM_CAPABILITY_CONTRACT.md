# LLM-01: LLM Capability and Safety Contract

**Document type:** Normative contract  
**Status:** Active  
**Applies to:** Janus CryptoBOM — all LLM-enabled subsystems  
**Research basis:** RESEARCH.md §9 (Safe Neuro-Symbolic Architecture), §4.4 (Evidence Model), §7.4 (Remediation Lifecycle)

---

## Purpose

This document is the authoritative contract governing all use of large language models within Janus CryptoBOM. It specifies the permitted capability modes, input/output schemas, provenance requirements, authority boundaries, and operator responsibilities that MUST be satisfied before any LLM subsystem is enabled. Implementations that do not satisfy these requirements are non-compliant with the Janus safety model regardless of any other configuration.

The architecture described here is the only deployment pattern under which claims of "AI-powered crypto migration" are substantiated. Absent these controls, such claims are marketing, not engineering. (RESEARCH.md §9.3)

---

## 1. Architecture Invariants

The following eight invariants are binding on all LLM integration points in Janus. No capability mode, configuration flag, or operator override may relax them. They are derived directly from RESEARCH.md §9.3.

### Invariant 1 — Bounded Evidence Input

LLM calls MUST operate exclusively on structured `BoundedEvidencePackage` inputs (see Section 3). Raw source code files, binary file contents, full configuration files, and process memory dumps MUST NOT be passed to any LLM provider. The context permitted to the model is the algorithm name and a maximum 512-byte snippet, not the containing file.

**Rationale:** Source code and configuration files constitute attacker-controlled input. Passing them verbatim enables prompt injection (RESEARCH.md §9.2) and risks exposing secrets to model infrastructure with unknown residency and tenancy properties.

### Invariant 2 — Schema-Validated Structured Output

All LLM responses MUST be validated against the applicable output schema (Section 4 for verdicts, Section 5 for remediation suggestions) before any downstream consumption. Responses that fail schema validation MUST be discarded and treated as abstentions. Unstructured natural language from LLM responses MUST NOT be written to the Janus database as inventory truth, finding state, or migration instructions.

**Rationale:** Free-form LLM output cannot be reliably parsed, audited, or validated by deterministic systems. Schema gating is the hard boundary between hypothesis and fact. (RESEARCH.md §9.3 invariant 2)

### Invariant 3 — Mandatory Confidence Scores and Abstention

Every LLM output MUST carry a `confidence` float in the range [0.0, 1.0]. The verdict value `abstain` is an explicit, first-class allowed output — it is not a failure. Abstentions MUST be routed to human review. Implementations MUST penalize wrong-confident outputs over abstentions in any calibration evaluation. Outputs that lack a confidence score MUST be rejected as malformed.

**Rationale:** LLMs have no native calibration. Forcing an explicit confidence field and permitting abstention prevents the system from silently accepting low-quality classifications. (RESEARCH.md §9.3 invariant 4)

### Invariant 4 — Mandatory Evidence Citation

Every LLM verdict or remediation suggestion MUST include one or more `evidence_citations` referencing the `finding_id` or `evidence_id` values from the input evidence package. Uncited claims MUST be discarded. A citation checker MUST verify that the cited identifiers exist in the evidence set provided to this call. This is not advisory — it is a hard gate against hallucinated references. (RESEARCH.md §9.3 invariant 3)

### Invariant 5 — Deterministic Verification Before State Change

No state change — to the Janus inventory, to a migration queue, or to any managed endpoint configuration — MAY be triggered solely by LLM output. Before any state change occurs, a deterministic verifier (policy engine, config validator, TLS probe, schema checker) MUST confirm the LLM's proposal. The deterministic outcome is authoritative; the LLM output is a hypothesis. (RESEARCH.md §9.3 invariant 1; §7.4 invariant 4)

### Invariant 6 — Authority Inversion

LLMs annotate and propose. LLMs do not authorize and do not execute. Specifically:

- An LLM output MUST NOT be used as an authorization signal for any migration command.
- An LLM MUST NOT sign any artifact (migration command, evidence record, audit entry).
- An LLM MUST NOT remove a deterministic finding from the inventory. It may annotate a finding with a down-rank proposal, which a deterministic policy evaluation step may act on.
- Human approval is required wherever RESEARCH.md §7.4 requires it, regardless of LLM confidence.

(RESEARCH.md §9.3 invariants 1, 8)

### Invariant 7 — Prompt Injection Defense

Analyzed content — code snippets, config fragments, algorithm names, file paths — MUST be placed in the USER turn of the prompt, never in the SYSTEM prompt. The SYSTEM prompt is reserved for static instructions authored by Janus developers. Delimiter quarantine (e.g., XML-tagged blocks) MUST be applied to user-supplied content. An instruction-detection pre-filter SHOULD be applied to content before embedding. The LLM pipeline MUST be red-teamed with repositories containing seeded injection payloads as a release gate. (RESEARCH.md §9.2, §9.3 invariant 5)

### Invariant 8 — Full Provenance Recording

Every LLM call MUST produce and persist a `LLMProvenanceRecord` (see Section 7) before the output is consumed by any downstream system. Provenance records are immutable once written. The ability to reconstruct which model, prompt version, and input produced a given verdict or patch is a compliance requirement, not a debugging convenience. Recalibration against frozen labeled corpora MUST use these records. (RESEARCH.md §9.3 invariant 7)

---

## 2. Capability Modes

LLM capability is controlled by the `JANUS_LLM_BASE_URL` environment variable. When this variable is unset or empty, the system operates in `disabled` mode and no LLM calls are made. The active mode is determined at server startup and is not hot-switchable without a restart.

### Mode: `disabled`

**Condition:** `JANUS_LLM_BASE_URL` is unset or empty.

No LLM calls are made. All findings proceed through the deterministic policy engine only. The `/api/findings/{id}/analyze` and `/api/migrations/suggest` endpoints return `503 Service Unavailable` with body `{"error":"llm_disabled"}`. This is the default and MUST be the default for new installations.

**Permitted operations:** None.

### Mode: `analysis_only`

**Condition:** `JANUS_LLM_BASE_URL` is set; `JANUS_LLM_ENABLE_REMEDIATION` is unset or `false`.

The LLM subsystem MAY be invoked to classify usage intent and triage false positives. All outputs are read-only verdicts: the model annotates findings with intent labels, adjusted severity proposals, and false-positive rationale. No candidate patches are generated. No migration commands are produced.

**Permitted operations:**
- Intent classification (e.g., `protect`, `negotiate`, `verify`, `test`)
- False-positive triage with cited reasoning
- Severity adjustment proposals (subject to deterministic policy re-evaluation)
- Human-readable explanation of findings for operator/auditor consumption

**Not permitted:**
- Generating code diffs or configuration patches
- Enqueuing migration commands
- Modifying inventory records directly

### Mode: `suggest_remediation`

**Condition:** `JANUS_LLM_BASE_URL` is set; `JANUS_LLM_ENABLE_REMEDIATION=true`.

All `analysis_only` operations are permitted. In addition, the LLM MAY generate candidate remediation patches for source and configuration findings. All candidate patches are suggestions only. `human_approval_required` is unconditionally `true` in all `RemediationSuggestion` outputs (see Section 5). The operator MUST explicitly approve a suggestion before it enters the migration queue. The deterministic policy engine and config validators MUST evaluate the suggestion before it is presented to the operator.

**Permitted operations:** All `analysis_only` operations, plus:
- Candidate patch generation (unified diff, source and config targets only)
- Dependency upgrade recommendations
- Compensating control recommendations for binary and network findings

**Not permitted:**
- Automatic migration queue insertion without human approval
- Binary file patching (see Section 6)
- Signing of migration commands

### Mode: `automated_remediation`

**Status: NOT IMPLEMENTED.**

This mode requires LLM-13 (sandboxed validation infrastructure) and LLM-14 (per-agent PQ signing of LLM-derived commands) to be implemented and audited. These capabilities are planned for the security-hardening phase. Until LLM-13 and LLM-14 are complete and pass independent security review, this mode MUST NOT be enabled. Any configuration that purports to enable autonomous LLM-driven migration without these controls is non-compliant with this contract.

---

## 3. Evidence Package Schema

The `BoundedEvidencePackage` is the only permitted input to LLM analysis calls. It is constructed by the Janus agent and server from validated `CryptoFinding` records. The package is transmitted to the LLM subsystem; it is never the raw finding payload.

Field limits and type constraints are normative. Implementations MUST reject packages that violate them.

```json
{
  "finding_id": "string (UUID, required)",
  "evidence_type": "enum: source_code_pattern | config_file | tls_service | dependency | binary_import | process_memory",
  "algorithm_detected": "string (e.g. 'RSA-2048', 'AES-128-CBC') — required",
  "detection_method": "string (e.g. 'RegexMatch', 'ContextConfirmed', 'TLSHandshake', 'BinaryImport') — required",
  "confidence_floor": "float 0.0–1.0 — minimum confidence asserted by the deterministic sensor",
  "file_path": "string — relative path, sanitized, no traversal sequences",
  "line_range": "[start_line: integer, end_line: integer] — optional, only for source_code_pattern evidence",
  "context_snippet": "string — MAX 512 bytes. The algorithm name plus at most 2 lines of surrounding context. NOT the full file contents. MUST be sanitized to remove secrets, keys, and tokens before inclusion.",
  "intent_labels": "string[] — initial labels from deterministic heuristics (e.g. ['protect', 'negotiate']); the LLM may confirm or revise",
  "sensitivity_label": "enum: public | internal | confidential | restricted",
  "collection_timestamp": "string — ISO 8601"
}
```

**Construction rules:**

1. `context_snippet` MUST be derived from the source text by extracting the matching line and one line before and one line after, then truncating to 512 bytes. It MUST NOT be the full function, file, or block.
2. Secrets, private keys, tokens, and passwords MUST be redacted from `context_snippet` before the package is assembled. A secret-scanning step MUST run before any LLM call.
3. `sensitivity_label` gates which LLM providers may receive the package. `restricted` evidence MUST only be sent to residency-compliant, tenant-isolated deployments. The `JANUS_LLM_BASE_URL` for restricted evidence MUST point to an approved endpoint.
4. For `binary_import` and `process_memory` evidence types, `context_snippet` contains the imported symbol name or memory pattern identifier only — not disassembled or decompiled content.

This schema encodes the evidence model from RESEARCH.md §4.4 in a form bounded for safe LLM consumption. The full `EvidenceRecord` (§4.4) is the source of truth; the `BoundedEvidencePackage` is a read-only, size-limited projection of it.

---

## 4. LLM Verdict Schema

All LLM analysis responses MUST conform to the following JSON Schema. Responses that do not parse as valid JSON or that fail schema validation MUST be discarded and logged as `malformed_response` provenance events.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12",
  "type": "object",
  "required": ["job_id", "finding_id", "verdict", "confidence", "reasoning", "evidence_citations"],
  "additionalProperties": false,
  "properties": {
    "job_id": {
      "type": "string",
      "description": "Opaque identifier for this LLM call, matches the LLMProvenanceRecord.job_id"
    },
    "finding_id": {
      "type": "string",
      "description": "UUID matching the finding_id from the input BoundedEvidencePackage"
    },
    "verdict": {
      "type": "string",
      "enum": ["false_positive", "confirmed", "severity_adjusted", "needs_review", "abstain"],
      "description": "Structured verdict. 'abstain' is a valid, first-class output and MUST NOT be treated as an error."
    },
    "adjusted_severity": {
      "type": ["integer", "null"],
      "minimum": 1,
      "maximum": 5,
      "description": "Proposed severity on the 1–5 scale, or null if no adjustment is proposed. Only meaningful when verdict is 'severity_adjusted'. Subject to deterministic policy re-evaluation before any database write."
    },
    "confidence": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 1.0,
      "description": "Calibrated confidence in the verdict. Required. Outputs without this field are rejected as malformed."
    },
    "reasoning": {
      "type": "string",
      "maxLength": 1000,
      "description": "Human-readable explanation of the verdict. Free text is permitted here only. MUST reference the evidence_citations by ID."
    },
    "evidence_citations": {
      "type": "array",
      "items": {"type": "string"},
      "minItems": 1,
      "description": "Array of evidence_ids or finding_ids from the input package that support this verdict. MUST NOT be empty. A citation checker verifies each ID exists in the provided evidence set."
    },
    "abstention_reason": {
      "type": ["string", "null"],
      "description": "Required when verdict is 'abstain'. Describes why the model cannot determine a verdict (insufficient context, conflicting evidence, out-of-scope pattern, etc.). Null for all other verdicts."
    }
  }
}
```

**Downstream handling rules:**

- `false_positive`: finding is flagged for human confirmation before any inventory state change. The deterministic policy engine re-runs against the finding; if the engine still asserts the finding, human review is required before suppression.
- `confirmed`: severity from the deterministic engine is preserved unless `adjusted_severity` is also set and passes policy re-evaluation.
- `severity_adjusted`: `adjusted_severity` is a proposal. The policy engine MUST accept or reject it according to the active policy profile before the database is updated.
- `needs_review`: finding is escalated to the review queue without modification.
- `abstain`: finding is escalated to the review queue. The `abstention_reason` is recorded. No inventory state change occurs.

---

## 5. Remediation Suggestion Schema

Remediation suggestions are only produced in `suggest_remediation` mode. They are proposals, not commands. The `human_approval_required` field is unconditionally `true` and MUST be rejected as malformed if it is absent or `false`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12",
  "type": "object",
  "required": [
    "job_id", "finding_id", "recommendation_type", "target_algorithm",
    "assumptions", "compatibility_notes", "validation_required",
    "human_approval_required", "confidence"
  ],
  "additionalProperties": false,
  "properties": {
    "job_id": {
      "type": "string",
      "description": "Matches the LLMProvenanceRecord.job_id for this call"
    },
    "finding_id": {
      "type": "string",
      "description": "UUID matching the finding_id from the input BoundedEvidencePackage"
    },
    "recommendation_type": {
      "type": "string",
      "enum": [
        "config_change",
        "dependency_upgrade",
        "api_refactor",
        "compensating_control",
        "binary_not_supported"
      ],
      "description": "Semantic type of recommendation. 'binary_not_supported' MUST be used for binary_import and process_memory evidence types — no patch is generated."
    },
    "target_algorithm": {
      "type": "string",
      "description": "The PQC or classical algorithm being recommended as the replacement (e.g. 'ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM')"
    },
    "candidate_patch": {
      "type": ["string", "null"],
      "maxLength": 4096,
      "description": "Unified diff patch, max 4096 chars. MUST be null for binary_import and process_memory evidence types, and for any recommendation_type of 'binary_not_supported' or 'compensating_control'. A null value does not make the suggestion invalid."
    },
    "assumptions": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Explicit list of assumptions the patch makes (e.g. 'caller passes a pre-allocated output buffer', 'OpenSSL >= 3.5 is available', 'no other callers of this function'). Operators MUST review these before applying."
    },
    "compatibility_notes": {
      "type": "string",
      "description": "Interoperability considerations: peer systems that may reject the new algorithm, minimum library versions, protocol negotiation impacts."
    },
    "validation_required": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Ordered list of validation steps the operator MUST complete before applying this suggestion. These are operator responsibilities, not automated gates."
    },
    "human_approval_required": {
      "const": true,
      "description": "Unconditionally true. A response with this field absent or set to false MUST be rejected as malformed."
    },
    "confidence": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 1.0,
      "description": "Calibrated confidence in the correctness and safety of this suggestion."
    }
  }
}
```

**Patch quality gates** applied before presenting a suggestion to an operator:

1. The `candidate_patch` MUST apply cleanly to the current version of the target file (verified by the server before display).
2. If the suggestion targets a source file that has a test suite, the patch MUST be flagged for compilation and test execution in the simulation environment (RESEARCH.md §7.4 invariant 3).
3. A `bounded_repair_loop` of at most 3 iterations (generate → build → test → repair) MAY be executed automatically; failures after 3 iterations exit to the human review queue with the full transcript. (RESEARCH.md §9.3 invariant 6)

---

## 6. Binary Remediation Policy

Janus MUST NOT rewrite binary files. The `candidate_patch` field MUST be `null` for any finding with `evidence_type` of `binary_import` or `process_memory`. The `recommendation_type` MUST be `binary_not_supported`.

For binary findings, the only permitted LLM-assisted responses are the following five remediation pathways, each of which requires human decision and action:

1. **Vendor upgrade recommendation.** Identify a newer version of the binary or library that ships with PQC support. The suggestion MUST cite the vendor's published PQC roadmap or release notes if available.

2. **Rebuild-from-source guidance.** If source is available (identified via the dependency evidence chain), provide guidance on the source-level changes and compiler/library flags needed to produce a PQC-capable rebuild. The rebuild itself is a source-code change and follows the normal `api_refactor` or `config_change` pathway.

3. **Runtime interposition.** For dynamically linked binaries, describe an `LD_PRELOAD` hook or API interception approach that interposes PQC over the legacy call. This is an analysis-only recommendation: Janus does not generate or deploy the interposition library. The operator is responsible for implementing and validating it.

4. **Network compensating control.** Wrap the binary's network communications in a PQC-capable proxy (mTLS termination, PQC tunnel). This is a `compensating_control` recommendation. Network-layer evidence (TLS probe results from `tls_service` findings) SHOULD be cited to establish the scope.

5. **Isolate and risk-accept.** Document the finding as a known, unmitigated risk with a formal justification. The `validation_required` array MUST include steps for risk-acceptance documentation, compensating-control review, and re-assessment scheduling. Risk-acceptance records are subject to governance review (RESEARCH.md §11).

These five pathways exhaust the permitted LLM-assisted responses to binary findings. Any suggestion that proposes direct binary patching or binary generation MUST be rejected as malformed.

---

## 7. Provenance Record

Every LLM call MUST produce and persist a `LLMProvenanceRecord` before the response is consumed. The record is immutable once written. It MUST be stored in the Janus database with the same sensitivity label as the evidence package that triggered the call.

```json
{
  "job_id": "string (UUID, matches job_id in verdict or suggestion output)",
  "provider": "string (e.g. 'openai', 'anthropic', 'local-ollama')",
  "model": "string (exact model identifier including version, e.g. 'gpt-4o-2024-08-06')",
  "prompt_name": "string (name of the prompt template used, e.g. 'intent-classification-v3')",
  "prompt_version": "string (semver or commit hash of the prompt template)",
  "input_hash": "string (SHA-256 hex of the fully rendered prompt sent to the provider)",
  "output_hash": "string (SHA-256 hex of the raw response received from the provider)",
  "tokens_input": "integer",
  "tokens_output": "integer",
  "latency_ms": "integer",
  "finding_id": "string (UUID)",
  "verdict_or_suggestion": "enum: verdict | suggestion | malformed_response | provider_error",
  "schema_valid": "boolean (true if output passed schema validation, false if discarded)",
  "timestamp": "string (ISO 8601)"
}
```

**Retention and access rules:**

- Provenance records MUST be retained for the duration of the audit retention period applicable to the finding they reference.
- Records for `restricted` findings MUST be stored with field-level encryption and access scoped to authorized audit roles.
- The `input_hash` and `output_hash` fields enable auditors to verify that the stored transcript matches the prompt and response that produced a given verdict — the full prompt and response MAY be stored separately, with the hashes providing integrity linkage.
- Periodic recalibration against a frozen labeled corpus MUST use provenance records to identify which prompt version and model produced each verdict. Recalibration results MUST be recorded as new provenance events with `prompt_name` set to `recalibration-{corpus-version}`. (RESEARCH.md §9.3 invariant 7)

---

## 8. Operator Responsibilities

Before enabling any LLM capability mode other than `disabled`, operators MUST satisfy all of the following requirements. The Janus server does not enforce these procedurally; operators are accountable for compliance.

### Before enabling `analysis_only`

1. **Provider due diligence.** Confirm the LLM provider's data-residency, tenancy isolation, and retention policies are compatible with the sensitivity labels of findings that will be submitted. `restricted` findings MUST NOT be submitted to providers that do not offer residency-compliant, tenant-isolated inference.

2. **API key management.** The LLM API key MUST be supplied via `JANUS_LLM_API_KEY_FILE` (file path) or `JANUS_LLM_API_KEY` (environment variable), never embedded in configuration files or command lines. The key MUST be rotated on the same schedule as other Janus secrets.

3. **Model pinning.** The `JANUS_LLM_MODEL_ANALYSIS` variable MUST be set to a specific versioned model identifier. Floating aliases (e.g., `gpt-4o-mini` without a date suffix) are acceptable only if the provider guarantees stable behavior for the alias; otherwise use a dated version string. Model changes MUST be treated as prompt-version changes and trigger recalibration.

4. **Baseline calibration.** Before enabling analysis on production findings, run the LLM pipeline against a held-out labeled calibration corpus and record precision, recall, and abstention rates per evidence type. These baseline metrics MUST be stored and compared against in future recalibrations. (RESEARCH.md §9.1)

5. **Injection red-team.** Before enabling analysis on any repository, run the LLM pipeline against at least one seeded test repository containing prompt injection payloads in code comments, file names, and configuration values. Confirm that injected instructions do not influence verdict outputs.

6. **Secret-scan configuration.** Confirm that the `context_snippet` assembly pipeline has a secret-scanning step enabled and that it has been tested against known secret patterns (private key headers, API key prefixes, JWT fragments).

### Before enabling `suggest_remediation` (in addition to the above)

7. **Patch review process.** Establish and document a patch review process. Every suggested patch MUST be reviewed by a human with crypto engineering competence before it is applied. The review checklist MUST include: correctness of the algorithm substitution, absence of nonce reuse or constant-time violations in the patch, and compatibility with the target runtime.

8. **Simulation environment.** Confirm that the Janus sandbox simulation environment (RESEARCH.md §7.4 invariant 3) is operational and that patches submitted for review have passed at minimum: clean application to the current source, compilation in the target language/framework, and execution of available unit tests.

9. **Governance notification.** Notify the Cryptographic Governance Board or equivalent authority that `suggest_remediation` is being enabled. Record the notification in the exception/approval register.

---

## 9. Non-Goals

The following capabilities are explicitly outside the scope of Janus LLM features. They are listed here as a normative boundary for compliance review and audit.

### No autonomous migration execution

Janus LLM features MUST NOT execute any migration — modification of a configuration file, network service, key material, or trust store — without explicit human approval. The `automated_remediation` mode is not implemented (Section 2). Any future implementation of automated remediation requires independent security review as specified in LLM-13 and LLM-14.

### No training data contribution

Janus MUST NOT submit finding data, evidence packages, or operator interactions to any LLM provider for the purpose of model training, fine-tuning, or feedback. Operators MUST verify that their provider contract disables training-data use for API calls. This is a data classification requirement: Janus finding inventories are `confidential` or `restricted` assets and MUST be treated accordingly.

### No PII in prompts

`BoundedEvidencePackage` construction MUST NOT include personally identifiable information. File paths submitted in evidence packages MUST be sanitized to remove usernames, home directory paths, and email addresses before the package is assembled. The `context_snippet` field MUST be reviewed for PII as part of the secret-scanning step described in Section 8.

### No raw source code submission

Full source files, function bodies, class definitions, and module contents MUST NOT be submitted to LLM providers. The 512-byte `context_snippet` limit in Section 3 is the enforced boundary. This applies to all evidence types including `source_code_pattern` and `config_file`. This constraint exists for both security reasons (secret exposure, RESEARCH.md §9.2) and data-residency reasons.

### No LLM-authoritative inventory

LLM outputs never constitute authoritative inventory facts. A finding exists in the Janus inventory because a deterministic sensor produced it. An LLM may propose that a finding is a false positive, but the finding record is not removed until a human approves the removal. An LLM may propose a severity adjustment, but the adjusted severity is not written until the deterministic policy engine accepts it. The inventory is the output of deterministic sensors and human decisions, with LLM annotations as advisory metadata.

### No guarantee of accuracy

LLM-derived annotations carry the confidence scores specified in Sections 4 and 5. Janus makes no representation that LLM-derived verdicts are correct. Published evidence on LLM crypto-misuse detection accuracy is corpus-dependent and inconsistent (RESEARCH.md §9.1). Operators MUST run their own calibration corpus and MUST NOT make compliance assertions based solely on LLM-derived findings without independent verification.

---

*This document encodes the neuro-symbolic architecture specified in RESEARCH.md §9. It is a normative contract. Changes to this document require review by the platform security lead and the Cryptographic Governance Board.*
