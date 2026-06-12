# Crypto-Agility Scorecard

**Document type:** Reference  
**Status:** Active  
**Applies to:** Janus CryptoBOM server — `server/internal/agility/scorecard.go`  
**Research basis:** RESEARCH.md §10 (Crypto Agility: Framework and Measurable Maturity Model)

---

## 1. Overview

The crypto-agility scorecard measures how cheaply and quickly an organization can replace any cryptographic algorithm, parameter, key, certificate, or protocol mechanism across its managed fleet. Crypto agility is not a property of algorithms; it is a property of software architecture and operations. A system that uses ML-KEM-768 everywhere but hardcodes it throughout source code is no more agile than a system using RSA-2048 in the same way.

The primary threat driving urgency is **harvest-now-decrypt-later (HNDL)**: nation-state adversaries are capturing ciphertext today against the arrival of a cryptographically relevant quantum computer (CRQC). The data whose confidentiality lifetime exceeds the sum of migration time and CRQC arrival time is already at risk. A high agility score reduces migration time — the Y term in Mosca's inequality (X + Y > Z) — and thus reduces HNDL exposure.

Agility also matters beyond the initial PQC migration. HQC standardization (~2026–2027), potential parameter changes to ML-KEM or ML-DSA, and the non-zero probability of cryptanalytic advances against structured lattices all guarantee future algorithm churn. The platform that achieves a measured, low migration cost the first time will amortize that investment across every subsequent transition.

The scorecard is computed by `ComputeScorecard` (per-host) and `ComputeFleetScorecard` (fleet aggregate) in `server/internal/agility/scorecard.go`. It operates on findings already persisted to the Janus database; it does not re-scan.

---

## 2. Metric Definitions

### 2.1 HardcodeIndex

**Target:** < 5% (i.e., < 0.05)

**Formula:**

```
HardcodeIndex = (findings whose asset_ref ends in a source file extension) / (total findings)
```

Source file extensions recognized: `.go`, `.rs`, `.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.cs`, `.rb`, `.php`.

A finding whose `asset_ref` is a source file path represents a cryptographic API call embedded in application code — the algorithm is resolved at build time, not via a provider or configuration. A finding whose `asset_ref` is a config file, network endpoint, or dependency is not counted as hardcoded.

**Interpretation:** A hardcode index of 0.15 means 15% of the cryptographic usages in the fleet are wired into source, not delegated to a provider or config layer. To replace the algorithm in those call sites, someone must modify source code and rebuild every service involved. Each additional point above the 5% target represents worsening blast radius for future algorithm changes.

**Note:** This metric is a proxy. The classifier uses file extension of the `asset_ref`, not static analysis of the call site itself. A finding can land in a source file because the relevant code is in a test or dead-code path. Reachability analysis and LLM-assisted intent classification (RESEARCH.md §4.3, §9) can improve the signal, but the scorecard operates on the raw finding set.

**What drives improvement:** Adopting provider abstraction (JCA, CNG, PKCS#11, Tink-style interfaces) so application code calls a policy-mediated API rather than naming an algorithm directly. RESEARCH.md §10.2 describes the architectural mechanisms; CI lints that reject literal algorithm strings in application code can enforce the pattern from day one.

---

### 2.2 NegotiationCoverage

**Target:** > 90% (i.e., > 0.90)

**Formula:**

```
NegotiationCoverage = negotiableServices / totalServices
```

where `totalServices` and `negotiableServices` are supplied by the caller of `ComputeScorecard`. A service is "negotiable" if it supports algorithm negotiation — for example, a TLS endpoint that advertises multiple cipher groups and can upgrade to hybrid KEMs without a config push.

**Interpretation:** A coverage of 0.60 means 40% of discovered services are committed to a single algorithm with no per-connection negotiation capability. Those services cannot participate in a staged rollout; every change requires a flag-day per service.

**Current API behavior:** The `GET /api/agility/scorecard` endpoint passes `totalServices=0, negotiableServices=0` to `ComputeScorecard`. This means `NegotiationCoverage` is always 0.0 from the HTTP endpoint until the wiring to service discovery data is implemented. The formula and target remain correct as definitions; the current endpoint does not populate this field.

**What drives improvement:** Deploying TLS termination layers with configurable cipher group priorities (nginx/HAProxy cipher string management, OS crypto-policy frameworks), enabling IKEv2 RFC 9370 multiple-KE, and preferring protocol-level negotiation over static config per service.

---

### 2.3 BlastRadiusScore

**Target:** Lower is better; no fixed threshold.

**Formula:**

```
algorithmAssets[alg] = count of distinct asset_refs using that algorithm
maxBlast = max(algorithmAssets[alg]) across all algorithms
BlastRadiusScore = min(1.0, maxBlast / total findings)
```

The per-algorithm blast radii are also exposed in `AlgorithmBlastRadii` — a map from algorithm name to distinct asset count.

**Interpretation:** If RSA-2048 appears across 80 distinct asset references out of 200 total findings, `BlastRadiusScore` = min(1.0, 80/200) = 0.40. A score of 0.40 means the most-widespread algorithm touches 40% of the finding population's asset set. This is a concentration-of-exposure metric: high blast radius for a single algorithm means a cryptanalytic event affecting that algorithm has wide reach.

`TopBlastRadiusAlgorithms(sc, n)` returns the top-N algorithms by asset count, sorted descending. The fleet scorecard exposes the top 5 via the API response.

**What drives improvement:** Diversifying algorithm usage (hybrid constructions), reducing the number of services that depend on a single classic algorithm, and migrating the highest-blast-radius algorithms first as a prioritization signal.

---

### 2.4 TTSA (Time To Swap Algorithm)

**Target:** < 30 days planned swap; < 7 days emergency swap

**Definition:** Wall-clock time from a profile change (the cryptographic policy profile is updated to require a different algorithm) to the point where ≥ 99% of the fleet has applied the change and the previous algorithm is no longer negotiated on any monitored path.

**Source:** RESEARCH.md §10.3. The metric is the authoritative TTSA definition for Janus.

**Current implementation status:** `TTSADays` is declared in the `Scorecard` struct and included in the JSON response, but `ComputeScorecard` never assigns it — it remains `nil`. TTSA requires active drill measurement: flip a policy profile in a staging environment, instrument negotiation outcomes, and record the elapsed time to full compliance. The field is a defined reporting slot for when that instrumentation is wired up or when organizations supply drill results externally.

**Obtaining a TTSA measurement:** Run the emergency-swap game-day described in RESEARCH.md §10.4 and §10.5 — introduce a test-algorithm deprecation in the profile, measure the time to 99% compliance via the negotiation monitor, and record the result. Annually exercise the runbook per RESEARCH.md §10.5 to keep the number current and feed the compliance dashboard.

---

### 2.5 ProfileAdoptionLatency

**Target:** < 14 days (p95 time from profile publish to fleet compliance)

**Formula:**

```
ProfileAdoptionLatencyDays = latestRemediation - policySwitchedAt  (in days)
```

where `latestRemediation` is the timestamp of the most-recent finding with `status = "remediated"` that was updated after `policySwitchedAt`. `policySwitchedAt` is the timestamp of the last policy profile switch, passed in by the caller.

**Interpretation:** If a new profile requiring ML-KEM-768 was activated on day 0 and the last open finding was remediated on day 11, `ProfileAdoptionLatencyDays` = 11. This measures the trailing edge — how long the last finding lingered after the policy changed.

**Current API behavior:** The endpoint passes `policySwitchedAt=nil`, so this field is always `nil` in the HTTP response. It is populated correctly when callers supply the policy switch timestamp programmatically.

**Relationship to RESEARCH.md §10.3:** RESEARCH.md lists "profile adoption latency: p95 endpoint lag applying a signed profile update: <72h" as a different metric — the lag for config-push to reach endpoints. The `ProfileAdoptionLatencyDays` field measures remediation completion latency (the full wave close-out), not endpoint config propagation speed. These are complementary; the <14-day target applies to the finding-remediation lifecycle.

---

## 3. Maturity Levels

The maturity level is computed by `computeMaturity` from `HardcodeIndex` (hi) and `NegotiationCoverage` (nc). All conditions are strict inequalities, evaluated highest-tier-first. Both conditions must hold for a tier to be assigned.

| Level | Name | Condition | Meaning |
|---|---|---|---|
| 4 | `crypto_agile` | hi < 0.02 AND nc > 0.90 | < 2% hardcoded call sites; > 90% of services negotiate algorithms. The fleet can execute a planned algorithm swap via profile change with minimal source changes. |
| 3 | `agile` | hi < 0.05 AND nc > 0.80 | < 5% hardcoded; > 80% negotiable. Most algorithm changes are config-layer operations. A small residual of source changes is manageable in a planned wave. |
| 2 | `planned` | hi < 0.20 AND nc > 0.60 | < 20% hardcoded; > 60% negotiable. Algorithm changes require engineering work but can be planned and waved. The organization has meaningful provider abstraction in place. |
| 1 | `reactive` | hi < 0.50 AND nc > 0.20 | < 50% hardcoded; > 20% negotiable. Significant source-level coupling to algorithms. Swaps require substantial engineering and a long planned window. |
| 0 | `none` | Otherwise (or no findings) | Pervasive hardcoding or no negotiation capability. Each algorithm change is a large engineering project. Also the initial state for hosts with no findings. |

**Fleet maturity** is computed over the aggregated fleet scorecard (averaged metrics), not as the minimum of per-host levels.

**Practical implication of current API wiring:** Because `NegotiationCoverage` is always 0.0 from the HTTP endpoint, the nc > threshold condition always fails for levels 1–4. Every host with findings will score Level 0 until negotiation data is wired in. Interpret current API results as reflecting only the HardcodeIndex signal.

---

## 4. API Endpoints

### GET /api/agility/scorecard

Returns the crypto-agility scorecard for the fleet or a single host.

**Authentication:** JWT required. No role restriction (read-only endpoint).

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `host_uuid` | string | No | If provided, returns a per-host scorecard. If omitted, returns fleet-wide aggregate plus per-host breakdown. |

**Fleet response (no host_uuid):**

```json
{
  "fleet": {
    "hardcode_index": 0.07,
    "negotiation_coverage": 0.0,
    "blast_radius_score": 0.41,
    "ttsa_days": null,
    "profile_adoption_latency_days": null,
    "maturity_level": 0,
    "maturity_name": "none",
    "algorithm_blast_radii": {
      "RSA-2048": 14.0,
      "AES-128-CBC": 6.0,
      "ECDSA-P256": 9.0
    },
    "computed_at": "2026-06-12T10:00:00Z"
  },
  "hosts": [
    {
      "host_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "hardcode_index": 0.12,
      "negotiation_coverage": 0.0,
      "blast_radius_score": 0.38,
      "ttsa_days": null,
      "profile_adoption_latency_days": null,
      "maturity_level": 0,
      "maturity_name": "none",
      "algorithm_blast_radii": {"RSA-2048": 4.0},
      "computed_at": "2026-06-12T10:00:00Z"
    }
  ],
  "top_blast_radius": [
    {"algorithm": "RSA-2048", "asset_count": 14.0},
    {"algorithm": "ECDSA-P256", "asset_count": 9.0},
    {"algorithm": "AES-128-CBC", "asset_count": 6.0}
  ]
}
```

**Per-host response (with host_uuid):**

Returns a single `Scorecard` object (the `fleet` shape above without the `hosts` and `top_blast_radius` wrappers).

**Notes:**
- Scorecard is computed on-demand over the findings currently in the database; there is no caching or pre-computation.
- The endpoint fetches up to 5,000 findings per call (the internal `QueryParams.Limit`). Fleets with more than 5,000 findings may see a partial scorecard.
- `ttsa_days` and `profile_adoption_latency_days` are `null` from this endpoint; see §2.4 and §2.5.

---

## 5. Interpreting the Scorecard

**Reading the HardcodeIndex number:** An index of 0.08 on a host with 25 findings means 2 findings are source-file findings. Those 2 call sites require code changes to migrate. An index of 0.30 on a host with 100 findings means 30 source call sites need engineering attention. Use `algorithm_blast_radii` to understand which algorithms are most pervasively hardcoded so wave planning can prioritize by remediation impact.

**Reading the BlastRadiusScore:** The `top_blast_radius` array in the fleet response identifies the highest-concentration algorithms. The algorithm at the top of the list is the one that, if cryptographically broken or deprecated, would require the most per-asset remediation work. This feeds directly into QRisk-based wave sequencing (RESEARCH.md §2.4): high blast radius combined with high algorithm vulnerability factor (V(a) = 1.0 for quantum-broken key exchange) drives a high-priority first wave.

**Maturity as a trend, not a grade:** The maturity level is most useful tracked over time — a level rising from 0 to 2 over two quarters reflects genuine architectural progress. A single snapshot at Level 0 is an inventory signal, not a condemnation. The path from 0 to 4 runs through provider-abstraction refactors (reduces HardcodeIndex) and TLS config improvements (increases NegotiationCoverage), both of which feed back into the scorecard automatically as findings are remediated.

**What the scorecard does not measure:** TTSA (until drill data is wired in), rollback readiness, inventory freshness, the fraction of the estate with coverage from two or more sensor classes, or compliance deadline proximity. These require separate tracking against the full agility maturity framework in RESEARCH.md §10.3. The scorecard is one instrument in that framework.

**Escalation trigger:** Any fleet-level `maturity_name` of `none` with a `hardcode_index` > 0.30 warrants a wave-planning review and prioritization of provider-abstraction work before PQC algorithm changes are attempted. Migrating to ML-KEM-768 everywhere in source code simultaneously is slower and riskier than introducing an abstraction layer first.
