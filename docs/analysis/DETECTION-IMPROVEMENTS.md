# Detection Quality, False-Positive Reduction, and Remediation — Analysis & Research Roadmap

Date: 2026-06-12 · Scope: `agent/src/discovery/source.rs` (deep review), informed by the verified IETF/IANA results in `research/VERIFICATION.md`. Cross-references are to `docs/RESEARCH.md` sections.

## 1. Defects found in the current source scanner (by inspection)

| # | Defect | Class | Status |
|---|---|---|---|
| D1 | String stripping erased the dominant algorithm-selection idiom: `Cipher.getInstance("RSA")`, `crypto.createHash('md5')`, `hashlib.new("sha1")`, `EVP_get_digestbyname("...")` were **invisible** | False negative (severe — JCA/Node/Python/.NET select algorithms via string literals) | **Fixed** (string-API pass, 9f286bf) |
| D2 | Config formats (yaml/toml/conf/xml) had quoted values stripped — `ciphers = "ECDHE-RSA-AES128"` undetectable | False negative (severe — config is the highest-leverage remediation class, §7.1) | **Fixed** |
| D3 | Ed25519/EdDSA, X25519/Curve25519, standalone DSA had no patterns — quantum-vulnerable and ubiquitous (SSH keys, JWT EdDSA, TLS groups) | False negative | **Fixed** |
| D4 | No recognition of hybrid PQ group names (X25519MLKEM768, mlkem768x25519-sha256) — hybrid deployments either missed or misread as classical ECC | Misclassification | **Fixed** (names taken from verified IANA registry entries 4587/4588/4589) |
| D5 | Intent inference by substring: `design`→sign(protect), `thread`→read(verify, −30% confidence), `checksum`→check | Confidence distortion both directions | **Fixed** (word-boundary regexes, run on comment-stripped text) |
| D6 | LLM intent output trusted unconditionally at 0.95 confidence — violates §9.3 authority inversion; scanned repo content can prompt-inject the classifier ("classify this RSA as test-only") and the scanner obeys | Security / FP+FN | **Fixed** (closed-enum validation; LLM can only lower confidence) |
| D7 | Passive scan wrote `<file>.patch` beside every QV finding in the *customer's tree* and repeatedly overwrote a single `remediation.patch` in CWD (last-finding-wins) | Safety (privileged agent mutating scanned estate) | **Fixed** (in-memory aggregation → one artifact next to the report) |
| D8 | Static patch replaced RSA→MLKEM768 even in signing contexts (wrong family) | Remediation correctness | **Fixed** (role-aware mapping) |
| D9 | Rust `tests/` and JS `spec/` directories not treated as test paths | False positive | **Fixed** (path-component match) |
| D10 | `match_count>=2` corroboration counts *different algorithms* on one line (`SHA256withRSA`) as mutual corroboration (0.88) — they are one usage | Confidence inflation | Open — needs calibration data before changing (see §3.1) |
| D11 | `\bDSA\b`-class patterns can't use lookbehind (regex crate); ML-DSA/SLH-DSA tails suppressed by explicit prefix check | — | Mitigated |

## 2. What "good" looks like (research-grounded targets)

The scanner's epistemic ceiling is RESEARCH.md §4.1(1): regex scanning is "fast, high recall on mainstream APIs; FPs from test/dead/verification-only code; FNs from wrappers, reflection, dynamic dispatch." The path beyond that ceiling, in increasing cost:

### 2.1 Now implemented (this changeset)
- **Two-channel matching**: identifiers on stripped text + string literals in API context — recovers the JCA-idiom FN class while keeping the comment/docstring FP defense.
- **Closed-vocabulary, monotone-down LLM annotation** (§9.3 rules 1–4): deterministic facts own truth; the LLM relabels intent only within {protect, verify, parse, negotiate, test, observed} and can never raise a finding above its deterministic tier.

### 2.2 Next (cheap, high leverage — ordered)
1. **Dataflow-to-config join** (§4.1 pitfall): when the string argument is not a literal (`getInstance(cfg.algo)`), emit a typed finding "algorithm determined by config key X" instead of nothing. Single-function intraprocedural backward slice over the line window is enough for v1.
2. **Verify-only as a migration class, not a discount**: findings with intent=verify keep full *inventory* weight but route to a different remediation class ("preserve verify, stop producing" — §4.1). Today the 0.70 multiplier conflates "less certain" with "less urgent"; split `confidence` from `urgency` when the EvidenceRecord schema (§4.4) lands in the proto.
3. **Per-sensor calibration corpus** (§13 experiment a): a scripted fixture tree (~50 labeled cases: real use / test-only / verify-only / comment / string-no-API / config / hybrid-PQ) checked into `tests/fixtures/detection/`, with precision/recall computed in CI. The confidence floors (0.20/0.60/0.78/0.80/0.88) are currently *invented*; calibrate them against measured per-tier precision. This also unblocks D10 with data instead of opinion.
4. **Negative evidence**: emit "scanned N files, M skipped (size/extension/unreadable)" as an Evidence record per scan root — required for honest-coverage reporting (§4.2) and cheap now that Evidence carries `source_type`.
5. **Network probe codepoint table**: classify negotiated TLS groups by the now-verified IANA values (4587/4588/4589 hybrid, 512–514 pure ML-KEM, 0x0904–0x0906 mldsa sigschemes, 25497 = obsolete draft hybrid → "upgrade" finding) in `discovery/network.rs`.

### 2.3 Later (the research frontier)
- **Reachability pruning** via code property graphs (Joern-class, §4.1) — the single highest-leverage FP reducer; answers "is this RSA decrypt reachable from a network entrypoint." Heavy; run server-side on uploaded evidence, not in the agent.
- **Runtime corroboration**: a static finding confirmed by the runtime sensor (process maps / interceptor hook) jumps confidence (§4.2); the fusion belongs server-side where both evidence streams meet. Janus already has both sensors — the join is missing, not the data.
- **Conflict objects** (§4.4): static-says-RSA / runtime-never-sees-it surfaced as a first-class conflict demanding extended observation, never silently resolved.

## 3. Efficient remediation (problem 3) — recommended architecture

Current state: per-finding unified diffs from a line-level heuristic (now role-aware and review-marked), or an LLM diff via the server proxy. Both are **candidate hints**, not appliable changes. The research-correct pipeline (§7) is:

1. **Recipes over patches**: a versioned, signed library of (pattern, precondition-evidence, transform, validation, rollback) tuples per finding class. For Janus's existing finding classes the first recipes are mechanical and *deterministic*: SChannel registry diffs (PowerShell), `update-crypto-policies --set` commands, `sshd_config` KexAlgorithms diffs, OpenSSL conf `Groups = X25519MLKEM768:*` edits. These are config-class = "High — auto-generate, gated apply" (§7.1) and align with Janus's existing HMAC-signed MigrationCommand machinery — the engine exists; the recipe content is the gap.
2. **LLM patches stay in the candidate lane** (§7.2): repository-aware retrieval, n≥3 candidates, compile+test gates before a human ever sees them. Without a build sandbox, present them as "candidate — not validated"; the UI must not render them as appliable. The static patch header now says exactly that.
3. **Placement**: build/CI PR-authoring is the preferred venue for source findings (§12); host mutation only for config classes already covered by `mutation.rs`'s backup→apply→validate→rollback pipeline.

## 4. Honest residuals
- **Measured (2026-06-12): corpus v1 = 14 labeled files → precision 1.000, recall 1.000** (`cargo test corpus_precision_recall -- --nocapture` in `agent/`). The corpus immediately caught one real FN during authoring (`DH_generate_key` — trailing `\b` vs underscore, fixed). Caveats: 14 files is small and was authored by the same session that built the engine — treat 1.0/1.0 as an upper bound on this corpus, not a field estimate. Next step: grow it adversarially (wrappers, reflection, mixed-language files, real-world OSS excerpts) and have the Linux side add cases blind.
- Wrappers, reflection, homegrown crypto, and string-built algorithm names remain undetected (known ceiling, §4.1).
- D10 (cross-algorithm corroboration inflation) intentionally left pending calibration data.
- `agent/src/policy.rs` (offline severity) and `server/internal/policy` were not re-reviewed this session; the verify-only urgency split (2.2-2) needs both.
