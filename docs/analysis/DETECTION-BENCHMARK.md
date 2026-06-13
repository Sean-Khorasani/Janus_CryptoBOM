# Janus Detection Benchmark (WP-014)

This document is the published precision/recall benchmark for the Janus crypto
detection engine, reported **by detector and by language** as required by
WP-014. The benchmark is a versioned, labeled corpus executed as a Rust test so
the numbers are reproducible and regressions fail CI.

## How to run

```bash
cd agent
cargo test detection_benchmark::benchmark_by_language_and_detector -- --nocapture
```

The corpus lives inline in `agent/src/discovery/source.rs`
(`mod detection_benchmark`), alongside the original aggregate corpus
(`mod detection_corpus`, `corpus_precision_recall`). Both run under `cargo test`.

## Scope and method

- **Axis under test:** quantum-vulnerable (QV) detection. A file counts as
  "flagged" when it carries a QV, non-test finding at confidence ≥ 0.5. This is
  the signal that drives PQC posture, so it is what the benchmark measures.
- **Detectors covered:** the regex/source detectors (RSA, ECDSA, DH, DSA,
  Ed25519, X25519, MD5, SHA-1) and the WP-014 **structural config** detectors
  (`structural-nginx`, `structural-ssh`, `structural-openssl`).
- **Languages covered:** go, rust, python, javascript/typescript, jvm, native
  (C/C++), and `config` (nginx / sshd_config / openssl.cnf).
- **Out of scope here:** legacy *classical* symmetric weaknesses (DES/3DES/RC4)
  are detected by the engine but are **not** quantum-vulnerable, so they are not
  part of this QV-recall benchmark. They belong to a separate classical-weakness
  axis. PQC-hybrid groups (X25519MLKEM768, mlkem768x25519, sntrup761x25519) are
  included as **true negatives** — they must never be flagged QV.

## Current results (benchmark v2, 2026-06-13)

18 labeled cases. Aggregate: **precision 1.000, recall 1.000, 0 false positives.**

| Language | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| config | 3 | 0 | 0 | 1.000 | 1.000 |
| go | 2 | 0 | 0 | 1.000 | 1.000 |
| javascript | 2 | 0 | 0 | 1.000 | 1.000 |
| jvm | 1 | 0 | 0 | 1.000 | 1.000 |
| native | 1 | 0 | 0 | 1.000 | 1.000 |
| python | 1 | 0 | 0 | 1.000 | 1.000 |
| rust | 1 | 0 | 0 | 1.000 | 1.000 |

| Detector | TP | FN | Recall |
|---|---|---|---|
| RSA | 2 | 0 | 1.000 |
| ECDSA | 1 | 0 | 1.000 |
| DH | 1 | 0 | 1.000 |
| DSA | 1 | 0 | 1.000 |
| Ed25519 | 1 | 0 | 1.000 |
| X25519 | 1 | 0 | 1.000 |
| MD5 | 1 | 0 | 1.000 |
| SHA-1 | 1 | 0 | 1.000 |
| structural-nginx | 1 | 0 | 1.000 |
| structural-ssh | 1 | 0 | 1.000 |
| structural-openssl | 1 | 0 | 1.000 |

### Release gates

The test asserts: **0 false positives, recall ≥ 0.90, precision ≥ 0.99.** A
detector or language regression that drops a true positive or introduces a false
positive fails the build.

## Honesty notes (WP-014 acceptance: "no detector labels heuristic reachability as proven")

- Source/regex and binary import-table findings now set `reachable = false`. A
  textual match or an import-table symbol does **not** prove the primitive is
  exercised at runtime, so the engine does not claim proven reachability.
- Structural config findings set `reachable = true` because a config directive
  (`ssl_ciphers`, `KexAlgorithms`, `CipherString`) is an *active negotiated
  selection* — its reachability is established by the configuration itself.
- Confidence provenance is recorded in `Evidence.source_type`
  (`regex-match`, `context-confirmed`, `string-api-context`, `multi-pattern`,
  `structural-config`) so downstream tools can weight findings by method.

## Caveats and roadmap

- The corpus is curated and modest in size; treat the numbers as a
  regression gate and a per-detector coverage map, not a field-accuracy
  estimate. Adversarial expansion (blind cases contributed by the other side of
  the team) is invited.
- Full multi-language **AST / data-flow** analysis (tree-sitter or equivalent)
  is **deferred**: it would add C-toolchain build dependencies that complicate
  the portable Windows/Linux build. WP-014 here delivers (a) **structural,
  directive-aware** parsing for the highest-value configuration formats, (b)
  honest reachability, and (c) this per-detector/per-language benchmark. The
  source detectors remain regex + comment/string-stripping + intent
  classification; their method tier is recorded honestly in evidence.
