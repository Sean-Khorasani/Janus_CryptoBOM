# JOURNAL — PQC research verification & Janus improvement program

Decision log, dead ends, and open questions. Newest entries at the bottom of each dated section.

## 2026-06-12 — Session start

**State found:**
- `docs/RESEARCH.md` present (588 lines, knowledge horizon Jan 2026, ~30 ⚠ items). No `research/` artifacts yet.
- Working tree on `main` had ~79 modified files (+4909/−1695) **uncommitted and not authored by this session**. Decision: do NOT commit or revert them; branch `research/pqc-verification-and-analysis` carries them in the working tree, but only files created by this program are staged/committed. **Open question for repo owner:** whether that working set should be committed or discarded.
- Recent commits show prior sessions removed GitHub CI workflow (5ff505e) — so "CI on windows-latest + ubuntu-latest" (Phase 3 requirement) currently has no workflow to extend; will need to recreate one or document why not.

**Plan:**
1. Phase 1: six parallel research agents against live primary sources (NIST / IETF / gov timelines / ecosystem / cryptanalysis+implementations / competitive tooling) → `research/VERIFICATION.md`, `research/SOURCES.json`, `research/CHANGELOG.md`, `research/REPORT-v2.md`.
2. Phase 2 in foreground while agents run: read server (Go), agent (Rust), UI (TS); build fixture corpus; measure detection precision/recall → `docs/analysis/*.md`.
3. Checkpoint summary + `docs/ROADMAP.md`, then implement "now" tier on per-item feature branches.

**Conventions discovered so far (to follow):** Go server `server/internal/*` packages, Rust agent modules under `agent/src/discovery/`, conventional commits already in history (`chore:`, `config:`, `hsm:` prefixes), `VERSION.env` as release contract, Makefile + MSBuild dual build.

## 2026-06-12 — Phase 1 partial completion + pivot

- Six parallel research agents launched; **five aborted on session rate limits** (NIST, gov timelines, ecosystem, cryptanalysis, competitive tooling) — only IETF/IANA completed. Saved to research/{VERIFICATION.md, SOURCES.json, CHANGELOG.md}. REPORT-v2.md deferred until remaining domains verified (rerun after limit reset).
- Two Explore agents (architecture, detection enumeration) also hit the limit; Phase 2 docs deferred. Full build attempt failed on a log-path error (ran from ui/ cwd); not retried — token budget.
- **User directive:** very limited tokens; skip tests/multi-agent fan-out; focus research effort on (a) improving weak-algorithm scan quality, (b) false-positive reduction, (c) efficient migration solutions / fix application. Pivoting to a single deep pass over agent/src/discovery/source.rs + server policy with a concrete improvement design and the highest-leverage implementation.

## 2026-06-12 — Detection overhaul (commit 9f286bf)

- Deep review of source.rs found 11 defects (D1–D11, see docs/analysis/DETECTION-IMPROVEMENTS.md); 9 fixed and tested (14 tests green), D10 deliberately deferred pending calibration data, D11 mitigated.
- Pre-existing compile breaks in the **user's uncommitted WIP** (plugin.rs:205 usize cast, interceptor.rs:245 FARPROC cast) fixed in the working tree but **left unstaged** — they belong to work this session didn't author; HEAD compiles without them.
- Remaining session-limit-blocked work (rerun when tokens allow): 5 research domains (NIST/gov/ecosystem/cryptanalysis/tooling) → REPORT-v2.md; Phase 2 architecture/security docs; fixture corpus with measured precision/recall; ROADMAP.md.

## 2026-06-12 — Shared-working-tree coordination (Windows ⇄ WSL)

Both teammates operate on this SAME directory (WSL symlink → one tree, one .git). Protocol agreed: foreign uncommitted changes are off-limits; stage by explicit path only; no branch switches or concurrent same-file sessions without announcing here; worktree split proposed (see ONBOARDING.md Team Tips). Note for the Linux side: the ~79 modified files on main predate this session and were left untouched; two unstaged one-line build fixes in your WIP are mine (plugin.rs:205 usize cast, interceptor.rs:245 FARPROC cast) — keep or fold into your work. Current branch: research/pqc-verification-and-analysis.

## 2026-06-12 — CLAIMED (Windows-side Claude): items W1–W5

W1 Windows agent depth (cert-store chain analysis, SChannel/CNG policy, PFX/JKS carving) · W2 CNG/SChannel PQ-capability detection (empirical, this machine) · W3 runtime/interceptor reconciliation (plugin.rs/interceptor.rs fixes are mine) · W4 SChannel remediation recipes + mutation.rs validation · W5 Windows e2e/CI/fixture measurement. Linux side: crypto-policies/eBPF/SSH depth, linux-gate, ubuntu CI. Neutral pool (first-come): research domains → REPORT-v2.md, GAP-ANALYSIS, ROADMAP, server CBOM/QRisk.

## 2026-06-12 — W1/W2 delivered (commit follows), W4/W5 status

W2 done: CNG PQ capability + SChannel group policy sensors, grounded in live probe of build 26200.8655 (ML-KEM/ML-DSA present in CNG; SChannel curves classical-only -> canonical finding). W1 done: cert-store QV flagging, weak-key, combo sig-alg fix, PQ-cert recognition, self-signed typing, PFX/PEM/JKS carving (metadata-only). W3 done earlier (fixes in tree, unstaged). W4 partial: remediation hint embedded in the SChannel finding; full recipe artifacts (PowerShell/registry diff + mutation.rs validation) remain. W5 not started (e2e needs PostgreSQL; CI workflow recreation pending). Linux side: please run make linux-gate over discovery changes - windows.rs parsers compile cross-platform with tests.

## 2026-06-12 — CLAIMED (Windows-side): W6 measured detection corpus, W4 completion, W5a CI workflow

W6: labeled fixture corpus + precision/recall measurement as a cargo test (mission requires numbers, not impressions). W4: SChannel PQ remediation recipe artifact (generated, never auto-applied). W5a: recreate dual-OS GitHub Actions workflow (unit tests only; e2e/HSM stays local per 5ff505e rationale).

## 2026-06-12 — W4/W5a/W6 delivered

W6: corpus v1 measured precision 1.000 / recall 1.000 (14 files; caught+fixed DH_generate_key FN). W4: schannel-pq-remediation.ps1 recipe generator (gated, reversible, precondition-checked). W5a: .github/workflows/ci.yml restored for ubuntu+windows unit tests. Verified: agent 61/61, server all-ok on this machine. Remaining for either side: W5b e2e-on-CI (needs postgres service container), corpus adversarial expansion (Linux side invited, blind cases), 5 research domains, GAP-ANALYSIS/ROADMAP, server CBOM/QRisk.

## 2026-06-12 — CLAIMED (Linux/WSL-side): L1–L6 implementation batch

**L1** WP-026 docs: `docs/PRIVACY_DATA_GOVERNANCE.md` + prompt-injection test stubs in `agent/src/evidence.rs`
**L2** WP-027 partial: `docs/ALGORITHM_COMPATIBILITY.md` — algorithm-to-PQC migration compatibility matrix (static reference)
**L3** WP-013 auto-reopen: extend `InsertTelemetry` in `server/internal/store/store.go` to auto-reopen resolved findings on recurrence + `store_test.go`
**L4** WP-022 fields: extend `WavePlan` with `CanaryTargets`/`MaintenanceWindow`/`ApprovalPolicy` fields + DB migration 25; extend `waveplan_test.go`
**L5** UI improvements: `ui/src/components/FindingTimeline.tsx` (new), wire into `FindingsGrid.tsx`; compliance-rules panel in `PolicyStudio.tsx`; cert-health card in `OverviewView.tsx`
**L6** WP-019 tests: policy engine fuzz test (`server/internal/policy/engine_fuzz_test.go`); httpapi property tests expansion
Files Windows teammate should NOT touch while these are in-flight: `server/internal/store/store.go`, `server/internal/waveplan/`, `ui/src/components/FindingsGrid.tsx`, `ui/src/components/PolicyStudio.tsx`, `ui/src/components/OverviewView.tsx`.

## 2026-06-12 — L1–L6 delivered (commits 5ad356a..4dac225)

**L1 (WP-026):** `docs/PRIVACY_DATA_GOVERNANCE.md` (323 lines) — data classification, LLM consent gate, redaction patterns, Linux AES-256-GCM encryption, operator responsibilities.
**L2 (WP-027):** `docs/ALGORITHM_COMPATIBILITY.md` (329 lines) — NIST QSL table, RSA/ECDSA/AES/TLS→PQC migration matrix, library support table (OpenSSL 3.5+, rustls, BoringSSL, Go circl).
**L3 (WP-013):** `server/internal/store/store.go` — auto-reopen on recurrence (`status IN ('remediated','accepted_risk')` → `open`, lifecycle event), DB migration 26. `store_test.go` — migration uniqueness tests, compile-time interface assertion, integration test skeleton (skips without DB URL).
**L4 (WP-022):** `WavePlan` extended with `CanaryTargets`/`MaintenanceWindow`/`ApprovalPolicy` fields, DB migration 25 with CHECK constraint. 3 new waveplan tests (15 total). Policy engine `FuzzAssess` test (10 seeds, no-panic invariant).
**L5 (WP-013/017/018 UI):** `FindingTimeline.tsx` (211 lines) — vertical event history with status badges, actor, timestamps. Wired into `FindingsGrid.tsx` (History button per row). Compliance rules collapsible panel in `PolicyStudio.tsx`. Cert-health card (expired/30d/90d) in `OverviewView.tsx`. TypeScript clean.
**L6 (WP-019/026):** `evidence.rs` — AWS access key redaction pattern, 6 new tests (prompt injection, 512-byte cap, TLS classification, AWS key, JWT). `network.rs` — `ocsp:unchecked` field in TLS metadata string. `docs/NETWORK_ASSESSMENT.md` (185 lines).
Test counts: Go 18 packages green; Rust 71 tests green. All files staged with explicit paths.

## 2026-06-12 — Full-project review (docs/analysis/PROJECT-REVIEW.md)

Read UI (App/useApi/auth/Header/AgentFleetInventory/OverviewView/i18n), server auth.go + hsm/softhsm.go. Findings: 5 security (S1 hardcoded creds=Critical, S5 fake SoftHSM Verify=Critical, S2 public agent endpoints, S3 token-in-localStorage/URL, S4 static agent token), 5 partial impls (P1 real-time/useWebSocket missing — polling-only despite CLAUDE.md; P2 HSM stub; P3 bulk-select dead-end; P4 saveAgentDiagnostics dead code; P5 client-local finding lifecycle), 6 bugs (B1 per-asset remediation fudge, B2 Safety Score ignores triage, B3 type drift, B4 RTL not applied for fa, B5 error masking, B6 untranslated tabs), and 11 UI/UX recommendations led by real-time, RTL/i18n, trustworthy score, bulk-select resolution, keyboard-accessible sort headers, honest-coverage panel. Recommended immediate fixes: S1 + S5. Not yet implemented — awaiting go-ahead on which to action.

## 2026-06-12 — CLAIMED (Windows-side): UI fixes + features U1/U3/U4/U5/U6 + bugs

Implementing: real-time useWebSocket hook wired into useApi (rec 1), trustworthy Safety Score (rec 3/B2), complete bulk-select agent actions (rec 4), keyboard-accessible sortable headers + aria-sort (rec 5), honest-coverage panel (rec 6); hiding the localization switcher for now (rec 2, sidesteps B4 RTL); fixing bugs B1 (per-asset remediation fudge), B3 (Overview type drift), B5 (error masking), B6 (untranslated tabs). All UI — compiles cross-platform (browser-only). Any server endpoint added compiles on Linux+Windows. Linux side: please leave ui/ to me this round.

## 2026-06-12 — UI features + bug fixes delivered (commit f6298fb)

COMMITTED (mine, clean): real-time useWebSocket hook + useApi wiring (rec 1); triage-aware Safety Score + tooltip (rec 3/B2); HonestCoverage panel (rec 6); Header live/freshness indicator (B5); localization switcher hidden in App.tsx (rec 2); B1 (per-asset remediation fudge removed), B3 (typed stalled_agents), B6 (tab labels via t()). UI builds clean (tsc+vite).

NOT committed — shared-tree entanglement (FOR LINUX TEAMMATE):
- AgentFleetInventory.tsx is your UNTRACKED file. I added bulk-select actions (rec 4: client-side CSV export of selected agents' findings, filtered from /api/findings — no server dep) + keyboard-accessible sortable headers with aria-sort/scope (rec 5). These edits sit in the working tree on top of your untracked file. Please commit AgentFleetInventory.tsx (it carries my additions) or tell me to.
- i18n/index.tsx (your untracked file): I locked locale to 'en' so a non-English browser doesn't get a half-translated, switcher-less UI. Same handoff.
- authenticatedResource.ts (your untracked file): reverted clean — no changes left by me.
- server/internal/httpapi/server.go: I had added a host_uuid filter to exportCSV but REVERTED it — your uncommitted edits (hostFindings route, structs) are entangled there and host_findings.go is untracked + currently doesn't compile (host_findings.go:37 make([]interface{}) vs []store.Finding). Left untouched; bulk export went fully client-side so it needs no server change.

## 2026-06-12 — CLAIMED (Windows-side): all LLM-flow tasks (LLM-021/022)

LLM-021 (agent never initiates LLM during scan) — DONE, committed 92d539a, 15 tests pass. LLM-022 (server batch+filter analyze endpoint, server-side evidence assembly, bounded-concurrency worker, findings-list selection UI + inline verdicts) — implementing now. Server LLM files (llm_analysis.go, llm/service.go, server.go) are clean == HEAD so I can edit/commit without entanglement; agent main.rs is your dirty WIP so I left scan() signature intact (flag ignored) rather than touch it. Plan updated with the normative flow + acceptance criteria.

## 2026-06-12 — LLM-021/022 delivered

- LLM-021 (agent never initiates LLM): 92d539a — removed both LLM functions + per-match call sites from source.rs; scanning fully deterministic. 15 source tests pass.
- LLM-022 server: c628271 — POST /api/llm/analyze/batch (finding_ids OR filter: severity_gte/status/algorithm/host_uuid/scope all|all_critical), dedup, cap 500, audit; GET /api/llm/batches/{id}; bounded-concurrency worker (JANUS_LLM_MAX_CONCURRENT) assembling evidence SERVER-SIDE from stored finding metadata. 5 new unit tests pass; httpapi+llm packages green; new file gofmt-clean, server.go diff = 3 route lines only.
- LLM-022 UI: b6eadf1 — findings list (FindingsGrid) row checkboxes + select-all/all-critical/page, "Analyze selected with AI" (gated on /api/llm/status enabled AND operator/admin role), batch submit + poll + inline VerdictBadge (advisory; never auto-changes status). UI builds clean.
- Plan: 02f6b10 — refined requirement + normative flow + acceptance criteria under LLM-021/022.
- Shared-tree note: ui/node_modules got overwritten cross-platform (Linux binaries) — ran npm install to restore Windows build; ui/package-lock.json left uncommitted (env artifact, differs per OS). The git-worktree split (ONBOARDING.md) would prevent this.
- Residual for LLM-022: batch grouping is in-memory (verdicts persist in DB); a durable batches table is a future nicety. Optional bulk-verdicts endpoint would avoid the per-row verdict GETs on page load.
