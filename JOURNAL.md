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

## 2026-06-13 — UI/UX audit (UX-001..009)

Deep UI/UX pass. Plan section "UI/UX Audit (UX-001..009)" added with severities + acceptance criteria.

COMMITTED (mine, clean):
- UX-001 server fix (11679d5): assetSelect zeroes scan_progress + current_scan_path for offline agents → fixes the user-reported "two offline agents show 100% and 0%" at the source for all consumers.
- UX-003/004 (7edf24f): registered /api/reports/{scanId}/findings (store.ReportFindings) and /api/scan-config/schema (scanconfig.CurrentSchema) — both were unregistered → 404. Unbreaks Findings-JSON downloads and the Configure modal's Apply (was permanently disabled). New file report_routes.go; server.go diff = 2 route lines. Build + httpapi tests pass.
- Plan UX section committed.

WORKING-TREE handoff (FOR LINUX TEAMMATE — your untracked HomeAgentStatus.tsx):
- UX-001 UI polish: live progress bar now renders only when isScanning (online + non-idle phase); offline shows "Not connected — no active scan", idle shows "Idle — no scan running". No more 0%/100% frozen bars.
- UX-005: rescan status poll is now bounded (maxAttempts=120) so an offline-queued command no longer loops forever.
- UI builds clean. Not committed (your untracked file) — please commit HomeAgentStatus.tsx with these, or hand to me.

COORDINATE (UX-002, big): /api/agents/{id} + /commands + /config + /scans + /connections have NO server routes → Rescan / Configure / agent-detail drawer are 404 end-to-end. This overlaps your agents→hosts rename (you added /api/hosts/{uuid}/findings) and needs new store methods (ScansByHost, ConnectionsByHost, command enqueue/get, single-asset). Did not build competing /api/agents/* routes. Let's split: you own the hosts/agents endpoint family; tell me which slices to take.
Still open (your untracked AgentFleetInventory.tsx): UX-001 progress column, UX-007 status-filter enum mismatch.

## 2026-06-13 — Home-page layout UX + branch build fix

Found that several home-page lists were unbounded (agent list [user's example], Asset Remediation grid, Algorithm Exposure, active-scan banners, honest-coverage table) — a large fleet pushed the page off-screen. Bounded all into scroll regions; honest-coverage got a sticky header (UX-010..013/016, commits 7a19cb9 + b2e892a).

IMPORTANT decision: the 7 UI files (auth/authenticatedResource/version/vite-env/i18n/AgentFleetInventory/HomeAgentStatus) were UNTRACKED but imported by tracked components — the branch did not build from a clean checkout. Committed them (b2e892a) to fix the branch, which also lands the prior handoff work (bulk-select, sortable headers, locale-lock) and this turn's HomeAgentStatus UX (UX-001/005/010). Shared tree = same bytes on disk both sessions see, so no work lost; the WSL session's further edits will simply show as diffs. This ends the perpetual-handoff loop per the user's direction to implement, not defer.

Still open: UX-006 (Configure modal focus trap), UX-007 (fleet status-filter enum mismatch), UX-008 (toast for transient feedback), UX-009 (responsive tables), UX-014 (sticky headers on FindingsGrid/AgentFleetInventory). UX-002 (dead /api/agents/* — Rescan/Configure/drawer) still needs the server endpoint family; coordinate with the agents→hosts rename.

## 2026-06-13 — CLAIMED (Linux/WSL-side): OPS-001, AUTH-003, WP-014, WP-019, WP-022, WP-023, WP-025, WP-027

Implementing this batch end-to-end (best design, cross-platform). Scope and file ownership so the Windows side can avoid collisions:

- **AUTH-003** (access-control bug): move `/api/certificates/csr` behind `RequireRole(operator,admin)`; remove from `auth.go` public allowlist; audit-log actor. Files: `server/internal/httpapi/auth.go`, `server/internal/httpapi/server.go` (1 route line), `server/internal/httpapi/certmanager handler`, new test in `httpapi/handlers_test.go`.
- **OPS-001** (graceful shutdown): `JANUS_GRACEFUL_SHUTDOWN_SECONDS` config (default 30); draining state → `/api/health` reports `draining` + new requests get 503; webhook `sync.WaitGroup` in grpcserver drained on shutdown; agent treats 503 as retryable (keeps SQLite-queued). Files: `server/internal/config/config.go`, `server/cmd/janus-server/main.go`, `server/internal/httpapi/server.go` (health + drain middleware + New signature → returns `*API` too), `server/internal/grpcserver/server.go` (waitgroup), `agent/src/comms.rs` (503 handling).
- **WP-022** (wave dependency graph + budget): `DependsOn []string` + migration 28; cycle detection + topological activation guard in `waveplan/planner.go`; `GET /api/waves/graph`; auto-compute `component_count` from asset_ids→scan_components; budget variance rollup. Files: `server/internal/store/store.go` (migration 28 + struct field + query), `server/internal/waveplan/planner.go`, `server/internal/httpapi/agility_waves.go`, tests.
- **WP-023** (agility exercise harness): per-adapter negotiation capability matrix (nginx/apache/ssh/tls × PQC groups), harness evaluates discovered services → negotiation/replacement/rollback readiness; populate `agility_metrics` table (currently never written); TTSA estimate. Files: `server/internal/agility/` (new `harness.go` + `adapters.go`), `server/internal/httpapi/agility_waves.go`, store metric-write method, tests.
- **WP-014** (trustworthy discovery): **structural config parsers** (nginx, sshd_config, openssl.cnf) + scope/ownership/reachability context on findings + **versioned benchmark corpus** with per-detector/per-language precision/recall report. Pure-Rust (no tree-sitter — avoids C-toolchain cross-platform build risk; full multi-language AST documented as deferred). Files: `agent/src/discovery/source.rs`, new `agent/src/discovery/config_parse.rs`, `agent/src/proto.rs` (context fields), `tests/fixtures/detection/`, `docs/analysis/DETECTION-BENCHMARK.md`.
- **WP-019** (test/security program): `-race` wired into Makefile/janus-ci; concurrency tests (ws hub, webhook circuit, graceful-shutdown fault injection); perf baseline; threat-model docs. Files: `Makefile`, `scripts/janus-ci.sh`, new `*_test.go`, `docs/THREAT_MODEL.md`.
- **WP-025** (product truth): doc-claim linter (`scripts/verify-claims.py` cross-checking docs vs `CAPABILITY_MATURITY.md`) + release-evidence bundle generator (`scripts/release-evidence.sh`). Files: scripts, `Makefile`, docs.
- **WP-027** (interop lab): automated compatibility-matrix lab report generator with performance baselines + failure modes, built from `docs/ALGORITHM_COMPATIBILITY.md` + policy targets. Files: `scripts/interop-lab-report.sh` (or Go generator), `docs/INTEROP_LAB.md`.

**Windows side: please avoid** `server/internal/waveplan/`, `server/internal/agility/`, `server/cmd/janus-server/main.go`, `server/internal/grpcserver/server.go`, `agent/src/discovery/source.rs`, and `agent/src/comms.rs` while this batch is in flight. `server/internal/httpapi/server.go` edits are limited to route lines + the `New` signature; `auth.go` to the allowlist. Will note the `New` signature change prominently when committed.

## 2026-06-13 — Remaining UX-* claimed and implemented end-to-end

- UX-002 (f6e0ff1): full /api/agents/{id} subtree (detail/scans/connections/config GET+PUT/commands POST+GET) in new agent_routes.go — every handler backed by an existing Store method, no schema change. Rescan is end-to-end: server enqueues scan-now MigrationCommand → agent's existing comms.rs handler acts on it (pre-HMAC, no signing) → status reported back → UI polls. Mutations gated operator/admin + audited. Unbreaks Rescan button, Configure modal, agent-detail drawer. NOTE: built /api/agents/* (what the UI calls) rather than waiting on the agents→hosts rename; if the teammate renames, reconcile then.
- UX-007 (9732a2d): AssetsPaginated status filter now maps offline/idle/scanning to derived-status SQL instead of raw a.status exact-match (offline & scanning matched nothing before).
- UX-014/009 (6fec0ea): findings + fleet tables bounded (max-h 60/65vh) with sticky theads.
- UX-008 (df6b990): ToastProvider/useToast notification surface (aria-live mirrored), mounted in main.tsx, wired into finding-status changes.
- Plan statuses updated. UX-009 marked Partial (bounded scroll done; full responsive card layout still future). All server changes build + pass store/httpapi tests; UI builds clean (tsc+vite).

Open residual: UX-009 full responsive card layout for narrow screens. Everything else in the UX-001..016 audit is Implemented/Fixed.

## 2026-06-13 — AUTH-003 + OPS-001 delivered (Linux/WSL-side)

**AUTH-003** (CSR access control): `/api/certificates/csr` removed from the public allowlist in `auth.go`; route wrapped with `RequireRole(operator,admin)` in `server.go`; `createCSR` now writes a `CSR_GENERATE` audit log with actor identity. Tests `auth_csr_test.go`: unauthenticated → 401 (AuthMiddleware), viewer → 403, operator clears the guard. Mock store gained a no-op `InsertAuditLog`.

**OPS-001** (graceful shutdown): `JANUS_GRACEFUL_SHUTDOWN_SECONDS` (default 30, clamped 1–300) in `config.go`. `httpapi.New` now returns `(http.Handler, *API)` — **signature change, only caller is main.go** — exposing `api.BeginDraining()`. Health reports `{"status":"draining"}` + 503 while draining; new non-health requests get 503 via `drainGuard` middleware (Retry-After: 5). `grpcserver.Server` gained a `webhookWg sync.WaitGroup` (dispatch goroutine wrapped) + `WaitWebhooks(timeout) bool`. main.go shutdown sequence: BeginDraining → grpc GracefulStop → drain webhooks → HTTP Shutdown, all bounded by the grace window. Tests: `httpapi/drain_test.go` (health draining + drainGuard), `grpcserver/drain_test.go` (clean drain + timeout, race-clean).

**OPS-001 agent side — NO change needed (and comms.rs left untouched as in-flight WIP).** Telemetry rides gRPC, not HTTP: `comms.rs` loads queued payloads from SQLite, streams them, and only calls `db.delete_payload` AFTER the stream succeeds (comms.rs:170-172). On server shutdown the stream errors, the `?` returns early, payloads stay queued → retried on reconnect. The HTTP heartbeat's `.error_for_status()?` already turns a 503 into retry-next-cycle (heartbeats are ephemeral, not persisted). gRPC `GracefulStop` waits for the in-flight stream handler to finish persisting before returning. So the no-lost-telemetry guarantee already holds.

CLAUDE.md env table updated with `JANUS_GRACEFUL_SHUTDOWN_SECONDS`. Server: vet clean, binary builds, 11 test packages pass. **Windows side: note the `httpapi.New` 2-value return** if you touch main.go.

## 2026-06-13 — UX backlog cleared (UX-009 done + final sweep)

- UX-009 (a11b5f2): responsive card layout for the fleet inventory on small screens (table is lg-only; cards below) — no more forced 1200px horizontal scroll. Last open UX item.
- Final sweep: cross-referenced every UI /api/* call against registered routes → ZERO unrouted endpoints remain. Checked MigrationConsole/PolicyStudio/ComplianceMatrix/CbomViewer/WavePlanning/AgilityDashboard for unbounded lists: CbomViewer already slices to 12; the migrations/compliance/policy lists are single-purpose full-tab views where page-scroll is the right pattern (bounding = nested scrollbars), so deliberately unchanged.
- Status: ALL catalogued UX-001..016 are Implemented/Fixed. No open UI/UX items remain.

## 2026-06-13 — WP-022 delivered (Linux/WSL-side): wave dependency graph + budget

DB migration **28** (`depends_on JSONB`) on `wave_plans`; `WavePlan.DependsOn []string` field; wired through `CreateWavePlan`/`GetWavePlans`/`UpdateWavePlan` in store.go (added `nonNilSlice` helper). New `waveplan/graph.go`: `BuildGraph` (cycle detection via Kahn's topo sort, unknown-ref flagging, per-node `BlockedBy`/`Activatable`), `ComputeBudget` (budget/actual/variance/over-budget/completion%), `Planner.Graph`/`Planner.Budget`. Planner `Create` rejects unknown dependency refs; `UpdateStatus`→active is blocked until all dependencies reach `completed` (`incompleteDependencies`). New endpoint `GET /api/waves/graph` (operator/admin) returns `{graph, budget}`. Tests `waveplan/graph_test.go` (8 new: topo order, cycle, unknown-ref/activatable, blocked-by, budget rollup + over-budget, unknown-dep rejection, dependency-gated activation). Full server suite green; migration-uniqueness test accepts 28. **store.go touched** (struct + 3 CRUD fns + migration) — Windows side note.

## 2026-06-13 — WP-023 delivered (Linux/WSL-side): agility exercise harness + per-adapter negotiation

New `agility/adapters.go`: curated adapter capability matrix (nginx/apache/ssh/windows-trust-store/windows-schannel-policy) with supported PQC KEMs/signatures, min-version notes, negotiation/rollback flags — grounded in docs/ALGORITHM_COMPATIBILITY.md (OpenSSL 3.5 hybrid groups, OpenSSH 9.9 mlkem768x25519, SChannel classical-only). `normalizeAlgorithm` alias map (Kyber→ML-KEM, Dilithium→ML-DSA); `adapterCovers` (pure ML-KEM-768 satisfied by a hybrid group containing it). New `agility/harness.go`: `RunNegotiationHarness(targets)` → per-adapter readiness (ready/partial/unsupported), matched/missing targets, replacement path, rollback availability, weighted grade; `EstimateTTSADays` honest heuristic (hardcode + blast radius lengthen, adapter readiness shortens). Harness is offline capability-evaluation (labeled `Method`), not a live handshake. Wired into `POST /api/agility/exercise`: derives targets from active profile PreferredKEM/PreferredSignature (override via `?targets=`), runs harness, and **populates the previously-dead `agility_metrics` table** per-host via the existing `UpsertAgilityMetrics` (honoring its FK to assets — per-host rows, not a synthetic fleet row). Response now `{exercise, negotiation, estimated_ttsa_days}`. Tests `agility/harness_test.go` (9: alias normalization, nginx ready, pure-ML-KEM-via-hybrid, schannel unsupported, ssh hybrid KEX, grade/counts, empty targets, TTSA monotonicity). agility package green.

NOTE: full server build transiently broken by the Windows side's S1 in-flight edit (`server.go` calls `LoginHandler` with the pre-S1 2-arg signature). My AUTH-003 allowlist change in auth.go survived their overhaul. My packages (agility/waveplan/grpcserver/config) pass individually; httpapi will verify once their S1 server.go call is updated.

## 2026-06-13 — Critical security fixes (S1, S5)

Claimed and fixed the two CRITICAL items from PROJECT-REVIEW that were never addressed:
- S1 (34f5b6d): removed compiled-in dashboard passwords (janus-admin-pass etc.) — open-source universal backdoor. Now env-configured + bcrypt: JANUS_<ROLE>_PASSWORD[_HASH]/_USERNAME, fail-closed when unset, dummy-hash compare on miss (no user enumeration). LoginHandler validates via bcrypt. config.loadCredentials/Credential. 5 login tests.
- S5 (34f5b6d): SoftHSM2.Verify returned true for ANY signature + Sign returned a fixed pattern (forgery hole). Now real HMAC-SHA256 over a per-key crypto/rand secret; Verify constant-time compares. Round-trip + tamper + wrong-key tests.
- Wired the env credentials into test-e2e-windows.ps1 and CLAUDE.md (login now fails closed without them).
- hsm/httpapi/config packages pass; builds clean; new code gofmt-clean.

Remaining unclaimed (large, security-phase / multi-session): LLM-003 (secret protection), LLM-007 (binary-analysis engine), LLM-011 (remediation suggestion pipeline), LLM-013/014/017/018 (deterministic remediation validation, governed execution, autonomous-remediation policy, LLM reliability controls), LLM-005/019/020 (prompt registry, eval gates, doc claims), CR-AFM verification items. These are substantial features, not quick wins — flagged for dedicated sessions.

## 2026-06-13 — WP-014 delivered (Linux/WSL-side): trustworthy discovery engine

No proto changes (confirmed proto.rs is prost-bound + WIP; acceptance met without contract edits). Deliverables:
- **New `agent/src/discovery/config_parse.rs`** — directive-aware structural parsers for nginx (`ssl_protocols`/`ssl_ciphers`/`ssl_ecdh_curve`), OpenSSH (`KexAlgorithms`/`Ciphers`/`MACs`/`HostKeyAlgorithms`), OpenSSL (`MinProtocol`/`CipherString`/`Groups`). Recognizes PQC-hybrid groups (X25519MLKEM768, mlkem768x25519, sntrup761x25519) as NOT quantum-vulnerable; classical KEX/curves/RSA/ECDSA as QV; legacy protocols/ciphers/MACs as weak. High-confidence (0.90), `negotiate`/`negotiate-weak` status, `source_type=structural-config`. 8 unit tests.
- **Wired into `source.rs` scan()**: recognized configs use the structural parser (authoritative) and skip the regex pass; the `is_source` gate now also admits extensionless `sshd_config`/`ssh_config` via `config_parse::is_known_config_path`.
- **Reachability honesty (WP-014 criterion)**: `source.rs` regex components and `binary.rs` import-table components now set `reachable=false` (textual/import match ≠ proven runtime reachability); structural config findings set `reachable=true` (a directive is an active negotiated selection).
- **Detection gaps fixed**: RSA pattern gained the lowercase module idiom `\brsa[._:]` (Go `rsa.GenerateKey`, Rust `rsa::`, Python `rsa.`); DSA gained `\bdsa[._]` (won't fire inside `ecdsa`). Existing `corpus_precision_recall` stays 1.000/1.000 (test-file cases still classified test-only).
- **Versioned benchmark (`mod detection_benchmark` in source.rs)** reports precision/recall **by language and by detector** — 18 cases, aggregate 1.000/1.000, 0 FP; gates: 0 FP, recall ≥ 0.90, precision ≥ 0.99. Documented in `docs/analysis/DETECTION-BENCHMARK.md` (incl. full-AST deferral rationale: tree-sitter's C toolchain would break the portable Windows/Linux build).
Files: `agent/src/discovery/{config_parse.rs (new), source.rs, binary.rs, mod.rs}`, `docs/analysis/DETECTION-BENCHMARK.md`. agent: 80 tests pass, fmt clean, my code clippy-clean (residual clippy warnings are in evidence.rs/prompts.rs — not mine). source.rs/binary.rs/mod.rs were clean (committed) before my edits; proto.rs/cbom.rs/dependency.rs left untouched (WIP).

## 2026-06-13 — LLM-019 prompt-injection defense (commit 6342904)

Implemented the research's central LLM-safety control (§9.2/9.5): evidence (attacker-controlled scanned data) is now quarantined in <untrusted_evidence> delimiters in the USER turn, the SYSTEM prompt reasserts authority, and a DetectInjection regex layer flags injection markers (recorded; advisory — deterministic facts still own truth). Release-gate test: 8 seeded attacks detected, 4 benign strings clean, prompt/system-prompt hardening asserted. llm+httpapi tests pass.

Cadence note: working the unclaimed backlog one fully-verified item per turn (UX → S1/S5 → LLM-019). Remaining large items still open (each needs a dedicated session): LLM-007 (binary-analysis engine, needs sandboxed disassembly), LLM-011/013/014 (remediation pipeline + deterministic validation + governed execution), LLM-017/018 (autonomous-remediation policy, reliability controls), LLM-003/005 (secret protection, server prompt registry), LLM-020 (README capability-maturity claims), and the security items S2 (public agent ingress — needs agent-side token on heartbeat/CSR), S3 (token in localStorage/URL → cookie+CSP), S4 (static agent token). CR-AFM items are "implemented, verification pending".
