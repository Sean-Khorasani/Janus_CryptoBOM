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
