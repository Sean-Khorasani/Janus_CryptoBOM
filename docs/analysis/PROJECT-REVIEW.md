# Janus CryptoBOM — Source Review: Issues, Partial Implementations, Bugs & Improvements

Date: 2026-06-12 · Reviewer: Windows-side session · Method: direct read of UI (`ui/src`), server auth/HSM/WS, agent discovery (covered in `DETECTION-IMPROVEMENTS.md`). Severity: **C**ritical / **H**igh / **M**edium / **L**ow. References are `file:line`. This is an assessment; nothing here was changed — fixes are proposed, with the security-critical ones flagged for immediate action.

---

## A. Security (review the agent runs privileged; the server aggregates an attack map)

| # | Sev | Finding | Evidence | Recommendation |
|---|---|---|---|---|
| **S1** | **C** | **Hardcoded static credentials.** Login accepts only compiled-in `admin/janus-admin-pass`, `operator/janus-operator-pass`, `viewer/janus-viewer-pass`. No user store, no hashing, no rotation. The repo is **open source** → these are a universal backdoor on every deployment. | `server/internal/httpapi/auth.go:212-223` | Replace with a real user store: hashed passwords (argon2/bcrypt), seeded admin from env/secret at first boot, configurable. Until then, at minimum require a mandatory `JANUS_ADMIN_PASSWORD` env (panic if unset, like the signing key). |
| **S2** | **H** | **Unauthenticated agent ingress.** `/api/agent/heartbeat` and `/api/certificates/csr` are explicitly public "for older agents." Heartbeat carries scan progress/CPU/mem/diagnostics; CSR lets *anyone* request certificate signing. Agents are untrusted input (RESEARCH.md §4.4/§12) yet these take agent data with no auth. | `auth.go:121-125` | Apply the agent HMAC token (S4) to heartbeat and CSR; drop the "older agent" exemption or gate it behind an explicit `JANUS_ALLOW_LEGACY_AGENTS` flag, off by default. |
| **S3** | **H** | **Tokens in localStorage + WS token in URL.** JWT stored in `localStorage` (XSS-exfiltratable). WebSocket auth passes `?access_token=<jwt>` in the URL → leaks into server access logs, proxy logs, browser history. | `ui/src/auth.ts:4-6`, `useApi.ts:139`, `AgentFleetInventory.tsx:77`, server side `auth.go:128-132` | Prefer httpOnly+Secure+SameSite cookie for the session; for WS use a short-lived single-use ticket fetched over the authed channel, not the long-lived JWT in the query string. Add a CSP header. |
| **S4** | **M** | **Static agent token.** Agent auth = `HMAC(signing_key, host_uuid)` — never expires, derived solely from a guessable/observable host UUID; a leak is valid forever, and it only guards 2 endpoints. | `auth.go:108-119` | Add expiry/nonce to the agent token; rotate; cover all agent endpoints. |
| **S5** | **C** | **SoftHSM2 fallback is fake crypto.** `Sign` returns a fixed byte pattern `soft-hsm-sig-<keyID>`; `Verify` returns `true` for *any* signature when the key exists. If this backend is ever selected in production, all HSM-backed signatures are forgeable and verification is meaningless. | `server/internal/hsm/softhsm.go:38-60` | Ensure SoftHSM2 cannot be selected outside dev (gate on a dev flag; default-production must require the real PKCS#11 backend). Make `Verify` actually verify, or make the type clearly test-only and unreachable from prod wiring. Matches `TASKS.md` HSM-01. |

Positive: `VerifyToken` ignores the JWT `alg` header and always uses HMAC-SHA256, so it is **not** vulnerable to alg-confusion / `alg:none` (`auth.go:62-95`). Good a11y/security scaffolding exists (focus trap, skip link, ARIA roles).

---

## B. Partial implementations & doc↔code drift

| # | Sev | Finding | Evidence |
|---|---|---|---|
| **P1** | **H** | **Real-time is largely unimplemented.** CLAUDE.md advertises a `useWebSocket` hook with WS updates + 10s polling fallback. No such hook exists; the main dashboard (`useApi`) is **polling-only at 10s**. The server hub broadcasts `telemetry_update`/`finding_status`/`migration_*`/`policy_switched`, but only `AgentFleetInventory` opens a socket — and only to trigger a refetch on 3 event types. The advertised real-time UX is absent for Overview/Findings/Migrations/Compliance. | `ui/src/hooks/useApi.ts:242-250`; only WS at `AgentFleetInventory.tsx:75-85`; no `useWebSocket.ts` in tree |
| **P2** | **H** | **HSM PKCS#11 partly stubbed** (see S5). `TASKS.md` HSM-01/02/03 flag the in-memory stub and a Windows skeleton; a later commit claims the SoftHSM2 DLL loads. Two backends coexist — reconcile which is wired in prod. | `server/internal/hsm/softhsm.go`, `pkcs11_windows.go`; `TASKS.md:44-50` |
| **P3** | **M** | **Bulk-select dead-end.** Agent inventory shows "N agents selected for bulk operations" but there are **no bulk-action controls** anywhere. | `AgentFleetInventory.tsx:161` (banner), `:165/:170` (checkboxes) — no consuming action |
| **P4** | **L** | **Dead code:** `saveAgentDiagnostics` is built and returned by `useApi` but never consumed by any component. | `useApi.ts:324-332,361`; not destructured in `App.tsx:82-100` |
| **P5** | **M** | **Finding lifecycle is client-local & fragile.** Status lives primarily in `localStorage`; `readPersistedFindingStatuses` iterates **every** localStorage key and treats any whose value is in the lifecycle set as a finding id — pollution-prone and collision-prone. Server `PUT /status` exists but the client treats localStorage as the working store. | `App.tsx:22-57,114-146` |

---

## C. Bugs / correctness

| # | Sev | Finding | Evidence | Fix |
|---|---|---|---|---|
| **B1** | **M** | **Misleading per-asset remediation.** When no finding matches an asset by `host_uuid`/`hostname`, all findings are dumped onto `assets[0]` (`idx===0`). Produces wrong per-asset "X/Y remediated" numbers — a demo fudge. | `OverviewView.tsx:202-207` | Remove the fallback; show "no findings mapped to this asset" honestly. |
| **B2** | **M** | **Safety Score ignores triage.** Score is computed from raw `overview.*_findings` counts; marking findings remediated/false-positive (client-side) never improves it, while the algorithm histogram on the same page *does* filter them — inconsistent. | `useApi.ts:252-258` vs `OverviewView.tsx:43-69` | Compute score from server-authoritative open findings, excluding remediated/false-positive; add a tooltip explaining the formula. |
| **B3** | **L** | **Type drift:** `overview.stalled_agents` read via `(overview as any)` — field missing from the `Overview` type, so it's untyped and easy to break. | `OverviewView.tsx:132-133`; type at `useApi.ts:5-13` | Add `stalled_agents` to `Overview`. |
| **B4** | **M** | **RTL not applied.** Persian (`fa`) is right-to-left but only `documentElement.lang` is set, never `dir="rtl"` → broken Persian layout. The language `aria-label` also advertises Arabic, but there is no `ar` locale. | `i18n/index.tsx:36-38`; `App.tsx:204` | Set `document.documentElement.dir = isRTL(locale) ? 'rtl' : 'ltr'`; add `ar` or drop it from the label. |
| **B5** | **L** | **Error masking.** `fetchWithTimeout` resolves synthetic `500`/`504` Responses on network failure, so `load()` cannot distinguish offline vs server error; no backoff on the 10s loop. | `useApi.ts:153-169` | Surface error class; add backoff when consecutive failures occur. |
| **B6** | **L** | **Untranslated tab labels** "Agility", "Wave Plans", "LLM Analysis" are hardcoded while peers use `t()`. | `App.tsx:166-168` | Route through `t()`; audit components for hardcoded English (FindingsGrid, AgentFleetInventory labels are all literal). |

---

## D. UI/UX improvements (priority focus)

**High-value**
1. **Ship real-time (P1).** A shared `useWebSocket` hook feeding `useApi` state would make Overview/Findings/Migrations live; the server infrastructure already broadcasts the events. Biggest perceived-quality win, low server cost. Keep 10s polling as the documented fallback.
2. **RTL + i18n completeness (B4/B6).** Persian users currently get an LTR layout. Set `dir`, mirror the layout, and finish translation coverage (many components are English-only despite the locale switcher implying full support).
3. **Make the Safety Score trustworthy (B2).** It should respond to triage and be explainable (hover = formula + counts). A security score that never moves when you remediate erodes trust in the whole dashboard.
4. **Resolve bulk-select (P3).** Either implement bulk agent actions (rescan, tag, decommission) or remove the selection affordance — a checkbox that does nothing reads as broken.

**Accessibility & interaction**
5. **Sortable headers aren't keyboard-accessible.** `AgentFleetInventory` uses clickable `<th onClick>` with no `role="button"`, `tabindex`, or key handler, and `<th>` lacks `scope`. Convert to header buttons with `aria-sort`. (Commend the existing skip link, focus trap, ARIA tabs — keep that bar.)
6. **Honest-coverage surface.** Per RESEARCH.md §4.2 ("never claim 100% coverage"), add a per-host "what was scanned / what wasn't / evidence freshness" panel — the agent now emits negative-evidence records (CNG-PQ-absent, etc.) that the UI can render.
7. **Confirmation + feedback on state-changing actions.** Verify policy switch (`PolicyStudio`) and migration enqueue (`MigrationConsole`) show confirm dialogs and success/failure toasts, not just optimistic silent updates.
8. **Mobile/responsive.** Inventory tables force `min-w-[1200px]` horizontal scroll; consider responsive card layouts or column priority at small widths.
9. **Error UX.** The header status is binary ("Live controller" / "API offline") and the error banner is sticky; add a transient, dismissible toast and a "last updated Ns ago" freshness indicator instead of a permanent banner.

**Security-facing UX**
10. Move tokens out of `localStorage`/URL (S3) — this is also a UX win (sessions survive cleanly, no token in shareable URLs).

---

## E. Cross-cutting suggestions
- **Server-authoritative finding lifecycle** (fixes P5/B2 together): make the DB the source of truth, drop the localStorage scan-all-keys mirror, keep a small optimistic cache keyed only by finding id.
- **EvidenceRecord on the wire** (RESEARCH.md §4.4): findings/components should carry provenance + confidence + negative-evidence end-to-end; the agent already produces much of this (`Evidence` proto, the new `cng-pq-primitive-absent` negative records) but the UI/API don't expose provenance or conflicts.
- **Credentials → real auth** (S1) is the single highest-priority fix; it gates any real deployment and pairs with the SECURITY-REVIEW deliverable.

---

## F. Recommended immediate actions (this branch)
Per the original brief ("fix critical security immediately"), **S1 (hardcoded creds)** and **S5 (fake SoftHSM Verify reachable in prod)** are the two that warrant fixing now; the rest belong in the ranked ROADMAP. The remaining items are reviewable/triageable and platform-neutral, so they can be split with the Linux session. Nothing here was modified in this review pass.
