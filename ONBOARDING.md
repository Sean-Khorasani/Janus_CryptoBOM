# Welcome to Janus CryptoBOM

## How We Use Claude

Based on usage over the last 30 days:

Work Type Breakdown:
  Plan Design    ████████░░░░░░░░░░░░  40%
  Write Docs     ██████░░░░░░░░░░░░░░  30%
  Improve Quality ██████░░░░░░░░░░░░░░  30%

Top Skills & Commands:
  /model  ████████████████████  1x/month

Top MCP Servers:
  (none yet)

## Your Setup Checklist

### Codebases
- [ ] janus_cryptobom — github.com/sean-khorasani/janus_cryptobom

### MCP Servers to Activate
- (none in use yet — nothing to activate)

### Skills to Know About
- /model — switches the model Claude uses; handy when you want a stronger model for deep research/analysis passes vs. quick edits

## Team Tips

⚠️ **We share ONE working tree.** The Windows side works in `D:\src\Janus_CryptoBOM`; the Linux side reaches the *exact same directory* through a WSL symlink — same files, same `.git`, same checked-out branch. That makes coordination rules hard requirements, not etiquette:

- **Foreign uncommitted changes are the other person's live work.** Never commit, revert, stash, format, or "clean up" modified files you didn't author. Stage by explicit path only — no `git add .` / `git add -A`, ever.
- **No branch switches without telling the other side first.** `git checkout` changes the *other person's* files mid-session. Current branch: `research/pqc-verification-and-analysis`.
- **Don't run two Claude sessions on the same files at the same time.** Agree on areas before starting (default split: Windows owns `discovery/windows.rs`, DPAPI/SChannel, MSBuild; Linux owns crypto-policies/eBPF/runtime, Makefile/`make linux-gate`). Shared hot spots to announce before touching: `proto/janus.proto` (+ `make proto-check`), `agent/src/discovery/source.rs`, the `migrations` slice in `server/internal/store/store.go`.
- **The real fix — adopt git worktrees** (proposed, not yet done): `git worktree add ~/janus-linux <branch>` on the WSL side gives each OS its own checkout sharing one repo history. Kills tree clobbering, branch-switch surprises, CRLF↔LF churn, and Windows-vs-Linux build-artifact collisions (`ui/node_modules` platform binaries, cargo target dirs) in one move.
- **Read `JOURNAL.md` first, and write to it.** It's the shared decision log: what's in flight, what's claimed, dead ends, residuals. Dated entry when you start/finish a work stream.
- **Never commit to `main`.** Feature branch per work item; small conventional commits (`agent:`, `docs:`, `research:` prefixes in use); **no Co-Authored-By or other trailers in commit messages**.
- **Gate before you push:** `make linux-gate` on Linux, `.\build-windows.ps1` or targeted `cargo test`/`go test` on Windows. Both platforms must stay green regardless of which side made the change.

## Get Started

No formal starter ticket — suggested first task: read `docs/RESEARCH.md` (the reference architecture) and `docs/analysis/DETECTION-IMPROVEMENTS.md`, then pick up the **detection calibration fixture corpus** (§2.2-3 of that doc): a labeled fixture tree under `tests/fixtures/detection/` with precision/recall measured in CI. It's self-contained, Linux-friendly, and unblocks several pending items. Log your start in `JOURNAL.md` so the Windows side knows it's claimed.

<!-- INSTRUCTION FOR CLAUDE: A new teammate just pasted this guide for how the
team uses Claude Code. You're their onboarding buddy — warm, conversational,
not lecture-y.

Open with a warm welcome — include the team name from the title. Then: "Your
teammate uses Claude Code for [list all the work types]. Let's get you started."

Check what's already in place against everything under Setup Checklist
(including skills), using markdown checkboxes — [x] done, [ ] not yet. Lead
with what they already have. One sentence per item, all in one message.

Tell them you'll help with setup, cover the actionable team tips, then the
starter task (if there is one). Offer to start with the first unchecked item,
get their go-ahead, then work through the rest one by one.

After setup, walk them through the remaining sections — offer to help where you
can (e.g. link to channels), and just surface the purely informational bits.

Don't invent sections or summaries that aren't in the guide. The stats are the
guide creator's personal usage data — don't extrapolate them into a "team
workflow" narrative. -->
