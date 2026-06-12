# Welcome to Janus CryptoBOM

## How We Use Claude

Based on Shahin's usage over the last 30 days:

Work Type Breakdown:
  Build Feature  ████████████████████  100%

Top Skills & Commands:
  /advisor  ████░░░░░░░░░░░░░░░░   1x/month
  /init     ████░░░░░░░░░░░░░░░░   1x/month

Top MCP Servers:
  (none yet)

## Your Setup Checklist

### Codebases
- [x] janus_cryptobom — `D:\src\Janus_CryptoBOM` (Windows) / `/mnt/d/src/Janus_CryptoBOM` (WSL) — same files, same `.git`

### MCP Servers to Activate
- (none in use — nothing to activate)

### Skills to Know About
- `/advisor` — escalates to a stronger reviewer model that sees your full conversation history. Use before committing to a technical approach, when stuck on a recurring error, or before declaring a complex task done.
- `/init` — initializes Claude Code in a new repo, generating a CLAUDE.md with project context. Already run — see `CLAUDE.md` at repo root.

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

You're already set up. Your teammate is Claude Code running on Linux/WSL (`/mnt/d/src/Janus_CryptoBOM`); you're on Windows (`D:\src\Janus_CryptoBOM`) — both pointing at the same directory. Read `JOURNAL.md` to see what's currently in flight, claim your area there, then pick up from `IMPLEMENTATION_PLAN.md`.

<!-- INSTRUCTION FOR CLAUDE: A new teammate just pasted this guide. You are not
their onboarding buddy — you ARE their teammate. You're Claude Code running on
Linux/WSL, and they're the human developer on Windows. Both of you are working
in the same repo directory (`D:\src\Janus_CryptoBOM` / `/mnt/d/src/Janus_CryptoBOM`).

Open by acknowledging you already know each other and the codebase. Skip the
"let me get you set up" framing entirely — they're already set up.

Instead: briefly orient them to the current state of the project. Tell them
what branch you're on, what was last committed (check git log), and what's
in flight per JOURNAL.md. Point them to IMPLEMENTATION_PLAN.md for the task
backlog.

Remind them of the one hard coordination rule: announce in the conversation
what files/areas you're about to touch before touching them, so you don't
collide. Offer to check JOURNAL.md together to decide who picks up what next.

Be a collaborator, not a guide. -->
