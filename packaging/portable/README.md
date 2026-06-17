# Portable "copy and run" packaging

This directory builds dependency-free bundles (`.tar.gz` **and** `.zip`) that an
operator deploys by unpacking, editing `janus.env`, and running a launcher — no
`apt`/`dpkg`/`rpm` required. It is **additive** to `packaging/linux/`
(`build-release.sh` tarballs + `build-packages.sh` deb/rpm), which are unchanged.

## Build (Linux/macOS)

```bash
make portable           # agent + server-ui bundles for the host arch
make portable-agent     # agent only — needs just the Rust toolchain (no UI/npm)
make portable-server    # server + UI bundle (builds UI + Go server)
```

Output: `dist/portable/` (bundles + `SHA256SUMS`).

### Cross-architecture (best effort)

```bash
JANUS_PORTABLE_ARCHES="x86_64 aarch64" make portable
```

- **Server** cross-compiles for any listed arch (Go's built-in `GOOS/GOARCH`).
- **Agent** cross-builds only if the Rust target and a matching C cross-linker
  are installed (`rusqlite` bundles C SQLite). If not, that arch's agent is
  **skipped with a loud warning** — never silently omitted. Install with
  `rustup target add aarch64-unknown-linux-gnu` plus the aarch64 cross-gcc.
- The host arch always uses the binaries already built by the `make` deps.

## Build (Windows)

```powershell
msbuild JanusCryptoBOM.msbuild.proj /t:PortableAgent          # build + package
msbuild JanusCryptoBOM.msbuild.proj /t:PortableAgentNoBuild   # package an existing build
```

Output: `dist\portable\janus-agent-<version>-windows-x86_64.zip`.

## What's in each bundle

| File | Purpose |
|---|---|
| `bin/` | the binary (`janus-agent[.exe]` / `janus-server`) |
| `run.sh` / `run.ps1` | launcher: loads `janus.env`, renders config (agent), starts the binary |
| `janus.env` | the one file an operator edits |
| `janus-agent.toml.template` | (agent) rendered to `janus-agent.toml` on first run, generate-if-absent |
| `ui/`, `policies/` | (server) built dashboard + policy profiles |
| `README.md`, `VERSION.env` | end-user instructions + release contract |

## Files here

- `build-portable.sh` — the Linux builder (component arg: `agent`/`server`/`all`).
- `run-agent.sh` / `run-agent.ps1` / `run-server.sh` — launchers copied into bundles as `run.sh`/`run.ps1`.
- `janus-agent.toml.template` — agent config template with `${JANUS_*}` placeholders.
- `janus-agent.env.example` / `janus-agent.windows.env.example` / `janus-server.env.example` — copied into bundles as `janus.env`.
- `README-agent.md` / `README-server-ui.md` — end-user docs shipped in the bundles.
- `../windows/build-portable-agent.ps1` — the Windows agent zip builder.

> The server bundle starts the API/gRPC server only; the dashboard `ui/` is
> static files that need an SPA-capable static server (see the bundle README).
