# Janus CryptoBOM — Quick Start

Get a Janus control plane (server + dashboard) and an agent running. There are **three
ways to deploy**, in order of how quickly you can get going:

| # | Method | Best for | PostgreSQL | UI hosting |
|---|--------|----------|------------|-----------|
| **A** | [Docker Compose](#a-docker-compose) | evaluation, a one-host demo | **auto** (in the compose stack) | served by a container |
| **B** | [Portable bundles](#b-portable-bundles) | a host without Docker, air-gapped installs | **you provide** (`setup-postgres`) | host the static `ui/` yourself |
| **C** | [Native / local install](#c-native--local-install) | production-style hosts, systemd/Windows service | **you provide** (`setup-postgres`) | serve `ui/` with nginx/IIS/etc. |

All three need **one shared signing key** and (for B and C) a **PostgreSQL** instance —
both covered once below, then referenced per method.

For full settings, roles, and operations see **[GUIDE.md](GUIDE.md)**; for the API see
**[API_REFERENCE.md](API_REFERENCE.md)**; for internals see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## 0. Prerequisites (all methods)

### 0.1 The signing key

Janus uses **one 32-byte hex key per deployment**, shared by the server and every agent
(`JANUS_COMMAND_SIGNING_KEY`). Generate it once with the bundled CLI (no external tools,
same on every OS) — or `openssl`:

```bash
janus-server gen-hmac-key      # bundled; works on Windows + Linux
# or: openssl rand -hex 32
```

Keep it out of version control. In production, prefer `JANUS_COMMAND_SIGNING_KEY_FILE`
(a file path) over the env var.

> **Hardening (optional).** You can keep this key inside an HSM (`JANUS_HSM_SIGN_COMMANDS`)
> and/or add an asymmetric **ML-DSA** signature that agents verify against a pinned
> fingerprint (`JANUS_COMMAND_SIG_SCHEME=ml-dsa`). See [`docs/GUIDE.md`](GUIDE.md) §7.

You can optionally use a **separate** key for dashboard
sessions via `JANUS_JWT_SECRET` (defaults to the command key).

### 0.2 PostgreSQL (methods B and C only — Docker does this for you)

Janus needs a PostgreSQL 16 database. **The server creates and upgrades its own schema on
startup** (versioned migrations) — you only need to provision an empty role + database.

Run the provided helper against your PostgreSQL as a superuser:

```bash
# Linux/macOS
PGHOST=localhost PGUSER=postgres PGPASSWORD=secret \
  ./scripts/setup-postgres.sh 'a-strong-janus-password'
```
```powershell
# Windows
$env:PGHOST="localhost"; $env:PGUSER="postgres"; $env:PGPASSWORD="secret"
.\scripts\setup-postgres.ps1 -JanusPassword "a-strong-janus-password"
```

It creates the `janus` role + `janus` database (idempotent) and prints the
`JANUS_DATABASE_URL` to use. Manual equivalent, if you prefer:

```sql
CREATE ROLE janus WITH LOGIN PASSWORD 'a-strong-janus-password';
CREATE DATABASE janus OWNER janus;
```

Connection string: `postgres://janus:<password>@<host>:5432/janus?sslmode=disable`
(use `sslmode=require` once PostgreSQL has TLS).

---

## A. Docker Compose

Everything (PostgreSQL + server + a passive agent) on one host. No DB setup needed.

```bash
# from the repo root
export JANUS_COMMAND_SIGNING_KEY=$(openssl rand -hex 32)
docker compose up -d
docker compose ps          # postgres healthy, server + agent up
```

The compose `postgres` service auto-creates the `janus` role/db from its `POSTGRES_*`
env; the server waits for it (healthcheck) and migrates on start. Ports: HTTP/REST/WS
**:8080**, gRPC **:9443**, PostgreSQL **:5432**.

The server serves the **API/gRPC only** — see [§ Serving the dashboard](#serving-the-dashboard)
to bring up the UI. Then jump to [First results](#first-results).

To set dashboard passwords, add `JANUS_ADMIN_PASSWORD=…` (etc.) to the `janus-server`
service environment (there are no default credentials).

---

## B. Portable bundles

Unzip → edit `janus.env` → run a launcher. No package manager, no Docker. Build the
bundles with `make portable` (Linux) or the MSBuild `Portable` target (Windows); they land
in `dist/portable/`.

**First, prepare PostgreSQL** ([§0.2](#02-postgresql-methods-b-and-c-only--docker-does-this-for-you)).

### B.1 Server + UI

```powershell
# unzip janus-server-ui-*-<os>.zip, then:
cd janus-server-ui-*
notepad janus.env     # Linux: $EDITOR janus.env
#   set JANUS_COMMAND_SIGNING_KEY=<key from §0.1>
#   set JANUS_DATABASE_URL=postgres://janus:<pw>@<host>:5432/janus?sslmode=disable
#   set JANUS_ADMIN_PASSWORD=<pick one>   (no default credentials)
.\run.ps1             # Linux: ./run.sh   — starts API/gRPC, runs migrations
```

### B.2 Agent

```powershell
# unzip janus-agent-*-<os>.zip, then:
cd janus-agent-*
notepad janus.env     # set JANUS_COMMAND_SIGNING_KEY (the SAME key) + controller endpoints
.\run.ps1             # Linux: ./run.sh — renders janus-agent.toml on first run, then scans
```

The agent is **passive by default** — it discovers and reports; it never changes anything
until you explicitly enqueue a signed migration. Now host the UI (below) and see
[First results](#first-results).

---

## C. Native / local install

Run the binaries directly on the host (production-style, with the agent as a managed
service). Obtain binaries by building (`make build` on Linux, `msbuild
JanusCryptoBOM.msbuild.proj /t:Build` on Windows) or from the release tarballs
(`make release-linux` → `dist/packages/`, incl. native `.deb`/`.rpm` for the agent).

**First, prepare PostgreSQL** ([§0.2](#02-postgresql-methods-b-and-c-only--docker-does-this-for-you)).

### C.1 Server

```bash
export JANUS_DATABASE_URL="postgres://janus:<pw>@localhost:5432/janus?sslmode=disable"
export JANUS_HTTP_ADDR="0.0.0.0:8080"
export JANUS_GRPC_ADDR="0.0.0.0:9443"
export JANUS_COMMAND_SIGNING_KEY="<key from §0.1>"
export JANUS_ADMIN_PASSWORD="<pick one>"
./bin/janus-server        # Windows: .\bin\janus-server.exe
```

For a long-running server, wrap it in your init system (a systemd unit, Windows service
via NSSM, or a container). See [GUIDE.md §3](GUIDE.md) for a sample systemd unit and
production hardening (`JANUS_REQUIRE_TLS`/`JANUS_REQUIRE_MTLS`, retention, mTLS).

### C.2 Agent as a managed service

```bash
# Linux (systemd): installs the binary + a hardened passive unit
sudo ./scripts/install-agent-linux.sh        # uninstall: scripts/uninstall-agent-linux.sh
```
```powershell
# Windows service
.\scripts\install-agent-windows-service.ps1 -AgentExe "D:\janus\bin\janus-agent.exe" `
  -ConfigPath "D:\janus\agent\janus-agent.example.toml" -Start
```

Or run the native packages: `apt install ./janus-agent_*.deb` / `rpm -i janus-agent-*.rpm`
(they install `/usr/bin/janus-agent`, a config, and a passive systemd unit). Edit the
agent's `janus-agent.toml` to set `command_signing_key` (the shared key) and
`controller_endpoint`, then start the service.

---

## Serving the dashboard

The server serves the **API/gRPC only** — the dashboard is static files in `ui/` (built by
`npm run build` / shipped in the server+UI bundle). Host them with any SPA-capable static
server (one that falls back to `index.html`):

```bash
npx --yes serve -s ui -l 5173          # quick: dashboard at http://127.0.0.1:5173
# or nginx:  location / { try_files $uri /index.html; }
```

Then set `JANUS_CORS_ORIGIN` to that origin (e.g. `http://127.0.0.1:5173`) and restart the
server so the browser can call the API.

---

## First results

1. **Open the dashboard** and log in with a role password you set (`JANUS_ADMIN_PASSWORD`
   etc. — there are no default credentials). The **Overview** tab shows the fleet
   quantum-readiness score; **CBOM**, **Compliance Matrix**, and **Fleet Command** populate
   as agents report.
2. **Pick a policy** — in **Policy Studio**, activate `nist-pqc-2026` or `cnsa-2.0`.
3. **Triage & migrate** (operator/admin) — review findings, run a dry-run
   (`POST /api/sandbox/simulate`), then enqueue a signed migration and watch it live.

---

## Use Janus in CI (no server needed)

The agent's `check` subcommand is a self-contained gate — exit 0 when clean, 1 when it
finds quantum-vulnerable crypto:

```bash
janus-agent check ./src --format sarif --output janus-findings.sarif
janus-agent check ./src --changed-since origin/main      # only files changed vs a git ref
# or the helper:
./scripts/janus-ci.sh ./src --fail-on critical
```

Upload `janus-findings.sarif` to GitHub code scanning with
`github/codeql-action/upload-sarif`.

---

## Troubleshooting & next steps

- **Server exits immediately** → `JANUS_COMMAND_SIGNING_KEY` is unset (it's required).
- **Agent won't start** → empty `command_signing_key` in its TOML/`janus.env`.
- **DB connection refused** → check `JANUS_DATABASE_URL`; for B/C run [§0.2](#02-postgresql-methods-b-and-c-only--docker-does-this-for-you).
- **Dashboard can't reach the API (CORS)** → set `JANUS_CORS_ORIGIN` to the UI origin.
- Production hardening, roles, wave planning, maintenance: **[GUIDE.md](GUIDE.md)**. Full
  endpoint reference: **[API_REFERENCE.md](API_REFERENCE.md)**. Writing plugins:
  **[PLUGIN_GUIDE.md](PLUGIN_GUIDE.md)**.
