# Janus Agent — portable bundle

No package manager required. Copy this bundle to the target host, unpack, set
your values, and run.

## Linux / macOS

```bash
tar xzf janus-agent-*.tar.gz        # or: unzip janus-agent-*.zip
cd janus-agent-*/
$EDITOR janus.env                   # set JANUS_COMMAND_SIGNING_KEY + endpoints
./run.sh                            # renders janus-agent.toml, then runs
```

`./run.sh --once` runs a single scan and exits; `./run.sh check ./path` is the
CI-gate mode.

## Windows

```powershell
Expand-Archive janus-agent-*-windows-*.zip -DestinationPath .
cd janus-agent-*-windows-*
notepad janus.env                   # set JANUS_COMMAND_SIGNING_KEY + endpoints
.\run.ps1
```

## How configuration works

`run.sh` / `run.ps1` read **janus.env** and, on first run, render
**janus-agent.toml** from `janus-agent.toml.template`. After that the `.toml`
is the source of truth — edit it directly for anything not exposed in
`janus.env`. Delete the `.toml` to re-render from `janus.env`.

Required: `JANUS_COMMAND_SIGNING_KEY` (32-byte hex, shared with the server —
`openssl rand -hex 32`). The agent will not start without it.

State (SQLite offline queue, host-id, reports, backups) is written under
`JANUS_STATE_DIR` (default `state/`, relative to the bundle).

## Production note

To keep upgrades simple, point the signing key and the agent state at locations
**outside** this bundle folder before going live — set
`JANUS_COMMAND_SIGNING_KEY_FILE` (a file holding the key) and `JANUS_STATE_DIR`
in `janus.env`. Then upgrading is just "unpack the new bundle and run"; your key
and queued data are never touched.
