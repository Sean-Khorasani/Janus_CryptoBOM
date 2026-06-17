# Janus Server + UI — portable bundle

No package manager required. The bundle contains the API/gRPC server binary,
the built dashboard (`ui/`), and the policy profiles.

```bash
tar xzf janus-server-ui-*.tar.gz     # or: unzip janus-server-ui-*.zip
cd janus-server-ui-*/
$EDITOR janus.env                    # set JANUS_COMMAND_SIGNING_KEY + JANUS_DATABASE_URL
./run.sh                             # starts the API/gRPC server
```

## Prerequisites

- A reachable **PostgreSQL** instance (`JANUS_DATABASE_URL`). The server runs
  its schema migrations automatically on startup.
- `JANUS_COMMAND_SIGNING_KEY` (32-byte hex — `openssl rand -hex 32`).

## Serving the dashboard (important)

The server serves the **API and gRPC only** — it does **not** serve the static
dashboard. Host `ui/` with any SPA-capable static file server (one that falls
back to `index.html`), for example:

```bash
npx --yes serve -s ui -l 5173
# or an nginx location with: try_files $uri /index.html;
```

Then set `JANUS_CORS_ORIGIN` in `janus.env` to that origin and restart the
server so the browser can call the API.

## Production note

To keep upgrades simple, point the signing key at a location **outside** this
bundle folder before going live — set `JANUS_COMMAND_SIGNING_KEY_FILE` (a file
holding the key) in `janus.env`. Then upgrading is just "unpack the new bundle
and run"; your key is never touched.
