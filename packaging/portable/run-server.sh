#!/usr/bin/env bash
# Janus Server portable launcher.
# Usage: edit janus.env, then ./run.sh   (extra args are passed to the server)
#
# NOTE: this starts the API/gRPC server only. The dashboard UI in ./ui is a set
# of static files; the server does NOT serve them. Host ./ui with any static
# file server that has SPA history-fallback (see the hint printed on startup).
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$here"

ENV_FILE="${JANUS_ENV_FILE:-janus.env}"
if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "./$ENV_FILE"
    set +a
fi

: "${JANUS_HTTP_ADDR:=127.0.0.1:8080}"

if [[ -z "${JANUS_COMMAND_SIGNING_KEY:-}" && -z "${JANUS_COMMAND_SIGNING_KEY_FILE:-}" ]]; then
    echo "ERROR: set JANUS_COMMAND_SIGNING_KEY in $ENV_FILE (openssl rand -hex 32)." >&2
    exit 1
fi

cat <<EOF
Janus API/gRPC starting (HTTP: ${JANUS_HTTP_ADDR}, gRPC: ${JANUS_GRPC_ADDR:-127.0.0.1:9443}).
The dashboard UI is static files in ./ui — the server does not serve them.
Serve them with any SPA-capable static server, for example:
    npx --yes serve -s ui -l 5173
Then set JANUS_CORS_ORIGIN in $ENV_FILE to that origin and restart.
EOF

exec ./bin/janus-server "$@"
