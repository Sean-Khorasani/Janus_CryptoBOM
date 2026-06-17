#!/usr/bin/env bash
# Janus Agent portable launcher.
# Usage: edit janus.env, then ./run.sh   (extra args are passed to the agent,
# e.g. ./run.sh --once  or  ./run.sh check ./path)
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$here"

# 1. Load deployment settings from janus.env (override path with JANUS_ENV_FILE).
ENV_FILE="${JANUS_ENV_FILE:-janus.env}"
if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "./$ENV_FILE"
    set +a
fi

# 2. Defaults for anything not set in janus.env.
: "${JANUS_CONTROLLER_ENDPOINT:=http://127.0.0.1:9443}"
: "${JANUS_HTTP_CONTROLLER_ENDPOINT:=http://127.0.0.1:8080}"
: "${JANUS_COMMAND_SIGNING_KEY:=}"
# JANUS_SCAN_ROOTS is intentionally a TOML-array string literal, not a shell array.
# shellcheck disable=SC2089
: "${JANUS_SCAN_ROOTS:=[\"/opt\", \"/srv\"]}"
: "${JANUS_STATE_DIR:=state}"
# shellcheck disable=SC2090
export JANUS_CONTROLLER_ENDPOINT JANUS_HTTP_CONTROLLER_ENDPOINT \
    JANUS_COMMAND_SIGNING_KEY JANUS_SCAN_ROOTS JANUS_STATE_DIR

CONFIG="${JANUS_CONFIG:-janus-agent.toml}"
TEMPLATE="janus-agent.toml.template"

# 3. Render the config on first run (generate-if-absent: later hand-edits to
#    janus-agent.toml survive; delete it to re-render from janus.env).
if [[ ! -f "$CONFIG" ]]; then
    if [[ -z "$JANUS_COMMAND_SIGNING_KEY" ]]; then
        echo "ERROR: JANUS_COMMAND_SIGNING_KEY is empty in $ENV_FILE." >&2
        echo "       Generate one with: openssl rand -hex 32" >&2
        exit 1
    fi
    if [[ ! -f "$TEMPLATE" ]]; then
        echo "ERROR: $TEMPLATE missing; cannot render $CONFIG." >&2
        exit 1
    fi
    if command -v envsubst >/dev/null 2>&1; then
        # The single-quoted list names the vars envsubst should expand (envsubst
        # does the expansion, not the shell) — SC2016 is a false positive here.
        # shellcheck disable=SC2016
        envsubst '${JANUS_CONTROLLER_ENDPOINT} ${JANUS_HTTP_CONTROLLER_ENDPOINT} ${JANUS_COMMAND_SIGNING_KEY} ${JANUS_SCAN_ROOTS} ${JANUS_STATE_DIR}' \
            <"$TEMPLATE" >"$CONFIG"
    else
        # Fallback when gettext/envsubst is not installed. '|' delimiter avoids
        # clashing with '/' and ':' in the endpoint values.
        sed -e "s|\${JANUS_CONTROLLER_ENDPOINT}|${JANUS_CONTROLLER_ENDPOINT}|g" \
            -e "s|\${JANUS_HTTP_CONTROLLER_ENDPOINT}|${JANUS_HTTP_CONTROLLER_ENDPOINT}|g" \
            -e "s|\${JANUS_COMMAND_SIGNING_KEY}|${JANUS_COMMAND_SIGNING_KEY}|g" \
            -e "s|\${JANUS_SCAN_ROOTS}|${JANUS_SCAN_ROOTS}|g" \
            -e "s|\${JANUS_STATE_DIR}|${JANUS_STATE_DIR}|g" \
            "$TEMPLATE" >"$CONFIG"
    fi
    echo "Rendered $CONFIG from $TEMPLATE. Edit it directly to change settings;"
    echo "delete it to re-render from $ENV_FILE."
fi

# 4. Ensure the state directory exists, then launch.
mkdir -p "$JANUS_STATE_DIR"
echo "Starting janus-agent (config: $CONFIG, state: $JANUS_STATE_DIR)..."
exec ./bin/janus-agent --config "$CONFIG" "$@"
