#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/janus-e2e-linux.XXXXXX")"

cleanup() {
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

phase() {
  printf '\n==> %s\n' "$1"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: required command not found: %s\n' "$1" >&2
    exit 1
  }
}

require_minimum_version() {
  local name="$1"
  local actual="$2"
  local minimum="$3"

  if [[ "$(printf '%s\n%s\n' "$minimum" "$actual" | sort -V | head -n1)" != "$minimum" ]]; then
    printf 'error: %s %s is older than required version %s\n' "$name" "$actual" "$minimum" >&2
    exit 1
  fi
  printf '%-12s %s (minimum %s)\n' "$name" "$actual" "$minimum"
}

phase "Checking Linux toolchain"
[[ "$(uname -s)" == "Linux" ]] || {
  printf 'error: this smoke test requires Linux\n' >&2
  exit 1
}

for tool in go cargo rustc node npm rsync sort; do
  require_command "$tool"
done

GO_VERSION="$(go version | sed -E 's/.* go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/')"
RUST_VERSION="$(rustc --version | awk '{print $2}')"
CARGO_VERSION="$(cargo --version | awk '{print $2}')"
NODE_VERSION="$(node --version | sed 's/^v//')"
NPM_VERSION="$(npm --version)"

require_minimum_version "Go" "$GO_VERSION" "1.25"
require_minimum_version "Rust" "$RUST_VERSION" "1.96.0"
require_minimum_version "Cargo" "$CARGO_VERSION" "1.96.0"
require_minimum_version "Node.js" "$NODE_VERSION" "22.0.0"
require_minimum_version "npm" "$NPM_VERSION" "10.0.0"

phase "Testing server"
(
  cd "$ROOT_DIR/server"
  go test -mod=readonly ./...
)

phase "Testing agent"
(
  cd "$ROOT_DIR/agent"
  CARGO_TARGET_DIR="$TMP_DIR/cargo-target" cargo test --locked
)

phase "Installing and building UI"
UI_WORK_DIR="$TMP_DIR/ui"
rsync -a --exclude node_modules --exclude dist "$ROOT_DIR/ui/" "$UI_WORK_DIR/"
(
  cd "$UI_WORK_DIR"
  npm ci
  npm run build -- --outDir "$TMP_DIR/ui-dist" --emptyOutDir
)

phase "Validating Docker Compose configuration"
if command -v docker >/dev/null 2>&1; then
  docker compose version >/dev/null 2>&1 || {
    printf 'error: Docker is installed but Compose v2 is unavailable\n' >&2
    exit 1
  }
  printf '%s\n' "$(docker --version)"
  printf '%s\n' "$(docker compose version)"
  docker compose -f "$ROOT_DIR/docker-compose.yml" config --quiet
  if docker info >/dev/null 2>&1; then
    printf 'Docker daemon is accessible; no daemon operations are required by this smoke test.\n'
  else
    printf 'Docker daemon is inaccessible; skipped daemon operations.\n'
  fi
else
  printf 'Docker is not installed; skipped Compose validation.\n'
fi

phase "Running controlled agent fixture check"
cat >"$TMP_DIR/janus-agent.toml" <<EOF
controller_endpoint = "http://127.0.0.1:9443"
http_controller_endpoint = "http://127.0.0.1:8080"
execution_mode = "passive"
cache_path = "$TMP_DIR/agent.sqlite3"
host_uuid_path = "$TMP_DIR/host-id"
report_path = "$TMP_DIR/report.html"
sarif_path = "$TMP_DIR/report.sarif"
scan_interval_seconds = 60
max_file_bytes = 10485760
max_binary_bytes = 10485760
command_signing_key = "linux-e2e-controlled-signing-key"
scan_roots = ["$ROOT_DIR/tests/testdata"]
exclude_dirs = []
network_targets = []
plugin_dirs = []
plugin_commands = []
intercept_mode = "disabled"

[active]
allowed_services = []
allowed_config_roots = []
backup_dir = "$TMP_DIR/backups"
EOF

AGENT_CHECK_LOG="$TMP_DIR/agent-check.log"
if (
  cd "$ROOT_DIR/agent"
  CARGO_TARGET_DIR="$TMP_DIR/cargo-target" cargo run --locked --bin janus-agent -- \
    --config "$TMP_DIR/janus-agent.toml" check "$ROOT_DIR/tests/testdata"
) >"$AGENT_CHECK_LOG" 2>&1; then
  AGENT_CHECK_STATUS=0
else
  AGENT_CHECK_STATUS=$?
fi
cat "$AGENT_CHECK_LOG"

case "$AGENT_CHECK_STATUS" in
  0)
    grep -q "Check passed" "$AGENT_CHECK_LOG" || {
      printf 'error: agent exited successfully without a check result\n' >&2
      exit 1
    }
    ;;
  1)
    grep -q "Rule ID:" "$AGENT_CHECK_LOG" || {
      printf 'error: agent check failed without reporting controlled fixture findings\n' >&2
      exit 1
    }
    printf 'Agent reported the expected controlled fixture findings.\n'
    ;;
  *)
    printf 'error: agent check exited with unexpected status %s\n' "$AGENT_CHECK_STATUS" >&2
    exit "$AGENT_CHECK_STATUS"
    ;;
esac

phase "Linux E2E smoke test passed"
