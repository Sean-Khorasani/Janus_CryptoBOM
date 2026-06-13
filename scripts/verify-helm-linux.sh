#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chart="$repo_root/deploy/helm/janus"
failures=0

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  if [[ -f "$chart/$1" ]]; then
    pass "$1 exists"
  else
    fail "$1 is missing"
  fi
}

require_text() {
  local file="$1"
  local pattern="$2"
  local description="$3"

  if grep -Eq "$pattern" "$chart/$file"; then
    pass "$description"
  else
    fail "$description"
  fi
}

printf 'Static Helm Linux deployment checks\n'
for file in \
  Chart.yaml \
  values.yaml \
  templates/configmap.yaml \
  templates/deployment-agent.yaml \
  templates/deployment-server.yaml \
  templates/postgres-statefulset.yaml \
  templates/service.yaml \
  templates/secrets.yaml; do
  require_file "$file"
done

require_text values.yaml '^  grpcPort: 9443$' 'server gRPC port defaults to 9443'
require_text templates/service.yaml 'targetPort: grpc' 'service targets the named gRPC container port'
require_text templates/configmap.yaml 'controller_endpoint = "http://.*service\.grpcPort' 'agent uses the in-cluster gRPC service port'
require_text templates/configmap.yaml 'http_controller_endpoint = "http://.*service\.httpPort' 'agent uses the in-cluster HTTP service port'
require_text templates/deployment-agent.yaml 'JANUS_COMMAND_SIGNING_KEY_FILE' 'agent reads the signing key from a mounted file'
require_text templates/deployment-agent.yaml 'mountPath: /data/janus-agent\.toml' 'agent configuration is mounted at the image default path'
require_text templates/deployment-agent.yaml 'mountPath: /data$' 'agent has writable state storage'
require_text templates/deployment-agent.yaml 'readOnly: true' 'host filesystem mount is read-only'
require_text templates/deployment-agent.yaml 'type: Directory' 'host filesystem mount requires an existing Linux root directory'
require_text values.yaml 'path: /api/health' 'server probes use the unauthenticated health endpoint'
require_text templates/deployment-server.yaml 'workingDir: /data' 'server runs from writable data working directory'
require_text templates/deployment-server.yaml 'cp -R /policies/\.' 'packaged policies are initialized into writable storage'
require_text templates/deployment-server.yaml 'mountPath: /tmp' 'server has writable temporary storage'
require_text templates/postgres-statefulset.yaml 'if not \.Values\.postgresql\.persistence\.enabled' 'PostgreSQL supports ephemeral Linux storage'
require_text templates/postgres-statefulset.yaml 'if \.Values\.postgresql\.persistence\.enabled' 'PostgreSQL PVC creation honors persistence.enabled'

if ((failures > 0)); then
  printf '\nStatic validation failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

if ! command -v helm >/dev/null 2>&1; then
  printf '\nHelm is not installed; static checks passed and helm lint/template were skipped.\n'
  exit 0
fi

printf '\nHelm lint and render checks\n'
helm lint "$chart"
helm template janus "$chart" >/dev/null
helm template janus "$chart" --set agent.enabled=false >/dev/null
helm template janus "$chart" --set postgresql.persistence.enabled=false >/dev/null
helm template janus "$chart" \
  --set postgresql.enabled=false \
  --set externalDatabase.host=postgres.example.invalid >/dev/null
pass 'helm lint and template variants passed'
