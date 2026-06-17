#!/usr/bin/env bash
# janus-llm.sh — non-interactive CLI for the Janus LLM analysis API (LLM-016).
#
# Wraps the stable REST endpoints documented in docs/API_REFERENCE.md so they can be
# driven from CI and automation. RBAC is enforced server-side from the bearer token;
# this script only carries it. Output is the server's raw JSON on stdout (pipe to `jq`).
#
# Environment:
#   JANUS_API_URL    Base URL of the server HTTP API (default http://127.0.0.1:8080)
#   JANUS_API_TOKEN  Bearer token (JWT) for an operator/admin session (required for
#                    mutating verbs: analyze, suggest, review, batch)
#
# Exit codes:
#   0  success (HTTP 2xx)
#   1  usage error
#   2  request failed (HTTP >= 400) — the JSON error body is printed to stderr
#   3  missing dependency (curl)
#
# Usage:
#   janus-llm.sh status
#   janus-llm.sh test
#   janus-llm.sh usage
#   janus-llm.sh analyze   <finding_id> [job_type]      # default job_type: false_positive_triage
#   janus-llm.sh suggest   <finding_id>                  # remediation_suggestion (requires suggest_remediation mode)
#   janus-llm.sh jobs      [limit] [offset]
#   janus-llm.sh job       <job_id>
#   janus-llm.sh verdict   <finding_id>
#   janus-llm.sh suggestion <finding_id>
#   janus-llm.sh review-verdict    <verdict_id>    approved|rejected [note]
#   janus-llm.sh review-suggestion <suggestion_id> approved|rejected [note]
set -euo pipefail

API_URL="${JANUS_API_URL:-http://127.0.0.1:8080}"
TOKEN="${JANUS_API_TOKEN:-}"

command -v curl >/dev/null 2>&1 || { echo "janus-llm: curl is required" >&2; exit 3; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-1}"; }

# req METHOD PATH [JSON_BODY] — perform the call, print body, map HTTP status to exit code.
req() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -w '\n%{http_code}' "${API_URL}${path}")
  [ -n "$TOKEN" ] && args+=(-H "Authorization: Bearer ${TOKEN}")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  local out code
  out="$(curl "${args[@]}")"
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  printf '%s\n' "$body"
  if [ "$code" -ge 400 ]; then
    echo "janus-llm: request failed (HTTP ${code})" >&2
    exit 2
  fi
}

# json_field NAME VALUE — emit a minimal JSON string field, escaping backslashes/quotes.
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

[ $# -ge 1 ] || usage 1
cmd="$1"; shift || true

case "$cmd" in
  status)  req GET  "/api/llm/status" ;;
  test)    req POST "/api/llm/test-connection" ;;
  usage)   req GET  "/api/llm/usage" ;;
  jobs)
    limit="${1:-50}"; offset="${2:-0}"
    req GET "/api/llm/jobs?limit=${limit}&offset=${offset}" ;;
  job)
    [ $# -ge 1 ] || usage 1
    req GET "/api/llm/jobs/$1" ;;
  verdict)
    [ $# -ge 1 ] || usage 1
    req GET "/api/llm/verdicts/$1" ;;
  suggestion)
    [ $# -ge 1 ] || usage 1
    req GET "/api/llm/suggestions/$1" ;;
  analyze)
    [ $# -ge 1 ] || usage 1
    fid="$(json_str "$1")"; jt="${2:-false_positive_triage}"
    req POST "/api/llm/analyze" "{\"finding_id\":\"${fid}\",\"job_type\":\"$(json_str "$jt")\"}" ;;
  suggest)
    [ $# -ge 1 ] || usage 1
    fid="$(json_str "$1")"
    req POST "/api/llm/analyze" "{\"finding_id\":\"${fid}\",\"job_type\":\"remediation_suggestion\"}" ;;
  review-verdict)
    [ $# -ge 2 ] || usage 1
    vid="$1"; decision="$(json_str "$2")"; note="$(json_str "${3:-}")"
    req POST "/api/llm/verdicts/${vid}/review" "{\"decision\":\"${decision}\",\"note\":\"${note}\"}" ;;
  review-suggestion)
    [ $# -ge 2 ] || usage 1
    sid="$1"; decision="$(json_str "$2")"; note="$(json_str "${3:-}")"
    req POST "/api/llm/suggestions/${sid}/review" "{\"decision\":\"${decision}\",\"note\":\"${note}\"}" ;;
  -h|--help|help) usage 0 ;;
  *) echo "janus-llm: unknown command '${cmd}'" >&2; usage 1 ;;
esac
