#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s OUTPUT_DIR [ARTIFACT ...]\n' "${0##*/}" >&2
}

[[ $# -ge 1 ]] || {
  usage
  exit 2
}

output_dir="$1"
shift
mkdir -p "$output_dir"

{
  printf 'evidence_format=janus-linux-release-evidence-v1\n'
  printf 'generated_at=%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  printf 'commit=%s\n' "$(git rev-parse HEAD)"
  printf 'ref=%s\n' "${GITHUB_REF:-local}"
  printf 'workflow_run_id=%s\n' "${GITHUB_RUN_ID:-local}"
  printf 'runner_os=%s\n' "${RUNNER_OS:-$(uname -s)}"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'support_tier=supported\n'
  printf 'platform=ubuntu-24.04-x86_64-glibc\n'
} >"$output_dir/manifest.txt"

{
  uname -a
  go version
  rustc --version
  cargo --version
  node --version
  npm --version
  docker --version
} >"$output_dir/toolchain.txt"

if (($# > 0)); then
  sha256sum "$@" >"$output_dir/artifact-sha256.txt"
fi

git status --short >"$output_dir/worktree-status.txt"
printf 'Linux release evidence metadata collected in %s\n' "$output_dir"
