#!/usr/bin/env bash
set -euo pipefail

# Fails on an unpinned protoc, descriptor drift, nondeterministic descriptor
# output, or semantic drift in the repository-specific Rust and Go bindings.
# This is the protobuf drift gate; it needs only protoc, Python 3, and cmp.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"

actual_version="$(protoc --version | awk '{print $2}')"
if [[ "$actual_version" != "$PROTOC_VERSION" ]]; then
  printf 'error: protoc %s required, found %s\n' "$PROTOC_VERSION" "$actual_version" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cd "$repo_root"
for attempt in 1 2; do
  protoc \
    --proto_path=. \
    --descriptor_set_out="$tmp_dir/janus-$attempt.pb" \
    proto/janus.proto
done

cmp "$tmp_dir/janus-1.pb" "$tmp_dir/janus-2.pb"
sha256sum "$tmp_dir/janus-1.pb" |
  awk '{print $1 "  proto/janus.proto"}' >"$tmp_dir/janus.descriptor.sha256"

if ! cmp -s proto/janus.descriptor.sha256 "$tmp_dir/janus.descriptor.sha256"; then
  printf 'error: protobuf descriptor drift; run scripts/proto/generate.sh\n' >&2
  diff -u proto/janus.descriptor.sha256 "$tmp_dir/janus.descriptor.sha256" || true
  exit 1
fi

python3 scripts/proto/verify_bindings.py
printf 'protobuf descriptor and bindings match proto/janus.proto (protoc %s)\n' "$PROTOC_VERSION"
