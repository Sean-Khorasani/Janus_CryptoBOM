#!/usr/bin/env bash
set -euo pipefail

# Regenerates the canonical descriptor checksum from proto/janus.proto.
#
# The checked-in Rust and Go bindings use repository-specific APIs that stock
# generators cannot reproduce without disruptive API changes. verify.sh
# therefore validates those bindings semantically against this descriptor and
# the canonical schema. Run this script after an intentional schema change,
# review all binding changes, then run verify.sh.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"

actual_version="$(protoc --version | awk '{print $2}')"
if [[ "$actual_version" != "$PROTOC_VERSION" ]]; then
  printf 'error: protoc %s required, found %s\n' "$PROTOC_VERSION" "$actual_version" >&2
  exit 1
fi

tmp_descriptor="$(mktemp)"
trap 'rm -f "$tmp_descriptor"' EXIT

cd "$repo_root"
protoc --proto_path=. --descriptor_set_out="$tmp_descriptor" proto/janus.proto
sha256sum "$tmp_descriptor" | awk '{print $1 "  proto/janus.proto"}' >proto/janus.descriptor.sha256

python3 scripts/proto/verify_bindings.py
printf 'generated proto/janus.descriptor.sha256 with protoc %s\n' "$PROTOC_VERSION"
