#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "$root/VERSION.env"
arch="$(uname -m)"
case "$arch" in x86_64|aarch64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
release="${JANUS_VERSION}-${JANUS_BUILD_DATE}.${JANUS_BUILD_SEQUENCE}"
out="$root/dist/packages"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

server="$work/janus-server-ui-$release-linux-$arch"
mkdir -p "$server/bin" "$server/ui" "$server/policies"
install -m 0755 "$root/server/janus-server" "$server/bin/janus-server"
cp -a "$root/ui/dist/." "$server/ui/"
cp -a "$root/policies/." "$server/policies/"
install -m 0644 "$root/VERSION.env" "$server/VERSION.env"
install -m 0644 "$root/packaging/release/README-server-ui.md" "$server/README.md"
tar -C "$work" -czf "$out/$(basename "$server").tar.gz" "$(basename "$server")"

agent="$work/janus-agent-$release-linux-$arch"
mkdir -p "$agent/bin"
install -m 0755 "$root/agent/target/release/janus-agent" "$agent/bin/janus-agent"
install -m 0644 "$root/agent/janus-agent.linux.toml" "$agent/janus-agent.toml"
install -m 0644 "$root/VERSION.env" "$agent/VERSION.env"
install -m 0644 "$root/packaging/release/README-agent.md" "$agent/README.md"
tar -C "$work" -czf "$out/$(basename "$agent").tar.gz" "$(basename "$agent")"
(cd "$out" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%P\0' |
  sort -z | xargs -0r sha256sum > SHA256SUMS)
printf 'Release artifacts written to %s\n' "$out"
