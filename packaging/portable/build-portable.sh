#!/usr/bin/env bash
# build-portable.sh — produce portable "copy and run" bundles (.tar.gz + .zip)
# for the Janus agent and/or server+UI. No dpkg/rpmbuild required.
#
# This is ADDITIVE to packaging/linux/build-release.sh (tarballs) and
# build-packages.sh (deb/rpm); it does not replace them. Each bundle ships a
# run.sh launcher + janus.env so deployment is "unpack, edit janus.env, run".
#
# Usage:
#   build-portable.sh [agent|server|all]      (default: all)
#
# Environment:
#   JANUS_PORTABLE_ARCHES   space/comma list of arches (default: host arch).
#                           Recognized: x86_64 (amd64), aarch64 (arm64).
#                           Host arch uses the already-built binaries; other
#                           arches are cross-built best-effort (Go always; the
#                           Rust agent only if its target + linker are present,
#                           otherwise that arch is skipped with a loud warning).
#
# Output: dist/portable/  (bundles + SHA256SUMS)
set -euo pipefail

component="${1:-all}"
case "$component" in agent | server | all) ;; *)
    echo "usage: $0 [agent|server|all]" >&2
    exit 2
    ;;
esac

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
pkg="$root/packaging/portable"
# shellcheck disable=SC1091
source "$root/VERSION.env"
release="${JANUS_VERSION}-${JANUS_BUILD_DATE}.${JANUS_BUILD_SEQUENCE}"
out="$root/dist/portable"
mkdir -p "$out"

host_arch="$(uname -m)"
arches_raw="${JANUS_PORTABLE_ARCHES:-$host_arch}"
# Normalize separators to spaces.
arches="$(printf '%s' "$arches_raw" | tr ',' ' ')"

warn() { printf '\033[1;33mWARNING: %s\033[0m\n' "$*" >&2; }
info() { printf '  %s\n' "$*"; }

# Map a requested arch to (canonical, GOARCH, rust-target).
arch_canon() { case "$1" in x86_64 | amd64) echo x86_64 ;; aarch64 | arm64) echo aarch64 ;; *) echo "" ;; esac; }
go_arch() { case "$1" in x86_64) echo amd64 ;; aarch64) echo arm64 ;; esac; }
rust_target() { case "$1" in x86_64) echo x86_64-unknown-linux-gnu ;; aarch64) echo aarch64-unknown-linux-gnu ;; esac; }

archive() { # bundle_parent bundle_name
    local parent="$1" name="$2"
    tar -C "$parent" -czf "$out/$name.tar.gz" "$name"
    if command -v zip >/dev/null 2>&1; then
        (cd "$parent" && zip -rq "$out/$name.zip" "$name")
    else
        warn "zip not installed; produced only $name.tar.gz (no .zip)."
    fi
    info "packaged $name"
}

# Resolve the agent binary for an arch into $1 (dest path). Returns non-zero if
# it cannot be produced (caller skips that arch).
resolve_agent_bin() { # canon dest
    local canon="$1" dest="$2"
    if [[ "$canon" == "$(arch_canon "$host_arch")" ]]; then
        local src="$root/agent/target/release/janus-agent"
        [[ -f "$src" ]] || { warn "host agent binary missing ($src). Run 'make portable-agent' or 'cd agent && cargo build --release'."; return 1; }
        install -m 0755 "$src" "$dest"
        return 0
    fi
    # Cross-build (best-effort).
    local tgt; tgt="$(rust_target "$canon")"
    if ! rustc --print target-list 2>/dev/null | grep -qx "$tgt" || ! rustup target list --installed 2>/dev/null | grep -qx "$tgt"; then
        warn "Rust target $tgt not installed; SKIPPING $canon agent. Add it with: rustup target add $tgt (plus a $canon C cross-linker for bundled SQLite)."
        return 1
    fi
    info "cross-building agent for $canon ($tgt)..."
    if ! (cd "$root/agent" && cargo build --locked --release --target "$tgt") >/dev/null 2>&1; then
        warn "cross-build of the agent for $canon FAILED (likely missing C cross-linker for bundled SQLite). SKIPPING $canon agent."
        return 1
    fi
    install -m 0755 "$root/agent/target/$tgt/release/janus-agent" "$dest"
}

# Resolve the server binary for an arch into $1. Go cross-compiles natively.
resolve_server_bin() { # canon dest
    local canon="$1" dest="$2"
    if [[ "$canon" == "$(arch_canon "$host_arch")" ]]; then
        local src="$root/server/janus-server"
        [[ -f "$src" ]] || { warn "host server binary missing ($src). Run 'make portable-server' or 'cd server && go build ./cmd/janus-server'."; return 1; }
        install -m 0755 "$src" "$dest"
        return 0
    fi
    info "cross-building server for $canon (GOARCH=$(go_arch "$canon"))..."
    if ! (cd "$root/server" && GOOS=linux GOARCH="$(go_arch "$canon")" go build -trimpath -o "$dest" ./cmd/janus-server) >/dev/null 2>&1; then
        warn "cross-build of the server for $canon FAILED. SKIPPING $canon server."
        return 1
    fi
}

build_agent() { # canon
    local canon="$1"
    local work name bdir
    work="$(mktemp -d)"; trap 'rm -rf "$work"' RETURN
    name="janus-agent-$release-linux-$canon"
    bdir="$work/$name"
    mkdir -p "$bdir/bin"
    resolve_agent_bin "$canon" "$bdir/bin/janus-agent" || return 0
    install -m 0644 "$pkg/janus-agent.toml.template" "$bdir/janus-agent.toml.template"
    install -m 0644 "$pkg/janus-agent.env.example" "$bdir/janus.env"
    install -m 0755 "$pkg/run-agent.sh" "$bdir/run.sh"
    install -m 0644 "$pkg/README-agent.md" "$bdir/README.md"
    install -m 0644 "$root/VERSION.env" "$bdir/VERSION.env"
    archive "$work" "$name"
}

build_server() { # canon
    local canon="$1"
    local work name bdir
    work="$(mktemp -d)"; trap 'rm -rf "$work"' RETURN
    name="janus-server-ui-$release-linux-$canon"
    bdir="$work/$name"
    mkdir -p "$bdir/bin" "$bdir/ui" "$bdir/policies"
    resolve_server_bin "$canon" "$bdir/bin/janus-server" || return 0
    [[ -d "$root/ui/dist" ]] || { warn "ui/dist missing; run 'make ui'. SKIPPING $canon server bundle."; return 0; }
    cp -a "$root/ui/dist/." "$bdir/ui/"
    cp -a "$root/policies/." "$bdir/policies/"
    install -m 0644 "$pkg/janus-server.env.example" "$bdir/janus.env"
    install -m 0755 "$pkg/run-server.sh" "$bdir/run.sh"
    install -m 0644 "$pkg/README-server-ui.md" "$bdir/README.md"
    install -m 0644 "$root/VERSION.env" "$bdir/VERSION.env"
    archive "$work" "$name"
}

echo "Building portable bundles ($component) for arch(es): $arches"
for a in $arches; do
    canon="$(arch_canon "$a")"
    if [[ -z "$canon" ]]; then
        warn "unrecognized arch '$a' (use x86_64 or aarch64); skipping."
        continue
    fi
    [[ "$component" == "agent" || "$component" == "all" ]] && build_agent "$canon"
    [[ "$component" == "server" || "$component" == "all" ]] && build_server "$canon"
done

# Refresh checksums over everything currently in the output dir.
(cd "$out" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%P\0' |
    sort -z | xargs -0r sha256sum >SHA256SUMS)
printf 'Portable artifacts written to %s\n' "$out"
ls -1 "$out"
