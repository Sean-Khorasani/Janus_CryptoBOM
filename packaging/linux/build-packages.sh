#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"

binary="$repo_root/agent/target/release/janus-agent"
output_dir="$repo_root/dist/packages"
version=""
release=""
format="all"
source_date_epoch="${SOURCE_DATE_EPOCH:-1704067200}"

usage() {
  cat <<'EOF'
Usage: packaging/linux/build-packages.sh [options]

Options:
  --binary PATH       Existing Linux release agent binary
  --output-dir PATH   Package output directory (default: dist/packages)
  --version VERSION   Package version (default: agent Cargo.toml version)
  --release RELEASE   RPM/Debian package release (default: VERSION.env build)
  --format FORMAT     all, deb, or rpm (default: all)
  --help              Show this help
EOF
}

fail() {
  printf 'build-packages.sh: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --binary) binary="${2:?missing value for --binary}"; shift 2 ;;
    --output-dir) output_dir="${2:?missing value for --output-dir}"; shift 2 ;;
    --version) version="${2:?missing value for --version}"; shift 2 ;;
    --release) release="${2:?missing value for --release}"; shift 2 ;;
    --format) format="${2:?missing value for --format}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

case "$format" in all|deb|rpm) ;; *) fail "format must be all, deb, or rpm" ;; esac
if [[ -f "$repo_root/VERSION.env" ]]; then
  # shellcheck disable=SC1091
  source "$repo_root/VERSION.env"
fi
release="${release:-${JANUS_BUILD_DATE:-1}.${JANUS_BUILD_SEQUENCE:-1}}"
[[ -x "$binary" ]] || fail "release agent binary is not executable: $binary"
binary="$(cd -- "$(dirname -- "$binary")" && pwd -P)/$(basename -- "$binary")"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH must be an integer"
[[ "$release" =~ ^[0-9]+([.][0-9]+)*$ ]] ||
  fail "release must contain only numeric dot-separated segments"

if [[ -z "$version" ]]; then
  version="${JANUS_VERSION:-}"
fi
if [[ -z "$version" ]]; then
  version="$(sed -n '/^\[package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' \
    "$repo_root/agent/Cargo.toml" | head -n 1)"
fi
[[ "$version" =~ ^[0-9]+([.][0-9]+)*([+~._-][A-Za-z0-9]+)*$ ]] ||
  fail "unsupported package version: $version"

config="$repo_root/agent/janus-agent.linux.toml"
unit="$repo_root/packaging/systemd/janus-agent.service"
tmpfiles="$repo_root/packaging/systemd/janus-agent.tmpfiles"
profiles="$repo_root/packaging/systemd/profiles"
for input in "$config" "$unit" "$tmpfiles" "$profiles/README.md" \
  "$profiles/runtime-discovery.conf" "$profiles/process-memory.conf" \
  "$profiles/plugin-cgroup.conf"; do
  [[ -f "$input" ]] || fail "required package input is missing: $input"
done

machine="$(uname -m)"
case "$machine" in
  x86_64) deb_arch="amd64"; rpm_arch="x86_64" ;;
  aarch64|arm64) deb_arch="arm64"; rpm_arch="aarch64" ;;
  *) fail "unsupported package architecture: $machine" ;;
esac

mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/janus-native-package.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

normalize_tree() {
  find "$1" -print0 | xargs -0r touch --no-dereference --date="@$source_date_epoch"
}

build_deb() {
  command -v dpkg-deb >/dev/null || fail "dpkg-deb is required to build .deb packages"
  command -v gzip >/dev/null || fail "gzip is required to build .deb packages"
  local root="$work_dir/deb-root"
  local package="$output_dir/janus-agent_${version}-${release}_${deb_arch}.deb"

  install -D -m 0755 "$binary" "$root/usr/bin/janus-agent"
  install -D -m 0640 "$config" "$root/etc/janus-agent/janus-agent.toml"
  install -D -m 0644 "$unit" "$root/usr/lib/systemd/system/janus-agent.service"
  install -D -m 0644 "$tmpfiles" "$root/usr/lib/tmpfiles.d/janus-agent.conf"
  install -d -m 0755 "$root/usr/share/janus-agent/systemd-profiles"
  install -m 0644 "$profiles"/* "$root/usr/share/janus-agent/systemd-profiles/"
  install -D -m 0644 "$script_dir/debian/copyright" \
    "$root/usr/share/doc/janus-agent/copyright"
  install -D -m 0644 "$script_dir/debian/lintian-overrides" \
    "$root/usr/share/lintian/overrides/janus-agent"
  sed "s/@VERSION@/${version}-${release}/g" "$script_dir/debian/changelog" |
    gzip -9n >"$root/usr/share/doc/janus-agent/changelog.Debian.gz"
  chmod 0644 "$root/usr/share/doc/janus-agent/changelog.Debian.gz"
  install -d -m 0755 "$root/DEBIAN"
  sed -e "s/@VERSION@/${version}-${release}/g" -e "s/@ARCH@/$deb_arch/g" \
    "$script_dir/debian/control" >"$root/DEBIAN/control"
  install -m 0644 "$script_dir/debian/conffiles" "$root/DEBIAN/conffiles"
  install -m 0755 "$script_dir/debian/postinst" "$root/DEBIAN/postinst"
  install -m 0755 "$script_dir/debian/prerm" "$root/DEBIAN/prerm"
  install -m 0755 "$script_dir/debian/postrm" "$root/DEBIAN/postrm"
  normalize_tree "$root"
  rm -f -- "$package"
  dpkg-deb --root-owner-group --uniform-compression --build "$root" "$package"
  printf '%s\n' "$package"
}

build_rpm() {
  command -v rpmbuild >/dev/null || fail "rpmbuild is required to build .rpm packages"
  local topdir="$work_dir/rpmbuild"
  local rpm_version="${version//-/_}"
  mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  cp "$script_dir/rpm/janus-agent.spec" "$topdir/SPECS/"
  SOURCE_DATE_EPOCH="$source_date_epoch" rpmbuild -bb \
    --define "_topdir $topdir" \
    --define "_buildhost reproducible.invalid" \
    --define "__strip /bin/true" \
    --define "_unitdir /usr/lib/systemd/system" \
    --define "_tmpfilesdir /usr/lib/tmpfiles.d" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "janus_version $rpm_version" \
    --define "janus_release $release" \
    --define "janus_arch $rpm_arch" \
    --define "janus_binary $binary" \
    --define "janus_config $config" \
    --define "janus_unit $unit" \
    --define "janus_tmpfiles $tmpfiles" \
    --define "janus_profiles $profiles" \
    "$topdir/SPECS/janus-agent.spec"
  find "$topdir/RPMS" -type f -name '*.rpm' -exec cp -p {} "$output_dir/" \;
  find "$output_dir" -maxdepth 1 -type f -name "janus-agent-${rpm_version}-${release}*.rpm" -print
}

export SOURCE_DATE_EPOCH="$source_date_epoch"
case "$format" in
  all) build_deb; build_rpm ;;
  deb) build_deb ;;
  rpm) build_rpm ;;
esac
(cd "$output_dir" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%P\0' |
  sort -z | xargs -0r sha256sum > SHA256SUMS)
