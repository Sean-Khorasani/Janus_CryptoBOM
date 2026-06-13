#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
builder="$repo_root/packaging/linux/build-packages.sh"
agent_binary="${1:-$repo_root/agent/target/release/janus-agent}"
source_date_epoch="${SOURCE_DATE_EPOCH:-1704067200}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/janus-native-package-ci.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

fail() {
  printf 'verify-linux-native-packages.sh: %s\n' "$*" >&2
  exit 1
}

assert_file_mode() {
  local expected="$1"
  local path="$2"
  local actual
  [[ -f "$path" ]] || fail "missing package payload file: $path"
  actual="$(stat -c '%a' "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "unexpected mode for $path: expected $expected, got $actual"
}

assert_contains() {
  local needle="$1"
  local path="$2"
  grep -Fq -- "$needle" "$path" ||
    fail "$path does not contain required text: $needle"
}

[[ "$(uname -s)" == Linux ]] || fail "native package verification requires Linux"
[[ -x "$builder" ]] || fail "package builder is not executable: $builder"
[[ -x "$agent_binary" ]] || fail "release agent binary is not executable: $agent_binary"
for command in dpkg-deb sha256sum; do
  command -v "$command" >/dev/null || fail "$command is required"
done

printf 'Building native packages twice to verify reproducibility\n'
build_format="deb"
if command -v rpm >/dev/null && command -v rpmbuild >/dev/null; then
  build_format="all"
fi
for run in first second; do
  SOURCE_DATE_EPOCH="$source_date_epoch" "$builder" \
    --binary "$agent_binary" --output-dir "$work_dir/$run" --format "$build_format"
done

first_deb="$(find "$work_dir/first" -maxdepth 1 -type f -name '*.deb' -print -quit)"
second_deb="$(find "$work_dir/second" -maxdepth 1 -type f -name '*.deb' -print -quit)"
[[ -n "$first_deb" && -n "$second_deb" ]] || fail "Debian package was not produced"
[[ "$(sha256sum "$first_deb" | cut -d ' ' -f 1)" == \
   "$(sha256sum "$second_deb" | cut -d ' ' -f 1)" ]] ||
  fail "Debian package is not reproducible"

printf 'Inspecting Debian metadata, scripts, payload, and modes\n'
deb_root="$work_dir/deb-root"
deb_control="$work_dir/deb-control"
dpkg-deb --extract "$first_deb" "$deb_root"
dpkg-deb --control "$first_deb" "$deb_control"
[[ "$(dpkg-deb --field "$first_deb" Package)" == janus-agent ]] ||
  fail "unexpected Debian package name"
[[ "$(dpkg-deb --field "$first_deb" Architecture)" != all ]] ||
  fail "Debian package must be architecture-specific"
assert_file_mode 755 "$deb_root/usr/bin/janus-agent"
assert_file_mode 640 "$deb_root/etc/janus-agent/janus-agent.toml"
assert_file_mode 644 "$deb_root/usr/lib/systemd/system/janus-agent.service"
assert_file_mode 644 "$deb_root/usr/lib/tmpfiles.d/janus-agent.conf"
for profile in README.md runtime-discovery.conf process-memory.conf plugin-cgroup.conf; do
  assert_file_mode 644 "$deb_root/usr/share/janus-agent/systemd-profiles/$profile"
done
cmp -s "$agent_binary" "$deb_root/usr/bin/janus-agent" ||
  fail "Debian package modified the release agent binary"
[[ "$(cat "$deb_control/conffiles")" == /etc/janus-agent/janus-agent.toml ]] ||
  fail "Debian configuration is not declared as a conffile"
assert_contains '= remove ]' "$deb_control/prerm"
assert_contains '= purge ]' "$deb_control/postrm"
assert_contains 'systemctl preset janus-agent.service' "$deb_control/postinst"
if command -v lintian >/dev/null; then
  lintian --fail-on error,warning "$first_deb"
fi

if command -v rpm >/dev/null && command -v rpmbuild >/dev/null; then
  printf 'Inspecting RPM metadata, scripts, payload, and reproducibility\n'
  first_rpm="$(find "$work_dir/first" -maxdepth 1 -type f -name '*.rpm' -print -quit)"
  second_rpm="$(find "$work_dir/second" -maxdepth 1 -type f -name '*.rpm' -print -quit)"
  [[ -n "$first_rpm" && -n "$second_rpm" ]] || fail "RPM package was not produced"
  [[ "$(sha256sum "$first_rpm" | cut -d ' ' -f 1)" == \
     "$(sha256sum "$second_rpm" | cut -d ' ' -f 1)" ]] ||
    fail "RPM package is not reproducible"
  [[ "$(rpm -qp --queryformat '%{NAME}' "$first_rpm")" == janus-agent ]] ||
    fail "unexpected RPM package name"
  rpm -qpl "$first_rpm" >"$work_dir/rpm-files"
  rpm -qp --scripts "$first_rpm" >"$work_dir/rpm-scripts"
  rpm -qp --configfiles "$first_rpm" >"$work_dir/rpm-configfiles"
  rpm -qp --dump "$first_rpm" >"$work_dir/rpm-dump"
  for path in /usr/bin/janus-agent /etc/janus-agent/janus-agent.toml \
    /usr/lib/systemd/system/janus-agent.service \
    /usr/lib/tmpfiles.d/janus-agent.conf \
    /usr/share/janus-agent/systemd-profiles/runtime-discovery.conf; do
    assert_contains "$path" "$work_dir/rpm-files"
  done
  assert_contains '/etc/janus-agent/janus-agent.toml' "$work_dir/rpm-configfiles"
  assert_contains 'systemctl preset janus-agent.service' "$work_dir/rpm-scripts"
  assert_contains 'systemctl disable --now janus-agent.service' "$work_dir/rpm-scripts"
  rpm_agent_digest="$(awk '$1 == "/usr/bin/janus-agent" { print $4 }' "$work_dir/rpm-dump")"
  [[ "$rpm_agent_digest" == "$(sha256sum "$agent_binary" | cut -d ' ' -f 1)" ]] ||
    fail "RPM package modified the release agent binary"
  [[ "$(awk '$1 == "/usr/bin/janus-agent" { print $5 }' "$work_dir/rpm-dump")" == 0100755 ]] ||
    fail "RPM agent binary mode is not 0755"
  [[ "$(awk '$1 == "/etc/janus-agent/janus-agent.toml" { print $5 }' "$work_dir/rpm-dump")" == 0100640 ]] ||
    fail "RPM configuration mode is not 0640"
  for path in /usr/lib/systemd/system/janus-agent.service \
    /usr/lib/tmpfiles.d/janus-agent.conf \
    /usr/share/janus-agent/systemd-profiles/README.md \
    /usr/share/janus-agent/systemd-profiles/runtime-discovery.conf \
    /usr/share/janus-agent/systemd-profiles/process-memory.conf \
    /usr/share/janus-agent/systemd-profiles/plugin-cgroup.conf; do
    [[ "$(awk -v path="$path" '$1 == path { print $5 }' "$work_dir/rpm-dump")" == 0100644 ]] ||
      fail "RPM asset mode is not 0644: $path"
  done
else
  printf 'rpmbuild/rpm unavailable; statically validating RPM spec\n'
  spec="$repo_root/packaging/linux/rpm/janus-agent.spec"
  assert_contains '%config(noreplace) %{_sysconfdir}/janus-agent/janus-agent.toml' "$spec"
  assert_contains '%preun' "$spec"
  assert_contains 'systemctl disable --now janus-agent.service' "$spec"
fi

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  printf 'Running Debian install, upgrade, remove, and purge lifecycle in Ubuntu\n'
  lifecycle="$work_dir/lifecycle"
  mkdir -p "$lifecycle"
  cp "$first_deb" "$lifecycle/janus-agent.deb"
  cat >"$lifecycle/verify.sh" <<'EOF'
#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install --no-install-recommends --yes /packages/janus-agent.deb
test -x /usr/bin/janus-agent
test -f /etc/janus-agent/janus-agent.toml
test -f /usr/lib/systemd/system/janus-agent.service
getent passwd janusagent >/dev/null
test "$(stat -c '%U:%G:%a' /etc/janus-agent)" = root:janusagent:750
test "$(stat -c '%U:%G:%a' /etc/janus-agent/janus-agent.toml)" = root:janusagent:640
test "$(stat -c '%U:%G:%a' /var/lib/janus-agent)" = janusagent:janusagent:700
mkdir -p /var/lib/janus-agent
printf 'state\n' >/var/lib/janus-agent/lifecycle-state
printf '\n# native-package-upgrade-marker\n' >>/etc/janus-agent/janus-agent.toml

dpkg --install /packages/janus-agent.deb
grep -q '^# native-package-upgrade-marker$' /etc/janus-agent/janus-agent.toml
test -f /var/lib/janus-agent/lifecycle-state

dpkg --remove janus-agent
test ! -e /usr/bin/janus-agent
test -f /etc/janus-agent/janus-agent.toml
test -f /var/lib/janus-agent/lifecycle-state

dpkg --install /packages/janus-agent.deb
grep -q '^# native-package-upgrade-marker$' /etc/janus-agent/janus-agent.toml
dpkg --purge janus-agent
test ! -e /etc/janus-agent
test ! -e /var/lib/janus-agent
! getent passwd janusagent >/dev/null
EOF
  chmod +x "$lifecycle/verify.sh"
  docker run --rm --volume "$lifecycle:/packages:ro" ubuntu:24.04 \
    /packages/verify.sh
else
  printf 'Docker unavailable; skipped isolated Ubuntu package-manager lifecycle\n'
fi

printf 'Native Debian/RPM package verification passed.\n'
