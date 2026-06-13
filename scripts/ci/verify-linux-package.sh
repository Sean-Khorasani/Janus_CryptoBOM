#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
agent_binary="${1:-$repo_root/agent/target/release/janus-agent}"
stage="$(mktemp -d "${TMPDIR:-/tmp}/janus-package-ci.XXXXXX")"
signing_key="$stage/source-command-signing-key"
printf '%s\n' 'staged-package-command-signing-key' >"$signing_key"

cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

assert_file_mode() {
  local expected="$1"
  local path="$2"
  local actual

  [[ -f "$path" ]] || fail "missing staged file: $path"
  actual="$(stat -c '%a' "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "unexpected mode for $path: expected $expected, got $actual"
}

[[ "$(uname -s)" == Linux ]] || fail "package verification requires Linux"
[[ -x "$agent_binary" ]] || fail "release agent binary is not executable: $agent_binary"

printf 'Installing staged package\n'
"$repo_root/scripts/install-agent-linux.sh" --destdir "$stage" --binary "$agent_binary" \
  --command-signing-key-file "$signing_key"

assert_file_mode 755 "$stage/usr/bin/janus-agent"
assert_file_mode 640 "$stage/etc/janus-agent/janus-agent.toml"
assert_file_mode 640 "$stage/etc/janus-agent/command-signing-key"
assert_file_mode 644 "$stage/usr/lib/systemd/system/janus-agent.service"
assert_file_mode 644 "$stage/usr/lib/tmpfiles.d/janus-agent.conf"
[[ "$(stat -c '%a' "$stage/var/lib/janus-agent")" == 700 ]] ||
  fail "staged state directory is not mode 700"
assert_file_mode 600 "$stage/var/lib/janus-agent/cache-protection-key"

printf 'Verifying reinstall preserves operator configuration\n'
printf '\n# package-ci-preservation-marker\n' >>"$stage/etc/janus-agent/janus-agent.toml"
"$repo_root/scripts/install-agent-linux.sh" --destdir "$stage" --binary "$agent_binary"
grep -q '^# package-ci-preservation-marker$' "$stage/etc/janus-agent/janus-agent.toml" ||
  fail "reinstall replaced operator configuration"

printf 'Verifying systemd unit syntax and hardening\n'
verify_unit="$stage/janus-agent-verify.service"
sed "s|^ExecStart=/usr/bin/janus-agent|ExecStart=$stage/usr/bin/janus-agent|" \
  "$stage/usr/lib/systemd/system/janus-agent.service" >"$verify_unit"
systemd-analyze verify "$verify_unit"
# systemd-analyze encodes the threshold in tenths, so 40 means exposure 4.0.
systemd-analyze security --offline=yes --threshold=40 "$verify_unit"
grep -q '^NoNewPrivileges=true$' "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "systemd unit does not enable NoNewPrivileges"
grep -q '^ProtectSystem=strict$' "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "systemd unit does not enable ProtectSystem=strict"
grep -q '^CapabilityBoundingSet=$' "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "passive systemd unit does not drop all capabilities"
grep -q '^ProtectProc=invisible$' "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "passive systemd unit exposes the host process tree"
grep -q '^RestrictNamespaces=true$' "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "passive systemd unit allows namespace creation"
grep -q '^LoadCredential=command-signing-key:' "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "systemd unit does not load the command signing key as a credential"
grep -q '^Environment=JANUS_COMMAND_SIGNING_KEY_FILE=%d/command-signing-key$' \
  "$stage/usr/lib/systemd/system/janus-agent.service" ||
  fail "systemd unit does not direct the agent to its private credential"

printf 'Verifying uninstall preserves state by default\n'
"$repo_root/scripts/uninstall-agent-linux.sh" --destdir "$stage"
[[ ! -e "$stage/usr/bin/janus-agent" ]] || fail "uninstall left the agent binary"
[[ -f "$stage/etc/janus-agent/janus-agent.toml" ]] ||
  fail "default uninstall removed configuration"
[[ -d "$stage/var/lib/janus-agent" ]] || fail "default uninstall removed state"

printf 'Verifying purge removes configuration and state\n'
"$repo_root/scripts/install-agent-linux.sh" --destdir "$stage" --binary "$agent_binary"
"$repo_root/scripts/uninstall-agent-linux.sh" --destdir "$stage" --purge
[[ ! -e "$stage/etc/janus-agent" ]] || fail "purge left configuration"
[[ ! -e "$stage/var/lib/janus-agent" ]] || fail "purge left state"

printf 'Linux staged package and systemd verification passed.\n'
