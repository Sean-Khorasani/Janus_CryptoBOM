#!/usr/bin/env bash
set -euo pipefail

unset CDPATH
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"

binary="${1:-${repo_root}/agent/target/release/janus-agent}"
evidence_dir="${JANUS_SYSTEMD_EVIDENCE_DIR:-${repo_root}/evidence/systemd-live}"
install_script="${repo_root}/scripts/install-agent-linux.sh"
uninstall_script="${repo_root}/scripts/uninstall-agent-linux.sh"
service="janus-agent.service"
installed_binary="/usr/bin/janus-agent"
config_dir="/etc/janus-agent"
config_file="${config_dir}/janus-agent.toml"
command_key_file="${config_dir}/command-signing-key"
state_dir="/var/lib/janus-agent"
unit_file="/usr/lib/systemd/system/${service}"
tmpfiles_file="/usr/lib/tmpfiles.d/janus-agent.conf"
config_marker="# systemd-live-preservation-marker"
state_marker="${state_dir}/systemd-live-preservation-marker"
claimed_host=false
work_dir=""

usage() {
  cat <<'EOF'
Run the Janus agent's real systemd lifecycle on a disposable Linux host.

Usage: sudo JANUS_SYSTEMD_LIVE_DISPOSABLE=1 \
  scripts/ci/verify-linux-systemd-live.sh [AGENT_BINARY]

The verifier installs to canonical host paths and creates/removes the
janusagent system account. It refuses to run unless the disposable-host guard
is set and no existing Janus installation or account is present.

Set JANUS_SYSTEMD_EVIDENCE_DIR to retain status and journal evidence.
EOF
}

fail() {
  printf 'verify-linux-systemd-live.sh: %s\n' "$*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "expected file: $1"
}

assert_dir() {
  [[ -d "$1" ]] || fail "expected directory: $1"
}

assert_absent() {
  [[ ! -e "$1" ]] || fail "expected path to be absent: $1"
}

assert_owner() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(stat -c '%U:%G' "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "expected owner $expected for $path, got $actual"
}

assert_mode() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(stat -c '%a' "$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "expected mode $expected for $path, got $actual"
}

wait_for_active() {
  local _
  for _ in {1..30}; do
    if systemctl is-active --quiet "$service"; then
      sleep 2
      systemctl is-active --quiet "$service" && return 0
    fi
    sleep 1
  done
  systemctl status --no-pager --full "$service" >&2 || true
  fail "$service did not remain active"
}

wait_for_file() {
  local path="$1"
  local _
  for _ in {1..30}; do
    [[ -s "$path" ]] && return 0
    sleep 1
  done
  fail "service did not create non-empty state file: $path"
}

main_pid() {
  systemctl show --property=MainPID --value "$service"
}

assert_non_root_service() {
  local pid expected_uid runtime_uid unit_user credential_path
  pid="$(main_pid)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail "invalid MainPID: $pid"

  unit_user="$(systemctl show --property=User --value "$service")"
  [[ "$unit_user" == "janusagent" ]] ||
    fail "expected systemd User=janusagent, got $unit_user"

  expected_uid="$(id -u janusagent)"
  runtime_uid="$(awk '/^Uid:/ { print $2; exit }' "/proc/${pid}/status")"
  [[ "$runtime_uid" == "$expected_uid" ]] ||
    fail "service PID $pid runs as UID $runtime_uid, expected $expected_uid"
  [[ "$runtime_uid" != "0" ]] || fail "service PID $pid runs as root"
  credential_path="$(
    tr '\0' '\n' <"/proc/${pid}/environ" |
      sed -n 's/^JANUS_COMMAND_SIGNING_KEY_FILE=//p'
  )"
  [[ "$credential_path" == /run/credentials/*/command-signing-key ]] ||
    fail "service PID $pid does not use a private systemd command-key credential"
  [[ -s "$credential_path" ]] ||
    fail "service PID $pid command-key credential is missing or empty"
}

capture_evidence() {
  mkdir -p "$evidence_dir"
  {
    printf 'captured_at=%s\n' "$(date --utc --iso-8601=seconds)"
    printf 'systemd_state=%s\n' "$(systemctl is-system-running 2>&1 || true)"
    systemctl show "$service" 2>&1 || true
  } >"${evidence_dir}/systemd-show.log"
  systemctl status --no-pager --full "$service" \
    >"${evidence_dir}/systemd-status.log" 2>&1 || true
  journalctl --no-pager --unit "$service" \
    >"${evidence_dir}/systemd-journal.log" 2>&1 || true
}

record_stage() {
  local stage="$1"
  local active enabled pid runtime_uid unit_user
  active="$(systemctl is-active "$service" 2>&1 || true)"
  enabled="$(systemctl is-enabled "$service" 2>&1 || true)"
  pid="$(main_pid 2>/dev/null || true)"
  unit_user="$(systemctl show --property=User --value "$service" 2>/dev/null || true)"
  runtime_uid=""
  if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/${pid}/status" ]]; then
    runtime_uid="$(awk '/^Uid:/ { print $2; exit }' "/proc/${pid}/status")"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date --utc --iso-8601=seconds)" "$stage" "$active" "$enabled" \
    "$pid" "$unit_user" "$runtime_uid" >>"${evidence_dir}/lifecycle.tsv"
  systemctl show "$service" >"${evidence_dir}/${stage}-show.log" 2>&1 || true
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  capture_evidence
  if [[ "$claimed_host" == true ]]; then
    "$uninstall_script" --purge --daemon-reload >/dev/null 2>&1 || true
  fi
  [[ -z "$work_dir" ]] || rm -rf -- "$work_dir"
  exit "$status"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ "${JANUS_SYSTEMD_LIVE_DISPOSABLE:-}" == "1" ]] ||
  fail "set JANUS_SYSTEMD_LIVE_DISPOSABLE=1 only on a disposable host"
[[ "$EUID" -eq 0 ]] || fail "live systemd verification requires root"
[[ -x "$binary" ]] || fail "agent binary is not executable: $binary"
[[ -x "$install_script" ]] || fail "installer is not executable: $install_script"
[[ -x "$uninstall_script" ]] || fail "uninstaller is not executable: $uninstall_script"
command -v systemctl >/dev/null || fail "systemctl is required"
command -v journalctl >/dev/null || fail "journalctl is required"
[[ "$(cat /proc/1/comm)" == "systemd" ]] ||
  fail "systemd must be PID 1 in the disposable environment"
[[ "$(systemctl show --property=Version --value 2>/dev/null)" != "" ]] ||
  fail "a running systemd system manager is required"

id janusagent >/dev/null 2>&1 && fail "janusagent account already exists"
for path in \
  "$installed_binary" "$config_dir" "$state_dir" "$unit_file" "$tmpfiles_file"; do
  assert_absent "$path"
done

mkdir -p "$evidence_dir"
: >"${evidence_dir}/lifecycle.tsv"
printf 'timestamp\tstage\tactive\tenabled\tmain_pid\tunit_user\truntime_uid\n' \
  >>"${evidence_dir}/lifecycle.tsv"
work_dir="$(mktemp -d)"
trap cleanup EXIT
claimed_host=true

cp -- "$binary" "${work_dir}/janus-agent-v1"
cp -- "$binary" "${work_dir}/janus-agent-v2"
printf '\nJANUS_SYSTEMD_LIVE_UPGRADE_V2\n' >>"${work_dir}/janus-agent-v2"
chmod 0755 "${work_dir}/janus-agent-v1" "${work_dir}/janus-agent-v2"
v1_hash="$(sha256sum "${work_dir}/janus-agent-v1" | awk '{ print $1 }')"
v2_hash="$(sha256sum "${work_dir}/janus-agent-v2" | awk '{ print $1 }')"
[[ "$v1_hash" != "$v2_hash" ]] || fail "upgrade fixtures must differ"

printf 'Installing the service and provisioning a generated command key\n'
dd if=/dev/urandom bs=32 count=1 status=none | base64 >"${work_dir}/command-signing-key"
"$install_script" --binary "${work_dir}/janus-agent-v1" \
  --command-signing-key-file "${work_dir}/command-signing-key" \
  --daemon-reload --enable
command_key_hash="$(sha256sum "$command_key_file" | awk '{ print $1 }')"
runuser -u janusagent -- test -r "$command_key_file" ||
  fail "janusagent cannot read the generated command-key file"
systemctl start "$service"
wait_for_active
systemctl is-enabled --quiet "$service" || fail "$service is not enabled"
assert_non_root_service
assert_file "$installed_binary"
assert_file "$config_file"
assert_dir "$state_dir"
assert_owner "root:janusagent" "$config_file"
assert_owner "janusagent:janusagent" "$state_dir"
assert_mode 640 "$config_file"
assert_mode 640 "$command_key_file"
assert_mode 750 "$config_dir"
assert_mode 700 "$state_dir"
runuser -u janusagent -- test -r "$config_file" ||
  fail "janusagent cannot read its configuration"
wait_for_file "${state_dir}/agent.db"
wait_for_file "${state_dir}/host-id"
printf '%s\n' "$config_marker" >>"$config_file"
runuser -u janusagent -- touch "$state_marker"
first_pid="$(main_pid)"
record_stage installed

printf 'Restarting the service\n'
systemctl restart "$service"
wait_for_active
assert_non_root_service
restart_pid="$(main_pid)"
[[ "$restart_pid" != "$first_pid" ]] ||
  fail "restart did not replace service PID $first_pid"
record_stage restarted

printf 'Upgrading the running installation\n'
"$install_script" --binary "${work_dir}/janus-agent-v2" --daemon-reload
[[ "$(sha256sum "$installed_binary" | awk '{ print $1 }')" == "$v2_hash" ]] ||
  fail "upgrade did not replace the installed binary"
grep -Fxq "$config_marker" "$config_file" ||
  fail "upgrade replaced operator configuration"
assert_file "$state_marker"
[[ "$(sha256sum "$command_key_file" | awk '{ print $1 }')" == "$command_key_hash" ]] ||
  fail "upgrade replaced the generated command-key file"
systemctl restart "$service"
wait_for_active
assert_non_root_service
upgrade_pid="$(main_pid)"
[[ "$upgrade_pid" != "$restart_pid" ]] ||
  fail "upgrade restart did not replace service PID $restart_pid"
grep -Fxq "$config_marker" "$config_file" ||
  fail "upgrade restart lost operator configuration"
assert_file "$state_marker"
record_stage upgraded

printf 'Uninstalling while preserving configuration and state\n'
"$uninstall_script" --daemon-reload
systemctl is-active --quiet "$service" &&
  fail "$service remained active after uninstall"
systemctl is-enabled --quiet "$service" &&
  fail "$service remained enabled after uninstall"
assert_absent "$installed_binary"
assert_absent "$unit_file"
assert_absent "$tmpfiles_file"
grep -Fxq "$config_marker" "$config_file" ||
  fail "default uninstall removed operator configuration"
assert_file "$state_marker"
[[ "$(sha256sum "$command_key_file" | awk '{ print $1 }')" == "$command_key_hash" ]] ||
  fail "default uninstall removed or replaced the generated command-key file"
id janusagent >/dev/null 2>&1 ||
  fail "default uninstall removed the service account"
record_stage uninstalled

printf 'Reinstalling preserved configuration and state\n'
"$install_script" --binary "${work_dir}/janus-agent-v2" \
  --daemon-reload --enable --start
wait_for_active
assert_non_root_service
grep -Fxq "$config_marker" "$config_file" ||
  fail "reinstall replaced preserved operator configuration"
assert_file "$state_marker"
[[ "$(sha256sum "$command_key_file" | awk '{ print $1 }')" == "$command_key_hash" ]] ||
  fail "reinstall replaced the generated command-key file"
record_stage reinstalled

printf 'Purging the installation\n'
"$uninstall_script" --purge --daemon-reload
systemctl is-active --quiet "$service" &&
  fail "$service remained active after purge"
assert_absent "$installed_binary"
assert_absent "$unit_file"
assert_absent "$tmpfiles_file"
assert_absent "$config_dir"
assert_absent "$state_dir"
assert_absent "$command_key_file"
id janusagent >/dev/null 2>&1 &&
  fail "purge left the janusagent account"
record_stage purged
claimed_host=false

capture_evidence
printf 'Live systemd install/start/restart/upgrade/uninstall/purge verification passed.\n'
