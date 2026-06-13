#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
agent_binary="${1:-$repo_root/agent/target/release/janus-agent}"
evidence_dir="${2:-$(mktemp -d "${TMPDIR:-/tmp}/janus-linux-discovery-evidence.XXXXXX")}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/janus-linux-discovery.XXXXXX")"
fixture_root="$work_dir/scanned-root"
state_dir="$work_dir/state"

cleanup() {
  if [[ -n "${memory_holder_pid:-}" ]]; then
    kill "$memory_holder_pid" 2>/dev/null || true
    wait "$memory_holder_pid" 2>/dev/null || true
  fi
  if [[ "${JANUS_KEEP_DISCOVERY_WORK:-0}" == 1 ]]; then
    printf 'Retained Linux discovery work directory: %s\n' "$work_dir" >&2
    return
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

run_and_capture_status() {
  local status_file="$1"
  shift

  set +e
  "$@"
  local status=$?
  set -e
  printf '%s\n' "$status" >"$status_file"
}

combine_trace() {
  local destination="$1"
  local part
  local found=false

  : >"$destination"
  for part in "$destination".*; do
    [[ -f "$part" ]] || continue
    found=true
    cat "$part" >>"$destination"
    rm -f -- "$part"
  done
  [[ "$found" == true ]] || fail "strace produced no trace files for $destination"
}

toml_quote() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

snapshot_tree() {
  local root="$1"
  local destination="$2"

  python3 - "$root" "$destination" <<'PY'
import hashlib
import os
import stat
import sys

root, destination = sys.argv[1:]
rows = []
for current, directories, files in os.walk(root, topdown=True, followlinks=False):
    directories.sort()
    files.sort()
    for name in directories + files:
        path = os.path.join(current, name)
        relative = os.path.relpath(path, root)
        metadata = os.lstat(path)
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            rows.append((relative, "symlink", f"{mode:04o}", os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            rows.append((relative, "directory", f"{mode:04o}", "-"))
        elif stat.S_ISREG(metadata.st_mode):
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            rows.append(
                (relative, "file", f"{mode:04o}", f"{metadata.st_size}:{digest.hexdigest()}")
            )
        else:
            rows.append((relative, "other", f"{mode:04o}", "-"))

with open(destination, "w", encoding="utf-8", newline="\n") as output:
    output.write("path\ttype\tmode\tsize_or_target_and_sha256\n")
    for row in sorted(rows):
        output.write("\t".join(row) + "\n")
PY
}

snapshot_process_and_network() {
  local scope="$1"
  local process_destination="$2"
  local network_destination="$3"

  JANUS_DISCOVERY_SNAPSHOT_MARKER="$work_dir" \
    JANUS_DISCOVERY_SNAPSHOT_SCOPE="$scope" \
    JANUS_DISCOVERY_PROCESS_DESTINATION="$process_destination" \
    JANUS_DISCOVERY_NETWORK_DESTINATION="$network_destination" \
    python3 <<'PY'
import os

marker = os.environ["JANUS_DISCOVERY_SNAPSHOT_MARKER"]
scope = os.environ["JANUS_DISCOVERY_SNAPSHOT_SCOPE"]
process_destination = os.environ["JANUS_DISCOVERY_PROCESS_DESTINATION"]
network_destination = os.environ["JANUS_DISCOVERY_NETWORK_DESTINATION"]
processes = []
sockets = []

for entry in sorted(os.listdir("/proc")):
    if not entry.isdigit():
        continue
    process = os.path.join("/proc", entry)
    try:
        with open(os.path.join(process, "cmdline"), "rb") as handle:
            command = handle.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if marker not in command:
        continue
    normalized = command.replace(marker, "$WORK_DIR")
    processes.append(normalized)
    try:
        descriptors = os.listdir(os.path.join(process, "fd"))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    for descriptor in descriptors:
        try:
            target = os.readlink(os.path.join(process, "fd", descriptor))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if target.startswith("socket:["):
            sockets.append(normalized)

with open(process_destination, "w", encoding="utf-8", newline="\n") as output:
    output.write(f"scope\t{scope}\n")
    output.write(f"matching_processes\t{len(processes)}\n")
    output.write("commands\t" + (" | ".join(sorted(processes)) or "none") + "\n")

with open(network_destination, "w", encoding="utf-8", newline="\n") as output:
    output.write(f"scope\t{scope}\n")
    output.write(f"network_socket_fds\t{len(sockets)}\n")
    output.write("owners\t" + (" | ".join(sorted(sockets)) or "none") + "\n")
PY
}

summarize_passive_trace() {
  local trace="$1"
  local destination="$2"

  python3 - "$trace" "$fixture_root" "$agent_binary" "$destination" <<'PY'
import os
import re
import sys

trace_path, fixture_root, agent_binary, destination = sys.argv[1:]
network_calls = {
    "accept", "accept4", "bind", "connect", "getpeername", "getsockname",
    "listen", "recvfrom", "recvmmsg", "recvmsg", "sendmmsg", "sendmsg",
    "sendto", "setsockopt", "shutdown", "socket",
}
mutating_calls = {
    "chmod", "chown", "creat", "fchmodat", "fchownat", "link", "linkat",
    "mkdir", "mkdirat", "mknod", "mknodat", "mount", "open_by_handle_at",
    "rename", "renameat", "renameat2", "rmdir", "symlink", "symlinkat",
    "truncate", "unlink", "unlinkat", "utime", "utimensat",
}
write_flags = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE")
counts = {"target_write_syscalls": 0, "network_syscalls": 0, "child_execs": 0}
syscalls = {"target_write_syscalls": set(), "network_syscalls": set(), "child_execs": set()}

with open(trace_path, encoding="utf-8", errors="replace") as trace:
    for raw in trace:
        line = re.sub(r"^\d+\s+", "", raw.rstrip())
        match = re.match(r"([a-zA-Z0-9_]+)\(", line)
        if not match:
            continue
        call = match.group(1)
        if call in network_calls:
            counts["network_syscalls"] += 1
            syscalls["network_syscalls"].add(call)
        if call == "execve" and agent_binary not in line:
            counts["child_execs"] += 1
            syscalls["child_execs"].add(call)
        if fixture_root in line and (
            call in mutating_calls or (call in {"open", "openat", "openat2"} and any(flag in line for flag in write_flags))
        ):
            counts["target_write_syscalls"] += 1
            syscalls["target_write_syscalls"].add(call)

with open(destination, "w", encoding="utf-8", newline="\n") as output:
    output.write("measure\tcount\tsyscalls\n")
    for name in ("target_write_syscalls", "network_syscalls", "child_execs"):
        names = ",".join(sorted(syscalls[name])) or "none"
        output.write(f"{name}\t{counts[name]}\t{names}\n")
PY
}

trace_count() {
  awk -F '\t' -v measure="$2" '$1 == measure { print $2 }' "$1"
}

write_config() {
  local destination="$1"
  local runtime="$2"
  local process_memory="$3"
  local plugins="$4"
  local plugin_block="${5:-}"
  local config_name
  config_name="$(basename "$destination")"

  {
    printf 'controller_endpoint = "http://127.0.0.1:1"\n'
    printf 'http_controller_endpoint = "http://127.0.0.1:1"\n'
    printf 'execution_mode = "passive"\n'
    printf 'cache_path = %s\n' "$(toml_quote "$state_dir/$config_name.db")"
    printf 'host_uuid_path = %s\n' "$(toml_quote "$state_dir/$config_name.host-id")"
    printf 'report_path = ""\n'
    printf 'sarif_path = ""\n'
    printf 'scan_interval_seconds = 60\n'
    printf 'max_file_bytes = 2097152\n'
    printf 'max_binary_bytes = 16777216\n'
    printf 'command_signing_key = "linux-discovery-evidence-key-32-bytes"\n'
    printf 'scan_roots = [%s]\n' "$(toml_quote "$fixture_root")"
    printf 'exclude_dirs = []\n'
    printf 'network_targets = []\n'
    printf 'enable_runtime_discovery = %s\n' "$runtime"
    printf 'enable_process_memory_scraping = %s\n' "$process_memory"
    printf 'enable_plugin_discovery = %s\n' "$plugins"
    printf 'enable_active_tls_probing = false\n'
    printf 'plugin_dirs = []\n'
    printf 'intercept_mode = "disabled"\n'
    if [[ -n "$plugin_block" ]]; then
      printf '%s\n' "$plugin_block"
    fi
    printf '\n[active]\n'
    printf 'allowed_services = []\n'
    printf 'allowed_config_roots = []\n'
    printf 'backup_dir = %s\n' "$(toml_quote "$state_dir/backups")"
  } >"$destination"
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux discovery verification requires Linux"
[[ -x "$agent_binary" ]] || fail "agent binary is not executable: $agent_binary"
require_command python3
require_command sha256sum
require_command strace
require_command timeout

mkdir -p "$fixture_root/src" "$fixture_root/config" "$state_dir" "$evidence_dir"
printf '%s\n' 'use sha2::{Digest, Sha256};' >"$fixture_root/src/crypto_fixture.rs"
printf '%s\n' '{"dependencies":{"@noble/hashes":"1.8.0"}}' >"$fixture_root/package.json"
printf '%s\n' 'ssl_protocols TLSv1.3;' >"$fixture_root/config/tls.conf"
ln -s src/crypto_fixture.rs "$fixture_root/source-link"
chmod 0750 "$fixture_root/src"
chmod 0640 "$fixture_root/src/crypto_fixture.rs"
python3 - "$fixture_root" <<'PY'
import os
import sys

timestamp = 946684800
root = sys.argv[1]
for current, directories, files in os.walk(root, topdown=False, followlinks=False):
    for name in files:
        path = os.path.join(current, name)
        if not os.path.islink(path):
            os.utime(path, (timestamp, timestamp))
    for name in directories:
        path = os.path.join(current, name)
        if not os.path.islink(path):
            os.utime(path, (timestamp, timestamp))
os.utime(root, (timestamp, timestamp))
PY

passive_config="$work_dir/passive.toml"
write_config "$passive_config" false false false
snapshot_tree "$fixture_root" "$evidence_dir/filesystem.before.tsv"
snapshot_process_and_network passive-check \
  "$evidence_dir/process.before.tsv" "$evidence_dir/network.before.tsv"

run_and_capture_status "$evidence_dir/passive.exit-status.txt" \
  strace -ff -qq -s 4096 -e trace=%file,%network,%process \
  -o "$work_dir/passive.strace" \
  "$agent_binary" --config "$passive_config" check "$fixture_root" \
  >"$evidence_dir/passive.stdout.txt" 2>"$evidence_dir/passive.stderr.txt"
combine_trace "$work_dir/passive.strace"

passive_status="$(<"$evidence_dir/passive.exit-status.txt")"
[[ "$passive_status" == 0 || "$passive_status" == 1 ]] ||
  fail "passive check failed unexpectedly with status $passive_status"

snapshot_tree "$fixture_root" "$evidence_dir/filesystem.after.tsv"
snapshot_process_and_network passive-check \
  "$evidence_dir/process.after.tsv" "$evidence_dir/network.after.tsv"
cmp -s "$evidence_dir/filesystem.before.tsv" "$evidence_dir/filesystem.after.tsv" ||
  fail "passive discovery mutated the scanned root"
cmp -s "$evidence_dir/process.before.tsv" "$evidence_dir/process.after.tsv" ||
  fail "passive discovery left a process behind"
cmp -s "$evidence_dir/network.before.tsv" "$evidence_dir/network.after.tsv" ||
  fail "passive discovery left a network socket behind"

summarize_passive_trace "$work_dir/passive.strace" "$evidence_dir/passive-trace-summary.tsv"
[[ "$(trace_count "$evidence_dir/passive-trace-summary.tsv" target_write_syscalls)" == 0 ]] ||
  fail "passive discovery attempted to write inside the scanned root"
[[ "$(trace_count "$evidence_dir/passive-trace-summary.tsv" network_syscalls)" == 0 ]] ||
  fail "passive discovery attempted network activity"
[[ "$(trace_count "$evidence_dir/passive-trace-summary.tsv" child_execs)" == 0 ]] ||
  fail "passive discovery executed a child process"

invalid_memory_config="$work_dir/process-memory-without-runtime.toml"
write_config "$invalid_memory_config" false true false
run_and_capture_status "$evidence_dir/process-memory-config-denial.exit-status.txt" \
  "$agent_binary" --config "$invalid_memory_config" --once \
  >"$evidence_dir/process-memory-config-denial.stdout.txt" \
  2>"$evidence_dir/process-memory-config-denial.stderr.txt"
[[ "$(<"$evidence_dir/process-memory-config-denial.exit-status.txt")" != 0 ]] ||
  fail "process-memory mode ran without its required runtime-discovery opt-in"
grep -q 'enable_process_memory_scraping requires enable_runtime_discovery = true' \
  "$evidence_dir/process-memory-config-denial.stderr.txt" ||
  fail "process-memory configuration denial did not explain the missing prerequisite"

python3 -c '
import ctypes
import time
secret = b"-----BEGIN PRIVATE KEY----- linux-discovery-denial-fixture"
if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
    raise SystemExit("failed to disable process dumpability")
time.sleep(90)
' &
memory_holder_pid=$!
for _ in {1..50}; do
  [[ -r "/proc/$memory_holder_pid/status" ]] && break
  sleep 0.1
done
[[ -r "/proc/$memory_holder_pid/status" ]] || fail "process-memory denial fixture did not start"

memory_config="$work_dir/process-memory.toml"
write_config "$memory_config" true true false
run_and_capture_status "$evidence_dir/process-memory-denial.exit-status.txt" \
  timeout 75 strace -ff -qq -s 4096 -e trace=%file \
  -o "$work_dir/process-memory.strace" \
  "$agent_binary" --config "$memory_config" --once \
  >"$evidence_dir/process-memory-denial.stdout.txt" \
  2>"$evidence_dir/process-memory-denial.stderr.txt"
combine_trace "$work_dir/process-memory.strace"
grep -E "/proc/$memory_holder_pid/(maps|mem).*(EACCES|EPERM)" "$work_dir/process-memory.strace" \
  >"$evidence_dir/process-memory-denial.tsv" ||
  fail "process-memory mode did not encounter the expected permission denial"
sed -E 's/^[0-9]+ +//' "$evidence_dir/process-memory-denial.tsv" |
  sed -E "s#/proc/$memory_holder_pid/#/proc/KEY_HOLDER_PID/#g" |
  sort -u >"$evidence_dir/process-memory-denial.normalized.txt"
rm -f "$evidence_dir/process-memory-denial.tsv"
kill "$memory_holder_pid" 2>/dev/null || true
wait "$memory_holder_pid" 2>/dev/null || true
memory_holder_pid=

plugin_sentinel="$work_dir/plugin-executed"
plugin_block="$(
  printf '[[plugin_commands]]\n'
  printf 'name = "permission-denied-plugin"\n'
  printf 'command = "/bin/sh"\n'
  printf 'args = ["-c", %s]\n' "$(toml_quote "touch $plugin_sentinel")"
  printf 'timeout_seconds = 5\n'
  printf 'max_memory_mb = 64\n'
  printf 'max_cpu_percent = 10\n'
)"
plugin_config="$work_dir/plugin.toml"
write_config "$plugin_config" false false true "$plugin_block"
run_and_capture_status "$evidence_dir/plugin-denial.exit-status.txt" \
  timeout 45 strace -ff -qq -s 4096 -e trace=%file,%process \
  -o "$work_dir/plugin.strace" \
  "$agent_binary" --config "$plugin_config" --once \
  >"$evidence_dir/plugin-denial.stdout.txt" \
  2>"$evidence_dir/plugin-denial.stderr.txt"
combine_trace "$work_dir/plugin.strace"
[[ ! -e "$plugin_sentinel" ]] ||
  fail "plugin executed without the required cgroup v2 isolation"
grep -E 'janus-plugin-.*(EACCES|EPERM|EROFS)' "$work_dir/plugin.strace" |
  sed -E 's/^[0-9]+ +//' |
  sed -E 's/janus-plugin-[0-9]+-[0-9a-f-]+/janus-plugin-PID-UUID/g' |
  sort -u >"$evidence_dir/plugin-denial.normalized.txt" ||
  fail "plugin mode did not fail closed on unavailable cgroup delegation"

{
  printf 'evidence_format\tjanus-linux-discovery-v1\n'
  printf 'passive_scanned_root_mutation\tnone\n'
  printf 'passive_target_write_syscalls\t0\n'
  printf 'passive_network_syscalls\t0\n'
  printf 'passive_child_execs\t0\n'
  printf 'process_memory_without_runtime\trejected\n'
  printf 'process_memory_permission_denial\tobserved\n'
  printf 'plugin_without_cgroup_delegation\trejected-before-exec\n'
} >"$evidence_dir/manifest.tsv"

printf 'Linux discovery evidence verification passed: %s\n' "$evidence_dir"
