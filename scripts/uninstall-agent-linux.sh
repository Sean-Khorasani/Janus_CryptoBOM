#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr}"
DESTDIR="${DESTDIR:-}"
PURGE=false
KEEP_SERVICE=false
DAEMON_RELOAD=false

usage() {
  cat <<'EOF'
Uninstall the Janus Linux agent.

Usage: scripts/uninstall-agent-linux.sh [options]

Options:
  --prefix PATH     Installation prefix (default: $PREFIX or /usr)
  --destdir PATH    Remove files from a staged installation below PATH
  --purge           Also remove configuration, state, and the system account
  --keep-service    Do not stop or disable the service during a real uninstall
  --daemon-reload   Run systemctl daemon-reload after removing the unit
  -h, --help        Show this help

By default, /etc/janus-agent and /var/lib/janus-agent are preserved.
PREFIX and DESTDIR may also be supplied as environment variables.
EOF
}

die() {
  printf 'uninstall-agent-linux.sh: %s\n' "$*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --prefix)
      (($# >= 2)) || die "--prefix requires a path"
      PREFIX="$2"
      shift 2
      ;;
    --destdir)
      (($# >= 2)) || die "--destdir requires a path"
      DESTDIR="$2"
      shift 2
      ;;
    --purge)
      PURGE=true
      shift
      ;;
    --keep-service)
      KEEP_SERVICE=true
      shift
      ;;
    --daemon-reload)
      DAEMON_RELOAD=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$PREFIX" == /* ]] || die "PREFIX must be an absolute path"
PREFIX="${PREFIX%/}"
[[ -n "$PREFIX" ]] || PREFIX="/"

if [[ -n "$DESTDIR" ]]; then
  [[ "$DESTDIR" == /* ]] || die "DESTDIR must be an absolute path"
  DESTDIR="${DESTDIR%/}"
  [[ "$DESTDIR" != "/" ]] || DESTDIR=""
fi

REAL_ROOT_INSTALL=false
if [[ -z "$DESTDIR" && "$EUID" -eq 0 ]]; then
  REAL_ROOT_INSTALL=true
fi

if [[ -z "$DESTDIR" && "$EUID" -ne 0 ]]; then
  die "a real uninstall requires root; use DESTDIR for an unprivileged staged uninstall"
fi
if [[ -n "$DESTDIR" && "$DAEMON_RELOAD" == true ]]; then
  die "--daemon-reload cannot be used with DESTDIR"
fi

if [[ "$REAL_ROOT_INSTALL" == true && "$KEEP_SERVICE" == false ]]; then
  systemctl disable --now janus-agent.service >/dev/null 2>&1 || true
fi

rm -f -- \
  "${DESTDIR}${PREFIX}/bin/janus-agent" \
  "${DESTDIR}${PREFIX}/lib/systemd/system/janus-agent.service" \
  "${DESTDIR}${PREFIX}/lib/tmpfiles.d/janus-agent.conf"

if [[ "$PURGE" == true ]]; then
  rm -rf -- "${DESTDIR}/etc/janus-agent" "${DESTDIR}/var/lib/janus-agent"
  if [[ "$REAL_ROOT_INSTALL" == true ]] && id janusagent >/dev/null 2>&1; then
    userdel janusagent
  fi
else
  printf 'Preserved configuration: %s\n' "${DESTDIR}/etc/janus-agent"
  printf 'Preserved state: %s\n' "${DESTDIR}/var/lib/janus-agent"
fi

if [[ "$DAEMON_RELOAD" == true ]]; then
  systemctl daemon-reload
fi

printf 'Uninstalled Janus agent from prefix: %s\n' "${DESTDIR}${PREFIX}"
