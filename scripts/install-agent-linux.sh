#!/usr/bin/env bash
set -euo pipefail

unset CDPATH
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

PREFIX="${PREFIX:-/usr}"
DESTDIR="${DESTDIR:-}"
BINARY="${REPO_ROOT}/agent/target/release/janus-agent"
CONFIG_EXAMPLE="${REPO_ROOT}/agent/janus-agent.linux.toml"
SERVICE_SOURCE="${REPO_ROOT}/packaging/systemd/janus-agent.service"
TMPFILES_SOURCE="${REPO_ROOT}/packaging/systemd/janus-agent.tmpfiles"
COMMAND_SIGNING_KEY_FILE=""
DAEMON_RELOAD=false
ENABLE=false
START=false

usage() {
  cat <<'EOF'
Install the Janus Linux agent.

Usage: scripts/install-agent-linux.sh [options]

Options:
  --prefix PATH          Installation prefix (default: $PREFIX or /usr)
  --destdir PATH         Stage files below PATH without host side effects
  --binary PATH          Release janus-agent binary to install
  --config-example PATH  Linux TOML configuration example to install
  --command-signing-key-file PATH
                         Controller-provisioned signing key to install
  --daemon-reload        Run systemctl daemon-reload after installation
  --enable               Enable janus-agent.service
  --start                Start janus-agent.service
  -h, --help             Show this help

Installed paths:
  PREFIX/bin/janus-agent
  /etc/janus-agent/janus-agent.toml
  PREFIX/lib/systemd/system/janus-agent.service
  PREFIX/lib/tmpfiles.d/janus-agent.conf

The configuration file is created only when it does not already exist.
PREFIX and DESTDIR may also be supplied as environment variables.
EOF
}

die() {
  printf 'install-agent-linux.sh: %s\n' "$*" >&2
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
    --binary)
      (($# >= 2)) || die "--binary requires a path"
      BINARY="$2"
      shift 2
      ;;
  --config-example)
      (($# >= 2)) || die "--config-example requires a path"
      CONFIG_EXAMPLE="$2"
      shift 2
      ;;
    --command-signing-key-file)
      (($# >= 2)) || die "--command-signing-key-file requires a path"
      COMMAND_SIGNING_KEY_FILE="$2"
      shift 2
      ;;
    --daemon-reload)
      DAEMON_RELOAD=true
      shift
      ;;
    --enable)
      ENABLE=true
      shift
      ;;
    --start)
      START=true
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

[[ -f "$BINARY" ]] || die "release binary not found: $BINARY"
[[ -f "$CONFIG_EXAMPLE" ]] || die "Linux config example not found: $CONFIG_EXAMPLE"
[[ -f "$SERVICE_SOURCE" ]] || die "systemd unit not found: $SERVICE_SOURCE"
[[ -f "$TMPFILES_SOURCE" ]] || die "tmpfiles definition not found: $TMPFILES_SOURCE"
if [[ -n "$COMMAND_SIGNING_KEY_FILE" ]]; then
  [[ -f "$COMMAND_SIGNING_KEY_FILE" ]] ||
    die "command signing key file not found: $COMMAND_SIGNING_KEY_FILE"
  [[ "$(wc -c <"$COMMAND_SIGNING_KEY_FILE")" -ge 16 ]] ||
    die "command signing key file must contain at least 16 bytes"
fi

REAL_ROOT_INSTALL=false
if [[ -z "$DESTDIR" && "$EUID" -eq 0 ]]; then
  REAL_ROOT_INSTALL=true
fi

if [[ -z "$DESTDIR" && "$EUID" -ne 0 ]]; then
  die "a real installation requires root; use DESTDIR for an unprivileged staged install"
fi

if [[ -n "$DESTDIR" && ("$DAEMON_RELOAD" == true || "$ENABLE" == true || "$START" == true) ]]; then
  die "systemd actions cannot be used with DESTDIR"
fi

if [[ "$REAL_ROOT_INSTALL" == true ]] && ! getent group janusagent >/dev/null 2>&1; then
  groupadd --system janusagent
fi
if [[ "$REAL_ROOT_INSTALL" == true ]] && ! id janusagent >/dev/null 2>&1; then
  useradd --system --gid janusagent --home-dir /var/lib/janus-agent \
    --no-create-home --shell /usr/sbin/nologin janusagent
fi

BIN_DIR="${DESTDIR}${PREFIX}/bin"
CONFIG_DIR="${DESTDIR}/etc/janus-agent"
STATE_DIR="${DESTDIR}/var/lib/janus-agent"
UNIT_DIR="${DESTDIR}${PREFIX}/lib/systemd/system"
TMPFILES_DIR="${DESTDIR}${PREFIX}/lib/tmpfiles.d"

install -d -m 0755 "$BIN_DIR" "$UNIT_DIR" "$TMPFILES_DIR"
install -d -m 0750 "$CONFIG_DIR"
install -d -m 0700 "$STATE_DIR"
install -m 0755 "$BINARY" "${BIN_DIR}/janus-agent"
if [[ ! -e "${STATE_DIR}/cache-protection-key" ]]; then
  umask 077
  dd if=/dev/urandom bs=32 count=1 status=none |
    base64 >"${STATE_DIR}/cache-protection-key"
fi
chmod 0600 "${STATE_DIR}/cache-protection-key"

if [[ ! -e "${CONFIG_DIR}/janus-agent.toml" ]]; then
  install -m 0640 "$CONFIG_EXAMPLE" "${CONFIG_DIR}/janus-agent.toml"
else
  printf 'Preserving existing configuration: %s\n' "${CONFIG_DIR}/janus-agent.toml"
fi
if [[ -n "$COMMAND_SIGNING_KEY_FILE" ]]; then
  install -m 0640 "$COMMAND_SIGNING_KEY_FILE" "${CONFIG_DIR}/command-signing-key"
elif [[ ! -e "${CONFIG_DIR}/command-signing-key" ]]; then
  printf 'No command signing credential installed; provision %s before starting the service.\n' \
    "${CONFIG_DIR}/command-signing-key" >&2
fi

sed "s|^ExecStart=/usr/bin/janus-agent|ExecStart=${PREFIX}/bin/janus-agent|" \
  "$SERVICE_SOURCE" >"${UNIT_DIR}/janus-agent.service"
chmod 0644 "${UNIT_DIR}/janus-agent.service"
install -m 0644 "$TMPFILES_SOURCE" "${TMPFILES_DIR}/janus-agent.conf"

if [[ "$REAL_ROOT_INSTALL" == true ]]; then
  chown root:janusagent "$CONFIG_DIR" "${CONFIG_DIR}/janus-agent.toml"
  if [[ -e "${CONFIG_DIR}/command-signing-key" ]]; then
    chown root:janusagent "${CONFIG_DIR}/command-signing-key"
  fi
  chown janusagent:janusagent "$STATE_DIR"
  chown janusagent:janusagent "${STATE_DIR}/cache-protection-key"
fi

if [[ "$DAEMON_RELOAD" == true ]]; then
  systemctl daemon-reload
fi
if [[ "$ENABLE" == true ]]; then
  systemctl enable janus-agent.service
fi
if [[ "$START" == true ]]; then
  systemctl start janus-agent.service
fi

printf 'Installed Janus agent binary: %s\n' "${BIN_DIR}/janus-agent"
printf 'Janus agent configuration: %s\n' "${CONFIG_DIR}/janus-agent.toml"
