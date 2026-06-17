#!/usr/bin/env bash
# hsm-softhsm-init.sh — initialize a SoftHSM2 token for Janus HSM (PKCS#11) testing on
# Linux, and print the environment the server / tests need.
#
# Prefers the PQC-enabled SoftHSM built under HSM/tools/build (real ML-DSA, FIPS 204),
# built against OpenSSL 3.5; falls back to the system SoftHSM2 (HMAC command-signing only,
# no ML-DSA). The token is created under HSM/linux-tokens so the setup is repo-local and
# reproducible. Idempotent: re-running keeps the existing token.
#
# Usage:
#   source ./scripts/hsm-softhsm-init.sh      # exports the env into your shell, OR
#   ./scripts/hsm-softhsm-init.sh             # prints the export lines to eval
#
# Resulting environment (consumed by the server and the cgo integration tests):
#   JANUS_HSM_MODULE_PATH / JANUS_HSM_TEST_MODULE  — the libsofthsm2.so to load
#   SOFTHSM2_CONF                                  — SoftHSM config (token dir)
#   LD_LIBRARY_PATH                                — OpenSSL 3.5 libs (PQC build only)
#   JANUS_HSM_TOKEN_LABEL / JANUS_HSM_TEST_LABEL   — JanusTestToken
#   JANUS_HSM_PIN / JANUS_HSM_TEST_PIN             — 1234
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
BUILD="$ROOT/HSM/tools/build"
PQC_MODULE="$BUILD/softhsm-prefix/lib/softhsm/libsofthsm2.so"
PQC_UTIL="$BUILD/softhsm-prefix/bin/softhsm2-util"
OSSL_LIB="$BUILD/openssl-prefix/lib64"
LABEL="${JANUS_HSM_TOKEN_LABEL:-JanusTestToken}"
PIN="${JANUS_HSM_PIN:-1234}"
SOPIN="${JANUS_HSM_SO_PIN:-5678}"

mkdir -p "$ROOT/HSM/linux-tokens"
CONF="$ROOT/HSM/softhsm2.linux.conf"
cat > "$CONF" <<EOF
directories.tokendir = $ROOT/HSM/linux-tokens
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

if [ -f "$PQC_MODULE" ] && [ -x "$PQC_UTIL" ]; then
	MODULE="$PQC_MODULE"; UTIL="$PQC_UTIL"; LDP="$OSSL_LIB"
	KIND="PQC (ML-DSA-capable, OpenSSL 3.5)"
else
	MODULE=""
	for cand in /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so; do
		[ -f "$cand" ] && { MODULE="$cand"; break; }
	done
	UTIL="$(command -v softhsm2-util || true)"; LDP=""
	KIND="system SoftHSM2 (HMAC only, no ML-DSA)"
	[ -n "$MODULE" ] || { echo "ERROR: no SoftHSM2 module found; build it or apt-get install softhsm2" >&2; exit 1; }
fi

export SOFTHSM2_CONF="$CONF"
[ -n "$LDP" ] && export LD_LIBRARY_PATH="${LDP}:${LD_LIBRARY_PATH:-}"

# Initialize the token only if it isn't already present (idempotent).
if ! LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" "$UTIL" --show-slots 2>/dev/null | grep -q "$LABEL"; then
	LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" "$UTIL" --init-token --free \
		--label "$LABEL" --pin "$PIN" --so-pin "$SOPIN" >&2
fi

export JANUS_HSM_MODULE_PATH="$MODULE"  JANUS_HSM_TEST_MODULE="$MODULE"
export JANUS_HSM_TOKEN_LABEL="$LABEL"   JANUS_HSM_TEST_LABEL="$LABEL"
export JANUS_HSM_PIN="$PIN"             JANUS_HSM_TEST_PIN="$PIN"

echo "# Janus SoftHSM ready: $KIND" >&2
echo "export SOFTHSM2_CONF='$SOFTHSM2_CONF'"
[ -n "$LDP" ] && echo "export LD_LIBRARY_PATH='${LD_LIBRARY_PATH}'"
echo "export JANUS_HSM_MODULE_PATH='$MODULE' JANUS_HSM_TEST_MODULE='$MODULE'"
echo "export JANUS_HSM_TOKEN_LABEL='$LABEL' JANUS_HSM_TEST_LABEL='$LABEL'"
echo "export JANUS_HSM_PIN='$PIN' JANUS_HSM_TEST_PIN='$PIN'"
