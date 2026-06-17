#!/bin/sh
# openssl-inventory — Janus agent plugin (DOC-003 sample).
#
# Use case: report the host's OpenSSL/TLS crypto capabilities — version, offered cipher
# suites, named curves, and (on OpenSSL 3.5+/oqs-provider) PQC KEM/signature algorithms.
# The agent keyword-extracts the algorithm names below (RSA, ECDSA, ECDH, AES, SHA*,
# ML-KEM, ML-DSA, ...) into the CBOM.
#
# Metadata-only: prints capability names/versions, never keys or secrets. Read-only.
set -u

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl-inventory: openssl not found on host" >&2
  exit 0
fi

echo "openssl-inventory"
echo "version: $(openssl version 2>/dev/null)"

echo "== tls cipher suites (DEFAULT) =="
# Names include ECDHE / RSA / ECDSA / AES / SHA* tokens the agent recognizes.
openssl ciphers -v DEFAULT 2>/dev/null || echo "(unable to list ciphers)"

echo "== named curves (ECDH / ECDSA) =="
openssl ecparam -list_curves 2>/dev/null || echo "(unable to list curves)"

echo "== kem algorithms (PQC, if this build exposes them) =="
openssl list -kem-algorithms 2>/dev/null || echo "(openssl list -kem-algorithms not supported on this build)"

echo "== signature algorithms =="
openssl list -signature-algorithms 2>/dev/null || echo "(openssl list -signature-algorithms not supported on this build)"
