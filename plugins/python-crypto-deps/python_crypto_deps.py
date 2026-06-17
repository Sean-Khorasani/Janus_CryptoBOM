#!/usr/bin/env python3
"""python-crypto-deps — Janus agent plugin (DOC-003 sample).

Use case: inventory crypto-relevant packages installed in the current Python environment
and the algorithm families they bring. Complements dependency-manifest scanning by reading
what is *actually installed* in this interpreter.

Metadata-only: prints package names, versions, and algorithm families (named with tokens
the agent recognizes: RSA, ECDSA, ECDH, AES, SHA256, SHA1, ML-KEM, ML-DSA, SLH-DSA, ...).
Never prints keys or secrets. Read-only.
"""
import json
import sys

try:
    from importlib import metadata as im
except Exception:  # very old Python
    import importlib_metadata as im  # type: ignore

# Known crypto libraries -> algorithm families they typically provide. The family strings
# use the tokens the agent keyword-extracts, so installed libs surface in the CBOM.
CRYPTO_LIBS = {
    "cryptography": "RSA ECDSA ECDH AES SHA256 SHA1",
    "pyOpenSSL": "RSA ECDSA AES SHA256",
    "pycryptodome": "RSA AES SHA256 ECDSA",
    "pycryptodomex": "RSA AES SHA256 ECDSA",
    "paramiko": "RSA ECDSA ECDH AES SHA256",
    "pynacl": "Ed25519 X25519",
    "oqs": "ML-KEM ML-DSA SLH-DSA",
    "liboqs-python": "ML-KEM ML-DSA SLH-DSA",
    "ecdsa": "ECDSA ECDH",
    "rsa": "RSA",
    "bcrypt": "bcrypt",
    "certifi": "TLS trust store",
}


def main() -> int:
    found = []
    try:
        dists = list(im.distributions())
    except Exception as exc:  # pragma: no cover
        print(f"python-crypto-deps: cannot enumerate packages: {exc}", file=sys.stderr)
        return 0
    for dist in dists:
        try:
            name = dist.metadata["Name"]
        except Exception:
            continue
        if name in CRYPTO_LIBS:
            found.append(
                {"package": name, "version": dist.version, "provides": CRYPTO_LIBS[name]}
            )

    report = {
        "tool": "python-crypto-deps",
        "python": sys.version.split()[0],
        "packages": sorted(found, key=lambda p: p["package"].lower()),
    }
    print(json.dumps(report, indent=2))
    if not found:
        print("(no recognized crypto packages in this environment)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
