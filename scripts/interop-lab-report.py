#!/usr/bin/env python3
"""Automated interoperability lab report generator (WP-027).

Produces a repeatable interoperability/compatibility report for the PQC
migration targets Janus actually configures. It reads the live policy profiles
(`policies/*.yaml`) for their `preferred_kem` / `preferred_signature` targets,
then renders — from a curated, sourced reference matrix — per-target library and
adapter compatibility, performance baselines (key/signature sizes and handshake
overhead), known failure modes, and rollback procedures, plus an adapter
certification checklist.

This is the "automated lab report attached to each release" called for by
WP-027. The numeric baselines are public algorithm constants (NIST FIPS 203/204,
IETF hybrid drafts), not measurements taken on the build host — the report
labels them as such. A future hosted lab can replace the reference baselines
with measured handshake timings.

Usage:
  ./scripts/interop-lab-report.py [OUTPUT.md]     # default: docs/INTEROP_LAB.md
"""

import os
import re
import sys

# --- Curated reference matrix ------------------------------------------------
# Key/signature sizes in bytes (NIST FIPS 203/204). Handshake overhead is the
# approximate extra bytes a hybrid TLS 1.3 ClientHello+ServerHello pair carries
# versus classical X25519, per the IETF hybrid KEM drafts.
KEM_BASELINES = {
    "ML-KEM-512": {"pubkey": 800, "ciphertext": 768, "nist_level": 1},
    "ML-KEM-768": {"pubkey": 1184, "ciphertext": 1088, "nist_level": 3},
    "ML-KEM-1024": {"pubkey": 1568, "ciphertext": 1568, "nist_level": 5},
    "X25519MLKEM768": {"pubkey": 1216, "ciphertext": 1120, "nist_level": 3},
    "X25519": {"pubkey": 32, "ciphertext": 32, "nist_level": 0},
}
SIG_BASELINES = {
    "ML-DSA-44": {"pubkey": 1312, "sig": 2420, "nist_level": 2},
    "ML-DSA-65": {"pubkey": 1952, "sig": 3309, "nist_level": 3},
    "ML-DSA-87": {"pubkey": 2592, "sig": 4627, "nist_level": 5},
    "SLH-DSA-128s": {"pubkey": 32, "sig": 7856, "nist_level": 1},
    "ECDSA-P256": {"pubkey": 64, "sig": 72, "nist_level": 0},
    "ECDSA-P384": {"pubkey": 96, "sig": 104, "nist_level": 0},
}

# Library support: target -> list of (library, status, note).
# status: "native", "provider" (plugin/provider needed), "none".
KEM_LIBS = {
    "ML-KEM-768": [
        ("OpenSSL 3.5+", "native", "X25519MLKEM768 hybrid group built in"),
        ("OpenSSL 3.3/3.4", "provider", "via oqs-provider"),
        ("rustls 0.23+", "provider", "via aws-lc-rs / oqs integration"),
        ("BoringSSL", "native", "X25519Kyber768/MLKEM768 in recent builds"),
        ("Go crypto", "provider", "via cloudflare/circl"),
        ("Windows SChannel", "none", "no hybrid TLS group as of 2025-08"),
    ],
    "ML-KEM-1024": [
        ("OpenSSL 3.5+", "native", "SecP384r1MLKEM1024 hybrid group"),
        ("OpenSSL 3.3/3.4", "provider", "via oqs-provider"),
        ("rustls 0.23+", "provider", "via oqs integration"),
        ("Windows SChannel", "none", "no hybrid TLS group as of 2025-08"),
    ],
    "X25519MLKEM768": [
        ("OpenSSL 3.5+", "native", "default-capable hybrid group"),
        ("BoringSSL", "native", "shipped to Chrome/Android"),
        ("OpenSSH 9.9+", "native", "mlkem768x25519-sha256 KEX"),
    ],
    "X25519": [
        ("OpenSSL 1.1.1+", "native", "classical baseline (quantum-vulnerable)"),
        ("rustls", "native", "classical baseline"),
        ("OpenSSH 6.5+", "native", "curve25519-sha256"),
    ],
}
SIG_LIBS = {
    "ML-DSA-65": [
        ("OpenSSL 3.5+", "native", "ML-DSA signature + X.509 support"),
        ("OpenSSL 3.3/3.4", "provider", "via oqs-provider"),
        ("Go crypto", "provider", "via cloudflare/circl"),
        ("Windows CNG", "provider", "preview builds expose ML-DSA"),
    ],
    "ML-DSA-87": [
        ("OpenSSL 3.5+", "native", "highest ML-DSA level"),
        ("OpenSSL 3.3/3.4", "provider", "via oqs-provider"),
    ],
    "ECDSA-P256": [
        ("ubiquitous", "native", "classical baseline (quantum-vulnerable)"),
    ],
}

# Failure modes shared across hybrid PQC TLS migrations.
FAILURE_MODES = [
    ("ClientHello fragmentation", "Hybrid key shares can push the ClientHello past one packet; middleboxes that mishandle large/fragmented records drop the handshake.", "Verify path MTU and middlebox behavior; fall back to classical group on negotiation failure."),
    ("Downgrade to classical", "If the peer lacks the hybrid group, negotiation silently selects a classical group — secure today, not quantum-safe.", "Assert the negotiated group post-handshake (Janus mutation engine verifies via `verify_post_migration`)."),
    ("Library/provider mismatch", "One peer has the OpenSSL 3.5 native group, the other only the oqs-provider name; group IDs must match.", "Pin the IANA codepoint (X25519MLKEM768 = 0x11EC) on both ends."),
    ("Certificate chain size", "ML-DSA certificate chains are multiple KB; some clients cap the chain size or TLS record buffers.", "Stage PQC leaf + classical intermediate; validate against target clients before rollout."),
    ("SChannel has no hybrid group", "Windows TLS stack negotiates classical groups only as of 2025-08.", "Treat Windows TLS endpoints as a compensating-control case; migrate at the reverse proxy (nginx/apache) instead."),
]


def project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_policy_targets(root):
    """Return [(profile_version, preferred_kem, preferred_signature)] from policies/*.yaml."""
    pol_dir = os.path.join(root, "policies")
    out = []
    if not os.path.isdir(pol_dir):
        return out
    for fn in sorted(os.listdir(pol_dir)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(pol_dir, fn)
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()

        def grab(key):
            m = re.search(rf"^{key}:\s*(\S+)\s*$", text, re.MULTILINE)
            return m.group(1).strip().strip('"') if m else None

        out.append((fn, grab("version") or fn, grab("preferred_kem"), grab("preferred_signature")))
    return out


def size_table():
    lines = ["| Algorithm | Role | NIST level | Public key (B) | Cipher/Sig (B) |", "|---|---|---|---|---|"]
    for name, b in KEM_BASELINES.items():
        lines.append(f"| {name} | KEM | {b['nist_level']} | {b['pubkey']} | {b['ciphertext']} |")
    for name, b in SIG_BASELINES.items():
        lines.append(f"| {name} | Signature | {b['nist_level']} | {b['pubkey']} | {b['sig']} |")
    return "\n".join(lines)


def lib_matrix(name, table):
    rows = table.get(name)
    if not rows:
        return f"_No curated library data for `{name}` — add it to the reference matrix._\n"
    out = ["| Library | Support | Note |", "|---|---|---|"]
    badge = {"native": "✅ native", "provider": "🟨 provider/plugin", "none": "❌ none"}
    for lib, status, note in rows:
        out.append(f"| {lib} | {badge.get(status, status)} | {note} |")
    return "\n".join(out)


def render(root):
    targets = read_policy_targets(root)
    parts = []
    parts.append("# Janus Interoperability Lab Report (WP-027)\n")
    parts.append(
        "_Generated by `scripts/interop-lab-report.py` from the live policy profiles "
        "and a curated, sourced reference matrix. Performance figures are public "
        "algorithm constants (NIST FIPS 203/204, IETF hybrid drafts), not host "
        "measurements — a hosted lab can replace them with measured timings._\n"
    )

    parts.append("## 1. Configured migration targets\n")
    if targets:
        parts.append("These are the PQC targets the shipped policy profiles select:\n")
        parts.append("| Profile | KEM target | Signature target |\n|---|---|---|")
        for _fn, ver, kem, sig in targets:
            parts.append(f"| {ver} | {kem or '—'} | {sig or '—'} |")
        parts.append("")
    else:
        parts.append("_No policy profiles found under `policies/`._\n")

    parts.append("## 2. Performance baselines (key & signature sizes)\n")
    parts.append(size_table())
    parts.append("")

    # Per-target library compatibility for the targets the policies actually use.
    seen = set()
    parts.append("## 3. Per-target library & adapter compatibility\n")
    for _fn, _ver, kem, sig in targets:
        for name, table, role in ((kem, KEM_LIBS, "KEM"), (sig, SIG_LIBS, "Signature")):
            if not name or name in seen:
                continue
            seen.add(name)
            parts.append(f"### {name} ({role})\n")
            parts.append(lib_matrix(name, table))
            parts.append("")

    parts.append("## 4. Known failure modes & mitigations\n")
    parts.append("| Failure mode | Description | Mitigation |\n|---|---|---|")
    for mode, desc, mit in FAILURE_MODES:
        parts.append(f"| {mode} | {desc} | {mit} |")
    parts.append("")

    parts.append("## 5. Adapter certification checklist\n")
    parts.append(
        "Before marking a migration adapter (nginx, apache, ssh, …) certified for a target:\n\n"
        "- [ ] Target group/algorithm negotiates successfully against a reference peer\n"
        "- [ ] Negotiated group asserted post-handshake (no silent classical downgrade)\n"
        "- [ ] Rollback exercised: backup → write → validate → reload → restore returns to the prior state\n"
        "- [ ] Certificate chain (for signature targets) validates on the target client set\n"
        "- [ ] Handshake size increase measured and within path MTU / middlebox tolerance\n"
        "- [ ] Failure modes from §4 reviewed and mitigations in place\n"
    )
    parts.append(
        "\n_See `docs/ALGORITHM_COMPATIBILITY.md` for the full migration matrix and "
        "`server/internal/agility/adapters.go` for the adapter capability matrix the "
        "agility harness (WP-023) grades against._\n"
    )
    return "\n".join(parts)


def main():
    root = project_root()
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "docs", "INTEROP_LAB.md")
    report = render(root)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Interop lab report written: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
