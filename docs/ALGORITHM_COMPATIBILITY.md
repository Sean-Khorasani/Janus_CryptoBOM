# Algorithm Compatibility Reference

**WP-027 (partial) — PQC Migration Compatibility Matrix**

This document is a technical reference for operators planning post-quantum cryptography migrations using Janus CryptoBOM. It covers algorithm migration paths, library support status, protocol constraints, and known issues. Policy targets referenced here are drawn from `policies/nist-pqc-2026.yaml` and `policies/cnsa-2.0.yaml`.

---

## 1. NIST Quantum Security Levels

NIST defines five security levels based on the computational resources required to break the algorithm, benchmarked against AES and SHA.

| Level | Benchmark | Algorithms at this level |
|---|---|---|
| 1 | Equivalent to breaking AES-128 | ML-KEM-512, ML-DSA-44, SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s |
| 2 | Equivalent to finding SHA-256 collision | — |
| 3 | Equivalent to breaking AES-192 | ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-192s |
| 4 | Equivalent to finding SHA-384 collision | — |
| 5 | Equivalent to breaking AES-256 | ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256s |

Janus policy profiles target Level 3 as the baseline (NIST FIPS 203/204/205, `nist-pqc-2026.yaml`) and Level 5 as the CNSA 2.0 floor (`cnsa-2.0.yaml`).

### Standards Authority

| Standard | Document | Algorithms |
|---|---|---|
| FIPS 203 | Module-Lattice-Based Key Encapsulation Mechanism | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| FIPS 204 | Module-Lattice-Based Digital Signature | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| FIPS 205 | Stateless Hash-Based Digital Signature | SLH-DSA (all parameter sets) |
| CNSA 2.0 (2022) | NSA Commercial National Security Algorithm Suite 2.0 | ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/SHA-512 |
| SP 800-131A Rev.3 | Transitioning Use of Cryptographic Algorithms | Deprecation timelines |

---

## 2. PQC Migration Targets

The following algorithms are the current migration targets in Janus policy profiles:

| Algorithm | Type | NIST Level | FIPS Standard | Janus Profile |
|---|---|---|---|---|
| ML-KEM-768 | KEM | 3 | FIPS 203 | `nist-pqc-2026` (hybrid: X25519MLKEM768) |
| ML-KEM-1024 | KEM | 5 | FIPS 203 | `cnsa-2.0` (preferred KEM) |
| ML-DSA-65 | Signature | 3 | FIPS 204 | `nist-pqc-2026` (preferred signature) |
| ML-DSA-87 | Signature | 5 | FIPS 204 | `cnsa-2.0` (preferred signature) |
| SLH-DSA-SHA2-128s | Signature | 1 | FIPS 205 | Supported via certmanager |
| X25519MLKEM768 | Hybrid KEM | 3 (quantum) + X25519 | IETF draft | `nist-pqc-2026` TLS KEM group |

---

## 3. Source-to-Target Migration Matrix

### 3.1 RSA (Signatures)

**Source algorithms:** RSA-2048, RSA-3072, RSA-4096 (PKCS#1 v1.5 or PSS)

**Migration paths:**

| Source | Target | Notes |
|---|---|---|
| RSA-2048 (signing) | ML-DSA-65 | Level 3. Direct replacement for code-signing and TLS authentication. RSA-2048 is deprecated under CNSA 2.0; flagged as critical by Janus. |
| RSA-3072 (signing) | ML-DSA-65 or ML-DSA-87 | RSA-3072 meets the NIST transitional minimum (SP 800-131A); migrate to ML-DSA-65 for NIST profile, ML-DSA-87 for CNSA 2.0. |
| RSA-4096 (signing) | ML-DSA-87 | RSA-4096 is not quantum-safe. ML-DSA-87 provides comparable assurance at Level 5 with substantially smaller signatures. |

**Key and signature sizes:**

| Algorithm | Public key | Private key | Signature |
|---|---|---|---|
| RSA-2048 | 256 bytes | 1,192 bytes | 256 bytes |
| RSA-4096 | 512 bytes | 2,350 bytes | 512 bytes |
| ML-DSA-65 | 1,952 bytes | 4,000 bytes | 3,293 bytes |
| ML-DSA-87 | 2,592 bytes | 4,864 bytes | 4,627 bytes |

**Library support:**
- OpenSSL 3.5+: native ML-DSA support. OpenSSL 3.3/3.4: requires oqs-provider.
- BoringSSL: no native ML-DSA; use libOQS integration.
- libOQS: full support, all parameter sets.
- Go standard library (`crypto/rsa`): no PQC; use `cloudflare/circl` or `open-quantum-safe/liboqs-go`.
- Rust (`rsa` crate): no PQC; use `pqcrypto-mldsa` or `oqs` crate.

**Protocol support:**
- TLS 1.3: ML-DSA certificate authentication is supported via RFC 8446 extensions when both endpoints use a PQC-capable library.
- X.509 PKI: ML-DSA object identifiers are defined in the IETF draft `draft-ietf-lamps-dilithium-certificates`.
- PKCS#7/CMS: ML-DSA signed CMS objects require the server-side `certmanager.GenerateCSR()` path (`server/internal/certmanager/certmanager.go`).

**Known issues:**
- ML-DSA signatures (3–4 KB) are significantly larger than RSA signatures (256–512 bytes). TLS handshake sizes increase; monitor for MTU-related fragmentation on UDP-based protocols (DTLS, QUIC).
- Intermediate CAs must also be migrated; a chain with a classical intermediate over a PQC leaf does not provide quantum-safe authentication of the chain.

---

### 3.2 ECDSA (Signatures)

**Source algorithms:** ECDSA P-256, ECDSA P-384

**Migration paths:**

| Source | Target | Notes |
|---|---|---|
| ECDSA P-256 | ML-DSA-65 | P-256 is deprecated under CNSA 2.0. Flagged as `high` severity by Janus CNSA policy. ML-DSA-65 at Level 3 is the minimum acceptable replacement. |
| ECDSA P-384 | ML-DSA-65 or ML-DSA-87 | P-384 meets CNSA 2.0 classical transitional requirements but is not quantum-safe. Migrate to ML-DSA-87 for full CNSA 2.0 compliance. |

**Janus policy flag:** `assessCNSA` in `server/internal/policy/` flags ECDSA < P-384 as high severity. ECDSA P-384 itself is flagged as requiring migration in the hybrid phase.

**Library support:** Same as §3.1 (ML-DSA targets are common). ECDSA P-384 is used as the classical fallback in `certmanager.GenerateClassicalCSR()` for hybrid transitions.

**Protocol support:**
- TLS 1.3 with ECDSA P-384 certificates is the recommended classical transitional baseline while ML-DSA infrastructure matures.
- FIDO2/WebAuthn implementations using P-256 will require library updates when migrating to ML-DSA authentication.

---

### 3.3 ECDH and X25519 (Key Agreement)

**Source algorithms:** ECDH P-256, ECDH P-384, X25519

**Migration paths:**

| Source | Target | Notes |
|---|---|---|
| ECDH P-256 | ML-KEM-768 (hybrid) | Hybrid X25519MLKEM768 is the NIST profile target. Provides classical and quantum security during transition. |
| ECDH P-384 | ML-KEM-1024 | CNSA 2.0 profile target. Pure ML-KEM-1024 or hybrid P-384+ML-KEM-1024. |
| X25519 | X25519MLKEM768 | Hybrid construction standardized in IETF RFC 9180 / HPKE. Used as the TLS KEM group in `nist-pqc-2026.yaml` (`preferred_kem: X25519MLKEM768`). |

**Why hybrid?** During the transition period, hybrid KEM provides security against both classical adversaries (who may exploit implementation weaknesses in new PQC algorithms) and quantum adversaries. If either component is compromised, the session key is still protected by the other.

**TLS KEM groups:**

| KEM group | TLS extension value | Status |
|---|---|---|
| X25519MLKEM768 | 0x11EC (IANA) | Deployed (Chrome, Firefox, OpenSSL 3.5+) |
| P-256+ML-KEM-768 | — | Proposed; less deployment |
| ML-KEM-768 (pure) | IANA reserved | Post-transition target |
| ML-KEM-1024 (pure) | IANA reserved | CNSA 2.0 post-transition target |

Janus `discovery/network.rs` detects `TlsHybridPqc` (confidence 0.95) when X25519MLKEM768 is negotiated, upgrading the TLS endpoint assessment from `TlsTls13Classical`.

**Key sizes:**

| Algorithm | Public key | Ciphertext (sender) | Shared secret |
|---|---|---|---|
| X25519 | 32 bytes | 32 bytes | 32 bytes |
| ML-KEM-768 | 1,184 bytes | 1,088 bytes | 32 bytes |
| X25519MLKEM768 | 1,216 bytes | 1,120 bytes | 64 bytes (combined) |
| ML-KEM-1024 | 1,568 bytes | 1,568 bytes | 32 bytes |

**Library support:**
- OpenSSL 3.5+: native ML-KEM and X25519MLKEM768 KEM group.
- OpenSSL 3.3/3.4: X25519MLKEM768 via oqs-provider.
- rustls: hybrid KEM group support available via `rustls-post-quantum` crate (X25519MLKEM768).
- BoringSSL: X25519MLKEM768 available in Chromium fork; upstream support varies by release.
- Go `crypto/tls`: no native ML-KEM; use cloudflare/circl for ML-KEM primitives.

**Known issues:**
- Increased TLS `ClientHello` size (KEM public key is ~1 KB larger than X25519). Some older TLS middleboxes (proxies, DPI appliances) may reject or fragment oversized ClientHellos.
- RFC 9180 HPKE with ML-KEM is the recommended path for non-TLS uses (encrypted messaging, file encryption). This is separate from TLS KEM group negotiation.

---

### 3.4 RSA Key Transport (RSA-OAEP)

**Source:** RSA-OAEP used for session key encapsulation (e.g., in CMS EnvelopedData, S/MIME, older TLS RSA key exchange)

**Migration path:** Replace with ML-KEM direct key encapsulation.

| Source | Target | Notes |
|---|---|---|
| RSA-OAEP-2048 | ML-KEM-768 | Functional replacement: both produce a shared secret. Direct protocol mapping in CMS (RFC 9180 KEM mode). |
| RSA-OAEP-4096 | ML-KEM-1024 | CNSA 2.0 equivalent. |

**Protocol notes:**
- TLS 1.2 RSA key exchange (`TLS_RSA_*` cipher suites) has no forward secrecy and was removed in TLS 1.3. Janus flags TLS 1.2 RSA key exchange as critical. Migration target is TLS 1.3 with X25519MLKEM768.
- For CMS (PKCS#7) encrypted messages: replace `id-RSAES-OAEP` with ML-KEM KEM identifier once the LAMPS WG standards finalize (`draft-ietf-lamps-pqc-kem-ltk`).
- For custom RSA-OAEP file encryption: use HPKE (RFC 9180) with ML-KEM-768 or ML-KEM-1024 as the KEM component.

---

### 3.5 AES Symmetric Encryption

**Source:** AES-128-CBC, AES-128-GCM, AES-128-CTR

**Migration path:** AES is not broken by quantum computing in the same way as asymmetric algorithms. However, Grover's algorithm halves the effective key length, so:
- AES-128 provides ~64 bits of quantum security — below the 128-bit floor required by CNSA 2.0.
- AES-256 provides ~128 bits of quantum security — meets CNSA 2.0.
- The mode does not change (GCM, CTR, CBC remain valid); only the key size matters for quantum resistance.

| Source | Target | Notes |
|---|---|---|
| AES-128-GCM | AES-256-GCM | Drop-in key size upgrade. No protocol or format change required. |
| AES-128-CBC | AES-256-GCM | Upgrade both key size and mode; CBC lacks authentication, which is a separate classical vulnerability. |
| AES-128-CTR | AES-256-GCM | CTR lacks authentication; GCM adds GHASH authentication tag. |

**Janus policy flag:** `assessCNSA` flags AES-128 findings as `high` severity.

**Library support:** AES-256 is universally supported in all TLS libraries, OpenSSL, BoringSSL, ring (Rust), Go `crypto/aes`. No library upgrades required; this is a configuration change.

**Known issues:**
- AES-256-GCM nonce reuse is catastrophic (decrypts ciphertext and leaks the authentication key). Ensure nonce generation uses a CSPRNG or a counter with a unique session key per context. AES-256-CBC does not have this risk but lacks integrity.
- HSM-backed AES key operations require the HSM to support 256-bit keys. Verify HSM firmware and PKCS#11 key generation capabilities (`server/internal/hsm/`).

---

### 3.6 SHA Hash Functions

**Source:** SHA-1, SHA-256, SHA-384

**Migration guidance:**

| Source | Target | Notes |
|---|---|---|
| SHA-1 | SHA-384 or SHA-512 | SHA-1 is classically broken (collision attacks). Janus flags all SHA-1 usage as critical. Immediate replacement required. |
| SHA-256 | SHA-384 or SHA-512 | SHA-256 provides ~128 bits of quantum security (Grover). CNSA 2.0 requires SHA-384 minimum for new applications. Janus CNSA policy flags SHA-256 as requiring review. |
| SHA-384 | Compliant (CNSA 2.0) | 192-bit classical security; ~96-bit quantum security. Accepted by CNSA 2.0. |

**Hash functions are not replaced by PQC algorithms** — they are symmetric primitives and are quantum-resistant at SHA-384 and above. ML-DSA and SLH-DSA use SHA-3 and SHAKE variants internally; their security does not depend on the application's SHA usage.

**Library support:** SHA-384 and SHA-512 are universally supported. No library upgrades required.

---

### 3.7 TLS Protocol Version

**Source:** TLS 1.0, TLS 1.1, TLS 1.2

**Migration path:**

| Source | Target | Notes |
|---|---|---|
| TLS 1.0 | TLS 1.3 | TLS 1.0/1.1 deprecated by RFC 8996 (2021). Critical finding in all Janus profiles. |
| TLS 1.1 | TLS 1.3 | Same as TLS 1.0. |
| TLS 1.2 | TLS 1.3 | TLS 1.2 is acceptable classically but cannot negotiate hybrid PQC KEM groups. Required by NIST and CNSA 2.0 policy profiles. |

**TLS 1.3 with hybrid KEM groups** is the complete target state:
1. Negotiate TLS 1.3 (`require_tls_13: true` in all Janus profiles).
2. Advertise X25519MLKEM768 (NIST profile) or P-384+ML-KEM-1024 (CNSA 2.0 profile) in the `supported_groups` extension.
3. Use ML-DSA-65 or ML-DSA-87 for the server certificate signature algorithm.

**Janus TLS assessment categories** (`discovery/network.rs`):

| Category | Meaning | Severity |
|---|---|---|
| `tls-hybrid-pqc` | TLS 1.3, hybrid KEM negotiated | Compliant |
| `tls-tls13-classical` | TLS 1.3, classical KEM only | Medium (CNSA 2.0: High) |
| `tls-classical-only` | TLS 1.2 or lower, no PQC | High |
| `tls-tls12-weak` | TLS 1.2 without forward secrecy | Critical |
| `tls-no-tls` | Plaintext connection | Critical |

**Library support:**
- TLS 1.3 with X25519MLKEM768: OpenSSL 3.5+ (native), OpenSSL 3.3/3.4 (oqs-provider), rustls with rustls-post-quantum, Chrome/Boringssl (deployed).
- Server-side: nginx 1.27+, HAProxy 3.1+ with OpenSSL 3.5. Apache httpd requires OpenSSL 3.5+.

**Known issues:**
- Some enterprise proxies and DPI appliances do not support TLS 1.3 or drop connections with unrecognized KEM groups. Test `X25519MLKEM768` against all network middleboxes before broad rollout.
- TLS 1.2 with ECDHE and AES-256-GCM is an acceptable interim state for systems that cannot immediately support TLS 1.3.

---

### 3.8 PKCS#7 / CMS Signed Artifacts

**Source:** CMS SignedData with RSA or ECDSA signatures

**Migration path:**

| Source | Target | Notes |
|---|---|---|
| CMS / PKCS#7 with RSA-PKCS1-v1.5 | CMS with ML-DSA-65 or ML-DSA-87 | Requires RFC 9629 (`id-ml-dsa` OIDs). Library support still maturing. |
| CMS with ECDSA P-256 | CMS with ML-DSA-65 | Same OID requirements. |
| PKCS#12 (`.pfx`) with classical keys | PKCS#12 with ML-DSA keys | Not yet universally supported; check HSM and toolkit versions. |

Janus `certmanager.GenerateCSR()` (`server/internal/certmanager/certmanager.go`) calls `GenerateOpenSSLPQCSR()` for ML-DSA and SLH-DSA profiles, invoking `openssl genpkey` with the normalized algorithm name. This requires OpenSSL 3.5+ or an oqs-provider-patched OpenSSL 3.3/3.4.

---

## 4. Library Support Summary

| Library | ML-KEM | ML-DSA | SLH-DSA | Hybrid KEM (X25519MLKEM768) | TLS 1.3 PQC |
|---|---|---|---|---|---|
| OpenSSL 3.5+ | Native | Native | Native | Native | Yes |
| OpenSSL 3.3–3.4 | Via oqs-provider | Via oqs-provider | Via oqs-provider | Via oqs-provider | With oqs-provider |
| BoringSSL | Partial (Chromium fork) | No (upstream) | No | X25519MLKEM768 in Chrome | Chrome only |
| libOQS | Yes | Yes | Yes | Via IETF KEM combiner | Via oqs-provider |
| rustls + rustls-post-quantum | ML-KEM-768 | No (cert only) | No | X25519MLKEM768 | Yes |
| Go crypto/tls | No | No | No | No | No (requires circl) |
| cloudflare/circl | ML-KEM | ML-DSA | SLH-DSA | X25519MLKEM768 | Partial |

**Notes:**
- "Native" means the algorithm is available without additional providers or plugins.
- Library version support is approximate. Consult release notes for your specific version before deploying.
- BoringSSL's upstream (not Chromium fork) status changes frequently; check the BoringSSL commit log.
- The `oqs-provider` for OpenSSL is maintained by the Open Quantum Safe project; pin to a tested version in production.

---

## 5. Janus Policy Profiles: Algorithm Targets Summary

| Profile | Preferred KEM | Preferred Signature | Min RSA | Min DH | TLS |
|---|---|---|---|---|---|
| `nist-pqc-2026.yaml` | X25519MLKEM768 | ML-DSA-65 | 3072 bits | 3072 bits | 1.3 + hybrid PQC |
| `cnsa-2.0.yaml` | ML-KEM-1024 | ML-DSA-87 | 3072 bits | 3072 bits | 1.3 + hybrid PQC |

These values are read at migration command build time by `server/internal/orchestrator/` (`BuildCommand()` reads `preferredKEM` and `preferredSignature` from the active policy profile). There are no hardcoded algorithm defaults in the server — the policy profile is the single source of truth.

---

## 6. Migration Sequencing Guidance

Post-quantum migration should follow this priority order to reduce risk surface efficiently:

1. **Critical first:** Replace TLS 1.0/1.1 and SHA-1 — classical vulnerabilities that pose immediate risk independent of quantum timeline.
2. **Key agreement:** Deploy TLS 1.3 with X25519MLKEM768 (NIST) or ML-KEM-1024 (CNSA 2.0). This is a server/library configuration change with no key management complexity.
3. **Symmetric key sizes:** Upgrade AES-128 to AES-256 across configuration files. Low risk, no protocol changes required.
4. **Certificate signatures:** Migrate CA and end-entity certificates to ML-DSA. Requires PKI infrastructure updates and coordination across all relying parties.
5. **Application-layer signatures:** Migrate PKCS#7/CMS signed artifacts and code-signing certificates to ML-DSA. Requires verifier updates in all consumers.
6. **RSA key transport:** Replace RSA-OAEP in messaging and file encryption with HPKE/ML-KEM. Requires protocol updates in both sender and receiver.

Janus migration commands are dispatched per-finding, but operators should plan the sequence above at the deployment level rather than migrating individual findings in isolation.

---

## 7. References

- FIPS 203 (ML-KEM): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- FIPS 204 (ML-DSA): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- FIPS 205 (SLH-DSA): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
- CNSA 2.0: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
- NIST SP 800-131A Rev.3: https://csrc.nist.gov/pubs/sp/800/131/a/r3/final
- RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180
- X25519MLKEM768 IANA: https://www.iana.org/assignments/tls-parameters/
- Open Quantum Safe / oqs-provider: https://github.com/open-quantum-safe/oqs-provider
- IETF LAMPS WG (PQC in PKIX/CMS): https://datatracker.ietf.org/wg/lamps/documents/
