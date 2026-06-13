# Network Assessment — Capabilities and Limitations

This document describes the network/PKI assessment capabilities of the Janus CryptoBOM agent.
It is derived directly from `agent/src/discovery/network.rs` and reflects what the scanner
actually does today, not aspirational roadmap items.

---

## Scope: Protocols Probed

The agent performs active TCP probing against the endpoints listed under `network_targets` in
`janus-agent.toml`.  For each target, it:

1. Opens a TCP connection (3-second timeout).
2. Negotiates STARTTLS if the port indicates a protocol that requires it (see below).
3. Performs a TLS handshake via `rustls` with a custom certificate verifier that deliberately
   skips chain validation (reconnaissance mode — see Limitations).
4. Extracts protocol parameters from the completed handshake and from the raw ServerHello bytes.

### Plain TLS / HTTPS

Any target that does not match a STARTTLS port is probed as direct TLS.  Port 80 is short-
circuited as cleartext with no TLS handshake attempted.

### STARTTLS variants

| Port | Protocol | Negotiation sequence |
|------|----------|----------------------|
| 25, 587 | SMTP | Banner read → EHLO → STARTTLS |
| 389 | LDAP | STARTTLS extended request (OID 1.3.6.1.4.1.1466.20037) |
| 5432 | PostgreSQL | 8-byte SSLRequest packet; expects `S` response |
| 3306 | MySQL | Handshake packet read → SSLRequest capability flags |

---

## Evidence Collected

For every successfully completed handshake, the following data is captured:

### Protocol parameters (stored in `Evidence.raw_artifact_sha256`)

The field carries a structured pipe-delimited string rather than a hash (DISC-03 design):

```
<tls_version>|<cipher_suite>|<alpn_protocol>|ocsp:<ocsp_status>
```

Example: `TLSv1.3|TLS13_AES_256_GCM_SHA384|h2|ocsp:unchecked`

Fields:
- **tls_version** — negotiated TLS version as reported by rustls (e.g. `TLSv1.3`, `TLSv1.2`)
- **cipher_suite** — IANA cipher suite name (e.g. `TLS13_AES_256_GCM_SHA384`)
- **alpn_protocol** — ALPN protocol negotiated (e.g. `h2`, `http/1.1`, `unknown`)
- **ocsp_status** — revocation status placeholder; currently always `unchecked`
  (see WP-016 Future Work below)

### Named group / key exchange (from raw ServerHello bytes)

The agent parses the TLS `key_share` extension from raw ServerHello bytes to identify the
negotiated named group.  Recognised groups:

| ID (decimal) | Name | PQC hybrid |
|---|---|---|
| 4588 | X25519MLKEM768 | yes |
| 4605 | SecP256r1MLKEM768 | yes |
| 4590 | X448MLKEM1024 | yes |
| 29 | X25519 | no |
| 23 | secp256r1 | no |
| 24 | secp384r1 | no |

The `pqc_hybrid` flag on `NetworkObservation` is set to `true` when a hybrid PQC group is
negotiated.

### Certificate metadata (end-entity certificate)

Extracted from the first certificate in the peer chain via a custom DER parser:

- **subject** — Distinguished Name components (CN, O, C, OU)
- **issuer** — Distinguished Name components
- **not_after** — expiry as Unix timestamp (`certificate_not_after_unix`)
- **signature algorithm** — one of: `SHA256-RSA`, `SHA384-RSA`, `ECDSA-SHA256`,
  `ECDSA-SHA384`, `SHA1-RSA`, `MD5-RSA`, or `unknown`

### Intermediate CA auditing

For each certificate in the chain at index ≥ 1 (intermediate CAs), the agent creates a
`CbomComponent` of type `certificate`.  It flags the component as weak if:

- Signature algorithm contains `SHA1`, `SHA-1`, or `MD5`
- RSA public key is smaller than 2048 bits

Weak intermediate CAs are tagged with `status: "weak-intermediate-ca-observed"`.

---

## Finding Classification

Each probe result is assigned a `TlsAssessmentCategory`, stored in `Evidence.source_type`.

Priority order (highest-priority applied first when multiple conditions are true):

| Category | `source_type` string | Confidence | Condition |
|---|---|---|---|
| `TlsHybridPqc` | `tls-hybrid-pqc` | 0.95 | PQC hybrid group negotiated |
| `TlsCertExpired` | `tls-cert-expired` | 0.85 | `not_after` in the past |
| `TlsCertSelfSigned` | `tls-cert-self-signed` | 0.85 | subject == issuer (both non-empty) |
| `TlsTls13Classical` | `tls-tls13-classical` | 0.90 | TLS 1.3, no hybrid PQC group |
| `TlsTls12Weak` | `tls-tls12-weak` | 0.90 | TLS 1.2 |
| `TlsClassicalOnly` | `tls-classical-only` | 0.90 | TLS < 1.2, or version unrecognised |
| `NoTls` | `tls-no-tls` | 0.95 | Port 80 (cleartext short-circuit) |
| `Unreachable` | `tls-unreachable` | 0.50 | TCP connect failed or timed out |
| `TlsHandshakeFailed` | `tls-handshake-failed` | 0.50 | TCP OK, TLS handshake error |

Confidence 0.50 on connectivity errors reflects that firewalls and transient failures are
indistinguishable from a missing TLS listener at scan time.

---

## Limitations

The following capabilities are **not** implemented in the current scanner:

### No live OCSP check (WP-016)

The `ocsp_status` field in TLS metadata is always `"unchecked"`.  The agent does not fetch
the OCSP responder URL from the certificate's Authority Information Access (AIA) extension,
does not submit an OCSP request, and does not interpret stapled OCSP responses embedded in
the TLS handshake.

### No CRL download

The agent does not fetch or parse Certificate Revocation Lists from the CRL Distribution
Points (CDP) extension.  Revoked certificates are not detected.

### No HPKP / DANE

HTTP Public Key Pinning and DNS-Based Authentication of Named Entities are not checked.

### No Certificate Transparency log check

The agent does not query CT logs or verify SCT extensions in certificates.

### Chain validation deliberately disabled

The rustls `NoCertificateVerification` verifier is used for all probes.  This allows the
agent to collect TLS metadata from hosts with expired, self-signed, or untrusted certificates
without aborting the handshake, but it means hostname mismatch and chain validation errors
are not surfaced as `TlsCertInvalidChain` findings during normal scanning.

### TLS 1.0 / 1.1 not probed

rustls does not support TLS versions below 1.2.  Servers that offer only TLS 1.0 or 1.1 will
produce a `tls-handshake-failed` finding, not a specific old-version finding.

---

## Future Work (WP-016)

The following enhancements are planned under work package WP-016:

1. **Live OCSP check** — parse AIA extension from end-entity DER, HTTP GET/POST the
   responder, interpret `good` / `revoked` / `unknown` response, update `ocsp_status` field.

2. **OCSP stapling detection** — check for a stapled OCSP response in the TLS handshake
   `CertificateStatus` message and validate it without a network round-trip.

3. **CRL download** — parse CDP extension, download CRL, verify against end-entity serial
   number.

4. **CT log query** — query a CT log API (e.g. `crt.sh`) for the end-entity certificate's
   SHA-256 fingerprint and flag certificates not present in any known log.

5. **TLS 1.0/1.1 detection** — probe with a TLS 1.0/1.1 ClientHello using a raw TCP socket
   (bypassing rustls) and surface old-version findings explicitly.
