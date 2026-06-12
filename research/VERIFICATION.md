# RESEARCH.md Live-Source Verification

**Date checked:** 2026-06-12. Method: each ⚠-flagged claim fetched from its primary source (IETF Datatracker, IANA registries, RFC Editor). Format per item: original statement → current status → action.

**Coverage status (honest residual):** Of the six verification domains (NIST, IETF, government timelines, ecosystem, cryptanalysis/implementations, competitive tooling), **only the IETF domain completed verification this session** — the other five research passes were aborted by session rate limits (see JOURNAL.md 2026-06-12). Their claims in RESEARCH.md remain ⚠-unverified and MUST NOT be used for compliance decisions until a follow-up pass completes. This file will be extended in place.

---

## IETF / IANA (verified 2026-06-12, complete)

| # | Item | Original (Jan 2026) | Current status (2026-06-12) | Action | Tag |
|---|---|---|---|---|---|
| 1 | Hybrid ML-KEM TLS (draft-ietf-tls-ecdhe-mlkem) | ⚠ draft | **-05** (2026-05-26), submitted to IESG, on telechat 2026-06-18; RFC imminent. IANA TLS groups: **4587 SecP256r1MLKEM768, 4588 X25519MLKEM768, 4589 SecP384r1MLKEM1024** (Recommended=N); 25497 X25519Kyber768Draft00 OBSOLETE | updated | [PROD] |
| 2 | Pure ML-KEM TLS groups | ⚠ draft-connolly | Adopted → **draft-ietf-tls-mlkem-07** (Informational, "Revised I-D Needed" post-WGLC). IANA: **512/513/514 MLKEM512/768/1024** | updated | [EMRG] |
| 3 | ML-DSA in TLS | ⚠ | **draft-ietf-tls-mldsa-03**, IESG "Waiting for AD Go-Ahead". SignatureScheme **0x0904/0x0905/0x0906 mldsa44/65/87**; SLH-DSA schemes 0x0911–0x091C also registered | updated | [EMRG] |
| 4 | ML-DSA X.509 certs | ⚠ draft-ietf-lamps-dilithium-certificates | **RFC 9881** (Oct 2025, Proposed Standard). ML-DSA in CMS = **RFC 9882** (Oct 2025) | updated | [STD] |
| 5 | ML-KEM X.509 / CMS | ⚠ drafts | **RFC 9935** (X.509) and **RFC 9936** (CMS KEMRecipientInfo), both **March 2026** — post-horizon | updated | [STD] |
| 6 | SLH-DSA certs RFC number | report bibliography ambiguous | **Correction:** RFC 9814 (Jul 2025) = SLH-DSA in **CMS**; SLH-DSA **X.509 certs = RFC 9909** (Dec 2025) | corrected | [STD] |
| 7 | Composite sigs / KEM (LAMPS) | ⚠ drafts | **composite-sigs-19** (submitted to IESG, OIDs 1.3.6.1.5.5.7.6.**37–54**); **composite-kem-14** (Publication Requested, OIDs **.55–66**). Not RFCs | updated | [EMRG] |
| 8 | Related/"chameleon" certs | ⚠ drafts | Related certs = **RFC 9763** (Jun 2025). **Chameleon draft EXPIRED** (dead end, no successor) | updated / retracted | [STD] / [EXP] |
| 9 | Merkle Tree Certificates | ⚠ draft-davidben (TLS WG) | Re-homed: **draft-ietf-plants-merkle-tree-certs-04** (2026-05-24) in **new PLANTS WG** ("PKI, Logs, And Tree Signatures") | updated | [EXP] |
| 10 | OpenPGP PQC | ⚠ draft | **draft-ietf-openpgp-pqc-17**, IESG-approved, RFC Editor queue (Blocked). Not yet an RFC | confirmed (progress) | [EMRG] |
| 11 | ML-DSA in JOSE/COSE | ⚠ draft | **RFC 9964** (May 2026): COSE algs **ML-DSA-44=-48, -65=-49, -87=-50** (Recommended=Yes), key type **AKP=7**. SLH-DSA COSE still draft | updated | [STD] |
| 12 | RFC 9794 hybrid terminology | ⚠ | Confirmed: RFC 9794, Jun 2025, Informational (PQUIP) | confirmed | [SPEC] |
| 13 | SSH PQ | mlkem768x25519 default; sigs pending ⚠ | KEX: **draft-ietf-sshm-mlkem-hybrid-kex-10** in RFC Ed queue (mlkem768x25519-sha256 etc.). ML-DSA SSH keys: individual drafts only (sfluhrer-06, rpe-03), not adopted | confirmed / updated | [PROD] kex; [EXP] keys |
| 14 | KEMTLS/AuthKEM | [EXP] | draft-celi-wiggers-tls-authkem-07, still individual, unadopted | confirmed | [EXP] |
| 15 | PQUIP guidance | — | pqc-engineers-14 and hybrid-signature-spectrums-07 in RFC Ed queue; hybrid-design-16 (TLS) in RFC Ed queue | updated | [SPEC] |

**New since the report's horizon (Jan 2026):** RFC 9935/9936 (ML-KEM X.509/CMS, Mar 2026); RFC 9964 (ML-DSA COSE/JOSE, May 2026); PLANTS WG chartered; composite sigs/KEM at IESG with pinned OID arcs; ecdhe-mlkem on 2026-06-18 telechat.

**Could not verify (stated by the research pass):** PLANTS charter approval date; OpenPGP-PQC RFC-Editor block reason.

## Direct implications for Janus detection/feature work

1. Detection of TLS groups 4587/4588/4589 and 512/513/514, and SignatureSchemes 0x0904–0x0906 / 0x0911–0x091C, is now standards-anchored — the agent's network probe should classify these codepoints explicitly (and treat 25497 as "obsolete draft hybrid — flag for upgrade").
2. Certificate scanning can now name concrete OIDs: ML-DSA (RFC 9881), ML-KEM (RFC 9935), SLH-DSA (RFC 9909), composite arcs 1.3.6.1.5.5.7.6.37–66 — a PQ-cert recognizer is implementable today.
3. JOSE/COSE tokens with `alg` ML-DSA-44/65/87 are standardized — token-scanning rules can mark them PQ-OK rather than unknown.

---

*Pending sections: NIST · Government timelines · Ecosystem (Windows CNG/SChannel, OpenSSL, distros) · Cryptanalysis & implementations · Competitive tooling.*
