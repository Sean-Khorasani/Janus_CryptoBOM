# Maturity-tag changes vs docs/RESEARCH.md (Jan 2026)

Verified 2026-06-12 against IETF Datatracker / IANA / RFC Editor (see SOURCES.json).

| Item | Old tag | New tag | Why |
|---|---|---|---|
| X25519MLKEM768 TLS hybrid (ecdhe-mlkem) | [PROD] ⚠ draft | [PROD] (RFC imminent) | At IESG, telechat 2026-06-18; codepoints 4587/4588/4589 permanent in IANA registry |
| ML-DSA X.509 certificates | [EMRG] ⚠ | **[STD]** | Published as RFC 9881 (Oct 2025); CMS = RFC 9882 |
| ML-KEM X.509 / CMS | [EMRG] ⚠ | **[STD]** | RFC 9935 / RFC 9936 (Mar 2026) |
| SLH-DSA X.509 certificates | [EMRG] ⚠ | **[STD]** | RFC 9909 (Dec 2025). Bibliography correction: RFC 9814 is SLH-DSA-in-CMS, not certificates |
| Related certificates (multi-auth binding) | [EXP→EMRG] ⚠ | **[STD]** | RFC 9763 (Jun 2025) |
| "Chameleon" delta certs | [EXP→EMRG] ⚠ | **[EXP] (dead)** | draft-bonnell-lamps-chameleon-certs expired Oct 2025, no successor — drop from plans |
| Composite signatures / KEM | [EMRG] ⚠ | [EMRG] (late-stage) | At IESG with pinned OID arcs 1.3.6.1.5.5.7.6.37–66; not yet RFCs |
| Merkle Tree Certificates | [EXP→EMRG] ⚠ | **[EXP]** | Moved to new PLANTS WG; architecture still in flux — downgrade from the report's optimistic trajectory |
| ML-DSA in JOSE/COSE | [EMRG] ⚠ | **[STD]** | RFC 9964 (May 2026) + IANA COSE registrations (Recommended=Yes) |
| OpenPGP PQC | [EMRG] ⚠ | [EMRG] | IESG-approved, RFC Editor queue blocked — unchanged tag, status advanced |
| SSH ML-KEM hybrid KEX | [PROD] ⚠ | [PROD] | draft-ietf-sshm-mlkem-hybrid-kex-10 in RFC Editor queue |
| SSH ML-DSA host/user keys | (pending ⚠) | **[EXP]** | Only unadopted individual drafts exist |
| Pure ML-KEM TLS groups | (not tagged) | [EMRG] | WG-adopted but in post-WGLC rework; codepoints 512–514 live |

All other report tags unchanged pending the remaining verification domains (NIST, gov, ecosystem, cryptanalysis, tooling — see VERIFICATION.md residuals).
