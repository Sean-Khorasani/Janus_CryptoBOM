# Janus CryptoBOM — Competitive Analysis & Strategic Feature Roadmap

> Research conducted June 2026. Sources: vendor product pages, press releases, industry analyst reports, NIST NCCoE publications, and open-source project documentation.

---

## 1. Competitor Profiles

### 1.1 SandboxAQ AQtive Guard (formerly Cryptosense)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2022 (spin-out from Alphabet) |
| **Funding** | $500M+ (Series E, 2024) |
| **HQ** | Palo Alto, CA |
| **Deployments** | U.S. Department of War (DoW) CIO — 5-year ACDI agreement; Kingdom of Bahrain — 60+ ministries; DISA QRC PKI prototype |
| **Core Differentiator** | Large Quantitative Models (LQMs) — AI-driven noise filtering and root-cause analysis vs. traditional rules |

**Discovery:** Six scanning surfaces (code, runtime, pipelines, network, cloud, endpoints). Integrates with CrowdStrike Falcon, Palo Alto Networks firewalls.

**PQC:** Researchers co-authored NIST standards. PQC impact simulation before enforcement. ACDI (Automated Cryptographic Discovery & Inventory) deployed at DoW scale.

**Remediation:** Automated credential rotation, certificate renewal. Runtime guardrails block attacks at inference speed. GenAI assistant for standards navigation.

**Pricing:** Enterprise SaaS + professional services. Not publicly disclosed.

**Key Weakness:** Focused on AI-agent/NHI security alongside crypto. May dilute crypto-specific depth. No process memory scraping for unencrypted keys. Limited Windows-specific coverage (no Schannel/CNG/CAPI depth).

---

### 1.2 Keyfactor (Command + AgileSec + InfoSec Global)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2001 (Keyfactor), 2016 (InfoSec Global), merged 2024 |
| **Funding** | Private equity (Insight Partners) |
| **HQ** | Independence, OH |
| **Deployments** | 1,700+ enterprise customers, 900M+ certificates managed |

**Discovery:** AgileSec Analytics — full asset inventory of certs, keys, libraries, protocols, HSMs, KMS, CI/CD pipelines, cloud workloads. Deployable via Tanium, CrowdStrike, ServiceNow, Azure Sentinel, Venafi, Entrust.

**PQC:** Hybrid RSA/ML-DSA, ML-KEM/RSA, ML-DSA/ECDSA certificate issuance via EJBCA. PQC Lab (free SaaS PKI sandbox). Bouncy Castle 1.80+ crypto library integration. PKI-centric approach to PQC readiness.

**Remediation:** AgileSec Agility — remediate without source code changes. Right-click renew/revoke from Command dashboard. Automated approval workflows.

**Pricing:** Per-certificate/per-node model. Enterprise licensing.

**Key Weakness:** Certificate-centric (not full CBOM/SBOM). No process memory scanning. No binary PE/ELF symbol analysis. Windows coverage limited to certificate stores. No STARTTLS protocol probing for SMTP/LDAP/PostgreSQL.

---

### 1.3 IBM Quantum Safe (zCDI + Explorer + Remediator)

| Dimension | Details |
|-----------|---------|
| **Founded** | 1911 (IBM); PQC program launched 2020 |
| **HQ** | Armonk, NY |
| **Deployments** | zCDI GA June 2025; Palo Alto Networks joint solution (early 2026) |

**zCDI (IBM Z Crypto Discovery & Inventory):** Mainframe-only. Consolidates application, job, network data. Predefined NIST/CNSA compliance profiles. CycloneDX 1.6 CBOM export.

**Quantum Safe Explorer:** Scans source code and object code for cryptographic artifacts. CBOM generation. Portfolio view for insights. **Remediator:** Hybrid cryptographic environments. "Harvest now, decrypt later" defense. Remediation patterns for apps, networks, third-party integrations.

**Key Weakness:** Mainframe-centric. zCDI is IBM Z only. Explorer/Remediator just announced (May 2025). Limited non-mainframe coverage. No binary import/export analysis. No process memory scanning. Expensive enterprise licensing.

---

### 1.4 Thales PQC Agility (Luna HSM + HSE)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2007 (Thales e-Security); Thales Group |
| **HQ** | Paris, France |
| **Deployments** | Global HSM leader in banking, government, defense |

**HSM Capabilities:** Luna HSM v7.9.2 (Feb 2026) — full ML-KEM/ML-DSA support. Hybrid KEM for NTLS, SSH, REST API. PQC key wrapping/unwrapping. LMS/HSS multi-part signatures. FIPS 140-3 Level 3.

**Crypto Agility:** Firmware updates (no hardware swap). FPGA updates. PKCS#11 extensions.

**HSE (High Speed Encryptor):** Network-layer PQC for transport protection.

**Key Weakness:** HSM/appliance boundary only. No endpoint agent. No source code scanning. No dependency analysis. No process memory inspection. CBOM capability is basic (key inventory only, not code-level). No STARTTLS probing.

---

### 1.5 PQShield (UltraPQ Suite)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2018 (Oxford spin-out) |
| **Funding** | $37M Series B (2024) |
| **HQ** | Oxford, UK |
| **Deployments** | U.S. government via Carahsoft; CNSA 2.0-hardened hardware IP |

**Hardware IP:** PQPlatform-TrustSys — PQC-first Root of Trust for ASIC/FPGA. SCA/FIA countermeasures. FIPS 140-3 certified. ML-DSA/ML-KEM/LMS with classical fallback.

**Software:** PQCryptoLib-Embedded (PQMicroLib) for constrained devices. CNSA 2.0 compliance with phase-in roadmap (2025-2035).

**Key Differentiator:** Co-author of NIST PQC standards. Only competitor with hardware-level SCA/FIA countermeasures. Side-channel validated by eShard.

**Key Weakness:** No endpoint agent for discovery. No source/dependency scanning. No network TLS probing. No migration orchestration. Hardware IP supplier — not a posture management platform. No dashboard for fleet management.

---

### 1.6 QuSecure (QuProtect R3)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2019 |
| **Funding** | $28M Series A (2023) |
| **HQ** | San Mateo, CA |
| **Deployments** | U.S. Army, Air Force, telecoms, energy, financial institutions, cloud providers |

**Recon:** Automated cryptographic asset discovery. Algorithm-level detection across network, cloud, apps, endpoints. Live inventory updates. Available as complimentary tool.

**Resilience:** Runtime algorithm switching — no source code changes. Zero-downtime remediation. Policy-based enforcement across systems. Works with existing infrastructure (no rip-and-replace). Cisco router IKEv2/IPsec support.

**Reporting:** CBOM generation (one-click). NIST, NSM-10, EO 14028, CNSA 2.0, GDPR, CMMC 2.0 alignment. Audit-ready compliance reporting.

**Key Differentiator:** Runtime algorithm switching at network level without touching application code. Zero-downtime migration. Named Frost & Sullivan "Global Product Leader in PQC Industry."

**Key Weakness:** Network-layer focus — no deep code-level scanning (source, binary, dependency). No process memory scanning for unencrypted keys. Limited Windows OS-level coverage (no Schannel, CNG/CAPI, DPAPI). No STARTTLS probing for mail/database protocols.

---

### 1.7 Crypto4A (QxHSM / QxEDGE / QxVault)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2017 |
| **HQ** | Ottawa, Canada |
| **Deployments** | Government, defense, financial services |

**QASM Architecture:** FPGA-based — new PQC algorithms via firmware updates. First HSM submitted for FIPS 140-3 L3 with all NIST PQC algorithms (FIPS 203/204/205 + LMS). FIPS 140-2 L3 certified; FIPS 140-3 L3 pending.

**Seed-Based Key Management:** Compact seed custody (tens of bytes per key). Deterministic re-derivation within QASM boundary.

**QxVault:** Integrated secrets management platform with built-in PQC HSM.

**Key Weakness:** HSM only — no discovery, no scanning, no migration orchestration. No endpoint agent. No network probing. No dashboard. Infrastructure component, not a platform.

---

### 1.8 DigiCert Trust Lifecycle Manager

| Dimension | Details |
|-----------|---------|
| **Founded** | 2003 |
| **HQ** | Lehi, UT |
| **Deployments** | Public CA for 89% of Fortune 500 |

**PQC Certificates:** ML-DSA & SLH-DSA issuance via CSR, EST, REST API. Key escrow for PQC certs.

**Discovery:** Network sensors + host agents for certificate inventory. Maps certs to deployment context and owner.

**PQC Maturity Model:** Novice → Apprentice → Practitioner → Master levels. Quantum Advisor Program for readiness planning.

**Certificate Lifespan:** 200 days (2026) → 100 days (2027) → 47 days (2029) — driving automation urgency.

**Key Weakness:** Certificate-only scope. No cryptographic algorithm discovery in code. No binary analysis. No dependency parsing. No network TLS key exchange analysis. PKI/certificate lifecycle tool, not a full crypto posture management platform.

---

### 1.9 Entrust Cryptographic Security Platform

| Dimension | Details |
|-----------|---------|
| **Founded** | 1994 |
| **HQ** | Minneapolis, MN |
| **Deployments** | Global PKI/HSM installed base |

**Unified Platform (May 2025):** Industry's first unified keys + secrets + certificates management. PKI Hub (PQC-ready container-based PKI). nShield HSM integration. PQ Lab for PQC migration simulation. Hybrid X.509 certificate testing.

**Public Cert Business:** Migrated to Sectigo (Sept 2025) — 500K+ certificates. Entrust now focuses on private PKI + HSM.

**Key Weakness:** PKI/HSM centric. No endpoint agent. No source code scanning. No binary analysis. No network probing. No process memory inspection. No CBOM generation. Infrastructure/management layer, not discovery.

---

### 1.10 ISARA Corp (now Cisco)

| Dimension | Details |
|-----------|---------|
| **Founded** | 2015; acquired by Cisco 2023 |
| **HQ** | Waterloo, Canada (now San Jose, CA) |
| **Status** | Crypto-agility toolkit integrated into Cisco security portfolio |

**Original ISARA:** Radiate Toolkit for drop-in PQC algorithm replacement. Catalyst crypto-agility SDK. X.509 hybrid certificate testing. IETF PQC protocol contributions.

**Post-Acquisition:** ISARA technology integrated into Cisco Secure portfolio (routers, firewalls, VPN). No longer a standalone product. Cisco's crypto agility roadmap follows CNSA 2.0 timelines.

**Key Weakness:** No longer independently available. Absorbed into Cisco ecosystem. Limited to Cisco hardware/software. No discovery/inventory capabilities.

---

## 2. Comparative Feature Matrix

| Capability | Janus | SandboxAQ | Keyfactor | IBM QS | Thales | PQShield | QuSecure | DigiCert | Entrust |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| **Discovery — Source Code** | ✅ Regex + LLM intent | ✅ LQM | ❌ | ✅ Explorer | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Discovery — Binary PE/ELF/Mach-O** | ✅ Import/export symbols | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Discovery — Dependencies** | ✅ 8 package managers | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Discovery — Network TLS Probe** | ✅ + STARTTLS | ✅ | ✅ Sensors | ❌ | ❌ | ❌ | ✅ | ✅ Sensors | ❌ |
| **Discovery — Process Memory** | ✅ Win+Linux PEM scan | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Discovery — Windows OS** | ✅ Schannel/CNG/CAPI/DPAPI/GPO/HTTP.sys | Partial | Partial | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Discovery — Cert Store** | ✅ Windows+Java | ✅ | ✅ | ✅ zCDI | ❌ | ❌ | ✅ | ✅ | ✅ PKI |
| **CBOM/CycloneDX 1.6** | ✅ | ✅ | Partial | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **NIST FIPS 203/204/205** | ✅ | ✅ | ✅ | ✅ | ✅ HW | ✅ HW | ✅ | ✅ | ✅ |
| **CNSA 2.0 Support** | ✅ Full rules | ✅ | Partial | ✅ | ✅ | ✅ | ✅ | ✅ | Partial |
| **Context-Aware Severity** | ✅ Verify/parse/negotiate | ✅ LQM | Partial | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Active Migration** | ✅ Atomic+rollback | ✅ LQM-driven | ✅ Cert renewal | ✅ Remediator | ❌ | ❌ | ✅ Runtime | ✅ Cert | ❌ |
| **Migration Signed Directives** | ✅ HMAC-SHA256 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Webhook/SIEM Integration** | ✅ + circuit breaker | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Real-Time Dashboard** | ✅ + WebSocket | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Structured Logging** | ✅ slog/tracing | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **LLM-Powered Analysis** | ✅ Intent + patches | ✅ GenAI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Plugin/Extension System** | ✅ TOML-based | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Resource-Limited Plugins** | ✅ cgroups/Job obj | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Schema Versioning** | ✅ 7 migrations | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Air-Gapped Operation** | ✅ Offline SQLite | ❌ | Partial | ❌ | ✅ HSM | ✅ HW | ✅ | ❌ | ❌ |
| **Open Source** | ✅ Apache 2.0 | ❌ Proprietary | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Pricing Model** | Free OSS | Enterprise SaaS | Per-cert/node | Enterprise | HSM HW | IP license | Enterprise SaaS | Per-cert | Per-cert/HSM |

---

## 3. Market Trends & Analyst Signals

### 3.1 Regulatory Timeline Pressure

| Deadline | Event |
|----------|-------|
| **2025** | CNSA 2.0 software/firmware signing compliance required |
| **2026** | CNSA 2.0 networking equipment (VPN, routers) compliance required; TLS cert validity → 200 days |
| **2027** | CNSA 2.0 OS compliance; TLS cert validity → 100 days |
| **2029** | TLS cert validity → 47 days; Gartner quantum readiness deadline |
| **2030** | NIST classical crypto deprecation begins; CNSA 2.0 niche equipment |
| **2033** | CNSA 2.0 browsers/cloud/OS full compliance |
| **2035** | NIST complete RSA/ECDSA/ECDH disallowance; CNSA 2.0 legacy system deadline |

### 3.2 Industry Signals

- **Frost & Sullivan** named QuSecure "Global Product Leader in PQC Industry" — signals market validation for orchestration-layer PQC
- **Gartner 2026 Top Cybersecurity Trends**: PQC is a central focus area; market projected to grow from $300M (2024) to $3.5B+ (2029)
- **ESG Brief (Feb 2025)**: Only 20% of organizations feel prepared for PQC. First step = full visibility via discovery.
- **CA/Browser Forum**: Certificate lifespan compression converging with quantum deadlines — automation imperative
- **NIST NCCoE PQC Migration Project**: 30+ participants including SandboxAQ, IBM, Thales, DigiCert, Entrust, PQShield, Keyfactor, Crypto4A, Microsoft, AWS, Google, Cisco
- **Linux Foundation PQCA**: IBM donated CBOM tools; OQS and PQ Code Package gaining traction

### 3.3 Open Source Landscape

| Tool | Scope | Maturity |
|------|-------|----------|
| **PQCA CBOMkit** | Java/Python source scanning via SonarQube plugin; container scanning; GitHub Action | Early (40-50 GitHub stars) |
| **cdxgen** | General SBOM generation; CycloneDX format; supports 20+ languages | Mature (npm, 1K+ stars) |
| **QRAMM CSNP** | CLI source scanner for 50+ classical algorithms; basic TLS endpoint sweeping | Niche |
| **Open Quantum Safe (OQS)** | Reference PQC algorithm implementations; TLS 1.3 integration | Mature (1.5K+ stars) |
| **PQ Code Package** | High-assurance C/assembly ML-KEM/ML-DSA | Active (NIST reference) |

**None of the open-source tools provide:** process memory scanning, Windows OS-level discovery, active migration with rollback, HMAC-signed directives, fleet management dashboard, WebSocket real-time updates, LLM-powered analysis, or plugin systems.

---

## 4. Janus Gap Analysis

### Where Janus Leads

1. **Broadest Discovery Surface**: The only platform scanning source + binary + dependencies + network (with STARTTLS) + process memory (Win+Linux) + Windows OS registry/cert stores
2. **Active Migration with Safety**: Only HMAC-signed, atomic migration with automated rollback. QuSecure does runtime switching but no cryptographic directive signing. SandboxAQ does renewal but no config-file patching.
3. **Open Source**: Apache 2.0 — no competitor offers this. PQCA CBOMkit is OSS but far less capable.
4. **Air-Gapped Operation**: Offline SQLite with encrypted storage. QuSecure requires connectivity. SandboxAQ is SaaS.
5. **Plugin Architecture**: Extensible via TOML-based plugins with OS-enforced resource limits (cgroups/Job objects). No competitor has this.
6. **LLM Integration**: Both intent classification and remediation patch generation built-in. Only SandboxAQ has comparable GenAI (LQMs).

### Where Janus Lags

| Gap | Best Competitor | Janus Status |
|-----|-----------------|-------------|
| **AI-Driven Noise Filtering** | SandboxAQ LQMs | LLM-based but not LQM-scale |
| **Runtime Algorithm Switching** | QuSecure Resilience | ❌ Not implemented |
| **HSM/PKI Integration** | Keyfactor, Thales, Entrust | ❌ CSR generation only |
| **Certificate Lifecycle Automation** | DigiCert, Keyfactor | ❌ Cert discovery only |
| **Hybrid Certificate Issuance** | Keyfactor EJBCA, Entrust | ❌ CSR only, no issuance |
| **Hardware-Level Side-Channel Protection** | PQShield | ❌ N/A (software-only) |
| **Cloud-Native SaaS Deployment** | SandboxAQ, DigiCert | ❌ On-prem only |
| **SCA/SAST Tool Integration** | Keyfactor (Tanium, CrowdStrike), CBOMkit (SonarQube) | ❌ No integrations |
| **PQC Lab/Sandbox** | Keyfactor PQC Lab, Entrust PQ Lab | ❌ No simulation environment |
| **Regulatory Compliance Reports** | QuSecure (NSM-10, EO 14028) | ❌ Basic CBOM only |
| **Crypto Center of Excellence (CCoE) Framework** | DigiCert Maturity Model | ❌ No maturity assessment |
| **Quantum-Readiness Scoring** | DigiCert PQC Maturity Model | Basic safety score only |
| **Third-Party Library Vuln Database** | SandboxAQ, OSV.dev | OSV.dev integration only |
| **FIPS 140-3 Validated Crypto** | Thales, PQShield, Crypto4A | ❌ N/A (software platform) |
| **Mainframe Support** | IBM zCDI | ❌ |

---

## 5. Strategic Feature Recommendations (Prioritized)

### Tier 1 — Immediate (Make Janus the Clear Leader)

| # | Feature | Rationale | Competitor Gap |
|---|---------|-----------|----------------|
| **F1** | **PQC Migration Simulator (Sandbox Mode)** | Test migrations in sandbox before enforcement — SandboxAQ's most praised feature | SandboxAQ has "PQC Impact Simulation"; no other platform does this |
| **F2** | **SAST/CI-CD Integrations** | SonarQube plugin, GitHub Action, GitLab CI template — reach developers where they work | CBOMkit has SonarQube; Keyfactor integrates with Tanium/CrowdStrike |
| **F3** | **Fleet Quantum-Readiness Score** | Per-asset and per-fleet 0-100 quantum readiness scoring with drill-down — DigiCert's maturity model applied to technology | No competitor has automated scoring at asset granularity |
| **F4** | **Compliance Report Generator** | One-click NSM-10, EO 14028, OMB M-23-02, CNSA 2.0, GDPR, CMMC 2.0 PDF reports with audit trail | QuSecure has CBOM-based reports; Entrust has governance consulting |
| **F5** | **Runtime Algorithm Interception (QuSecure Parity)** | Network-level algorithm upgrade without touching source code — QuSecure's key differentiator | QuSecure Resilience does this; Janus currently requires config patching |
| **F6** | **Hybrid Certificate Issuance Pipeline** | Full lifecycle: CSR → CA issuance → deployment → renewal for hybrid RSA+ML-DSA certs | Keyfactor EJBCA + Entrust PKI Hub do this end-to-end |

### Tier 2 — Short-Term (Deepen the Moat)

| # | Feature | Rationale |
|---|---------|-----------|
| **F7** | **Increased Confidence Analysis** | Move beyond LLM-based intent to statistical models (LQM-like signal/noise filtering) for fewer false positives | 
| **F8** | **Cloud-Native Deployment** | Helm chart for Kubernetes, Terraform module, AWS/Azure/GCP marketplace listings | 
| **F9** | **PQC Lab (Free Tier)** | Publicly accessible sandbox for testing PQC certificates, hybrid TLS, migration diffs — drives adoption |
| **F10** | **Cryptographic Health SLA Dashboard** | SLAs for: key rotation cadence, cert expiry windows, algorithm deprecation deadlines. Automated breach alerts |
| **F11** | **Third-Party Advisory Integration** | Beyond OSV.dev — integrate CVE, NVD, GitHub Advisory, vendor-specific bulletins (OpenSSL, Bouncy Castle, Go crypto) |
| **F12** | **Agent Auto-Upgrade** | Server-pushed agent binary updates with signature verification — fleet-wide upgrade orchestration |

### Tier 3 — Medium-Term (Expand the Platform)

| # | Feature | Rationale |
|---|---------|-----------|
| **F13** | **HSM Integration Layer** | PKCS#11 connector for Thales Luna, Crypto4A QxHSM, Entrust nShield — key lifecycle visibility inside HSMs |
| **F14** | **Mainframe Agent (z/OS)** | Lightweight agent for IBM Z crypto discovery — parity with IBM zCDI for the mainframe market |
| **F15** | **Container/Kubernetes Operator** | Scan container images (like CBOMkit-theia), detect crypto in Kubernetes Secrets, ConfigMaps, service meshes |
| **F16** | **Side-Channel Vulnerability Detection** | Test-level detection of timing side-channels, cache attacks, power analysis vulnerabilities in crypto implementations |
| **F17** | **Post-Quantum VPN/IKEv2 Integration** | Like QuSecure + Cisco — deploy PQC algorithms on VPN endpoints, IPsec tunnels, SD-WAN |
| **F18** | **Crypto Center of Excellence (CCoE) Toolkit** | Templates, maturity assessments, stakeholder dashboards, training modules — operationalize crypto governance |

### Tier 4 — Long-Term (Visionary)

| # | Feature | Rationale |
|---|---------|-----------|
| **F19** | **Formal Verification of Crypto Implementations** | Partner with ProVerif/Tamarin/Verifpal for automated formal verification of discovered crypto implementations |
| **F20** | **PQC Performance Benchmarking** | Per-machine benchmarking of PQC algorithm performance (ML-KEM ops/sec, ML-DSA sign/verify throughput) to guide migration priorities |
| **F21** | **Zero-Knowledge Proof Discovery** | As ZKP adoption grows, detect and inventory ZK proof systems, circuits, and proving/verification keys |
| **F22** | **Cross-Organization Crypto Risk Exchange** | Anonymized industry benchmarking — "how does your crypto posture compare to peers in your sector?" |
| **F23** | **Homomorphic Encryption Readiness** | Inventory HE library usage, assess FHE scheme appropriateness, benchmark HE performance |
| **F24** | **Quantum Key Distribution (QKD) Integration** | If QKD networks become mainstream, integrate with QKD key management interfaces (ETSI QKD API) |

---

## 6. Janus Differentiator Summary

### What Makes Janus Unique (and must be protected)

1. **Broadest discovery surface in the industry** — 7 distinct scan modalities (source, binary, dependency, network TLS/STARTTLS, process memory, Windows OS, plugins). No single competitor covers more than 4.

2. **Only platform with cryptographic safety guarantees** — HMAC-signed migration commands, atomic rollback, path traversal sandboxing, file extension allowlisting, config drift detection. QuSecure switches algorithms but cannot prove the command was authorized.

3. **Only open-source PQC posture management platform** — Apache 2.0. PQCA CBOMkit is OSS but source-only. This is a massive strategic advantage for government, defense, and regulated industries.

4. **Only platform with memory-level private key detection** — Reads process memory on both Windows and Linux searching for unencrypted PEM private keys. No competitor attempts this.

5. **Plugin architecture with resource limits** — Cgroups v2 / Job Objects enforcement on third-party plugins. Extensible without sacrificing security.

### The "Janus Moat" — Three Things No Competitor Can Easily Copy

1. **Combination of discovery breadth + active safe migration** — Most competitors do one or the other
2. **Open-source model with enterprise safety** — Government/defense can audit the code; enterprises get signed, safe migrations
3. **Windows-first deep integration** — Schannel, CNG/CAPI, DPAPI, HTTP.sys, GPO, certutil — no competitor has this depth on Windows

---

## 7. Sources

- [SandboxAQ AQtive Guard](https://www.aqtiveguard.com/) — Product pages, press releases (April-December 2025)
- [Keyfactor AgileSec](https://www.keyfactor.com/infosecglobal/) — Solution briefs, PQC expansion announcement (April 2025)
- [IBM zCDI 1.1](https://www.ibm.com/products/z-crypto-discovery-inventory) — GA announcement (June 2025)
- [IBM Quantum Safe Explorer](https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/1.0.x) — Announcement (May 2025)
- [Thales Luna HSM 7.9.2](https://thalesdocs.com/gphsm/luna/7/docs/usb/Content/CRN/Luna/usb_firmware/7-9-2.htm) — Firmware release notes (February 2026)
- [PQShield UltraPQ Suite](https://pqshield.com/ultrapq-suite-from-a-leading-quantum-security-company/) — Product pages (April 2025)
- [QuSecure QuProtect R3](https://www.qusecure.com/product/) — Product pages, Frost & Sullivan award
- [Crypto4A QxHSM/QxEDGE](https://crypto4a.com/products) — Product pages, FIPS submission (March 2025)
- [DigiCert Trust Lifecycle Manager PQC](https://docs.digicert.com/zf/trust-lifecycle-manager/enroll-and-manage-certificates/post-quantum-cryptography-pqc.html) — Documentation
- [Entrust Cryptographic Security Platform](https://www.entrust.com/company/newsroom/entrust-announces-industrys-first-unified-cryptographic-security-platform) — Announcement (April 2025)
- [PQCA GitHub](https://github.com/PQCA) — Open-source projects
- [NIST NCCoE PQC Migration](https://www.nccoe.nist.gov/crypto) — Project participants
- [Frost & Sullivan PQC Report](https://finance.yahoo.com/news/qusecure-named-global-product-leader-120000689.html) — Industry recognition
- [ESG Brief — Entrust Crypto Agility](https://www.techtarget.com/esg-global/wp-content/uploads/2025/02/ESG-Brief-Entrust-Crypto-Agility-Certificates-Feb-2025-002.pdf) — Market data
- [DigiCert PQC Maturity Model](https://www.digicert.com/content/dam/digicert/pdfs/ebook/post-quantum-cryptography-for-dummies.pdf) — Framework
