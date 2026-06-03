## Janus CryptoBOM


Janus CryptoBOM is an enterprise-grade, post-quantum cryptographic posture management, discovery, and automated migration suite. This document serves as the foundational technical blueprint for building the multi-tier platform.

------------------------------
## Code Scanners & CBOM Generators (AppSec/SCA)
These tools map source code, software supply chains, and dependencies to find legacy algorithms (like RSA) and generate a Cryptographic Bill of Materials (CBOM).
## Open-Source

* [PQCA CBOMkit](https://github.com/) (Linux Foundation): A flagship open-source reference implementation from the Post-Quantum Cryptography Alliance. It scans Java/Python libraries and integrates natively with SBOM tools to find binary-level cryptographic primitives. 
* [QRAMM CryptoScan](https://github.com/csnp/cryptoscan): A popular open-source CLI tool built for the PQC era. It scans repositories for over 50+ crypto patterns (AES, MD5, RSA), classifies quantum risks, and outputs CycloneDX CBOM files.
* CycloneDX cdxgen: A widely used open-source CLI utility that generates deep CBOMs across dozens of programming languages by mapping active crypto libraries.

## Commercial

* [SandboxAQ AQtive Guard](https://www.sandboxaq.com/): One of Janus's closest commercial competitors. It analyzes public software artifacts and codebases to track cryptographic vulnerabilities at scale.
* [ReversingLabs Spectra Assure](https://www.reversinglabs.com/products/spectra-assure): A commercial binary analysis platform. Instead of reading source code, it decompiles compiled binaries, container images, and VM disks to map out hidden crypto assets.

------------------------------
## Network & Infrastructure Discovery
These tools focus on scanning corporate networks, endpoints, and live traffic to identify outdated TLS handshakes, cipher suites, and unapproved algorithms.
## Open-Source

* [QRAMM TLS-Analyzer](https://qramm.org/): An open-source utility that tests active network endpoints for TLS/SSL configurations and flags compliance gaps against modern government standards.
* [OWASP CryptoSunshine](https://github.com/OWASP): An open-source dashboard extension that visualizes cryptographic inventories and highlights network-level quantum compliance risks.

## Commercial

* [IBM Z Crypto Discovery Inventory (zCDI)](https://www.ibm.com/products/z-crypto-discovery-inventory): A specialized enterprise dashboard that aggregates crypto statistics across mainframe configurations, networks, and data sources. It generates audit reports but lacks real-time migration agents.
* QuantumGate Crypto Discovery Tool (CDT): A commercial infrastructure monitoring tool that relies on network and cloud sensors to map protocols and keys across AWS, Azure, and on-prem hardware.

------------------------------
## Key Management, PKI, & Certificate Lifecycle Management (CLM)
These solutions handle the "upgrade and transition" side of Janus. They manage the Certificate Authorities (CAs) and automate the deployment of hybrid or post-quantum certificates.
## Commercial

* Keyfactor AgileSec: A major enterprise tool in the Crypto Posture Management space. It provides end-to-end discovery of machine identities, certificates, and keys while preparing PKI setups for hybrid ML-DSA or ML-KEM deployment.
* Fortanix Data Security Manager (DSM): An HSM-backed key management system. While it cannot read your source code, it provides a comprehensive inventory of all active cloud and on-prem keys, flagging weak algorithms instantly.
* Thales Post-Quantum Crypto Agility: Hardware Security Modules (HSMs) and software connectors designed to let enterprises switch out classical keys for post-quantum variants with minimal disruption.

------------------------------
## Direct Comparison: Competitors vs. Janus CryptoBOM

| Solution Name | Code/Binary Scanner | Network Discovery | Key/Cert Management | Active Migration Automation |
|---|---|---|---|---|
| Janus CryptoBOM | Yes | Yes | Yes | Yes (Full Suite) |
| PQCA CBOMkit (Open-Source) | Yes | No | No | No |
| QRAMM Toolkit (Open-Source) | Yes | Yes | No | No |
| SandboxAQ AQtive Guard | Yes | Yes | No | Partial |
| Keyfactor AgileSec | Partial | Yes | Yes | Yes (PKI Focus) |
| IBM zCDI | No | Yes | Partial | No |

------------------------------

## Solutions with Memory Scanning Capabilities
While no tool explicitly scans memory purely for "PQC migration mapping," several established open-source and commercial solutions across Windows, Linux, and macOS scan live memory to extract cryptographic keys, configurations, or process data.

## 1. Volatility Framework (Open-Source)
The absolute industry standard for memory forensics. It ingests a raw RAM dump or interfaces with live memory acquisition tools to reconstruct the state of OS processes.

* Crypto Capability: Features specific plugins (like aesfinder and rsafinder) designed to scan memory pages for structural byte alignments unique to AES key schedules and RSA private key structures.
* Supported OS: Windows, Linux, macOS.

## 2. SandboxAQ AQtive Guard (Commercial)
A direct competitor in the cryptographic management space. It focuses heavily on discovering quantum-vulnerable algorithms.

* Crypto Capability: It uses non-disruptive local discovery mechanisms that can analyze active runtime environments to build a comprehensive Cryptographic Bill of Materials (CBOM) including live cryptographic providers.
* Supported OS: Mainly Windows and Linux enterprise environments.

## 3. Microsoft AVML & WinPmem (Open-Source / Forensic Tools)
AVML (developed by Microsoft for Linux) and WinPmem (for Windows) are capture agents. They do not analyze data themselves but cleanly map raw physical memory to user space.

* Crypto Capability: When combined with a parsing script, they allow you to scrape a server's entire running RAM for active TLS master keys or outdated cipher configurations without interrupting the service.
* Supported OS: Windows (WinPmem) and Linux (AVML).

## 4. Frida (Open-Source)
A dynamic instrumentation toolkit for developers and security researchers. Rather than taking a massive memory dump, it injects a JavaScript engine directly into a target process's memory space.

* Crypto Capability: It hooks directly into standard crypto libraries (OpenSSL, Apple CommonCrypto, Windows CryptoAPI). It monitors arguments in real-time, instantly extracting public/private keys as they are passed to encryption functions.
* Supported OS: Windows, Linux, macOS, Android, iOS.

## 5. Keyfactor AgileSec (Commercial)
An enterprise cryptographic agility platform. It actively discovers keys and machine identities at scale.

* Crypto Capability: Scans local file systems, application configurations, and accessible runtime environments to detect weak keys, expiring certificates, and algorithms vulnerable to quantum threats.
* Supported OS: Windows, Linux.

------------------------------
## Direct Comparison Matrix

| Solution Name | OS Support | Scanning Mechanism | Primary Purpose | EDR Impact |
|---|---|---|---|---|
| Janus CryptoBOM | Windows, Linux, macOS | API Injection / Kernel Driver | CBOM Discovery & PQC Migration | High (Requires Explicit EDR Whitelisting) |
| Volatility Framework | Windows, Linux, macOS | Post-Capture Artifact Carving | Digital Forensics / Malware Hunt | None (Analyzes static offline files) |
| SandboxAQ AQtive Guard | Windows, Linux | Process & Runtime Inspection | Post-Quantum Compliance | Medium (Enterprise Whitelisting required) |
| AVML / WinPmem | Windows, Linux | Raw Physical Memory Dump | Forensic Capture | Critical (Triggers immediate EDR alert) |
| Frida | Windows, Linux, macOS, Mobile | Dynamic Runtime Hooking | Reverse Engineering / Auditing | High (Antivirus blocks its process injection) |
| Keyfactor AgileSec | Windows, Linux | Systems & Memory Inventory | PKI & Certificate Agility | Low to Medium (Enterprise Signed) |

------------------------------
## Components

Janus CryptoBOM is a crypto posture management and PQC migration foundation. It includes:

- `proto/`: shared Protobuf contract for agent registration, CBOM telemetry, migration commands, and status reports.
- `server/`: Go controller with gRPC intake, PostgreSQL persistence, policy scoring, command signing, and a JSON API for the UI.
- `agent/`: Rust endpoint agent with passive discovery, binary/source/config/dependency scanners, offline SQLite cache, and signed active-mode mutation support.
- `ui/`: React/Tailwind dashboard for posture, CBOM exploration, and migration operations.
- `infra/`: local deployment assets.

The implementation deliberately treats runtime and memory discovery as secret-safe telemetry. It records crypto metadata and HMAC fingerprints only; raw key/session/plaintext capture is not implemented as a routine operating mode.

## Current Standards Baseline

- NIST FIPS 203: ML-KEM for key establishment.
- NIST FIPS 204: ML-DSA for digital signatures.
- NIST FIPS 205: SLH-DSA for stateless hash-based digital signatures.
- NIST CSWP 39: cryptographic agility strategy and practices.
- TLS migration target: TLS 1.3 with hybrid ECDHE-MLKEM groups where the runtime supports them.
- CBOM interchange: CycloneDX 1.6.

## Build

This workspace needs Go, Rust/Cargo, Node.js, npm, and `protoc` when regenerating code. The checked-in Go and Rust services avoid mandatory code generation for normal builds; `proto/janus.proto` remains the canonical contract.

### Windows / VS 2022

From a VS 2022 Developer PowerShell or Command Prompt:

```powershell
msbuild JanusCryptoBOM.msbuild.proj /t:Build
```

The MSBuild project calls [build-windows.ps1](D:/src/janus-cbom/build-windows.ps1), which bootstraps portable Go and Rust toolchains under `.tools` when they are not already on `PATH`, then builds:

- `bin\janus-server.exe`
- `bin\janus-agent.exe`
- `ui\dist`

End-to-end validation script for you to run:

```powershell
.\scripts\test-e2e-windows.ps1 -SkipBuild
```

The script starts the controller, runs the agent once, and writes `janus-controller-report.html`.

### Manual

```powershell
# UI
cd ui
npm install
npm run build

# Server
cd ..\server
go mod tidy
go test ./...
go build ./cmd/janus-server

# Agent
cd ..\agent
cargo test
cargo build --release
```

## Local Run

```powershell
# Start Postgres if Docker is available
docker compose -f infra/docker-compose.yml up -d postgres

# Start server
$env:JANUS_DATABASE_URL="postgres://janus:janus@localhost:5432/janus?sslmode=disable"
$env:JANUS_GRPC_ADDR="127.0.0.1:9443"
$env:JANUS_HTTP_ADDR="127.0.0.1:8080"
$env:JANUS_COMMAND_SIGNING_KEY="replace-with-32-byte-secret"
server\janus-server.exe

# Start agent
agent\target\release\janus-agent.exe --config agent\janus-agent.example.toml
```

## Safety Model

Passive mode never mutates host state. Active mode requires:

1. `execution_mode = "active"` in the local agent config.
2. A controller command signed with the configured HMAC key.
3. An allowed target service and explicit target config path.
4. Atomic backup, validation, reload, and rollback handling.

## Windows Agent Coverage

- Windows certificate stores through `certutil` and PowerShell certificate provider metadata.
- Windows CNG/CAPI provider inventory through `certutil -csplist`.
- Windows HTTP.sys TLS bindings through `netsh http show sslcert`.
- Windows Schannel policy through registry inventory.
- DPAPI-protected offline telemetry queue on Windows.
- Plugin manifests under `plugins/*/plugin.toml`.
- Local HTML report and SARIF report on every scan.
- Active Windows trust-store import with signed directive validation and rollback on failed validation.
