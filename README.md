# Janus CryptoBOM

Janus CryptoBOM is an enterprise-grade, post-quantum cryptographic posture management (PQC-PM), discovery, and automated migration suite. This document serves as the foundational technical blueprint for building the multi-tier platform.

---

## Ecosystem & Similar Solutions

### Code Scanners & CBOM Generators (AppSec/SCA)
These tools map source code, software supply chains, and dependencies to find legacy algorithms (like RSA) and generate a Cryptographic Bill of Materials (CBOM).

#### Open-Source
* **[PQCA CBOMkit](https://github.com/cbomkit/cbomkit)**: A flagship open-source reference implementation from the Post-Quantum Cryptography Alliance (hosted by the Linux Foundation). It scans source code (Java/Python/Go) via its SonarQube plugin (`sonar-cryptography`) and integrates with CI/CD pipelines to construct and manage CBOMs.
* **[QRAMM CryptoScan](https://github.com/csnp/cryptoscan)**: An open-source CLI scanner built for the PQC era by the CyberSecurity NonProfit (CSNP). It scans codebases for 50+ classical cryptographic algorithms, classifies quantum vulnerabilities, and outputs CycloneDX CBOM and SARIF files.
* **[CycloneDX cdxgen](https://github.com/CycloneDX/cdxgen)**: A widely adopted open-source CLI utility under the OWASP CycloneDX banner that generates deep CBOMs, SBOMs, and SaasBOMs across dozens of programming languages and ecosystems.

#### Commercial
* **[SandboxAQ AQtive Guard](https://www.sandboxaq.com/)**: A leading enterprise cryptographic posture management suite. It analyzes public software artifacts, codebases, and filesystems to track and manage cryptographic vulnerabilities at scale.
* **[ReversingLabs Spectra Assure](https://www.reversinglabs.com/products/spectra-assure)**: A commercial binary and software supply chain security analysis platform. Rather than reading source code, it decompiles compiled binaries, container images, and VM disks to map out hidden cryptographic assets.

---

### Network & Infrastructure Discovery
These tools focus on scanning corporate networks, endpoints, and live traffic to identify outdated TLS handshakes, cipher suites, and unapproved algorithms.

#### Open-Source
* **[QRAMM TLS-Analyzer](https://github.com/csnp/tls-analyzer)**: An open-source CLI utility from the CSNP QRAMM framework. It tests active network endpoints for TLS/SSL configurations and flags compliance gaps against modern government standards like CNSA 2.0.
* **[OWASP CycloneDX Sunshine (CryptoSunshine Extension)](https://github.com/CycloneDX/Sunshine)**: Developed by MONET+, CryptoSunshine is an open-source extension of OWASP CycloneDX Sunshine designed to visualize cryptographic inventories, manage CBOMs, and track compliance.

#### Commercial
* **[IBM Z Crypto Discovery Inventory (zCDI)](https://www.ibm.com/products/z-crypto-discovery-inventory)**: A specialized mainframe-oriented cryptographic posture dashboard. It aggregates crypto usage statistics across mainframe configurations, networks, and data sources for audit reports, but lacks active migration agents.
* **[QuantumGate Crypto Discovery Tool (CDT)](https://quantumgate.ae)**: A commercial infrastructure monitoring and risk assessment tool that relies on network and cloud sensors to map protocols and keys across AWS, Azure, and on-prem hardware. In 2026, it was adopted nationally by the UAE Cyber Security Council for critical infrastructure.

---

### Key Management, PKI, & Certificate Lifecycle Management (CLM)
These solutions handle the "upgrade and transition" side of Janus. They manage the Certificate Authorities (CAs) and automate the deployment of hybrid or post-quantum certificates.

#### Commercial
* **[Keyfactor AgileSec](https://www.keyfactor.com/products/agilesec/)**: A major enterprise tool in the Crypto Posture Management space. It provides end-to-end discovery of machine identities, certificates, and keys while preparing PKI setups for hybrid ML-DSA or ML-KEM deployment.
* **[Fortanix Data Security Manager (DSM)](https://www.fortanix.com/products/data-security-manager)**: A software-defined, HSM-backed key management and data security system. It provides a comprehensive inventory of all active cloud and on-prem keys, flagging weak and legacy algorithms.
* **[Thales Post-Quantum Crypto Agility](https://cpl.thalesgroup.com/encryption/post-quantum-cryptography)**: A suite of post-quantum-ready Hardware Security Modules (HSMs), encryptors, and software connectors designed to let enterprises switch classical keys for post-quantum variants (like ML-KEM, ML-DSA) with minimal disruption.

---

## Direct Comparison: Competitors vs. Janus CryptoBOM

The following matrix compares the core features of similar solutions against Janus CryptoBOM:

| Solution Name | License Model | Code/Binary Scanner | Network Discovery | Key/Cert Management | Active Migration Automation |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Janus CryptoBOM** | Commercial / Enterprise | **Yes** | **Yes** | **Yes** | **Yes (Full Suite)** |
| **PQCA CBOMkit** | Open-Source | Yes | No | No | No |
| **QRAMM Toolkit** | Open-Source | Yes (CryptoScan) | Yes (TLS-Analyzer) | No | No |
| **CycloneDX cdxgen** | Open-Source | Yes | No | No | No |
| **OWASP CryptoSunshine** | Open-Source | No | Yes | Yes (Inventory) | No |
| **SandboxAQ AQtive Guard** | Commercial | Yes | Yes | No | Partial |
| **ReversingLabs Spectra Assure**| Commercial | Yes (Binary Only) | No | No | No |
| **IBM zCDI** | Commercial | No | Yes | Partial | No |
| **QuantumGate CDT** | Commercial | No | Yes | Yes | No |
| **Keyfactor AgileSec** | Commercial | Partial | Yes | Yes | Yes (PKI Focus) |
| **Fortanix DSM** | Commercial | No | No | Yes (HSM/KM) | No |
| **Thales PQC Agility** | Commercial | No | No | Yes (HSM/KM) | Partial |

---

## Solutions with Memory Scanning Capabilities

While no tool explicitly scans memory purely for "PQC migration mapping," several established open-source and commercial solutions across Windows, Linux, and macOS scan live memory to extract cryptographic keys, configurations, or process data.

### 1. [Volatility Framework](https://github.com/volatilityfoundation/volatility) (Open-Source)
The absolute industry standard for memory forensics. It ingests a raw RAM dump or interfaces with live memory acquisition tools to reconstruct the state of OS processes.
* **Crypto Capability**: Features specific plugins (like `aesfinder` and `rsafinder`) designed to scan memory pages for structural byte alignments unique to AES key schedules and RSA private key structures.
* **Supported OS**: Windows, Linux, macOS.

### 2. [SandboxAQ AQtive Guard](https://www.sandboxaq.com/) (Commercial)
A direct competitor in the cryptographic management space. It focuses heavily on discovering quantum-vulnerable algorithms.
* **Crypto Capability**: It uses non-disruptive local discovery mechanisms that can analyze active runtime environments to build a comprehensive Cryptographic Bill of Materials (CBOM) including live cryptographic providers.
* **Supported OS**: Mainly Windows and Linux enterprise environments.

### 3. Microsoft [AVML](https://github.com/microsoft/avml) & [WinPmem](https://github.com/velocidex/WinPmem) (Open-Source / Forensic Tools)
AVML (developed by Microsoft for Linux) and WinPmem (for Windows) are capture agents. They do not analyze data themselves but cleanly map raw physical memory to user space.
* **Crypto Capability**: When combined with a parsing script, they allow you to scrape a server's entire running RAM for active TLS master keys or outdated cipher configurations without interrupting the service.
* **Supported OS**: Windows (WinPmem) and Linux (AVML).

### 4. [Frida](https://frida.re) (Open-Source)
A dynamic instrumentation toolkit for developers and security researchers. Rather than taking a massive memory dump, it injects a JavaScript engine directly into a target process's memory space.
* **Crypto Capability**: It hooks directly into standard crypto libraries (OpenSSL, Apple CommonCrypto, Windows CryptoAPI). It monitors arguments in real-time, instantly extracting public/private keys as they are passed to encryption functions.
* **Supported OS**: Windows, Linux, macOS, Android, iOS.

### 5. [Keyfactor AgileSec](https://www.keyfactor.com/products/agilesec/) (Commercial)
An enterprise cryptographic agility platform. It actively discovers keys and machine identities at scale.
* **Crypto Capability**: Scans local file systems, application configurations, and accessible runtime environments to detect weak keys, expiring certificates, and algorithms vulnerable to quantum threats.
* **Supported OS**: Windows, Linux.

---

### Direct Memory Comparison Matrix

| Solution Name | OS Support | Scanning Mechanism | Primary Purpose | EDR Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Janus CryptoBOM** | Windows, Linux, macOS | API Injection / Kernel Driver | CBOM Discovery & PQC Migration | High (Requires Explicit EDR Whitelisting) |
| **Volatility Framework** | Windows, Linux, macOS | Post-Capture Artifact Carving | Digital Forensics / Malware Hunt | None (Analyzes static offline files) |
| **SandboxAQ AQtive Guard** | Windows, Linux | Process & Runtime Inspection | Post-Quantum Compliance | Medium (Enterprise Whitelisting required) |
| **AVML / WinPmem** | Windows, Linux | Raw Physical Memory Dump | Forensic Capture | Critical (Triggers immediate EDR alert) |
| **Frida** | Windows, Linux, macOS, Mobile | Dynamic Runtime Hooking | Reverse Engineering / Auditing | High (Antivirus blocks its process injection) |
| **Keyfactor AgileSec** | Windows, Linux | Systems & Memory Inventory | PKI & Certificate Agility | Low to Medium (Enterprise Signed) |

---
## Workspace Components

Janus CryptoBOM is a crypto posture management and PQC migration foundation. It includes:

- **[proto/](file:///D:/src/Janus_CryptoBOM/proto)**: Shared Protobuf contract for agent registration, CBOM telemetry, migration commands, and status reports.
- **[server/](file:///D:/src/Janus_CryptoBOM/server)**: Go controller with gRPC intake, PostgreSQL persistence, policy scoring, command signing, and a JSON API for the UI.
- **[agent/](file:///D:/src/Janus_CryptoBOM/agent)**: Rust endpoint agent with passive discovery, binary/source/config/dependency scanners, offline SQLite cache, and signed active-mode mutation support.
- **[ui/](file:///D:/src/Janus_CryptoBOM/ui)**: React/Tailwind dashboard for posture, CBOM exploration, and migration operations.
- **[infra/](file:///D:/src/Janus_CryptoBOM/infra)**: Local deployment and infrastructure assets.

The implementation deliberately treats runtime and memory discovery as secret-safe telemetry. It records crypto metadata and HMAC fingerprints only; raw key/session/plaintext capture is not implemented as a routine operating mode.

---

## Current Standards Baseline

*   **NIST FIPS 203**: ML-KEM for key establishment.
*   **NIST FIPS 204**: ML-DSA for digital signatures.
*   **NIST FIPS 205**: SLH-DSA for stateless hash-based digital signatures.
*   **NIST CSWP 39**: Cryptographic agility strategy and practices.
*   **TLS Migration Target**: TLS 1.3 with hybrid ECDHE-MLKEM groups where the runtime supports them.
*   **CBOM Interchange**: CycloneDX 1.6.

---

## Build Instructions

> [!NOTE]
> This workspace requires **Go (1.21+)**, **Rust/Cargo**, **Node.js (v18+)**, and **npm**. If you plan to regenerate code using protobuf, you will also need the `protoc` compiler. The checked-in Go and Rust services avoid mandatory code generation for normal builds; **[proto/janus.proto](file:///D:/src/Janus_CryptoBOM/proto/janus.proto)** remains the canonical contract.

### Windows / VS 2022 Builds

From a VS 2022 Developer PowerShell or Command Prompt, run MSBuild against **[JanusCryptoBOM.msbuild.proj](file:///D:/src/Janus_CryptoBOM/JanusCryptoBOM.msbuild.proj)**:

*   **Standard Build (Autodetects/Bootstraps Tools)**:
    ```powershell
    msbuild JanusCryptoBOM.msbuild.proj /t:Build
    ```
    This calls **[build-windows.ps1](file:///D:/src/Janus_CryptoBOM/build-windows.ps1)**, which bootstraps portable Go and Rust toolchains under `.tools` when they are not already present on your `PATH`.
*   **Build Using System Tools Only**:
    ```powershell
    msbuild JanusCryptoBOM.msbuild.proj /t:BuildNoTools
    ```
    This runs the build steps while skipping any tool download or bootstrap attempts, relying entirely on existing tool versions installed on your system path.

The build outputs:
- `bin\janus-server.exe`
- `bin\janus-agent.exe`
- `ui\dist`

#### End-to-End Validation
To run the automated validation test script:
```powershell
.\scripts\test-e2e-windows.ps1 -SkipBuild
```
This script starts the controller, runs a scan with the agent, and outputs a validation report at `janus-controller-report.html`. You can view the test script code here: **[test-e2e-windows.ps1](file:///D:/src/Janus_CryptoBOM/scripts/test-e2e-windows.ps1)**.

### Manual / Non-Windows Builds

If you prefer building components individually or are running on macOS/Linux, you can use the **[Makefile](file:///D:/src/Janus_CryptoBOM/Makefile)**:

```powershell
# Build UI assets
cd ui
npm install
npm run build

# Build and test the Go Server
cd ..\server
go mod tidy
go test ./...
go build ./cmd/janus-server

# Build and test the Rust Agent
cd ..\agent
cargo test
cargo build --release
```

---

## Local Run & Environment Configuration

### 1. Database Setup (PostgreSQL)

Janus Server stores CBOM assets, telemetry evidence, findings, and migration records in PostgreSQL. 

#### A. Direct Host Installation (Windows)
If installing PostgreSQL directly on Windows (e.g., PostgreSQL 17):
1. Log in to the database as the superuser (`postgres`):
   ```cmd
   "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres
   ```
2. Run the following SQL queries to initialize the database schema owner and database:
   ```sql
   CREATE ROLE janus WITH LOGIN PASSWORD 'janus';
   CREATE DATABASE janus OWNER janus;
   GRANT ALL PRIVILEGES ON DATABASE janus TO janus;
   ```

> [!TIP]
> **Authentication Configuration (`pg_hba.conf`)**
> If you experience `password authentication failed` issues, locate your `pg_hba.conf` configuration file (typically in `C:\Program Files\PostgreSQL\17\data\pg_hba.conf`) and ensure there is an entry allowing password authentication for local connections, or temporarily configure it to `trust` for local loopback connections during development:
> ```text
> # TYPE  DATABASE        USER            ADDRESS                 METHOD
> host    all             all             127.0.0.1/32            scram-sha-256
> host    all             all             ::1/128                 scram-sha-256
> ```

#### B. Docker Container Setup
Alternatively, if Docker is available:
```powershell
docker compose -f infra/docker-compose.yml up -d postgres
```

---

### 2. Starting the Server

The server behaves as the central controller orchestrating gRPC telemetry from agents, processing cryptographic compliance checks, and presenting REST APIs to the UI.

To launch the built server binary on Windows:
```powershell
# 1. Set environment variables
$env:JANUS_DATABASE_URL="postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable"
$env:JANUS_GRPC_ADDR="127.0.0.1:9443"
$env:JANUS_HTTP_ADDR="127.0.0.1:8080"
$env:JANUS_COMMAND_SIGNING_KEY="local-development-command-signing-key"

# 2. Run the server executable
.\bin\janus-server.exe
```

---

### 3. Running the Agent

The agent is written in Rust and scans endpoints for cryptographic algorithms, active TLS settings, and certificates.

To run the agent on Windows:
1. Ensure the default configuration file `janus-agent.toml` exists at the root of the repository. You can copy the example file:
   ```powershell
   Copy-Item .\agent\janus-agent.example.toml -Destination .\janus-agent.toml -ErrorAction SilentlyContinue
   ```
2. Run a one-off telemetry scan and sync:
   ```powershell
   .\bin\janus-agent.exe --once
   ```
3. Alternatively, run the agent in daemon mode to perform periodic background scans:
   ```powershell
   .\bin\janus-agent.exe
   ```

*The example configuration is located at [agent/janus-agent.example.toml](file:///D:/src/Janus_CryptoBOM/agent/janus-agent.example.toml) and the main configuration file is [janus-agent.toml](file:///D:/src/Janus_CryptoBOM/janus-agent.toml).*

---

### 4. Running the Dashboard (React/TypeScript UI)

The frontend is a single-page React app served locally with a proxy connection to the backend REST API on port `8080`.

To start the Vite UI server:
```powershell
cd ui
npm install
npm run dev
```
Open your web browser and navigate to `http://127.0.0.1:5173` to explore findings, components, and active migration transactions.


---

## Safety Model

> [!WARNING]
> Passive mode never mutates host state. Active mode enables automated cryptosystem mutation (e.g., trust store updates, config changes). To execute active modifications:
>
> 1. `execution_mode = "active"` must be explicitly configured in the local agent config.
> 2. The controller command must be signed with the configured HMAC key.
> 3. The target service and config path must be explicitly whitelisted.
> 4. Active migrations must use atomic backup, verification, reload, and rollback handling.

---

## Windows Agent Coverage

- Windows certificate stores through `certutil` and PowerShell certificate provider metadata.
- Windows CNG/CAPI provider inventory through `certutil -csplist`.
- Windows HTTP.sys TLS bindings through `netsh http show sslcert`.
- Windows Schannel policy through registry inventory.
- DPAPI-protected offline telemetry queue on Windows.
- Plugin manifests under **[plugins/windows-inventory/plugin.toml](file:///D:/src/Janus_CryptoBOM/plugins/windows-inventory/plugin.toml)**.
- Local HTML report and SARIF report on every scan.
- Active Windows trust-store import with signed directive validation and rollback on failed validation.

