# Janus CryptoBOM: Enterprise Post-Quantum Cryptographic Posture Management & Migration Suite

Janus CryptoBOM is an enterprise-grade, post-quantum cryptographic posture management (PQC-PM), discovery, and automated migration platform. It enables organizations to discover legacy cryptographic vulnerabilities, assess quantum readiness, align with emerging standards, and orchestrate safe, automated migrations to Post-Quantum Cryptography (PQC).

---

## Table of Contents
- [Executive Briefing: The Post-Quantum Business Risk](#executive-briefing-the-post-quantum-business-risk)
- [The Janus Value Proposition](#the-janus-value-proposition)
- [Enterprise Dashboard Previews](#enterprise-dashboard-previews)
- [Direct Comparison Matrix](#direct-comparison-matrix)
- [Platform Architecture](#platform-architecture)
- [Building from Source](#building-from-source)
- [Quickstart & Running Instructions](#quickstart--running-instructions)
- [Safety Model & Security Controls](#safety-model--security-controls)
- [Platform Support & Windows Coverage](#platform-support--windows-coverage)
- [License](#license)

---

## Executive Briefing: The Post-Quantum Business Risk

### The Quantum Threat (Shor's Algorithm)
Symmetric and asymmetric encryption form the bedrock of trust for modern enterprise infrastructure. However, the development of cryptanalytically relevant quantum computers (CRQCs) threatens to dismantle this foundation. Shor's algorithm demonstrates that a quantum computer of sufficient scale will solve prime factorization and discrete logarithms in polynomial time, rendering legacy public-key cryptosystems—including RSA, Diffie-Hellman, ECDH, and ECDSA—completely obsolete.

### Harvest Now, Decrypt Later (HNDL)
This threat is not futuristic; it is active today. Hostile state actors and sophisticated syndicates are executing "Harvest Now, Decrypt Later" (HNDL) operations. Adversaries intercept and store encrypted enterprise and government communications today, waiting to decrypt them once quantum computers reach sufficient capability. CISOs and investors must realize that any sensitive data transmitted or stored using classical cryptography is already exposed to long-term risk.

### Regulatory Alignment (NIST FIPS 203/204/205)
Global standards are rapidly adapting to enforce PQC transition timelines. The National Institute of Standards and Technology (NIST) has released the finalized post-quantum standards:
- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) for key establishment.
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for digital signatures.
- **NIST FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) for digital signatures.

Compliance frameworks, including the Commercial National Security Algorithm (CNSA) Suite 2.0 and the Quantum Computing Cybersecurity Preparedness Act, mandate public and private enterprises to inventory their cryptographic assets, compile a Cryptographic Bill of Materials (CBOM), and begin immediate post-quantum migration.

---

## The Janus Value Proposition

Janus addresses the quantum transition challenge through three core business value pillars:

1. **Post-Quantum Cryptographic Posture Management (PQC-PM)**: Providing complete visibility across codebases, compiled binaries, operating system trust stores, network protocol suites, and process memory footprints to identify vulnerable public-key implementations.
2. **Context-Aware Semantic Intent Analysis**: Enterprise codebases contain legacy cryptosystems used in non-critical paths (e.g., test suites, signature verification of old files, or capability negotiations). Janus's AST-based semantic analysis engine differentiates active cryptographic protection from legacy verification-only paths, reducing security operation center (SOC) alert fatigue.
3. **Automated Sandboxed Migration**: Rather than leaving remediation to manual, error-prone software engineering cycles, Janus orchestrates signed, automated migration directives. It deploys hybrid and PQC certificates, updates server configurations (such as Nginx and Windows Schannel), verifies connectivity, and rolls back configuration states automatically if validation checks fail.

---

## Enterprise Dashboard Previews

The platform's unified interface bridges the gap between executive risk assessment and technical operations.

### Centralized CISO Fleet Safety Dashboard
The CISO Fleet Safety Dashboard provides real-time posture reporting across the enterprise. It displays aggregated Fleet Safety Scores, active monitored assets, real-time cryptographic vulnerability alerts, and the overall NIST FIPS compliance index.

![Centralized CISO Fleet Safety Dashboard](docs/images/dashboard_preview_1780620392773.png)

### Interactive Crypto Exposure Graph & Live Scan Status
The interactive Crypto Exposure Graph maps host-to-host and component-to-component cryptographic dependencies. Below the graph, the active scanning status banner displays client-side telemetry throughput and queue status, showing data synchronization rates from remote agents.

![Interactive Crypto Exposure Graph & Live Scan Status](docs/images/dashboard_preview_1780512832245.png)

---

## Direct Comparison Matrix

The table below contrasts Janus CryptoBOM against open-source and commercial security suites:

| Competitor / Suite | Discovery Mode | Network Sweep | Cert Management | Active Migration | Memory Scraping | EDR Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Janus CryptoBOM** | **Yes** (Source, binary, configurations) | **Yes** (Agent-based and agentless network socket discovery) | **Yes** (Schannel, Java TrustStore, Windows certutil/CAPI/CNG) | **Yes** (Atomic migration with automated verification, reload & failover rollback) | **Yes** (Safe API hook injection & DLL audit / read DPAPI shielded queue) | **High** (Requires EDR whitelisting/signed agent for active process memory auditing/mutations) |
| **PQCA CBOMkit** | **Yes** (Source code via SonarQube plugin) | **No** | **No** | **No** | **No** | **None** (Standard SCA/CI-CD scanner impact) |
| **cdxgen** | **Yes** (Source code & dependency-based SCA) | **No** | **No** | **No** | **No** | **None** (CLI-based developer tooling) |
| **QRAMM CSNP** | **Yes** (CLI source scan for 50+ classical algos) | **Yes** (TLS-Analyzer for active endpoint sweeping) | **No** | **No** | **No** | **None** / **Low** (Simple CLI/network tools) |
| **SandboxAQ AQtive Guard** | **Yes** (Source, filesystem, binary analysis) | **Yes** (Cloud/network sensors) | **No** | **Partial** (Configuration alerts, limited mutation automation) | **Yes** (Inspects runtime environments / providers) | **Medium** (Enterprise whitelist needed for local active scanning) |
| **Keyfactor AgileSec** | **Partial** (Finds weak keys in filesystem/code repositories) | **Yes** (Active network/endpoint scanner) | **Yes** (Full machine identity and certificate lifecycle management) | **Yes** (PKI upgrade focus, hybrid cert issuance) | **No** (Focuses on certificate & key storage, not runtime heap scraping) | **Low to Medium** (Enterprise-signed code agent) |
| **IBM zCDI** | **No** | **Yes** (Mainframe network connection analysis) | **Partial** (Aggregates cryptographic audit logs) | **No** | **No** | **None** (Mainframe host logs aggregation) |
| **Thales PQC Agility** | **No** | **No** | **Yes** (Agile HSM & KM connectors) | **Partial** (Automates HSM key transitions, lacks endpoint service mutation) | **No** | **None** / **Low** (Operates at HSM/appliance boundary) |

---

## Platform Architecture

Janus CryptoBOM is divided into four main layers:

- **React SPA Dashboard (`ui/`)**: A rich TypeScript-based Single-Page Application using React and Tailwind CSS that lets administrators monitor security posture, configure policy rules, and track automated migrations.
- **Go Server (`server/` and `cmd/janus-server/`)**: The control plane backend that manages agent registrations, aggregates CBOM telemetry payload records over gRPC, evaluates policies against a PostgreSQL database, and coordinates command-line migrations.
- **Rust Endpoint Agent (`agent/`)**: A high-performance, low-footprint daemon running on Windows, Linux, and macOS. It executes scheduled passive scans, analyzes code/binaries/dependencies, generates CycloneDX v1.6 compliant CBOM outputs, and executes signed active mutation instructions.
- **Protobuf Contracts (`proto/janus.proto`)**: Canonical definitions of the communication protocols linking the agents to the server, securing control transactions with cryptographically signed directives.

---

## Building from Source

### Prerequisites
- **Go 1.21+** (for building the server)
- **Rust & Cargo** (for building the agent)
- **Node.js v18+ & npm** (for building the dashboard interface)
- **MSBuild** or **make** (based on operating system)

### Windows Build (via MSBuild)
From a Visual Studio 2022 Developer PowerShell or Developer Command Prompt, navigate to the root directory and run:

1. **Standard Build** (automatically bootstraps portable Go and Rust toolchains locally if not in your current PATH):
   ```powershell
   msbuild JanusCryptoBOM.msbuild.proj /t:Build
   ```
2. **System Toolchain Build** (forces the build script to use system-installed Go, Rust, and npm tools):
   ```powershell
   msbuild JanusCryptoBOM.msbuild.proj /t:BuildNoTools
   ```

Built binaries will be located at `bin/janus-server.exe` and `bin/janus-agent.exe`. The static frontend build will be written to `ui/dist`.

To run the full end-to-end automated testing validation suite on Windows:
```powershell
.\scripts\test-e2e-windows.ps1 -SkipBuild
```

### Linux & macOS Build (via Makefile)
For UNIX-compliant environments, execute:

```bash
# Build the entire workspace (UI, Server, and Agent)
make test

# Or build individual components:
make ui
make server
make agent
```

---

## Quickstart & Running Instructions

### 1. Database Setup (PostgreSQL)
Janus requires a PostgreSQL instance to store assets, telemetry details, policy parameters, and migration execution records.

#### Option A: Direct Local Setup (Windows / Linux)
Log in to your PostgreSQL instance as a superuser and run:
```sql
CREATE ROLE janus WITH LOGIN PASSWORD 'janus';
CREATE DATABASE janus OWNER janus;
GRANT ALL PRIVILEGES ON DATABASE janus TO janus;
```

*Note on authentication: Ensure your `pg_hba.conf` allows password authentication (scram-sha-256 or md5) from localhost.*

#### Option B: Docker Container Setup
```bash
docker compose -f infra/docker-compose.yml up -d postgres
```

### 2. Launching the Go Server
Configure the target database URL and service listener ports using environment variables:

```powershell
# Set environment parameters
$env:JANUS_DATABASE_URL="postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable"
$env:JANUS_GRPC_ADDR="127.0.0.1:9443"
$env:JANUS_HTTP_ADDR="127.0.0.1:8080"
$env:JANUS_COMMAND_SIGNING_KEY="local-development-command-signing-key"

# (Optional) Enable context-aware risk engine API checks
# $env:JANUS_LLM_API_KEY="sk-..."
# $env:JANUS_LLM_API_URL="https://api.openai.com/v1"

# Run the controller executable
.\bin\janus-server.exe
```

### 3. Deploying the Rust Agent
1. Copy the template agent configuration file to the working folder:
   ```powershell
   copy .\agent\janus-agent.example.toml .\janus-agent.toml
   ```
2. Run a single scanning iteration and sync directly to the server:
   ```powershell
   .\bin\janus-agent.exe --once
   ```
3. Alternatively, run the agent as a background daemon to monitor the system dynamically:
   ```powershell
   .\bin\janus-agent.exe
   ```

### 4. Running the Dashboard (React Console)
To launch the developer console proxying to the Go server REST API:
```bash
cd ui
npm install
npm run dev
```
Open a browser and navigate to `http://127.0.0.1:5173`.

---

## Safety Model & Security Controls

Because Janus is capable of modifying enterprise configurations in Active Mode, a robust safety architecture is enforced:
1. **Explicit Opt-in**: The agent will run exclusively in passive scanning mode unless `execution_mode = "active"` is configured inside the local `janus-agent.toml`.
2. **Cryptographic Directives**: All active mutation commands received over gRPC are validated against the `signed_directive` signature field using the HMAC key configured locally in the agent's key database.
3. **Sandbox Whitelisting**: Path traversal protection restricts config alterations to approved configuration file extensions (`.conf`, `.config`, `.json`, `.toml`, `.yaml`, `.xml`).
4. **Atomic Rollbacks**: Every active migration executes inside a transaction state: backing up existing configurations, writing updates, verifying health, and automatically restoring backup states on any service failure.

---

## Platform Support & Windows Coverage

While cross-compiling natively across Linux and macOS, Janus provides deep integrations for Microsoft Windows systems:
- **Windows Certificate Stores**: Complete discovery of system certificates using `certutil` and PowerShell bindings.
- **Crypto Abstraction Parsing**: Mapping of Active CNG and CryptoAPI (CAPI) provider configurations via `certutil -csplist`.
- **HTTP.sys SSL Binding Sweeps**: Inspection of active HTTPS bindings using `netsh http show sslcert`.
- **Schannel Registry Enforcements**: Parsing and updating registry locations under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`.
- **DPAPI Data Shielding**: Using the Windows Data Protection API (DPAPI) to encrypt local configuration secrets on disk, ensuring decryption happens only in-memory on system startup.

---

## License

Janus CryptoBOM is distributed under the Apache License, Version 2.0. See the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) for full details.
