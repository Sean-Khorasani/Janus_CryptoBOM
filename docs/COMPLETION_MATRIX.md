# Janus CryptoBOM Implementation Matrix

## Implemented In This Workspace

| Requirement area | Implementation |
|---|---|
| Shared protobuf | `proto/janus.proto` plus manual Go/Rust bindings to avoid build-time `protoc` dependency. |
| Go controller | gRPC telemetry intake, PostgreSQL persistence, policy scoring, command signing, migration queue, HTTP API, HTML report, CSR API. |
| React dashboard | Overview, CBOM explorer, asset inventory, migration transaction console, dry-run migration enqueue, report link. |
| Rust agent | Tokio main loop, config manager, offline SQLite cache, gRPC sync, passive discovery, active mutation framework. |
| Windows discovery | Certificate stores, CNG/CAPI provider inventory, HTTP.sys TLS bindings, Schannel registry policy, process metadata. |
| Source discovery | Static crypto pattern scan across common source/config extensions. |
| Binary discovery | PE/ELF/Mach-O and binary symbol/string scanner for OpenSSL/CNG/CAPI/CommonCrypto crypto APIs. |
| Dependency discovery | Go, npm, Python, Maven, and Cargo manifest parsing with crypto-library classification. |
| Network discovery | Async endpoint probe with OpenSSL TLS 1.3/hybrid group attempt and cleartext detection. |
| Runtime discovery | Process metadata and Linux process map crypto-library inventory. |
| CBOM | CycloneDX 1.6-compatible JSON with Janus crypto properties. |
| SARIF | Local SARIF 2.1.0 output for policy findings. |
| Reports | Agent HTML report and controller enterprise HTML report. |
| Plugins | Manifest-loaded external command plugins, including Windows crypto inventory plugin. |
| Active mutation | Signed config patching with backup, validation, reload, rollback; Windows trust-store import with rollback on validation failure. |
| PQC policy | Role-correct detection for key exchange, signatures, certificate public keys, certificate signatures, hashes, symmetric algorithms, TLS observations. |
| Windows service | Install/uninstall scripts for the agent service. |
| Third-party repositories | Concrete upstream repositories cloned by `scripts/fetch-third-party.ps1`. |

## Deliberate Security Boundaries

The agent does not implement routine raw private-key, session-key, password, token, plaintext, or decrypted payload extraction from live process memory. The implemented runtime layer is metadata-only by default and suitable for production telemetry. Lab/forensic integrations with Frida or Volatility should be feature-gated separately with explicit legal approval and local sealed storage.

## User Test Entry Points

```powershell
msbuild JanusCryptoBOM.msbuild.proj /t:Build
.\scripts\test-e2e-windows.ps1 -SkipBuild
```

