# Janus CryptoBOM

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
