# Janus CryptoBOM Operations

## Controller

Required environment:

- `JANUS_DATABASE_URL`
- `JANUS_GRPC_ADDR`
- `JANUS_HTTP_ADDR`
- `JANUS_COMMAND_SIGNING_KEY`

Optional TLS:

- `JANUS_TLS_CERT_FILE`
- `JANUS_TLS_KEY_FILE`

The controller enforces TLS 1.3 when certificate files are configured. Hybrid ECDHE-MLKEM negotiation depends on the Go runtime and linked TLS stack used in deployment.

## Agent

Passive mode:

- Scans source files, dependency manifests, binaries, processes, Linux process maps, and configured network endpoints.
- Writes telemetry to local SQLite first.
- Uploads queued telemetry when the controller is reachable.
- Does not mutate host state.

Active mode:

- Requires `execution_mode = "active"`.
- Verifies HMAC-signed controller commands.
- Restricts writes to `active.allowed_config_roots`.
- Applies unified diffs atomically with backup, validates service syntax, reloads, and rolls back on failure.

## Windows End-to-End Test

From a VS 2022 Developer PowerShell or Command Prompt:

```powershell
.\build-windows.ps1
.\scripts\test-e2e-windows.ps1 -SkipBuild
```

The script expects Docker for PostgreSQL. If Docker is unavailable, start PostgreSQL manually with:

```text
postgres://janus:janus@localhost:5432/janus?sslmode=disable
```

Outputs:

- `bin\janus-server.exe`
- `bin\janus-agent.exe`
- `janus-agent-report.html`
- `janus-agent.sarif`
- `janus-controller-report.html`

## Windows Service

Install:

```powershell
.\scripts\install-agent-windows-service.ps1 -AgentExe .\bin\janus-agent.exe -ConfigPath .\agent\janus-agent.example.toml -Start
```

Uninstall:

```powershell
.\scripts\uninstall-agent-windows-service.ps1
```

## PQC Policy Defaults

- Flag RSA/DH/ECDH/ECDSA/DSA roles as quantum-vulnerable.
- Treat RSA below 3072 bits as critical in the 2026 transition profile.
- Require TLS 1.3 validation.
- Treat classical-only TLS key exchange as critical.
- Track certificate signatures separately from key exchange.
- Target `X25519MLKEM768` for near-term TLS hybrid key establishment and `ML-DSA-65` for private-PKI signature pilots.
