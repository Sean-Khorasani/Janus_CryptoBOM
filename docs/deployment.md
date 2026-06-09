# Janus CryptoBOM Deployment and Operations Manual

This document covers deployment topologies, environment configuration, installation playbooks, and operational procedures.

---

## 1. Architectural Topologies

### 1.1 Single-Server (Docker Compose)
```
                     +--------------------------+
                     |       Docker Host         |
                     |  janus-server :8080:9443  |
                     |  janus-agent  (passive)   |
                     |  postgres      :5432      |
                     +--------------------------+
```

### 1.2 Distributed HA
```
 Agent Fleet → Load Balancer → [Controller-A, Controller-B, Controller-C]
                                      ↓
                               pgpool-II / pgBouncer
                                      ↓
                          [PostgreSQL Primary → Replica]
```

### 1.3 Kubernetes (Helm)
```bash
helm install janus ./deploy/helm/janus \
  --set server.replicaCount=3 \
  --set postgres.persistence.enabled=true \
  --set ingress.enabled=true
```

Helm chart at `deploy/helm/janus/` — includes Deployment (server), DaemonSet (agent), ConfigMap, Service, Ingress, PostgreSQL StatefulSet, and Secrets.

---

## 2. Environment Configuration

### 2.1 Server (Complete Reference)

| Variable | Default | Required | Purpose |
|----------|---------|----------|---------|
| **`JANUS_COMMAND_SIGNING_KEY`** | — | **YES** | 32-byte HMAC/JWT key. Generate: `openssl rand -hex 32` |
| `JANUS_DATABASE_URL` | `postgres://janus:janus@localhost:5432/janus?sslmode=disable` | YES | PostgreSQL DSN |
| `JANUS_GRPC_ADDR` | `127.0.0.1:9443` | No | gRPC bind address |
| `JANUS_HTTP_ADDR` | `127.0.0.1:8080` | No | HTTP/WS bind address |
| `JANUS_TLS_CERT_FILE` | — | No | TLS certificate for gRPC |
| `JANUS_TLS_KEY_FILE` | — | No | TLS private key |
| `JANUS_CLIENT_CA_FILE` | — | No | Client CA for mTLS |
| `JANUS_DISABLE_AUTH` | `false` | No | Dev-mode skip JWT |
| `JANUS_CORS_ORIGIN` | `http://localhost:5173` | No | Dashboard origin |
| `JANUS_LOG_LEVEL` | `info` | No | debug/info/warn/error |
| `JANUS_DB_MAX_CONNS` | `25` | No | Pool max |
| `JANUS_DB_MIN_CONNS` | `5` | No | Pool min |
| `JANUS_DB_MAX_CONN_LIFETIME` | `30m` | No | Connection max age |
| `JANUS_DB_MAX_CONN_IDLE_TIME` | `5m` | No | Idle timeout |
| `JANUS_AGENT_STALL_SECONDS` | `300` | No | Stall threshold |
| `JANUS_HSM_MODULE_PATH` | — | No | PKCS#11 .dll/.so path |
| `JANUS_HSM_PIN` | — | No | HSM user PIN |

### 2.2 Agent Configuration (`janus-agent.toml`)

```toml
controller_endpoint = "http://127.0.0.1:9443"
execution_mode = "passive"          # passive | active
cache_path = "janus-agent.sqlite3"
host_uuid_path = "janus-host-id"
scan_interval_seconds = 900
max_file_bytes = 2097152
max_binary_bytes = 16777216

# REQUIRED — no default fallback. Generate: openssl rand -hex 32
command_signing_key = "your-32-byte-hex-key"

scan_roots = ["."]
exclude_dirs = [".git", "target", "node_modules", "dist", ".venv"]
network_targets = ["127.0.0.1:443"]
plugin_dirs = ["plugins"]
intercept_mode = "passive"          # passive (log) | active (modify ciphers)

[[plugin_commands]]
name = "windows-cng-capabilities"
command = "certutil"
args = ["-csplist"]
timeout_seconds = 20
max_memory_mb = 512
max_cpu_percent = 50

[active]
allowed_services = ["nginx", "apache", "ssh", "windows-trust-store", "windows-schannel-policy"]
allowed_config_roots = ["."]
backup_dir = ".janus-backups"
```

---

## 3. Installation Playbooks

### 3.1 Docker Compose

```yaml
# infra/docker-compose.yml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: janus
      POSTGRES_PASSWORD: janus
      POSTGRES_DB: janus
    ports: ["5432:5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U janus -d janus"]

  janus-server:
    build: { context: ../, dockerfile: server/Dockerfile }
    ports: ["8080:8080", "9443:50051"]
    environment:
      JANUS_DATABASE_URL: "postgres://janus:janus@postgres:5432/janus?sslmode=disable"
      JANUS_GRPC_ADDR: "0.0.0.0:50051"
      JANUS_HTTP_ADDR: "0.0.0.0:8080"
      JANUS_COMMAND_SIGNING_KEY: "change-me-in-production-32-byte-hex-key"
      JANUS_LOG_LEVEL: "info"
      JANUS_DB_MAX_CONNS: "25"
      JANUS_DB_MIN_CONNS: "5"
      JANUS_AGENT_STALL_SECONDS: "300"
    depends_on: { postgres: { condition: service_healthy } }

  janus-agent:
    build: { context: ../agent, dockerfile: Dockerfile }
    volumes:
      - ../:/scan:ro
      - agent-data:/data
    depends_on: [janus-server]

volumes:
  janus-postgres:
  janus-agent-data:
```

### 3.2 Linux systemd

```ini
[Unit]
Description=Janus CryptoBOM Endpoint Agent
After=network.target

[Service]
Type=simple
User=janusagent
Group=janusagent
WorkingDirectory=/var/lib/janus-agent
ExecStart=/usr/local/bin/janus-agent --config /var/lib/janus-agent/janus-agent.toml
Restart=on-failure
RestartSec=10

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadOnlyPaths=/
ReadWritePaths=/var/lib/janus-agent/

[Install]
WantedBy=multi-user.target
```

### 3.3 Windows Service

```powershell
.\scripts\install-agent-windows-service.ps1 -AgentExe "D:\janus\bin\janus-agent.exe" -ConfigPath "D:\janus\agent\janus-agent.example.toml" -Start
```

### 3.4 Kubernetes (Helm)

```bash
# Install
helm install janus ./deploy/helm/janus \
  --set server.image.tag=latest \
  --set secrets.commandSigningKey=$(openssl rand -hex 32)

# Upgrade
helm upgrade janus ./deploy/helm/janus --set server.replicaCount=5

# Uninstall
helm uninstall janus
```

---

## 4. HSM Setup (F13)

### SoftHSM2

```powershell
# Automated setup
.\HSM\setup-softHSM2.ps1

# Manual initialization
$env:SOFTHSM2_CONF = ".\HSM\softhsm2.conf"
softhsm2-util --init-token --slot 0 --label "JanusTestToken" --so-pin 5678 --pin 1234
softhsm2-util --generate-key rsa:2048 --label "janus-test-rsa" --pin 1234 --id A001

# Configure Janus
$env:JANUS_HSM_MODULE_PATH = ".\HSM\bin\softhsm2.dll"
$env:JANUS_HSM_PIN = "1234"
.\bin\janus-server.exe
```

### Production HSM

Set `JANUS_HSM_MODULE_PATH` to your vendor PKCS#11 library:
- Thales Luna: `C:\Program Files\Thales\Luna\cryptoki.dll`
- Utimaco: `C:\Program Files\Utimaco\cs_pkcs11_R3.dll`
- nCipher: `C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll`

---

## 5. Observability

### Structured Logging (F4.1)
- **Server:** JSON output via `log/slog`. Level: `JANUS_LOG_LEVEL`
- **Agent:** JSON output via `tracing`. Level: `RUST_LOG`
- **SIEM:** `GET /api/export/siem` — JSON-lines stream

### WebSocket (F4.2)
Connect to `ws://HOST:8080/api/ws` for real-time events: `telemetry_update`, `finding_status`, `migration_enqueued`, `migration_status`, `policy_switched`, `lab_simulation`

### Prometheus (F25)
`GET /metrics` exposes: `janus_assets_total`, `janus_components_total`, `janus_findings_total`, `janus_critical_findings_total`, `janus_high_findings_total`, `janus_open_migrations_total`

### Agent Health
- Heartbeat every 5s with scan progress, CPU, memory, phase
- Stalled detection: agents with `last_seen > 5min` counted in `/api/overview`
- Diagnostics buffer: cleared after successful upload, capped at 100 entries

### Fleet Quantum-Readiness Score (F3)
Formula: `100 - (critical×18 + high×8 + stalled×15) + remediation_bonus`
Available in `/api/overview` and compliance report.

---

## 6. CI/CD Integration (F2)

### GitHub Actions
```yaml
# .github/workflows/janus-scan.yml
- uses: actions/checkout@v4
- run: janus-cli check . --format sarif --output janus-findings.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: janus-findings.sarif }
```

### Generic CI
```bash
./scripts/janus-ci.sh ./src --fail-on critical
```

---

## 7. Document References
- [Design Manual](design.md) — Architecture, DB schema, API contracts
- [Case Studies](case_studies.md) — 12 production playbooks
- [Competitive Analysis](competitive-analysis.md) — 10-competitor comparison
- [Feature Inventory](feature-inventory.md) — Implementation status
- [Main README](../README.md) — Platform overview, quickstart
