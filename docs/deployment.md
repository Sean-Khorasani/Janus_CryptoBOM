# Janus CryptoBOM Deployment and Operations Manual

This document provides complete instructions for deploying, configuring, and operating the Janus CryptoBOM suite across diverse enterprise infrastructures. It covers architectural topologies (single-server and highly available clusters), server and agent environment parameters, and automated installation playbooks.

---

## 1. Architectural Topologies

Depending on system scale, network complexity, and availability requirements, Janus CryptoBOM supports two deployment models:

### 1.1 Single-Server Deployment
The single-server topology is designed for proof-of-concept (POC) evaluations, local developer testing, and small-scale infrastructures. 

In this setup, a single server hosts the Go HTTP and gRPC controller, the React static assets, and the PostgreSQL database. The database and controller run as Docker containers managed by a single Docker Compose file. Remote agents connect directly to the public-facing HTTP and gRPC ports of the single server.

```
                  +-------------------------------------------------------+
                  |                      Single Host                      |
                  |                                                       |
                  |   +-----------------------------------------------+   |
                  |   |                React Web UI                   |   |
                  |   +-----------------------------------------------+   |
                  |                           |                           |
                  |                           v                           |
                  |   +-----------------------------------------------+   |
                  |   |           Go HTTP REST & gRPC API             |   |
                  |   +-----------------------------------------------+   |
                  |                           |                           |
                  |                           v                           |
                  |   +-----------------------------------------------+   |
                  |   |            PostgreSQL Database                |   |
                  |   +-----------------------------------------------+   |
                  +-------------------------------------------------------+
                                              ^
                                              | HTTPS / gRPC
                                              |
                                      +---------------+
                                      | Remote Agents |
                                      +---------------+
```

### 1.2 Distributed Enterprise High Availability (HA) Topology
For large-scale enterprise environments with thousands of endpoints, Janus CryptoBOM must be deployed in a high-availability topology. This architecture guarantees horizontal scalability, fault tolerance, and minimal network latency:

```
                                     +----------------------+
                                     |  Agent Fleet Geoms   |
                                     +----------------------+
                                                |
                                                v DNS Geo-Routing
                                     +----------------------+
                                     |   Load Balancer      |
                                     | (Nginx / HAProxy /   |
                                     |    AWS ALB / NLB)    |
                                     +----------------------+
                                      /         |          \
                 +-------------------+          |           +-------------------+
                 |                              |                               |
                 v Port 8080 / 9443             v Port 8080 / 9443              v Port 8080 / 9443
        +------------------+           +------------------+            +------------------+
        |   Go Controller  |           |   Go Controller  |            |   Go Controller  |
        |      Node A      |           |      Node B      |            |      Node C      |
        +------------------+           +------------------+            +------------------+
                 \                              |                               /
                  \                             |                              /
                   \----------------------------+-----------------------------/
                                                |
                                                v SQL Connection Pool
                                     +----------------------+
                                     |     pgpool-II /      |
                                     |   HA Database Proxy  |
                                     +----------------------+
                                      /                    \
                                     v                      v (Streaming Replication)
                            +------------------+          +------------------+
                            |    PostgreSQL    |          |    PostgreSQL    |
                            |   Primary Node   |--------->|   Replica Node   |
                            +------------------+          +------------------+
```

#### 1. Load Balancing Layer
A highly available load balancer (such as Nginx, HAProxy, or a cloud provider's network load balancer) exposes a single public IP. It acts as the gateway, distributing incoming traffic across the application tier:
*   **HTTP REST (Port 8080)**: Distributed using round-robin load-balancing. Since the Go controller is stateless and uses JWTs for authorization, session persistence (sticky sessions) is not required.
*   **gRPC Control Channel (Port 9443)**: Distributed using least-connections or IP-hash algorithms. gRPC streams are long-lived, and TCP-level load balancing ensures agent streams are balanced evenly across active controllers.

#### 2. Application Controller Tier
A cluster of stateless Go controller instances runs across multiple availability zones. If a controller node fails, the load balancer routes requests to the remaining nodes. Agents automatically reconnect and resume telemetry streams with a healthy controller instance.

#### 3. Highly Available Database Tier
PostgreSQL is deployed in a primary-replica cluster managed by failover orchestrators like Patroni. Read and write commands from the Go controllers pass through a high-availability database proxy (such as pgpool-II or pgBouncer):
*   **Write Operations**: Directed exclusively to the Primary database node.
*   **Read Operations**: Distributed across Replica database nodes to offload complex queries from the primary node.

#### 4. Global Infrastructure Geo-Routing
For geographically distributed networks, DNS geo-routing (such as AWS Route53 Geo-DNS or Anycast DNS) directs endpoint agents to the nearest regional load balancer and controller cluster, reducing latency and securing telemetry uploads.

---

## 2. Environment & Parameter Configurations

### 2.1 Server Environment Variables
Configure the Go controller using the following environment variables:

| Variable Name | Default Value | Description | Security / Operational Impact |
| :--- | :--- | :--- | :--- |
| `JANUS_DATABASE_URL` | `postgres://janus:janus@localhost:5432/janus?sslmode=disable` | PostgreSQL database connection string (URL format). | Contains sensitive database credentials. In production, configure with `sslmode=verify-full`. |
| `JANUS_GRPC_ADDR` | `127.0.0.1:9443` | Listener address (IP:port) for the gRPC agent control channel. | Bind to `0.0.0.0` in containerized environments to accept connections from external networks. |
| `JANUS_HTTP_ADDR` | `127.0.0.1:8080` | Listener address (IP:port) for the HTTP REST API server. | Used to serve static assets and handle frontend API operations. Bind to `0.0.0.0` inside containers. |
| `JANUS_COMMAND_SIGNING_KEY` | `local-development-command-signing-key` | Symmetric key used to sign active mutation commands. | **Critical Security Key**. Must be at least 16 characters in size. Ensure it is unique and rotated regularly. |
| `JANUS_TLS_CERT_FILE` | *Empty* | Path to the server's TLS certificate file. | Required to secure gRPC and HTTP communication. |
| `JANUS_TLS_KEY_FILE` | *Empty* | Path to the server's private key file. | Required to secure gRPC and HTTP communication. |
| `JANUS_CLIENT_CA_FILE` | *Empty* | Path to the CA certificate file used to verify client certificates. | Set this to enable mutual TLS (mTLS) authentication for remote agents. |
| `JANUS_DISABLE_AUTH` | `false` | Boolean flag (`true` or `false`) to disable REST API token verification. | **Disable only in test environments**. Enabling this in production exposes system configuration APIs. |
| `JANUS_LLM_API_KEY` | *Empty* | API token for OpenAI or compatible LLM providers. | Enables LLM-assisted context-aware risk analysis and vulnerability scoring. |
| `JANUS_LLM_API_URL` | `https://api.openai.com/v1` | Base endpoint URL for LLM integration services. | Allows routing request data through private security gateways or on-premise model servers. |

---

### 2.2 Agent Configuration (`janus-agent.toml`)
Configure the agent using settings defined in `janus-agent.toml`. Below is an annotated example of a configuration file:

```toml
# ==============================================================================
# Janus Endpoint Agent Configuration
# ==============================================================================

# Central controller gRPC endpoint (format: http://IP:Port or https://IP:Port)
controller_endpoint = "http://127.0.0.1:9443"

# Optional: Override HTTP REST API endpoint for heartbeats and diagnostics.
# If omitted, the agent derives the HTTP endpoint from controller_endpoint.
http_controller_endpoint = "http://127.0.0.1:8080"

# TLS/mTLS configuration paths (leave blank to disable TLS verification)
# tls_ca_cert = "/var/lib/janus-agent/certs/ca.crt"
# tls_client_cert = "/var/lib/janus-agent/certs/client.crt"
# tls_client_key = "/var/lib/janus-agent/certs/client.key"

# Agent operation mode: "passive" (scanning only) or "active" (allows configuration mutations)
execution_mode = "active"

# Path to the local SQLite database cache (offline storage and logging)
cache_path = "janus-agent.sqlite3"

# File path where the agent persists its unique host UUID
host_uuid_path = "janus-host-id"

# File paths for saving local scan reports
report_path = "janus-agent-report.html"
sarif_path = "janus-agent.sarif"

# The frequency of passive filesystem scanning cycles (in seconds)
scan_interval_seconds = 900

# Limits file sizes to inspect (to prevent parsing large database or video files)
max_file_bytes = 2097152       # 2 MB for text source code files
max_binary_bytes = 16777216    # 16 MB for compiled binaries

# The symmetric HMAC key used to verify incoming migration commands.
# On Windows, prefix with "dpapi:" to read encrypted secrets from the registry.
# On UNIX, prefix with "plain:" to define plaintext keys.
command_signing_key = "local-development-command-signing-key"

# List of root folders where the agent scans for files
scan_roots = ["/etc", "/opt", "/var/www"]

# Folders excluded from filesystem sweeps
exclude_dirs = [".git", "target", "node_modules", "dist", ".venv", "__pycache__", "temp"]

# Target addresses for post-migration TLS connection verification checks
network_targets = ["127.0.0.1:443"]

# Directories containing custom scanning plugins
plugin_dirs = ["plugins"]

# Configures active mutation guardrails
[active]
# System service daemons the agent is allowed to restart or reload
allowed_services = ["nginx", "apache", "sshd"]

# Root directories where the agent is allowed to edit configuration files
allowed_config_roots = ["/etc/nginx", "/etc/apache2", "/etc/ssh"]

# Directory where original files are backed up before modification
backup_dir = "/var/lib/janus-agent/backups"
```

---

## 3. Installation & Provisioning Playbooks

### 3.1 Linux systemd Service Provisioning
Run the agent as a background daemon on Linux using a systemd service unit. 

To enforce security isolation and prevent unauthorized access, the service runs as a non-root user (`janusagent`) and uses systemd sandboxing parameters:

1.  **Create Service User**:
    ```bash
    sudo useradd -r -s /bin/false janusagent
    ```
2.  **Create Working Directories**:
    ```bash
    sudo mkdir -p /var/lib/janus-agent/backups
    sudo chown -R janusagent:janusagent /var/lib/janus-agent
    ```
3.  **Write systemd Configuration File**:
    Write the following systemd unit configuration to `/etc/systemd/system/janus-agent.service`:
    ```ini
    [Unit]
    Description=Janus CryptoBOM Endpoint Agent
    After=network.target
    Documentation=https://github.com/janus-cbom/janus

    [Service]
    Type=simple
    User=janusagent
    Group=janusagent
    WorkingDirectory=/var/lib/janus-agent
    ExecStart=/usr/local/bin/janus-agent --config /var/lib/janus-agent/janus-agent.toml
    Restart=on-failure
    RestartSec=10

    # ==========================================================================
    # Security Sandboxing & Hardening Guardrails
    # ==========================================================================
    ProtectSystem=strict
    ProtectHome=true
    PrivateTmp=true
    PrivateDevices=true
    NoNewPrivileges=true
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    RestrictRealtime=true
    RestrictSUIDSGID=true
    RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
    
    # Filesystem Restrictions
    ReadOnlyPaths=/
    ReadWritePaths=/var/lib/janus-agent/
    # If the agent is in active mode, grant access to specific application paths:
    # ReadWritePaths=/etc/nginx/
    # ReadWritePaths=/etc/ssh/
    # ReadWritePaths=/etc/apache2/

    [Install]
    WantedBy=multi-user.target
    ```
4.  **Start and Enable Service**:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl start janus-agent
    sudo systemctl enable janus-agent
    ```

---

### 3.2 Windows GPO & Service Distribution
In Active Directory Windows environments, distribute the agent across target endpoints using Group Policy Objects (GPO).

#### 1. Software Distribution via GPO
1.  Compile the agent for Windows (`x86_64-pc-windows-msvc` or `aarch64-pc-windows-msvc`).
2.  Package the executable `janus-agent.exe` and a default `janus-agent.toml` configuration template into a Microsoft Installer (`.msi`) package.
3.  Store the installer on a shared network drive accessible by all domain computer accounts (e.g., `\\corp-dc\SysVol\corp.local\Policies\Janus\`).
4.  Create a Group Policy Object named **Janus Agent Deployment** and assign the software package under `Computer Configuration -> Policies -> Software Settings -> Software installation`.

#### 2. DPAPI Secret Shielding
To secure credentials in transit and prevent plaintext storage of the `command_signing_key` on target endpoint filesystems, use the Windows Data Protection API (DPAPI). Administrators can deploy a PowerShell startup script via GPO to encrypt the plaintext HMAC key locally on the endpoint:

```powershell
# ==============================================================================
# PowerShell Script: Encrypt Command Signing Key with DPAPI
# ==============================================================================
Add-Type -AssemblyName System.Security

$configPath = "C:\Program Files\JanusAgent\janus-agent.toml"
if (-not (Test-Path $configPath)) {
    Write-Error "Agent configuration file not found."
    Exit 1
}

# The plaintext key to encrypt
$plainTextKey = "local-development-command-signing-key"

# Convert plaintext key to byte array
$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainTextKey)

# Encrypt key using DPAPI (machine-level scope)
$entropy = $null
$protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
    $plainBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)

# Convert encrypted bytes to Base64 and add the "dpapi:" prefix
$base64Encrypted = [System.Convert]::ToBase64String($protectedBytes)
$dpapiValue = "dpapi:$base64Encrypted"

# Update the janus-agent.toml file
$toml = Get-Content $configPath -Raw
if ($toml -match 'command_signing_key\s*=\s*".*?"') {
    $toml = $toml -replace 'command_signing_key\s*=\s*".*?"', "command_signing_key = `"$dpapiValue`""
    Set-Content -Path $configPath -Value $toml -NoNewline
    Write-Output "Successfully encrypted command_signing_key using DPAPI."
} else {
    Write-Error "Could not locate command_signing_key property in TOML configuration."
}
```

This PowerShell script reads the configuration template, encrypts the plaintext key using the machine's cryptographic keys, and updates the `command_signing_key` property with the DPAPI string prefix. The agent dynamically decrypts the key on startup, preventing unauthorized users from accessing the key in plaintext.

#### 3. Service Installation
Install the agent as a Windows service using GPO Startup Scripts:
```cmd
sc.exe create JanusAgent binPath= "C:\Program Files\JanusAgent\janus-agent.exe --config C:\Program Files\JanusAgent\janus-agent.toml" start= auto obj= "NT AUTHORITY\SYSTEM"
sc.exe start JanusAgent
```

---

### 3.3 Docker Compose Stack Configuration
For single-server deployments or localized testing, run the full stack using this Docker Compose configuration:

```yaml
version: "3.8"

services:
  postgres:
    image: postgres:16-alpine
    container_name: janus-postgres
    restart: always
    environment:
      POSTGRES_USER: janus
      POSTGRES_PASSWORD: janus
      POSTGRES_DB: janus
    ports:
      - "5432:5432"
    volumes:
      - pg-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U janus -d janus"]
      interval: 5s
      timeout: 5s
      retries: 5

  janus-server:
    image: janus-server:latest
    container_name: janus-server
    restart: always
    ports:
      - "8080:8080"
      - "9443:9443"
    environment:
      JANUS_DATABASE_URL: postgres://janus:janus@postgres:5432/janus?sslmode=disable
      JANUS_HTTP_ADDR: 0.0.0.0:8080
      JANUS_GRPC_ADDR: 0.0.0.0:9443
      JANUS_DISABLE_AUTH: "false"
      JANUS_COMMAND_SIGNING_KEY: local-development-command-signing-key
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/api/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  janus-agent:
    image: janus-agent:latest
    container_name: janus-agent
    restart: always
    environment:
      JANUS_CONTROLLER_ENDPOINT: http://janus-server:9443
      JANUS_SCAN_ROOTS: /scan
      JANUS_CACHE_PATH: /data/agent.db
    volumes:
      - .:/scan:ro
      - agent-data:/data
    depends_on:
      - janus-server

volumes:
  pg-data:
    name: janus_pg_data
  agent-data:
    name: janus_agent_data
```

---

## 4. Document References
*   [Janus Design Manual](design.md) — System architecture, database schema layout, gRPC service contracts, and workflow diagrams.
*   [Main README](../README.md) — Executive briefing, features comparison, and local building guide.
