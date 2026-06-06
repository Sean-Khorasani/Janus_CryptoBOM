# Janus CryptoBOM System Design Manual

This document provides the developer-level technical blueprint and system design specification for **Janus CryptoBOM**, an enterprise post-quantum cryptographic posture management (PQC-PM) and automated migration suite. 

---

## 1. Core System Architecture

Janus CryptoBOM uses a multi-tier architecture to identify, assess, and mitigate cryptographic vulnerabilities across remote systems. The system consists of four primary components:

```
+----------------------------------------------------------------------------------+
|                                  React SPA (ui/)                                 |
+----------------------------------------------------------------------------------+
                                         |
                                         | HTTPS REST API
                                         v
+----------------------------------------------------------------------------------+
|                        Go REST & gRPC Controller (server/)                       |
+----------------------------------------------------------------------------------+
                     |                                           |
                     | SQL Database Pool                         | gRPC over TLS 1.3
                     v                                           v
+----------------------------------------+   +-------------------------------------+
|      PostgreSQL Database (store/)      |   |     Rust Endpoint Agent (agent/)    |
+----------------------------------------+   +-------------------------------------+
```

### 1.1 Go HTTP REST & gRPC Controller
The central controller is written in Go, acting as the centralized authority. It exposes two interfaces:
*   **gRPC Server (Port 9443)**: Operates a bi-directional streaming control channel for agent synchronization, registrations, and remote migration command dispatches.
*   **HTTP REST API (Port 8080)**: Serves backend REST interfaces for the React SPA, provides Prometheus metrics instrumentation, exports compliance files (CSV, CycloneDX JSON, SARIF, SIEM), and serves local HTML reports.

The internal package structure under `server/` separates roles:
*   `cmd/janus-server/main.go`: Application entrypoint, environment bootstrapper, and signal handler.
*   `internal/config`: Loads server environment settings (`JANUS_DATABASE_URL`, `JANUS_GRPC_ADDR`, etc.).
*   `internal/store`: Manages PostgreSQL connection pools using pgx/v5 (`pgxpool`), applies automatic migrations, and runs paginated query logic.
*   `internal/orchestrator`: Manages live agent telemetry streaming connections, coordinates task execution queues, and structures HMAC-signed commands.
*   `internal/policy`: Evaluates cryptographic telemetry against compliance rules and OSV vulnerability databases to generate risk classifications.
*   `internal/httpapi`: Exposes REST endpoints, validates JWT operator/admin credentials, and outputs compliance data.
*   `internal/grpcserver`: Implements the `JanusTelemetry` gRPC service interface.

### 1.2 React SPA Frontend
The user console is a single-page web application located in `ui/`. It is built with:
*   **Vite**: Frontend toolchain and dev server.
*   **React 19 & TypeScript**: Provides a type-safe component-based user interface.
*   **Tailwind CSS & Lucide React**: Delivers utility-first styling and vector iconography.

The UI implements a centralized dashboard that displays fleet-wide posture statistics (active assets, vulnerable component counts, critical findings), an interactive force-directed dependency exposure graph illustrating cryptographic component usage, and a real-time status banner displaying agent scanning progress. In development, the Vite server runs on port 5173 and proxies `/api` endpoints to the Go server on port 8080.

### 1.3 PostgreSQL Database Schema
The server stores configuration profiles, agent registration status, cryptographic bill of materials (CBOM) metadata, and active migration states in PostgreSQL. The `store.Postgres` struct maintains the connection pool and executes schema updates on startup. Tables use relational constraints and indices on frequently queried foreign keys (`host_uuid`, `severity`, etc.) to guarantee optimal performance during large-scale telemetry uploads.

### 1.4 Rust Multi-Platform Agent
The endpoint agent is a native daemon written in Rust for minimal system overhead and compile-time memory safety. It runs in user space on Windows, Linux, and macOS.
*   **Passive Scan Engine**: Performs filesystem traversals and scans process memory and loaded libraries (DLLs) using custom scanning modules. It serializes findings into CycloneDX v1.6 CBOM format.
*   **Offline Cache Store**: Written to a local, encrypted SQLite database. Telmetries are stored locally when the central controller is unreachable, enabling reliable air-gapped operations.
*   **Communication Client**: Automatically connects to the controller gRPC server, performing registration handshakes and streaming local telemetry caches. It periodically sends HTTP heartbeats and log lines to the REST API.
*   **Mutation Engine**: Executes automated migration configurations in active execution mode. It verifies HMAC-SHA256 command signatures, generates configuration backups, applies unified patches, checks configuration syntaxes, reloads services, and rolls back files automatically upon verification failure.

---

## 2. Architectural Component Diagram

The following diagram illustrates the relationship between individual codebase modules, the persistent data layer, and the remote execution agent:

```mermaid
flowchart TD
    subgraph Frontend [React SPA Frontend - ui/]
        Dashboard[CISO Posture Dashboard]
        ExposureGraph[Dependency Exposure Graph]
        StatusBanner[Agent Status Banner]
        ProfileEditor[Fleet Profile Editor]
    end

    subgraph Controller [Go REST & gRPC Controller - server/]
        HTTPServer[HTTP REST API Server<br>internal/httpapi]
        gRPCServer[gRPC Telemetry Server<br>internal/grpcserver]
        OrchEngine[Orchestration Engine<br>internal/orchestrator]
        PolicyEngine[Compliance & Policy Engine<br>internal/policy]
        LLMClient[OSV & LLM Integration Client<br>internal/policy/osv]
    end

    subgraph DB [PostgreSQL Database]
        AssetsTable[(assets)]
        TelePayloadsTable[(telemetry_payloads)]
        FindingsTable[(crypto_findings)]
        MigrationsTable[(migration_transactions)]
        ProfilesTable[(config_profiles)]
        MappingsTable[(agent_profile_mappings)]
        AuditTable[(audit_logs)]
    end

    subgraph Agent [Rust Endpoint Agent - agent/]
        Scheduler[Internal Task Scheduler]
        StaticScan[Static Filesystem Scan / AST Scan]
        MemoryScan[Process Memory & DLL Hooking]
        LocalStore[(SQLite Local Store)]
        CommsClient[gRPC & TCP Comms Client]
        MutationEngine[Mutation Engine]
    end

    Dashboard & ExposureGraph & StatusBanner & ProfileEditor <-->|HTTPS REST API| HTTPServer
    HTTPServer <--> OrchEngine & PolicyEngine
    gRPCServer <--> OrchEngine
    OrchEngine & PolicyEngine <--> DB
    CommsClient <-->|gRPC Telemetry & Commands| gRPCServer
    CommsClient <-->|TCP Heartbeats & Diagnostics| HTTPServer
    Scheduler --> StaticScan & MemoryScan
    StaticScan & MemoryScan --> LocalStore
    LocalStore --> CommsClient
    MutationEngine -->|Config Backups & Patches| LocalStore
    CommsClient --> MutationEngine
```

---

## 3. Database Schema Blueprint

The physical database schema in PostgreSQL is managed dynamically by the central Go controller. Below is the detailed database structure:

### 3.1 Table: `assets`
Contains the inventory of all registered agents, their current platforms, and runtime performance indicators.
*   **Physical Table Name**: `assets`
*   **Primary Key**: `host_uuid` (TEXT)

| Column Name | Data Type | Constraints / Defaults | Description |
| :--- | :--- | :--- | :--- |
| `host_uuid` | TEXT | PRIMARY KEY | Unique UUID generated by the agent. |
| `hostname` | TEXT | NOT NULL | Endpoint hostname. |
| `os_name` | TEXT | NOT NULL | OS name (e.g. `windows`, `linux`, `macos`). |
| `os_version` | TEXT | NOT NULL | OS kernel release version. |
| `arch` | TEXT | NOT NULL | CPU architecture (e.g. `amd64`, `arm64`). |
| `execution_mode`| INTEGER | NOT NULL | 1 = Passive, 2 = Active. |
| `capabilities` | JSONB | NOT NULL DEFAULT '[]' | String list of supported agent modules. |
| `last_seen` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Last heartbeat sync timestamp. |
| `scan_progress` | INTEGER | NOT NULL DEFAULT 0 | Percentage progress of active scanning run. |
| `current_scan_path`| TEXT | NOT NULL DEFAULT '' | Currently traversed directory. |
| `cpu_usage` | DOUBLE PREC | NOT NULL DEFAULT 0.0 | CPU load percentage on agent endpoint. |
| `mem_usage` | DOUBLE PREC | NOT NULL DEFAULT 0.0 | Memory footprint in megabytes. |
| `status` | TEXT | NOT NULL DEFAULT 'offline' | Logical agent status (e.g. `scanning`, `idle`, `offline`). |
| `total_files_scanned`| INTEGER| NOT NULL DEFAULT 0 | Count of inspected files on current pass. |

### 3.2 Table: `telemetry_payloads`
Stores the raw and parsed CBOM and SBOM telemetry datasets uploaded by the agents.
*   **Physical Table Name**: `telemetry_payloads`
*   **Primary Key**: `telemetry_id` (TEXT)

| Column Name | Data Type | Constraints / Defaults | Description |
| :--- | :--- | :--- | :--- |
| `telemetry_id` | TEXT | PRIMARY KEY | Unique payload session UUID. |
| `host_uuid` | TEXT | NOT NULL REFERENCES `assets(host_uuid)` ON DELETE CASCADE | Target asset reference. |
| `scan_started` | TIMESTAMPTZ| NOT NULL | Timestamp when telemetry collection began. |
| `scan_finished` | TIMESTAMPTZ| NOT NULL | Timestamp when telemetry collection ended. |
| `component_count` | INTEGER | NOT NULL | Count of components inside the payload. |
| `finding_count` | INTEGER | NOT NULL | Count of cryptographical findings reported. |
| `network_observation_count`| INTEGER| NOT NULL | Count of cipher configurations monitored. |
| `cyclone_dx` | JSONB | NULL | Structural CycloneDX v1.6 compliance document. |
| `payload` | JSONB | NOT NULL | Raw protobuf-to-JSON serialized dataset. |
| `received_at` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Telemetry arrival time. |

### 3.3 Table: `crypto_findings` (Logical Entity: findings)
Maintains specific cryptographic policy violations, vulnerable algorithms, and unsafe libraries detected on endpoints.
*   **Physical Table Name**: `crypto_findings`
*   **Primary Key**: `finding_id` (TEXT)
*   **Unique Index**: `UNIQUE (asset_ref, algorithm, policy_rule_id)` (prevents duplicate findings)

| Column Name | Data Type | Constraints / Defaults | Description |
| :--- | :--- | :--- | :--- |
| `finding_id` | TEXT | PRIMARY KEY | Unique finding UUID. |
| `telemetry_id` | TEXT | NOT NULL REFERENCES `telemetry_payloads(telemetry_id)` ON DELETE CASCADE | Associated telemetry payload trace. |
| `host_uuid` | TEXT | NOT NULL REFERENCES `assets(host_uuid)` ON DELETE CASCADE | Target asset reference. |
| `severity` | INTEGER | NOT NULL | 1 = Info, 2 = Low, 3 = Med, 4 = High, 5 = Critical. |
| `title` | TEXT | NOT NULL | Brief finding title (e.g. `Vulnerable Key Size`). |
| `description` | TEXT | NOT NULL | Detailed context and path locations. |
| `asset_ref` | TEXT | NOT NULL | Component BOM-ref locator link. |
| `algorithm` | TEXT | NOT NULL | Associated algorithm (e.g. `RSA-1024`, `MD5`). |
| `policy_rule_id` | TEXT | NOT NULL | Violated posture policy engine identifier. |
| `migration_profile`| TEXT | NOT NULL | Target migration pathway. |
| `evidence_ids` | JSONB | NOT NULL DEFAULT '[]' | File and location proof identifier mappings. |
| `status` | TEXT | NOT NULL DEFAULT 'open' | Lifecycle state: `open`, `accepted_risk`, `false_positive`, `remediated`. |
| `updated_by` | TEXT | NOT NULL DEFAULT '' | Admin operator identity that altered the status. |
| `updated_at` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Last modification time. |
| `created_at` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Finding registration time. |
| `confidence` | DOUBLE PREC | NOT NULL DEFAULT 0.82 | Heuristic context scoring confidence value. |

### 3.4 Table: `migration_transactions` (Logical Entity: migrations)
Tracks the step-by-step state of mutation configurations applied to the endpoints.
*   **Physical Table Name**: `migration_transactions`
*   **Primary Key**: `command_id` (TEXT)

| Column Name | Data Type | Constraints / Defaults | Description |
| :--- | :--- | :--- | :--- |
| `command_id` | TEXT | PRIMARY KEY | Unique migration task identifier. |
| `host_uuid` | TEXT | NOT NULL REFERENCES `assets(host_uuid)` ON DELETE CASCADE | Targeted agent endpoint. |
| `target_service` | TEXT | NOT NULL | Name of target daemon (e.g. `nginx`, `sshd`). |
| `migration_profile`| TEXT | NOT NULL | Target PQC configuration profile. |
| `target_kem` | TEXT | NOT NULL | Target PQC Key-Encapsulation Mechanism. |
| `target_signature` | TEXT | NOT NULL | Target digital signature algorithm. |
| `config_path` | TEXT | NOT NULL | Target file system path containing target settings. |
| `state` | INTEGER | NOT NULL | State code (pending, applying, succeeded, etc.). |
| `dry_run` | BOOLEAN | NOT NULL | Dry run flag (skips filesystem writes). |
| `issued_at` | TIMESTAMPTZ| NOT NULL | Timestamp when command was dispatched. |
| `updated_at` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Last migration status update timestamp. |
| `last_error` | TEXT | NOT NULL DEFAULT '' | String serialization of execution error stack. |
| `output` | TEXT | NOT NULL DEFAULT '' | Target standard output or console logs from run. |
| `observed_tls` | JSONB | NULL | Post-migration network handshake observation details. |

### 3.5 Table: `config_profiles` (Logical Entity: fleet_profiles)
Stores the collection of configuration profiles defining scanning exclusions and rules for subsets of agents.
*   **Physical Table Name**: `config_profiles`
*   **Primary Key**: `profile_id` (TEXT)

| Column Name | Data Type | Constraints / Defaults | Description |
| :--- | :--- | :--- | :--- |
| `profile_id` | TEXT | PRIMARY KEY | Unique configuration profile UUID. |
| `name` | TEXT | NOT NULL | Human-readable name. |
| `exclude_dirs` | TEXT | NOT NULL DEFAULT '' | Comma-delimited list of scanning exclusions. |
| `min_key_size` | INTEGER | NOT NULL DEFAULT 2048 | Minimum allowed RSA key size in bits. |
| `scan_schedule` | TEXT | NOT NULL DEFAULT 'daily' | Cron execution schedule syntax. |
| `llm_api_key` | TEXT | NOT NULL DEFAULT '' | Context API key for LLM assessment services. |
| `llm_api_url` | TEXT | NOT NULL DEFAULT 'https://api.openai.com/v1' | Target API proxy URL. |
| `updated_at` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Last modification time. |

### 3.6 Table: `agent_profile_mappings` (Logical Entity: fleet_mappings)
Maps specific agents to their designated configuration profiles.
*   **Physical Table Name**: `agent_profile_mappings`
*   **Primary Key**: `host_uuid` (TEXT)

| Column Name | Data Type | Constraints / Defaults | Description |
| :--- | :--- | :--- | :--- |
| `host_uuid` | TEXT | PRIMARY KEY REFERENCES `assets(host_uuid)` ON DELETE CASCADE | Associated agent UUID. |
| `profile_id` | TEXT | NOT NULL REFERENCES `config_profiles(profile_id)` ON DELETE CASCADE | Assigned profile UUID. |
| `mapped_at` | TIMESTAMPTZ| NOT NULL DEFAULT `now()` | Mapping creation timestamp. |

---

## 4. API Contract Reference

### 4.1 HTTP REST API Endpoints

All REST APIs run on port 8080 and require Bearer Token authorization unless `JANUS_DISABLE_AUTH=true` is set.

#### 1. POST `/api/auth/login`
Authenticates administration operators and issues JWT tokens.
*   **Role Permission**: Anonymous
*   **Request Payload**:
    ```json
    {
      "username": "admin",
      "password": "secure_password"
    }
    ```
*   **Response Payload (200 OK)**:
    ```json
    {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "username": "admin",
      "role": "admin"
    }
    ```

#### 2. GET `/api/overview`
Retrieves consolidated count statistics of assets, components, findings, and algorithms.
*   **Role Permission**: Operator, Admin
*   **Response Payload (200 OK)**:
    ```json
    {
      "assets": 12,
      "components": 342,
      "findings": 47,
      "critical_findings": 3,
      "high_findings": 14,
      "open_migrations": 1,
      "algorithm_histogram": {
        "RSA-1024": 15,
        "SHA1": 22,
        "ECDSA-P256": 8
      }
    }
    ```

#### 3. GET `/api/findings`
Lists security posture findings. Supports pagination, sorting, and keyword searching.
*   **Query Parameters**:
    *   `limit`: Integer. Limits result count (default: `50`, max: `500`).
    *   `offset`: Integer. Starts response window (default: `0`).
    *   `sort`: Column sort choice: `severity`, `algorithm`, `asset_ref`, `policy_rule_id`, `created_at`, `status` (default: `severity`).
    *   `order`: Direction: `asc` | `desc` (default: `desc`).
    *   `search`: Search string (filters matching `title`, `description`, `asset_ref`, `algorithm`, `policy_rule_id`).
*   **Response Headers**:
    *   `X-Total-Count`: Total matched findings count in database.
*   **Response Payload (200 OK)**:
    ```json
    [
      {
        "finding_id": "f5127d14-386b-4e89-be2a-43c39352be55",
        "host_uuid": "3e9b1d7d-bc65-4927-aa87-d4215dbd0fef",
        "severity": 4,
        "title": "Quantum-Vulnerable Key Exchange",
        "description": "Monitored ephemeral Diffie-Hellman key exchange utilizing classic DH groups.",
        "asset_ref": "pkg:generic/nginx@1.25.1",
        "algorithm": "DH-1024",
        "policy_rule_id": "PQC-RULE-002",
        "migration_profile": "nginx-hybrid-kem",
        "status": "open",
        "updated_by": "",
        "updated_at": "2026-06-06T07:12:00Z",
        "created_at": "2026-06-06T07:12:00Z",
        "confidence": 0.95
      }
    ]
    ```

#### 4. PUT `/api/findings/{id}/status`
Updates lifecycle state of a specific posture finding.
*   **Role Permission**: Operator, Admin
*   **Request Payload**:
    ```json
    {
      "status": "accepted_risk",
      "updated_by": "operator_john"
    }
    ```
*   **Response Payload (200 OK)**:
    ```json
    {
      "finding_id": "f5127d14-386b-4e89-be2a-43c39352be55",
      "status": "accepted_risk"
    }
    ```

#### 5. POST `/api/migrations/enqueue`
Enqueues a signed active PQC config modification command.
*   **Role Permission**: Operator, Admin
*   **Request Payload**:
    ```json
    {
      "host_uuid": "3e9b1d7d-bc65-4927-aa87-d4215dbd0fef",
      "target_service": "nginx",
      "migration_profile": "nginx-hybrid-kem",
      "config_path": "/etc/nginx/nginx.conf",
      "patch_unified_diff": "--- /etc/nginx/nginx.conf\n+++ /etc/nginx/nginx.conf\n@@ -3,3 +3,3 @@\n-ssl_protocols TLSv1.2;\n+ssl_protocols TLSv1.3;\n",
      "dry_run": false
    }
    ```
*   **Response Payload (202 Accepted)**:
    ```json
    {
      "command_id": "c71a3962-d278-43d9-a41e-f32a76f2cd11",
      "host_uuid": "3e9b1d7d-bc65-4927-aa87-d4215dbd0fef",
      "target_service": "nginx",
      "migration_profile": "nginx-hybrid-kem",
      "target_kem": "ML-KEM-768",
      "target_signature": "ML-DSA-65",
      "config_path": "/etc/nginx/nginx.conf",
      "state": 1,
      "dry_run": false,
      "issued_at_unix": 1780730000
    }
    ```

### 4.2 gRPC Service Definition

Defined in `proto/janus.proto`. The interface uses streaming APIs to process asynchronous telemetry payloads and stream migration events.

```protobuf
syntax = "proto3";

package janus.v1;

option go_package = "github.com/janus-cbom/janus/server/internal/pb;pb";

enum ExecutionMode {
  EXECUTION_MODE_UNSPECIFIED = 0;
  EXECUTION_MODE_PASSIVE = 1;
  EXECUTION_MODE_ACTIVE = 2;
}

enum CryptoRole {
  CRYPTO_ROLE_UNSPECIFIED = 0;
  CRYPTO_ROLE_KEM = 1;
  CRYPTO_ROLE_KEY_EXCHANGE = 2;
  CRYPTO_ROLE_SIGNATURE = 3;
  CRYPTO_ROLE_CERT_PUBLIC_KEY = 4;
  CRYPTO_ROLE_CERT_SIGNATURE = 5;
  CRYPTO_ROLE_SYMMETRIC = 6;
  CRYPTO_ROLE_HASH = 7;
  CRYPTO_ROLE_MAC = 8;
  CRYPTO_ROLE_KDF = 9;
  CRYPTO_ROLE_RANDOM = 10;
  CRYPTO_ROLE_KEY_STORAGE = 11;
}

enum RiskSeverity {
  RISK_SEVERITY_UNSPECIFIED = 0;
  RISK_SEVERITY_INFO = 1;
  RISK_SEVERITY_LOW = 2;
  RISK_SEVERITY_MEDIUM = 3;
  RISK_SEVERITY_HIGH = 4;
  RISK_SEVERITY_CRITICAL = 5;
}

enum MigrationState {
  MIGRATION_STATE_UNSPECIFIED = 0;
  MIGRATION_STATE_PENDING = 1;
  MIGRATION_STATE_LOCKED = 2;
  MIGRATION_STATE_APPLYING = 3;
  MIGRATION_STATE_VALIDATING = 4;
  MIGRATION_STATE_ROLLING_BACK = 5;
  MIGRATION_STATE_SUCCEEDED = 6;
  MIGRATION_STATE_FAILED = 7;
}

message AgentRegistration {
  string host_uuid = 1;
  string hostname = 2;
  repeated string hardware_signatures = 3;
  string os_name = 4;
  string os_version = 5;
  string arch = 6;
  ExecutionMode execution_mode = 7;
  string agent_version = 8;
  repeated string capabilities = 9;
  int64 registered_at_unix = 10;
}

message AgentRegistrationAck {
  string host_uuid = 1;
  bool accepted = 2;
  string controller_id = 3;
  string policy_version = 4;
  repeated string enabled_capabilities = 5;
  string message = 6;
}

message CbomTelemetryPayload {
  string telemetry_id = 1;
  string host_uuid = 2;
  int64 scan_started_unix = 3;
  int64 scan_finished_unix = 4;
  repeated CbomComponent components = 5;
  repeated CryptoFinding findings = 6;
  repeated NetworkObservation network_observations = 7;
  repeated Evidence evidence = 8;
  string cyclone_dx_json = 9;
}

message CbomComponent {
  string bom_ref = 1;
  string name = 2;
  string version = 3;
  string component_type = 4;
  string purl = 5;
  string file_path = 6;
  string language = 7;
  repeated CryptoAlgorithm algorithms = 8;
  repeated string dependencies = 9;
  bool reachable = 10;
}

message CryptoAlgorithm {
  string name = 1;
  string family = 2;
  CryptoRole role = 3;
  string status = 4;
  uint32 key_bits = 5;
  string curve = 6;
  string implementation_library = 7;
  string source_file = 8;
  uint32 source_line = 9;
  uint32 source_column = 10;
  string symbol = 11;
  double confidence = 12;
  bool quantum_vulnerable = 13;
}

message CryptoFinding {
  string finding_id = 1;
  RiskSeverity severity = 2;
  string title = 3;
  string description = 4;
  string asset_ref = 5;
  string algorithm = 6;
  string policy_rule_id = 7;
  repeated string evidence_ids = 8;
  string migration_profile = 9;
}

message NetworkObservation {
  string endpoint = 1;
  string protocol = 2;
  string tls_version = 3;
  string cipher_suite = 4;
  string named_group = 5;
  string signature_algorithm = 6;
  string certificate_subject = 7;
  string certificate_issuer = 8;
  int64 certificate_not_after_unix = 9;
  bool pqc_hybrid = 10;
  bool cleartext = 11;
}

message Evidence {
  string evidence_id = 1;
  string source_type = 2;
  string source_tool = 3;
  string target = 4;
  int64 collection_time_unix = 5;
  string raw_artifact_sha256 = 6;
  double confidence = 7;
  string sensitivity_class = 8;
}

message MigrationCommand {
  string command_id = 1;
  string host_uuid = 2;
  string target_service = 3;
  string migration_profile = 4;
  string target_kem = 5;
  string target_signature = 6;
  string config_path = 7;
  repeated string validation_checklist = 8;
  uint32 rollback_window_seconds = 9;
  string patch_unified_diff = 10;
  bytes signed_directive = 11;
  int64 issued_at_unix = 12;
  bool dry_run = 13;
}

message MigrationStatusReport {
  string command_id = 1;
  string host_uuid = 2;
  MigrationState state = 3;
  bool success = 4;
  string error_vector = 5;
  string output = 6;
  repeated string validation_signatures = 7;
  NetworkObservation observed_tls = 8;
  int64 reported_at_unix = 9;
}

message MigrationStatusAck {
  string command_id = 1;
  bool accepted = 2;
  string message = 3;
}

service JanusTelemetry {
  rpc RegisterAgent(AgentRegistration) returns (AgentRegistrationAck);
  rpc StreamTelemetry(stream CbomTelemetryPayload) returns (stream MigrationCommand);
  rpc ReportMigrationStatus(stream MigrationStatusReport) returns (MigrationStatusAck);
}
```

---

## 5. System Control Flow & Sequence Diagrams

### 5.1 Telemetry Ingestion Sequence
During normal operations, the agent collects local cryptographic metadata and streams it to the controller. The sequence handles network drops by buffer queuing payloads in SQLite:

```mermaid
sequenceDiagram
    participant Agent as Rust Endpoint Agent
    participant Cache as Agent SQLite Cache
    participant gRPC as Go gRPC Server
    participant HTTP as Go HTTP Server
    participant DB as PostgreSQL Database
    participant UI as React UI Console

    Agent->>Agent: Run startup diagnostic self-tests
    Agent->>gRPC: RegisterAgent(AgentRegistration)
    gRPC->>DB: Upsert registration status in assets table
    DB-->>gRPC: Success
    gRPC-->>Agent: AgentRegistrationAck(accepted = true)
    
    rect rgb(230, 245, 230)
        Note over Agent: Scan Phase (scheduled)
        Agent->>Agent: Crawl scan_roots and read process memory/DLL maps
        Agent->>Agent: Parse cryptographic keys and identify algorithms
        Agent->>Agent: Assemble CycloneDX compliance CBOM document
        Agent->>Cache: Enqueue CbomTelemetryPayload into local cache
    end

    rect rgb(240, 240, 255)
        Note over Agent: Sync Phase
        Agent->>Cache: Load pending payloads (pending_payloads)
        Agent->>gRPC: StreamTelemetry(stream CbomTelemetryPayload)
        gRPC->>DB: Begin database transaction
        gRPC->>DB: Write row to telemetry_payloads (CycloneDX JSON)
        gRPC->>DB: Upsert matched findings to crypto_findings
        gRPC->>DB: Commit database transaction
        DB-->>gRPC: Transaction committed
        gRPC-->>Agent: Respond with stream of MigrationCommand (if any)
        Agent->>Cache: Delete synced telemetry UUIDs (delete_payload)
    end

    loop Every 5s (Heartbeat)
        Agent->>HTTP: POST /api/agent/heartbeat (system metrics, scanning state)
        HTTP->>DB: Update last seen status, CPU, memory, and scan path
        UI->>HTTP: Poll /api/overview and /api/assets
        HTTP-->>UI: Update posture safety dashboard, charts, and agent status banner
    end
```

### 5.2 Active Migration Sequence
When migrating systems to modern PQC standards, commands are enqueued, signed, verified, validated locally, and rolled back if validation checks fail:

```mermaid
sequenceDiagram
    actor Admin as Security Admin / Operator
    participant UI as React UI Console
    participant REST as Go HTTP REST API
    participant Orch as Orchestration Engine
    participant gRPC as Go gRPC Server
    participant Agent as Rust Endpoint Agent
    participant Backup as Agent Backup Folder
    participant Daemon as Managed Daemon (Nginx/Apache/SSHD)
    participant DB as PostgreSQL Database

    Admin->>UI: Request migration (Select target config path, input patch unified diff)
    UI->>REST: POST /api/migrations/enqueue (enqueueRequest)
    Note over REST: Authorize: Verify admin / operator session role
    REST->>DB: GetLatestConfigHash(host_uuid, config_path)
    DB-->>REST: Return last known sha256 checksum (drift check)
    REST->>Orch: BuildCommand() and generate signed_directive (HMAC-SHA256)
    REST->>DB: Log migration transaction details (PENDING state)
    REST-->>UI: Return 202 Accepted (Command ID)
    Orch->>gRPC: Enqueue migration task to streaming channel
    gRPC->>Agent: Stream MigrationCommand
    
    rect rgb(255, 240, 240)
        Note over Agent: Mutation Verification Guard
        Agent->>Agent: Verify signed_directive with local HMAC-SHA256 key
        Agent->>Agent: Verify config_path is in allowed_config_roots list
        Agent->>Agent: Verify file extension is safe (not restricted)
        Agent->>Agent: Verify current file checksum matches validation checklist (drift check)
        Agent->>Backup: Write configuration backup file (.bak)
        Agent->>Agent: Apply patch_unified_diff to in-memory configuration file
        Agent->>Agent: Overwrite target path with patched configuration contents
    end

    rect rgb(240, 255, 240)
        Note over Agent: Integration Validation
        Agent->>Agent: Validate configuration syntax (nginx -t / apachectl configtest / sshd -t)
        alt Syntax Verification Fails
            Agent->>Agent: Restores original config file from backup (.bak)
            Agent->>gRPC: Send MigrationStatusReport(state = FAILED, error = "Syntax verification failed")
        else Syntax Verification Passes
            Agent->>Daemon: Trigger graceful reload command (SIGHUP / Restart-Service / systemctl reload)
            Agent->>Agent: Validate post-migration network socket TLS connection (verify handshake)
            alt Network TLS Verification Fails
                Agent->>Agent: Restores original config file from backup (.bak)
                Agent->>Daemon: Trigger graceful reload to revert daemon to previous state
                Agent->>gRPC: Send MigrationStatusReport(state = FAILED, error = "Post-migration TLS verification failed")
            else Network TLS Verification Passes
                Agent->>gRPC: Send MigrationStatusReport(state = SUCCEEDED, validation_signatures, observed_tls)
            end
        end
    end

    gRPC->>DB: Update migration state (SUCCEEDED / FAILED), error details, and observed TLS
    DB-->>UI: Update migration status grid and audit log
```

---

## 6. Activity Diagrams

### 6.1 Agent Run Loop
The agent daemon schedules and executes telemetry gathering and synchronizations using the following logic sequence:

```mermaid
flowchart TD
    Start([Agent Execution Started]) --> LoadConfig[Load agent configuration from janus-agent.toml]
    LoadConfig --> OpenCache[Open local SQLite database and verify tables]
    OpenCache --> SelfTest[Execute diagnostic self-test suite]
    SelfTest --> SpawnHeartbeat[Spawn background thread: periodic heartbeat and diagnostic logs]
    
    subgraph RunLoop [Scheduled Scanning Cycle]
        TriggerScan[Scheduled ticker trigger: scan_interval_seconds] --> ResetMetrics[Reset scan progress and metrics]
        ResetMetrics --> ScanSys[Inventory OS metadata, system resources, and CNG/CryptoAPI providers]
        ScanSys --> ScanFiles[Crawl filesystem scan roots for source, binaries, and configurations]
        ScanFiles --> ScanMem[Dynamic scan of active process memory footprints and loaded DLLs]
        ScanMem --> GenerateCBOM[Construct CycloneDX v1.6 CBOM payload]
        GenerateCBOM --> EvaluatePolicy[Check findings against policies and calculate confidence levels]
        EvaluatePolicy --> WriteLocal[Export local HTML and SARIF reports to disk]
        WriteLocal --> SaveCache[Enqueue CBOM telemetry payload into SQLite cache]
        SaveCache --> SyncCheck{Controller gRPC endpoint reachable?}
        
        SyncCheck -- Yes --> Register[Perform gRPC registration handshake]
        Register --> SyncPayloads[Stream pending cached payloads]
        SyncPayloads --> ReceiveCmds[Process pending Migration Commands]
        ReceiveCmds --> ClearCache[Delete synchronized payloads from SQLite cache]
        ClearCache --> SleepScan[Wait for next scheduled scanning cycle]
        
        SyncCheck -- No --> LogDefer[Buffer logs in SQLite cache]
        LogDefer --> SleepScan
    end
    
    SpawnHeartbeat --> TriggerScan
    SleepScan --> TriggerScan
```

### 6.2 Mutation Safety Boundaries
The agent isolates, verifies, validates, and rolls back configuration modifications using the following guardrails:

```mermaid
flowchart TD
    ReceiveCmd([Receive Migration Command]) --> CheckMode{Is agent execution_mode == active?}
    CheckMode -- No --> RejectPassive[Reject: Active mutation disabled in passive mode]
    CheckMode -- Yes --> HMACCheck{Does HMAC-SHA256 signature verification pass?}
    
    HMACCheck -- No --> RejectSignature[Reject: Invalid signed directive key signature]
    HMACCheck -- Yes --> RootCheck{Is config_path located within allowed_config_roots?}
    
    RootCheck -- No --> RejectPath[Reject: Config path falls outside allowed file tree boundaries]
    RootCheck -- Yes --> ExtCheck{Is the file extension restricted?}
    
    ExtCheck -- Yes --> RejectExt[Reject: Restricted file extension blocked to prevent system write]
    ExtCheck -- No --> DriftCheck{Does target file checksum match validation checklist checksum?}
    
    DriftCheck -- No --> RejectDrift[Reject: File modification blocked due to configuration drift]
    DriftCheck -- Yes --> SaveBackup[Generate copy of target file in backup directory]
    
    SaveBackup --> ApplyPatch[Parse and apply patch_unified_diff to configuration contents]
    ApplyPatch --> WritePatch[Write patched contents to target config_path]
    WritePatch --> ValidateSyntax{Does configuration syntax validation command pass?}
    
    ValidateSyntax -- No --> RollbackBackup1[Rollback: Overwrite target path with backup file]
    RollbackBackup1 --> ReportFailSyntax[Report Migration FAILED: Configuration syntax error]
    
    ValidateSyntax -- Yes --> ReloadDaemon[Gracefully reload daemon service]
    ReloadDaemon --> TLSVerify{Do post-migration network TLS handshake connections pass?}
    
    TLSVerify -- No --> RollbackBackup2[Rollback: Overwrite target path with backup file]
    RollbackBackup2 --> ReloadDaemon2[Gracefully reload daemon to restore original state]
    ReloadDaemon2 --> ReportFailTLS[Report Migration FAILED: Network TLS handshake verification failed]
    
    TLSVerify -- Yes --> ReportSuccess[Report Migration SUCCEEDED: Send observed TLS & verification signatures]

    RejectPassive & RejectSignature & RejectPath & RejectExt & RejectDrift --> FailTerminal([Terminal Failure State])
    ReportFailSyntax & ReportFailTLS --> FailTerminal
    ReportSuccess --> SuccessTerminal([Migration Task Succeeded])
```

---

## 7. Developer Environment Setup

This section outlines the setup steps to configure, build, and debug the Janus CryptoBOM codebase in a local development environment.

### 7.1 Go Server & PostgreSQL Setup
1.  **Install Prerequisites**: Install Go (v1.21+) and PostgreSQL (v14+).
2.  **Database Configuration**:
    Create a dedicated PostgreSQL user and database:
    ```sql
    CREATE ROLE janus WITH LOGIN PASSWORD 'janus';
    CREATE DATABASE janus OWNER janus;
    GRANT ALL PRIVILEGES ON DATABASE janus TO janus;
    ```
3.  **Environment Variables**:
    Set the environment variables to configure the database connection pool and server listeners:
    ```bash
    export JANUS_DATABASE_URL="postgres://janus:janus@127.0.0.1:5432/janus?sslmode=disable"
    export JANUS_GRPC_ADDR="127.0.0.1:9443"
    export JANUS_HTTP_ADDR="127.0.0.1:8080"
    export JANUS_COMMAND_SIGNING_KEY="local-development-command-signing-key"
    export JANUS_DISABLE_AUTH="true"
    ```
4.  **Run Server**:
    Navigate to the root server folder and compile/run the backend server:
    ```bash
    cd server
    go run cmd/janus-server/main.go
    ```
    *Note: The database tables and schemas will be created automatically on startup.*

### 7.2 React SPA & Vite Setup
1.  **Install Node.js**: Install Node.js (v18+) and npm.
2.  **Install Dependencies**:
    Navigate to the UI folder and install dependency packages:
    ```bash
    cd ui
    npm install
    ```
3.  **Vite Dev Server Configuration**:
    Vite dev server is configured in `vite.config.ts` to run on port `5173` and proxy API calls:
    ```typescript
    import { defineConfig } from "vite";
    import react from "@vitejs/plugin-react";

    export default defineConfig({
      plugins: [react()],
      server: {
        port: 5173,
        proxy: {
          "/api": "http://127.0.0.1:8080"
        }
      }
    });
    ```
4.  **Launch Web UI**:
    Start the Vite dev server:
    ```bash
    npm run dev
    ```
    Open `http://127.0.0.1:5173` in a browser.

### 7.3 Debugging Rust Agents
1.  **Install Rust**: Install Rust and Cargo (`rustup`).
2.  **Generate Agent Configuration**:
    Copy the sample configuration file to the working folder:
    ```bash
    cp agent/janus-agent.example.toml janus-agent.toml
    ```
3.  **Configure Environment Variables**:
    Build and run the agent in debug mode:
    ```bash
    # Run a single scan and synchronize to the controller
    cargo run --bin janus-agent -- --config janus-agent.toml --once
    
    # Run the agent in daemon mode
    cargo run --bin janus-agent -- --config janus-agent.toml
    ```
4.  **Database Inspection**:
    To inspect the local cache database status on the endpoint:
    ```bash
    sqlite3 janus-agent.sqlite3 "SELECT * FROM agent_audit"
    sqlite3 janus-agent.sqlite3 "SELECT * FROM queued_telemetry"
    ```
5.  **Log Level Control**:
    Set the rust logging environment variable to output verbose tracing:
    ```bash
    export RUST_LOG=debug
    cargo run --bin janus-agent -- --config janus-agent.toml
    ```

---

## 8. Document References
*   [Janus Deployment Guide](deployment.md) — Production HA setups, sandboxing configurations, systemd and GPO installations.
*   [Main README](../README.md) — Platform overview, feature comparisons, and quickstart instructions.
