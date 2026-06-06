# Janus CryptoBOM: Enterprise Case Studies & Playbooks

This document contains 10 production-grade, end-to-end deployment case studies and playbooks for Janus CryptoBOM. They cover scenarios ranging from simple passive compliance audits to complex, multi-stage, post-quantum cryptographic (PQC) migrations with failover rollback capability.

---

## Scenario Summary Matrix

| ID | Title | Complexity | Target OS / Env | Core Technology | Migration / Remediation Action |
|:---|:---|:---|:---|:---|:---|
| **1** | [Passive CI/CD Compliance Check](#case-study-1-passive-cicd-compliance-check) | Simple | Linux / Windows | CLI / Headless Agent | Blocks PR merge upon discovering quantum-vulnerable algorithms |
| **2** | [Host Certificate Store Audit](#case-study-2-host-certificate-store-audit) | Simple | Windows | PowerShell / Certutil | Automated reporting of legacy SHA-1 and weak RSA certificates |
| **3** | [Open Listening Sockets Discovery](#case-study-3-open-listening-sockets-discovery) | Simple | Cross-platform | Socket API / Get-NetTCPConnection | Discovers unencrypted ports (FTP/HTTP) and registers CBOM exposure |
| **4** | [Fleet TLS Protocol Policy Sweeping](#case-study-4-fleet-tls-protocol-policy-sweeping) | Medium | Windows Server | Schannel Registry Mutator | Fleet-wide deactivation of TLS 1.0/1.1 and promotion to TLS 1.2/1.3 |
| **5** | [Shadow Crypto Loaded Process DLL Auditing](#case-study-5-shadow-crypto-loaded-process-dll-auditing) | Medium | Windows | Toolhelp32 APIs / Symbol Audit | Runtime tracking of loaded legacy OpenSSL and bcrypt library hooks |
| **6** | [Supply Chain Vulnerability Sync via OSV.dev](#case-study-6-supply-chain-vulnerability-sync-via-osvdev) | Medium | Go Server backend | OSV.dev JSON API / Cargo & npm | Automatically flags libraries with known CVEs in cryptographic functions |
| **7** | [End-to-End Automated Nginx PQC Migration](#case-study-7-end-to-end-automated-nginx-pqc-migration) | Complex | Linux (Ubuntu/Debian) | EST / ACME, Nginx Config, Diff | Swap legacy RSA certificate for ML-KEM/hybrid cert; reload & test |
| **8** | [Automatic Failover Rollback of Schannel Policy](#case-study-8-automatic-failover-rollback-of-schannel-policy) | Complex | Windows Server | Registry Backup / Loopback Test | Roll back Schannel updates to last-known-good backup if test fails |
| **9** | [Deep RAM Scraping for Plaintext Key Exposure](#case-study-9-deep-ram-scraping-for-plaintext-key-exposure) | Complex | Windows / JVM | ReadProcessMemory / DPAPI | Memory inspection to detect private keys; shield using local DPAPI |
| **10** | [Remote CA Root Certificate Rotation](#case-study-10-remote-ca-root-certificate-rotation) | Complex | Windows Enterprise | PowerShell Cert store / ML-DSA | Deploy ML-DSA root CA certificate with atomic rollback on trust failure |

---

## Simple Scenarios

### Case Study 1: Passive CI/CD Compliance Check

#### Objective
Integrate the headless `janus-agent` into a GitHub Actions or GitLab CI/CD pipeline to scan repository source code, identify quantum-vulnerable cryptographic algorithms (such as RSA-1024, RSA-2048, 3DES, MD5, and SHA-1), and block non-compliant commits from merging.

#### Execution Workflow
1. The developer submits a Pull Request containing source code containing legacy cryptography (e.g., using `crypto/rsa` in Go or `java.security.KeyPairGenerator` in Java with a 1024-bit key size).
2. The CI runner executes the headless `janus-agent` pointing to the repository clone path.
3. The agent parses the Abstract Syntax Tree (AST), identifies the insecure algorithm, generates a CycloneDX CBOM, and returns exit code `1` to block the build.

#### Pipeline Command
```bash
# Execute headless scan on repository directory
./bin/janus-agent.exe --once --scan-path D:\src\app-repository --output-format cyclonedx --fail-on-vulnerability
```

#### Local Configuration (`janus-agent.toml`)
```toml
[agent]
host_uuid = "e87f5492-c43b-411a-8ab1-1ccfa82a19d4"
execution_mode = "passive"

[scanner.static]
enabled = true
paths = ["D:\\src\\app-repository"]
fail_on_quantum_vulnerable = true
severity_threshold = "medium"
```

#### gRPC Telemetry Payload (`CbomTelemetryPayload` Snippet)
```json
{
  "telemetry_id": "tel-990812-abc",
  "host_uuid": "e87f5492-c43b-411a-8ab1-1ccfa82a19d4",
  "scan_started_unix": 1780512800,
  "scan_finished_unix": 1780512805,
  "components": [
    {
      "bom_ref": "pkg:golang/github.com/my-org/my-app@1.0.0",
      "name": "my-app",
      "version": "1.0.0",
      "component_type": "application",
      "language": "Go",
      "algorithms": [
        {
          "name": "RSA",
          "family": "ASYMMETRIC",
          "role": "CRYPTO_ROLE_SIGNATURE",
          "status": "DEPRECATED",
          "key_bits": 1024,
          "source_file": "src/security/crypto.go",
          "source_line": 42,
          "confidence": 1.0,
          "quantum_vulnerable": true
        }
      ]
    }
  ]
}
```

---

### Case Study 2: Host Certificate Store Audit

#### Objective
Audit the local Windows system certificate store (My/Personal and Root/Trusted Root) to discover expired, weak (RSA < 2048 bits), or insecure (SHA-1 signature algorithm) certificates, and generate a compliance log for security auditors.

#### Execution Workflow
1. The `janus-agent` wakes up on a scheduled interval on a Windows server.
2. The agent executes PowerShell-native bindings and calls system crypto APIs to enumerate the local store.
3. Certs matching SHA-1 or short key structures are cataloged and dispatched to the controller.

#### Audit Commands
The agent executes the equivalent PowerShell query to inspect local certificate parameters:
```powershell
Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\LocalMachine\Root | 
    Where-Object { 
        $_.SignatureAlgorithm.FriendlyName -like "*sha1*" -or 
        ($_.PublicKey.Key.KeySize -lt 2048 -and $_.PublicKey.Oid.FriendlyName -eq "RSA") 
    } | 
    Select-Object Subject, SerialNumber, Thumbprint, NotAfter, SignatureAlgorithm
```

To cross-verify via native command line, the agent uses:
```cmd
certutil -store My
certutil -store Root
```

#### gRPC Telemetry Payload (`NetworkObservation` Snippet)
```json
{
  "endpoint": "db-server-01.internal",
  "protocol": "TCP",
  "tls_version": "TLS 1.2",
  "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "certificate_subject": "CN=db-server-legacy.internal",
  "certificate_issuer": "CN=Legacy CA Enterprise",
  "certificate_not_after_unix": 1780512999,
  "pqc_hybrid": false,
  "cleartext": false
}
```

---

### Case Study 3: Open Listening Sockets Discovery

#### Objective
Identify active listening TCP sockets on the host that are serving cleartext or unencrypted protocols (such as FTP on port 21, HTTP on port 80, or Telnet on port 23) and map these connections to the host inventory to ensure they are shut down or migrated to TLS.

#### Execution Workflow
1. The agent's socket scanner runs a system command and binds to network notification events.
2. Active TCP ports in the `LISTEN` state are gathered.
3. The process owning each socket is mapped, and unencrypted ports are flagged with `cleartext = true`.

#### Scanning Command
On Windows endpoints, the agent runs:
```powershell
Get-NetTCPConnection -State Listen | 
    Select-Object LocalAddress, LocalPort, OwningProcess | 
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            ProcessName  = $proc.ProcessName
            PID          = $_.OwningProcess
        }
    }
```

On Linux endpoints, the agent runs:
```bash
ss -tlnp
```

#### gRPC Telemetry Payload (`NetworkObservation` Snippet)
```json
{
  "endpoint": "0.0.0.0:80",
  "protocol": "HTTP",
  "tls_version": "None",
  "cipher_suite": "None",
  "certificate_subject": "",
  "certificate_issuer": "",
  "pqc_hybrid": false,
  "cleartext": true
}
```

---

## Medium Scenarios

### Case Study 4: Fleet TLS Protocol Policy Sweeping

#### Objective
Locate legacy TLS configurations (TLS 1.0 and TLS 1.1) across a large fleet of Windows Servers and update the registry configurations to enforce TLS 1.2 and TLS 1.3 as the exclusive operational protocol options.

#### Execution Workflow
1. The central CISO dashboard identifies a fleet of Windows Server 2022 targets that are allowing connections over TLS 1.0.
2. The administrator triggers a migration configuration profile targeting TLS protocols.
3. The agent receives a signed gRPC command, modifies the registry keys, and registers a system reboot/reload requirement.

#### PowerShell Registry Inspection & Sweep Commands
```powershell
# Check if TLS 1.0 server mode is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue

# Disable TLS 1.0 Server Configuration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -Force

# Enable TLS 1.3 Server Configuration (Exclusive Policy Setup)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "DisabledByDefault" -Value 0 -Force
```

#### gRPC Migration Command (`MigrationCommand` Snippet)
```json
{
  "command_id": "cmd-88921-schannel",
  "host_uuid": "f7a31bca-832f-488f-9a40-2cb039d91f28",
  "target_service": "Schannel",
  "migration_profile": "Enforce-Modern-TLS-Only",
  "target_kem": "X25519MLKEM768",
  "target_signature": "MLDSA65",
  "config_path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
  "validation_checklist": [
    "VerifyRegistryKeys",
    "SchannelRestartValidation"
  ],
  "rollback_window_seconds": 300,
  "dry_run": false
}
```

---

### Case Study 5: Shadow Crypto Loaded Process DLL Auditing

#### Objective
Audit running application processes to identify "Shadow Cryptography"—cases where developers bundle unapproved, outdated, or static cryptographic library DLLs (such as old `openssl.dll`, `libcrypto.dll`, or `bcrypt.dll` binaries) directly into their execution runtime path instead of using the OS security provider APIs.

#### Execution Workflow
1. The agent enumerates running system processes on Windows.
2. Using the `Toolhelp32` Windows API, the agent snapshot-inspects loaded modules for every active process ID.
3. If an unapproved library filename or hash is encountered, the agent reads its export table symbols to verify active cryptographic functions.

#### System Level API Code Concept (Rust Agent Module)
The Rust agent uses bindings equivalent to this win32 API snapshot loop:
```rust
unsafe {
    let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
    let mut module_entry = MODULEENTRY32 {
        dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };
    if Module32First(h_snapshot, &mut module_entry) != 0 {
        loop {
            let module_name = CStr::from_ptr(module_entry.szModule.as_ptr()).to_string_lossy();
            if module_name.to_lowercase().contains("openssl") || module_name.to_lowercase().contains("libcrypto") {
                // Register vulnerable library telemetry
                register_finding(process_id, &module_name, &module_entry.szExePath);
            }
            if Module32Next(h_snapshot, &mut module_entry) == 0 {
                break;
            }
        }
    }
    CloseHandle(h_snapshot);
}
```

#### gRPC Telemetry finding (`CbomComponent` Snippet)
```json
{
  "bom_ref": "process-pid-4912-module-openssl-dll",
  "name": "openssl.dll",
  "version": "1.1.0g",
  "component_type": "library",
  "file_path": "C:\\inetpub\\wwwroot\\bin\\openssl.dll",
  "algorithms": [
    {
      "name": "RSA",
      "family": "ASYMMETRIC",
      "role": "CRYPTO_ROLE_KEY_EXCHANGE",
      "implementation_library": "openssl.dll",
      "confidence": 0.95,
      "quantum_vulnerable": true
    }
  ],
  "reachable": true
}
```

---

### Case Study 6: Supply Chain Vulnerability Sync via OSV.dev

#### Objective
Verify software supply chain security by scanning software manifest files (such as Rust `Cargo.lock` or Node.js `package-lock.json`), generating CBOM package URLs (`purls`), and querying the OSV.dev database via the Go controller server to identify known CVEs affecting cryptographic libraries.

#### Execution Workflow
1. The agent crawls build directories and locates `package-lock.json`.
2. The dependency chain is converted to CycloneDX CBOM format and streamed via gRPC to the central server.
3. The server extract packages, queries OSV.dev, flags vulnerabilities, and schedules dashboard alerts.

#### Go Server OSV Query implementation
The Go server runs a query to `https://api.osv.dev/v1/query`:
```go
package osv

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type OSVQuery struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

func QueryOSV(packageName string, version string, ecosystem string) (*http.Response, error) {
	queryPayload := OSVQuery{Version: version}
	queryPayload.Package.Name = packageName
	queryPayload.Package.Ecosystem = ecosystem
	
	jsonBytes, _ := json.Marshal(queryPayload)
	return http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(jsonBytes))
}
```

#### gRPC Telemetry vulnerability (`CryptoFinding` Snippet)
```json
{
  "finding_id": "find-cve-2024-0723",
  "severity": "RISK_SEVERITY_HIGH",
  "title": "Vulnerability in node-forge Cryptographic library",
  "description": "node-forge version <1.3.1 contains a verification bypass vulnerability in RSA signature parsing.",
  "asset_ref": "pkg:npm/node-forge@1.2.0",
  "algorithm": "RSA",
  "policy_rule_id": "rule-no-cve-in-crypto",
  "migration_profile": "Upgrade-Forge-Library"
}
```

---

## Complex Scenarios

### Case Study 7: End-to-End Automated Nginx PQC Migration

#### Objective
Execute an end-to-end configuration and certificate transition on an active Nginx web server, migrating from legacy TLS 1.2 (using RSA-2048 keys) to post-quantum TLS 1.3 (utilizing ML-KEM hybrid key exchange groups).

```
[Go Controller] ------(Signed MigrationCommand)------> [Rust Agent]
      ^                                                     |
      |                                              1. Backup Nginx Conf
      |-- (gRPC MigrationStatusReport)               2. Call EST/ACME for ML-KEM Cert
                                                     3. Apply Unified Patch Diff
                                                     4. Run nginx -t
                                                     5. reload nginx
                                                     6. Execute TLS loopback test
                                                     7. Commit or Rollback Config
```

#### Execution Workflow
1. The server issues a signed `MigrationCommand` payload carrying a unified diff targeting `/etc/nginx/nginx.conf`.
2. The agent backs up the current configuration file.
3. The agent interacts with the Enterprise CA via EST/ACME protocol to request an ML-KEM/hybrid-X25519 TLS server certificate.
4. The agent writes the new certificate files to `/etc/ssl/certs/janus_pqc.crt` and updates `/etc/nginx/nginx.conf` via the patch diff.
5. The agent executes validation check: `nginx -t`. If validation fails, it immediately aborts and logs the failure.
6. The agent reloads Nginx: `systemctl reload nginx`.
7. The agent initiates a TLS connection loopback probe to verify that the server serves TLS 1.3 Kyber-hybrid handshakes.
8. If the connection fails or hangs, the agent restores the backed-up configuration and reloads Nginx to ensure zero-downtime operations.

#### Unified Patch Diff Snippet
```diff
--- /etc/nginx/nginx.conf
+++ /etc/nginx/nginx.conf
@@ -12,12 +12,12 @@
     server {
         listen 443 ssl;
         server_name secure.enterprise.com;
 
-        ssl_certificate /etc/ssl/certs/legacy_rsa.crt;
-        ssl_certificate_key /etc/ssl/private/legacy_rsa.key;
-        ssl_protocols TLSv1.2;
-        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
+        ssl_certificate /etc/ssl/certs/janus_pqc.crt;
+        ssl_certificate_key /etc/ssl/private/janus_pqc.key;
+        ssl_protocols TLSv1.3;
+        ssl_conf_commands Curves=X25519Kyber768Draft00:X25519;
+        ssl_prefer_server_ciphers on;
     }
 }
```

#### gRPC Command Payload
```json
{
  "command_id": "cmd-nginx-pqc-001",
  "host_uuid": "7b8e192f-3b8c-4731-92b0-ca72449a0a19",
  "target_service": "nginx",
  "migration_profile": "Ubuntu-Nginx-PQC-Target",
  "target_kem": "ML-KEM-768",
  "target_signature": "ML-DSA-65",
  "config_path": "/etc/nginx/nginx.conf",
  "validation_checklist": [
    "nginx -t",
    "curl -iv https://127.0.0.1 --curves X25519Kyber768Draft00"
  ],
  "rollback_window_seconds": 60,
  "patch_unified_diff": "--- /etc/nginx/nginx.conf\n+++ /etc/nginx/nginx.conf\n@@ -12,12 +12,12 @@\n     server {\n         listen 443 ssl;\n         server_name secure.enterprise.com;\n \n-        ssl_certificate /etc/ssl/certs/legacy_rsa.crt;\n-        ssl_certificate_key /etc/ssl/private/legacy_rsa.key;\n-        ssl_protocols TLSv1.2;\n-        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n+        ssl_certificate /etc/ssl/certs/janus_pqc.crt;\n+        ssl_certificate_key /etc/ssl/private/janus_pqc.key;\n+        ssl_protocols TLSv1.3;\n+        ssl_conf_commands Curves=X25519Kyber768Draft00:X25519;\n+        ssl_prefer_server_ciphers on;\n     }\n }",
  "signed_directive": "dGhpcy1pcy1hLXNpZ25lZC1obWFjLWRpcmVjdGl2ZS1mb3ItbmdpbngtY29uZmlndXJhdGlvbi1tdXRhdGlvbg==",
  "issued_at_unix": 1780513000,
  "dry_run": false
}
```

#### gRPC Status Response Sequence
The agent streams the progress state:
```json
{
  "command_id": "cmd-nginx-pqc-001",
  "host_uuid": "7b8e192f-3b8c-4731-92b0-ca72449a0a19",
  "state": "MIGRATION_STATE_APPLYING",
  "success": true,
  "output": "Applied unified diff patch to /etc/nginx/nginx.conf. Created configuration backup at /etc/nginx/nginx.conf.bak"
}
```
Followed by the validation check status:
```json
{
  "command_id": "cmd-nginx-pqc-001",
  "host_uuid": "7b8e192f-3b8c-4731-92b0-ca72449a0a19",
  "state": "MIGRATION_STATE_VALIDATING",
  "success": true,
  "output": "Nginx validation command 'nginx -t' returned status 0. Nginx service gracefully reloaded."
}
```
And the final verification outcome:
```json
{
  "command_id": "cmd-nginx-pqc-001",
  "host_uuid": "7b8e192f-3b8c-4731-92b0-ca72449a0a19",
  "state": "MIGRATION_STATE_SUCCEEDED",
  "success": true,
  "output": "Loopback connectivity probe successful. TLS 1.3 handshakes running hybrid group X25519Kyber768Draft00 verified.",
  "observed_tls": {
    "endpoint": "127.0.0.1:443",
    "protocol": "HTTPS",
    "tls_version": "TLS 1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "named_group": "X25519Kyber768Draft00",
    "pqc_hybrid": true,
    "cleartext": false
  }
}
```

---

### Case Study 8: Automatic Failover Rollback of Schannel Policy

#### Objective
Enforce advanced TLS 1.3 security parameters and post-quantum hybrid groups in the Windows Schannel registry framework, automatically rolling back to the original configuration backup if the post-upgrade environment verification test fails to protect fleet host access.

#### Execution Workflow
1. The agent exports a backup copy of the target registry path using PowerShell.
2. The agent executes a batch of registry modifications to adjust cipher suite priorities and add PQC-hybrid group configurations.
3. The agent initiates a system loopback check to verify the local Schannel pipeline can establish a secure test connection.
4. The test fails (e.g., due to an unsupported configuration on older Windows Server versions).
5. The agent executes a failover script, importing the registry backup, and notifying the central controller of the failure and rollback event.

#### PowerShell Migration & Rollback Script
```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$backupPath = "C:\Windows\Temp\schannel_backup.reg"

# 1. Generate Backup
reg export HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL $backupPath /y

# 2. Apply Custom Policy (Adding Kyber hybrid curve parameters)
try {
    # Attempting to set modern TLS curves (Simulated key entry)
    New-Item -Path "$regPath\KeyExchangeAlgorithms\Kyber768" -Force
    New-ItemProperty -Path "$regPath\KeyExchangeAlgorithms\Kyber768" -Name "Enabled" -Value 1 -PropertyType DWord -Force
    
    # Run loopback socket verification check
    $testSocket = New-Object System.Net.Sockets.TcpClient
    $connectTask = $testSocket.ConnectAsync("127.0.0.1", 443)
    Start-Sleep -Seconds 2
    
    if (-not $connectTask.IsCompleted) {
        throw "Connection timeout on Schannel port loopback check. Aborting."
    }
}
catch {
    # 3. Failover Triggered - Importing Registry Backup
    Write-Warning "Schannel validation test failed: $_. Reverting to backup."
    reg import $backupPath
    Remove-Item -Path $backupPath -Force
    exit 1
}
```

#### gRPC Telemetry Status (`MigrationStatusReport` Snippet)
```json
{
  "command_id": "cmd-schannel-rollback-002",
  "host_uuid": "7a8b19c2-55ef-4d33-91c2-db772a8c39b1",
  "state": "MIGRATION_STATE_ROLLING_BACK",
  "success": false,
  "error_vector": "Schannel connection loopback check timed out. Registry backup successfully restored.",
  "output": "System successfully restored to pre-migration parameters."
}
```

---

### Case Study 9: Deep RAM Scraping for Plaintext Key Exposure

#### Objective
Audit host memory to discover cases where Java processes running in production expose raw, plaintext private RSA/ECC keys in their Heap/RAM space instead of utilizing secure storage frameworks (such as the Windows Data Protection API - DPAPI or Hardware Security Modules).

#### Execution Workflow
1. The agent scans the process tree to find active JVM instances.
2. The agent requests memory read permissions and scans memory segments matching ASN.1 DER private key structures.
3. Upon identifying a key, it logs a critical security finding and dispatches it to the controller.
4. The administrator configures a remediation policy to secure the file parameter using local DPAPI encryption.

#### Scanning Script (PowerShell API Binding Hook)
```powershell
# Enumerate processes and inspect virtual memory for Java executables
$targetProcesses = Get-Process -Name "java" -ErrorAction SilentlyContinue
foreach ($proc in $targetProcesses) {
    # Call agent native routine to scrape process memory mapping for private key signatures
    & .\bin\janus-agent.exe --scrape-memory-pid $proc.Id
}
```

#### Secret Protection Script (PowerShell DPAPI Module)
To remediate raw storage issues, the agent encrypts target key passwords in local configuration files using DPAPI:
```powershell
# Import System Security assemblies
Add-Type -AssemblyName System.Security

# Original configuration parameter
$cleartextKey = "super-secret-ca-key-passphrase"
$plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($cleartextKey)

# Entropy key for localized isolation
$entropyBytes = [System.Security.Cryptography.RNGCryptoServiceProvider]::GenerateBytes(16)

# Encrypt data using LocalMachine boundary context
$encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($plaintextBytes, $entropyBytes, 'LocalMachine')

# Convert to Base64 for safe config file storage
$securePayloadBase64 = [Convert]::ToBase64String($encryptedBytes)
$entropyBase64 = [Convert]::ToBase64String($entropyBytes)
```

#### gRPC Telemetry finding (`CryptoFinding` Snippet)
```json
{
  "finding_id": "find-memory-leak-009",
  "severity": "RISK_SEVERITY_CRITICAL",
  "title": "Plaintext Private Key Discovered in Process Heap Memory",
  "description": "A raw PKCS#8 RSA Private Key pattern was detected in the heap memory of Java process PID 8892. Ephemeral memory shielding was applied.",
  "asset_ref": "host:f7a31bca-832f-488f-9a40-2cb039d91f28:pid-8892",
  "algorithm": "RSA",
  "policy_rule_id": "rule-no-plaintext-keys-in-memory",
  "evidence_ids": ["ev-mem-heap-009"]
}
```

---

### Case Study 10: Remote CA Root Certificate Rotation

#### Objective
Rotate an enterprise Root Certificate Authority (CA) certificate across a fleet of Windows workstations, replacing a legacy SHA-256/RSA root certificate with a post-quantum ML-DSA signed root CA certificate, ensuring automatic rollback if trust validation fails.

#### Execution Workflow
1. The agent receives a migration directive containing the Base64-encoded ML-DSA root certificate.
2. The agent exports a backup copy of the `LocalMachine\Root` store.
3. The agent imports the ML-DSA certificate into the trusted root authority store using elevated PowerShell bindings.
4. The agent tests system certificate validation pipelines.
5. If the new chain fails to validate, the agent deletes the certificate thumbprint to restore the system state.

#### PowerShell Import, Verification & Rollback Script
```powershell
$certBase64 = "MIIB6TCCAXCgAwIBAgIQYmFzZTY0LW1sZHNhLXJvb3QtY2VydGlmaWNhdGU..."
$certBytes = [System.Convert]::FromBase64String($certBase64)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certBytes)

# 1. Import Certificate to Root store
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

# 2. Execute Chain Verification Test
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority

$isValid = $chain.Build($cert)
if (-not $isValid) {
    # 3. Rollback Action: Remove imported certificate
    Write-Error "Certificate path validation failed. Executing atomic rollback."
    $store.Open("ReadWrite")
    $store.Remove($cert)
    $store.Close()
    exit 1
}

Write-Host "ML-DSA Root Certificate Authority successfully enrolled."
```

#### gRPC Telemetry Status (`MigrationStatusReport` Snippet)
```json
{
  "command_id": "cmd-rot-ca-100",
  "host_uuid": "f9a21bca-312c-4991-88b0-a292d919baef",
  "state": "MIGRATION_STATE_SUCCEEDED",
  "success": true,
  "output": "ML-DSA Root CA certificate imported successfully into LocalMachine\\Root. Validated thumbprint: 7bf8192a6c31bfd7890b23f81e72a44901bc3b81"
}
```

---

## Verifying Document Connections & Links

For design specifications, system APIs, database schemas, and Mermaid flowcharts, refer to [docs/design.md](design.md).
For installation playbooks, HA topologies, and environment configurations, refer to [docs/deployment.md](deployment.md).
For the general overview and quickstart instructions, refer to [README.md](../README.md).
To inspect the protobuf messaging interfaces, see [proto/janus.proto](../proto/janus.proto).
