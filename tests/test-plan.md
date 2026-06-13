# Janus CryptoBOM — Comprehensive Test Plan

> Version: 1.0 | June 2026 | Test directory: `.\tests\`

---

## Test Categories

### 1. Server API Tests (`tests/scripts/test-api.ps1`)
- Health check endpoint
- Authentication flow (login, JWT validation, expiry)
- Overview endpoint (assets, findings, readiness score, stalled agents)
- Components pagination
- Findings CRUD + status sync
- Policy CRUD + activation
- Compliance report generation
- PQC lab simulation
- SLA metrics
- Agent upgrade info
- Audit log export
- WebSocket connectivity
- Rate limiting
- CORS headers

### 2. Agent Scanner Tests (`tests/scripts/test-agent.ps1`)
- check subcommand exit codes
- Source code crypto detection
- Binary PE/ELF/Mach-O symbol detection
- Dependency manifest parsing
- Exclusion path matching
- Memory scanning
- Network TLS probing
- Windows registry inspection
- Plugin execution with resource limits

### 3. Policy Engine Tests (`tests/scripts/test-policy.ps1`)
- NIST PQC 2026.1 assessment rules
- CNSA 2.0 additional rules
- OSV severity parsing
- Context-aware severity adjustment
- Custom policy profile activation

### 4. Migration Engine Tests (`tests/scripts/test-migration.ps1`)
- HMAC command signing/verification
- Dry-run execution
- Config patching
- Validation steps
- Rollback on failure
- Post-migration TLS verification

### 5. Integration Tests (`tests/scripts/test-integration.ps1`)
- Agent → Server registration
- Telemetry streaming
- Migration command round-trip
- Webhook dispatch with retry
- WebSocket event delivery
- Structured logging output

### 6. UI Tests (`tests/scripts/test-ui.ps1`)
- Dark mode toggle persistence
- Finding status sync to backend
- Tab navigation rendering
- Advanced Settings save/load
- Stalled agent badge display
- Components pagination controls
- Policy studio create/activate

---

## Test Data (`tests/testdata/`)

| File | Purpose |
|------|---------|
| `sample-rsa-code.rs` | Rust source with RSA, SHA-1, AES-128 usage |
| `sample-ecdsa.py` | Python with ECDSA + MD5 |
| `sample-go-crypto.go` | Go with crypto/tls + x/crypto |
| `sample-pom.xml` | Maven with Bouncy Castle dependency |
| `sample-package.json` | npm with crypto-js + jsonwebtoken |
| `sample-nginx.conf` | Nginx config with TLS 1.2 ciphers |
| `malicious-policy-version.json` | Path traversal attempt for createPolicy |
| `sample-binary.exe` | Compiled PE binary with OpenSSL imports |
| `sample-pem-key.txt` | PEM private key for memory scan test |
| `sample-cert-chain.pem` | X.509 certificate chain for network scan |
