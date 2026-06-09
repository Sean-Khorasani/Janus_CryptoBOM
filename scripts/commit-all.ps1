# Janus CryptoBOM — Per-File Commit Script
# Each changed file gets its own commit with a specific description.
# Usage:
#   .\scripts\commit-all.ps1 -DryRun     preview only (no git changes)
#   .\scripts\commit-all.ps1             execute all commits
param([switch]$DryRun)
$ErrorActionPreference = "Continue"
Push-Location (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

# ── Per-file commit definitions ──
# Each entry: File = path, Msg = 1-3 line commit description
# Order: docs first, then server, agent, ui, infra, test

$commits = @(

  # ── Documentation ──
  @{ File = "README.md"; Msg = "docs: updated README with full API reference, environment variables, and CNSA 2.0 coverage" },
  @{ File = "docs/competitive-analysis.md"; Msg = "docs: added competitive analysis comparing 10 enterprise PQC platforms with benchmark matrix" },
  @{ File = "docs/feature-inventory.md"; Msg = "docs: added feature inventory tracking 32 implemented features across 4 tiers" },
  @{ File = "docs/design.md"; Msg = "docs: rewritten design manual with all server packages, agent modules, versioned migrations, WebSocket hub, and HSM architecture" },
  @{ File = "docs/deployment.md"; Msg = "docs: rewritten deployment guide with Helm, Docker Compose, systemd/GPO, HSM setup, and observability config" },
  @{ File = "docs/case_studies.md"; Msg = "docs: rewritten case studies with 12 production playbooks covering new F1-F32 features" },

  # ── Server: config & main ──
  @{ File = "server/internal/config/config.go"; Msg = "server/config: required JANUS_COMMAND_SIGNING_KEY; added CORS origin, DB pool, log level, and stall threshold config" },
  @{ File = "server/cmd/janus-server/main.go"; Msg = "server/main: migrated to structured JSON logging via log/slog; wired WebSocket hub, HSM, and DB pool config" },

  # ── Server: store ──
  @{ File = "server/internal/store/store.go"; Msg = "server/store: implemented versioned schema migrations (v1-v9), connection pool config, and readiness score computation" },
  @{ File = "server/internal/store/ensure_schema.go"; Msg = "server/store: extracted EnsureSchema runner with transactional migration application" },

  # ── Server: gRPC & HTTP API ──
  @{ File = "server/internal/grpcserver/server.go"; Msg = "server/grpc: added webhook circuit breaker with retry/backoff; broadcasts telemetry and migration events to WebSocket hub" },
  @{ File = "server/internal/httpapi/server.go"; Msg = "server/api: added CORS restriction, components pagination, compliance report, PQC lab, SLA metrics, agent upgrade, and audit export endpoints; fixed path traversal in createPolicy" },
  @{ File = "server/internal/httpapi/features.go"; Msg = "server/api: added feature endpoint handlers (compliance report, PQC lab, SLA metrics, agent upgrade, audit export, rate limiter)" },

  # ── Server: policy ──
  @{ File = "server/internal/policy/engine.go"; Msg = "server/policy: added CNSA 2.0 assessment rules, configurable MinimumConfidence threshold, and profile-aware severity adjustment" },
  @{ File = "server/internal/policy/osv.go"; Msg = "server/policy: fixed OSV severity parsing to read actual CVSS scores via strconv.ParseFloat" },
  @{ File = "server/internal/policy/confidence.go"; Msg = "server/policy: added ConfidenceAnalyzer with per-rule breakdowns, false-positive tracking, and operator feedback" },

  # ── Server: orchestrator ──
  @{ File = "server/internal/orchestrator/orchestrator.go"; Msg = "server/orch: uses active policy profile values (PreferredKEM/PreferredSignature) for migration targets" },

  # ── Server: WebSocket ──
  @{ File = "server/internal/ws/"; Msg = "server/ws: added stdlib-only RFC 6455 WebSocket hub for real-time dashboard event broadcasting" },

  # ── Server: HSM ──
  @{ File = "server/internal/hsm/"; Msg = "server/hsm: added syscall-based PKCS#11 client, SoftHSM2 mock, key metadata, and HSM configuration with no external dependencies" },

  # ── Server: sandbox ──
  @{ File = "server/internal/sandbox/"; Msg = "server/sandbox: added PQC migration simulator with patch preview and validation checklist without execution" },

  # ── Agent: config & deps ──
  @{ File = "agent/Cargo.toml"; Msg = "agent: added reqwest dependency for future HTTP client migration" },
  @{ File = "agent/janus-agent.example.toml"; Msg = "agent: documented command_signing_key as required with generation instructions" },
  @{ File = "agent/src/config.rs"; Msg = "agent/config: added intercept_mode field; required command_signing_key (no insecure default)" },

  # ── Agent: main & comms ──
  @{ File = "agent/src/main.rs"; Msg = "agent/main: enhanced check subcommand with binary and dependency scanning; added watch::channel heartbeat shutdown for --once mode; removed duplicate policy assessment" },
  @{ File = "agent/src/comms.rs"; Msg = "agent/comms: added shutdown signal for graceful heartbeat termination; cleared diagnostics buffer after successful upload" },

  # ── Agent: storage ──
  @{ File = "agent/src/storage.rs"; Msg = "agent/storage: added scan_state table for content-hash diffing, periodic VACUUM (24h interval), and AES-CTR encryption for non-Windows platforms" },

  # ── Agent: discovery modules ──
  @{ File = "agent/src/discovery/mod.rs"; Msg = "agent/discovery: registered sidechannel module in scan pipeline; exported modules for enhanced check subcommand" },
  @{ File = "agent/src/discovery/binary.rs"; Msg = "agent/discovery/binary: fixed include_entry to use path-component equality matching instead of substring" },
  @{ File = "agent/src/discovery/dependency.rs"; Msg = "agent/discovery/dependency: added 8 FHE library entries; deduplicated openssl; fixed include_entry path-component matching" },
  @{ File = "agent/src/discovery/source.rs"; Msg = "agent/discovery/source: added 7 FHE regex patterns; fixed include_entry path-component and GLOBAL_EXCLUSIONS matching" },
  @{ File = "agent/src/discovery/runtime.rs"; Msg = "agent/discovery/runtime: implemented Linux memory scanning via /proc/PID/mem with PEM private key detection" },
  @{ File = "agent/src/discovery/plugin.rs"; Msg = "agent/discovery/plugin: added OS-enforced resource limits (cgroups v2 on Linux, Job objects on Windows)" },
  @{ File = "agent/src/discovery/sidechannel.rs"; Msg = "agent/discovery/sidechannel: added timing side-channel detection with 8 patterns across 4 severity levels" },

  # ── Agent: mutation & interceptor ──
  @{ File = "agent/src/mutation.rs"; Msg = "agent/mutation: replaced fragile reg query parsing with locale-independent regex pattern" },
  @{ File = "agent/src/interceptor.rs"; Msg = "agent/interceptor: added TLS cipher/group hook injection with active/passive intercept modes for runtime PQC upgrade" },

  # ── UI: core ──
  @{ File = "ui/src/index.css"; Msg = "ui/css: added comprehensive dark mode (CSS custom properties, glass-morphism, shimmer skeletons, gradient badges) and focus-visible accessibility styles" },
  @{ File = "ui/tailwind.config.ts"; Msg = "ui/tailwind: enabled darkMode selector and added semantic color tokens" },
  @{ File = "ui/src/App.tsx"; Msg = "ui/app: added locale switcher; synced finding statuses to backend API with optimistic update and failure revert" },
  @{ File = "ui/src/main.tsx"; Msg = "ui/main: wrapped app with I18nProvider for multi-language support" },

  # ── UI: hooks ──
  @{ File = "ui/src/hooks/useApi.ts"; Msg = "ui/hooks: added updateFindingStatus API call; exposed fetchFleetConfig, fetchAuditLogs, and agent diagnostics" },
  @{ File = "ui/src/hooks/useTranslation.ts"; Msg = "ui/hooks: added useTranslation hook with locale detection and persistence" },

  # ── UI: components ──
  @{ File = "ui/src/components/Header.tsx"; Msg = "ui/header: added dark mode, accessibility attributes (aria-label, role), and login modal focus trap" },
  @{ File = "ui/src/components/OverviewView.tsx"; Msg = "ui/overview: added stalled agent metric card and dark mode styling throughout" },
  @{ File = "ui/src/components/FindingsGrid.tsx"; Msg = "ui/findings: added dark mode, keyboard navigation, ARIA attributes, and backend status sync" },
  @{ File = "ui/src/components/CbomViewer.tsx"; Msg = "ui/cbom: added dark mode styling and accessibility attributes" },
  @{ File = "ui/src/components/ComplianceMatrix.tsx"; Msg = "ui/compliance: added dark mode, aria-sort on columns, and keyboard-accessible rows" },
  @{ File = "ui/src/components/CryptoGraph.tsx"; Msg = "ui/graph: added dark mode-aware SVG rendering and accessibility labels" },
  @{ File = "ui/src/components/MigrationConsole.tsx"; Msg = "ui/migration: added dark mode, ARIA expand/collapse, keyboard navigation, and focus trap" },
  @{ File = "ui/src/components/PolicyStudio.tsx"; Msg = "ui/policy: added dark mode styling and accessible form controls" },
  @{ File = "ui/src/components/FleetManagement.tsx"; Msg = "ui/fleet: added Advanced Settings panel, stall detection, FocusTrap, and dark mode throughout" },

  # ── UI: a11y & i18n ──
  @{ File = "ui/src/a11y/"; Msg = "ui/a11y: added FocusTrap, SkipLink, A11yAnnouncer, and useKeyboardNav for WCAG 2.1 AA compliance" },
  @{ File = "ui/src/i18n/"; Msg = "ui/i18n: added 4 locales (en/fa/zh/es) with 42 translation keys, I18nProvider, and locale switcher" },

  # ── Infrastructure ──
  @{ File = "deploy/"; Msg = "infra: added 13-file Helm chart (Deployment, DaemonSet, ConfigMap, Service, Ingress, PostgreSQL, Secrets)" },
  @{ File = ".github/"; Msg = "ci: added GitHub Actions workflow with SARIF upload, CBOM generation, and compliance gate" },
  @{ File = "scripts/janus-ci.sh"; Msg = "ci: added generic CI runner script with configurable fail levels" },
  @{ File = "infra/docker-compose.yml"; Msg = "infra: added new environment variables (GRPC_ADDR, HTTP_ADDR, COMMAND_SIGNING_KEY, LOG_LEVEL, DB pool, stall threshold)" },
  @{ File = "policies/nist-pqc-2026.yaml"; Msg = "policies: added minimum_confidence field to NIST PQC 2026.1 profile" },
  @{ File = "policies/cnsa-2.0.yaml"; Msg = "policies: added minimum_confidence field to CNSA 2.0 profile" },
  @{ File = "policies/custom.yaml"; Msg = "policies: added minimum_confidence field to custom enterprise profile" },
  @{ File = "config/"; Msg = "config: added externalized LLM prompt templates (classify-intent, remediate-patch, offline-fallback)" },
  @{ File = ".gitignore"; Msg = "chore: added HSM/bin/, HSM/tokens/, HSM/tools/, Test/reports/, Temp/, *.patch to gitignore" },

  # ── HSM setup ──
  @{ File = "HSM/README.md"; Msg = "hsm: added SoftHSM2 setup documentation and PKCS#11 integration guide" },
  @{ File = "HSM/setup-softHSM2.ps1"; Msg = "hsm: added automated SoftHSM2 setup script (vcpkg/Chocolatey/GitHub/source)" },
  @{ File = "HSM/softhsm2.conf"; Msg = "hsm: added SoftHSM2 configuration template with token directory" },
  @{ File = "HSM/test-pkcs11.ps1"; Msg = "hsm: added direct PKCS#11 library validation test script" },
  @{ File = "HSM/mock-pkcs11/"; Msg = "hsm: added Go-based mock PKCS#11 DLL source for development testing" },

  # ── Test suite ──
  @{ File = "Test/run-all-tests.ps1"; Msg = "test: added master test runner with consolidated JSON report generation" },
  @{ File = "Test/test-plan.md"; Msg = "test: added comprehensive test plan covering API, policy, migration, integration, and UI" },
  @{ File = "Test/scripts/test-f1-sandbox.ps1"; Msg = "test: added F1 PQC migration sandbox simulator validation tests" },
  @{ File = "Test/scripts/test-f5-interceptor.ps1"; Msg = "test: added F5 runtime TLS interception hook validation tests" },
  @{ File = "Test/scripts/test-f7-confidence.ps1"; Msg = "test: added F7 statistical confidence analysis endpoint tests" },
  @{ File = "Test/scripts/test-f8-helm.ps1"; Msg = "test: added F8 Helm chart structure validation tests" },
  @{ File = "Test/scripts/test-f11-advisory.ps1"; Msg = "test: added F11 OSV advisory integration parsing tests" },
  @{ File = "Test/scripts/test-f13-hsm.ps1"; Msg = "test: added F13 HSM PKCS#11 DLL and package validation tests" },
  @{ File = "Test/scripts/test-f16-sidechannel.ps1"; Msg = "test: added F16 side-channel detection pattern tests" },
  @{ File = "Test/scripts/test-f23-fhe.ps1"; Msg = "test: added F23 FHE library detection coverage tests" },
  @{ File = "Test/scripts/test-f28-confidence-threshold.ps1"; Msg = "test: added F28 profile minimum confidence threshold tests" },
  @{ File = "Test/scripts/test-f30-darkmode.ps1"; Msg = "test: added F30 dark mode CSS and component coverage tests" },
  @{ File = "Test/scripts/test-f31-i18n.ps1"; Msg = "test: added F31 i18n locale completeness and integration tests" },
  @{ File = "Test/scripts/test-f32-a11y.ps1"; Msg = "test: added F32 WCAG 2.1 AA accessibility compliance tests" },
  @{ File = "Test/scripts/test-api.ps1"; Msg = "test: added 22 API integration tests (health, auth, CRUD, CORS, metrics)" },
  @{ File = "Test/scripts/test-policy.ps1"; Msg = "test: added 5 policy engine validation tests" },
  @{ File = "Test/scripts/test-hsm.ps1"; Msg = "test: added HSM API integration tests" },
  @{ File = "Test/testdata/sample-rsa-code.rs"; Msg = "test: added Rust sample with RSA, SHA-1, and AES-128 for scanner validation" },
  @{ File = "Test/testdata/sample-ecdsa.py"; Msg = "test: added Python sample with ECDSA, MD5, and verify/negotiate intent detection" },
  @{ File = "Test/testdata/sample-go-crypto.go"; Msg = "test: added Go sample with crypto/tls, x/crypto, md5, and sha1 usage" },
  @{ File = "Test/testdata/sample-nginx.conf"; Msg = "test: added Nginx config sample with TLS 1.2 and classical ciphers" },
  @{ File = "Test/testdata/sample-package.json"; Msg = "test: added npm package.json with crypto dependencies for dependency scanner" },
  @{ File = "Test/testdata/malicious-policy-version.json"; Msg = "test: added path traversal attack vector for createPolicy security testing" }
)

# ── Get git status for classification ──
$gitStatus = git status --short 2>&1
$trackedFiles = @{}
foreach ($line in $gitStatus) {
  if ($line -match '^\?\? (.+)$') {
    $trackedFiles[$Matches[1]] = 'NEW'
  } elseif ($line -match '^[ MARC][ MARC] (.+)$') {
    # M = modified, A = added, R = renamed, C = copied
    $trackedFiles[$Matches[1]] = 'MODIFIED'
  }
}

# ── Build the list of files to commit ──
$toCommit = @()
foreach ($entry in $commits) {
  $pattern = $entry.File
  $matched = @()
  foreach ($key in $trackedFiles.Keys) {
    if ($pattern.EndsWith('/')) {
      if ($key.StartsWith($pattern)) { $matched += $key }
    } else {
      if ($key -eq $pattern) { $matched += $key }
    }
  }
  if ($matched.Count -eq 0) {
    # File not in git changes — check if it's a directory that resolved to files
    # Try matching against tracked keys that START with the pattern
    foreach ($key in $trackedFiles.Keys) {
      if ($key.StartsWith($pattern)) { $matched += $key }
    }
  }
  foreach ($f in $matched) {
    $toCommit += @{ File = $f; Status = $trackedFiles[$f]; Msg = $entry.Msg }
  }
}

# ── showed plan ──
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Janus CryptoBOM — Per-File Commit Plan" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Mode: $(if ($DryRun) { 'DRY RUN — reviewing only, no changes' } else { 'LIVE — committing now' })" -ForegroundColor $(if ($DryRun) { 'Yellow' } else { 'Red' })
Write-Host "Total commits: $($toCommit.Count)"
Write-Host ""

$num = 0
foreach ($entry in $toCommit) {
  $num++
  $icon = if ($entry.Status -eq 'NEW') { '+' } else { '~' }
  $color = if ($entry.Status -eq 'NEW') { 'Green' } else { 'Yellow' }

  Write-Host "── [$num/$($toCommit.Count)] $icon $($entry.File)" -ForegroundColor $color
  foreach ($line in ($entry.Msg -split "`n")) {
    Write-Host "      $line" -ForegroundColor Gray
  }

  if (-not $DryRun) {
    git add $entry.File 2>&1 | Out-Null
    $tmpFile = [System.IO.Path]::GetTempFileName()
    $entry.Msg | Out-File -FilePath $tmpFile -Encoding utf8 -NoNewline
    $result = git commit -F $tmpFile 2>&1
    Remove-Item $tmpFile -Force
    if ($LASTEXITCODE -eq 0) {
      Write-Host "      COMMITTED" -ForegroundColor Green
    } else {
      Write-Host "      SKIPPED ($result)" -ForegroundColor Yellow
    }
  }
  Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
if ($DryRun) {
  Write-Host " DRY RUN complete. Review the plan above." -ForegroundColor Yellow
  Write-Host " Run without -DryRun to execute all commits." -ForegroundColor Yellow
} else {
  Write-Host " All commits executed." -ForegroundColor Green
}
Write-Host "========================================" -ForegroundColor Cyan

Pop-Location
