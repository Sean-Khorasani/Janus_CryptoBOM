# Janus CryptoBOM — Master Test Runner
# Executes all test suites and generates consolidated report

param(
  [string]$BaseUrl = "http://127.0.0.1:8080",
  [switch]$SkipServerTests,
  [switch]$SkipPolicyTests,
  [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReportDir = Join-Path $ScriptDir "reports"
$StartTime = Get-Date
$TotalPassed = 0
$TotalFailed = 0

# Create report directory
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

Write-Host @"

========================================
 Janus CryptoBOM — Master Test Runner
========================================
 Start: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
 Report Dir: $ReportDir
"@ -ForegroundColor Cyan

# ---- 1. Go Unit Tests ----
Write-Host "`n[SUITE 1/4] Go Unit Tests" -ForegroundColor Yellow
$env:PATH = "D:\src\Janus_CryptoBOM\.tools\go\bin;$env:PATH"
Push-Location "D:\src\Janus_CryptoBOM\server"
$goTest = go test ./... 2>&1
$goExit = $LASTEXITCODE
Pop-Location

Write-Host $goTest
if ($goExit -eq 0) {
  $TotalPassed++
  Write-Host "  PASS  Go unit tests" -ForegroundColor Green
} else {
  $TotalFailed++
  Write-Host "  FAIL  Go unit tests" -ForegroundColor Red
}

# ---- 2. Policy Engine Tests ----
if (!$SkipPolicyTests) {
  Write-Host "`n[SUITE 2/4] Policy Engine Tests" -ForegroundColor Yellow
  $policyScript = Join-Path $ScriptDir "scripts\test-policy.ps1"
  if (Test-Path $policyScript) {
    $policyResult = & $policyScript
    if ($LASTEXITCODE -eq 0) { $TotalPassed++ } else { $TotalFailed++ }
  } else {
    Write-Host "  SKIP  Policy test script not found" -ForegroundColor Gray
  }
}

# ---- 3. API Integration Tests (requires running server) ----
if (!$SkipServerTests) {
  Write-Host "`n[SUITE 3/4] API Integration Tests" -ForegroundColor Yellow

  # Check if server is running
  try {
    $health = Invoke-RestMethod "$BaseUrl/api/health" -Method GET -TimeoutSec 3
    Write-Host "  Server is running: $($health.status)" -ForegroundColor Green

    $apiScript = Join-Path $ScriptDir "scripts\test-api.ps1"
    if (Test-Path $apiScript) {
      & $apiScript -BaseUrl $BaseUrl
      if ($LASTEXITCODE -eq 0) { $TotalPassed++ } else { $TotalFailed++ }
    }
  } catch {
    Write-Host "  SKIP  Server not running at $BaseUrl — start janus-server first" -ForegroundColor Gray
  }
}

# ---- 4. Build Verification ----
Write-Host "`n[SUITE 4/4] Build Verification" -ForegroundColor Yellow
Push-Location "D:\src\Janus_CryptoBOM\server"
$buildResult = go build ./cmd/janus-server 2>&1
$buildExit = $LASTEXITCODE
Pop-Location

if ($buildExit -eq 0) {
  $TotalPassed++
  Write-Host "  PASS  Go server builds cleanly" -ForegroundColor Green
} else {
  $TotalFailed++
  Write-Host "  FAIL  Go server build" -ForegroundColor Red
  Write-Host $buildResult
}

# Check Rust agent (cargo check — may not be available)
if (Get-Command cargo -ErrorAction SilentlyContinue) {
  Push-Location "D:\src\Janus_CryptoBOM\agent"
  $rustCheck = cargo check 2>&1
  $rustExit = $LASTEXITCODE
  Pop-Location
  if ($rustExit -eq 0) {
    $TotalPassed++
    Write-Host "  PASS  Rust agent compiles cleanly" -ForegroundColor Green
  } else {
    $TotalFailed++
    Write-Host "  FAIL  Rust agent compile" -ForegroundColor Red
  }
} else {
  Write-Host "  SKIP  Rust toolchain not available" -ForegroundColor Gray
}

# ---- Consolidated Report ----
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

$report = @{
  timestamp = $EndTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
  duration_seconds = $Duration.TotalSeconds
  suites_run = $(if ($SkipServerTests) { 3 } else { 4 })
  total_tests = $TotalPassed + $TotalFailed
  passed = $TotalPassed
  failed = $TotalFailed
  pass_rate_pct = if (($TotalPassed + $TotalFailed) -gt 0) {
    [math]::Round(($TotalPassed / ($TotalPassed + $TotalFailed)) * 100, 1)
  } else { 0 }
}

$reportPath = Join-Path $ReportDir "consolidated-report.json"
$report | ConvertTo-Json | Out-File $reportPath -Encoding utf8

Write-Host @"

========================================
 Test Run Complete
========================================
 Duration: $($Duration.ToString('mm\:ss'))
 Passed:   $TotalPassed
 Failed:   $TotalFailed
 Rate:     $($report.pass_rate_pct)%
 Report:   $reportPath
"@ -ForegroundColor $(if ($TotalFailed -eq 0) { "Green" } else { "Red" })

exit $(if ($TotalFailed -gt 0) { 1 } else { 0 })
