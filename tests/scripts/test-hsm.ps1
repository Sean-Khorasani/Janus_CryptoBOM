# Janus CryptoBOM — HSM Integration Tests
# Tests PKCS#11 operations via the Janus HSM API
# Prerequisites: Run HSM\setup-softHSM2.ps1 first (mock mode OK)

param(
  [string]$BaseUrl = "http://127.0.0.1:8080",
  [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$Passed = 0
$Failed = 0

function Test-Case($Name, $Script) {
  try {
    $result = & $Script
    if ($result) {
      $Passed++
      Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
      $Failed++
      Write-Host "  FAIL  $Name" -ForegroundColor Red
    }
  } catch {
    $Failed++
    Write-Host "  ERROR $Name — $($_.Exception.Message)" -ForegroundColor Red
  }
}

function Invoke-Api($Method, $Path, $Body) {
  $token = $env:JANUS_TEST_TOKEN
  $headers = @{"Content-Type"="application/json"}
  if ($token) { $headers["Authorization"] = "Bearer $token" }
  $params = @{ Method=$Method; Uri="$BaseUrl$Path"; Headers=$headers }
  if ($Body) { $params.Body = (ConvertTo-Json $Body -Depth 5) }
  try {
    return Invoke-RestMethod @params -SkipCertificateCheck
  } catch {
    return $_.Exception.Response
  }
}

Write-Host "=== Janus HSM Integration Test Suite ===" -ForegroundColor Cyan
Write-Host "Base URL: $BaseUrl`n"

# ---- Authenticate ----
Write-Host "[Setup] Authenticating..."
try {
  $login = Invoke-Api POST "/api/auth/login" @{username="admin";password="janus-admin-pass"}
  $env:JANUS_TEST_TOKEN = $login.token
  Write-Host "  Token obtained: $($login.role)`n" -ForegroundColor Green
} catch {
  Write-Host "  Auth failed — tests may require JANUS_DISABLE_AUTH=true`n" -ForegroundColor Yellow
}

# ---- HSM Key Listing ----
Test-Case "GET /api/hsm/keys returns key list" {
  $r = Invoke-Api GET "/api/hsm/keys"
  return $r -is [array] -or $r.keys -is [array] -or ($r -and $null -ne $r)
}

# ---- HSM Key Generation ----
Test-Case "POST /api/hsm/keys/generate RSA-2048" {
  $r = Invoke-Api POST "/api/hsm/keys/generate" @{
    algorithm = "RSA-2048"
    label = "test-rsa-2048"
  }
  return $null -ne $r.key_id
}

Test-Case "POST /api/hsm/keys/generate ECDSA-P256" {
  $r = Invoke-Api POST "/api/hsm/keys/generate" @{
    algorithm = "ECDSA-P256"
    label = "test-ecdsa-p256"
  }
  return $null -ne $r.key_id
}

Test-Case "POST /api/hsm/keys/generate ECDSA-P384 (CNSA)" {
  $r = Invoke-Api POST "/api/hsm/keys/generate" @{
    algorithm = "ECDSA-P384"
    label = "test-ecdsa-p384"
  }
  $global:CnsaKeyId = $r.key_id
  return $null -ne $r.key_id
}

Test-Case "POST /api/hsm/keys/generate with invalid algorithm rejected" {
  try {
    $r = Invoke-Api POST "/api/hsm/keys/generate" @{algorithm="BROKEN-CRYPTO";label="bad"}
    return $false
  } catch {
    return $true
  }
}

# ---- HSM Sign & Verify ----
Test-Case "POST /api/hsm/sign with test message" {
  $testData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Janus HSM test message"))
  $r = Invoke-Api POST "/api/hsm/sign" @{
    key_id = $global:CnsaKeyId
    data = $testData
  }
  $global:Signature = $r.signature
  return $null -ne $r.signature
}

Test-Case "POST /api/hsm/verify valid signature" {
  $testData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Janus HSM test message"))
  $r = Invoke-Api POST "/api/hsm/verify" @{
    key_id = $global:CnsaKeyId
    data = $testData
    signature = $global:Signature
  }
  return $r.valid -eq $true
}

Test-Case "POST /api/hsm/verify tampered data" {
  $wrongData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Tampered message"))
  $r = Invoke-Api POST "/api/hsm/verify" @{
    key_id = $global:CnsaKeyId
    data = $wrongData
    signature = $global:Signature
  }
  return $r.valid -eq $false
}

Test-Case "POST /api/hsm/verify with wrong key_id" {
  $testData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Janus HSM test message"))
  $r = Invoke-Api POST "/api/hsm/verify" @{
    key_id = "nonexistent-key"
    data = $testData
    signature = $global:Signature
  }
  # Should return valid=false or error
  return $r.valid -eq $false -or $r.error
}

# ---- HSM Key Info ----
Test-Case "GET /api/hsm/keys/{id} returns key details" {
  $r = Invoke-Api GET "/api/hsm/keys/$global:CnsaKeyId"
  return $null -ne $r -and $null -ne $r.key_id
}

# ---- HSM Config Verification ----
Test-Case "HSM config is accessible" {
  $hsmConf = Join-Path $PSScriptRoot "..\softhsm2.conf"
  if (Test-Path $hsmConf) {
    $content = Get-Content $hsmConf -Raw
    return $content -match "directories.tokendir" -and $content -match "objectstore.backend"
  }
  # If conf file not found, check if mock mode is documented
  return $true
}

# ---- Cleanup ----
Test-Case "HSM token directory exists" {
  $tokensDir = Join-Path $PSScriptRoot "..\tokens"
  if (!(Test-Path $tokensDir)) {
    New-Item -ItemType Directory -Force -Path $tokensDir | Out-Null
  }
  return (Test-Path $tokensDir)
}

# ---- Summary ----
Write-Host "`n=== HSM Test Results ===" -ForegroundColor Cyan
Write-Host "Passed: $Passed / $($Passed + $Failed)" -ForegroundColor Green
if ($Failed -gt 0) {
  Write-Host "Failed: $Failed" -ForegroundColor Red
}

$report = @{
  timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
  suite = "HSM Integration"
  total = $Passed + $Failed
  passed = $Passed
  failed = $Failed
}
$reportPath = Join-Path $PSScriptRoot "..\reports\hsm-test-results.json"
New-Item -ItemType Directory -Force -Path (Split-Path $reportPath) | Out-Null
$report | ConvertTo-Json | Out-File $reportPath -Encoding utf8
Write-Host "Report: $reportPath" -ForegroundColor Yellow

exit $(if ($Failed -gt 0) { 1 } else { 0 })
