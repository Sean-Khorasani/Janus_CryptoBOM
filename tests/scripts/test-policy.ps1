# Janus CryptoBOM — Policy Engine Test Suite
# Tests: NIST rules, CNSA rules, OSV severity, context-aware adjustment

param([switch]$Verbose)

$ErrorActionPreference = "Continue"
$Passed = 0
$Failed = 0

Write-Host "=== Janus Policy Engine Test Suite ===" -ForegroundColor Cyan

# Run Go policy engine tests
$goPath = "D:\src\Janus_CryptoBOM\.tools\go\bin"
if (Test-Path "$goPath\go.exe") {
  $env:PATH = "$goPath;$env:PATH"
}

Push-Location "D:\src\Janus_CryptoBOM\server"

Write-Host "`n[1/4] Running Go policy engine unit tests..."
$goTest = go test ./internal/policy/... -v -run Test 2>&1
$goExit = $LASTEXITCODE
Write-Host $goTest
if ($goExit -eq 0) {
  $Passed++
  Write-Host "  PASS  Go policy tests" -ForegroundColor Green
} else {
  $Failed++
  Write-Host "  FAIL  Go policy tests" -ForegroundColor Red
}

Write-Host "`n[2/4] Verifying NIST PQC 2026.1 profile..."
$nistProfile = Get-Content "D:\src\Janus_CryptoBOM\policies\nist-pqc-2026.yaml" | Out-String
if ($nistProfile -match "minimum_rsa_key_bits: 3072" -and
    $nistProfile -match "require_tls_13: true" -and
    $nistProfile -match "preferred_kem: X25519MLKEM768" -and
    $nistProfile -match "preferred_signature: ML-DSA-65") {
  $Passed++
  Write-Host "  PASS  NIST profile validation" -ForegroundColor Green
} else {
  $Failed++
  Write-Host "  FAIL  NIST profile validation" -ForegroundColor Red
}

Write-Host "`n[3/4] Verifying CNSA 2.0 profile..."
$cnsaProfile = Get-Content "D:\src\Janus_CryptoBOM\policies\cnsa-2.0.yaml" | Out-String
if ($cnsaProfile -match "minimum_rsa_key_bits: 3072" -and
    $cnsaProfile -match "preferred_kem: ML-KEM-1024" -and
    $cnsaProfile -match "preferred_signature: ML-DSA-87") {
  $Passed++
  Write-Host "  PASS  CNSA 2.0 profile validation" -ForegroundColor Green
} else {
  $Failed++
  Write-Host "  FAIL  CNSA 2.0 profile validation" -ForegroundColor Red
}

Write-Host "`n[4/4] Verifying OSV severity parsing implementation..."
$osvFile = "D:\src\Janus_CryptoBOM\server\internal\policy\osv.go"
$osvContent = Get-Content $osvFile -Raw
if ($osvContent -match "cvssScoreToJanus" -and
    $osvContent -match "ParseFloat" -and
    $osvContent -match "strconv") {
  $Passed++
  Write-Host "  PASS  OSV severity parsing validated" -ForegroundColor Green
} else {
  $Failed++
  Write-Host "  FAIL  OSV severity parsing implementation missing" -ForegroundColor Red
  Write-Host "  Expected: cvssScoreToJanus function with strconv.ParseFloat"
}

# Verify CNSA assessment rules exist
Write-Host "`n[Bonus] Verifying CNSA 2.0 assessment rules in engine..."
$engineFile = "D:\src\Janus_CryptoBOM\server\internal\policy\engine.go"
$engineContent = Get-Content $engineFile -Raw
if ($engineContent -match "assessCNSA" -and
    $engineContent -match "JANUS-CNSA-001" -and
    $engineContent -match "JANUS-CNSA-002" -and
    $engineContent -match "JANUS-CNSA-003") {
  $Passed++
  Write-Host "  PASS  CNSA assessment rules present" -ForegroundColor Green
} else {
  $Failed++
  Write-Host "  FAIL  CNSA assessment rules missing" -ForegroundColor Red
}

Pop-Location

# Summary
Write-Host "`n=== Policy Test Results ===" -ForegroundColor Cyan
Write-Host "Passed: $Passed / $($Passed + $Failed)" -ForegroundColor Green
if ($Failed -gt 0) { Write-Host "Failed: $Failed" -ForegroundColor Red }

exit $(if ($Failed -gt 0) { 1 } else { 0 })
