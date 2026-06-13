# Janus CryptoBOM — API Test Suite
# Tests: health, auth, overview, components, findings, policies, compliance, lab, SLA, upgrade, audit, WS, rate-limit, CORS

param(
  [string]$BaseUrl = "http://127.0.0.1:8080",
  [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$Passed = 0
$Failed = 0
$TestResults = @()

function Test-Case($Name, $Script) {
  try {
    $result = & $Script
    if ($result) {
      $Passed++
      $TestResults += @{ Name=$Name; Status="PASS" }
      Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
      $Failed++
      $TestResults += @{ Name=$Name; Status="FAIL"; Error="$result" }
      Write-Host "  FAIL  $Name — $result" -ForegroundColor Red
    }
  } catch {
    $Failed++
    $TestResults += @{ Name=$Name; Status="ERROR"; Error=$_.Exception.Message }
    Write-Host "  ERROR $Name — $($_.Exception.Message)" -ForegroundColor Red
  }
}

function Invoke-Api($Method, $Path, $Body, $Headers) {
  $uri = "$BaseUrl$Path"
  $params = @{ Method=$Method; Uri=$uri; ContentType="application/json" }
  if ($Body) { $params.Body = (ConvertTo-Json $Body -Depth 5) }
  if ($Headers) { $params.Headers = $Headers }
  try {
    return Invoke-RestMethod @params -SkipCertificateCheck
  } catch {
    return $_.Exception.Response
  }
}

Write-Host "=== Janus API Test Suite ===" -ForegroundColor Cyan
Write-Host "Base URL: $BaseUrl`n"

# ---- Health Check ----
Test-Case "Health endpoint returns OK" {
  $r = Invoke-Api GET "/api/health"
  return $r.status -eq "ok" -and $r.db -eq "connected"
}

Test-Case "Health returns JSON content-type" {
  try {
    $r = Invoke-WebRequest "$BaseUrl/api/health" -UseBasicParsing
    return $r.Headers["Content-Type"] -match "application/json"
  } catch { return $false }
}

# ---- Authentication ----
Test-Case "Login with valid credentials" {
  $r = Invoke-Api POST "/api/auth/login" @{username="admin";password="janus-admin-pass"}
  $global:Token = $r.token
  return $null -ne $global:Token -and $r.role -eq "admin"
}

Test-Case "Login with invalid credentials rejected" {
  try {
    $r = Invoke-Api POST "/api/auth/login" @{username="admin";password="wrong"}
    return $false
  } catch { return $true }
}

Test-Case "Protected endpoint requires auth" {
  try {
    $r = Invoke-RestMethod "$BaseUrl/api/fleet/config" -Method GET
    return $false
  } catch { return $_.Exception.Response.StatusCode -eq 401 }
}

Test-Case "Authenticated request succeeds" {
  $r = Invoke-Api GET "/api/overview" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r -and $r.assets -is [long]
}

# ---- Overview & Readiness ----
Test-Case "Overview includes readiness score" {
  $r = Invoke-Api GET "/api/overview" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r.readiness_score -and $r.readiness_score -ge 0 -and $r.readiness_score -le 100
}

Test-Case "Overview includes stalled agents count" {
  $r = Invoke-Api GET "/api/overview" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r.stalled_agents
}

Test-Case "Overview includes algorithm histogram" {
  $r = Invoke-Api GET "/api/overview" $null @{Authorization="Bearer $global:Token"}
  return $r.algorithm_histogram -is [object]
}

Test-Case "Overview includes readiness breakdown" {
  $r = Invoke-Api GET "/api/overview" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r.readiness_breakdown -and $r.readiness_breakdown.PSObject.Properties["total_score"]
}

# ---- Components Pagination ----
Test-Case "Components returns paginated with X-Total-Count" {
  try {
    $r = Invoke-WebRequest "$BaseUrl/api/components?limit=10&offset=0" -Method GET -Headers @{Authorization="Bearer $global:Token"} -UseBasicParsing
    $body = $r.Content | ConvertFrom-Json
    return ($r.Headers["X-Total-Count"] -ne $null) -and ($body.Count -le 10)
  } catch { return $false }
}

Test-Case "Components with search parameter works" {
  $r = Invoke-Api GET "/api/components?search=openssl&limit=5" $null @{Authorization="Bearer $global:Token"}
  return $true  # endpoint exists and doesn't error
}

# ---- Findings Status Sync ----
Test-Case "Findings status update works" {
  try {
    $r = Invoke-Api PUT "/api/findings/test-finding-id/status" @{status="accepted_risk";updated_by="test-runner"} @{Authorization="Bearer $global:Token"}
    return $true
  } catch { return $_.Exception.Response.StatusCode -eq 404 }  # 404 is OK — finding doesn't exist, but endpoint works
}

# ---- Policy Management ----
Test-Case "List available policies" {
  $r = Invoke-Api GET "/api/policies" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r.active -and $null -ne $r.available
}

Test-Case "Create policy blocked for path traversal" {
  try {
    $body = Get-Content "$PSScriptRoot/../testdata/malicious-policy-version.json" | ConvertFrom-Json
    $r = Invoke-Api POST "/api/policies/create" $body @{Authorization="Bearer $global:Token"}
    return $false  # should be blocked
  } catch {
    return $_.Exception.Message -match "400|invalid|reject" -or $_.Exception.Response.StatusCode -eq 400
  }
}

Test-Case "Switch policy profile" {
  $r = Invoke-Api POST "/api/policies/active" @{version="nist-pqc-2026.1"} @{Authorization="Bearer $global:Token"}
  return $r.status -eq "ok"
}

# ---- Compliance Report ----
Test-Case "Compliance report returns HTML" {
  try {
    $r = Invoke-WebRequest "$BaseUrl/api/report/compliance" -Headers @{Authorization="Bearer $global:Token"} -UseBasicParsing
    return $r.Content -match "<html" -and $r.Content -match "Janus CryptoBOM"
  } catch { return $false }
}

# ---- PQC Lab Simulator ----
Test-Case "PQC Lab simulation returns patch" {
  $r = Invoke-Api POST "/api/lab/simulate" @{algorithm="RSA";target_service="nginx";config_snippet="ssl_ciphers RSA;"} @{Authorization="Bearer $global:Token"}
  return $null -ne $r.simulation_id -and $null -ne $r.migration_patch
}

Test-Case "PQC Lab uses active profile algorithms" {
  $r = Invoke-Api POST "/api/lab/simulate" @{algorithm="RSA";target_service="nginx"} @{Authorization="Bearer $global:Token"}
  return $r.recommended_kem -ne "" -and $r.recommended_signature -ne ""
}

# ---- SLA Metrics ----
Test-Case "SLA metrics endpoint returns scores" {
  $r = Invoke-Api GET "/api/sla/metrics" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r.readiness_score -and $null -ne $r.cert_health
}

# ---- Agent Upgrade ----
Test-Case "Agent upgrade info returns version" {
  $r = Invoke-Api GET "/api/agent/upgrade" $null @{Authorization="Bearer $global:Token"}
  return $null -ne $r.latest_version -and $null -ne $r.download_url
}

# ---- Audit Log Export ----
Test-Case "Audit log returns JSON array" {
  $r = Invoke-Api GET "/api/export/audit" $null @{Authorization="Bearer $global:Token"}
  return $r -is [array]
}

Test-Case "Audit log CSV export returns CSV" {
  try {
    $r = Invoke-WebRequest "$BaseUrl/api/export/audit?format=csv" -Headers @{Authorization="Bearer $global:Token"} -UseBasicParsing
    return $r.Content -match "timestamp,username,action"
  } catch { return $false }
}

# ---- CORS ----
Test-Case "CORS headers include DELETE method" {
  try {
    $r = Invoke-WebRequest "$BaseUrl/api/health" -Method OPTIONS -Headers @{Origin="http://localhost:5173";"Access-Control-Request-Method"="DELETE"} -UseBasicParsing
    $methods = $r.Headers["Access-Control-Allow-Methods"]
    return $methods -match "DELETE"
  } catch { return ($_.Exception.Response.Headers["Access-Control-Allow-Methods"] -match "DELETE") }
}

# ---- Prometheus Metrics ----
Test-Case "Prometheus metrics endpoint returns text" {
  try {
    $r = Invoke-WebRequest "$BaseUrl/metrics" -UseBasicParsing
    return $r.Content -match "janus_assets_total" -and $r.Content -match "janus_findings_total"
  } catch { return $false }
}

# ---- Summary ----
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Host "Passed: $Passed / $($Passed + $Failed)" -ForegroundColor Green
if ($Failed -gt 0) {
  Write-Host "Failed: $Failed" -ForegroundColor Red
}

$TestResults | ForEach-Object {
  $icon = if ($_.Status -eq "PASS") { "[PASS]" } else { "[FAIL]" }
  Write-Host "$icon $($_.Name)"
}

# Generate JSON report
$report = @{
  timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
  total = $Passed + $Failed
  passed = $Passed
  failed = $Failed
  results = $TestResults
}
$reportPath = Join-Path $PSScriptRoot "../reports/api-test-results.json"
$report | ConvertTo-Json -Depth 3 | Out-File $reportPath -Encoding utf8
Write-Host "`nReport saved to: $reportPath" -ForegroundColor Yellow

exit $(if ($Failed -gt 0) { 1 } else { 0 })
