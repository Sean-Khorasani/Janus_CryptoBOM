param(
  [switch]$SkipBuild,
  [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Bin = Join-Path $Root "bin"
$ServerExe = Join-Path $Bin "janus-server.exe"
$AgentExe = Join-Path $Bin "janus-agent.exe"
$ReportOut = Join-Path $Root "janus-controller-report.html"

if (!$SkipBuild) {
  & (Join-Path $Root "build-windows.ps1")
}

if (!(Test-Path $ServerExe)) { throw "Server executable not found: $ServerExe" }
if (!(Test-Path $AgentExe)) { throw "Agent executable not found: $AgentExe" }

if (Get-Command docker -ErrorAction SilentlyContinue) {
  docker compose -f (Join-Path $Root "infra\docker-compose.yml") up -d postgres
} else {
  Write-Warning "Docker not found. Ensure PostgreSQL is running at postgres://janus:janus@localhost:5432/janus?sslmode=disable"
}

$env:JANUS_DATABASE_URL = "postgres://janus:janus@localhost:5432/janus?sslmode=disable"
$env:JANUS_GRPC_ADDR = "127.0.0.1:9443"
$env:JANUS_HTTP_ADDR = "127.0.0.1:8080"
$env:JANUS_COMMAND_SIGNING_KEY = "local-development-command-signing-key"

$server = Start-Process -FilePath $ServerExe -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 4

try {
  & $AgentExe --config (Join-Path $Root "agent\janus-agent.example.toml") --once
  Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/api/report.html -OutFile $ReportOut
  Write-Host "Controller report written to $ReportOut"
} finally {
  if (!$KeepRunning -and $server -and !$server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
}

