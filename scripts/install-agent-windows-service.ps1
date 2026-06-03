param(
  [string]$AgentExe = "D:\src\janus-cbom\bin\janus-agent.exe",
  [string]$ConfigPath = "D:\src\janus-cbom\agent\janus-agent.example.toml",
  [string]$ServiceName = "JanusCryptoBOMAgent",
  [string]$DisplayName = "Janus CryptoBOM Agent",
  [switch]$Start
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $AgentExe)) {
  throw "Agent executable not found: $AgentExe"
}
if (!(Test-Path $ConfigPath)) {
  throw "Agent config not found: $ConfigPath"
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  if ($existing.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force
  }
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 2
}

$binPath = "`"$AgentExe`" --config `"$ConfigPath`""
sc.exe create $ServiceName binPath= $binPath start= delayed-auto DisplayName= "`"$DisplayName`"" | Out-Null
sc.exe description $ServiceName "Janus CryptoBOM endpoint agent for Windows cryptographic posture and PQC migration telemetry." | Out-Null

if ($Start) {
  Start-Service -Name $ServiceName
}

Get-Service -Name $ServiceName

