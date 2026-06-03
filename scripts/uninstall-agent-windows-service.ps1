param(
  [string]$ServiceName = "JanusCryptoBOMAgent"
)

$ErrorActionPreference = "Stop"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (!$existing) {
  Write-Host "Service $ServiceName is not installed."
  return
}

if ($existing.Status -ne "Stopped") {
  Stop-Service -Name $ServiceName -Force
}

sc.exe delete $ServiceName | Out-Null
Write-Host "Service $ServiceName removed."

