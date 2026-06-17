# build-portable-agent.ps1 — produce a portable "copy and run" Windows agent zip.
#
# Additive to build-windows.ps1's staging; this bundle ships the env-driven
# run.ps1 launcher + janus.env + janus-agent.toml.template so deployment is
# "unzip, edit janus.env, run .\run.ps1". Requires the agent to be built first
# (bin\janus-agent.exe) — e.g. via:  msbuild JanusCryptoBOM.msbuild.proj /t:Build
#
# Output: dist\portable\janus-agent-<version>-windows-x86_64.zip
[CmdletBinding()]
param([string]$Root)

$ErrorActionPreference = "Stop"
# $PSScriptRoot (packaging\windows) is only reliable in the body, not in a param
# default — resolve the repo root (two levels up) here.
if (-not $Root) { $Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }

# Parse VERSION.env into a hashtable (same idiom as build-windows.ps1).
$Release = @{}
Get-Content (Join-Path $Root "VERSION.env") | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $Release[$Matches[1]] = $Matches[2].Trim() }
}
$ArtifactVersion = "$($Release.JANUS_VERSION)-$($Release.JANUS_BUILD_DATE).$($Release.JANUS_BUILD_SEQUENCE)"

$exe = Join-Path $Root "bin\janus-agent.exe"
if (-not (Test-Path $exe)) {
    throw "bin\janus-agent.exe not found. Build first: msbuild JanusCryptoBOM.msbuild.proj /t:Build"
}

$portable = Join-Path $Root "packaging\portable"
$outDir = Join-Path $Root "dist\portable"
$stageRoot = Join-Path $Root "dist\windows-portable-stage"
$name = "janus-agent-$ArtifactVersion-windows-x86_64"
$stage = Join-Path $stageRoot $name

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $stage "bin") | Out-Null
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Binary (+ interceptor DLL if present).
Copy-Item -Force $exe (Join-Path $stage "bin\janus-agent.exe")
$dll = Join-Path $Root "bin\janus_interceptor.dll"
if (Test-Path $dll) { Copy-Item -Force $dll (Join-Path $stage "bin\janus_interceptor.dll") }

# Portable launcher + config template + ready-to-edit janus.env + docs.
Copy-Item -Force (Join-Path $portable "run-agent.ps1") (Join-Path $stage "run.ps1")
Copy-Item -Force (Join-Path $portable "janus-agent.toml.template") (Join-Path $stage "janus-agent.toml.template")
Copy-Item -Force (Join-Path $portable "janus-agent.windows.env.example") (Join-Path $stage "janus.env")
Copy-Item -Force (Join-Path $portable "README-agent.md") (Join-Path $stage "README.md")
Copy-Item -Force (Join-Path $Root "VERSION.env") (Join-Path $stage "VERSION.env")

# Zip it (top-level dir included, matching the Linux bundles).
$zipPath = Join-Path $outDir "$name.zip"
Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
Compress-Archive -Path $stage -DestinationPath $zipPath -CompressionLevel Optimal

# Checksum (SHA256SUMS, appended-and-deduped over the output dir).
$sums = Join-Path $outDir "SHA256SUMS"
$lines = @()
if (Test-Path $sums) {
    $lines = Get-Content $sums | Where-Object { $_ -notmatch "  $name\.zip$" }
}
$hash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
$lines += "$hash  $name.zip"
$lines | Sort-Object | Set-Content -Path $sums -Encoding ASCII

Write-Host "Portable Windows agent bundle written: $zipPath"
