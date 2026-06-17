# build-portable-server.ps1 — produce a portable "copy and run" Windows server+UI zip.
#
# Additive to win-build.ps1's staging; this bundle ships the env-driven run.ps1
# launcher + janus.env so deployment is "unzip, edit janus.env, run .\run.ps1".
# Requires the server + UI to be built first (bin\janus-server.exe and ui\dist) —
# e.g. via:  msbuild JanusCryptoBOM.msbuild.proj /t:Build
#
# Output: dist\portable\janus-server-ui-<version>-windows-x86_64.zip
# Mirrors packaging\windows\build-portable-agent.ps1 and the Linux build_server().
[CmdletBinding()]
param([string]$Root)

$ErrorActionPreference = "Stop"
# $PSScriptRoot (packaging\windows) is only reliable in the body, not in a param
# default — resolve the repo root (two levels up) here.
if (-not $Root) { $Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }

# Parse VERSION.env into a hashtable (same idiom as win-build.ps1).
$Release = @{}
Get-Content (Join-Path $Root "VERSION.env") | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $Release[$Matches[1]] = $Matches[2].Trim() }
}
$ArtifactVersion = "$($Release.JANUS_VERSION)-$($Release.JANUS_BUILD_DATE).$($Release.JANUS_BUILD_SEQUENCE)"

$exe = Join-Path $Root "bin\janus-server.exe"
if (-not (Test-Path $exe)) {
    throw "bin\janus-server.exe not found. Build first: msbuild JanusCryptoBOM.msbuild.proj /t:Build"
}
$uiDist = Join-Path $Root "ui\dist"
if (-not (Test-Path (Join-Path $uiDist "index.html"))) {
    throw "ui\dist not built. Build first: msbuild JanusCryptoBOM.msbuild.proj /t:Build"
}

$portable = Join-Path $Root "packaging\portable"
$outDir = Join-Path $Root "dist\portable"
$stageRoot = Join-Path $Root "dist\windows-portable-stage"
$name = "janus-server-ui-$ArtifactVersion-windows-x86_64"
$stage = Join-Path $stageRoot $name

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $stage "bin") | Out-Null
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Server binary, static UI (from ui\dist), and policy profiles.
Copy-Item -Force $exe (Join-Path $stage "bin\janus-server.exe")
Copy-Item -Recurse -Force $uiDist (Join-Path $stage "ui")
Copy-Item -Recurse -Force (Join-Path $Root "policies") (Join-Path $stage "policies")

# Portable launcher + ready-to-edit janus.env + docs + version contract.
Copy-Item -Force (Join-Path $portable "run-server.ps1") (Join-Path $stage "run.ps1")
Copy-Item -Force (Join-Path $portable "janus-server.env.example") (Join-Path $stage "janus.env")
Copy-Item -Force (Join-Path $portable "README-server-ui.md") (Join-Path $stage "README.md")
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

Write-Host "Portable Windows server+UI bundle written: $zipPath"
