param(
  [switch]$SkipToolInstall,
  [switch]$SkipServer,
  [switch]$SkipAgent,
  [switch]$SkipUi,
  [switch]$Package
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Tools = Join-Path $Root ".tools"
$GoRoot = Join-Path $Tools "go"
$RustupHome = Join-Path $Tools "rustup"
$CargoHome = Join-Path $Tools "cargo"
$env:RUSTUP_HOME = $RustupHome
$env:CARGO_HOME = $CargoHome
$env:PATH = "$GoRoot\bin;$CargoHome\bin;$env:PATH"

$Release = @{}
Get-Content (Join-Path $Root "VERSION.env") | ForEach-Object {
  if ($_ -match '^([A-Z0-9_]+)=(.+)$') { $Release[$Matches[1]] = $Matches[2] }
}
$FullVersion = "$($Release.JANUS_VERSION)+$($Release.JANUS_BUILD_DATE).$($Release.JANUS_BUILD_SEQUENCE)"
$ArtifactVersion = "$($Release.JANUS_VERSION)-$($Release.JANUS_BUILD_DATE).$($Release.JANUS_BUILD_SEQUENCE)"
$env:JANUS_BUILD_DATE = $Release.JANUS_BUILD_DATE
$env:JANUS_BUILD_SEQUENCE = $Release.JANUS_BUILD_SEQUENCE
$env:JANUS_AGENT_PROTOCOL_VERSION = $Release.JANUS_AGENT_PROTOCOL_VERSION
$env:JANUS_AGENT_MIN_SERVER_VERSION = $Release.JANUS_AGENT_MIN_SERVER_VERSION

function Ensure-Dir($Path) {
  New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Install-Go {
  if (Get-Command go -ErrorAction SilentlyContinue) { return }
  Ensure-Dir $Tools
  $zip = Join-Path $Tools "go-windows-amd64.zip"
  $url = "https://go.dev/dl/go1.23.5.windows-amd64.zip"
  if (!(Test-Path $zip)) {
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
  }
  if (Test-Path $GoRoot) {
    Remove-Item -Recurse -Force $GoRoot
  }
  Expand-Archive -Force -Path $zip -DestinationPath $Tools
}

function Install-Rust {
  if (Get-Command cargo -ErrorAction SilentlyContinue) { return }
  Ensure-Dir $Tools
  Ensure-Dir $RustupHome
  Ensure-Dir $CargoHome
  $rustup = Join-Path $Tools "rustup-init.exe"
  if (!(Test-Path $rustup)) {
    Invoke-WebRequest -UseBasicParsing -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustup
  }
  & $rustup -y --no-modify-path --profile minimal --default-toolchain stable --default-host x86_64-pc-windows-msvc
}

if (!$SkipToolInstall) {
  Install-Go
  Install-Rust
}

if (!$SkipUi) {
  Push-Location (Join-Path $Root "ui")
  $env:VITE_JANUS_VERSION = $FullVersion
  $env:VITE_JANUS_REQUIRED_API_VERSION = $Release.JANUS_UI_REQUIRED_API_VERSION
  npm install
  npm run build
  Pop-Location
}

if (!$SkipServer) {
  Ensure-Dir (Join-Path $Root "bin")
  Push-Location (Join-Path $Root "server")
  go mod tidy
  go test ./...
  $ldflags = "-X github.com/janus-cbom/janus/server/internal/version.Version=$($Release.JANUS_VERSION) -X github.com/janus-cbom/janus/server/internal/version.BuildDate=$($Release.JANUS_BUILD_DATE) -X github.com/janus-cbom/janus/server/internal/version.BuildSequence=$($Release.JANUS_BUILD_SEQUENCE) -X github.com/janus-cbom/janus/server/internal/version.APIVersion=$($Release.JANUS_API_VERSION) -X github.com/janus-cbom/janus/server/internal/version.AgentProtocolVersion=$($Release.JANUS_AGENT_PROTOCOL_VERSION)"
  go build -ldflags $ldflags -o (Join-Path $Root "bin\janus-server.exe") ./cmd/janus-server
  Pop-Location
}

if (!$SkipAgent) {
  Push-Location (Join-Path $Root "agent")
  cargo test
  cargo build --release
  Ensure-Dir (Join-Path $Root "bin")
  Copy-Item -Force (Join-Path $Root "agent\target\release\janus-agent.exe") (Join-Path $Root "bin\janus-agent.exe")
  Copy-Item -Force (Join-Path $Root "agent\target\release\janus_interceptor.dll") (Join-Path $Root "bin\janus_interceptor.dll")
  Copy-Item -Force (Join-Path $Root "agent\target\release\janus-agent.exe") (Join-Path $Root "bin\janus-cli.exe")
  Pop-Location
}

if ($Package) {
  $Dist = Join-Path $Root "dist\packages"
  $Stage = Join-Path $Root "dist\windows-stage"
  Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
  Ensure-Dir $Dist
  Remove-Item -Force (Join-Path $Dist "SHA256SUMS.windows") -ErrorAction SilentlyContinue

  $ServerStage = Join-Path $Stage "janus-server-ui-$ArtifactVersion-windows-x86_64"
  Ensure-Dir (Join-Path $ServerStage "bin")
  Copy-Item (Join-Path $Root "bin\janus-server.exe") (Join-Path $ServerStage "bin")
  Copy-Item -Recurse (Join-Path $Root "ui\dist") (Join-Path $ServerStage "ui")
  Copy-Item -Recurse (Join-Path $Root "policies") (Join-Path $ServerStage "policies")
  Copy-Item (Join-Path $Root "VERSION.env") $ServerStage
  Copy-Item (Join-Path $Root "packaging\release\README-server-ui.md") (Join-Path $ServerStage "README.md")

  $AgentStage = Join-Path $Stage "janus-agent-$ArtifactVersion-windows-x86_64"
  Ensure-Dir (Join-Path $AgentStage "bin")
  Copy-Item (Join-Path $Root "bin\janus-agent.exe") (Join-Path $AgentStage "bin")
  Copy-Item (Join-Path $Root "bin\janus_interceptor.dll") (Join-Path $AgentStage "bin")
  Copy-Item (Join-Path $Root "agent\janus-agent.example.toml") (Join-Path $AgentStage "janus-agent.toml")
  Copy-Item (Join-Path $Root "VERSION.env") $AgentStage
  Copy-Item (Join-Path $Root "packaging\release\README-agent.md") (Join-Path $AgentStage "README.md")
  Copy-Item (Join-Path $Root "scripts\install-agent-windows-service.ps1") $AgentStage
  Copy-Item (Join-Path $Root "scripts\uninstall-agent-windows-service.ps1") $AgentStage

  foreach ($Bundle in @($ServerStage, $AgentStage)) {
    $Zip = Join-Path $Dist "$([IO.Path]::GetFileName($Bundle)).zip"
    Remove-Item -Force $Zip -ErrorAction SilentlyContinue
    Compress-Archive -Path $Bundle -DestinationPath $Zip
    Get-FileHash -Algorithm SHA256 $Zip | ForEach-Object { "$($_.Hash.ToLower())  $([IO.Path]::GetFileName($Zip))" } | Add-Content (Join-Path $Dist "SHA256SUMS.windows")
  }
}

Write-Host "Janus Windows build complete."
