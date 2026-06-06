param(
  [switch]$SkipToolInstall,
  [switch]$SkipServer,
  [switch]$SkipAgent,
  [switch]$SkipUi
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
  npm install
  npm run build
  Pop-Location
}

if (!$SkipServer) {
  Ensure-Dir (Join-Path $Root "bin")
  Push-Location (Join-Path $Root "server")
  go mod tidy
  go test ./...
  go build -o (Join-Path $Root "bin\janus-server.exe") ./cmd/janus-server
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

Write-Host "Janus Windows build complete."
