# Janus Server portable launcher (Windows).
# Usage: edit janus.env, then  .\run.ps1   (extra args pass through to the server)
#
# NOTE: this starts the API/gRPC server only. The dashboard UI in .\ui is a set
# of static files; the server does NOT serve them. Host .\ui with any static
# file server that has SPA history-fallback (see the hint printed on startup).
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $ServerArgs)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

# 1. Load janus.env (KEY="value" lines; '#' comments and blanks ignored).
$envFile = if ($env:JANUS_ENV_FILE) { $env:JANUS_ENV_FILE } else { "janus.env" }
$settings = @{}
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $k, $v = $line.Split("=", 2)
            $v = $v.Trim().Trim('"').Trim("'")
            $settings[$k.Trim()] = $v
            Set-Item -Path "Env:$($k.Trim())" -Value $v
        }
    }
}

# 2. Require a signing key (matches run-server.sh and the server's own startup check).
$signingKey     = if ($settings.ContainsKey("JANUS_COMMAND_SIGNING_KEY")) { $settings["JANUS_COMMAND_SIGNING_KEY"] } else { "" }
$signingKeyFile = if ($settings.ContainsKey("JANUS_COMMAND_SIGNING_KEY_FILE")) { $settings["JANUS_COMMAND_SIGNING_KEY_FILE"] } else { "" }
if (-not $signingKey -and -not $signingKeyFile) {
    throw "JANUS_COMMAND_SIGNING_KEY is not set in $envFile. Generate one with: openssl rand -hex 32"
}

# 3. Defaults for listen addresses (mirrors run-server.sh).
if (-not $env:JANUS_HTTP_ADDR) { $env:JANUS_HTTP_ADDR = "127.0.0.1:8080" }
$grpcAddr = if ($env:JANUS_GRPC_ADDR) { $env:JANUS_GRPC_ADDR } else { "127.0.0.1:9443" }

# 4. Print the UI-serving hint (the server serves API/gRPC only; ui\ is static).
Write-Host "Janus API/gRPC starting (HTTP: $($env:JANUS_HTTP_ADDR), gRPC: $grpcAddr)."
Write-Host "The dashboard UI is static files in .\ui - the server does not serve them."
Write-Host "Serve them with any SPA-capable static server, for example:"
Write-Host "    npx --yes serve -s ui -l 5173"
Write-Host "Then set JANUS_CORS_ORIGIN in $envFile to that origin and restart."

# 5. Launch.
$exe = Join-Path $here "bin\janus-server.exe"
if (-not (Test-Path $exe)) { throw "Server executable not found: $exe" }
& $exe @ServerArgs
exit $LASTEXITCODE
