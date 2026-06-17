# Janus Agent portable launcher (Windows).
# Usage: edit janus.env, then  .\run.ps1   (extra args pass through to the agent,
# e.g.  .\run.ps1 --once)
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $AgentArgs)

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

# 2. Defaults for anything not set.
function Get-Setting($name, $default) {
    if ($settings.ContainsKey($name) -and $settings[$name]) { return $settings[$name] }
    return $default
}
$controller   = Get-Setting "JANUS_CONTROLLER_ENDPOINT"      "http://127.0.0.1:9443"
$httpEndpoint = Get-Setting "JANUS_HTTP_CONTROLLER_ENDPOINT" "http://127.0.0.1:8080"
$signingKey   = Get-Setting "JANUS_COMMAND_SIGNING_KEY"      ""
$scanRoots    = Get-Setting "JANUS_SCAN_ROOTS"               '["C:\\Program Files", "C:\\inetpub"]'
$stateDir     = Get-Setting "JANUS_STATE_DIR"                "state"

$config   = if ($env:JANUS_CONFIG) { $env:JANUS_CONFIG } else { "janus-agent.toml" }
$template = "janus-agent.toml.template"

# 3. Render the config on first run (generate-if-absent).
if (-not (Test-Path $config)) {
    if (-not $signingKey) {
        throw "JANUS_COMMAND_SIGNING_KEY is empty in $envFile. Generate one with: openssl rand -hex 32"
    }
    if (-not (Test-Path $template)) {
        throw "$template missing; cannot render $config."
    }
    (Get-Content $template -Raw).
        Replace('${JANUS_CONTROLLER_ENDPOINT}', $controller).
        Replace('${JANUS_HTTP_CONTROLLER_ENDPOINT}', $httpEndpoint).
        Replace('${JANUS_COMMAND_SIGNING_KEY}', $signingKey).
        Replace('${JANUS_SCAN_ROOTS}', $scanRoots).
        Replace('${JANUS_STATE_DIR}', $stateDir) |
        Set-Content -Path $config -Encoding UTF8
    Write-Host "Rendered $config from $template. Edit it directly to change settings; delete it to re-render from $envFile."
}

# 4. Ensure the state directory exists, then launch.
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$exe = Join-Path $here "bin\janus-agent.exe"
if (-not (Test-Path $exe)) { throw "Agent executable not found: $exe" }
Write-Host "Starting janus-agent (config: $config, state: $stateDir)..."
& $exe --config $config @AgentArgs
exit $LASTEXITCODE
