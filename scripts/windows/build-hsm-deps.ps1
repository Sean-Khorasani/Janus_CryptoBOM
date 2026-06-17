<#
.SYNOPSIS
  Build OpenSSL 3.5 + a PQC-enabled SoftHSM2 (ML-DSA) on Windows and initialize a test
  token, so Janus can exercise the HSM/PKCS#11 path with real ML-DSA keys.

.DESCRIPTION
  Run this from a "x64 Native Tools Command Prompt for VS 2022" (so cl/nmake/cmake are on
  PATH), then: powershell -ExecutionPolicy Bypass -File scripts\windows\build-hsm-deps.ps1

  SoftHSM2's ML-DSA support requires OpenSSL 3.5+, which Windows package managers don't
  ship yet, so this builds OpenSSL 3.5.1 from the source already in HSM\tools\build, then
  builds the vendored HSM\tools\SoftHSMv2-source against it with -DENABLE_MLDSA=ON.

  Prerequisites (besides the VS 2022 toolchain): Perl (Strawberry Perl) on PATH for the
  OpenSSL build, and CMake (bundled with VS 2022's "C++ CMake tools" component).

  Output (printed at the end): the JANUS_HSM_* environment to run the server in pkcs11 mode.
#>
param(
  [string]$OpensslPrefix = "$PSScriptRoot\..\..\HSM\tools\build\openssl-win-prefix",
  [string]$SoftHsmPrefix = "$PSScriptRoot\..\..\HSM\tools\build\softhsm-win-prefix",
  [string]$TokenLabel    = "JanusTestToken",
  [string]$Pin           = "1234",
  [string]$SoPin         = "5678"
)
$ErrorActionPreference = "Stop"
$Root   = (Resolve-Path "$PSScriptRoot\..\..").Path
$Build  = Join-Path $Root "HSM\tools\build"
$OpensslPrefix = [IO.Path]::GetFullPath($OpensslPrefix)
$SoftHsmPrefix = [IO.Path]::GetFullPath($SoftHsmPrefix)

function Need($cmd, $hint) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "'$cmd' not found on PATH. $hint"
  }
}
Need cl    "Run from a 'x64 Native Tools Command Prompt for VS 2022'."
Need nmake "Run from a 'x64 Native Tools Command Prompt for VS 2022'."
Need cmake "Install the 'C++ CMake tools for Windows' VS component, or cmake.org."
Need perl  "Install Strawberry Perl (https://strawberryperl.com) and re-open the prompt."

# ---- 1. OpenSSL 3.5.1 (VC-WIN64A) ------------------------------------------------------
if (Test-Path (Join-Path $OpensslPrefix "bin\openssl.exe")) {
  Write-Host "OpenSSL already built at $OpensslPrefix - skipping."
} else {
  $srcTar = Join-Path $Build "openssl.tar.gz"
  if (-not (Test-Path $srcTar)) {
    Write-Host "Downloading OpenSSL 3.5.1 source..."
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/openssl/openssl/releases/download/openssl-3.5.1/openssl-3.5.1.tar.gz" -OutFile $srcTar
  }
  $osslSrc = Join-Path $Build "openssl-win-src"
  if (Test-Path $osslSrc) { Remove-Item -Recurse -Force $osslSrc }
  New-Item -ItemType Directory -Force -Path $osslSrc | Out-Null
  tar -xf $srcTar -C $osslSrc --strip-components=1   # bsdtar ships with Windows 10+
  Push-Location $osslSrc
  Write-Host "Configuring + building OpenSSL (this takes a few minutes)..."
  perl Configure VC-WIN64A no-asm no-tests no-docs --prefix="$OpensslPrefix" --openssldir="$OpensslPrefix\ssl"
  if ($LASTEXITCODE -ne 0) { throw "OpenSSL Configure failed" }
  nmake; if ($LASTEXITCODE -ne 0) { throw "OpenSSL nmake failed" }
  nmake install_sw install_ssldirs; if ($LASTEXITCODE -ne 0) { throw "OpenSSL install failed" }
  Pop-Location
}
& (Join-Path $OpensslPrefix "bin\openssl.exe") list -signature-algorithms | Select-String -SimpleMatch "ML-DSA" |
  ForEach-Object { Write-Host "OpenSSL ML-DSA: $_" }

# ---- 2. SoftHSM2 with ML-DSA, against that OpenSSL -------------------------------------
$shsmSrc   = Join-Path $Root "HSM\tools\SoftHSMv2-source"
$shsmBuild = Join-Path $Build "softhsm-win-build"
if (Test-Path $shsmBuild) { Remove-Item -Recurse -Force $shsmBuild }
Write-Host "Configuring + building SoftHSM2 (ML-DSA enabled)..."
cmake -S "$shsmSrc" -B "$shsmBuild" -A x64 `
  -DENABLE_64bit=ON -DENABLE_MLDSA=ON -DENABLE_GOST=OFF -DENABLE_P11_KIT=OFF `
  -DENABLE_STATIC=OFF -DBUILD_TESTS=OFF -DDISABLE_NON_PAGED_MEMORY=ON `
  -DWITH_CRYPTO_BACKEND=openssl "-DOPENSSL_ROOT_DIR=$OpensslPrefix" `
  "-DCMAKE_INSTALL_PREFIX=$SoftHsmPrefix"
if ($LASTEXITCODE -ne 0) { throw "SoftHSM cmake configure failed" }
cmake --build "$shsmBuild" --config Release; if ($LASTEXITCODE -ne 0) { throw "SoftHSM build failed" }
cmake --install "$shsmBuild" --config Release; if ($LASTEXITCODE -ne 0) { throw "SoftHSM install failed" }

# Locate the produced module + util (Windows layout varies by config).
$module = Get-ChildItem -Recurse -Path $SoftHsmPrefix -Filter "softhsm2.dll" | Select-Object -First 1
$util   = Get-ChildItem -Recurse -Path $SoftHsmPrefix -Filter "softhsm2-util.exe" | Select-Object -First 1
if (-not $module -or -not $util) { throw "build succeeded but softhsm2.dll / softhsm2-util.exe not found under $SoftHsmPrefix" }

# OpenSSL 3.5 DLLs must be loadable by the module at runtime.
Copy-Item -Force (Join-Path $OpensslPrefix "bin\*.dll") $module.DirectoryName -ErrorAction SilentlyContinue

# ---- 3. Initialize a test token --------------------------------------------------------
$tokenDir = Join-Path $Root "HSM\win-tokens"
New-Item -ItemType Directory -Force -Path $tokenDir | Out-Null
$conf = Join-Path $Root "HSM\softhsm2.win.conf"
"directories.tokendir = $tokenDir`nobjectstore.backend = file`nlog.level = INFO`nslots.removable = false" |
  Set-Content -Encoding ascii $conf
$env:SOFTHSM2_CONF = $conf
$env:PATH = "$($OpensslPrefix)\bin;$env:PATH"
& $util.FullName --init-token --free --label $TokenLabel --pin $Pin --so-pin $SoPin

# ---- 4. Tell the operator how to run Janus --------------------------------------------
Write-Host ""
Write-Host "=== SoftHSM2 (ML-DSA) ready. Set these to run the server in pkcs11 mode: ===" -ForegroundColor Green
Write-Host "set SOFTHSM2_CONF=$conf"
Write-Host "set JANUS_HSM_MODE=pkcs11"
Write-Host "set JANUS_HSM_MODULE_PATH=$($module.FullName)"
Write-Host "set JANUS_HSM_TOKEN_LABEL=$TokenLabel"
Write-Host "set JANUS_HSM_PIN=$Pin"
Write-Host ""
Write-Host "Generate the ML-DSA command-signing key + see its fingerprint:"
Write-Host "  bin\janus-server.exe hsm keygen --module `"$($module.FullName)`" --slot-index 0 --pin $Pin --label janus-command-mldsa"
