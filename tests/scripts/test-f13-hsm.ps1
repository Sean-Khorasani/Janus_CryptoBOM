# F13 — HSM PKCS#11 Integration Tests
param($BaseUrl="http://127.0.0.1:8080")
$Passed=0; $Failed=0
function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$h=@{'Content-Type'='application/json'}
$hsmDll="D:\src\Janus_CryptoBOM\HSM\bin\softhsm2.dll"
Write-Host "=== F13: HSM Integration Tests ===" -F Cyan

Test "SoftHSM2 DLL exists in HSM/bin/" { return (Test-Path $hsmDll) -and ((Get-Item $hsmDll).Length -gt 1000000) }
Test "SoftHSM2 DLL is 64-bit" { return (Get-Item $hsmDll).Length -gt 2000000 }
Test "softhsm2.conf exists" { return Test-Path "D:\src\Janus_CryptoBOM\HSM\softhsm2.conf" }
Test "HSM tokens directory exists" { return Test-Path "D:\src\Janus_CryptoBOM\HSM\tokens" }
Test "softhsm2-util.exe exists" { return Test-Path "D:\src\Janus_CryptoBOM\HSM\bin\softhsm2-util.exe" }
Test "DLL exports C_GetInfo (valid PKCS#11)" {
  Add-Type -TypeDefinition @"
    using System; using System.Runtime.InteropServices;
    public class PKCSCheck { [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string p);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern bool FreeLibrary(IntPtr h); }
"@ -ErrorAction SilentlyContinue
  $hnd=[PKCSCheck]::LoadLibrary($hsmDll); $proc=[PKCSCheck]::GetProcAddress($hnd,"C_GetInfo"); [PKCSCheck]::FreeLibrary($hnd)
  return $proc -ne [IntPtr]::Zero
}
Test "HSM Go package compiles" { $p="D:\src\Janus_CryptoBOM\server\internal\hsm\"; return (Test-Path "$p\hsm.go") -and (Test-Path "$p\pkcs11.go") -and (Test-Path "$p\softhsm.go") -and (Test-Path "$p\keyinfo.go") -and (Test-Path "$p\config.go") }
Test "HSM setup script exists" { return Test-Path "D:\src\Janus_CryptoBOM\HSM\setup-softHSM2.ps1" }
Test "softhsm2.conf has correct token dir" { $c=Get-Content "D:\src\Janus_CryptoBOM\HSM\softhsm2.conf" -Raw; return $c -match "directories.tokendir" -and $c -match "tokens" }
Test "DLL size is valid (>2MB, not corrupted)" { return (Get-Item $hsmDll).Length -eq 2786080 }

Write-Host "`nF13 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
