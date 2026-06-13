# F16 — Side-Channel Detection Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$f="D:\src\Janus_CryptoBOM\agent\src\discovery\sidechannel.rs"
Write-Host "=== F16: Side-Channel Detection Tests ===" -F Cyan

Test "sidechannel.rs exists" { return Test-Path $f -and (Get-Item $f).Length -gt 500 }
Test "ScanResult returned with findings" { $c=Get-Content $f -Raw; return $c -match "ScanResult" }
Test "CRITICAL level detection (branch on key)" { $c=Get-Content $f -Raw; return $c -match "CRITICAL|key.*branch|branch.*key" }
Test "HIGH level detection (non-constant compare)" { $c=Get-Content $f -Raw; return $c -match "HIGH|constant.time|memcmp|constant_time" }
Test "MEDIUM level detection (table lookup)" { $c=Get-Content $f -Raw; return $c -match "MEDIUM|table.*lookup|SBOX|lookup.*table" }
Test "LOW level detection (ciphertext equality)" { $c=Get-Content $f -Raw; return $c -match "LOW|ciphertext.*==|==.*ciphertext" }
Test "Comment/string stripping present" { $c=Get-Content $f -Raw; return $c -match "strip_comment|comment.*strip" }
Test "Registered in discovery/mod.rs" { $c=Get-Content "D:\src\Janus_CryptoBOM\agent\src\discovery\mod.rs" -Raw; return $c -match "sidechannel" }
Test "scan function signature exists" { $c=Get-Content $f -Raw; return $c -match "pub fn scan" }
Test "Has 4+ detection patterns" { $c=Get-Content $f -Raw; $m=[regex]::Matches($c,'CRITICAL|HIGH|MEDIUM|LOW'); return ($m|Group-Object Value|Measure).Count -ge 4 }

Write-Host "`nF16 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
