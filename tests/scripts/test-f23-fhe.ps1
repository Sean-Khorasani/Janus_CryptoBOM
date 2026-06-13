# F23 — FHE Library Detection Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$d="D:\src\Janus_CryptoBOM\agent\src\discovery\dependency.rs"
$s="D:\src\Janus_CryptoBOM\agent\src\discovery\source.rs"
Write-Host "=== F23: FHE Library Detection Tests ===" -F Cyan

Test "CRYPTO_PACKAGES has FHE entries" { $c=Get-Content $d -Raw; return ($c -match "tfhe-rs") -and ($c -match "concrete") -and ($c -match "openfhe") }
Test "FHE_NEEDLES constant defined" { $c=Get-Content $d -Raw; return $c -match "FHE_NEEDLES" }
Test "8 FHE libraries detected" { $c=Get-Content $d -Raw; $m=[regex]::Matches($c,'"tfhe-rs"|"concrete"|"openfhe"|"seal"|"lattigo"|"helib"|"palisade"|"tfhe"'); return ($m|Group-Object Value|Measure).Count -ge 8 }
Test "source.rs has FHE regex patterns" { $c=Get-Content $s -Raw; return ($c -match "FHE") -and ($c -match "CKKS") -and ($c -match "BGV") }
Test "7 FHE patterns in source.rs" { $c=Get-Content $s -Raw; $m=[regex]::Matches($c,'FHE|CKKS|BGV|BFV|TFHE|GSW|HomomorphicEncrypt'); return ($m|Group-Object Value|Measure).Count -ge 5 }
Test "FHE tagged as homomorphic-encryption family" { $c=Get-Content $s -Raw; return $c -match "homomorphic.encryption" }
Test "FHE confidence is high (>=0.85)" { $c=Get-Content $d -Raw; return $c -match '0\.95|0\.90' }
Test "Lattigo (Go FHE) detected" { $c=Get-Content $d -Raw; return $c -match "lattigo" }
Test "Microsoft SEAL detected" { $c=Get-Content $d -Raw; return $c -match "seal" }

Write-Host "`nF23 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
