# F5 — Runtime Algorithm Interception Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$f="D:\src\Janus_CryptoBOM\agent\src\interceptor.rs"
Write-Host "=== F5: Runtime TLS Interception Tests ===" -F Cyan

Test "interceptor.rs exists" { return Test-Path $f }
Test "SSL_CTX_set_cipher_list hook present" { $c=Get-Content $f -Raw; return $c -match "SSL_CTX_set_cipher_list" }
Test "SSL_set_cipher_list hook present" { $c=Get-Content $f -Raw; return $c -match "SSL_set_cipher_list" }
Test "SSL_CTX_set_ciphersuites hook present (TLS 1.3)" { $c=Get-Content $f -Raw; return $c -match "SSL_CTX_set_ciphersuites" }
Test "SSL_CTX_set1_groups_list hook present" { $c=Get-Content $f -Raw; return $c -match "SSL_CTX_set1_groups_list" }
Test "Intercept mode check (JANUS_INTERCEPT_MODE)" { $c=Get-Content $f -Raw; return $c -match "JANUS_INTERCEPT_MODE|intercept_mode" }
Test "Active mode injects PQC ciphers" { $c=Get-Content $f -Raw; return $c -match "MLKEM|Kyber|X25519MLKEM" }
Test "Passive mode logs only" { $c=Get-Content $f -Raw; return $c -match "passive" }
Test "config.rs has intercept_mode field" { $c=Get-Content "D:\src\Janus_CryptoBOM\agent\src\config.rs" -Raw; return $c -match "intercept_mode" }
Test "needs_pqc_injection helper exists" { $c=Get-Content $f -Raw; return $c -match "needs_pqc_injection|inject_pqc" }

Write-Host "`nF5 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
