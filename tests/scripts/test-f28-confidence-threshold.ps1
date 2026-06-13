# F28 — Finding Confidence Threshold Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$e="D:\src\Janus_CryptoBOM\server\internal\policy\engine.go"
Write-Host "=== F28: Confidence Threshold Tests ===" -F Cyan

Test "Profile has MinimumConfidence field" { $c=Get-Content $e -Raw; return $c -match "MinimumConfidence" }
Test "assessAlgorithm checks minimum confidence" { $c=Get-Content $e -Raw; return $c -match "minConf|MinimumConfidence|alg.Confidence.*minConf" }
Test "Default threshold is 0.4" { $c=Get-Content $e -Raw; return $c -match "0\.4" }
Test "NIST policy has minimum_confidence" { $c=Get-Content "D:\src\Janus_CryptoBOM\policies\nist-pqc-2026.yaml" -Raw; return $c -match "minimum_confidence" }
Test "CNSA policy has minimum_confidence" { $c=Get-Content "D:\src\Janus_CryptoBOM\policies\cnsa-2.0.yaml" -Raw; return $c -match "minimum_confidence" }
Test "Custom policy has minimum_confidence" { $c=Get-Content "D:\src\Janus_CryptoBOM\policies\custom.yaml" -Raw; return $c -match "minimum_confidence" }
Test "MinimumConfidence is float64" { $c=Get-Content $e -Raw; return $c -match "MinimumConfidence\s+float64" }
Test "createPolicy handler includes minimum_confidence" { $c=Get-Content "D:\src\Janus_CryptoBOM\server\internal\httpapi\server.go" -Raw; return $c -match "minimum_confidence|MinimumConfidence" }

Write-Host "`nF28 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
