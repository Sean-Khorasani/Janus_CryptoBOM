# F1 — PQC Migration Sandbox Simulator Tests
param($BaseUrl="http://127.0.0.1:8080")
$Passed=0; $Failed=0
function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$h=@{'Content-Type'='application/json'}
Write-Host "=== F1: PQC Migration Sandbox Tests ===" -F Cyan

Test "POST /api/sandbox/simulate returns simulation_id" {
  $r=Invoke-RestMethod "$BaseUrl/api/sandbox/simulate" -Method POST -Body '{"algorithm":"RSA","target_service":"nginx","config_snippet":"ssl_ciphers RSA;"}' -Headers $h
  $global:simId=$r.simulation_id
  return $null -ne $r.simulation_id -and $null -ne $r.migration_patch
}
Test "Simulation includes validation checklist" { return $global:simId -and (Invoke-RestMethod "$BaseUrl/api/sandbox/simulate" -Method POST -Body '{"algorithm":"ECDSA","target_service":"nginx"}' -Headers $h).validation_checklist.Count -gt 0 }
Test "Simulation recommends KEM from active profile" { $r=Invoke-RestMethod "$BaseUrl/api/sandbox/simulate" -Method POST -Body '{"algorithm":"DH","target_service":"sshd"}' -Headers $h; return $r.recommended_kem -match "ML-KEM|X25519MLKEM" }
Test "Simulation dry_run_available is true" { $r=Invoke-RestMethod "$BaseUrl/api/sandbox/simulate" -Method POST -Body '{"algorithm":"RSA","target_service":"apache"}' -Headers $h; return $r.dry_run_available -eq $true }
Test "Simulation for DSA recommends signature" { $r=Invoke-RestMethod "$BaseUrl/api/sandbox/simulate" -Method POST -Body '{"algorithm":"DSA","target_service":"nginx"}' -Headers $h; return $r.recommended_signature -match "ML-DSA|SLH-DSA" }

Write-Host "`nF1 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
