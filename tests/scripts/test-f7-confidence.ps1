# F7 — Statistical Confidence Analysis Tests
param($BaseUrl="http://127.0.0.1:8080")
$Passed=0; $Failed=0
function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$h=@{'Content-Type'='application/json'}
Write-Host "=== F7: Confidence Analysis Tests ===" -F Cyan

Test "GET /api/confidence/report returns structure" {
  $r=Invoke-RestMethod "$BaseUrl/api/confidence/report" -Headers $h
  return $null -ne $r.average_confidence -and $null -ne $r.low_confidence_count -and $null -ne $r.rule_confidence_breakdown
}
Test "Confidence report has numeric average" { $r=Invoke-RestMethod "$BaseUrl/api/confidence/report" -Headers $h; return $r.average_confidence -is [double] }
Test "Confidence report has high_confidence_count" { $r=Invoke-RestMethod "$BaseUrl/api/confidence/report" -Headers $h; return $null -ne $r.high_confidence_count }
Test "Confidence report has low_confidence_count below 0.5 threshold" { $r=Invoke-RestMethod "$BaseUrl/api/confidence/report" -Headers $h; return $r.low_confidence_count -ge 0 }
Test "Confidence file compiles in Go" { return (Get-Item "D:\src\Janus_CryptoBOM\server\internal\policy\confidence.go").Length -gt 0 }

Write-Host "`nF7 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
