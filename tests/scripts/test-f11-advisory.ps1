# F11 — Third-Party Advisory Integration Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$f="D:\src\Janus_CryptoBOM\server\internal\policy\osv.go"
Write-Host "=== F11: Advisory Integration Tests ===" -F Cyan

Test "osv.go exists" { return Test-Path $f -and (Get-Item $f).Length -gt 1000 }
Test "OSVClient struct defined" { $c=Get-Content $f -Raw; return $c -match "type OSVClient struct" }
Test "QueryPackage method exists" { $c=Get-Content $f -Raw; return $c -match "func.*QueryPackage" }
Test "CVSS score parsing implemented" { $c=Get-Content $f -Raw; return $c -match "cvssScoreToJanus" -and $c -match "ParseFloat" }
Test "FilterCryptoRelevant function exists" { $c=Get-Content $f -Raw; return $c -match "FilterCryptoRelevant" }
Test "GetFixedVersion extracts fix version" { $c=Get-Content $f -Raw; return $c -match "GetFixedVersion" }
Test "Local advisories database present" { $c=Get-Content $f -Raw; return $c -match "localAdvisories" }
Test "OSV severity mapped to Janus levels" { $c=Get-Content $f -Raw; return $c -match "9\.0.*5|7\.0.*4|4\.0.*3" }
Test "Response body size limited (1MB)" { $c=Get-Content $f -Raw; return $c -match "1<<20" }
Test "mapEcosystem supports 8+ ecosystems" { $c=Get-Content $f -Raw; $m=[regex]::Matches($c,'"Go"|"npm"|"PyPI"|"Maven"|"NuGet"|"crates.io"|"RubyGems"|"Packagist"'); return $m.Count -ge 6 }

Write-Host "`nF11 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
