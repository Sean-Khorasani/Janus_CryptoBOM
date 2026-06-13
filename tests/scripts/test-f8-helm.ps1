# F8 — Helm Chart Validation Tests
$Passed=0; $Failed=0
$chartDir="D:\src\Janus_CryptoBOM\deploy\helm\janus"
Write-Host "=== F8: Helm Chart Tests ===" -F Cyan

function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}

Test "Chart.yaml exists" { return Test-Path "$chartDir\Chart.yaml" }
Test "values.yaml exists" { return Test-Path "$chartDir\values.yaml" }
Test "templates/deployment-server.yaml exists" { return Test-Path "$chartDir\templates\deployment-server.yaml" }
Test "templates/deployment-agent.yaml exists" { return Test-Path "$chartDir\templates\deployment-agent.yaml" }
Test "templates/service.yaml exists" { return Test-Path "$chartDir\templates\service.yaml" }
Test "templates/configmap.yaml exists" { return Test-Path "$chartDir\templates\configmap.yaml" }
Test "templates/secrets.yaml exists" { return Test-Path "$chartDir\templates\secrets.yaml" }
Test "templates/ingress.yaml exists" { return Test-Path "$chartDir\templates\ingress.yaml" }
Test "templates/postgres-statefulset.yaml exists" { return Test-Path "$chartDir\templates\postgres-statefulset.yaml" }
Test "templates/_helpers.tpl exists" { return Test-Path "$chartDir\templates\_helpers.tpl" }
Test "templates/NOTES.txt exists" { return Test-Path "$chartDir\templates\NOTES.txt" }
Test "README.md exists" { return Test-Path "$chartDir\README.md" }
Test "Chart.yaml has valid apiVersion" { $c=Get-Content "$chartDir\Chart.yaml" -Raw; return $c -match "apiVersion" }
Test "values.yaml has replicaCount" { $c=Get-Content "$chartDir\values.yaml" -Raw; return $c -match "replicaCount" }

Write-Host "`nF8 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
