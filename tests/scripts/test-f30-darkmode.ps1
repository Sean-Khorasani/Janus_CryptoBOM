# F30 — Dark Mode Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$css="D:\src\Janus_CryptoBOM\ui\src\index.css"
$tw="D:\src\Janus_CryptoBOM\ui\tailwind.config.ts"
Write-Host "=== F30: Dark Mode Tests ===" -F Cyan

Test "CSS dark mode variables defined" { $c=Get-Content $css -Raw; return ($c -match "\[data-theme='dark'\]") -and ($c -match "--color-bg") -and ($c -match "--color-surface") }
Test "Tailwind darkMode selector configured" { $c=Get-Content $tw -Raw; return $c -match "darkMode" -and $c -match "data-theme" }
Test "Dark mode overrides for bg-white" { $c=Get-Content $css -Raw; return $c -match "dark.*bg-white|bg-white.*dark" }
Test "Dark mode overrides for form elements" { $c=Get-Content $css -Raw; return $c -match "dark.*input|dark.*textarea|dark.*select" }
Test "Scrollbar styling in dark mode" { $c=Get-Content $css -Raw; return $c -match "dark.*scrollbar" }
Test "Glass-morphism card class defined" { $c=Get-Content $css -Raw; return $c -match "glass-card" }
Test "Shimmer skeleton class defined" { $c=Get-Content $css -Raw; return $c -match "skeleton-shimmer|@keyframes shimmer" }
Test "Status badge gradients defined" { $c=Get-Content $css -Raw; return $c -match "badge-critical|badge-high|badge-medium" }
Test "Metric card styling defined" { $c=Get-Content $css -Raw; return $c -match "metric-card" }
Test "CSS contains 10+ semantic variables" { $c=Get-Content $css -Raw; $m=[regex]::Matches($c,'--color-|--shadow-|--radius-'); return $m.Count -ge 10 }
Test "App.tsx has theme toggle" { $c=Get-Content "D:\src\Janus_CryptoBOM\ui\src\App.tsx" -Raw; return $c -match "setTheme|dark.*light|light.*dark" }
Test "Components use dark: Tailwind variants" { $files=Get-ChildItem "D:\src\Janus_CryptoBOM\ui\src\components" -Filter *.tsx -Recurse; $count=0; foreach($f in $files){ if((Get-Content $f.FullName -Raw) -match "dark:"){$count++}}; return $count -ge 5 }

Write-Host "`nF30 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
