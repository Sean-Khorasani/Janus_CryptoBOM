# F32 — Accessibility (WCAG 2.1 AA) Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$a="D:\src\Janus_CryptoBOM\ui\src\a11y"
$css="D:\src\Janus_CryptoBOM\ui\src\index.css"
Write-Host "=== F32: Accessibility Tests ===" -F Cyan

Test "A11yAnnouncer.tsx exists" { return Test-Path "$a\A11yAnnouncer.tsx" }
Test "SkipLink.tsx exists" { return Test-Path "$a\SkipLink.tsx" }
Test "FocusTrap.tsx exists" { return Test-Path "$a\FocusTrap.tsx" }
Test "useKeyboardNav.ts exists" { return Test-Path "$a\useKeyboardNav.ts" }
Test "Focus-visible styles defined" { $c=Get-Content $css -Raw; return $c -match "focus-visible" }
Test "Skip-link class defined" { $c=Get-Content $css -Raw; return $c -match "skip-link" }
Test "Screen-reader-only class defined" { $c=Get-Content $css -Raw; return $c -match "sr-only" }
Test "Components have aria-labels" { $files=Get-ChildItem "D:\src\Janus_CryptoBOM\ui\src\components" -Filter *.tsx -Recurse; $count=0; foreach($f in $files){ if((Get-Content $f.FullName -Raw) -match "aria-label"){$count++}}; return $count -ge 5 }
Test "Components have role attributes" { $files=Get-ChildItem "D:\src\Janus_CryptoBOM\ui\src\components" -Filter *.tsx -Recurse; $count=0; foreach($f in $files){ if((Get-Content $f.FullName -Raw) -match "role="){$count++}}; return $count -ge 5 }
Test "FleetManagement imports FocusTrap" { $c=Get-Content "D:\src\Janus_CryptoBOM\ui\src\components\FleetManagement.tsx" -Raw; return $c -match "FocusTrap" }
Test "SkipLink used in App.tsx or main.tsx" { $c1=Get-Content "D:\src\Janus_CryptoBOM\ui\src\App.tsx" -Raw; $c2=Get-Content "D:\src\Janus_CryptoBOM\ui\src\main.tsx" -Raw; return ($c1 -match "SkipLink") -or ($c2 -match "SkipLink") }
Test "aria-hidden on decorative icons" { $files=Get-ChildItem "D:\src\Janus_CryptoBOM\ui\src\components" -Filter *.tsx -Recurse; $count=0; foreach($f in $files){ if((Get-Content $f.FullName -Raw) -match "aria-hidden"){$count++}}; return $count -ge 3 }

Write-Host "`nF32 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
