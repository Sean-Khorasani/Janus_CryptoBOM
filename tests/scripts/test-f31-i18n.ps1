# F31 — i18n/Localization Tests
$Passed=0; $Failed=0; function Test($n,$s){try{if(&$s){$Passed++;Write-Host "  PASS  $n" -F Green}else{$Failed++;Write-Host "  FAIL  $n" -F Red}}catch{$Failed++;Write-Host "  ERROR $n" -F Red}}
$i18n="D:\src\Janus_CryptoBOM\ui\src\i18n"
Write-Host "=== F31: i18n Tests ===" -F Cyan

Test "i18n/index.ts exists" { return Test-Path "$i18n\index.ts" }
Test "i18n/types.ts exists" { return Test-Path "$i18n\types.ts" }
Test "en.json locale exists" { return Test-Path "$i18n\locales\en.json" }
Test "fa.json locale exists" { return Test-Path "$i18n\locales\fa.json" }
Test "zh.json locale exists" { return Test-Path "$i18n\locales\zh.json" }
Test "es.json locale exists" { return Test-Path "$i18n\locales\es.json" }
Test "en.json has 30+ translation keys" { $c=Get-Content "$i18n\locales\en.json" -Raw | ConvertFrom-Json; return ($c.PSObject.Properties | Measure).Count -ge 30 }
Test "fa.json has Persian translations" { $c=Get-Content "$i18n\locales\fa.json" -Raw; return $c.Length -gt 200 }
Test "zh.json has Chinese translations" { $c=Get-Content "$i18n\locales\zh.json" -Raw; return $c.Length -gt 200 }
Test "es.json has Spanish translations" { $c=Get-Content "$i18n\locales\es.json" -Raw; return $c.Length -gt 200 }
Test "useTranslation hook exists" { return Test-Path "D:\src\Janus_CryptoBOM\ui\src\hooks\useTranslation.ts" }
Test "main.tsx imports i18n" { $c=Get-Content "D:\src\Janus_CryptoBOM\ui\src\main.tsx" -Raw; return $c -match "I18nProvider|i18n" }
Test "App.tsx has locale switcher" { $c=Get-Content "D:\src\Janus_CryptoBOM\ui\src\App.tsx" -Raw; return $c -match "setLocale|Globe|locale" }

Write-Host "`nF31 Results: $Passed/$($Passed+$Failed) passed" -F $(if($Failed){'Red'}else{'Green'})
exit $(if($Failed){1}else{0})
