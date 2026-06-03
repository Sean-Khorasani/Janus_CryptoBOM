param(
  [ValidateSet("Json", "Text")]
  [string]$Format = "Json"
)

$ErrorActionPreference = "Continue"

function Try-Run {
  param([scriptblock]$Block)
  try {
    & $Block
  } catch {
    $_.Exception.Message
  }
}

$certStores = @("Cert:\CurrentUser\My", "Cert:\CurrentUser\Root", "Cert:\LocalMachine\My", "Cert:\LocalMachine\Root")
$certificates = foreach ($store in $certStores) {
  Try-Run {
    Get-ChildItem -Path $store -ErrorAction Stop | Select-Object `
      @{Name="Store";Expression={$store}},
      Subject,
      Issuer,
      Thumbprint,
      NotAfter,
      SignatureAlgorithm,
      PublicKey
  }
}

$schannel = Try-Run {
  Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Recurse |
    ForEach-Object {
      $values = Get-ItemProperty -Path $_.PSPath
      [pscustomobject]@{
        Path = $_.Name
        Enabled = $values.Enabled
        DisabledByDefault = $values.DisabledByDefault
      }
    }
}

$httpBindings = Try-Run {
  netsh http show sslcert
}

$cngProviders = Try-Run {
  certutil -csplist
}

$result = [pscustomobject]@{
  Hostname = $env:COMPUTERNAME
  CollectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
  Certificates = $certificates
  SchannelPolicy = $schannel
  HttpSysTlsBindings = $httpBindings
  CngProviders = $cngProviders
}

if ($Format -eq "Json") {
  $result | ConvertTo-Json -Depth 6
} else {
  $result | Format-List | Out-String
}

