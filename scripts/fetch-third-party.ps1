param(
  [string]$Destination = "third_party"
)

$ErrorActionPreference = "Stop"

$repos = @(
  @{ Name = "volatility3"; Url = "https://github.com/volatilityfoundation/volatility3.git" },
  @{ Name = "frida-core"; Url = "https://github.com/frida/frida-core.git" },
  @{ Name = "lego"; Url = "https://github.com/go-acme/lego.git" },
  @{ Name = "step-ca"; Url = "https://github.com/smallstep/certificates.git" },
  @{ Name = "zgrab2"; Url = "https://github.com/zmap/zgrab2.git" },
  @{ Name = "testssl.sh"; Url = "https://github.com/testssl/testssl.sh.git" }
)

New-Item -ItemType Directory -Force -Path $Destination | Out-Null

foreach ($repo in $repos) {
  $target = Join-Path $Destination $repo.Name
  if (Test-Path $target) {
    git -C $target fetch --all --tags --prune
  } else {
    git clone --depth 1 $repo.Url $target
  }
}

