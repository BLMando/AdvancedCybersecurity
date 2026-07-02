# tpm_config.ps1 - Windows ZTA TPM Agent Configuration

$scriptDir = Split-Path $PSCommandPath -Parent
$CERT_DIR = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\..\volumes\certs\client"))
$ENVOY_CERT_PATH = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\..\volumes\certs\server\envoy.crt"))

if (-not (Test-Path $CERT_DIR)) {
    New-Item -ItemType Directory -Path $CERT_DIR -Force | Out-Null
}

$script:Sessions = @{}
