# tpm_agent_service.ps1 - Windows TPM ZTA Agent API Service Emulator
#
# Emula l'API HTTP del ZTAAgent macOS sulla porta 9090 su Windows.
# Gestisce l'enrollment, le firme TPM e il proxy mTLS MongoDB tramite Schannel.
#
# Avvio:
#   powershell -ExecutionPolicy Bypass -File .\scripts\windows\tpm_agent_service.ps1
#

param (
    [int]$Port = 9090,
    [string]$EnvoyHost = "localhost",
    [int]$EnvoyPort = 10000
)

$scriptDir = Split-Path $PSCommandPath -Parent

. (Join-Path $scriptDir "tpm_crypto.ps1")
. (Join-Path $scriptDir "tpm_config.ps1")
. (Join-Path $scriptDir "tpm_cert_helpers.ps1")
. (Join-Path $scriptDir "tpm_proxy.ps1")
. (Join-Path $scriptDir "tpm_handlers.ps1")
. (Join-Path $scriptDir "tpm_http.ps1")

Start-HttpServer
