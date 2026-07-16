# tWindows TPM ZTA Agent
# Avvio:
#   powershell -ExecutionPolicy Bypass -File .\scripts\windows\tpm_agent_service.ps1
#

param (
    [int]$Port = 9090,
    [string]$EnvoyHost = "localhost",
    [int]$EnvoyPort = 10000
)

# 1. Configurazione globale integrata (sostituisce tpm_config.ps1)
$scriptDir = Split-Path $PSCommandPath -Parent
$CERT_DIR = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\..\volumes\certs\client"))
$ENVOY_CERT_PATH = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\..\volumes\certs\server\envoy.crt"))

# Inizializzazione della mappa concomitante per le sessioni proxy (generic Object per supportare classi C#)
$script:Sessions = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Object]]::new()

# 2. Caricamento dei moduli agenti allineati
. (Join-Path $scriptDir "tpm_crypto.ps1")
. (Join-Path $scriptDir "tpm_proxy.ps1")
. (Join-Path $scriptDir "tpm_http.ps1")

# 3. Avvio del server HTTP API
Start-HttpServer
