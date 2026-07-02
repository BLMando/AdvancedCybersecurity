# tpm_config.ps1 - Shared configuration and state

$CERT_DIR = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $PSCommandPath -Parent) "..\..\volumes\certs\client"))
$ENVOY_CERT_PATH = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $PSCommandPath -Parent) "..\..\volumes\certs\server\envoy.crt"))

$script:Sessions = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()
