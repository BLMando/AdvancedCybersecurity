# tpm_agent_service.ps1 - Windows TPM ZTA Agent API Service Emulator
#
# Emula l'API HTTP del ZTAAgent macOS sulla porta 9090 su Windows.
# Gestisce l'enrollment, le firme TPM e il proxy mTLS MongoDB tramite Schannel.
#
# Avvio:
#   powershell.exe -ExecutionPolicy Bypass -File scripts/windows/tpm_agent_service.ps1
#

param (
    [int]$Port = 9090,
    [string]$EnvoyHost = "localhost",
    [int]$EnvoyPort = 10000
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Path relativo alla directory dei certificati client (condivisa col container PKI)
$CERT_DIR = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $PSCommandPath -Parent) "..\..\volumes\certs\client"))

# Dizionario thread-safe delle sessioni proxy attive: session_token (string) -> Listener state (hashtable)
$script:Sessions = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()

# Helper per convertire un X509Certificate2 in PEM
function Get-CertPem ($cert) {
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certB64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----\n$certB64\n-----END CERTIFICATE-----"
}

# Helper per estrarre la chiave pubblica PEM dal certificato
function Get-PublicKeyPem ($cert) {
    $pubKeyBytes = $cert.PublicKey.EncodedKeyValue.RawData
    # In una soluzione di produzione completa, si formatterebbe come SubjectPublicKeyInfo (ASN.1 DER/PEM)
    # Per praticità in PowerShell, esportiamo la chiave pubblica tramite RSACng
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    if ($rsa) {
        $pubKeyPem = $rsa.ExportSubjectPublicKeyInfoPem()
        return $pubKeyPem
    }
    return $null
}

# Helper per caricare certificato + chiave privata da file (fallback lab mode)
function Get-FileCertWithKey ($cn) {
    $crtPath = Join-Path $CERT_DIR "$cn.crt"
    $keyPath = Join-Path $CERT_DIR "$cn.key"
    if (-not (Test-Path $crtPath) -or -not (Test-Path $keyPath)) {
        return $null
    }
    $combinedPem = (Get-Content $crtPath -Raw) + "`n" + (Get-Content $keyPath -Raw)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($combinedPem)
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($bytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        return $cert
    } catch {
        Write-Host "    [WARN] Impossibile caricare cert+key da file per CN=$cn : $_" -ForegroundColor Yellow
        return $null
    }
}

# Helper per pipe bidirezionale asincrona dei dati TCP
function Start-Pipe ($sourceStream, $targetStream, $connectionName) {
    [System.Threading.Tasks.Task]::Run({
        $buffer = New-Object byte[] 65536
        try {
            while ($true) {
                $bytesRead = $sourceStream.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -le 0) { break }
                $targetStream.Write($buffer, 0, $bytesRead)
                $targetStream.Flush()
            }
        } catch {
            # Connessione interrotta
        } finally {
            $sourceStream.Close()
            $targetStream.Close()
        }
    })
}

# Avvia il Listener TCP Proxy mTLS locale per una sessione
# Trova il certificato del CN, apre una porta TCP casuale e fa mTLS verso Envoy con Schannel (TPM key access).
function Start-ProxySession ($cn, $ttlSeconds) {
    # 1. Trova il certificato nel Windows Store
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
    if (-not $cert) {
        Write-Host "[API] Cert non trovato in Windows Store per CN=$cn. Cerco su disco..." -ForegroundColor Yellow
        $cert = Get-FileCertWithKey $cn
        if (-not $cert) {
            throw "Certificato non trovato né in Windows Store né su disco per CN=$cn"
        }
        Write-Host "[API] Cert caricato da file per CN=$cn" -ForegroundColor Green
    } elseif (-not $cert.HasPrivateKey) {
        Write-Host "[API] Cert in Windows Store per CN=$cn non ha private key. Cerco su disco..." -ForegroundColor Yellow
        $fileCert = Get-FileCertWithKey $cn
        if ($fileCert) {
            $cert = $fileCert
            Write-Host "[API] Cert+key caricati da file per CN=$cn" -ForegroundColor Green
        } else {
            Write-Host "[API] Fallback file non disponibile per CN=$cn. Uso store cert senza private key (potrebbe fallire)." -ForegroundColor Yellow
        }
    }

    # 2. Crea un listener TCP su una porta dinamica (porta 0)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $localPort = $listener.LocalEndpoint.Port
    $sessionToken = [Guid]::NewGuid().ToString()

    $cts = [System.Threading.CancellationTokenSource]::new()

    $sessionState = @{
        CN = $cn
        Port = $localPort
        Listener = $listener
        CTS = $cts
        ExpiresAt = (Get-Date).AddSeconds($ttlSeconds)
    }

    $script:Sessions.TryAdd($sessionToken, $sessionState) | Out-Null

    # 3. Task asincrono di gestione connessioni in background
    [System.Threading.Tasks.Task]::Run({
        Write-Host "[*] Proxy TCP avviato su localhost:$localPort per CN=$cn (Sessione: $sessionToken)" -ForegroundColor Green
        try {
            while (-not $cts.Token.IsCancellationRequested) {
                # Accetta client locale (plain TCP dal driver MongoDB Python)
                $acceptTask = $listener.AcceptTcpClientAsync()
                $acceptTask.Wait($cts.Token)
                if ($acceptTask.IsCanceled) { break }
                $localClient = $acceptTask.Result
                
                # Avvia il tunnel verso Envoy con mTLS (Schannel/TPM)
                [System.Threading.Tasks.Task]::Run({
                    $localSock = $args[0]
                    $envoyClient = $null
                    $sslStream = $null
                    try {
                        Write-Host "    [Proxy] Nuova connessione locale. Tentativo mTLS verso Envoy ($EnvoyHost:$EnvoyPort)..." -ForegroundColor Cyan
                        
                        $envoyClient = [System.Net.Sockets.TcpClient]::new($EnvoyHost, $EnvoyPort)
                        
                        # Definisce il callback di validazione del certificato di Envoy (accetta sempre in lab)
                        $validationCallback = [System.Net.Security.RemoteCertificateValidationCallback] {
                            param($sender, $certificate, $chain, $sslPolicyErrors)
                            return $true
                        }
                        
                        $sslStream = [System.Net.Security.SslStream]::new(
                            $envoyClient.GetStream(),
                            $false,
                            $validationCallback
                        )
                        
                        # Carica la collezione di certificati client (incluso il certificato Windows TPM)
                        $certsCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($cert)
                        
                        # Avvia handshake mTLS client-side (il modulo Schannel negozia autonomamente la chiave TPM protetta)
                        $sslStream.AuthenticateAsClient(
                            $EnvoyHost,
                            $certsCollection,
                            [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13,
                            $false
                        )
                        
                        Write-Host "    [Proxy] Handshake mTLS completato con Envoy!" -ForegroundColor Green
                        
                        # Pipe bidirezionale asincrona
                        $localStream = $localSock.GetStream()
                        $t1 = Start-Pipe $localStream $sslStream "Local->Envoy"
                        $t2 = Start-Pipe $sslStream $localStream "Envoy->Local"
                        
                        [System.Threading.Tasks.Task]::WaitAll(@($t1, $t2))
                    } catch {
                        Write-Host "    [Proxy] Errore nel tunnel mTLS: $_" -ForegroundColor Red
                    } finally {
                        if ($localSock) { $localSock.Close() }
                        if ($sslStream) { $sslStream.Close() }
                        if ($envoyClient) { $envoyClient.Close() }
                    }
                }, $localClient)
            }
        } catch {
            # Il listener è stato fermato o è scaduta la sessione
        } finally {
            $listener.Stop()
            Write-Host "[*] Proxy TCP su localhost:$localPort fermato." -ForegroundColor Yellow
        }
    })

    return @{
        port = $localPort
        session_token = $sessionToken
    }
}

# Ferma la sessione proxy e chiude il listener
function Stop-ProxySession ($sessionToken) {
    if ($script:Sessions.ContainsKey($sessionToken)) {
        $state = $script:Sessions[$sessionToken]
        $state.CTS.Cancel()
        $state.Listener.Stop()
        $script:Sessions.TryRemove($sessionToken, [ref]$null) | Out-Null
        return $true
    }
    return $false
}

# Avvia l'API HTTP locale
function Start-HttpServer {
    $http = [System.Net.HttpListener]::new()
    $http.Prefixes.Add("http://localhost:$Port/")
    try {
        $http.Start()
    } catch {
        Write-Error "Impossibile avviare il server HTTP sulla porta $Port. Assicurati che non sia già in uso."
        exit 1
    }
    
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host " Windows ZTA TPM Agent Service Emulator attivo su http://localhost:$Port/" -ForegroundColor Cyan
    Write-Host " Inoltro traffico a Envoy su $EnvoyHost:$EnvoyPort" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host "Premere CTRL+C per arrestare il server.`n"

    try {
        while ($http.IsListening) {
            $context = $http.GetContext()
            [System.Threading.Tasks.Task]::Run({
                $ctx = $args[0]
                $req = $ctx.Request
                $res = $ctx.Response
                
                # Leggi corpo della richiesta
                $reader = [System.IO.StreamReader]::new($req.InputStream, [System.Text.Encoding]::UTF8)
                $body = $reader.ReadToEnd()
                $reader.Close()
                
                $responseObj = $null
                $statusCode = 200
                
                try {
                    $jsonBody = if ($body) { ConvertFrom-Json $body } else { $null }
                    
                    if ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/cert") {
                        $cn = $jsonBody.common_name
                        Write-Host "[API] Ricevuto /cert per CN=$cn" -ForegroundColor Gray
                        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
                        if (-not $cert) {
                            Write-Host "[API] Cert non trovato in Windows Store per CN=$cn. Cerco su disco..." -ForegroundColor Yellow
                            $cert = Get-FileCertWithKey $cn
                        }
                        if ($cert) {
                            $responseObj = @{
                                cert_pem = Get-CertPem $cert
                                key_available = $true
                            }
                        } else {
                            $statusCode = 404
                            $responseObj = @{ error = "Certificato non trovato per CN=$cn" }
                        }
                    }
                    elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/proxy/start") {
                        $cn = $jsonBody.common_name
                        $ttl = if ($jsonBody.ttl_seconds) { $jsonBody.ttl_seconds } else { 900 }
                        Write-Host "[API] Ricevuto /proxy/start per CN=$cn, TTL=$ttl" -ForegroundColor Gray
                        
                        try {
                            $proxyInfo = Start-ProxySession $cn $ttl
                            $responseObj = @{
                                status = "success"
                                port = $proxyInfo.port
                                session_token = $proxyInfo.session_token
                                expires_at = (Get-Date).AddSeconds($ttl).ToString("o")
                            }
                        } catch {
                            $statusCode = 404
                            $responseObj = @{ error = $_.Exception.Message }
                            Write-Host "[API] /proxy/start fallito per CN=$cn : $_" -ForegroundColor Yellow
                        }
                    }
                    elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/proxy/stop") {
                        $token = $jsonBody.session_token
                        Write-Host "[API] Ricevuto /proxy/stop per Token=$token" -ForegroundColor Gray
                        
                        if (Stop-ProxySession $token) {
                            $responseObj = @{ status = "stopped" }
                        } else {
                            $statusCode = 404
                            $responseObj = @{ error = "Sessione non trovata" }
                        }
                    }
                    elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/sign") {
                        $cn = $jsonBody.common_name
                        $dataB64 = $jsonBody.data_b64
                        Write-Host "[API] Ricevuto /sign per CN=$cn" -ForegroundColor Gray
                        
                        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
                        if ($cert) {
                            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                            $dataBytes = [Convert]::FromBase64String($dataB64)
                            
                            # Esegue la firma crittografica delegando a Schannel/TPM
                            $sigBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                            $sigB64 = [Convert]::ToBase64String($sigBytes)
                            
                            $responseObj = @{
                                signature_b64 = $sigB64
                                pub_key_pem = Get-PublicKeyPem $cert
                            }
                        } else {
                            $statusCode = 404
                            $responseObj = @{ error = "Certificato per la firma non trovato" }
                        }
                    }
                    else {
                        $statusCode = 404
                        $responseObj = @{ error = "Endpoint non valido o metodo HTTP errato" }
                    }
                } catch {
                    $statusCode = 500
                    $responseObj = @{ error = $_.Exception.Message }
                    Write-Host "[API ERROR] $_" -ForegroundColor Red
                }
                
                # Invia risposta
                $res.StatusCode = $statusCode
                $res.ContentType = "application/json"
                $res.Headers.Add("Access-Control-Allow-Origin", "*")
                
                $responseBody = ConvertTo-Json $responseObj -Depth 5 -Compress
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
                $res.ContentLength64 = $buffer.Length
                $res.OutputStream.Write($buffer, 0, $buffer.Length)
                $res.OutputStream.Close()
            }, $context)
        }
    } catch {
        # Server arrestato
    } finally {
        $http.Close()
    }
}

# Avvia l'event loop del server HTTP
Start-HttpServer
