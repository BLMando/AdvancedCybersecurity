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
$ENVOY_CERT_PATH = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $PSCommandPath -Parent) "..\..\volumes\certs\server\envoy.crt"))

# Dizionario thread-safe delle sessioni proxy attive: session_token (string) -> Listener state (hashtable)
$script:Sessions = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()

# Helper per convertire un X509Certificate2 in PEM
function Get-CertPem ($cert) {
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certB64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----"
}

# Helper per estrarre la chiave pubblica PEM dal certificato
function Get-PublicKeyPem ($cert) {
    $pubKeyBytes = $cert.PublicKey.EncodedKeyValue.RawData
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
    $ps = [System.Management.Automation.PowerShell]::Create()
    $null = $ps.AddScript({
        param($src, $tgt)
        $buffer = New-Object byte[] 65536
        try {
            while ($true) {
                $bytesRead = $src.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -le 0) { break }
                $tgt.Write($buffer, 0, $bytesRead)
                $tgt.Flush()
            }
        } catch {
            # Connessione interrotta
        } finally {
            $src.Close()
            $tgt.Close()
        }
    }).AddArgument($sourceStream).AddArgument($targetStream) | Out-Null
    return $ps
}

# Avvia il Listener TCP Proxy mTLS locale per una sessione
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
    $cts = [System.Threading.CancellationTokenSource]::new()
    $sessionToken = [Guid]::NewGuid().ToString()
    
    $sessionState = @{
        CN = $cn
        Port = $localPort
        Listener = $listener
        CTS = $cts
        ExpiresAt = (Get-Date).AddSeconds($ttlSeconds)
        ExpiryTimer = $null
    }
    $script:Sessions.TryAdd($sessionToken, $sessionState) | Out-Null
    $expiryTimer = [System.Threading.Timer]::new(
        [System.Threading.TimerCallback]{
            param($state)
            Stop-ProxySession $state | Out-Null
        },
        $sessionToken,
        [TimeSpan]::FromSeconds($ttlSeconds),
        [System.Threading.Timeout]::InfiniteTimeSpan
    )
    $sessionState.ExpiryTimer = $expiryTimer
    
    # Salva listener e cts nell'AppDomain per accesso cross-runspace
    $adKey = "ZTA_PROXY_$sessionToken"
    $adData = @{ Listener = $listener; CTS = $cts }
    [AppDomain]::CurrentDomain.SetData($adKey, $adData)
    
    # 3. Async background proxy loop via PowerShell.Create (PS 5.1 runspace compat)
    $bgPs = [System.Management.Automation.PowerShell]::Create()
    $null = $bgPs.AddScript({
        param($cn, $sessionToken, $adKey, $envoyHost, $envoyPort, $certObj)
        
        # Recupera oggetti condivisi dall'AppDomain
        $adData = [AppDomain]::CurrentDomain.GetData($adKey)
        $listener = $adData.Listener
        $cts = $adData.CTS
        $localPort = $listener.LocalEndpoint.Port
        
        Write-Host "[*] Proxy TCP avviato su localhost:$localPort per CN=$cn (Sessione: $sessionToken)" -ForegroundColor Green
        try {
            while (-not $cts.Token.IsCancellationRequested) {
                $acceptTask = $listener.AcceptTcpClientAsync()
                $acceptTask.Wait($cts.Token)
                if ($acceptTask.IsCanceled) { break }
                $localClient = $acceptTask.Result
                $capturedClient = $localClient
                
                $connPs = [System.Management.Automation.PowerShell]::Create()
                $null = $connPs.AddScript({
                    param($localSock, $cn, $cert, $envoyHost, $envoyPort, $pinnedEnvoyCertPath)
                    $logFile = Join-Path $env:TEMP "zta_proxy_debug.log"
                    $envoyClient = $null
                    $sslStream = $null
                    try {
                        "    [Proxy] Nuova connessione locale per CN=$cn. Tentativo mTLS verso Envoy (${envoyHost}:${envoyPort})..." | Out-File -FilePath $logFile -Append -Encoding utf8
                        
                        $envoyClient = [System.Net.Sockets.TcpClient]::new($envoyHost, $envoyPort)
                        "    [Proxy] TCP connesso a Envoy" | Out-File -FilePath $logFile -Append -Encoding utf8
                        
                        $validationCallback = [System.Net.Security.RemoteCertificateValidationCallback] {
                            param($sender, $certificate, $chain, $sslPolicyErrors)
                            if ($certificate -eq $null -or -not (Test-Path $pinnedEnvoyCertPath)) {
                                return $false
                            }
                            try {
                                $presentedCert = if ($certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                                    $certificate
                                } else {
                                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
                                }
                                $pinnedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pinnedEnvoyCertPath)
                                return $presentedCert.Thumbprint -eq $pinnedCert.Thumbprint
                            } catch {
                                return $false
                            }
                        }
                        
                        $sslStream = [System.Net.Security.SslStream]::new(
                            $envoyClient.GetStream(),
                            $false,
                            $validationCallback
                        )
                        
                        if ($cert -eq $null) {
                            "    [Proxy] ERRORE: cert e' null!" | Out-File -FilePath $logFile -Append -Encoding utf8
                            throw "Certificato client e' null"
                        }
                        
                        $certsCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($cert)
                        "    [Proxy] Collezione cert creata" | Out-File -FilePath $logFile -Append -Encoding utf8
                        
                        $sslStream.AuthenticateAsClient(
                            $envoyHost,
                            $certsCollection,
                            [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13,
                            $false
                        )
                        
                        "    [Proxy] Handshake mTLS completato con Envoy!" | Out-File -FilePath $logFile -Append -Encoding utf8
                        
                        $localStream = $localSock.GetStream()
                        $t1 = $localStream.CopyToAsync($sslStream)
                        $t2 = $sslStream.CopyToAsync($localStream)
                        
                        [System.Threading.Tasks.Task]::WaitAll(@($t1, $t2))
                    } catch {
                        "    [Proxy ERROR] Errore nel tunnel mTLS per CN=${cn}: $_" | Out-File -FilePath $logFile -Append -Encoding utf8
                    } finally {
                        if ($localSock) { $localSock.Close() }
                        if ($sslStream) { $sslStream.Close() }
                        if ($envoyClient) { $envoyClient.Close() }
                    }
                }).AddArgument($capturedClient).AddArgument($cn).AddArgument($certObj).AddArgument($envoyHost).AddArgument($envoyPort).AddArgument($ENVOY_CERT_PATH) | Out-Null
                $connPs.BeginInvoke() | Out-Null
            }
        } catch {
            Write-Host "[*] Proxy loop terminato per $cn : $_" -ForegroundColor Yellow
        } finally {
            $listener.Stop()
            [AppDomain]::CurrentDomain.SetData($adKey, $null)
            Write-Host "[*] Proxy TCP su localhost:$localPort fermato." -ForegroundColor Yellow
        }
    }).AddArgument($cn).AddArgument($sessionToken).AddArgument($adKey).AddArgument($EnvoyHost).AddArgument($EnvoyPort).AddArgument($cert) | Out-Null
    $bgPs.BeginInvoke() | Out-Null

    return @{
        port = $localPort
        session_token = $sessionToken
    }
}

# Ferma la sessione proxy e chiude il listener
function Stop-ProxySession ($sessionToken) {
    if ($script:Sessions.ContainsKey($sessionToken)) {
        $state = $script:Sessions[$sessionToken]
        if ($state.ExpiryTimer) { $state.ExpiryTimer.Dispose() }
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
    Write-Host " Inoltro traffico a Envoy su ${EnvoyHost}:${EnvoyPort}" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host "Premere CTRL+C per arrestare il server.`n"

    try {
        while ($http.IsListening) {
            $ctx = $http.GetContext()
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
                elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/enroll") {
                    $cn = $jsonBody.common_name
                    $role = $jsonBody.role
                    $dept = $jsonBody.department
                    Write-Host "[API] Ricevuto /enroll per CN=$cn, Ruolo=$role, Reparto=$dept" -ForegroundColor Gray
                    
                    try {
                        # 1. Recupera challenge dal server PKI
                        $challengeUrl = "http://localhost:8080/api/challenge"
                        $challengeResp = Invoke-RestMethod -Uri $challengeUrl -Method Get -TimeoutSec 10
                        $challengeId = $challengeResp.challenge_id
                        
                        # 2. Genera chiave nel TPM ed esegui la firma di attestazione
                        $hwScript = Join-Path (Split-Path $PSCommandPath -Parent) "hw_attestation.ps1"
                        $res = & $hwScript -CN $cn
                        $hwData = ConvertFrom-Json $res
                        
                        # Rileva MAC e CPU
                        $mac = ""
                        try {
                            $mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress
                        } catch {}
                        if (-not $mac) { $mac = "00:11:22:33:44:55" }
                        
                        $cpu = "Windows-PC"
                        try {
                            $cpu = (Get-CimInstance Win32_Processor).Name.Trim()
                        } catch {}
                        
                        # Costruisci PEM della chiave pubblica
                        $rsa = [System.Security.Cryptography.RSA]::Create()
                        $rsaParams = [System.Security.Cryptography.RSAParameters]::new()
                        $rsaParams.Modulus = [Convert]::FromBase64String($hwData.modulus_b64)
                        $rsaParams.Exponent = [Convert]::FromBase64String($hwData.exponent_b64)
                        $rsa.ImportParameters($rsaParams)
                        $pubKeyPem = $rsa.ExportSubjectPublicKeyInfoPem()
                        
                        # 3. Richiedi firma del certificato al server PKI
                        $enrollUrl = "http://localhost:8080/api/csr"
                        $enrollPayload = @{
                            user = $cn
                            role = $role
                            department = $dept
                            challenge_id = $challengeId
                            proof_string = $hwData.csr_pem
                            attestation_sig_b64 = $hwData.signature_b64
                            public_key_pem = $pubKeyPem
                            is_hardware_csr = $true
                            mac = $mac
                            cpu = $cpu
                        }
                        
                        $enrollResp = Invoke-RestMethod -Uri $enrollUrl -Method Post -ContentType "application/json" -Body (ConvertTo-Json $enrollPayload -Compress) -TimeoutSec 30
                        $certPem = $enrollResp.certificate_pem
                        
                        # 4. Importa certificato nel Windows Certificate Store
                        $certBytes = [System.Text.Encoding]::UTF8.GetBytes($certPem)
                        $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $certObj.Import($certBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                        
                        $store = New-Object System.Security.Cryptography.X509Store("My", "CurrentUser")
                        $store.Open("ReadWrite")
                        $store.Add($certObj)
                        $store.Close()
                        
                        # Associa la chiave privata tramite certutil -repairstore
                        $thumb = $certObj.Thumbprint
                        & certutil.exe -user -repairstore My $thumb | Out-Null
                        
                        # Scrivi copia del cert nella cartella condivisa client/
                        $certOutPath = Join-Path $CERT_DIR "$cn.crt"
                        [System.IO.File]::WriteAllText($certOutPath, $certPem)
                        
                        $responseObj = @{
                            status = "success"
                            message = "Enrollment completato!"
                        }
                        Write-Host "[API] /enroll completato con successo per CN=$cn" -ForegroundColor Green
                    } catch {
                        $statusCode = 500
                        $responseObj = @{ status = "error"; message = $_.Exception.Message }
                        Write-Host "[API] /enroll fallito per CN=$cn : $_" -ForegroundColor Red
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
        }
    } catch {
        # Server arrestato
    } finally {
        $http.Close()
    }
}

# Avvia l'event loop del server HTTP
Start-HttpServer
