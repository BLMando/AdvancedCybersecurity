# tpm_http.ps1 - HTTP API Server and Route Handlers module

Add-Type -AssemblyName System.Net.Http

# ----------------- Helper HTTP -----------------

function Send-JsonResponse ($res, $statusCode, $responseObj) {
    $res.StatusCode = $statusCode
    $res.ContentType = "application/json"
    if (-not $res.Headers["Access-Control-Allow-Origin"]) {
        $res.Headers.Add("Access-Control-Allow-Origin", "*")
    }
    $responseBody = ConvertTo-Json $responseObj -Depth 5 -Compress
    if ($null -eq $responseBody) { $responseBody = '{"error":"internal: null response object"}' }
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
    $res.ContentLength64 = $buffer.Length
    $res.OutputStream.Write($buffer, 0, $buffer.Length)
}

function Handle-CorsOptions ($res) {
    $res.StatusCode = 204
    $res.Headers.Add("Access-Control-Allow-Origin", "*")
    $res.Headers.Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    $res.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    $res.ContentLength64 = 0
    $res.OutputStream.Close()
}

function Invoke-PkiChallenge {
    $challengeUrl = "https://localhost:8080/api/challenge"
    $challengeResp = Invoke-RestMethod -Uri $challengeUrl -Method Get -TimeoutSec 10
    return $challengeResp.challenge_id
}

function Invoke-PkiEnrollment ($cn, $role, $dept, $challengeId, $proofString, $sigB64, $pubKeyPem, $mac, $cpu, $sessionToken, $isHardware) {
    $enrollUrl = "https://localhost:8080/api/csr"
    $enrollPayload = @{
        user = $cn
        role = $role
        department = $dept
        challenge_id = $challengeId
        proof_string = $proofString
        attestation_sig_b64 = $sigB64
        public_key_pem = $pubKeyPem
        is_hardware_csr = $isHardware
        mac = $mac
        cpu = $cpu
        enrollment_session_token = $sessionToken
    }
    $enrollResp = Invoke-RestMethod -Uri $enrollUrl -Method Post -ContentType "application/json" -Body (ConvertTo-Json $enrollPayload -Compress) -TimeoutSec 30
    return $enrollResp.certificate_pem
}

function Get-HardwareInfo {
    $mac = ""
    try {
        $mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress
    } catch {}
    if (-not $mac) { $mac = "00:11:22:33:44:55" }

    $cpu = "Windows-PC"
    try {
        $cpu = (Get-CimInstance Win32_Processor).Name.Trim()
    } catch {}
    return @{ mac = $mac; cpu = $cpu }
}

function Import-CertificateToStore ($certPem, $cn) {
    $certBytes = [System.Text.Encoding]::UTF8.GetBytes($certPem)
    $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $certObj.Import($certBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
    $store.Open("ReadWrite")
    $store.Add($certObj)
    $store.Close()

    $thumb = $certObj.Thumbprint
    Write-Host "[API] Associazione chiave privata con certutil..." -ForegroundColor Gray
    $certutilOut = & certutil.exe -user -repairstore My $thumb
    $certutilOut | ForEach-Object { Write-Host "    [certutil] $_" -ForegroundColor Gray }

    $certOutPath = Join-Path $CERT_DIR "$cn.crt"
    [System.IO.File]::WriteAllText($certOutPath, $certPem)
}

function Get-ErrorMessage ($err) {
    if ($null -ne $err.Exception) {
        return $err.Exception.Message
    }
    return $err.ToString()
}

# ----------------- Route Handlers (allineati a macOS) -----------------

function Handle-CertRequest ($cn) {
    Write-Host "[API] Ricevuto /cert per CN=$cn" -ForegroundColor Gray
    $cert = Get-ZtaCertificateWithFallback $cn
    if ($cert) {
        return (200, @{ cert_pem = Get-CertPem $cert; key_available = $true })
    }
    return (404, @{ error = "Certificato non trovato per CN=$cn" })
}

function Handle-EnrollRequest ($cn, $jsonBody) {
    $role = if ($jsonBody.role) { $jsonBody.role } else { "doctor" }
    $dept = if ($jsonBody.department) { $jsonBody.department } else { "Cardiologia" }
    $sessionToken = $jsonBody.enrollment_session_token
    Write-Host "[API] Ricevuto /enroll per CN=$cn, Ruolo=$role, Reparto=$dept" -ForegroundColor Gray

    $hw = Get-HardwareInfo
    $mac = $hw.mac
    $cpu = $hw.cpu

    try {
        $challengeId = Invoke-PkiChallenge

        # Chiamata in-process all'attestazione hardware (nessun sottoprocesso esterno!)
        $hwData = Invoke-HwAttestation $cn

        $modRaw = [Convert]::FromBase64String($hwData.modulus_b64)
        $expRaw = [Convert]::FromBase64String($hwData.exponent_b64)
        $pubKeyPem = Export-SpkiPublicKeyPem $modRaw $expRaw

        $certPem = Invoke-PkiEnrollment $cn $role $dept $challengeId $hwData.csr_pem $hwData.signature_b64 $pubKeyPem $mac $cpu $sessionToken $true

        Import-CertificateToStore $certPem $cn

        Write-Host "[API] /enroll hardware completato con successo per CN=$cn" -ForegroundColor Green
        return (200, @{ status = "success"; message = "Enrollment completato!" })
    } catch {
        Write-Host "[API] Enrollment TPM fallito per CN=$cn : $(Get-ErrorMessage $_). Provo fallback software..." -ForegroundColor Yellow
        return Handle-SoftwareFallbackEnroll $cn $role $dept $mac $cpu $sessionToken
    }
}

function Handle-SoftwareFallbackEnroll ($cn, $role, $dept, $mac, $cpu, $sessionToken) {
    try {
        $timestamp = (Get-Date -uformat "%Y-%m-%dT%H:%M:%SZ")
        $softKeyData = [RSASoftKeyHelper]::GenerateSoftwareKeyPair($cn, $timestamp)

        $modRaw = [Convert]::FromBase64String($softKeyData.modulus_b64)
        $expRaw = [Convert]::FromBase64String($softKeyData.exponent_b64)
        $pubKeyPem = Export-SpkiPublicKeyPem $modRaw $expRaw

        $challengeId = Invoke-PkiChallenge

        $certPem = Invoke-PkiEnrollment $cn $role $dept $challengeId $softKeyData.proof_string $softKeyData.signature_b64 $pubKeyPem $mac $cpu $sessionToken $false

        $certOutPath = Join-Path $CERT_DIR "$cn.crt"
        $keyOutPath = Join-Path $CERT_DIR "$cn.key"
        [System.IO.File]::WriteAllText($certOutPath, $certPem)
        [System.IO.File]::WriteAllText($keyOutPath, $softKeyData.private_key_pem)

        Write-Host "[API] /enroll software fallback completato per CN=$cn" -ForegroundColor Green
        return (200, @{ status = "success"; message = "Enrollment completato (Fallback Software)!" })
    } catch {
        Write-Host "[API] /enroll fallback software fallito per CN=$cn : $(Get-ErrorMessage $_)" -ForegroundColor Red
        return (500, @{ status = "error"; message = "Enrollment e software fallback falliti entrambi: $(Get-ErrorMessage $_)" })
    }
}

function Handle-ProxyStartRequest ($cn, $jsonBody) {
    $ttl = if ($jsonBody.ttl_seconds) { $jsonBody.ttl_seconds } else { 900 }
    Write-Host "[API] Ricevuto /proxy/start per CN=$cn, TTL=$ttl" -ForegroundColor Gray
    try {
        $proxyInfo = Start-ProxySession $cn $ttl
        return (200, @{
            status = "success"
            port = $proxyInfo.port
            session_token = $proxyInfo.session_token
            expires_at = (Get-Date).AddSeconds($ttl).ToString("o")
        })
    } catch {
        Write-Host "[API] /proxy/start fallito per CN=$cn : $(Get-ErrorMessage $_)" -ForegroundColor Yellow
        return (404, @{ error = (Get-ErrorMessage $_) })
    }
}

function Handle-ProxyStopRequest ($jsonBody) {
    $token = $jsonBody.session_token
    Write-Host "[API] Ricevuto /proxy/stop per Token=$token" -ForegroundColor Gray
    if (Stop-ProxySession $token) {
        return (200, @{ status = "stopped" })
    }
    return (404, @{ error = "Sessione non trovata" })
}

function Handle-OidcTokenRequest ($cn, $jsonBody) {
    $tokenCN = if ($cn) { $cn } else { "paolo.roselli" }
    $stepUp = $jsonBody.step_up -eq "true" -or $jsonBody.step_up -eq $true
    Write-Host "[API] Ricevuto /oidc/token per CN=$tokenCN, StepUp=$stepUp" -ForegroundColor Gray
    try {
        $challengeId = Invoke-PkiChallenge

        $cert = Get-ZtaCertificateWithFallback $tokenCN
        if (-not $cert) {
            throw "Certificato non trovato per CN=$tokenCN"
        }

        $timestamp = (Get-Date -uformat "%Y-%m-%dT%H:%M:%SZ")
        $proofString = "ZTA-CERT-BINDING|CN=$tokenCN|TIME=$timestamp"
        $proofBytes = [System.Text.Encoding]::UTF8.GetBytes($proofString)

        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if (-not $rsa) {
            throw "Impossibile recuperare la chiave privata per CN=$tokenCN"
        }
        $sigBytes = $rsa.SignData($proofBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $sigB64 = [Convert]::ToBase64String($sigBytes)

        $pubKeyPem = Get-PublicKeyPem $cert

        $oidcUrl = "https://localhost:8080/api/oidc/token"
        $oidcPayload = @{
            challenge_id = $challengeId
            signature = $sigB64
            public_key_pem = $pubKeyPem
            proof_string = $proofString
            step_up = $stepUp
        }
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $content = New-Object System.Net.Http.StringContent((ConvertTo-Json $oidcPayload -Compress), [System.Text.Encoding]::UTF8, "application/json")
        try {
            $response = $client.PostAsync($oidcUrl, $content).GetAwaiter().GetResult()
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $client.Dispose()

            $statusCode = [int]$response.StatusCode
            $responseObj = ConvertFrom-Json $responseBody

            if ($statusCode -eq 200) {
                Write-Host "[API] /oidc/token completato con successo per CN=$tokenCN" -ForegroundColor Green
                return (200, @{ status = "success"; token = $responseObj.access_token; access_token = $responseObj.access_token })
            } else {
                Write-Host "[API] /oidc/token fallito per CN=$tokenCN con codice $statusCode" -ForegroundColor Red
                return ($statusCode, $responseObj)
            }
        } catch {
            if ($client) { $client.Dispose() }
            Write-Host "[API] /oidc/token errore di connessione per CN=$tokenCN : $_" -ForegroundColor Red
            return (500, @{ status = "error"; message = (Get-ErrorMessage $_) })
        }
    } catch {
        Write-Host "[API] /oidc/token fallito per CN=$tokenCN : $_" -ForegroundColor Red
        return (500, @{ status = "error"; message = (Get-ErrorMessage $_) })
    }
}

function Handle-SignRequest ($cn, $jsonBody) {
    $dataB64 = $jsonBody.data_b64
    Write-Host "[API] Ricevuto /sign per CN=$cn" -ForegroundColor Gray
    $cert = Get-ZtaCertificateWithFallback $cn
    if (-not $cert) {
        return (404, @{ error = "Certificato per la firma non trovato" })
    }
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if (-not $rsa) {
            throw "Impossibile recuperare la chiave privata per la firma per CN=$cn"
        }
        $dataBytes = [Convert]::FromBase64String($dataB64)
        $sigBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $sigB64 = [Convert]::ToBase64String($sigBytes)
        return (200, @{ signature_b64 = $sigB64; pub_key_pem = Get-PublicKeyPem $cert })
    } catch {
        return (500, @{ error = (Get-ErrorMessage $_) })
    }
}

function Handle-AuthRequest ($cn) {
    Write-Host "[API] Ricevuto /auth per CN=$cn" -ForegroundColor Gray
    try {
        $cert = Get-ZtaCertificateWithFallback $cn
        if (-not $cert) {
            throw "Certificato non trovato per CN=$cn"
        }

        $uri = [System.Uri]"https://localhost:10000/api/resource"
        $tcp = [System.Net.Sockets.TcpClient]::new($uri.Host, $uri.Port)
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })
        $certsCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($cert)
        $ssl.AuthenticateAsClient($uri.Host, $certsCollection, [System.Security.Authentication.SslProtocols]::Tls12, $false)

        $writer = [System.IO.StreamWriter]::new($ssl)
        $writer.WriteLine("GET /api/resource HTTP/1.1")
        $writer.WriteLine("Host: $($uri.Host):$($uri.Port)")
        $writer.WriteLine("Connection: close")
        $writer.WriteLine("")
        $writer.Flush()

        $reader = [System.IO.StreamReader]::new($ssl)
        $resp = $reader.ReadToEnd()
        $ssl.Close()
        $tcp.Close()

        $statusLine = ($resp -split "`r`n")[0]
        Write-Host "[API] /auth completato con successo per CN=$cn" -ForegroundColor Green
        return (200, @{ status = "success"; response = "Status: 200, Data: $statusLine" })
    } catch {
        Write-Host "[API] /auth fallito per CN=$cn : $_" -ForegroundColor Red
        return (500, @{ status = "error"; message = (Get-ErrorMessage $_) })
    }
}

function Handle-ProxyStatusRequest {
    Write-Host "[API] Ricevuto GET /proxy/status" -ForegroundColor Gray
    $active = @()
    foreach ($pair in $script:Sessions) {
        $state = $pair.Value
        $active += @{
            common_name = $state.CN
            port = $state.Port
            expires_at = $state.ExpiresAt.ToString("o")
        }
    }
    return (200, @{ status = "success"; sessions = $active })
}

# ----------------- Start-HttpServer Loop -----------------

function Start-HttpServer {
    $http = [System.Net.HttpListener]::new()
    $boundAll = $false
    try {
        $http.Prefixes.Add("http://+:$Port/")
        $http.Start()
        $boundAll = $true
    } catch {
        Write-Host "    [WARN] Impossibile avviare il listener su tutte le interfacce (Accesso negato/Privilegi non sufficienti)." -ForegroundColor Yellow
        Write-Host "    [WARN] Provo fallback su localhost (non sara' raggiungibile dai container Docker)." -ForegroundColor Yellow
        $http.Close()
        $http = [System.Net.HttpListener]::new()
        $http.Prefixes.Add("http://localhost:$Port/")
        try {
            $http.Start()
        } catch {
            Write-Error "Impossibile avviare il server HTTP sulla porta $Port. Assicurati che non sia gia' in uso."
            exit 1
        }
    }

    Write-Host "="*70 -ForegroundColor Cyan
    if ($boundAll) {
        Write-Host " Windows ZTA Agent Service Emulation attivo su all interfaces (http://+:$Port/)" -ForegroundColor Cyan
    } else {
        Write-Host " Windows ZTA Agent Service Emulation attivo su http://localhost:$Port/ (Localhost Only)" -ForegroundColor Cyan
    }
    Write-Host " Inoltro traffico a Envoy su ${EnvoyHost}:${EnvoyPort}" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host "Premere CTRL+C per arrestare il server.`n"

    try {
        while ($http.IsListening) {
            $ctx = $http.GetContext()
            $req = $ctx.Request
            $res = $ctx.Response

            if ($req.HttpMethod -eq "OPTIONS") {
                Handle-CorsOptions $res
                continue
            }

            $reader = [System.IO.StreamReader]::new($req.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd()
            $reader.Close()

            $jsonBody = if ($body) { ConvertFrom-Json $body } else { $null }
            $cn = if ($jsonBody) { if ($jsonBody.common_name) { $jsonBody.common_name } else { $jsonBody.user } } else { $null }

            $route = "$($req.HttpMethod) $($req.Url.AbsolutePath)"

            try {
                $result = $null
                switch -Wildcard ($route) {
                    "POST /cert"         { $result = Handle-CertRequest $cn }
                    "POST /enroll"       { $result = Handle-EnrollRequest $cn $jsonBody }
                    "POST /proxy/start"  { $result = Handle-ProxyStartRequest $cn $jsonBody }
                    "POST /proxy/stop"   { $result = Handle-ProxyStopRequest $jsonBody }
                    "POST /oidc/token"   { $result = Handle-OidcTokenRequest $cn $jsonBody }
                    "POST /sign"         { $result = Handle-SignRequest $cn $jsonBody }
                    "POST /auth"         { $result = Handle-AuthRequest $cn }
                    "GET /proxy/status"  { $result = Handle-ProxyStatusRequest }
                    default              { $result = (404, @{ error = "Endpoint non valido o metodo HTTP errato" }) }
                }
                $statusCode, $responseObj = $result
                Send-JsonResponse $res $statusCode $responseObj
            } catch {
                Send-JsonResponse $res 500 @{ error = $_.Exception.Message }
                Write-Host "[API ERROR] $_" -ForegroundColor Red
            } finally {
                try { $res.Close() } catch {}
            }
        }
    } catch {
    } finally {
        $http.Close()
    }
}
