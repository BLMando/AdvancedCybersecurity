# tpm_handlers.ps1 - HTTP route handlers

Add-Type -AssemblyName System.Net.Http

function Get-ErrorMessage ($err) {
    if ($null -ne $err.Exception) {
        return $err.Exception.Message
    }
    return $err.ToString()
}

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
    Write-Host "[API] Ricevuto /enroll per CN=$cn, Ruolo=$role, Reparto=$dept, Token=(redacted)" -ForegroundColor Gray

    $hw = Get-HardwareInfo
    $mac = $hw.mac
    $cpu = $hw.cpu

    try {
        $challengeId = Invoke-PkiChallenge

        $hwScript = Join-Path (Split-Path $PSCommandPath -Parent) "hw_attestation.ps1"
        $hwRes = & $hwScript -CN $cn
        $hwData = ConvertFrom-Json $hwRes

        $modRaw = [Convert]::FromBase64String($hwData.modulus_b64)
        $expRaw = [Convert]::FromBase64String($hwData.exponent_b64)
        $pubKeyPem = Export-SpkiPublicKeyPem $modRaw $expRaw

        $certPem = Invoke-PkiEnrollment $cn $role $dept $challengeId $hwData.csr_pem $hwData.signature_b64 $pubKeyPem $mac $cpu $sessionToken $true

        Import-CertificateToStore $certPem $cn

        Write-Host "[API] /enroll completato con successo per CN=$cn" -ForegroundColor Green
        return (200, @{ status = "success"; message = "Enrollment completato!" })
    } catch {
        Write-Host "[API] Enrollment TPM/Store fallito per CN=$cn : $_. Provo fallback software file-based..." -ForegroundColor Yellow
        Write-Host "[API] Enrollment TPM/Store fallito per CN=$cn : $(Get-ErrorMessage $_). Provo fallback software file-based..." -ForegroundColor Yellow
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
        return (200, @{ status = "success"; message = "Enrollment completato (Fallback Software File-based)!" })
    } catch {
        Write-Host "[API] /enroll fallback software fallito per CN=$cn : $(Get-ErrorMessage $_)" -ForegroundColor Red
        return (500, @{ status = "error"; message = "TPM enrollment e software fallback falliti entrambi: $(Get-ErrorMessage $_)" })
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
            throw "Certificato non trovato in Windows Store né su disco per CN=$tokenCN"
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
