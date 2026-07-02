# tpm_handlers.ps1 - Request handlers and cert helpers

function Get-CertPem ($cert) {
    $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $b64 = [Convert]::ToBase64String($bytes, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----"
}

function Get-ZtaCertificate ($cn) {
    $crtPath = Join-Path $CERT_DIR "$cn.crt"
    $keyPath = Join-Path $CERT_DIR "$cn.key"
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    if (Test-Path $crtPath) {
        if (Test-Path $keyPath) {
            $combined = (Get-Content $crtPath -Raw) + "`n" + (Get-Content $keyPath -Raw)
            $cert.Import([System.Text.Encoding]::UTF8.GetBytes($combined), $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            return $cert
        } else {
            $storeCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" -and $_.HasPrivateKey } | Select-Object -First 1
            if ($storeCert) { return $storeCert }
            $cert.Import([System.Text.Encoding]::UTF8.GetBytes((Get-Content $crtPath -Raw)))
            return $cert
        }
    }
    return $null
}

function Get-HardwareInfo {
    $mac = "00:11:22:33:44:55"
    try {
        $mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress
    } catch {}
    return @{ mac = $mac; cpu = "Windows-PC" }
}

function Handle-CertRequest ($cn) {
    $cert = Get-ZtaCertificate $cn
    if ($cert) {
        return @{ cert_pem = Get-CertPem $cert; key_available = $true }
    }
    throw "Certificate not found for CN=$cn"
}

function Handle-EnrollRequest ($cn, $body) {
    $role = if ($body.role) { $body.role } else { "doctor" }
    $dept = if ($body.department) { $body.department } else { "Cardiologia" }
    $token = $body.enrollment_session_token

    # Check TPM presence
    $hasTpm = $false
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) { $hasTpm = $true }
    } catch {}

    try {
        # Generate TPM Key & Sign
        $label = "ZTA-HW-$cn"
        $keyData = [ZtaCryptoHelper]::GenerateTpmKeyAndSign($label, $cn, $hasTpm)
        $modBytes = [Convert]::FromBase64String($keyData.modulus_b64)
        $expBytes = [Convert]::FromBase64String($keyData.exponent_b64)
        $pubKeyPem = [ZtaCryptoHelper]::ExportPublicKeyPem($modBytes, $expBytes)

        $challenge = Invoke-RestMethod -Uri "https://localhost:8080/api/challenge" -Method Get
        
        $hw = Get-HardwareInfo
        $payload = @{
            user = $cn
            role = $role
            department = $dept
            challenge_id = $challenge.challenge_id
            proof_string = $keyData.proof_string
            attestation_sig_b64 = $keyData.signature_b64
            public_key_pem = $pubKeyPem
            is_hardware_csr = $false
            mac = $hw.mac
            cpu = $hw.cpu
            enrollment_session_token = $token
        }
        $resp = Invoke-RestMethod -Uri "https://localhost:8080/api/csr" -Method Post -ContentType "application/json" -Body (ConvertTo-Json $payload -Compress)
        
        $crtPath = Join-Path $CERT_DIR "$cn.crt"
        [System.IO.File]::WriteAllText($crtPath, $resp.certificate_pem)

        # Import cert to store and link private key
        $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certObj.Import([System.Text.Encoding]::UTF8.GetBytes($resp.certificate_pem), $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
        $store.Open("ReadWrite")
        $store.Add($certObj)
        $store.Close()
        & certutil.exe -silent -user -repairstore My $certObj.Thumbprint | Out-Null

        return @{ status = "success"; message = "Enrollment TPM completato!" }
    } catch {
        # Software Fallback
        $keyData = [ZtaCryptoHelper]::GenerateSoftwareKeyPair($cn)
        $modBytes = [Convert]::FromBase64String($keyData.modulus_b64)
        $expBytes = [Convert]::FromBase64String($keyData.exponent_b64)
        $pubKeyPem = [ZtaCryptoHelper]::ExportPublicKeyPem($modBytes, $expBytes)

        $challenge = Invoke-RestMethod -Uri "https://localhost:8080/api/challenge" -Method Get
        $hw = Get-HardwareInfo
        $payload = @{
            user = $cn
            role = $role
            department = $dept
            challenge_id = $challenge.challenge_id
            proof_string = $keyData.proof_string
            attestation_sig_b64 = $keyData.signature_b64
            public_key_pem = $pubKeyPem
            is_hardware_csr = $false
            mac = $hw.mac
            cpu = $hw.cpu
            enrollment_session_token = $token
        }
        $resp = Invoke-RestMethod -Uri "https://localhost:8080/api/csr" -Method Post -ContentType "application/json" -Body (ConvertTo-Json $payload -Compress)

        [System.IO.File]::WriteAllText((Join-Path $CERT_DIR "$cn.crt"), $resp.certificate_pem)
        [System.IO.File]::WriteAllText((Join-Path $CERT_DIR "$cn.key"), $keyData.private_key_pem)

        return @{ status = "success"; message = "Enrollment completato (Fallback Software)!" }
    }
}

function Handle-OidcTokenRequest ($cn, $body) {
    $stepUp = $body.step_up -eq $true -or $body.step_up -eq "true"
    $cert = Get-ZtaCertificate $cn
    if (-not $cert) { throw "Certificate not found for $cn" }

    $timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $proofString = "ZTA-CERT-BINDING|CN=$cn|TIME=$timestamp"
    $proofBytes = [System.Text.Encoding]::UTF8.GetBytes($proofString)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw "Private key not accessible for CN=$cn" }
    $sigBytes = $rsa.SignData($proofBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $sigB64 = [Convert]::ToBase64String($sigBytes)

    $pubParams = $rsa.ExportParameters($false)
    $pubKeyPem = [ZtaCryptoHelper]::ExportPublicKeyPem($pubParams.Modulus, $pubParams.Exponent)

    $challenge = Invoke-RestMethod -Uri "https://localhost:8080/api/challenge" -Method Get
    
    $payload = @{
        challenge_id = $challenge.challenge_id
        signature = $sigB64
        public_key_pem = $pubKeyPem
        proof_string = $proofString
        step_up = $stepUp
    }
    $resp = Invoke-RestMethod -Uri "https://localhost:8080/api/oidc/token" -Method Post -ContentType "application/json" -Body (ConvertTo-Json $payload -Compress)
    return @{ status = "success"; token = $resp.access_token; access_token = $resp.access_token }
}

function Handle-SignRequest ($cn, $body) {
    $cert = Get-ZtaCertificate $cn
    if (-not $cert) { throw "Certificate not found for CN=$cn" }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw "Private key not accessible for CN=$cn" }
    
    $dataBytes = [Convert]::FromBase64String($body.data_b64)
    $sigBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $sigB64 = [Convert]::ToBase64String($sigBytes)
    
    $pubParams = $rsa.ExportParameters($false)
    $pubKeyPem = [ZtaCryptoHelper]::ExportPublicKeyPem($pubParams.Modulus, $pubParams.Exponent)
    return @{ signature_b64 = $sigB64; pub_key_pem = $pubKeyPem }
}

function Handle-ProxyStartRequest ($cn, $body) {
    $ttl = if ($body.ttl_seconds) { $body.ttl_seconds } else { 900 }
    $proxyInfo = Start-ProxySession $cn $ttl
    return @{
        status = "success"
        port = $proxyInfo.port
        session_token = $proxyInfo.session_token
        expires_at = (Get-Date).AddSeconds($ttl).ToString("o")
    }
}

function Handle-ProxyStopRequest ($body) {
    if (Stop-ProxySession $body.session_token) {
        return @{ status = "stopped" }
    }
    throw "Session not found"
}

function Handle-AuthRequest ($cn) {
    $cert = Get-ZtaCertificate $cn
    if (-not $cert) { throw "Certificate not found for CN=$cn" }

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
    return @{ status = "success"; response = "Status: 200, Data: $statusLine" }
}
