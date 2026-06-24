# tpm_cert_helpers.ps1 - Certificate helper functions

function Get-CertPem ($cert) {
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certB64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----"
}

function Export-SpkiPublicKeyPem ($modulus, $exponent) {
    return [RSASoftKeyHelper]::ExportSpkiPublicKeyPem($modulus, $exponent)
}

function Get-PublicKeyPem ($cert) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    if ($rsa) {
        $params = $rsa.ExportParameters($false)
        return [RSASoftKeyHelper]::ExportSpkiPublicKeyPem($params.Modulus, $params.Exponent)
    }
    return $null
}

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

function Get-ZtaCertificate ($cn) {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" -and $_.HasPrivateKey } | Select-Object -First 1
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
    }
    return $cert
}

function Get-ZtaCertificateWithFallback ($cn) {
    $cert = Get-ZtaCertificate $cn
    if (-not $cert) {
        Write-Host "[API] Cert non trovato in Windows Store per CN=$cn. Cerco su disco..." -ForegroundColor Yellow
        $cert = Get-FileCertWithKey $cn
    } elseif (-not $cert.HasPrivateKey) {
        Write-Host "[API] Cert in Windows Store per CN=$cn non ha private key. Cerco su disco..." -ForegroundColor Yellow
        $fileCert = Get-FileCertWithKey $cn
        if ($fileCert) {
            $cert = $fileCert
            Write-Host "[API] Cert+key caricati da file per CN=$cn" -ForegroundColor Green
        }
    }
    return $cert
}
