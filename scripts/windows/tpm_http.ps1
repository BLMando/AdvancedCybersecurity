# tpm_http.ps1 - HTTP server and shared helpers

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

function Invoke-PkiEnrollment ($cn, $role, $dept, $challengeId, $proofString, $sigB64, $pubKeyPem, $mac, $cpu, $sessionToken) {
    $enrollUrl = "https://localhost:8080/api/csr"
    $enrollPayload = @{
        user = $cn
        role = $role
        department = $dept
        challenge_id = $challengeId
        proof_string = $proofString
        attestation_sig_b64 = $sigB64
        public_key_pem = $pubKeyPem
        is_hardware_csr = $false
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
    Write-Host "[API] Associazione chiave privata con certutil (non bloccante)..." -ForegroundColor Gray
    $job = Start-Job -ScriptBlock { param($t) & certutil.exe -silent -user -repairstore My $t | Out-Null } -ArgumentList $thumb
    $completed = $job | Wait-Job -Timeout 10
    if ($null -eq $completed) {
        Write-Host "[API WARN] certutil repairstore ha richiesto troppo tempo (timeout 10s) ed e' stato interrotto." -ForegroundColor Yellow
    }
    $job | Remove-Job -Force

    $certOutPath = Join-Path $CERT_DIR "$cn.crt"
    [System.IO.File]::WriteAllText($certOutPath, $certPem)
}

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
        Write-Host " Windows ZTA TPM Agent Service Emulator attivo su all interfaces (http://+:$Port/)" -ForegroundColor Cyan
    } else {
        Write-Host " Windows ZTA TPM Agent Service Emulator attivo su http://localhost:$Port/ (Localhost Only)" -ForegroundColor Cyan
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
