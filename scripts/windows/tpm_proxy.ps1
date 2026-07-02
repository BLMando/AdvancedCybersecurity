# tpm_proxy.ps1 - Proxy session management

function Start-ProxySession ($cn, $ttlSeconds) {
    $cert = Get-ZtaCertificateWithFallback $cn
    if (-not $cert) {
        throw "Certificato non trovato né in Windows Store né su disco per CN=$cn"
    }

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 0)
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
    $script:Sessions[$sessionToken] = $sessionState
    $expiryTimer = [System.Threading.Timer]::new(
        [System.Threading.TimerCallback]{ param($state) Stop-ProxySession $state | Out-Null },
        $sessionToken,
        [TimeSpan]::FromSeconds($ttlSeconds),
        [System.Threading.Timeout]::InfiniteTimeSpan
    )
    $sessionState.ExpiryTimer = $expiryTimer

    $adKey = "ZTA_PROXY_$sessionToken"
    $adData = @{ Listener = $listener; CTS = $cts }
    [AppDomain]::CurrentDomain.SetData($adKey, $adData)

    $bgPs = [System.Management.Automation.PowerShell]::Create()
    $null = $bgPs.AddScript({
        param($cn, $sessionToken, $adKey, $envoyHost, $envoyPort, $certObj, $envoyCertPath)

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
                }).AddArgument($capturedClient).AddArgument($cn).AddArgument($certObj).AddArgument($envoyHost).AddArgument($envoyPort).AddArgument($envoyCertPath) | Out-Null
                $connPs.BeginInvoke() | Out-Null
            }
        } catch {
            Write-Host "[*] Proxy loop terminato per $cn : $_" -ForegroundColor Yellow
        } finally {
            $listener.Stop()
            [AppDomain]::CurrentDomain.SetData($adKey, $null)
            Write-Host "[*] Proxy TCP su localhost:$localPort fermato." -ForegroundColor Yellow
        }
    }).AddArgument($cn).AddArgument($sessionToken).AddArgument($adKey).AddArgument($EnvoyHost).AddArgument($EnvoyPort).AddArgument($cert).AddArgument($ENVOY_CERT_PATH) | Out-Null
    $bgPs.BeginInvoke() | Out-Null

    return @{
        port = $localPort
        session_token = $sessionToken
    }
}

function Stop-ProxySession ($sessionToken) {
    if ($script:Sessions.ContainsKey($sessionToken)) {
        $state = $script:Sessions[$sessionToken]
        if ($state.ExpiryTimer) { $state.ExpiryTimer.Dispose() }
        $state.CTS.Cancel()
        $state.Listener.Stop()
        $script:Sessions.Remove($sessionToken)
        return $true
    }
    return $false
}
