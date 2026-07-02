# tpm_proxy.ps1 - TCP loopback proxy to Envoy
function Start-ProxySession ($cn, $ttlSeconds) {
    if ($script:Sessions.ContainsKey("default")) {
        Stop-ProxySession "default" | Out-Null
    }

    $cert = Get-ZtaCertificate $cn
    if (-not $cert) { throw "Certificate not found for CN=$cn" }

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 27019)
    $listener.Start()

    $session = @{
        CN = $cn
        Port = 27019
        Listener = $listener
        Active = $true
        ExpiresAt = (Get-Date).AddSeconds($ttlSeconds)
    }
    $script:Sessions["default"] = $session

    # Run connection accept loop in a background thread
    $thread = [System.Threading.Thread]::new({
        param($s, $c)
        try {
            while ($s.Active) {
                if (-not $s.Listener.Pending()) {
                    [System.Threading.Thread]::Sleep(100)
                    continue
                }
                $local = $s.Listener.AcceptTcpClient()
                
                # Pipe client in background task
                [System.Threading.Tasks.Task]::Run({
                    $localClient = $local
                    try {
                        $envoy = [System.Net.Sockets.TcpClient]::new("localhost", 10000)
                        $ssl = [System.Net.Security.SslStream]::new(
                            $envoy.GetStream(),
                            $false,
                            { param($snd, $certificate, $chain, $errors) return $true }
                        )
                        $certsCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($c)
                        $ssl.AuthenticateAsClient("localhost", $certsCollection, [System.Security.Authentication.SslProtocols]::Tls12, $false)

                        $localStream = $localClient.GetStream()
                        $t1 = $localStream.CopyToAsync($ssl)
                        $t2 = $ssl.CopyToAsync($localStream)
                        [System.Threading.Tasks.Task]::WaitAll(@($t1, $t2))
                    } catch {
                    } finally {
                        if ($envoy) { $envoy.Close() }
                        if ($localClient) { $localClient.Close() }
                    }
                })
            }
        } catch {}
    })
    $thread.Start($session, $cert)

    # Expiry task
    [System.Threading.Tasks.Task]::Run({
        [System.Threading.Thread]::Sleep([int]($ttlSeconds * 1000))
        if ($script:Sessions["default"] -eq $session) {
            Stop-ProxySession "default" | Out-Null
            Write-Host "[Proxy] Session expired for CN=$cn" -ForegroundColor Yellow
        }
    })

    return @{
        port = 27019
        session_token = "default"
    }
}

function Stop-ProxySession ($token) {
    if ($script:Sessions.ContainsKey("default")) {
        $s = $script:Sessions["default"]
        $s.Active = $false
        $s.Listener.Stop()
        $script:Sessions.Remove("default")
        return $true
    }
    return $false
}
