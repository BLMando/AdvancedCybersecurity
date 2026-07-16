# Compile the C# ZtaProxySession class once per PowerShell session
if (-not ([System.Management.Automation.PSTypeName]"ZtaProxySession").Type) {
    $csharpCode = @"
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public class ZtaProxySession {
    public string CN { get; private set; }
    public string SessionToken { get; private set; }
    public int Port { get; private set; }
    public DateTime ExpiresAt { get; private set; }
    
    private TcpListener _listener;
    private CancellationTokenSource _cts;
    private X509Certificate2 _clientCert;
    private string _pinnedEnvoyCertPath;
    private string _envoyHost;
    private int _envoyPort;
    private bool _isStopped = false;

    public ZtaProxySession(string cn, int port, X509Certificate2 clientCert, string envoyHost, int envoyPort, string pinnedEnvoyCertPath, int ttlSeconds) {
        CN = cn;
        SessionToken = Guid.NewGuid().ToString();
        Port = port;
        ExpiresAt = DateTime.UtcNow.AddSeconds(ttlSeconds);
        _clientCert = clientCert;
        _envoyHost = envoyHost;
        _envoyPort = envoyPort;
        _pinnedEnvoyCertPath = pinnedEnvoyCertPath;
        _cts = new CancellationTokenSource();
    }

    public void Start() {
        _listener = new TcpListener(IPAddress.Loopback, Port);
        _listener.Start();
        
        Task.Run(async () => {
            try {
                while (!_cts.Token.IsCancellationRequested) {
                    TcpClient localClient = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    Task unused = HandleIncomingConnectionAsync(localClient);
                }
            } catch {
                // listener stopped
            }
        });
    }

    private async Task HandleIncomingConnectionAsync(TcpClient localClient) {
        try {
            using (localClient)
            using (TcpClient envoyClient = new TcpClient()) {
                await envoyClient.ConnectAsync(_envoyHost, _envoyPort).ConfigureAwait(false);
                
                RemoteCertificateValidationCallback validationCallback = (sender, certificate, chain, sslPolicyErrors) => {
                    if (certificate == null) return false;
                    if (string.IsNullOrEmpty(_pinnedEnvoyCertPath) || !File.Exists(_pinnedEnvoyCertPath)) {
                        return true;
                    }
                    try {
                        X509Certificate2 presentedCert = new X509Certificate2(certificate);
                        X509Certificate2 pinnedCert = new X509Certificate2(_pinnedEnvoyCertPath);
                        return presentedCert.Thumbprint.Equals(pinnedCert.Thumbprint, StringComparison.OrdinalIgnoreCase);
                    } catch {
                        return false;
                    }
                };

                using (SslStream sslStream = new SslStream(
                    envoyClient.GetStream(),
                    false,
                    validationCallback
                )) {
                    X509Certificate2Collection certsCollection = new X509Certificate2Collection(_clientCert);
                    
                    await sslStream.AuthenticateAsClientAsync(
                        _envoyHost,
                        certsCollection,
                        System.Security.Authentication.SslProtocols.Tls12,
                        false
                    ).ConfigureAwait(false);

                    using (NetworkStream localStream = localClient.GetStream()) {
                        Task t1 = localStream.CopyToAsync(sslStream);
                        Task t2 = sslStream.CopyToAsync(localStream);
                        await Task.WhenAny(t1, t2).ConfigureAwait(false);
                    }
                }
            }
        } catch (Exception ex) {
            Console.WriteLine("[Proxy ERROR] Error in mTLS tunnel: " + ex.Message);
            if (ex.InnerException != null) {
                Console.WriteLine("[Proxy ERROR] Inner: " + ex.InnerException.Message);
            }
        }
    }

    public void Stop() {
        if (_isStopped) return;
        _isStopped = true;
        _cts.Cancel();
        if (_listener != null) {
            _listener.Stop();
        }
    }
}
"@
    Add-Type -TypeDefinition $csharpCode
}

function Start-ProxySession ($cn, $ttlSeconds) {
    # 1. Recupera il certificato ZTA (TPM o Fallback Software)
    $cert = Get-ZtaCertificateWithFallback $cn
    if (-not $cert) {
        throw "Certificato non trovato né in Windows Store né su disco per CN=$cn"
    }

    # 2. Cerca una porta locale libera a partire da 27019 (operatività allineata a macOS)
    $port = 27019
    while ($true) {
        $portInUse = $false
        foreach ($pair in $script:Sessions) {
            if ($pair.Value.Port -eq $port) {
                $portInUse = $true
                break
            }
        }
        if (-not $portInUse) {
            try {
                $testListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
                $testListener.Start()
                $testListener.Stop()
                break
            } catch {
                $portInUse = $true
            }
        }
        $port++
    }

    # 3. Istanzia e avvia la sessione proxy nativa C# in background
    $session = [ZtaProxySession]::new($cn, $port, $cert, $EnvoyHost, $EnvoyPort, $ENVOY_CERT_PATH, $ttlSeconds)
    $session.Start()

    $sessionToken = $session.SessionToken
    $script:Sessions.TryAdd($sessionToken, $session) | Out-Null

    # 4. Timer di scadenza automatica della sessione (TTL)
    $expiryTimer = [System.Threading.Timer]::new(
        [System.Threading.TimerCallback]{ param($state) Stop-ProxySession $state | Out-Null },
        $sessionToken,
        [TimeSpan]::FromSeconds($ttlSeconds),
        [System.Threading.Timeout]::InfiniteTimeSpan
    )

    Write-Host "[*] Proxy TCP (C# Async) avviato su localhost:$port per CN=$cn (Sessione: $sessionToken)" -ForegroundColor Green

    return @{
        port = $port
        session_token = $sessionToken
    }
}

function Stop-ProxySession ($sessionToken) {
    if ($script:Sessions.ContainsKey($sessionToken)) {
        $session = $script:Sessions[$sessionToken]
        $session.Stop()
        $script:Sessions.TryRemove($sessionToken, [ref]$null) | Out-Null
        Write-Host "[*] Proxy TCP su localhost:$($session.Port) arrestato correttamente." -ForegroundColor Yellow
        return $true
    }
    return $false
}
