# tpm_agent_service.ps1 - Windows TPM ZTA Agent API Service Emulator
#
# Emula l'API HTTP del ZTAAgent macOS sulla porta 9090 su Windows.
# Gestisce l'enrollment, le firme TPM e il proxy mTLS MongoDB tramite Schannel.
#
# Avvio:
#   powershell -ExecutionPolicy Bypass -File .\scripts\windows\tpm_agent_service.ps1
#

param (
    [int]$Port = 9090,
    [string]$EnvoyHost = "localhost",
    [int]$EnvoyPort = 10000
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
    Add-Type -TypeDefinition '
        using System;
        using System.Net;
        using System.Security.Cryptography;
        using System.Security.Cryptography.X509Certificates;
        using System.Text;
        using System.Collections;

        public class SSLBypass {
            public static void Bypass() {
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            }
        }

        public class RSASoftKeyHelper {
            private static byte[] EncodeInteger(byte[] bytes) {
                int left = 0;
                while (left < bytes.Length && bytes[left] == 0) left++;
                int len = bytes.Length - left;
                if (len == 0) return new byte[] { 0x02, 0x01, 0x00 };
                
                bool pad = (bytes[left] & 0x80) != 0;
                int datalen = len + (pad ? 1 : 0);
                
                byte[] lenBytes;
                if (datalen < 128) {
                    lenBytes = new byte[] { (byte)datalen };
                } else if (datalen <= 255) {
                    lenBytes = new byte[] { 0x81, (byte)datalen };
                } else {
                    lenBytes = new byte[] { 0x82, (byte)(datalen >> 8), (byte)(datalen & 0xff) };
                }
                
                byte[] res = new byte[1 + lenBytes.Length + datalen];
                res[0] = 0x02;
                Buffer.BlockCopy(lenBytes, 0, res, 1, lenBytes.Length);
                int writePos = 1 + lenBytes.Length;
                if (pad) {
                    res[writePos] = 0x00;
                    writePos++;
                }
                Buffer.BlockCopy(bytes, left, res, writePos, len);
                return res;
            }

            private static byte[] EncodeSequence(byte[] d1, byte[] d2, byte[] d3, byte[] d4, byte[] d5, byte[] d6, byte[] d7, byte[] d8, byte[] d9) {
                int totalLen = d1.Length + d2.Length + d3.Length + d4.Length + d5.Length + d6.Length + d7.Length + d8.Length + d9.Length;
                byte[] lenBytes;
                if (totalLen < 128) {
                    lenBytes = new byte[] { (byte)totalLen };
                } else if (totalLen <= 255) {
                    lenBytes = new byte[] { 0x81, (byte)totalLen };
                } else {
                    lenBytes = new byte[] { 0x82, (byte)(totalLen >> 8), (byte)(totalLen & 0xff) };
                }
                
                byte[] res = new byte[1 + lenBytes.Length + totalLen];
                res[0] = 0x30;
                Buffer.BlockCopy(lenBytes, 0, res, 1, lenBytes.Length);
                int writePos = 1 + lenBytes.Length;
                
                byte[][] parts = new byte[][] { d1, d2, d3, d4, d5, d6, d7, d8, d9 };
                foreach (var p in parts) {
                    Buffer.BlockCopy(p, 0, res, writePos, p.Length);
                    writePos += p.Length;
                }
                return res;
            }

            public static Hashtable GenerateSoftwareKeyPair(string cn, string timestamp) {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048)) {
                    RSAParameters p = rsa.ExportParameters(true);
                    
                    byte[] d1 = EncodeInteger(new byte[] { 0x00 });
                    byte[] d2 = EncodeInteger(p.Modulus);
                    byte[] d3 = EncodeInteger(p.Exponent);
                    byte[] d4 = EncodeInteger(p.D);
                    byte[] d5 = EncodeInteger(p.P);
                    byte[] d6 = EncodeInteger(p.Q);
                    byte[] d7 = EncodeInteger(p.DP);
                    byte[] d8 = EncodeInteger(p.DQ);
                    byte[] d9 = EncodeInteger(p.InverseQ);
                    
                    byte[] der = EncodeSequence(d1, d2, d3, d4, d5, d6, d7, d8, d9);
                    string privB64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
                    string privPem = "-----BEGIN RSA PRIVATE KEY-----\r\n" + privB64 + "\r\n-----END RSA PRIVATE KEY-----";

                    string proofString = "ZTA-CERT-BINDING|CN=" + cn + "|TIME=" + timestamp;
                    byte[] dataToSign = Encoding.UTF8.GetBytes(proofString);
                    byte[] signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    string sigB64 = Convert.ToBase64String(signature);

                    Hashtable result = new Hashtable();
                    result["private_key_pem"] = privPem;
                    result["modulus_b64"] = Convert.ToBase64String(p.Modulus);
                    result["exponent_b64"] = Convert.ToBase64String(p.Exponent);
                    result["proof_string"] = proofString;
                    result["signature_b64"] = sigB64;
                    return result;
                }
            }

            private static byte[] EncodeLength(int length) {
                if (length < 128) {
                    return new byte[] { (byte)length };
                } else if (length <= 255) {
                    return new byte[] { 0x81, (byte)length };
                } else {
                    return new byte[] { 0x82, (byte)(length >> 8), (byte)(length & 0xff) };
                }
            }

            public static string ExportSpkiPublicKeyPem(byte[] modulus, byte[] exponent) {
                byte[] modDer = EncodeInteger(modulus);
                byte[] expDer = EncodeInteger(exponent);
                
                int rsaPubKeyLen = modDer.Length + expDer.Length;
                byte[] rsaPubKeyLenBytes = EncodeLength(rsaPubKeyLen);
                byte[] rsaPubKeyDer = new byte[1 + rsaPubKeyLenBytes.Length + rsaPubKeyLen];
                rsaPubKeyDer[0] = 0x30;
                Buffer.BlockCopy(rsaPubKeyLenBytes, 0, rsaPubKeyDer, 1, rsaPubKeyLenBytes.Length);
                Buffer.BlockCopy(modDer, 0, rsaPubKeyDer, 1 + rsaPubKeyLenBytes.Length, modDer.Length);
                Buffer.BlockCopy(expDer, 0, rsaPubKeyDer, 1 + rsaPubKeyLenBytes.Length + modDer.Length, expDer.Length);
                
                int bitStringValLen = 1 + rsaPubKeyDer.Length;
                byte[] bitStringLenBytes = EncodeLength(bitStringValLen);
                byte[] bitStringDer = new byte[1 + bitStringLenBytes.Length + bitStringValLen];
                bitStringDer[0] = 0x03;
                Buffer.BlockCopy(bitStringLenBytes, 0, bitStringDer, 1, bitStringLenBytes.Length);
                bitStringDer[1 + bitStringLenBytes.Length] = 0x00;
                Buffer.BlockCopy(rsaPubKeyDer, 0, bitStringDer, 2 + bitStringLenBytes.Length, rsaPubKeyDer.Length);
                
                byte[] algIdDer = new byte[] { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
                
                int spkiLen = algIdDer.Length + bitStringDer.Length;
                byte[] spkiLenBytes = EncodeLength(spkiLen);
                byte[] spkiDer = new byte[1 + spkiLenBytes.Length + spkiLen];
                spkiDer[0] = 0x30;
                Buffer.BlockCopy(spkiLenBytes, 0, spkiDer, 1, spkiLenBytes.Length);
                Buffer.BlockCopy(algIdDer, 0, spkiDer, 1 + spkiLenBytes.Length, algIdDer.Length);
                Buffer.BlockCopy(bitStringDer, 0, spkiDer, 1 + spkiLenBytes.Length + algIdDer.Length, bitStringDer.Length);
                
                string b64 = Convert.ToBase64String(spkiDer, Base64FormattingOptions.InsertLineBreaks);
                return "-----BEGIN PUBLIC KEY-----\r\n" + b64 + "\r\n-----END PUBLIC KEY-----";
            }
        }
    '
    [SSLBypass]::Bypass()
} catch {
    [SSLBypass]::Bypass()
}


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

# Helper per esportare una chiave pubblica RSA in formato SubjectPublicKeyInfo (SPKI) PEM su .NET Framework
function Export-SpkiPublicKeyPem ($modulus, $exponent) {
    return [RSASoftKeyHelper]::ExportSpkiPublicKeyPem($modulus, $exponent)
}

# Helper per estrarre la chiave pubblica PEM dal certificato
function Get-PublicKeyPem ($cert) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    if ($rsa) {
        $params = $rsa.ExportParameters($false)
        return [RSASoftKeyHelper]::ExportSpkiPublicKeyPem($params.Modulus, $params.Exponent)
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

# Helper per recuperare il certificato preferendo quello con la chiave privata associata
function Get-ZtaCertificate ($cn) {
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" -and $_.HasPrivateKey } | Select-Object -First 1
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CN=$cn*" } | Select-Object -First 1
    }
    return $cert
}

# Helper che esegue la ricerca del certificato con fallback su file
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

# Avvia il Listener TCP Proxy mTLS locale per una sessione
function Start-ProxySession ($cn, $ttlSeconds) {
    # 1. Trova il certificato nel Windows Store o su disco
    $cert = Get-ZtaCertificateWithFallback $cn
    if (-not $cert) {
        throw "Certificato non trovato né in Windows Store né su disco per CN=$cn"
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
        param($cn, $sessionToken, $adKey, $envoyHost, $envoyPort, $certObj, $envoyCertPath)
        
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
    $boundAll = $false
    try {
        # Ascolta su tutte le interfacce per poter ricevere chiamate dai container Docker via host.docker.internal
        # Nota: in Windows HttpListener richiede privilegi amministrativi per associarsi a '+' o '*'
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
            
            # Gestione CORS OPTIONS preflight a livello globale
            if ($req.HttpMethod -eq "OPTIONS") {
                try {
                    $res.StatusCode = 204
                    $res.Headers.Add("Access-Control-Allow-Origin", "*")
                    $res.Headers.Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                    $res.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
                    $res.ContentLength64 = 0
                } catch {}
                finally {
                    try { $res.OutputStream.Close() } catch {}
                }
                continue
            }
            
            # Leggi corpo della richiesta
            $reader = [System.IO.StreamReader]::new($req.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            $responseObj = $null
            $statusCode = 200
            
            try {
                $jsonBody = if ($body) { ConvertFrom-Json $body } else { $null }
                $cn = $null
                if ($jsonBody) {
                    $cn = if ($jsonBody.common_name) { $jsonBody.common_name } else { $jsonBody.user }
                }
                
                if ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/cert") {
                    Write-Host "[API] Ricevuto /cert per CN=$cn" -ForegroundColor Gray
                    $cert = Get-ZtaCertificateWithFallback $cn
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
                    $role = $jsonBody.role
                    if (-not $role) { $role = "doctor" }
                    $dept = $jsonBody.department
                    if (-not $dept) { $dept = "Cardiologia" }
                    $sessionToken = $jsonBody.enrollment_session_token
                    Write-Host "[API] Ricevuto /enroll per CN=$cn, Ruolo=$role, Reparto=$dept, Token=(redacted)" -ForegroundColor Gray
                    
                    # Inizializza mac e cpu per l'utilizzo anche nel blocco catch di fallback
                    $mac = ""
                    try {
                        $mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress
                    } catch {}
                    if (-not $mac) { $mac = "00:11:22:33:44:55" }
                    
                    $cpu = "Windows-PC"
                    try {
                        $cpu = (Get-CimInstance Win32_Processor).Name.Trim()
                    } catch {}

                    try {
                        # 1. Recupera challenge dal server PKI
                        $challengeUrl = "https://localhost:8080/api/challenge"
                        $challengeResp = Invoke-RestMethod -Uri $challengeUrl -Method Get -TimeoutSec 10
                        $challengeId = $challengeResp.challenge_id
                        
                        # 2. Genera chiave nel TPM ed esegui la firma di attestazione
                        $hwScript = Join-Path (Split-Path $PSCommandPath -Parent) "hw_attestation.ps1"
                        $hwRes = & $hwScript -CN $cn
                        $hwData = ConvertFrom-Json $hwRes
                        
                        # Costruisci PEM della chiave pubblica (usa la funzione custom compatibile con .NET Framework)
                        $modRaw = [Convert]::FromBase64String($hwData.modulus_b64)
                        $expRaw = [Convert]::FromBase64String($hwData.exponent_b64)
                        $pubKeyPem = Export-SpkiPublicKeyPem $modRaw $expRaw
                        
                        # 3. Richiedi firma del certificato al server PKI
                        $enrollUrl = "https://localhost:8080/api/csr"
                        $enrollPayload = @{
                            user = $cn
                            role = $role
                            department = $dept
                            challenge_id = $challengeId
                            proof_string = $hwData.csr_pem
                            attestation_sig_b64 = $hwData.signature_b64
                            public_key_pem = $pubKeyPem
                            is_hardware_csr = $false
                            mac = $mac
                            cpu = $cpu
                            enrollment_session_token = $sessionToken
                        }
                        
                        $enrollResp = Invoke-RestMethod -Uri $enrollUrl -Method Post -ContentType "application/json" -Body (ConvertTo-Json $enrollPayload -Compress) -TimeoutSec 30
                        $certPem = $enrollResp.certificate_pem
                        
                        # 4. Importa certificato nel Windows Certificate Store
                        $certBytes = [System.Text.Encoding]::UTF8.GetBytes($certPem)
                        $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $certObj.Import($certBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                        
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
                        $store.Open("ReadWrite")
                        $store.Add($certObj)
                        $store.Close()
                        
                        # Associa la chiave privata tramite certutil -repairstore (usando -silent e con un timeout per evitare blocchi infiniti)
                        $thumb = $certObj.Thumbprint
                        Write-Host "[API] Associazione chiave privata con certutil (non bloccante)..." -ForegroundColor Gray
                        $job = Start-Job -ScriptBlock {
                            param($t)
                            & certutil.exe -silent -user -repairstore My $t | Out-Null
                        } -ArgumentList $thumb
                        $completed = $job | Wait-Job -Timeout 10
                        if ($null -eq $completed) {
                            Write-Host "[API WARN] certutil repairstore ha richiesto troppo tempo (timeout 10s) ed e' stato interrotto." -ForegroundColor Yellow
                        }
                        $job | Remove-Job -Force
                        
                        # Scrivi copia del cert nella cartella condivisa client/
                        $certOutPath = Join-Path $CERT_DIR "$cn.crt"
                        [System.IO.File]::WriteAllText($certOutPath, $certPem)
                        
                        $responseObj = @{
                            status = "success"
                            message = "Enrollment completato!"
                        }
                        Write-Host "[API] /enroll completato con successo per CN=$cn" -ForegroundColor Green
                    } catch {
                        Write-Host "[API] Enrollment TPM/Store fallito per CN=$cn : $_. Provo fallback software file-based..." -ForegroundColor Yellow
                        try {
                            $timestamp = (Get-Date -uformat "%Y-%m-%dT%H:%M:%SZ")
                            $softKeyData = [RSASoftKeyHelper]::GenerateSoftwareKeyPair($cn, $timestamp)
                            
                            $modRaw = [Convert]::FromBase64String($softKeyData.modulus_b64)
                            $expRaw = [Convert]::FromBase64String($softKeyData.exponent_b64)
                            $pubKeyPem = Export-SpkiPublicKeyPem $modRaw $expRaw
                            
                            $challengeUrl = "https://localhost:8080/api/challenge"
                            $challengeResp = Invoke-RestMethod -Uri $challengeUrl -Method Get -TimeoutSec 10
                            $challengeId = $challengeResp.challenge_id
                            
                            $enrollUrl = "https://localhost:8080/api/csr"
                            $enrollPayload = @{
                                user = $cn
                                role = $role
                                department = $dept
                                challenge_id = $challengeId
                                proof_string = $softKeyData.proof_string
                                attestation_sig_b64 = $softKeyData.signature_b64
                                public_key_pem = $pubKeyPem
                                is_hardware_csr = $false
                                mac = $mac
                                cpu = $cpu
                                enrollment_session_token = $sessionToken
                            }
                            
                            $enrollResp = Invoke-RestMethod -Uri $enrollUrl -Method Post -ContentType "application/json" -Body (ConvertTo-Json $enrollPayload -Compress) -TimeoutSec 30
                            $certPem = $enrollResp.certificate_pem
                            
                            # Scrivi copia del cert e della chiave nella cartella dei certificati client
                            $certOutPath = Join-Path $CERT_DIR "$cn.crt"
                            $keyOutPath = Join-Path $CERT_DIR "$cn.key"
                            [System.IO.File]::WriteAllText($certOutPath, $certPem)
                            [System.IO.File]::WriteAllText($keyOutPath, $softKeyData.private_key_pem)
                            
                            $responseObj = @{
                                status = "success"
                                message = "Enrollment completato (Fallback Software File-based)!"
                            }
                            Write-Host "[API] /enroll software fallback completato per CN=$cn" -ForegroundColor Green
                        } catch {
                            $statusCode = 500
                            $responseObj = @{ status = "error"; message = "TPM enrollment e software fallback falliti entrambi: $($_.Exception.Message)" }
                            Write-Host "[API] /enroll fallback software fallito per CN=$cn : $_" -ForegroundColor Red
                        }
                    }
                }
                elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/proxy/start") {
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
                elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/oidc/token") {
                    $tokenCN = if ($cn) { $cn } else { "paolo.roselli" }
                    $stepUp = $jsonBody.step_up -eq "true" -or $jsonBody.step_up -eq $true
                    Write-Host "[API] Ricevuto /oidc/token per CN=$tokenCN, StepUp=$stepUp" -ForegroundColor Gray
                    
                    try {
                        # 1. Recupera challenge dal server PKI
                        $challengeUrl = "https://localhost:8080/api/challenge"
                        $challengeResp = Invoke-RestMethod -Uri $challengeUrl -Method Get -TimeoutSec 10
                        $challengeId = $challengeResp.challenge_id
                        
                        # 2. Trova il certificato nel Windows Store (con fallback su file)
                        $cert = Get-ZtaCertificateWithFallback $tokenCN
                        if (-not $cert) {
                            throw "Certificato non trovato in Windows Store né su disco per CN=$tokenCN"
                        }
                        
                        # 3. Costruisci il proof_string e firmalo con la chiave TPM/Software
                        $timestamp = (Get-Date -uformat "%Y-%m-%dT%H:%M:%SZ")
                        $proofString = "ZTA-CERT-BINDING|CN=$tokenCN|TIME=$timestamp"
                        $proofBytes = [System.Text.Encoding]::UTF8.GetBytes($proofString)
                        
                        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                        if (-not $rsa) {
                            throw "Impossibile recuperare la chiave privata per CN=$tokenCN"
                        }
                        $sigBytes = $rsa.SignData($proofBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                        $sigB64 = [Convert]::ToBase64String($sigBytes)
                        
                        # 4. Ottieni la chiave pubblica PEM
                        $pubKeyPem = Get-PublicKeyPem $cert
                        
                        # 5. Invia al server PKI per ottenere il JWT
                        $oidcUrl = "https://localhost:8080/api/oidc/token"
                        $oidcPayload = @{
                            challenge_id = $challengeId
                            signature = $sigB64
                            public_key_pem = $pubKeyPem
                            proof_string = $proofString
                            step_up = $stepUp
                        }
                        
                        $oidcResp = Invoke-RestMethod -Uri $oidcUrl -Method Post -ContentType "application/json" -Body (ConvertTo-Json $oidcPayload -Compress) -TimeoutSec 15
                        
                        $responseObj = @{
                            status = "success"
                            token = $oidcResp.access_token
                            access_token = $oidcResp.access_token
                        }
                        Write-Host "[API] /oidc/token completato con successo per CN=$tokenCN" -ForegroundColor Green
                    } catch {
                        $statusCode = 500
                        $responseObj = @{ status = "error"; message = $_.Exception.Message }
                        if ($_.Exception -and $_.Exception.Response) {
                            try {
                                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                                $responseBody = $reader.ReadToEnd()
                                $reader.Close()
                                $statusCode = [int]$_.Exception.Response.StatusCode
                                # ConvertFrom-Json may return $null on empty body — keep the default $responseObj in that case
                                $parsed = ConvertFrom-Json $responseBody
                                if ($parsed -ne $null) { $responseObj = $parsed }
                            } catch {
                                # Fallback: keep the default $responseObj set above
                            }
                        }
                        Write-Host "[API] /oidc/token fallito per CN=$tokenCN : $_" -ForegroundColor Red
                    }
                }
                elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/sign") {
                    $dataB64 = $jsonBody.data_b64
                    Write-Host "[API] Ricevuto /sign per CN=$cn" -ForegroundColor Gray
                    
                    $cert = Get-ZtaCertificateWithFallback $cn
                    
                    if ($cert) {
                        try {
                            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                            if (-not $rsa) {
                                throw "Impossibile recuperare la chiave privata per la firma per CN=$cn"
                            }
                            $dataBytes = [Convert]::FromBase64String($dataB64)
                            
                            # Esegue la firma crittografica
                            $sigBytes = $rsa.SignData($dataBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                            $sigB64 = [Convert]::ToBase64String($sigBytes)
                            
                            $responseObj = @{
                                signature_b64 = $sigB64
                                pub_key_pem = Get-PublicKeyPem $cert
                            }
                        } catch {
                            $statusCode = 500
                            $responseObj = @{ error = $_.Exception.Message }
                        }
                    } else {
                        $statusCode = 404
                        $responseObj = @{ error = "Certificato per la firma non trovato" }
                    }
                }
                elseif ($req.HttpMethod -eq "POST" -and $req.Url.AbsolutePath -eq "/auth") {
                    Write-Host "[API] Ricevuto /auth per CN=$cn" -ForegroundColor Gray
                    
                    try {
                        # Trova il certificato nel Windows Store o su disco
                        $cert = Get-ZtaCertificateWithFallback $cn
                        if (-not $cert) {
                            throw "Certificato non trovato per CN=$cn"
                        }
                        
                        # Esegui handshake mTLS verso Envoy per verificare il funzionamento (porta 10001)
                        $uri = [System.Uri]"https://localhost:10001/api/resource"
                        $tcp = [System.Net.Sockets.TcpClient]::new($uri.Host, $uri.Port)
                        # Ignora la convalida del certificato server per Envoy in dev
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
                        
                        # Estrai la prima riga dello status HTTP
                        $statusLine = ($resp -split "`r`n")[0]
                        $responseObj = @{
                            status = "success"
                            response = "Status: 200, Data: $statusLine"
                        }
                        Write-Host "[API] /auth completato con successo per CN=$cn" -ForegroundColor Green
                    } catch {
                        $statusCode = 500
                        $responseObj = @{ status = "error"; message = $_.Exception.Message }
                        Write-Host "[API] /auth fallito per CN=$cn : $_" -ForegroundColor Red
                    }
                }
                elseif ($req.HttpMethod -eq "GET" -and $req.Url.AbsolutePath -eq "/proxy/status") {
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
                    $responseObj = @{
                        status = "success"
                        sessions = $active
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
            try {
                $res.StatusCode = $statusCode
                $res.ContentType = "application/json"
                if (-not $res.Headers["Access-Control-Allow-Origin"]) {
                    $res.Headers.Add("Access-Control-Allow-Origin", "*")
                }
                
                $responseBody = ConvertTo-Json $responseObj -Depth 5 -Compress
                # Guard: ConvertTo-Json returns $null when $responseObj is $null
                if ($null -eq $responseBody) { $responseBody = '{"error":"internal: null response object"}' }
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
                $res.ContentLength64 = $buffer.Length
                $res.OutputStream.Write($buffer, 0, $buffer.Length)
            } catch {
                Write-Host "[API ERROR] Errore durante la scrittura della risposta: $_" -ForegroundColor Red
            } finally {
                try { $res.Close() } catch {}
            }
        }
    } catch {
        # Server arrestato
    } finally {
        $http.Close()
    }
}

# Avvia l'event loop del server HTTP
Start-HttpServer
