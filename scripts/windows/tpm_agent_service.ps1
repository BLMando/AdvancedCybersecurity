# tpm_agent_service.ps1 - Windows TPM ZTA Agent Service
param (
    [int]$Port = 9090,
    [string]$EnvoyHost = "localhost",
    [int]$EnvoyPort = 10000
)

$scriptDir = Split-Path $PSCommandPath -Parent

# Load modules
. (Join-Path $scriptDir "tpm_config.ps1")
. (Join-Path $scriptDir "tpm_crypto.ps1")
. (Join-Path $scriptDir "tpm_proxy.ps1")
. (Join-Path $scriptDir "tpm_handlers.ps1")

# Start server
$http = [System.Net.HttpListener]::new()
$http.Prefixes.Add("http://+:$Port/")
try {
    $http.Start()
} catch {
    Write-Host "[WARN] Impossibile avviare il listener globale. Provo solo localhost..." -ForegroundColor Yellow
    $http.Close()
    $http = [System.Net.HttpListener]::new()
    $http.Prefixes.Add("http://localhost:$Port/")
    $http.Start()
}

Write-Host "="*70 -ForegroundColor Cyan
Write-Host " ZTA Windows TPM Agent Service Emulator attivo su http://localhost:$Port/" -ForegroundColor Cyan
Write-Host " Inoltro traffico a Envoy su ${EnvoyHost}:${EnvoyPort}" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan

try {
    while ($http.IsListening) {
        $ctx = $http.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response
        
        $res.Headers.Add("Access-Control-Allow-Origin", "*")
        if ($req.HttpMethod -eq "OPTIONS") {
            $res.StatusCode = 204
            $res.Headers.Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            $res.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
            $res.OutputStream.Close()
            continue
        }

        # Parse request body
        $reader = [System.IO.StreamReader]::new($req.InputStream, [System.Text.Encoding]::UTF8)
        $bodyText = $reader.ReadToEnd()
        $reader.Close()
        $body = if ($bodyText) { ConvertFrom-Json $bodyText } else { $null }
        $cn = if ($body) { if ($body.common_name) { $body.common_name } else { $body.user } } else { $null }

        $responseObj = $null
        $statusCode = 200

        try {
            switch ($req.Url.AbsolutePath) {
                "/cert"         { $responseObj = Handle-CertRequest $cn }
                "/enroll"       { $responseObj = Handle-EnrollRequest $cn $body }
                "/proxy/start"  { $responseObj = Handle-ProxyStartRequest $cn $body }
                "/proxy/stop"   { $responseObj = Handle-ProxyStopRequest $body }
                "/oidc/token"   { $responseObj = Handle-OidcTokenRequest $cn $body }
                "/sign"         { $responseObj = Handle-SignRequest $cn $body }
                "/auth"         { $responseObj = Handle-AuthRequest $cn }
                "/proxy/status" {
                    $active = @()
                    if ($script:Sessions.ContainsKey("default")) {
                        $s = $script:Sessions["default"]
                        $active += @{
                            common_name = $s.CN
                            port = $s.Port
                            expires_at = $s.ExpiresAt.ToString("o")
                        }
                    }
                    $responseObj = @{ status = "success"; sessions = $active }
                }
                default {
                    $statusCode = 404
                    $responseObj = @{ error = "Not Found" }
                }
            }
        } catch {
            $statusCode = 500
            $responseObj = @{ error = $_.ToString() }
            Write-Host "[API Error] $_" -ForegroundColor Red
        }

        # Send response
        $res.StatusCode = $statusCode
        $res.ContentType = "application/json"
        $json = ConvertTo-Json $responseObj -Compress
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
        $res.ContentLength64 = $buffer.Length
        $res.OutputStream.Write($buffer, 0, $buffer.Length)
        $res.OutputStream.Close()
    }
} catch {
    Write-Host "Server stopped: $_"
} finally {
    $http.Close()
}
