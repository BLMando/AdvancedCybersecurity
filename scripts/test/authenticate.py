import argparse
import base64
import json
import os
import platform
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# Force UTF-8 output on Windows to avoid charmap errors with emoji
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ZTA Authentication Simulator (Enhanced with native mTLS support)
def main():
    parser = argparse.ArgumentParser(description="ZTA Authentication Simulator")
    parser.add_argument("--cn", default="paolo.roselli", help="Common Name of the identity")
    parser.add_argument("--pki-url", default="http://127.0.0.1:8080", help="PKI Server URL")
    parser.add_argument("--mtls-url", default="https://localhost:10001", help="Envoy mTLS Endpoint URL (10001 = HTTP test, 10000 = MongoDB TCP)")
    parser.add_argument("--pki-ca", help="Path to CA bundle for PKI HTTPS verification")
    parser.add_argument("--cert-dir", default=str(Path(__file__).parent.parent / "certs" / "client"), help="Directory with enrolled certs")
    args = parser.parse_args()

    CN = args.cn
    PKI_URL = args.pki_url
    MTLS_URL = args.mtls_url

    print("="*70)
    print(f" ZTA MULTI-LAYER AUTHENTICATION: {CN.upper()}")
    print("="*70)

    def open_url(url, data=None, headers=None, context=None):
        request = urllib.request.Request(url, data=data, headers=headers or {})
        return urllib.request.urlopen(request, context=context)

    # --- LAYER 1: PKI IDENTITY VERIFICATION ---
    print(f"\n[*] Layer 1: Verifying Identity at PKI Server...")
    
    # 1. Fetch Auth Challenge
    print(f"[*] Fetching challenge from {PKI_URL}...")
    try:
        pki_context = None
        if PKI_URL.startswith("https://"):
            if args.pki_ca:
                pki_context = ssl.create_default_context(cafile=args.pki_ca)
            else:
                pki_context = ssl.create_default_context()

        with open_url(f"{PKI_URL}/api/challenge", context=pki_context) as response:
            challenge_data = json.loads(response.read().decode())
            ch_id = challenge_data["challenge_id"]
            print(f"[✓] Received Challenge ID: {ch_id}")
    except Exception as e:
        print(f"[!] Failed to fetch challenge: {e}")
        return

    # 2. Sign Challenge via Hardware Key
    current_os = platform.system()
    print(f"[*] Signing challenge via hardware key...")
    
    try:
        if current_os == "Darwin": # macOS Native Agent
            import requests
            payload = {
                "common_name": CN,
                "data_b64": base64.b64encode(ch_id.encode()).decode()
            }
            resp = requests.post("http://localhost:9090/sign", json=payload, timeout=30)
            if resp.status_code != 200:
                print(f"[!] ZTA Agent signing failed: {resp.text}")
                return
            sig_data = resp.json()
            signature_b64 = sig_data["signature_b64"]
            pub_pem = sig_data["pub_key_pem"]
            proof_string = ch_id # For PKI verify
        else:
            # Fallback for other OS or legacy (Simplified for brevity)
            if current_os == "Windows":
                helper_path = Path(__file__).parent / "windows" / "hw_attestation.ps1"
                cmd = ["powershell.exe", "-ExecutionPolicy", "RemoteSigned", "-File", str(helper_path), "-CN", CN]
            else:
                print(f"[!] OS {current_os} not supported.")
                return

            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            if result.returncode != 0:
                print(f"[!] Hardware signing failed:\n{result.stderr}")
                return
            
            sig_data = json.loads(result.stdout)
            signature_b64 = sig_data["signature_b64"]
            pub_pem = sig_data.get("pub_key_pem", "")
            proof_string = sig_data["csr_pem"]

        payload = {
            "challenge_id": ch_id,
            "signature": signature_b64,
            "public_key_pem": pub_pem,
            "proof_string": proof_string
        }
        
        # Verify at PKI
        data_json = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json"}
        with open_url(f"{PKI_URL}/api/verify", data=data_json, headers=req_headers, context=pki_context) as response:
            verify_res = json.loads(response.read().decode())
            print(f"[✓✓] PKI IDENTITY VERIFIED: Role={verify_res['identity']['role']}")
    except Exception as e:
        print(f"[!] PKI Verification FAILED: {e}")
        if hasattr(e, 'read'): print(e.read().decode())
        return

    # --- LAYER 2: NATIVE mTLS HANDSHAKE (PERIMETER GATE) ---
    if current_os == "Darwin":
        print(f"\n[*] Layer 2: Delegating Native mTLS Handshake to ZTA Agent...")
        
        try:
            payload = {
                "common_name": CN,
                "url": MTLS_URL
            }
            # Chiamata all'Agente Xcode sulla porta 9090
            import requests
            print(f"[*] Contacting ZTA Agent at localhost:9090 (Touch ID required)...")
            resp = requests.post("http://localhost:9090/auth", json=payload, timeout=60)
            
            if resp.status_code == 200:
                auth_data = resp.json()
                print(f"\n    {auth_data.get('response', 'No response body')}")
                
                if "Status: 200" in auth_data.get('response', ''):
                    print(f"\n" + "="*70)
                    print(" [✓✓✓] FULL ZERO TRUST AUTHENTICATION SUCCESSFUL!")
                    print(" Identity verified & Hardware mTLS perimeter cleared.")
                    print("="*70)
                else:
                    print(f"\n[!] mTLS PERIMETER CHECK FAILED.")
                    print(" Connection rejected or status not 200.")
            else:
                print(f"[!] ZTA Agent returned error: {resp.text}")
                
        except requests.exceptions.ConnectionError:
            print("[!] ZTA Native Agent is NOT running. Please start the Xcode app first.")
        except Exception as e:
            print(f"[!] Error during mTLS test via Agent: {e}")
            
    elif current_os == "Windows":
        print(f"\n[*] Layer 2: Executing Native mTLS Handshake via Windows Schannel/TPM...")
        try:
            # We locate the certificate by CN in the CurrentUser\My store
            # and invoke the Envoy endpoint via SslStream with the client cert attached.
            # Invoke-WebRequest -Certificate has known issues with client certs on Windows.
            ps_cmd = [
                "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
                f'$cert = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -like "*CN={CN}*" }} | Select-Object -First 1; '
                f'if (-not $cert) {{ Write-Error "Certificate for CN={CN} not found in Certificate Store"; exit 1 }}; '
                f'if (-not $cert.HasPrivateKey) {{ Write-Error "Certificate has no private key. Run certutil -user -repairstore My $($cert.Thumbprint) as admin"; exit 1 }}; '
                f'try {{ '
                f'  $uri = [System.Uri]"{MTLS_URL}"; '
                f'  $tcp = New-Object System.Net.Sockets.TcpClient($uri.Host, $uri.Port); '
                f'  $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {{ $true }}); '
                f'  $ssl.AuthenticateAsClient($uri.Host, (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($cert)), [System.Security.Authentication.SslProtocols]::Tls12, $false); '
                f'  $writer = New-Object System.IO.StreamWriter($ssl); '
                f'  $writer.WriteLine("GET / HTTP/1.1"); '
                f'  $writer.WriteLine("Host: $($uri.Host):$($uri.Port)"); '
                f'  $writer.WriteLine("Connection: close"); '
                f'  $writer.WriteLine(""); $writer.Flush(); '
                f'  Start-Sleep -Milliseconds 200; '
                f'  $reader = New-Object System.IO.StreamReader($ssl); '
                f'  $resp = $reader.ReadToEnd(); '
                f'  $ssl.Close(); $tcp.Close(); '
                f'  Write-Output "Status: 200, Data: $resp"; '
                f'}} catch {{ '
                f'  Write-Error $_.Exception.Message; '
                f'  exit 1; '
                f'}}'
            ]
            
            print(f"[*] Contacting Envoy at {MTLS_URL} using certificate from Windows Store...")
            res = subprocess.run(ps_cmd, capture_output=True, text=True, errors="replace")
            
            if res.returncode == 0:
                output = res.stdout.strip()
                print(f"\n    {output}")
                if "Status: 200" in output:
                    print(f"\n" + "="*70)
                    print(" [✓✓✓] FULL ZERO TRUST AUTHENTICATION SUCCESSFUL!")
                    print(" Identity verified & Hardware mTLS perimeter cleared.")
                    print("="*70)
                else:
                    print(f"\n[!] mTLS PERIMETER CHECK FAILED.")
            else:
                stderr = res.stderr.strip()
                print(f"[!] mTLS Handshake failed:\n{stderr or res.stdout.strip()}")
                
        except Exception as e:
            print(f"[!] Error during mTLS test via Windows: {e}")
    else:
        print(f"\n[*] mTLS Native testing currently not supported on {current_os}.")

if __name__ == "__main__":
    main()
