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
    parser.add_argument("--mtls-url", default="https://localhost:10000", help="Envoy mTLS Endpoint URL")
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

    # 2. Sign Challenge via Hardware Helper
    current_os = platform.system()
    if current_os == "Darwin": # macOS
        helper_path = Path(__file__).parent / "macos" / "hw_attestation_helper"
        cmd = [str(helper_path), CN]
    elif current_os == "Windows":
        helper_path = Path(__file__).parent / "windows" / "hw_attestation.ps1"
        cmd = ["powershell.exe", "-ExecutionPolicy", "RemoteSigned", "-File", str(helper_path), "-CN", CN]
    else:
        print(f"[!] OS {current_os} not supported.")
        return

    print(f"[*] Signing challenge via hardware key...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            print(f"[!] Hardware signing failed:\n{result.stderr}")
            return
        
        sig_data = json.loads(result.stdout)

        # Reconstruct public key PEM from modulus/exponent (new PS1 output format)
        pub_pem = sig_data.get("pub_key_pem", "")
        if not pub_pem and "modulus_b64" in sig_data and "exponent_b64" in sig_data:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
            modulus  = int.from_bytes(base64.b64decode(sig_data["modulus_b64"]),  byteorder="big")
            exponent = int.from_bytes(base64.b64decode(sig_data["exponent_b64"]), byteorder="big")
            public_key = RSAPublicNumbers(exponent, modulus).public_key()
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

        payload = {
            "challenge_id": ch_id,
            "signature": sig_data["signature_b64"],
            "public_key_pem": pub_pem,
            "proof_string": sig_data["csr_pem"]
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
    else:
        print("\n[*] mTLS Native testing currently only supported on macOS.")

if __name__ == "__main__":
    main()
