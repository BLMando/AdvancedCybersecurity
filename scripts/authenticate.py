import argparse
import urllib.request
import urllib.parse
import subprocess
import json
import base64
import os
import sys
import platform
from pathlib import Path

# ZTA Authentication Simulator (Enhanced with native mTLS support)
def main():
    parser = argparse.ArgumentParser(description="ZTA Authentication Simulator")
    parser.add_argument("--cn", default="paolo.roselli", help="Common Name of the identity")
    parser.add_argument("--pki-url", default="http://127.0.0.1:8080", help="PKI Server URL")
    parser.add_argument("--mtls-url", default="https://localhost:10000", help="Envoy mTLS Endpoint URL")
    args = parser.parse_args()

    CN = args.cn
    PKI_URL = args.pki_url
    MTLS_URL = args.mtls_url

    print("="*70)
    print(f" ZTA MULTI-LAYER AUTHENTICATION: {CN.upper()}")
    print("="*70)

    # --- LAYER 1: PKI IDENTITY VERIFICATION ---
    print(f"\n[*] Layer 1: Verifying Identity at PKI Server...")
    
    # 1. Fetch Auth Challenge
    print(f"[*] Fetching challenge from {PKI_URL}...")
    try:
        with urllib.request.urlopen(f"{PKI_URL}/api/challenge") as response:
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
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(helper_path), "-CN", CN]
    else:
        print(f"[!] OS {current_os} not supported.")
        return

    print(f"[*] Signing challenge via hardware key...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Hardware signing failed:\n{result.stderr}")
            return
        
        sig_data = json.loads(result.stdout)
        payload = {
            "challenge_id": ch_id,
            "signature": sig_data["signature_b64"],
            "public_key_pem": sig_data.get("pub_key_pem", ""),
            "proof_string": sig_data["csr_pem"]
        }
        
        # Verify at PKI
        data_json = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{PKI_URL}/api/verify", data=data_json, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            verify_res = json.loads(response.read().decode())
            print(f"[✓✓] PKI IDENTITY VERIFIED: Role={verify_res['identity']['role']}")
    except Exception as e:
        print(f"[!] PKI Verification FAILED: {e}")
        if hasattr(e, 'read'): print(e.read().decode())
        return

    # --- LAYER 2: NATIVE mTLS HANDSHAKE (PERIMETER GATE) ---
    if current_os == "Darwin":
        print(f"\n[*] Layer 2: Performing Native mTLS Handshake at {MTLS_URL}...")
        mtls_cmd = [str(helper_path), CN, "--test-url", MTLS_URL]
        
        try:
            # We run this and redirect its output to show it to the user
            print(f"[*] Invoking native security framework via helper...")
            mtls_proc = subprocess.run(mtls_cmd, capture_output=True, text=True)
            
            # Print the helper's internal logs (sent to stderr)
            if mtls_proc.stderr:
                for line in mtls_proc.stderr.splitlines():
                    if "[✓]" in line or "[*]" in line or "[!]" in line:
                        print(f"    {line}")
            
            if mtls_proc.returncode == 0 and "[✓] mTLS Handshake Successful!" in mtls_proc.stderr:
                print(f"\n" + "="*70)
                print(" [✓✓✓] FULL ZERO TRUST AUTHENTICATION SUCCESSFUL!")
                print(" Identity verified & Hardware mTLS perimeter cleared.")
                print("="*70)
            else:
                print(f"\n[!] mTLS PERIMETER CHECK FAILED.")
                print(" Connection rejected by Envoy Proxy.")
        except Exception as e:
            print(f"[!] Error during mTLS test: {e}")
    else:
        print("\n[*] mTLS Native testing currently only supported on macOS helper.")

if __name__ == "__main__":
    main()
