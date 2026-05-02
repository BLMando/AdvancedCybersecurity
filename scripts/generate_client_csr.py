#!/usr/bin/env python3
import argparse
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

# Try to import required libraries
try:
    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
except ImportError:
    print("[!] Missing libraries. Install them with: pip install requests cryptography")
    sys.exit(1)

def enroll(args):
    print(f"\n{'='*70}")
    print(f" ZTA PROFESSIONAL HARDWARE ENROLLMENT: {args.cn.upper()}")
    print(f"{'='*70}\n")

    helper_path = Path(__file__).parent / "hw_attestation_helper"
    if not helper_path.exists():
        print(f"[!] Helper not found. Please compile it first.")
        return

    try:
        res = subprocess.run([str(helper_path), args.cn], capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[!] Hardware helper failed (exit {e.returncode}):")
        print(f"    {e.stderr or e.stdout}")
        print(f"\n[!] Suggestion: Try to run the helper manually to see if it prompts for Keychain access:")
        print(f"    {helper_path} {args.cn}")
        return
    except Exception as e:
        print(f"[!] Unexpected error during hardware access: {e}")
        return

    # Build the payload for the server
    print(f"[*] Fetching server challenge...")
    resp = requests.get(f"{args.server}/api/challenge")
    ch_id = resp.json()["challenge_id"]

    print(f"[*] Submitting Enrollment (Zero Trust Proof of Possession)...")
    
    # Preariamo la chiave pubblica in formato PEM per il server
    pub_raw = base64.b64decode(data["pub_key_b64"])
    from cryptography.hazmat.backends import default_backend
    public_key = serialization.load_der_public_key(pub_raw, backend=default_backend())
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Rilevamento automatico se non forniti
    mac = args.mac
    if not mac:
        import uuid
        mac_int = uuid.getnode()
        mac = ':'.join(('%012X' % mac_int)[i:i+2] for i in range(0, 12, 2))
    
    cpu = args.cpu
    if not cpu:
        import platform
        cpu = platform.processor() or platform.machine()

    payload = {
        "user": args.cn,
        "role": args.role,
        "department": args.department,
        "challenge_id": ch_id,
        "proof_string": data["csr_pem"], 
        "attestation_sig_b64": data["signature_b64"],
        "public_key_pem": pub_pem,
        "is_native_proof": True,
        "mac": mac,
        "cpu": cpu
    }

    try:
        r = requests.post(f"{args.server}/api/csr", json=payload)
        r.raise_for_status()
        print(f"\n[✓✓✓] ENROLLMENT SUCCESSFUL (HARDWARE-BOUND)!")
        print(f"[*] Identity verified with MAC: {mac} and CPU: {cpu}")
        
        cert_path = Path(args.output_dir) / f"{args.cn}.crt"
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(r.json()["certificate_pem"])
        print(f"Certificate saved to: {cert_path}")
    except Exception as e:
        print(f"Enrollment failed: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Server error: {e.response.text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True)
    parser.add_argument("--role", default="doctor")
    parser.add_argument("--department", default="Cardiologia")
    parser.add_argument("--server", default="http://localhost:8080")
    parser.add_argument("--output-dir", default="./certs/client")
    parser.add_argument("--mac", help="Manually specify MAC address")
    parser.add_argument("--cpu", help="Manually specify CPU model")
    enroll(parser.parse_args())
