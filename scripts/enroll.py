#!/usr/bin/env python3
import argparse
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

# Force UTF-8 output on Windows to avoid charmap errors with emoji
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Try to import required libraries
try:
    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
except ImportError:
    print("[!] Missing libraries. Install them with: pip install requests cryptography")
    sys.exit(1)

def fetch_valid_roles(server_url: str) -> list[str]:
    """Scarica la lista dei ruoli validi dal PKI server prima dell'enrollment."""
    try:
        resp = requests.get(f"{server_url}/api/roles", timeout=5)
        resp.raise_for_status()
        return resp.json()["valid_names"]
    except Exception as e:
        # Fallback offline: lista statica (aggiornata manualmente)
        print(f"[*] Impossibile connettersi al PKI server per validare i ruoli ({e}). Uso fallback offline.")
        return ["doctor", "billing_staff", "auditor", "receptionist", "admin"]

def enroll(args):
    print(f"\n{'='*70}")
    print(f" ZTA PROFESSIONAL HARDWARE ENROLLMENT: {args.cn.upper()}")
    print(f"{'='*70}\n")

    # Step 0: Valida il ruolo prima di procedere
    valid_roles = fetch_valid_roles(args.server)
    if args.role not in valid_roles:
        print(f"[✗] Ruolo '{args.role}' non riconosciuto dal PKI server.")
        print(f"[*] Ruoli disponibili: {', '.join(valid_roles)}")
        return

    print(f"[✓] Ruolo '{args.role}' validato.")

    import platform
    current_os = platform.system()
    
    if current_os == "Darwin": # macOS
        print(f"[*] Detecting macOS: Attempting to connect to ZTA Native Agent...")
        try:
            payload = {
                "common_name": args.cn,
                "role": args.role,
                "department": args.department
            }
            # Chiamata all'Agente Xcode
            resp = requests.post("http://localhost:9090/enroll", json=payload, timeout=60)
            if resp.status_code == 200:
                data = resp.json()
                print(f"\n[✓✓✓] NATIVE ENROLLMENT SUCCESSFUL!")
                print(f"[*] Message: {data.get('message')}")
                print(f"[*] Identity is now hardware-bound and secured in the SEP.")
                return # Enrollment completato dall'agente
            else:
                print(f"[!] Native Agent returned error: {resp.text}")
                print("[*] Falling back to CLI helper (legacy)...")
        except requests.exceptions.ConnectionError:
            print("[!] ZTA Native Agent is NOT running. Please start the Xcode app first.")
            print("[*] Falling back to CLI helper (legacy)...")
        
        # Fallback al vecchio helper se l'agente non è attivo
        helper_path = Path(__file__).parent / "macos" / "hw_attestation_helper"
        cmd = [str(helper_path), args.cn]
    elif current_os == "Windows":
        helper_path = Path(__file__).parent / "windows" / "hw_attestation.ps1"
        cmd = ["powershell.exe", "-ExecutionPolicy", "RemoteSigned", "-File", str(helper_path), "-CN", args.cn]
    else:
        print(f"[!] OS {current_os} not supported for hardware enrollment.")
        return

    if current_os == "Darwin" and not helper_path.exists():
        print(f"[!] Helper not found at {helper_path}. Please compile it first.")
        return

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True)
        data = json.loads(res.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[!] Hardware helper failed (exit {e.returncode}):")
        print(f"    {e.stderr or e.stdout}")
        return
    except Exception as e:
        print(f"[!] Unexpected error during hardware access: {e}")
        return

    # Build the payload for the server
    print(f"[*] Fetching server challenge...")
    verify_tls = args.server_ca if args.server_ca else True
    resp = requests.get(f"{args.server}/api/challenge", verify=verify_tls)
    ch_id = resp.json()["challenge_id"]

    print(f"[*] Submitting Enrollment (Zero Trust Proof of Possession)...")
    
    # Preariamo la chiave pubblica in formato PEM per il server
    pub_pem = data.get("pub_key_pem")
    if not pub_pem:
        if "modulus_b64" in data and "exponent_b64" in data:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            modulus = int.from_bytes(base64.b64decode(data["modulus_b64"]), byteorder="big")
            exponent = int.from_bytes(base64.b64decode(data["exponent_b64"]), byteorder="big")
            public_key = RSAPublicNumbers(exponent, modulus).public_key()
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        elif "pub_key_b64" in data:
            # Fallback se pub_key_pem manca, ma pub_key_b64 c'è
            pub_raw = base64.b64decode(data["pub_key_b64"])
            from cryptography.hazmat.backends import default_backend
            try:
                public_key = serialization.load_der_public_key(pub_raw, backend=default_backend())
                pub_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            except:
                 # Se tutto fallisce, usiamo un placeholder o lanciamo errore
                 print("[!] Errore: Impossibile caricare la chiave pubblica dall'hardware.")
                 return
        else:
            print("[!] Errore: Nessuna chiave pubblica restituita dall'hardware.")
            return

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
        r = requests.post(f"{args.server}/api/csr", json=payload, verify=verify_tls)
        r.raise_for_status()
        print(f"\n[✓✓✓] ENROLLMENT SUCCESSFUL (HARDWARE-BOUND)!")
        print(f"[*] Identity verified with MAC: {mac} and CPU: {cpu}")
        
        cert_file = Path(args.output_dir) / f"{args.cn}.crt"
        cert_file.parent.mkdir(parents=True, exist_ok=True)
        cert_pem = r.json()["certificate_pem"]
        cert_file.write_text(cert_pem)
        os.chmod(cert_file, 0o600)
        print(f"Certificate saved to: {cert_file}")

        # 4. Import Certificate into Keychain/Certificate Store
        if current_os == "Darwin":
            print("[*] Importing certificate into Keychain to create Identity...")
            try:
                # Use security command to import the certificate
                # We point it to the label of the private key so they link up
                import_cmd = ["security", "import", str(cert_file), "-t", "cert", "-r", "trustRoot", "-c", "ZTA-HW-" + args.cn]
                subprocess.run(import_cmd, capture_output=True)
                print("[✓] Certificate imported and linked to hardware key.")
            except Exception as e:
                print(f"[!] Warning: Keychain import failed: {e}")
        elif current_os == "Windows":
            print("[*] Importing certificate into Windows Certificate Store...")
            try:
                # Use PowerShell to import certificate to CurrentUser\My and repair the store link with the TPM CNG key
                abs_cert_path = cert_file.resolve()
                ps_cmd = [
                    "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command",
                    f'$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("{abs_cert_path}"); '
                    f'$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser"); '
                    f'$store.Open("ReadWrite"); '
                    f'$store.Add($cert); '
                    f'$store.Close(); '
                    f'$thumb = $cert.Thumbprint; '
                    f'certutil.exe -user -repairstore My $thumb'
                ]
                res = subprocess.run(ps_cmd, capture_output=True, text=True, errors="replace")
                if res.returncode == 0:
                    print("[✓] Certificate imported and linked to Windows TPM/KSP key store successfully.")
                elif "privilegi" in res.stderr or "elevated" in res.stderr.lower():
                    print("[!] Nota: per collegare il certificato alla chiave TPM servono privilegi di amministratore.")
                    print(f"[*] Esegui manualmente in una shell come Administrator:")
                    print(f"    certutil.exe -user -repairstore My {abs_cert_path}")
                else:
                    print(f"[!] Warning: Windows Certificate Store repair failed:\n{res.stderr or res.stdout}")
            except Exception as e:
                print(f"[!] Warning: Windows Certificate Store import failed: {e}")

    except requests.exceptions.HTTPError as e:
        print(f"Enrollment failed (HTTP {e.response.status_code}): {e.response.text}")
    except requests.exceptions.ConnectionError:
        print("[!] Could not connect to the identity server. Is it running?")
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
    parser.add_argument("--server-ca", help="Path to CA bundle for HTTPS verification")
    parser.add_argument("--output-dir", default=str(Path(__file__).parent.parent / "certs" / "client"))
    parser.add_argument("--mac", help="Manually specify MAC address")
    parser.add_argument("--cpu", help="Manually specify CPU model")
    enroll(parser.parse_args())
