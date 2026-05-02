import os
import uuid
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from dataclasses import dataclass

@dataclass
class AttestationChallenge:
    challenge_id: str
    nonce: bytes
    expires_at: datetime
    used: bool = False

class PKIService:
    def __init__(self, cert_dir="/data/certs"):
        self.cert_dir = cert_dir
        self.ca_key_path = os.path.join(cert_dir, "ca.key")
        self.ca_cert_path = os.path.join(cert_dir, "ca.crt")
        self.issued_dir = os.path.join(cert_dir, "issued")
        self.challenges = {}  # challenge_id -> AttestationChallenge
        
        os.makedirs(self.issued_dir, exist_ok=True)
        self._ensure_ca()

    def _ensure_ca(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            return

        print("[*] Generating New Root CA for Lab...")
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Milano"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Milano"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AdvancedCybersecurity-Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ZTA Root CA"),
        ])
        
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.ca_key, hashes.SHA256())

        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def create_challenge(self):
        challenge_id = str(uuid.uuid4())
        nonce = os.urandom(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        challenge = AttestationChallenge(
            challenge_id=challenge_id,
            nonce=nonce,
            expires_at=expires_at
        )
        self.challenges[challenge_id] = challenge
        return challenge_id, base64.b64encode(nonce).decode()

    def verify_hardware_signature(self, challenge_id, signature_b64, public_key_pem=None, proof_string=None):
        if challenge_id not in self.challenges:
            print(f"[!] Challenge {challenge_id} not found")
            return False
            
        challenge = self.challenges[challenge_id]
        if challenge.used or datetime.now(timezone.utc) > challenge.expires_at:
            print(f"[!] Challenge {challenge_id} invalid or expired")
            return False

        try:
            signature = base64.b64decode(signature_b64)
            
            # 1. Native Proof Verification (Swift approach)
            if proof_string and public_key_pem:
                try:
                    pub_key = serialization.load_pem_public_key(public_key_pem.encode())
                except ValueError:
                    # Fallback for PKCS#1 format (BEGIN RSA PUBLIC KEY)
                    pub_key = serialization.load_pem_rsa_public_key(public_key_pem.encode())
                pub_key.verify(
                    signature,
                    proof_string.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                # Extract CN for identity lookup
                user_cn = "unknown"
                parts = proof_string.split("|")
                for p in parts:
                    if p.startswith("CN="):
                        user_cn = p.split("=")[1].strip()

                # 4. Identity Recognition: Lookup certificate to get Role and Department
                role = "unknown"
                dept = "unknown"
                
                # Search in /data/certs/client/ or fallback to /data/certs/
                cert_path = os.path.join(self.cert_dir, "client", f"{user_cn}.crt")
                if not os.path.exists(cert_path):
                    cert_path = os.path.join(self.cert_dir, f"{user_cn}.crt")
                
                if os.path.exists(cert_path):
                    print(f"[*] Found certificate at {cert_path}, loading attributes...")
                    with open(cert_path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                        print(f"[*] Cert Subject: {cert.subject}")
                        
                        # Get Role from TITLE
                        titles = cert.subject.get_attributes_for_oid(NameOID.TITLE)
                        if titles:
                            role = titles[0].value
                            
                        # Get Department from OU (filtering out MAC/CPU)
                        ous = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
                        for ou in ous:
                            val = str(ou.value)
                            if not val.startswith(("MAC:", "CPU:")):
                                dept = val
                                break
                else:
                    print(f"[!] Certificate for {user_cn} NOT FOUND at {cert_path}")

                print(f"[✓] Hardware Proof verified for {user_cn} ({role} in {dept})")
                self.challenges[challenge_id].used = True
                return {
                    "user": user_cn,
                    "role": role,
                    "department": dept
                }

            # 2. Try CSR verification (certtool fallback)
            try:
                raw_sig = signature
                try:
                    csr = x509.load_pem_x509_csr(raw_sig)
                except:
                    csr = x509.load_der_x509_csr(raw_sig)
                
                if csr.is_signature_valid:
                    print("[✓] Hardware CSR verified")
                    self.challenges[challenge_id].used = True
                    return True
            except Exception:
                pass

            # 3. Raw RSA verification (Standard nonce)
            if public_key_pem:
                pub_key = serialization.load_pem_public_key(public_key_pem.encode())
                pub_key.verify(
                    signature,
                    challenge.nonce,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print("[✓] Raw signature verified")
                self.challenges[challenge_id].used = True
                return True
            
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

    def issue_hardware_bound_certificate(self, csr_pem=None, challenge_id=None, signature_b64=None, public_key_pem=None, is_hardware_csr=False, proof_string=None, user=None, **kwargs):
        """Issue a certificate bound to verified hardware."""
        
        # 1. Attestation
        if not self.verify_hardware_signature(challenge_id, signature_b64, public_key_pem, proof_string):
            raise ValueError("Hardware attestation failed: signature invalid")

        # 2. Get Public Key and Identity
        if is_hardware_csr:
            raw_csr = base64.b64decode(signature_b64)
            try:
                csr_obj = x509.load_pem_x509_csr(raw_csr)
            except:
                csr_obj = x509.load_der_x509_csr(raw_csr)
            pub_key = csr_obj.public_key()
            subject = csr_obj.subject
            clean_user = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        elif proof_string:
            # For native proof, we use the public_key_pem provided
            pub_key = serialization.load_pem_rsa_public_key(public_key_pem.encode()) if "BEGIN RSA" in public_key_pem else serialization.load_pem_public_key(public_key_pem.encode())
            clean_user = user or "unknown"
            
            # Costruiamo il Subject includendo tutti i metadati
            subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, clean_user)]
            
            if kwargs.get("role"):
                subject_attrs.append(x509.NameAttribute(NameOID.TITLE, kwargs["role"]))
            if kwargs.get("department"):
                subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, kwargs["department"]))
            if kwargs.get("mac"):
                subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"MAC:{kwargs['mac']}"))
            if kwargs.get("cpu"):
                subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"CPU:{kwargs['cpu']}"))
            
            subject = x509.Name(subject_attrs)
        else:
            csr_obj = x509.load_pem_x509_csr(csr_pem.encode())
            pub_key = csr_obj.public_key()
            subject = csr_obj.subject
            clean_user = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hw_fingerprint = hashlib.sha256(pub_bytes).hexdigest()
        device_uri = f"urn:device:mac-keychain:{hw_fingerprint}"

        # 3. Issue Cert
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            pub_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(device_uri)]),
            critical=False
        ).sign(self.ca_key, hashes.SHA256())

        # Salva copia locale per identity lookup (Zero Trust Registry)
        client_save_path = os.path.join(self.cert_dir, "client", f"{clean_user}.crt")
        os.makedirs(os.path.dirname(client_save_path), exist_ok=True)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(client_save_path, "wb") as f:
            f.write(cert_pem)
            
        return cert_pem.decode()
