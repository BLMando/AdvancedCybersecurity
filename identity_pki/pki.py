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
        self.revoked_dir = os.path.join(cert_dir, "revoked")
        self.challenges = {}  # challenge_id -> AttestationChallenge
        
        os.makedirs(self.issued_dir, exist_ok=True)
        os.makedirs(self.revoked_dir, exist_ok=True)
        os.makedirs(os.path.join(self.cert_dir, "client"), exist_ok=True)
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

    def verify_proof(self, challenge_id, signature_b64, public_key_pem=None, proof_string=None):
        """Verify a hardware-bound proof of possession."""
        print(f"DEBUG: verify_proof called with ch_id={challenge_id}, has_sig={bool(signature_b64)}, has_pub={bool(public_key_pem)}, has_proof={bool(proof_string)}")
        
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
            if proof_string:
                # Extract CN for identity lookup
                user_cn = "unknown"
                parts = proof_string.split("|")
                for p in parts:
                    if p.startswith("CN="):
                        user_cn = p.split("=")[1].strip()

                print(f"DEBUG: Verifying proof for {user_cn}")
                
                # 0. Check for Revocation
                if os.path.exists(os.path.join(self.revoked_dir, f"{user_cn}.rev")):
                    print(f"[!] REJECTED: User {user_cn} has been REVOKED.")
                    return None

                # 1. Load Identity Context (Role, Dept, PubKey) from stored certificate
                role = "unknown"
                dept = "unknown"
                cert_pub_key = None
                
                cert_path = os.path.join(self.cert_dir, "client", f"{user_cn}.crt")
                if not os.path.exists(cert_path):
                    cert_path = os.path.join(self.cert_dir, f"{user_cn}.crt")
                
                if os.path.exists(cert_path):
                    print(f"[*] Found certificate at {cert_path}, loading attributes...")
                    with open(cert_path, "rb") as f:
                        cert_data = f.read()
                        cert = x509.load_pem_x509_certificate(cert_data)
                        cert_pub_key = cert.public_key()
                        
                        # Get Role and Dept from Subject
                        for attr in cert.subject:
                            if attr.oid == NameOID.TITLE:
                                role = attr.value
                            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                                val = str(attr.value)
                                if not val.startswith(("MAC:", "CPU:")):
                                    dept = val
                else:
                    print(f"[!] Certificate for {user_cn} NOT FOUND at {cert_path}")

                # 2. Resolve Public Key for verification
                pub_key = self._load_public_key(public_key_pem) if public_key_pem else None
                
                # Fallback to certificate public key if client didn't send one (hardware protection)
                if not pub_key and cert_pub_key:
                    print(f"[*] Using public key from stored certificate for {user_cn}")
                    pub_key = cert_pub_key

                if not pub_key:
                    print(f"[!] FAILED: No public key found for {user_cn}")
                    return None

                try:
                    pub_key.verify(
                        signature,
                        proof_string.encode(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    print(f"DEBUG: Signature verification SUCCESS for {user_cn}")
                except Exception as ve:
                    print(f"DEBUG: Signature verification FAILED: {ve}")
                    return None

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

    def _load_public_key(self, public_key_pem):
        """Helper to load public key with multiple fallbacks for compatibility."""
        try:
            if not public_key_pem:
                return None
            pub_key_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
            
            # Try generic loader
            try:
                return serialization.load_pem_public_key(pub_key_bytes)
            except Exception as e:
                # Fallback for RSA PKCS#1 (BEGIN RSA PUBLIC KEY)
                if "BEGIN RSA" in str(public_key_pem):
                    # If load_pem_rsa_public_key is missing, we try to load it by switching headers
                    # or just re-throwing. Some old versions of cryptography are very picky.
                    if hasattr(serialization, 'load_pem_rsa_public_key'):
                        return serialization.load_pem_rsa_public_key(pub_key_bytes)
                raise e
        except Exception as e:
            print(f"DEBUG: Failed to load public key: {e}")
            return None

    def issue_hardware_bound_certificate(self, csr_pem=None, challenge_id=None, signature_b64=None, public_key_pem=None, is_hardware_csr=False, proof_string=None, user=None, **kwargs):
        """Issue a certificate bound to verified hardware."""
        
        # 1. Attestation (This also loads role/dept if proof_string is provided)
        # We need to capture the results from verify_proof if possible, 
        # but for now we'll re-run the lookup logic for simplicity.
        if not self.verify_proof(challenge_id, signature_b64, public_key_pem, proof_string):
            raise ValueError("Hardware attestation failed: signature invalid")

        # 2. Get Public Key and Identity
        user_cn = user or "unknown"
        role = kwargs.get("role", "unknown")
        dept = kwargs.get("department", "unknown")
        cert_pub_key = None
        
        if proof_string:
            parts = proof_string.split("|")
            for p in parts:
                if p.startswith("CN="):
                    user_cn = p.split("=")[1].strip()

        # Try to find existing public key from cert on disk as fallback
        cert_path = os.path.join(self.cert_dir, "client", f"{user_cn}.crt")
        if not os.path.exists(cert_path):
            cert_path = os.path.join(self.cert_dir, f"{user_cn}.crt")
        
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                cert_pub_key = cert.public_key()
                # Use roles from cert if not provided
                for attr in cert.subject:
                    if attr.oid == NameOID.TITLE and role == "unknown":
                        role = attr.value
                    elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME and dept == "unknown":
                        val = str(attr.value)
                        if not val.startswith(("MAC:", "CPU:")):
                            dept = val

        pub_key = self._load_public_key(public_key_pem)
        if not pub_key:
            print(f"[*] Warning: Client public key invalid, falling back to stored key for {user_cn}")
            pub_key = cert_pub_key
            
        if not pub_key:
             raise ValueError("Could not load any public key for certificate issuance")

        clean_user = user_cn
        # Costruiamo il Subject includendo tutti i metadati
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, clean_user)]
        
        if role != "unknown":
            subject_attrs.append(x509.NameAttribute(NameOID.TITLE, role))
        if dept != "unknown":
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dept))
        
        # Add hardware tags
        if kwargs.get("mac"):
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"MAC:{kwargs['mac']}"))
        if kwargs.get("cpu"):
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"CPU:{kwargs['cpu']}"))
        
        subject = x509.Name(subject_attrs)
        # Case A: Native Hardware Proof (Preferred)
        if proof_string:
            # We already resolved pub_key and subject above
            pass
        # Case B: Standard Hardware CSR (Legacy/Fallback)
        elif is_hardware_csr and signature_b64:
            raw_csr = base64.b64decode(signature_b64)
            try:
                csr_obj = x509.load_pem_x509_csr(raw_csr)
            except:
                csr_obj = x509.load_der_x509_csr(raw_csr)
            pub_key = csr_obj.public_key()
            subject = csr_obj.subject
            clean_user = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # Case C: Standard CSR
        elif csr_pem:
            csr_obj = x509.load_pem_x509_csr(csr_pem.encode())
            pub_key = csr_obj.public_key()
            subject = csr_obj.subject
            clean_user = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        else:
            raise ValueError("No valid proof or CSR provided for certificate issuance")

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

    def list_certificates(self):
        """List all certificates in the registry."""
        certs = []
        client_dir = os.path.join(self.cert_dir, "client")
        if os.path.exists(client_dir):
            for filename in os.listdir(client_dir):
                if filename.endswith(".crt"):
                    user_cn = filename[:-4]
                    status = "revoked" if os.path.exists(os.path.join(self.revoked_dir, f"{user_cn}.rev")) else "active"
                    certs.append({"user": user_cn, "status": status})
        return certs

    def revoke_certificate(self, user_cn):
        """Mark a certificate as revoked."""
        revocation_file = os.path.join(self.revoked_dir, f"{user_cn}.rev")
        with open(revocation_file, "w") as f:
            f.write(f"Revoked at {datetime.now(timezone.utc)}")
        print(f"[!] Certificate for {user_cn} has been revoked.")
        return True
