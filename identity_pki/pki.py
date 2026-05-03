import base64
import hashlib
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)

@dataclass
class AttestationChallenge:
    challenge_id: str
    nonce: bytes
    expires_at: datetime
    used: bool = False


@dataclass(frozen=True)
class CARecord:
    created: datetime


@dataclass(frozen=True)
class CertificatePaths:
    certificate: Path
    private_key: Optional[Path] = None
    metadata: Optional[Path] = None


@dataclass(frozen=True)
class CertificateBundle:
    paths: CertificatePaths
    serial_number: int
    expires_at: datetime

class PKIService:
    def __init__(self, cert_dir: str = "/data/certs", data_dir: Optional[Path] = None):
        if data_dir is not None:
            cert_dir = str(data_dir)

        self.cert_dir = cert_dir
        self.cert_dir_path = Path(cert_dir)
        self.ca_key_path = self.cert_dir_path / "ca.key"
        self.ca_cert_path = self.cert_dir_path / "ca.crt"
        self.issued_dir = self.cert_dir_path / "issued"
        self.revoked_dir = self.cert_dir_path / "revoked"
        self.client_dir = self.cert_dir_path / "client"
        self.challenges = {}  # challenge_id -> AttestationChallenge

        self.ca_validity_days = int(os.environ.get("ZTA_CA_VALIDITY_DAYS", "3650"))
        self.cert_validity_days = int(os.environ.get("ZTA_CERT_VALIDITY_DAYS", "365"))
        self.challenge_ttl_minutes = int(os.environ.get("ZTA_CHALLENGE_TTL_MINUTES", "5"))

        self.issued_dir.mkdir(parents=True, exist_ok=True)
        self.revoked_dir.mkdir(parents=True, exist_ok=True)
        self.client_dir.mkdir(parents=True, exist_ok=True)

        self._ca_record: Optional[CARecord] = None
        self._ensure_ca()

    @property
    def ca_common_name(self) -> str:
        cn_values = self.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cn_values[0].value if cn_values else "Unknown"

    def _ensure_ca(self) -> None:
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            self.ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(),
                password=self._get_ca_password(),
            )
            self.ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            self._ca_record = CARecord(created=self.ca_cert.not_valid_before_utc)
            return

        logger.info("Generating new root CA for lab environment")
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Milano"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Milano"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AdvancedCybersecurity-Lab"),
                x509.NameAttribute(NameOID.COMMON_NAME, "ZTA Root CA"),
            ]
        )

        now = datetime.now(timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=self.ca_validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )

        encryption_algorithm = self._get_ca_encryption()
        self.ca_key_path.write_bytes(
            self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm,
            )
        )
        os.chmod(self.ca_key_path, 0o600)
        self.ca_cert_path.write_bytes(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        self._ca_record = CARecord(created=now)

    def _get_ca_password(self) -> Optional[bytes]:
        password = os.environ.get("ZTA_CA_KEY_PASSWORD")
        return password.encode("utf-8") if password else None

    def _get_ca_encryption(self) -> serialization.KeySerializationEncryption:
        password = self._get_ca_password()
        if password:
            return serialization.BestAvailableEncryption(password)
        logger.warning("CA private key is stored without encryption")
        return serialization.NoEncryption()

    def ca_summary(self) -> dict:
        fingerprint = hashlib.sha256(self.ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        return {
            "subject": self.ca_cert.subject.rfc4514_string(),
            "fingerprint_sha256": fingerprint,
            "created": self._ca_record.created if self._ca_record else None,
        }

    def create_challenge(self):
        challenge_id = str(uuid.uuid4())
        nonce = os.urandom(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.challenge_ttl_minutes)
        
        challenge = AttestationChallenge(
            challenge_id=challenge_id,
            nonce=nonce,
            expires_at=expires_at
        )
        self.challenges[challenge_id] = challenge
        return challenge_id, base64.b64encode(nonce).decode()

    def verify_proof(self, challenge_id, signature_b64, public_key_pem=None, proof_string=None):
        """Verify a hardware-bound proof of possession."""
        if challenge_id not in self.challenges:
            logger.warning("Challenge %s not found", challenge_id)
            return False
            
        challenge = self.challenges[challenge_id]
        if challenge.used or datetime.now(timezone.utc) > challenge.expires_at:
            logger.warning("Challenge %s invalid or expired", challenge_id)
            return False

        try:
            signature = base64.b64decode(signature_b64)
            
            # 1. Native Proof Verification (Swift approach)
            if proof_string:
                # Extract CN for identity lookup
                user_cn = self._extract_cn_from_proof(proof_string) or "unknown"
                
                # 0. Check for Revocation
                if os.path.exists(os.path.join(self.revoked_dir, f"{user_cn}.rev")):
                    logger.warning("Rejected revoked user %s", user_cn)
                    return None

                # 1. Load Identity Context (Role, Dept, PubKey) from stored certificate
                role = "unknown"
                dept = "unknown"
                cert_pub_key = None
                
                cert_path = self._find_certificate_path(user_cn)
                if cert_path:
                    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
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
                    logger.warning("Certificate for %s not found", user_cn)

                # 2. Resolve Public Key for verification
                pub_key = self._load_public_key(public_key_pem) if public_key_pem else None
                
                # Fallback to certificate public key if client didn't send one (hardware protection)
                if not pub_key and cert_pub_key:
                    logger.info("Using public key from stored certificate for %s", user_cn)
                    pub_key = cert_pub_key

                if not pub_key:
                    logger.warning("No public key found for %s", user_cn)
                    return None

                try:
                    pub_key.verify(
                        signature,
                        proof_string.encode(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                except Exception as ve:
                    logger.warning("Signature verification failed for %s: %s", user_cn, ve)
                    return None

                logger.info("Hardware proof verified for %s", user_cn)
                self.challenges[challenge_id].used = True
                return {
                    "user": user_cn,
                    "role": role,
                    "department": dept
                }

            # 2. Try CSR verification (certtool fallback)
            raw_sig = signature
            try:
                csr = x509.load_pem_x509_csr(raw_sig)
            except ValueError:
                csr = x509.load_der_x509_csr(raw_sig)

            if csr.is_signature_valid:
                logger.info("Hardware CSR verified")
                self.challenges[challenge_id].used = True
                return True

            # 3. Raw RSA verification (Standard nonce)
            if public_key_pem:
                pub_key = serialization.load_pem_public_key(public_key_pem.encode())
                pub_key.verify(
                    signature,
                    challenge.nonce,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                logger.info("Raw signature verified")
                self.challenges[challenge_id].used = True
                return True
            
        except Exception as e:
            logger.warning("Verification failed: %s", e)
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
            logger.warning("Failed to load public key: %s", e)
            return None

    def _extract_cn_from_proof(self, proof_string: str) -> Optional[str]:
        for part in proof_string.split("|"):
            if part.startswith("CN="):
                return part.split("=", 1)[1].strip()
        return None

    def _validate_cn(self, user_cn: str) -> str:
        if not user_cn:
            raise ValueError("User CN is required")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user_cn):
            raise ValueError("User CN contains invalid characters")
        return user_cn

    def _ensure_unique_cn(self, user_cn: str) -> None:
        if self._find_certificate_path(user_cn):
            raise ValueError(f"Certificate for {user_cn} already exists")

    def _find_certificate_path(self, user_cn: str) -> Optional[Path]:
        candidate_paths = [
            self.client_dir / f"{user_cn}.crt",
            self.cert_dir_path / f"{user_cn}.crt",
        ]
        for path in candidate_paths:
            if path.exists():
                return path
        return None

    def _build_subject(self, user_cn: str, role: Optional[str], dept: Optional[str], mac: Optional[str], cpu: Optional[str]) -> x509.Name:
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, user_cn)]
        if role:
            subject_attrs.append(x509.NameAttribute(NameOID.TITLE, role))
        if dept:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dept))
        if mac:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"MAC:{mac}"))
        if cpu:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"CPU:{cpu}"))
        return x509.Name(subject_attrs)

    def _build_san_entries(self, user_cn: str, mac: Optional[str], cpu: Optional[str]) -> list:
        entries = [x509.DNSName(f"{user_cn}.internal")]
        if mac:
            entries.append(x509.DNSName(f"MAC-{mac}"))
        if cpu:
            entries.append(x509.DNSName(f"CPU-{cpu}"))
        return entries

    def _issue_certificate(self, subject: x509.Name, public_key, user_cn: str, mac: Optional[str], cpu: Optional[str]) -> x509.Certificate:
        now = datetime.now(timezone.utc)
        san_entries = self._build_san_entries(user_cn, mac, cpu)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=self.cert_validity_days))
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def _write_bundle(self, user_cn: str, certificate: x509.Certificate, metadata: dict, private_key=None) -> CertificateBundle:
        issued_dir = self.issued_dir / user_cn
        issued_dir.mkdir(parents=True, exist_ok=True)

        cert_path = issued_dir / "certificate.crt"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

        metadata_path = issued_dir / "metadata.json"
        metadata_path.write_text(self._json_dump(metadata))

        private_key_path = None
        if private_key is not None:
            private_key_path = issued_dir / "private_key.pem"
            private_key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            os.chmod(private_key_path, 0o600)

        client_cert_path = self.client_dir / f"{user_cn}.crt"
        client_cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

        return CertificateBundle(
            paths=CertificatePaths(
                certificate=cert_path,
                private_key=private_key_path,
                metadata=metadata_path,
            ),
            serial_number=certificate.serial_number,
            expires_at=certificate.not_valid_after,
        )

    def _json_dump(self, metadata: dict) -> str:
        import json

        return json.dumps(metadata, indent=2, sort_keys=True)

    def issue_certificate(self, user: str, role: Optional[str] = None, department: Optional[str] = None,
                          hardware_mode: str = "manual", mac: Optional[str] = None, cpu: Optional[str] = None) -> CertificateBundle:
        user_cn = self._validate_cn(user)
        self._ensure_unique_cn(user_cn)

        if hardware_mode == "random":
            mac = mac or uuid.uuid4().hex[:12]
            cpu = cpu or "CPU-UNKNOWN"

        subject = self._build_subject(user_cn, role, department, mac, cpu)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = self._issue_certificate(subject, private_key.public_key(), user_cn, mac, cpu)

        metadata = {
            "user": user_cn,
            "role": role,
            "department": department,
            "hardware": {"mac": mac, "cpu": cpu},
            "enrollment_method": hardware_mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return self._write_bundle(user_cn, certificate, metadata, private_key=private_key)

    def sign_csr(self, csr_pem: str, user: Optional[str] = None, role: Optional[str] = None,
                 department: Optional[str] = None, hardware_mac: Optional[str] = None,
                 hardware_cpu: Optional[str] = None) -> CertificateBundle:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")

        csr_cn_values = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not csr_cn_values:
            raise ValueError("CSR is missing Common Name")
        csr_cn = csr_cn_values[0].value

        user_cn = self._validate_cn(user or csr_cn)
        if user and csr_cn != user_cn:
            raise ValueError("CSR Common Name does not match requested user")

        self._ensure_unique_cn(user_cn)

        subject = self._build_subject(user_cn, role, department, hardware_mac, hardware_cpu)
        certificate = self._issue_certificate(subject, csr.public_key(), user_cn, hardware_mac, hardware_cpu)

        metadata = {
            "user": user_cn,
            "role": role,
            "department": department,
            "hardware": {"mac": hardware_mac, "cpu": hardware_cpu},
            "enrollment_method": "csr",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return self._write_bundle(user_cn, certificate, metadata)

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
            user_cn = self._extract_cn_from_proof(proof_string) or user_cn

        # Try to find existing public key from cert on disk as fallback
        cert_path = self._find_certificate_path(user_cn)
        if cert_path:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
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
            logger.warning("Client public key invalid, falling back to stored key for %s", user_cn)
            pub_key = cert_pub_key
            
        if not pub_key:
             raise ValueError("Could not load any public key for certificate issuance")

        clean_user = self._validate_cn(user_cn)
        # Costruiamo il Subject includendo tutti i metadati
        subject = self._build_subject(
            clean_user,
            role if role != "unknown" else None,
            dept if dept != "unknown" else None,
            kwargs.get("mac"),
            kwargs.get("cpu"),
        )
        # Case A: Native Hardware Proof (Preferred)
        if proof_string:
            # We already resolved pub_key and subject above
            pass
        # Case B: Standard Hardware CSR (Legacy/Fallback)
        elif is_hardware_csr and signature_b64:
            raw_csr = base64.b64decode(signature_b64)
            try:
                csr_obj = x509.load_pem_x509_csr(raw_csr)
            except ValueError:
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
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        hw_fingerprint = hashlib.sha256(pub_bytes).hexdigest()
        device_uri = f"urn:device:mac-keychain:{hw_fingerprint}"

        now = datetime.now(timezone.utc)
        san_entries = self._build_san_entries(clean_user, kwargs.get("mac"), kwargs.get("cpu"))
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=self.cert_validity_days))
            .add_extension(
                x509.SubjectAlternativeName(san_entries + [x509.UniformResourceIdentifier(device_uri)]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        metadata = {
            "user": clean_user,
            "role": role if role != "unknown" else None,
            "department": dept if dept != "unknown" else None,
            "hardware": {"mac": kwargs.get("mac"), "cpu": kwargs.get("cpu")},
            "enrollment_method": "hardware_proof",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        bundle = self._write_bundle(clean_user, certificate, metadata)
        return bundle.paths.certificate.read_text()

    def list_certificates(self):
        """List all certificates in the registry."""
        certs = []
        if self.client_dir.exists():
            for filename in os.listdir(self.client_dir):
                if filename.endswith(".crt"):
                    user_cn = filename[:-4]
                    status = "revoked" if (self.revoked_dir / f"{user_cn}.rev").exists() else "active"
                    certs.append({"user": user_cn, "status": status})
        return certs

    def revoke_certificate(self, user_cn):
        """Mark a certificate as revoked."""
        clean_user = self._validate_cn(user_cn)
        revocation_file = self.revoked_dir / f"{clean_user}.rev"
        revocation_file.write_text(f"Revoked at {datetime.now(timezone.utc)}")
        logger.warning("Certificate for %s has been revoked", clean_user)
        return True
