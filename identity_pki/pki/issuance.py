import base64
import hashlib
import json
import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from identity_pki.pki.models import CertificateBundle, CertificatePaths

logger = logging.getLogger(__name__)


class PKIIssuanceMixin:
    def _get_identity_from_certificate(self, user_cn: str) -> tuple[str, str, Any | None]:
        role = "unknown"
        dept = "unknown"
        pub_key = None

        cert_path = self._find_certificate_path(user_cn)
        if cert_path:
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                pub_key = cert.public_key()

                for attr in cert.subject:
                    if attr.oid == NameOID.TITLE:
                        role = attr.value
                    elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                        val = str(attr.value)
                        if not val.startswith(("MAC:", "CPU:")):
                            dept = val
            except Exception as e:
                logger.warning("Failed to parse existing certificate for %s: %s", user_cn, e)
        else:
            logger.warning("Certificate for %s not found", user_cn)

        return role, dept, pub_key

    def _validate_cn(self, user_cn: str) -> str:
        if not user_cn:
            raise ValueError("User CN is required")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user_cn):
            raise ValueError("User CN contains invalid characters")
        return user_cn

    def _ensure_unique_cn(self, user_cn: str) -> None:
        if self._find_certificate_path(user_cn):
            raise ValueError(f"Certificate for {user_cn} already exists")

    def _find_certificate_path(self, user_cn: str) -> Path | None:
        candidate_paths = [
            self.issued_dir / user_cn / "certificate.crt",
            self.client_dir / f"{user_cn}.crt",
            self.cert_dir_path / f"{user_cn}.crt",
        ]
        for path in candidate_paths:
            if path.exists():
                return path
        return None

    def _build_subject(
        self, user_cn: str, role: str | None, dept: str | None, mac: str | None, cpu: str | None
    ) -> x509.Name:
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

    def _build_san_entries(self, user_cn: str, mac: str | None, cpu: str | None) -> list:
        entries = [x509.DNSName(f"{user_cn}.internal")]
        if mac:
            entries.append(x509.DNSName(f"MAC-{mac}"))
        if cpu:
            entries.append(x509.DNSName(f"CPU-{cpu}"))
        return entries

    def _build_end_entity_certificate(self, subject: x509.Name, public_key, san_entries: list) -> x509.Certificate:
        now = datetime.now(UTC)
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
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

    def _issue_certificate(
        self, subject: x509.Name, public_key, user_cn: str, mac: str | None, cpu: str | None
    ) -> x509.Certificate:
        san_entries = self._build_san_entries(user_cn, mac, cpu)
        return self._build_end_entity_certificate(subject, public_key, san_entries)

    def _write_bundle(
        self, user_cn: str, certificate: x509.Certificate, metadata: dict, private_key=None
    ) -> CertificateBundle:
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

        revocation_file = self.revoked_dir / f"{user_cn}.rev"
        if revocation_file.exists():
            try:
                revocation_file.unlink()
                logger.info("Removed revocation status for re-enrolled user %s", user_cn)
                self.generate_crl()
            except Exception as e:
                logger.error("Failed to remove revocation file for %s: %s", user_cn, e)

        return CertificateBundle(
            paths=CertificatePaths(
                certificate=cert_path,
                private_key=private_key_path,
                metadata=metadata_path,
            ),
            serial_number=certificate.serial_number,
            expires_at=certificate.not_valid_after_utc,
        )

    def _json_dump(self, metadata: dict) -> str:
        return json.dumps(metadata, indent=2, sort_keys=True)

    def issue_certificate(
        self,
        user: str,
        role: str | None = None,
        department: str | None = None,
        hardware_mode: str = "manual",
        mac: str | None = None,
        cpu: str | None = None,
    ) -> CertificateBundle:
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
            "timestamp": datetime.now(UTC).isoformat(),
        }

        return self._write_bundle(user_cn, certificate, metadata, private_key=private_key)

    def sign_csr(
        self,
        csr_pem: str,
        user: str | None = None,
        role: str | None = None,
        department: str | None = None,
        hardware_mac: str | None = None,
        hardware_cpu: str | None = None,
    ) -> CertificateBundle:
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
            "timestamp": datetime.now(UTC).isoformat(),
        }

        return self._write_bundle(user_cn, certificate, metadata)

    def issue_hardware_bound_certificate(
        self,
        csr_pem=None,
        challenge_id=None,
        signature_b64=None,
        public_key_pem=None,
        is_hardware_csr=False,
        proof_string=None,
        user=None,
        **kwargs,
    ):
        user_cn = user or "unknown"
        if proof_string:
            user_cn = self._extract_cn_from_proof(proof_string) or user_cn

        if user_cn != "unknown":
            revocation_file = self.revoked_dir / f"{user_cn}.rev"
            if revocation_file.exists():
                try:
                    revocation_file.unlink()
                    logger.info("Cleared revocation file for re-enrolling user %s before attestation", user_cn)
                    self.generate_crl()
                except Exception as e:
                    logger.error("Failed to remove revocation file for %s: %s", user_cn, e)

        if not self.verify_proof(challenge_id, signature_b64, public_key_pem, proof_string):
            raise ValueError("Hardware attestation failed: signature invalid")

        user_cn = user or "unknown"
        role = kwargs.get("role", "unknown")
        dept = kwargs.get("department", "unknown")
        cert_pub_key = None

        if proof_string:
            user_cn = self._extract_cn_from_proof(proof_string) or user_cn

        cert_role, cert_dept, cert_pub_key = self._get_identity_from_certificate(user_cn)
        if role == "unknown":
            role = cert_role
        if dept == "unknown":
            dept = cert_dept

        pub_key = self._load_public_key(public_key_pem)
        if not pub_key:
            logger.warning("Client public key invalid, falling back to stored key for %s", user_cn)
            pub_key = cert_pub_key

        if not pub_key:
            raise ValueError("Could not load any public key for certificate issuance")

        clean_user = self._validate_cn(user_cn)
        subject = self._build_subject(
            clean_user,
            role if role != "unknown" else None,
            dept if dept != "unknown" else None,
            kwargs.get("mac"),
            kwargs.get("cpu"),
        )

        if proof_string:
            pass
        elif is_hardware_csr and signature_b64:
            raw_csr = base64.b64decode(signature_b64)
            try:
                csr_obj = x509.load_pem_x509_csr(raw_csr)
            except ValueError:
                csr_obj = x509.load_der_x509_csr(raw_csr)
            pub_key = csr_obj.public_key()
            subject = csr_obj.subject
            clean_user = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
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

        san_entries = self._build_san_entries(clean_user, kwargs.get("mac"), kwargs.get("cpu"))
        san_entries.append(x509.UniformResourceIdentifier(device_uri))

        certificate = self._build_end_entity_certificate(subject, pub_key, san_entries)

        metadata = {
            "user": clean_user,
            "role": role if role != "unknown" else None,
            "department": dept if dept != "unknown" else None,
            "hardware": {"mac": kwargs.get("mac"), "cpu": kwargs.get("cpu")},
            "enrollment_method": "hardware_proof",
            "timestamp": datetime.now(UTC).isoformat(),
        }

        bundle = self._write_bundle(clean_user, certificate, metadata)
        return bundle.paths.certificate.read_text()
