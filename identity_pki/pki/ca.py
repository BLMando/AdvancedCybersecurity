import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from identity_pki.pki.models import CARecord

logger = logging.getLogger(__name__)


class PKICAMixin:
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
        
        ZTA_CA_CN = os.getenv("ZTA_CA_CN", "AdvancedCybersecurity-CA")
        ZTA_ORGANIZATION = os.getenv("ZTA_ORGANIZATION", "AdvancedCybersecurity-ORG")

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Milano"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Milano"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ZTA_ORGANIZATION),
                x509.NameAttribute(NameOID.COMMON_NAME, ZTA_CA_CN),
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
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), critical=False)
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
        password = os.getenv("ZTA_CA_KEY_PASSWORD")
        return password.encode("utf-8") if password else None

    def _get_ca_encryption(self) -> serialization.KeySerializationEncryption:
        password = self._get_ca_password()
        if password:
            return serialization.BestAvailableEncryption(password)
        logger.warning("CA private key is stored without encryption")
        return serialization.NoEncryption()

    @property
    def ca_common_name(self) -> str:
        cn_values = self.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cn_values[0].value if cn_values else "Unknown"

    def ca_summary(self) -> dict:
        fingerprint = hashlib.sha256(self.ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        return {
            "subject": self.ca_cert.subject.rfc4514_string(),
            "fingerprint_sha256": fingerprint,
            "created": self._ca_record.created if self._ca_record else None,
        }
