import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


def ensure_envoy_certs(cert_dir_path: Path, ca_cert: x509.Certificate, ca_key, validity_days: int = 365) -> None:
    server_dir = cert_dir_path.parent / "server"
    server_dir.mkdir(parents=True, exist_ok=True)

    cert_path = server_dir / "envoy.crt"
    key_path = server_dir / "envoy.key"

    if cert_path.exists() and key_path.exists():
        logger.info("Envoy server certificates already exist")
        return

    logger.info("Generating new Envoy server certificates")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ZTA_ORGANIZATION = os.getenv("ZTA_ORGANIZATION", "AdvancedCybersecurity-ORG")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ZTA_ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, "envoy"),
    ])

    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("envoy"),
                x509.DNSName("identity-pki"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    logger.info("Envoy server certificates generated successfully")


def ensure_mongo_certs(cert_dir_path: Path, ca_cert: x509.Certificate, ca_key, validity_days: int = 365) -> None:
    server_dir = cert_dir_path.parent / "server"
    server_dir.mkdir(parents=True, exist_ok=True)

    mongo_pem_path = server_dir / "mongo.pem"

    if mongo_pem_path.exists():
        logger.info("MongoDB server certificates already exist")
        return

    logger.info("Generating new MongoDB server certificates")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ZTA_ORGANIZATION = os.getenv("ZTA_ORGANIZATION", "AdvancedCybersecurity-ORG")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ZTA_ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, "mongo"),
    ])

    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("mongo"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

    combined_pem = key_pem + cert_pem
    mongo_pem_path.write_bytes(combined_pem)

    logger.info("MongoDB server certificates generated successfully (mongo.pem)")
