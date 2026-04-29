"""Core PKI helpers for the identity module.

This module keeps the Root CA persistent on disk and issues client certificates
that embed user identity, role/department information, and hardware hints in
the SAN extension so Envoy/OPA can consume them.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import secrets
import string
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from datetime import timezone

DEFAULT_ROLES: Dict[str, Dict[str, str]] = {
    "doctor": {"label": "Doctor", "department": "Cardiologia"},
    "billing": {"label": "Billing", "department": "Amministrazione"},
    "auditor": {"label": "Auditor", "department": "Audit"},
}


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value or "user"


def _clean_text(value: Optional[str]) -> str:
    return (value or "").strip()


def _format_mac(raw_value: int) -> str:
    return ":".join(
        "{:02X}".format((raw_value >> shift) & 0xFF)
        for shift in range(40, -1, -8)
    )


def _certificate_expiry_iso(certificate: x509.Certificate) -> str:
    expires_at = getattr(certificate, "not_valid_after_utc", None)
    if expires_at is None:
        expires_at = certificate.not_valid_after
    return expires_at.isoformat()


@dataclass(frozen=True)
class HardwareProfile:
    mac: str
    cpu: str
    source: str


@dataclass(frozen=True)
class CertificatePaths:
    certificate: Path
    private_key: Path
    pem_bundle: Path
    metadata: Path


@dataclass(frozen=True)
class CertificateBundle:
    slug: str
    user: str
    role: str
    department: str
    hardware: HardwareProfile
    subject: str
    san_dns: Iterable[str]
    serial_number: int
    expires_at: str
    fingerprint_sha256: str
    paths: CertificatePaths

    def to_dict(self) -> Dict[str, object]:
        return {
            "slug": self.slug,
            "user": self.user,
            "role": self.role,
            "department": self.department,
            "hardware": {
                "mac": self.hardware.mac,
                "cpu": self.hardware.cpu,
                "source": self.hardware.source,
            },
            "subject": self.subject,
            "san_dns": list(self.san_dns),
            "serial_number": str(self.serial_number),
            "expires_at": self.expires_at,
            "fingerprint_sha256": self.fingerprint_sha256,
            "paths": {
                "certificate": str(self.paths.certificate),
                "private_key": str(self.paths.private_key),
                "pem_bundle": str(self.paths.pem_bundle),
                "metadata": str(self.paths.metadata),
            },
        }


@dataclass(frozen=True)
class CARecord:
    key_path: Path
    cert_path: Path
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey
    created: bool


class PKIService:
    """Persistent CA + certificate issuance helper."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        organization_name: str = "Ospedale-San-Raffaele",
        ca_common_name: str = "ZTA-Healthcare-Root-CA",
    ) -> None:
        module_root = Path(__file__).resolve().parents[1]
        self.data_dir = Path(
            data_dir
            or os.environ.get("ZTA_PKI_DATA_DIR")
            or (module_root / "certs" / "identity_pki")
        )
        self.organization_name = os.environ.get(
            "ZTA_PKI_ORGANIZATION", organization_name
        )
        self.ca_common_name = os.environ.get("ZTA_PKI_CA_CN", ca_common_name)
        self.ca_dir = self.data_dir / "ca"
        self.issued_dir = self.data_dir / "issued"
        self._ca_record = self.load_or_create_ca()

    @property
    def ca_key_path(self) -> Path:
        return self.ca_dir / "hospital_ca.key"

    @property
    def ca_cert_path(self) -> Path:
        return self.ca_dir / "hospital_ca.crt"

    def ensure_directories(self) -> None:
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.issued_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create_ca(self) -> CARecord:
        self.ensure_directories()

        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            with self.ca_key_path.open("rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )
            with self.ca_cert_path.open("rb") as cert_file:
                certificate = x509.load_pem_x509_certificate(cert_file.read())
            return CARecord(
                key_path=self.ca_key_path,
                cert_path=self.ca_cert_path,
                certificate=certificate,
                private_key=private_key,
                created=False,
            )

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, self.ca_common_name),
            ]
        )
        now = datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        self.ca_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

        return CARecord(
            key_path=self.ca_key_path,
            cert_path=self.ca_cert_path,
            certificate=certificate,
            private_key=private_key,
            created=True,
        )

    def detect_local_hardware(self) -> HardwareProfile:
        mac = _format_mac(uuid.getnode())
        cpu = (
            platform.processor()
            or platform.uname().processor
            or platform.machine()
            or "Generic-Processor-ID"
        )
        return HardwareProfile(mac=mac.upper(), cpu=cpu, source="local")

    def generate_random_hardware(self) -> HardwareProfile:
        mac = "00:1A:2B:" + ":".join(
            "{:02X}".format(secrets.randbelow(256)) for _ in range(3)
        )
        cpu = "Simulated-" + "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)
        )
        return HardwareProfile(mac=mac, cpu=cpu, source="random")

    def resolve_hardware(
        self,
        mode: str,
        mac: Optional[str] = None,
        cpu: Optional[str] = None,
    ) -> HardwareProfile:
        normalized_mode = (mode or "local").strip().lower()
        if normalized_mode == "local":
            return self.detect_local_hardware()
        if normalized_mode == "random":
            return self.generate_random_hardware()
        if normalized_mode == "manual":
            clean_mac = _clean_text(mac)
            clean_cpu = _clean_text(cpu)
            if not clean_mac or not clean_cpu:
                raise ValueError("In manual mode, both MAC and CPU must be provided.")
            return HardwareProfile(mac=clean_mac.upper(), cpu=clean_cpu, source="manual")
        raise ValueError("Unsupported hardware mode. Use local, random, or manual.")

    def issue_certificate(
        self,
        user: str,
        role: str,
        department: Optional[str] = None,
        hardware_mode: str = "local",
        mac: Optional[str] = None,
        cpu: Optional[str] = None,
    ) -> CertificateBundle:
        clean_user = _clean_text(user)
        if not clean_user:
            raise ValueError("Username is required.")

        clean_role = _clean_text(role).lower()
        if clean_role not in DEFAULT_ROLES:
            raise ValueError("Unsupported role. Choose doctor, billing, or auditor.")

        role_definition = DEFAULT_ROLES[clean_role]
        clean_department = _clean_text(department) or role_definition["department"]
        hardware = self.resolve_hardware(hardware_mode, mac=mac, cpu=cpu)

        # Check if a valid certificate already exists for this DN
        bundle_slug = _slugify(clean_user)
        bundle_dir = self.issued_dir / bundle_slug
        metadata_path = bundle_dir / "metadata.json"
        if metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                expires_at_str = metadata.get("expires_at")
                if expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    if expires_at > datetime.now(datetime.timezone.utc):
                        raise ValueError(
                            f"A valid certificate already exists for user '{clean_user}' "
                            f"(expires: {expires_at_str}). CN-based uniqueness enforced."
                        )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                if isinstance(e, ValueError) and "valid certificate" in str(e):
                    raise
                # If metadata is corrupted, proceed with new issuance
                pass

        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, clean_department),
                x509.NameAttribute(NameOID.COMMON_NAME, clean_user),
            ]
        )
        san_values = [
            x509.DNSName(f"{_slugify(clean_user)}.internal"),
            x509.DNSName(f"MAC-{hardware.mac}"),
            x509.DNSName(f"CPU-{hardware.cpu}"),
        ]
        now = datetime.utcnow()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_record.certificate.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
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
                critical=False,
            )
            .sign(self._ca_record.private_key, hashes.SHA256())
        )

        bundle_dir.mkdir(parents=True, exist_ok=True)
        cert_path = bundle_dir / f"{bundle_slug}.crt"
        key_path = bundle_dir / f"{bundle_slug}.key"
        pem_path = bundle_dir / f"{bundle_slug}.pem"

        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        key_bytes = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert_path.write_bytes(cert_bytes)
        key_path.write_bytes(key_bytes)
        pem_path.write_bytes(cert_bytes + key_bytes)

        try:
            os.chmod(key_path, 0o600)
            os.chmod(pem_path, 0o600)
        except OSError:
            pass

        metadata = {
            "user": clean_user,
            "role": role_definition["label"],
            "department": clean_department,
            "hardware": {
                "mac": hardware.mac,
                "cpu": hardware.cpu,
                "source": hardware.source,
            },
            "subject": certificate.subject.rfc4514_string(),
            "san_dns": [value.value for value in san_values],
            "serial_number": str(certificate.serial_number),
            "expires_at": _certificate_expiry_iso(certificate),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "ca_cert": str(self.ca_cert_path),
        }
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
        )

        return CertificateBundle(
            slug=bundle_slug,
            user=clean_user,
            role=role_definition["label"],
            department=clean_department,
            hardware=hardware,
            subject=certificate.subject.rfc4514_string(),
            san_dns=[value.value for value in san_values],
            serial_number=certificate.serial_number,
            expires_at=_certificate_expiry_iso(certificate),
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            paths=CertificatePaths(
                certificate=cert_path,
                private_key=key_path,
                pem_bundle=pem_path,
                metadata=metadata_path,
            ),
        )

    def issue_server_certificate(
        self, cn: str = "envoy", dns_names: Optional[list] = None
    ) -> CertificatePaths:
        """Generate a server certificate signed by the CA."""
        clean_cn = _clean_text(cn) or "envoy"
        if dns_names is None:
            dns_names = ["envoy", "localhost", "127.0.0.1"]

        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, clean_cn),
            ]
        )
        san_values = [x509.DNSName(name) for name in dns_names] + [
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        ]

        now = datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_record.certificate.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
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
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_record.private_key, hashes.SHA256())
        )

        server_dir = Path(__file__).resolve().parents[1] / "certs" / "server"
        server_dir.mkdir(parents=True, exist_ok=True)
        cert_path = server_dir / "envoy.crt"
        key_path = server_dir / "envoy.key"
        pem_path = server_dir / "envoy.pem"

        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        key_bytes = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert_path.write_bytes(cert_bytes)
        key_path.write_bytes(key_bytes)
        pem_path.write_bytes(cert_bytes + key_bytes)

        return CertificatePaths(
            certificate=cert_path,
            private_key=key_path,
            pem_bundle=pem_path,
            metadata=server_dir / "metadata.json",
        )

    def sign_csr(
        self,
        csr_pem: str,
        user: str,
        role: str,
        department: Optional[str] = None,
        hardware_mac: Optional[str] = None,
        hardware_cpu: Optional[str] = None,
    ) -> CertificateBundle:
        """Sign a CSR (Certificate Signing Request) from the client device.
        
        The client device generates its own keypair and sends a CSR.
        The CA signs it and returns the certificate.
        This is the standard enrollment flow (more secure than server-side key generation).
        """
        clean_user = _clean_text(user)
        if not clean_user:
            raise ValueError("Username is required.")

        clean_role = _clean_text(role).lower()
        if clean_role not in DEFAULT_ROLES:
            raise ValueError("Unsupported role. Choose doctor, billing, or auditor.")

        role_definition = DEFAULT_ROLES[clean_role]
        clean_department = _clean_text(department) or role_definition["department"]

        # Parse the CSR
        try:
            csr_bytes = csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem
            csr = x509.load_pem_x509_csr(csr_bytes)
        except Exception as e:
            raise ValueError(f"Invalid CSR format: {e}")

        # Check if a valid certificate already exists for this CN
        bundle_slug = _slugify(clean_user)
        bundle_dir = self.issued_dir / bundle_slug
        metadata_path = bundle_dir / "metadata.json"
        if metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                expires_at_str = metadata.get("expires_at")
                if expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    now = datetime.now(timezone.utc) if expires_at.tzinfo else datetime.now(datetime.timezone.utc)
                    if expires_at > now:
                        raise ValueError(
                            f"A valid certificate already exists for user '{clean_user}' "
                            f"(expires: {expires_at_str}). CN-based uniqueness enforced."
                        )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                if isinstance(e, ValueError) and "valid certificate" in str(e):
                    raise
                pass

        # Extract SAN from CSR if present, otherwise create new ones
        san_values = []
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_values = list(san_ext.value)
        except x509.ExtensionNotFound:
            pass

        # Add hardware identifiers if not already in CSR
        hardware_mac = hardware_mac or _clean_text(hardware_mac) or ""
        hardware_cpu = hardware_cpu or _clean_text(hardware_cpu) or ""
        
        san_dns_list = [v.value for v in san_values if isinstance(v, x509.DNSName)]
        if hardware_mac and f"MAC-{hardware_mac}" not in san_dns_list:
            san_values.append(x509.DNSName(f"MAC-{hardware_mac}"))
        if hardware_cpu and f"CPU-{hardware_cpu}" not in san_dns_list:
            san_values.append(x509.DNSName(f"CPU-{hardware_cpu}"))

        # Sign the CSR
        now = datetime.utcnow()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_record.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
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
                critical=False,
            )
            .sign(self._ca_record.private_key, hashes.SHA256())
        )

        # Save certificate
        bundle_dir.mkdir(parents=True, exist_ok=True)
        cert_path = bundle_dir / f"{bundle_slug}.crt"
        metadata_path = bundle_dir / "metadata.json"

        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        cert_path.write_bytes(cert_bytes)

        metadata = {
            "user": clean_user,
            "role": role_definition["label"],
            "department": clean_department,
            "hardware": {
                "mac": hardware_mac,
                "cpu": hardware_cpu,
                "source": "csr",
            },
            "subject": certificate.subject.rfc4514_string(),
            "san_dns": [value.value for value in san_values if isinstance(value, x509.DNSName)],
            "serial_number": str(certificate.serial_number),
            "expires_at": _certificate_expiry_iso(certificate),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "ca_cert": str(self.ca_cert_path),
            "enrollment_method": "csr",
        }
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
        )

        return CertificateBundle(
            slug=bundle_slug,
            user=clean_user,
            role=role_definition["label"],
            department=clean_department,
            hardware=HardwareProfile(mac=hardware_mac, cpu=hardware_cpu, source="csr"),
            subject=certificate.subject.rfc4514_string(),
            san_dns=[value.value for value in san_values if isinstance(value, x509.DNSName)],
            serial_number=certificate.serial_number,
            expires_at=_certificate_expiry_iso(certificate),
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            paths=CertificatePaths(
                certificate=cert_path,
                private_key=Path(),  # Client keeps its own private key
                pem_bundle=Path(),
                metadata=metadata_path,
            ),
        )

    def ca_summary(self) -> Dict[str, object]:
        return {
            "created": self._ca_record.created,
            "subject": self._ca_record.certificate.subject.rfc4514_string(),
            "fingerprint_sha256": self._ca_record.certificate.fingerprint(
                hashes.SHA256()
            ).hex(),
            "key_path": str(self.ca_key_path),
            "cert_path": str(self.ca_cert_path),
            "data_dir": str(self.data_dir),
        }
