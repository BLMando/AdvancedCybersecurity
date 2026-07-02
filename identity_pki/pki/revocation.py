import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger(__name__)


class PKIRevocationMixin:
    def list_certificates(self):
        certs = []
        if self.client_dir.exists():
            for filename in os.listdir(self.client_dir):
                if filename.endswith(".crt"):
                    user_cn = filename[:-4]
                    status = "revoked" if (self.revoked_dir / f"{user_cn}.rev").exists() else "active"
                    key_exists = (self.client_dir / f"{user_cn}.key").exists() or (
                        self.issued_dir / user_cn / "private_key.pem"
                    ).exists()
                    role = "unknown"
                    metadata_path = self.issued_dir / user_cn / "metadata.json"
                    if metadata_path.exists():
                        try:
                            with open(metadata_path) as f:
                                meta = json.load(f)
                                role = meta.get("role", "unknown")
                        except Exception:
                            pass
                    certs.append({"user": user_cn, "status": status, "role": role, "is_hardware": not key_exists})
        return certs

    def generate_crl(self):
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(datetime.now(UTC))
        builder = builder.next_update(datetime.now(UTC) + timedelta(days=7))

        if self.revoked_dir.exists():
            for filename in os.listdir(self.revoked_dir):
                if filename.endswith(".rev"):
                    user_cn = filename[:-4]
                    cert_path = self._find_certificate_path(user_cn)
                    if cert_path and cert_path.exists():
                        try:
                            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                            serial_number = cert.serial_number

                            rev_content = (self.revoked_dir / filename).read_text()
                            rev_date = datetime.now(UTC)
                            match = re.search(r"Revoked at (.*)", rev_content)
                            if match:
                                try:
                                    rev_date = datetime.fromisoformat(match.group(1).strip())
                                except Exception:
                                    pass

                            revoked_cert = (
                                x509.RevokedCertificateBuilder()
                                .serial_number(serial_number)
                                .revocation_date(rev_date)
                                .build()
                            )
                            builder = builder.add_revoked_certificate(revoked_cert)
                        except Exception as e:
                            logger.error("Failed to add revoked cert for %s to CRL: %s", user_cn, e)

        crl = builder.sign(self.ca_key, hashes.SHA256())
        crl_path = self.cert_dir_path / "ca.crl"
        crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        logger.info("CRL successfully written to %s", crl_path)

    def revoke_certificate(self, user_cn):
        clean_user = self._validate_cn(user_cn)
        revocation_file = self.revoked_dir / f"{clean_user}.rev"
        revocation_file.write_text(f"Revoked at {datetime.now(UTC)}")
        logger.warning("Certificate for %s has been revoked", clean_user)
        self.generate_crl()
        return True
