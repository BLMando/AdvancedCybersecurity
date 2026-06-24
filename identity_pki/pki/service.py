import logging
import os
from pathlib import Path
from typing import Optional

from identity_pki.pki.ca import PKICAMixin
from identity_pki.pki.attestation import PKIAttestationMixin
from identity_pki.pki.issuance import PKIIssuanceMixin
from identity_pki.pki.revocation import PKIRevocationMixin
from identity_pki.pki.infra import ensure_envoy_certs, ensure_mongo_certs

logger = logging.getLogger(__name__)


class PKIService(PKICAMixin, PKIAttestationMixin, PKIIssuanceMixin, PKIRevocationMixin):
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
        self.challenges = {}

        self.ca_validity_days = int(os.environ.get("ZTA_CA_VALIDITY_DAYS", "3650"))
        self.cert_validity_days = int(os.environ.get("ZTA_CERT_VALIDITY_DAYS", "365"))
        self.challenge_ttl_minutes = int(os.environ.get("ZTA_CHALLENGE_TTL_MINUTES", "5"))

        self.issued_dir.mkdir(parents=True, exist_ok=True)
        self.revoked_dir.mkdir(parents=True, exist_ok=True)
        self.client_dir.mkdir(parents=True, exist_ok=True)

        self._ca_record = None
        self._ensure_ca()
        ensure_envoy_certs(self.cert_dir_path, self.ca_cert, self.ca_key, self.cert_validity_days)
        ensure_mongo_certs(self.cert_dir_path, self.ca_cert, self.ca_key, self.cert_validity_days)
        self.generate_crl()
