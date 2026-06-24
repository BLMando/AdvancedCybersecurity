from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


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
