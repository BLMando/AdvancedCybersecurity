"""OIDC key management, loading, and generation."""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _load_or_create_private_key() -> rsa.RSAPrivateKey:
    """Load the OIDC signing key from disk, or generate a new one if not found."""
    cert_dir = os.environ.get("ZTA_PKI_DATA_DIR", "/data/certs")
    key_path = os.path.join(cert_dir, "oidc_signing_key.pem")

    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as key_file:
                key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
                if isinstance(key, rsa.RSAPrivateKey):
                    return key
        except Exception:
            pass

    # Generate new key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Ensure directory exists
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    try:
        with open(key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    except Exception:
        pass
    return private_key


# Load or generate the persistent key for signing JWTs
_private_key = _load_or_create_private_key()
