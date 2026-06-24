"""OIDC JWT issuance and signing."""

import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .keys import _private_key
from .utils import b64url_encode_bytes, b64url_encode_json


def issue_jwt(user: str, role: str, cert_sha256_hex: str, step_up: bool = False) -> str:
    """Issue a signed JWT token containing claims and the certificate fingerprint (cnf)."""
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "zta-key-1",
    }

    # Convert cert hex to bytes, then base64url encoded representation of the hash
    cert_bytes = bytes.fromhex(cert_sha256_hex)
    x5t_s256 = b64url_encode_bytes(cert_bytes)

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "https://identity-pki:8080",
        "aud": "mongo",
        "sub": user,
        "role": [role],
        "iat": now,
        "exp": now + 900,  # 15 minutes validity
        "cnf": {
            "x5t#S256": x5t_s256,
            "x5t#S256_hex": cert_sha256_hex,
        },
    }
    if step_up:
        payload["step_up"] = True
        payload["step_up_time"] = now

    header_b64 = b64url_encode_json(header)
    payload_b64 = b64url_encode_json(payload)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    signature = _private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    signature_b64 = b64url_encode_bytes(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"
