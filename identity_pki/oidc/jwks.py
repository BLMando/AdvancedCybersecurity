"""OIDC JWKS (JSON Web Key Set) generation."""

from typing import Any, Dict, List
from .keys import _private_key
from .utils import b64url_encode_int


def get_jwks() -> Dict[str, List[Dict[str, Any]]]:
    """Return JWKS for verification."""
    numbers = _private_key.public_key().public_numbers()

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "zta-key-1",
        "n": b64url_encode_int(numbers.n),
        "e": b64url_encode_int(numbers.e),
    }
    return {"keys": [jwk]}
