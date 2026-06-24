"""Base64url encoding utility functions for OIDC tokens and keys."""

import base64
import json
from typing import Any


def b64url_encode_bytes(data: bytes) -> str:
    """Encode bytes to a base64url string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64url_encode_int(val: int) -> str:
    """Encode an integer to a base64url string representing its big-endian bytes."""
    byte_len = (val.bit_length() + 7) // 8
    b = val.to_bytes(byte_len, byteorder="big")
    return b64url_encode_bytes(b)


def b64url_encode_json(data: Any) -> str:
    """Encode a JSON-serializable object to a base64url string."""
    return b64url_encode_bytes(json.dumps(data).encode("utf-8"))
