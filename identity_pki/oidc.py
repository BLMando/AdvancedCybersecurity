import datetime
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives import serialization
import os

def _load_or_create_private_key():
    cert_dir = os.environ.get("ZTA_PKI_DATA_DIR", "/data/certs")
    key_path = os.path.join(cert_dir, "oidc_signing_key.pem")
    
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
        except Exception:
            pass
            
    # Generate new key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Ensure directory exists
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    try:
        with open(key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    except Exception:
        pass
    return private_key

# Load or generate the persistent key for signing JWTs
_private_key = _load_or_create_private_key()

def get_jwks():
    """Return JWKS for verification."""
    numbers = _private_key.public_key().public_numbers()
    
    def b64url(val):
        byte_len = (val.bit_length() + 7) // 8
        b = val.to_bytes(byte_len, byteorder='big')
        return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')
        
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "zta-key-1",
        "n": b64url(numbers.n),
        "e": b64url(numbers.e)
    }
    return {"keys": [jwk]}

def issue_jwt(user, role, cert_sha256_hex, step_up=False):
    """Issue a signed JWT token containing claims and the certificate fingerprint (cnf)."""
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "zta-key-1"
    }
    
    # Convert cert hex to bytes, then base64url encoded representation of the hash
    cert_bytes = bytes.fromhex(cert_sha256_hex)
    x5t_s256 = base64.urlsafe_b64encode(cert_bytes).decode('utf-8').rstrip('=')
    
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "iss": "https://identity-pki:8080",
        "aud": "mongo",
        "sub": user,
        "role": [role],

        "iat": now,
        "exp": now + 900, # 15 minutes validity
        "cnf": {
            "x5t#S256": x5t_s256,
            "x5t#S256_hex": cert_sha256_hex
        }
    }
    if step_up:
        payload["step_up"] = True
        payload["step_up_time"] = now

    
    def b64url_encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode('utf-8')).decode('utf-8').rstrip('=')
        
    header_b64 = b64url_encode(header)
    payload_b64 = b64url_encode(payload)
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    signature = _private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"
