import base64
import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec

from identity_pki.pki.models import AttestationChallenge

logger = logging.getLogger(__name__)


class PKIAttestationMixin:
    def create_challenge(self):
        challenge_id = str(uuid.uuid4())
        nonce = os.urandom(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.challenge_ttl_minutes)

        challenge = AttestationChallenge(
            challenge_id=challenge_id,
            nonce=nonce,
            expires_at=expires_at
        )
        self.challenges[challenge_id] = challenge
        return challenge_id, base64.b64encode(nonce).decode()

    def verify_proof(self, challenge_id, signature_b64, public_key_pem=None, proof_string=None) -> Optional[dict]:
        logger.debug("Verifying proof for challenge %s", challenge_id)

        try:
            challenge = self.challenges[challenge_id]
        except KeyError:
            logger.warning("Challenge %s not found (expired or never issued)", challenge_id)
            return None

        if challenge.used or datetime.now(timezone.utc) > challenge.expires_at:
            logger.warning("Challenge %s invalid or expired", challenge_id)
            return None

        try:
            signature = base64.b64decode(signature_b64)
            logger.debug("Signature received: %s...", signature_b64[:30])

            if proof_string:
                logger.debug("Proof string received: [%s]", proof_string)
                user_cn = self._extract_cn_from_proof(proof_string)
                if not user_cn and public_key_pem:
                    logger.info("CN not found in proof_string. Scanning issued certificates by public key...")
                    user_cn = self._find_user_by_public_key(public_key_pem)

                if not user_cn:
                    user_cn = "unknown"

                revocation_file = self.revoked_dir / f"{user_cn}.rev"
                if revocation_file.exists():
                    logger.warning("Rejected revoked user %s", user_cn)
                    return None

                role, dept, cert_pub_key = self._get_identity_from_certificate(user_cn)

                pub_key = self._load_public_key(public_key_pem) if public_key_pem else None

                if not pub_key and cert_pub_key:
                    logger.info("Using public key from stored certificate for %s", user_cn)
                    pub_key = cert_pub_key

                if not pub_key:
                    logger.warning("No public key found for %s", user_cn)
                    return None

                if not self._verify_cryptographic_signature(pub_key, signature, proof_string.encode()):
                    logger.warning("Signature verification failed for %s", user_cn)
                    return None

                logger.info("Hardware proof verified for %s", user_cn)
                self.challenges[challenge_id].used = True
                return {
                    "user": user_cn,
                    "role": role,
                    "department": dept
                }

            raw_sig = signature
            try:
                csr = x509.load_pem_x509_csr(raw_sig)
            except ValueError:
                csr = x509.load_der_x509_csr(raw_sig)

            if csr.is_signature_valid:
                logger.info("Hardware CSR verified")
                self.challenges[challenge_id].used = True
                return {"verified": True}

            if public_key_pem:
                pub_key = serialization.load_pem_public_key(public_key_pem.encode())
                if self._verify_cryptographic_signature(pub_key, signature, challenge.nonce):
                    logger.info("Raw signature verified")
                    self.challenges[challenge_id].used = True
                    return {"verified": True}

        except Exception as e:
            logger.warning("Verification failed: %s", e)
            return None

    def _verify_cryptographic_signature(self, pub_key, signature: bytes, data: bytes) -> bool:
        try:
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
                return True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            else:
                logger.warning("Unsupported key type for verification: %s", type(pub_key))
                return False
        except Exception as ve:
            logger.debug("Signature verification failed: %s", ve)
            return False

    def _load_public_key(self, public_key_pem):
        try:
            if not public_key_pem:
                return None
            pub_key_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
            try:
                return serialization.load_pem_public_key(pub_key_bytes)
            except Exception as e:
                if "BEGIN RSA" in str(public_key_pem):
                    if hasattr(serialization, 'load_pem_rsa_public_key'):
                        return serialization.load_pem_rsa_public_key(pub_key_bytes)
                raise e
        except Exception as e:
            logger.warning("Failed to load public key: %s", e)
            return None

    def _find_user_by_public_key(self, public_key_pem: str) -> Optional[str]:
        try:
            target_key = self._load_public_key(public_key_pem)
            if not target_key:
                return None
            target_bytes = target_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            for user_dir in self.issued_dir.iterdir():
                if user_dir.is_dir():
                    cert_file = user_dir / "certificate.crt"
                    if cert_file.exists():
                        try:
                            cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
                            cert_pub = cert.public_key()
                            cert_pub_bytes = cert_pub.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            if cert_pub_bytes == target_bytes:
                                logger.info("Found matching user for public key: %s", user_dir.name)
                                return user_dir.name
                        except Exception as e:
                            logger.debug("Failed parsing cert for %s: %s", user_dir.name, e)
        except Exception as e:
            logger.warning("Error searching user by public key: %s", e)
        return None

    def _extract_cn_from_proof(self, proof_string: str) -> Optional[str]:
        for part in proof_string.split("|"):
            if part.startswith("CN="):
                return part.split("=", 1)[1].strip()
        return None
