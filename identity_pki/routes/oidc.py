"""OIDC semantic endpoints for token exchange and key distribution."""

import os
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app

from ..auth import PRIMARY_SESSIONS
from .utils import error_response

oidc_bp = Blueprint("oidc", __name__)


@oidc_bp.get("/.well-known/jwks.json")
def well_known_jwks():
    """Retrieve JWKS for signature verification."""
    try:
        from ..oidc import get_jwks
        return jsonify(get_jwks())
    except Exception as e:
        return error_response(f"OIDC Error: {e}", 500)


@oidc_bp.get("/.well-known/openid-configuration")
def well_known_openid_configuration():
    """Retrieve OpenID Connect discovery document."""
    return jsonify({
        "issuer": "https://identity-pki:8080",
        "jwks_uri": "https://identity-pki:8080/.well-known/jwks.json",
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    })


@oidc_bp.post("/api/oidc/token")
def api_oidc_token():
    """Exchange verified biometric hardware signature for a cert-bound JWT token (RFC 8705)."""
    payload = request.get_json(silent=True) or {}
    challenge_id = payload.get("challenge_id")
    signature_b64 = payload.get("signature")
    public_key_pem = payload.get("public_key_pem")
    proof_string = payload.get("proof_string")
    step_up = payload.get("step_up", False)
    
    if not challenge_id or not signature_b64:
        return error_response("challenge_id and signature are required", 400)
        
    service = current_app.config["pki_service"]
    identity = service.verify_proof(
        challenge_id=challenge_id,
        signature_b64=signature_b64,
        public_key_pem=public_key_pem,
        proof_string=proof_string
    )
    
    if not identity:
        return error_response("Identity verification failed", 401)
        
    user_cn = identity["user"]
    role = identity["role"]
    
    # Check if user is revoked
    if os.path.exists(os.path.join(service.revoked_dir, f"{user_cn}.rev")):
        return error_response("Identity is revoked", 401)

    # Primary Authentication Session Gating (valid for 12 hours)
    session = PRIMARY_SESSIONS.get(user_cn)
    now = datetime.now(timezone.utc)
    
    if not session or (now - session["login_time"]) > timedelta(hours=12):
        return jsonify({
            "error": "primary_auth_required",
            "reason": "primary_session_required",
            "message": "Primary authentication expired or not found. Please login with AD + MFA."
        }), 401
        
    if step_up:
        if (now - session["last_mfa_time"]) > timedelta(seconds=120):
            return jsonify({
                "error": "primary_auth_required",
                "reason": "step_up_required",
                "message": "Step-up Authentication richiesta. Reinserisci la password e l'OTP."
            }), 401
    
    # Load cert fingerprint
    cert_path = os.path.join(service.cert_dir, "client", f"{user_cn}.crt")
    if not os.path.exists(cert_path):
        cert_path = os.path.join(service.cert_dir, "issued", user_cn, "certificate.crt")
        
    if not os.path.exists(cert_path):
        return error_response(f"Certificate not found for user '{user_cn}'. Enroll the user first.", 404)
        
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from ..oidc import issue_jwt
        
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        token = issue_jwt(user_cn, role, cert_fingerprint, step_up=step_up)
        
        return jsonify({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 900
        })
    except Exception as e:
        current_app.logger.exception("OIDC token issuance failed")
        return error_response(f"Failed to issue token: {e}", 500)
