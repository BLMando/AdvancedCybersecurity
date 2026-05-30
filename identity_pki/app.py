"""Flask web application for the PKI & identity module."""

from __future__ import annotations

import base64
import logging
import os
import sys

from flask import Flask, jsonify, render_template, request, send_from_directory
from cryptography.hazmat.primitives import serialization, hashes
from .pki import PKIService

# Load ZTA roles
try:
    from shared.zta_roles import ZTA_ROLES, VALID_ROLE_NAMES
except ImportError:
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        from shared.zta_roles import ZTA_ROLES, VALID_ROLE_NAMES
    except ImportError:
        ZTA_ROLES = {}
        VALID_ROLE_NAMES = []

logger = logging.getLogger(__name__)


def create_app(data_dir=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["JSON_SORT_KEYS"] = False
    
    # Use /data/certs by default for persistence in Docker
    cert_dir = data_dir or os.environ.get("ZTA_PKI_DATA_DIR", "/data/certs")
    service = PKIService(cert_dir=cert_dir)

    def error_response(message: str, code: int = 400):
        return jsonify({"error": message, "code": code}), code
    

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/challenge")
    def api_get_challenge():
        """Get a challenge for hardware attestation."""
        challenge_id, nonce_b64 = service.create_challenge()
        return jsonify({
            "challenge_id": challenge_id,
            "nonce_b64": nonce_b64
        })

    @app.post("/api/csr")
    def api_sign_csr():
        """Sign a CSR with Hardware Attestation."""
        payload = request.get_json(silent=True) or {}
        csr_pem = payload.get("csr", "")
        challenge_id = payload.get("challenge_id")
        signature_b64 = payload.get("attestation_sig_b64")
        is_hw = payload.get("is_hardware_csr", False)
        
        proof_string = payload.get("proof_string")
        
        if not csr_pem and not is_hw and not proof_string:
            return error_response("CSR required", 400)

        role = payload.get("role")
        if role and role not in VALID_ROLE_NAMES:
            return error_response(f"Role '{role}' is invalid. Valid roles are: {VALID_ROLE_NAMES}", 400)
        
        print(f"[DEBUG] CSR Payload ricevuto: {list(payload.keys())}")
        print(f"[DEBUG] MAC: {payload.get('mac_address')}, CPU: {payload.get('cpu_id')}")
        
        try:
            # If it's a hardware CSR, csr_pem might be empty or same as signature
            effective_csr = csr_pem if not is_hw else base64.b64decode(signature_b64).decode()
            
            user_mac = payload.get("mac_address") or payload.get("mac")
            user_cpu = payload.get("cpu_id") or payload.get("cpu")
            
            print(f"[DEBUG] Tentativo Enrollment per {payload.get('user')} con MAC={user_mac}, CPU={user_cpu}")

            cert_pem = service.issue_hardware_bound_certificate(
                csr_pem=effective_csr,
                challenge_id=challenge_id,
                signature_b64=signature_b64,
                public_key_pem=payload.get("public_key_pem"),
                is_hardware_csr=is_hw,
                proof_string=payload.get("proof_string"),
                user=payload.get("user"),
                role=payload.get("role"),
                department=payload.get("department"),
                mac=user_mac,
                cpu=user_cpu
            )
                
            return jsonify({
                "status": "signed",
                "certificate_pem": cert_pem,
            })
        except ValueError as e:
            return error_response(str(e), 400)
        except Exception as e:
            logger.exception("Enrollment failed with unexpected error")
            return jsonify({"error": f"Internal server error: {e}"}), 500

    @app.post("/api/certificates")
    def api_issue_certificate():
        """Issue a certificate without hardware attestation (lab mode)."""
        payload = request.get_json(silent=True) or {}
        user_cn = payload.get("user")
        if not user_cn:
            return error_response("User CN is required", 400)

        role = payload.get("role")
        if role and role not in VALID_ROLE_NAMES:
            return error_response(f"Role '{role}' is invalid. Valid roles are: {VALID_ROLE_NAMES}", 400)

        try:
            bundle = service.issue_certificate(
                user=user_cn,
                role=payload.get("role"),
                department=payload.get("department"),
                hardware_mode=payload.get("hardware_mode", "manual"),
                mac=payload.get("mac"),
                cpu=payload.get("cpu"),
            )
        except ValueError as exc:
            return error_response(str(exc), 400)

        return jsonify(
            {
                "status": "created",
                "certificate": {
                    "user": user_cn,
                    "path": str(bundle.paths.certificate),
                    "serial": bundle.serial_number,
                    "expires_at": bundle.expires_at.isoformat(),
                },
            }
        )

    @app.post("/api/verify")
    def api_verify_identity():
        """Verify a hardware-bound identity proof."""
        payload = request.get_json(silent=True) or {}
        challenge_id = payload.get("challenge_id")
        signature_b64 = payload.get("signature")
        public_key_pem = payload.get("public_key_pem")
        proof_string = payload.get("proof_string")
        
        identity = service.verify_proof(
            challenge_id=challenge_id,
            signature_b64=signature_b64,
            public_key_pem=public_key_pem,
            proof_string=proof_string
        )
        if identity:
            return jsonify({
                "status": "authenticated",
                "message": "Zero Trust hardware identity verified",
                "identity": identity
            })
        else:
            return jsonify({"error": "Identity verification failed"}), 401

    @app.get("/api/roles")
    def api_get_roles():
        """Get the valid roles and their mappings."""
        return jsonify({
            "roles": ZTA_ROLES,
            "valid_names": VALID_ROLE_NAMES
        })

    @app.get("/")
    def index():
        """Serve the landing page."""
        # Get CA fingerprint
        import hashlib
        ca_fingerprint = hashlib.sha256(service.ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        ca_info = {
            "subject": service.ca_cert.subject.rfc4514_string(),
            "fingerprint_sha256": ca_fingerprint,
            "data_dir": service.cert_dir
        }
        
        roles = {k: {"label": v["display_name"]} for k, v in ZTA_ROLES.items()}
        
        return render_template("index.html", ca=ca_info, roles=roles)

    @app.get("/admin")
    def admin_dashboard():
        """Serve the admin dashboard."""
        return render_template("admin.html")

    @app.get("/api/admin/certificates")
    def api_list_certificates():
        """List all certificates."""
        return jsonify(service.list_certificates())

    @app.get("/ca/download/<filename>")
    def download_ca_file(filename):
        """Download the CA certificate."""
        # Force filename to ca.crt regardless of what the template asks for
        return send_from_directory(service.cert_dir, "ca.crt", as_attachment=True)

    @app.post("/api/admin/revoke")
    def api_revoke_certificate():
        """Revoke a certificate."""
        payload = request.get_json(silent=True) or {}
        user_cn = payload.get("user")
        if not user_cn:
            return error_response("User CN is required", 400)
        try:
            service.revoke_certificate(user_cn)
        except ValueError as exc:
            return error_response(str(exc), 400)
        return jsonify({"status": "success", "message": f"User {user_cn} revoked"})

    return app

def main() -> None:
    logging.basicConfig(
        level=os.environ.get("ZTA_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    app = create_app()
    host = os.environ.get("IDENTITY_APP_HOST", "0.0.0.0")
    port = int(os.environ.get("IDENTITY_APP_PORT", "8080"))
    debug = os.environ.get("IDENTITY_APP_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    main()
