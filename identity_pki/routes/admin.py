import os
import sys
import hashlib
from flask import Blueprint, render_template, jsonify, send_from_directory, request, current_app
from cryptography.hazmat.primitives import serialization

from .utils import error_response

# Load ZTA roles
try:
    from shared.zta_roles import ZTA_ROLES
except ImportError:
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from shared.zta_roles import ZTA_ROLES
    except ImportError:
        ZTA_ROLES = {}

admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/")
def index():
    """Serve the landing page."""
    service = current_app.config["pki_service"]
    ca_fingerprint = hashlib.sha256(service.ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    
    ca_info = {
        "subject": service.ca_cert.subject.rfc4514_string(),
        "fingerprint_sha256": ca_fingerprint,
        "data_dir": service.cert_dir
    }
    
    roles = {k: {"label": v["display_name"]} for k, v in ZTA_ROLES.items()}
    
    ZTA_AGENT_PORT = os.getenv("ZTA_AGENT_PORT", "9090")
    return render_template("index.html", ca=ca_info, roles=roles, zta_agent_port=ZTA_AGENT_PORT)


@admin_bp.get("/admin")
def admin_dashboard():
    """Serve the admin dashboard."""
    return render_template("admin.html")


@admin_bp.get("/api/admin/certificates")
def api_list_certificates():
    """List all certificates."""
    service = current_app.config["pki_service"]
    return jsonify(service.list_certificates())


@admin_bp.get("/ca/download/<filename>")
def download_ca_file(filename):
    """Download the CA certificate."""
    service = current_app.config["pki_service"]
    # Force filename to ca.crt regardless of what the template asks for
    return send_from_directory(service.cert_dir, "ca.crt", as_attachment=True)


@admin_bp.post("/api/admin/revoke")
def api_revoke_certificate():
    """Revoke a certificate."""
    payload = request.get_json(silent=True) or {}
    user_cn = payload.get("user")
    if not user_cn:
        return error_response("User CN is required", 400)
    try:
        service = current_app.config["pki_service"]
        service.revoke_certificate(user_cn)
    except ValueError as exc:
        return error_response(str(exc), 400)
    return jsonify({"status": "success", "message": f"User {user_cn} revoked"})
