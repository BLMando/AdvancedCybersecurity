import os
import sys
import hashlib
import fcntl
import re
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
    
    return render_template("index.html", ca=ca_info, roles=roles)


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


def _get_blocklist_path():
    service = current_app.config["pki_service"]
    return os.path.join(service.cert_dir, "blocklist.txt")


def _read_blocklist() -> list[str]:
    path = _get_blocklist_path()
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_SH)
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _write_blocklist(ips: list[str]) -> None:
    path = _get_blocklist_path()
    with open(path, "w") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX)
            for ip in ips:
                f.write(f"{ip}\n")
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


@admin_bp.get("/api/admin/blocklist")
def api_get_blocklist():
    """Get the active firewall blocklist."""
    try:
        return jsonify(_read_blocklist())
    except Exception as e:
        return error_response(f"Failed to read blocklist: {e}", 500)


@admin_bp.post("/api/admin/blocklist/add")
def api_add_to_blocklist():
    """Add an IP address to the blocklist."""
    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip", "").strip()
    if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return error_response("Invalid IP address format", 400)
    try:
        ips = _read_blocklist()
        if ip not in ips:
            ips.append(ip)
            _write_blocklist(ips)
            current_app.logger.info("IP %s added to blocklist", ip)
        return jsonify({"status": "success", "message": f"IP {ip} blocked"})
    except Exception as e:
        return error_response(f"Failed to update blocklist: {e}", 500)


@admin_bp.post("/api/admin/blocklist/remove")
def api_remove_from_blocklist():
    """Remove an IP address from the blocklist."""
    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip", "").strip()
    if not ip:
        return error_response("IP address required", 400)
    try:
        ips = _read_blocklist()
        if ip in ips:
            ips.remove(ip)
            _write_blocklist(ips)
            current_app.logger.info("IP %s removed from blocklist", ip)
        return jsonify({"status": "success", "message": f"IP {ip} unblocked"})
    except Exception as e:
        return error_response(f"Failed to update blocklist: {e}", 500)
