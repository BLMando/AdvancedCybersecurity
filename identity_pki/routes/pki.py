"""PKI and Hardware Enrollment semantic endpoints."""

import base64
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, current_app

from ..auth import ENROLLMENT_SESSIONS
from ..database import provision_mongo_user as _provision_mongo_user
from .utils import error_response

# Load ZTA roles
try:
    from shared.zta_roles import ZTA_ROLES, VALID_ROLE_NAMES
except ImportError:
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from shared.zta_roles import ZTA_ROLES, VALID_ROLE_NAMES
    except ImportError:
        ZTA_ROLES = {}
        VALID_ROLE_NAMES = []

pki_bp = Blueprint("pki", __name__)


@pki_bp.get("/api/challenge")
def api_get_challenge():
    """Get a challenge for hardware attestation."""
    service = current_app.config["pki_service"]
    challenge_id, nonce_b64 = service.create_challenge()
    return jsonify({
        "challenge_id": challenge_id,
        "nonce_b64": nonce_b64
    })


@pki_bp.post("/api/csr")
def api_sign_csr():
    """Sign a CSR with Hardware Attestation."""
    payload = request.get_json(silent=True) or {}
    session_token = payload.get("enrollment_session_token")
    
    if not session_token:
        return error_response("Enrollment session token is required", 401)
        
    session = ENROLLMENT_SESSIONS.get(session_token)
    if not session:
        return error_response("Invalid enrollment session", 401)
        
    if datetime.now(timezone.utc) > session["expires_at"]:
        ENROLLMENT_SESSIONS.pop(session_token, None)
        return error_response("Enrollment session has expired", 401)
        
    user = session["cn"]
    role = session["role"]
    department = session["department"]

    csr_pem = payload.get("csr", "")
    challenge_id = payload.get("challenge_id")
    signature_b64 = payload.get("attestation_sig_b64")
    is_hw = payload.get("is_hardware_csr", False)
    proof_string = payload.get("proof_string")
    
    if not csr_pem and not is_hw and not proof_string:
        return error_response("CSR required", 400)
    
    print(f"[DEBUG] CSR Payload ricevuto: {list(payload.keys())}")
    print(f"[DEBUG] MAC: {payload.get('mac_address')}, CPU: {payload.get('cpu_id')}")
    
    service = current_app.config["pki_service"]
    try:
        if proof_string:
            effective_csr = ""
        else:
            effective_csr = csr_pem if not is_hw else base64.b64decode(signature_b64).decode()
        
        user_mac = payload.get("mac_address") or payload.get("mac")
        user_cpu = payload.get("cpu_id") or payload.get("cpu")
        
        print(f"[DEBUG] Tentativo Enrollment per {user} con MAC={user_mac}, CPU={user_cpu}")

        cert_pem = service.issue_hardware_bound_certificate(
            csr_pem=effective_csr,
            challenge_id=challenge_id,
            signature_b64=signature_b64,
            public_key_pem=payload.get("public_key_pem"),
            is_hardware_csr=is_hw,
            proof_string=payload.get("proof_string"),
            user=user,
            role=role,
            department=department,
            mac=user_mac,
            cpu=user_cpu
        )
        
        # Auto-provision user in MongoDB
        _provision_mongo_user(service, current_app.logger, user, role)
            
        return jsonify({
            "status": "signed",
            "certificate_pem": cert_pem,
        })
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        current_app.logger.exception("Enrollment failed with unexpected error")
        return jsonify({"error": f"Internal server error: {e}"}), 500


@pki_bp.post("/api/certificates")
def api_issue_certificate():
    """Issue a certificate without hardware attestation (lab mode)."""
    payload = request.get_json(silent=True) or {}
    session_token = payload.get("enrollment_session_token")
    
    if session_token:
        session = ENROLLMENT_SESSIONS.get(session_token)
        if not session:
            return error_response("Invalid enrollment session", 401)
        if datetime.now(timezone.utc) > session["expires_at"]:
            ENROLLMENT_SESSIONS.pop(session_token, None)
            return error_response("Enrollment session has expired", 401)
        user_cn = session["cn"]
        role = session["role"]
        department = session["department"]
    else:
        user_cn = payload.get("user")
        role = payload.get("role")
        department = payload.get("department")

    if not user_cn:
        return error_response("User CN is required", 400)

    if role and role not in VALID_ROLE_NAMES:
        return error_response(f"Role '{role}' is invalid. Valid roles are: {VALID_ROLE_NAMES}", 400)
        
    service = current_app.config["pki_service"]
    try:
        bundle = service.issue_certificate(
            user=user_cn,
            role=role,
            department=department,
            hardware_mode=payload.get("hardware_mode", "manual"),
            mac=payload.get("mac"),
            cpu=payload.get("cpu"),
        )
        # Auto-provision user in MongoDB
        _provision_mongo_user(service, current_app.logger, user_cn, role)
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


@pki_bp.post("/api/enroll")
def api_enroll_delegated():
    """Delegate hardware enrollment request to the host local agent."""
    payload = request.get_json(silent=True) or {}
    session_token = payload.get("enrollment_session_token")
    
    if not session_token:
        return error_response("Enrollment session token is required", 401)
        
    session = ENROLLMENT_SESSIONS.get(session_token)
    if not session:
        return error_response("Invalid enrollment session", 401)
        
    if datetime.now(timezone.utc) > session["expires_at"]:
        ENROLLMENT_SESSIONS.pop(session_token, None)
        return error_response("Enrollment session has expired", 401)
        
    user = session["cn"]
    role = session["role"]
    department = session["department"]
        
    agent_url = f"http://host.docker.internal:9090/enroll"
    agent_payload = {
        "common_name": user,
        "role": role,
        "department": department,
        "enrollment_session_token": session_token
    }
    
    req = urllib.request.Request(
        agent_url,
        data=json.dumps(agent_payload).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'Host': f'localhost:9090'
        },
        method='POST'
    )
    
    try:
        print(f"[DEBUG] Delegating enrollment to agent on {agent_url} for {user}...")
        with urllib.request.urlopen(req, timeout=60) as response:
            resp_data = response.read().decode('utf-8')
            return jsonify(json.loads(resp_data)), response.status
    except urllib.error.HTTPError as e:
        resp_data = e.read().decode('utf-8')
        try:
            err_json = json.loads(resp_data)
        except:
            err_json = {"message": resp_data}
        return jsonify({
            "status": "error",
            "message": f"Local Agent returned status {e.code}: {err_json.get('message', resp_data)}"
        }), e.code
    except urllib.error.URLError as e:
        return jsonify({
            "status": "error",
            "message": f"ZTA Local Agent is not running or unreachable on port 9090 on the host: {e.reason}"
        }), 502
    except Exception as e:
        current_app.logger.exception("Delegation failed with unexpected error")
        return jsonify({
            "status": "error",
            "message": f"Delegation error: {e}"
        }), 500


@pki_bp.post("/api/verify")
def api_verify_identity():
    """Verify a hardware-bound identity proof."""
    payload = request.get_json(silent=True) or {}
    challenge_id = payload.get("challenge_id")
    signature_b64 = payload.get("signature")
    public_key_pem = payload.get("public_key_pem")
    proof_string = payload.get("proof_string")
    
    service = current_app.config["pki_service"]
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


@pki_bp.get("/api/roles")
def api_get_roles():
    """Get the valid roles and their mappings."""
    return jsonify({
        "roles": ZTA_ROLES,
        "valid_names": VALID_ROLE_NAMES
    })
