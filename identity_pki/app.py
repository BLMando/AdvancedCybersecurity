"""Flask web application for the PKI & identity module."""

from __future__ import annotations

import base64
import logging
import os
import sys

from flask import Flask, jsonify, render_template, request, send_from_directory
from cryptography.hazmat.primitives import serialization, hashes
from .pki import PKIService
from pymongo import MongoClient
from pymongo.errors import OperationFailure
import json
import urllib.request
import random
import uuid
from datetime import datetime, timedelta, timezone

# Simulated Active Directory / HR database for ZTA Identity Verification
AD_USERS = {
    "dr.mario.rossi@ospedale.it": {
        "cn": "mario.rossi",
        "role": "doctor",
        "department": "Cardiologia",
        "password": "password123"
    },
    "giulia.bianchi@ospedale.it": {
        "cn": "giulia.bianchi",
        "role": "auditor",
        "department": "Audit",
        "password": "password123"
    },
    "luca.ferrari@ospedale.it": {
        "cn": "luca.ferrari",
        "role": "receptionist",
        "department": "Accettazione",
        "password": "password123"
    },
    "paolo.roselli@ospedale.it": {
        "cn": "paolo.roselli",
        "role": "doctor",
        "department": "Cardiologia",
        "password": "password123"
    },
     "mattia.mandorlini@ospedale.it": {
        "cn": "mattia.mandorlini",
        "role": "billing_staff",
        "department": "Cardiologia",
        "password": "password123"
    }
}

PENDING_OTPS = {}          # email -> {"otp": "123456", "expires_at": datetime, "user_info": dict}
ENROLLMENT_SESSIONS = {}   # token -> {"cn": cn, "role": role, "department": department, "expires_at": datetime}
PRIMARY_SESSIONS = {}      # cn -> {"login_time": datetime, "last_mfa_time": datetime}

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


def _provision_mongo_user(service: PKIService, logger: logging.Logger, username: str, role: str) -> None:
    try:
        mongo_root_user = os.environ.get("MONGO_ROOT_USERNAME", "admin")
        mongo_root_pass = os.environ.get("MONGO_ROOT_PASSWORD", "secret")
        mongo_db_name = os.environ.get("MONGO_INITDB_DATABASE", "zta_db")
        ca_path = os.path.join(service.cert_dir, "ca.crt")
        
        client = MongoClient(
            f"mongodb://{mongo_root_user}:{mongo_root_pass}@mongo:27017/admin",
            serverSelectionTimeoutMS=2000,
            tls=True,
            tlsCertificateKeyFile="/data/server/mongo.pem",
            tlsCAFile=ca_path,
            tlsAllowInvalidCertificates=True
        )
        db = client[mongo_db_name]
        
        from shared.zta_roles import ZTA_ROLES
        role_config = ZTA_ROLES.get(role, {})
        mongo_role = role_config.get("mongo_role", "read")
        
        password = f"{''.join(x.capitalize() for x in username.split('.'))}2026!"
        
        try:
            db.command("dropUser", username)
        except Exception:
            pass
            
        db.command(
            "createUser", username,
            pwd=password,
            roles=[{"role": mongo_role, "db": mongo_db_name}]
        )
        logger.info(f"Auto-provisioned MongoDB user '{username}' with role '{mongo_role}'")

        # Create user in $external database for MONGODB-OIDC authentication
        db_external = client["$external"]
        oidc_username = f"oidc/{username}"
        try:
            db_external.command("dropUser", oidc_username)
        except Exception:
            pass
        try:
            db_external.command(
                "createUser", oidc_username,
                roles=[{"role": mongo_role, "db": mongo_db_name}]
            )
            logger.info(f"Auto-provisioned MongoDB external OIDC user '{oidc_username}' with role '{mongo_role}'")
        except Exception as ex:
            logger.warning(f"Failed to auto-provision external OIDC user '{oidc_username}': {ex}")

        client.close()
    except Exception as e:
        logger.warning(f"Failed to auto-provision MongoDB user '{username}': {e}")


def _send_audit_event_impl(logger: logging.Logger, user, role, collection, action, translated_view,
                           query_filter, decision, count=0, error_type="",
                           message="", jwt_auth=False, hardware_mode=False):
    """Fire-and-forget audit event to the Splunk forwarder sidecar."""
    import threading as _threading
    def _send():
        try:
            audit_payload = json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user": user,
                "role": role,
                "resource": collection,
                "command": action,
                "translated_view": translated_view,
                "filter": query_filter,
                "decision": decision,
                "count": count,
                "error_type": error_type,
                "message": message,
                "jwt_auth": jwt_auth,
                "hardware_mode": hardware_mode,
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://opa-splunk-forwarder:5000/api/audit",
                data=audit_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception as e:
            logger.debug("Audit event delivery failed (non-critical): %s", e)
    _threading.Thread(target=_send, daemon=True).start()


def create_app(data_dir=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["JSON_SORT_KEYS"] = False
    
    # Use /data/certs by default for persistence in Docker
    cert_dir = data_dir or os.environ.get("ZTA_PKI_DATA_DIR", "/data/certs")
    service = PKIService(cert_dir=cert_dir)

    def error_response(message: str, code: int = 400):
        return jsonify({"error": message, "code": code}), code
    
    def provision_mongo_user(username, role):
        _provision_mongo_user(service, app.logger, username, role)

    def _send_audit_event(*args, **kwargs):
        _send_audit_event_impl(app.logger, *args, **kwargs)


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
        
        try:
            # If it's a hardware CSR, csr_pem might be empty or same as signature.
            # Skip decoding binary signature if proof_string is present (native hardware proof case)
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
            provision_mongo_user(user, role)
                
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
            provision_mongo_user(user_cn, role)
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

    @app.post("/api/auth/login")
    def api_auth_login():
        """Simulate Active Directory login and send OTP."""
        payload = request.get_json(silent=True) or {}
        email = payload.get("email", "").strip()
        password = payload.get("password", "")

        if not email or not password:
            return error_response("Email and Password are required", 400)

        user_info = AD_USERS.get(email)
        if not user_info or user_info["password"] != password:
            return error_response("Invalid email or password", 401)

        # Generate 6-digit OTP
        otp = f"{random.randint(100000, 999999)}"
        # Store in pending
        PENDING_OTPS[email] = {
            "otp": otp,
            "user_info": user_info,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        }

        app.logger.info(f"Simulated AD Login Success for {email}. OTP Code Generated: {otp}")
        return jsonify({
            "status": "otp_required",
            "message": f"Simulated MFA OTP generated for {email}",
            "email": email,
            "simulated_otp": otp  # Returned for ease of testing in lab UI
        })

    @app.post("/api/auth/verify-otp")
    def api_auth_verify_otp():
        """Verify the OTP and issue an enrollment session token."""
        payload = request.get_json(silent=True) or {}
        email = payload.get("email", "").strip()
        otp = payload.get("otp", "").strip()

        if not email or not otp:
            return error_response("Email and OTP are required", 400)

        pending = PENDING_OTPS.get(email)
        if not pending:
            return error_response("No pending authentication session found", 400)

        if datetime.now(timezone.utc) > pending["expires_at"]:
            PENDING_OTPS.pop(email, None)
            return error_response("OTP has expired", 401)

        if pending["otp"] != otp:
            return error_response("Invalid OTP code", 401)

        # Success: generate session token
        token = str(uuid.uuid4())
        user_cn = pending["user_info"]["cn"]
        ENROLLMENT_SESSIONS[token] = {
            "cn": user_cn,
            "role": pending["user_info"]["role"],
            "department": pending["user_info"]["department"],
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)
        }

        # Establish/Refresh Primary Auth Session (valid for 12 hours)
        now = datetime.now(timezone.utc)
        PRIMARY_SESSIONS[user_cn] = {
            "login_time": now,
            "last_mfa_time": now
        }

        # Clean up pending
        PENDING_OTPS.pop(email, None)

        app.logger.info(f"MFA Verified for {email}. Enrollment session token issued (redacted)")
        return jsonify({
            "status": "success",
            "enrollment_session_token": token,
            "user_info": {
                "cn": ENROLLMENT_SESSIONS[token]["cn"],
                "role": ENROLLMENT_SESSIONS[token]["role"],
                "department": ENROLLMENT_SESSIONS[token]["department"]
            }
        })

    @app.post("/api/auth/step-up")
    def api_auth_step_up():
        """Verify the OTP and password to refresh the last_mfa_time for Step-up Authentication."""
        payload = request.get_json(silent=True) or {}
        email = payload.get("email", "").strip()
        otp = payload.get("otp", "").strip()
        password = payload.get("password", "")

        if not email or not otp or not password:
            return error_response("Email, OTP and Password are required", 400)

        # 1. Verify password matches Active Directory
        user_info = AD_USERS.get(email)
        if not user_info or user_info["password"] != password:
            return error_response("Invalid email or password", 401)

        # 2. Verify OTP
        pending = PENDING_OTPS.get(email)
        if not pending:
            return error_response("No pending authentication session found", 400)

        if datetime.now(timezone.utc) > pending["expires_at"]:
            PENDING_OTPS.pop(email, None)
            return error_response("OTP has expired", 401)

        if pending["otp"] != otp:
            return error_response("Invalid OTP code", 401)

        # Success: Refresh/Establish primary session with updated last_mfa_time
        user_cn = user_info["cn"]
        now = datetime.now(timezone.utc)
        
        orig_session = PRIMARY_SESSIONS.get(user_cn, {})
        login_time = orig_session.get("login_time", now)
        
        PRIMARY_SESSIONS[user_cn] = {
            "login_time": login_time,
            "last_mfa_time": now
        }
        
        PENDING_OTPS.pop(email, None)
        
        app.logger.info(f"Step-up Authentication successful for {user_cn} ({email})")
        return jsonify({
            "status": "success",
            "message": "Step-up Authentication successful. Session MFA timestamp refreshed."
        })

    @app.post("/api/enroll")
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
            
        import urllib.request
        import urllib.error
        
        agent_url = "http://host.docker.internal:9090/enroll"
        agent_payload = {
            "common_name": user,
            "role": role,
            "department": department,
            "enrollment_session_token": session_token
        }
        
        from urllib.parse import urlparse
        parsed_url = urlparse(agent_url)
        host_port = parsed_url.port or 9090
        
        req = urllib.request.Request(
            agent_url,
            data=json.dumps(agent_payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Host': f'localhost:{host_port}'
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
            logger.exception("Delegation failed with unexpected error")
            return jsonify({
                "status": "error",
                "message": f"Delegation error: {e}"
            }), 500

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

    @app.get("/.well-known/jwks.json")
    def well_known_jwks():
        """Retrieve JWKS for signature verification."""
        try:
            from .oidc import get_jwks
            return jsonify(get_jwks())
        except Exception as e:
            return error_response(f"OIDC Error: {e}", 500)

    @app.get("/.well-known/openid-configuration")
    def well_known_openid_configuration():
        """Retrieve OpenID Connect discovery document."""
        return jsonify({
            "issuer": "https://identity-pki:8080",
            "jwks_uri": "https://identity-pki:8080/.well-known/jwks.json",
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })


    @app.post("/api/oidc/token")
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
                "message": "Autenticazione primaria scaduta o non trovata. Esegui il login AD + MFA."
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
            from .oidc import issue_jwt
            
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
            logger.exception("OIDC token issuance failed")
            return error_response(f"Failed to issue token: {e}", 500)


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

    @app.post("/api/query")
    def api_query():
        """Execute a MongoDB query via Envoy presenting the user's client certificate."""
        payload = request.get_json(silent=True) or {}
        user_cn = payload.get("user")
        collection_name = payload.get("collection")
        query_filter_str = payload.get("filter", "{}")
        limit = int(payload.get("limit", 10))
        jwt_token = payload.get("jwt_token")
        mongo_action = payload.get("action", "find")
        record_id = payload.get("record_id")          # Single-document _id for delete/update
        update_fields = payload.get("update_fields")  # Dict of specific fields to $set on update
        patient_id = payload.get("patient_id")        # patient_id to satisfy OPA WAF checks

        if not user_cn or not collection_name:
            return error_response("User CN and Collection name are required", 400)

        # Check if user is revoked
        if os.path.exists(os.path.join(service.revoked_dir, f"{user_cn}.rev")):
            return error_response("Identity is revoked", 401)

        if not jwt_token:
            return error_response(
                "Autenticazione OIDC obbligatoria. L'autenticazione legacy (SCRAM/Password) è disabilitata.",
                401
            )

        try:
            query_filter = json.loads(query_filter_str) if query_filter_str else {}
        except json.JSONDecodeError as e:
            return error_response(f"Invalid JSON filter: {e}", 400)

        # If a specific record_id is given, override the filter for single-doc operations
        if record_id and mongo_action in ("delete", "update"):
            from bson import ObjectId
            from bson.errors import InvalidId
            try:
                query_filter = {"_id": ObjectId(record_id)}
            except InvalidId:
                # Try as plain string _id (some collections use UUID strings)
                query_filter = {"_id": record_id}

            if patient_id:
                query_filter["patient_id"] = patient_id

        local_proxy_port = payload.get("local_proxy_port")

        # Path to client certificate and key in container
        cert_path = os.path.join(service.cert_dir, "client", f"{user_cn}.crt")
        key_path = os.path.join(service.cert_dir, "client", f"{user_cn}.key")

        # Fallback to issued directory
        if not os.path.exists(cert_path):
            cert_path = os.path.join(service.cert_dir, "issued", user_cn, "certificate.crt")
        if not os.path.exists(key_path):
            key_path = os.path.join(service.cert_dir, "issued", user_cn, "private_key.pem")

        if not os.path.exists(cert_path) and not jwt_token:
            return error_response(f"Credentials not found for user '{user_cn}'. Enroll the user first.", 404)

        if not jwt_token and not local_proxy_port and not os.path.exists(key_path):
            return error_response(
                f"User '{user_cn}' is hardware-enrolled. The private key remains secure in the client device's Secure Enclave "
                f"and is not available on the server. To query via this Web Console, re-enroll the user in Lab Mode (using /api/certificates) "
                f"so that the server generates and holds the key, or execute queries using the CLI tool (`scripts/mongo_proxy_cli.py`) on your host machine.",
                403
            )

        combined_pem_path = None
        if not local_proxy_port:
            if jwt_token and (not os.path.exists(key_path) or not os.path.exists(cert_path)):
                # Hardware mode OIDC connection from Flask to Envoy: use Flask's own server cert/key
                cert_path = "/data/server/envoy.crt"
                key_path = "/data/server/envoy.key"
                combined_pem_path = os.path.join(service.cert_dir, "client", "envoy_combined.pem")
            else:
                combined_pem_path = os.path.join(service.cert_dir, "client", f"{user_cn}_combined.pem")
            try:
                with open(combined_pem_path, "w") as out:
                    with open(cert_path) as c:
                        out.write(c.read())
                    with open(key_path) as k:
                        out.write(k.read())
            except Exception as e:
                return error_response(f"Failed to prepare combined PEM: {e}", 500)


        # Get role to perform RLS view translation
        role = "unknown"
        hardware_mode = False
        if jwt_token:
            try:
                parts = jwt_token.split(".")
                if len(parts) == 3:
                    payload_b64 = parts[1]
                    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                    payload_data = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
                    claims = json.loads(payload_data)
                    role = claims.get("role", "unknown")
                    if isinstance(role, list):
                        role = role[0] if role else "unknown"
            except Exception as ex:
                logger.warning(f"Failed to decode JWT claims: {ex}")

        # Also get hardware_mode if metadata exists
        metadata_path = os.path.join(service.cert_dir, f"issued/{user_cn}/metadata.json")
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path) as f:
                    meta = json.load(f)
                    if role == "unknown":
                        role = meta.get("role", "unknown")
                    hardware_mode = meta.get("enrollment_method", "manual") in ("random", "tpm")
            except Exception:
                pass

        if role == "unknown":
            try:
                from cryptography import x509
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                    titles = cert.subject.get_attributes_for_oid(x509.NameOID.TITLE)
                    if titles:
                        role = titles[0].value
            except Exception:
                pass

        # Call OPA to inspect the query filter for NoSQL Injection
        try:
            opa_payload = json.dumps({
                "input": {
                    "parsed_body": {
                        "query": json.dumps(query_filter)
                    }
                }
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://opa:8181/v1/data/envoy/authz/policy/is_malicious",
                data=opa_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=1) as resp:
                opa_res = json.loads(resp.read().decode("utf-8"))
                is_malicious = opa_res.get("result", False)
                if is_malicious:
                    # Log audit event for block
                    _send_audit_event(
                        user=user_cn,
                        role=role,
                        collection=collection_name,
                        action=mongo_action,
                        translated_view=collection_name,
                        query_filter=query_filter_str,
                        decision="DENY",
                        error_type="nosql_injection_blocked",
                        message="OPA L7 WAF Blocked: Suspicious NoSQL injection pattern detected in payload",
                        jwt_auth=bool(jwt_token),
                        hardware_mode=hardware_mode
                    )
                    return jsonify({
                        "status": "error",
                        "error_type": "authorization_denied",
                        "message": "Richiesta bloccata - Rilevato pattern NoSQL sospetto",
                        "role": role,
                        "translated_collection": collection_name
                    }), 403
        except Exception as e:
            # Fallback: if OPA is down or query fails, we log it and default to safe deny
            app.logger.error("Failed to query OPA for NoSQL injection check: %s", e)
            return jsonify({
                "status": "error",
                "error_type": "security_system_failure",
                "message": "Security validation failed. Please try again later."
            }), 500

        # Translate collection to RLS view
        view_name = collection_name
        if role != "admin":
            from shared.zta_roles import ZTA_ROLES
            role_config = ZTA_ROLES.get(role, {})
            allowed = role_config.get("allowed_collections", [])
            if collection_name not in allowed:
                _send_audit_event(
                    user=user_cn,
                    role=role,
                    collection=collection_name,
                    action=mongo_action,
                    translated_view=view_name,
                    query_filter=query_filter_str,
                    decision="DENY",
                    error_type="authorization_denied",
                    message=f"OPA/RBAC Access Denied: Role '{role}' is not allowed to access collection '{collection_name}'",
                    jwt_auth=bool(jwt_token),
                    hardware_mode=hardware_mode
                )
                return jsonify({
                    "status": "error",
                    "error_type": "authorization_denied",
                    "message": f"OPA/RBAC Access Denied: Role '{role}' is not allowed to access collection '{collection_name}'",
                    "role": role,
                    "translated_collection": view_name
                }), 403

            # Action-level permission check (mirrors criteria.rego permissions)
            action_permission_map = {
                "doctor": {
                    "patients": {"find"},
                    "providers": {"find"},
                    "admissions": {"find", "insert", "update"},
                    "clinical_records": {"find", "insert", "update"},
                    "billing": set()
                },
                "billing_staff": {
                    "patients": {"find"},
                    "providers": {"find"},
                    "admissions": {"find"},
                    "clinical_records": set(),
                    "billing": {"find", "insert", "update"}
                },
                "auditor": {
                    "patients": {"find"},
                    "providers": {"find"},
                    "admissions": {"find"},
                    "clinical_records": {"find"},
                    "billing": {"find"}
                },
                "receptionist": {
                    "patients": {"find", "insert", "update"},
                    "providers": {"find"},
                    "admissions": {"find", "insert", "update"},
                    "clinical_records": set(),
                    "billing": set()
                }
            }
            role_allowed_actions = action_permission_map.get(role, {}).get(collection_name, set())
            if mongo_action not in role_allowed_actions:
                _send_audit_event(
                    user=user_cn,
                    role=role,
                    collection=collection_name,
                    action=mongo_action,
                    translated_view=view_name,
                    query_filter=query_filter_str,
                    decision="DENY",
                    error_type="authorization_denied",
                    message=f"OPA/RBAC Access Denied: Role '{role}' is not allowed to perform '{mongo_action}' on collection '{collection_name}'",
                    jwt_auth=bool(jwt_token),
                    hardware_mode=hardware_mode
                )
                return jsonify({
                    "status": "error",
                    "error_type": "authorization_denied",
                    "message": f"OPA/RBAC Access Denied: Role '{role}' is not allowed to perform '{mongo_action}' on collection '{collection_name}'",
                    "role": role,
                    "translated_collection": view_name
                }), 403

            # Enforce that update operations on clinical_records contain patient_id in the query filter
            if collection_name == "clinical_records" and mongo_action == "update":
                if not query_filter.get("patient_id"):
                    return jsonify({
                        "status": "error",
                        "error_type": "authorization_denied",
                        "message": "OPA/RBAC Access Denied: Document failed validation (missing patient_id)",
                        "role": role,
                        "translated_collection": view_name
                    }), 403

            rls_views = {
                "doctor": {
                    "patients": "v_patients_doctor",
                    "providers": "v_providers_all",
                    "admissions": "v_admissions_doctor",
                    "clinical_records": "v_clinical_doctor",
                },
                "billing_staff": {
                    "patients": "v_patients_billing",
                    "providers": "v_providers_all",
                    "admissions": "v_admissions_billing",
                    "billing": "v_billing_staff",
                },
                "auditor": {
                    "patients": "v_patients_doctor",
                    "providers": "v_providers_all",
                    "admissions": "v_admissions_auditor",
                    "clinical_records": "v_clinical_auditor",
                    "billing": "v_billing_auditor",
                },
                "receptionist": {
                    "patients": "v_patients_reception",
                    "providers": "v_providers_all",
                    "admissions": "v_admissions_reception",
                }
            }
            view_name = rls_views.get(role, {}).get(collection_name, collection_name)

        mongo_db_name = os.environ.get("MONGO_INITDB_DATABASE", "zta_db")
        mongo_root_user = os.environ.get("MONGO_ROOT_USERNAME", "admin")
        mongo_root_pass = os.environ.get("MONGO_ROOT_PASSWORD", "secret")
        ca_path = os.path.join(service.cert_dir, "ca.crt")

        try:
            if jwt_token:
                from pymongo.auth_oidc import OIDCCallback, OIDCCallbackResult

                class StaticTokenCallback(OIDCCallback):
                    def __init__(self, token):
                        self.token = token
                    def fetch(self, context):
                        return OIDCCallbackResult(access_token=self.token)

                callback_instance = StaticTokenCallback(jwt_token)

                if local_proxy_port:
                    client = MongoClient(
                        f"mongodb://host.docker.internal:{local_proxy_port}/{mongo_db_name}?authSource=$external&authMechanism=MONGODB-OIDC&directConnection=true",
                        authMechanismProperties={
                            "OIDC_CALLBACK": callback_instance,
                            "authzId": f"oidc/{user_cn}"
                        },
                        serverSelectionTimeoutMS=8000
                    )
                else:
                    client = MongoClient(
                        f"mongodb://envoy:10000/{mongo_db_name}?authSource=$external&authMechanism=MONGODB-OIDC&directConnection=true",
                        authMechanismProperties={
                            "OIDC_CALLBACK": callback_instance,
                            "authzId": f"oidc/{user_cn}"
                        },
                        tls=True,
                        tlsCertificateKeyFile=combined_pem_path,
                        tlsCAFile=ca_path,
                        tlsAllowInvalidCertificates=True,
                        serverSelectionTimeoutMS=4000
                    )
            else:
                if local_proxy_port:
                    # Connect via the host's local proxy port
                    client = MongoClient(
                        f"mongodb://{mongo_root_user}:{mongo_root_pass}@host.docker.internal:{local_proxy_port}/{mongo_db_name}?authSource=admin&directConnection=true",
                        serverSelectionTimeoutMS=8000
                    )
                else:
                    # Connect to Envoy proxy inside the docker network
                    client = MongoClient(
                        f"mongodb://{mongo_root_user}:{mongo_root_pass}@envoy:10000/{mongo_db_name}?authSource=admin&directConnection=true",
                        tls=True,
                        tlsCertificateKeyFile=combined_pem_path,
                        tlsCAFile=ca_path,
                        tlsAllowInvalidCertificates=True,
                        serverSelectionTimeoutMS=4000
                    )

            db = client[mongo_db_name]
            
            results_json = []
            count = 0
            message = "Success"
            target_collection = view_name if mongo_action == "find" else collection_name
            
            if mongo_action == "find":
                cursor = db[target_collection].find(query_filter).limit(limit)
                from bson import json_util
                results = list(cursor)
                results_json = json.loads(json_util.dumps(results))
                count = len(results_json)
            elif mongo_action == "update":
                # Build $set payload: use specific update_fields if provided, else generic stamp
                if update_fields and isinstance(update_fields, dict):
                    # Sanitize: strip leading $ from keys to prevent operator injection
                    safe_fields = {k: v for k, v in update_fields.items() if not k.startswith("$")}
                    if target_collection != "providers":
                        set_payload = {**safe_fields, "updated_at": datetime.now(timezone.utc)}
                    else:
                        set_payload = safe_fields
                else:
                    if target_collection != "providers":
                        set_payload = {
                            "updated_at": datetime.now(timezone.utc)
                        }
                    else:
                        set_payload = {}
                
                if set_payload:
                    update_op = {"$set": set_payload}
                    res = db[target_collection].update_many(query_filter, update_op)
                    count = res.modified_count
                else:
                    count = 0
                message = f"Aggiornati {count} documenti in '{target_collection}'"
            elif mongo_action == "delete":
                res = db[target_collection].delete_many(query_filter)
                count = res.deleted_count
                message = f"Eliminati {count} documenti da '{target_collection}'"
            else:
                client.close()
                return error_response(f"Unsupported action: {mongo_action}", 400)
                
            client.close()

            _send_audit_event(
                user=user_cn,
                role=role,
                collection=collection_name,
                action=mongo_action,
                translated_view=target_collection,
                query_filter=query_filter_str,
                decision="ALLOW",
                count=count,
                message=message,
                jwt_auth=bool(jwt_token),
                hardware_mode=hardware_mode
            )

            return jsonify({
                "status": "success",
                "role": role,
                "translated_collection": target_collection,
                "count": count,
                "results": results_json,
                "message": message
            })

        except OperationFailure as e:
            err_msg = e.details.get("errmsg", str(e)) if e.details else str(e)
            _send_audit_event(
                user=user_cn,
                role=role,
                collection=collection_name,
                action=mongo_action,
                translated_view=view_name,
                query_filter=query_filter_str,
                decision="DENY",
                error_type="authorization_denied",
                message=f"OPA/RBAC Access Denied: {err_msg}",
                jwt_auth=bool(jwt_token),
                hardware_mode=hardware_mode
            )
            return jsonify({
                "status": "error",
                "error_type": "authorization_denied",
                "message": f"OPA/RBAC Access Denied: {err_msg}",
                "role": role,
                "translated_collection": view_name
            }), 403
        except Exception as e:
            return jsonify({
                "status": "error",
                "error_type": "connection_failed",
                "message": f"Connection failed: {e}"
            }), 500

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
    ssl_context = ("/data/server/envoy.crt", "/data/server/envoy.key")
    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)

if __name__ == "__main__":
    main()
