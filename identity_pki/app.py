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
    
    def provision_mongo_user(username, role):
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
            app.logger.info(f"Auto-provisioned MongoDB user '{username}' with role '{mongo_role}'")

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
                app.logger.info(f"Auto-provisioned MongoDB external OIDC user '{oidc_username}' with role '{mongo_role}'")
            except Exception as ex:
                app.logger.warning(f"Failed to auto-provision external OIDC user '{oidc_username}': {ex}")

            client.close()
        except Exception as e:
            app.logger.warning(f"Failed to auto-provision MongoDB user '{username}': {e}")
    

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
            
            # Auto-provision user in MongoDB
            provision_mongo_user(payload.get("user"), payload.get("role"))
                
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
            # Auto-provision user in MongoDB
            provision_mongo_user(user_cn, payload.get("role"))
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

    @app.post("/api/enroll")
    def api_enroll_delegated():
        """Delegate hardware enrollment request to the host local agent."""
        payload = request.get_json(silent=True) or {}
        user = payload.get("common_name") or payload.get("user")
        role = payload.get("role")
        department = payload.get("department")
        
        if not user:
            return error_response("User CN is required", 400)
            
        import urllib.request
        import urllib.error
        
        agent_url = "http://host.docker.internal:9090/enroll"
        agent_payload = {
            "common_name": user,
            "role": role,
            "department": department
        }
        
        req = urllib.request.Request(
            agent_url,
            data=json.dumps(agent_payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
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
            token = issue_jwt(user_cn, role, cert_fingerprint)
            
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

        if not user_cn or not collection_name:
            return error_response("User CN and Collection name are required", 400)

        try:
            query_filter = json.loads(query_filter_str) if query_filter_str else {}
        except json.JSONDecodeError as e:
            return error_response(f"Invalid JSON filter: {e}", 400)

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


        if role == "unknown":
            metadata_path = os.path.join(service.cert_dir, f"issued/{user_cn}/metadata.json")
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path) as f:
                        meta = json.load(f)
                        role = meta.get("role", "unknown")
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

        # Translate collection to RLS view
        view_name = collection_name
        if role != "admin":
            from shared.zta_roles import ZTA_ROLES
            role_config = ZTA_ROLES.get(role, {})
            allowed = role_config.get("allowed_collections", [])
            if collection_name not in allowed:
                return jsonify({
                    "status": "error",
                    "error_type": "authorization_denied",
                    "message": f"OPA/RBAC Access Denied: Role '{role}' is not allowed to access collection '{collection_name}'",
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
                        authMechanismProperties={"OIDC_CALLBACK": callback_instance},
                        serverSelectionTimeoutMS=8000
                    )
                else:
                    client = MongoClient(
                        f"mongodb://envoy:10000/{mongo_db_name}?authSource=$external&authMechanism=MONGODB-OIDC&directConnection=true",
                        authMechanismProperties={"OIDC_CALLBACK": callback_instance},
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
            cursor = db[view_name].find(query_filter).limit(limit)
            
            from bson import json_util
            results = list(cursor)
            results_json = json.loads(json_util.dumps(results))
            client.close()

            return jsonify({
                "status": "success",
                "role": role,
                "translated_collection": view_name,
                "count": len(results_json),
                "results": results_json
            })

        except OperationFailure as e:
            err_msg = e.details.get("errmsg", str(e)) if e.details else str(e)
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
