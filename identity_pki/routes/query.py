"""Data querying operations targeting MongoDB through Envoy sidecars."""

import os
import sys
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
from pymongo.errors import OperationFailure

from ..auth import (
    check_action_permissions as _check_action_permissions,
    get_rls_view_name as _get_rls_view_name,
    resolve_user_metadata as _resolve_user_metadata,
)
from ..database import (
    prepare_combined_pem as _prepare_combined_pem,
)
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

query_bp = Blueprint("query", __name__)


@query_bp.get("/health")
def health():
    return jsonify({"status": "ok"})


@query_bp.post("/api/query")
def api_query():
    """Execute a MongoDB query via Envoy presenting the user's client certificate."""
    import uuid
    request_id = str(uuid.uuid4())
    response = None
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
        return error_response("User CN and collection name are mandatory.", 400)

    service = current_app.config["pki_service"]

    # Check if user is revoked
    if os.path.exists(os.path.join(service.revoked_dir, f"{user_cn}.rev")):
        return error_response("Identity revoked or suspended by administrator.", 401)

    if not jwt_token:
        return error_response(
            "OIDC authentication mandatory. Legacy authentication (SCRAM/Password) is disabled.",
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
        return error_response(f"Credentials not found for user '{user_cn}'. Please register the user first.", 404)

    if not jwt_token and not local_proxy_port and not os.path.exists(key_path):
        return error_response(
            f"User '{user_cn}' is registered in Hardware Bound mode (TPM/Secure Enclave). "
            f"The private key resides securely on the client and is not available on the server. "
            f"To use this web console, register the user in Lab mode (/api/certificates) "
            f"so the server can host the key temporarily, or execute queries via "
            f"the hardware client CLI from your host computer.",
            403
        )

    combined_pem_path = None
    if not local_proxy_port:
        try:
            combined_pem_path = _prepare_combined_pem(service, user_cn, cert_path, key_path, jwt_token)
        except Exception as e:
            return error_response(f"Error preparing combined PEM: {e}", 500)

    # Resolve role and hardware_mode
    role, hardware_mode, device_info = _resolve_user_metadata(service, user_cn, cert_path, jwt_token, current_app.logger)

    # Translate collection to RLS view
    view_name = collection_name
    if role != "admin":
        role_config = ZTA_ROLES.get(role, {})
        allowed = role_config.get("allowed_collections", [])
        if collection_name not in allowed:
            return jsonify({
                "status": "error",
                "error_type": "authorization_denied",
                "message": f"Access denied (OPA/RBAC): Role '{role}' is not authorized to access collection '{collection_name}'.",
                "role": role,
                "translated_collection": view_name
            }), 403

        if not _check_action_permissions(role, collection_name, mongo_action):
            return jsonify({
                "status": "error",
                "error_type": "authorization_denied",
                "message": f"Access denied (OPA/RBAC): Role '{role}' is not authorized to execute '{mongo_action}' on collection '{collection_name}'.",
                "role": role,
                "translated_collection": view_name
            }), 403

        # Enforce that update operations on clinical_records contain patient_id in the query filter
        if collection_name == "clinical_records" and mongo_action == "update":
            if not query_filter.get("patient_id"):
                return jsonify({
                    "status": "error",
                    "error_type": "authorization_denied",
                    "message": "Access denied (OPA/RBAC): Non-compliant document (mandatory patient_id filter missing).",
                    "role": role,
                    "translated_collection": view_name
                }), 403

        view_name = _get_rls_view_name(role, collection_name)

    ca_path = os.path.join(service.cert_dir, "ca.crt")

    try:
        import requests
        from bson import json_util

        target_collection = view_name if mongo_action == "find" else collection_name

        # Prepare HTTP payload
        # NOTE: Do NOT include "mechanism": "MONGODB-OIDC" here.  That field
        # would trigger OPA's full OIDC token-binding verification via JWKS
        # fetch, which fails on TLS hostname mismatch between the cert CN and
        # the "identity-pki" server name.  The mongo_proxy already hardcodes
        # MONGODB-OIDC in its MongoDB connection string, so it doesn't need
        # this field from the payload.
        query_payload = {
            "command": mongo_action,
            "collection": target_collection,
            "query": query_filter,
            "update_fields": update_fields,
            "limit": limit,
            "user": user_cn,
            "role": role,
            "payload": jwt_token
        }

        # Serialize utilizing json_util to support BSON types (like ObjectIDs/dates)
        payload_data = json_util.dumps(query_payload)

        import logging
        logging.getLogger("werkzeug").info(f"[DEBUG] Envoy payload: {payload_data[:500]}...")

        headers = {
            "Content-Type": "application/json",
            "x-zta-user": user_cn,
            "x-zta-role": role,
            "Authorization": f"Bearer {jwt_token}",
            "x-request-id": request_id
        }

        if local_proxy_port:
            url = f"http://host.docker.internal:{local_proxy_port}/query"
            response = requests.post(url, data=payload_data, headers=headers, timeout=10)
        else:
            url = "https://envoy:10000/query"
            response = requests.post(
                url,
                data=payload_data,
                headers=headers,
                cert=combined_pem_path,
                verify=ca_path,
                timeout=10
            )

        if response.status_code != 200:
            err_msg = ""
            err_type = "query_failed"
            try:
                res_data = response.json()
                err_msg = res_data.get("message")
                err_type = res_data.get("error_type", "query_failed")
            except Exception:
                pass
            
            if not err_msg:
                # Fallback to checking Envoy/OPA response headers
                decision = response.headers.get("x-zta-decision")
                if response.status_code == 403 or decision == "DENY":
                    err_type = "authorization_denied"
                    block_reason = response.headers.get("x-zta-block-reason")
                    if block_reason and block_reason != "none":
                        if block_reason == "RISK_THRESHOLD_EXCEEDED":
                            err_msg = "Access denied: the calculated risk level exceeds the permitted threshold."
                        elif block_reason == "STEP_UP_REQUIRED":
                            err_msg = "Secondary (Step-up) authentication required. Please perform Touch ID / Windows Hello verification to proceed."
                        elif block_reason == "STEP_UP_STALE":
                            err_msg = "Biometric session expired. Please re-authenticate on your device."
                        elif block_reason == "RBAC_DENIED":
                            err_msg = f"Insufficient permissions. Role '{role}' does not have access to collection '{collection_name}' for operation '{mongo_action}'."
                        elif block_reason == "ROLE_SEGREGATION_DENIED":
                            err_msg = "Segregation of Duties violation: Access to this resource is blocked for organizational reasons."
                        elif block_reason == "INSPECTION_VIOLATION":
                            if role == "doctor" and collection_name == "clinical_records" and mongo_action == "update" and not query_filter.get("patient_id"):
                                err_msg = "Doctors are required to specify the patient_id filter when updating clinical records."
                            else:
                                err_msg = "Non-compliant request: L7 security checks blocked the query."
                        elif block_reason == "OIDC_TOKEN_INVALID":
                            err_msg = "Invalid or expired authentication session. Please perform hardware login again."
                        elif block_reason == "UNAUTHENTICATED":
                            err_msg = "Unidentified user or unregistered certificate."
                        else:
                            err_msg = f"Access denied: Zero Trust Decision (Reason: {block_reason})."
                    else:
                        if role == "doctor" and collection_name == "clinical_records" and mongo_action == "update" and not query_filter.get("patient_id"):
                            err_msg = "OPA/RBAC Access Denied: Doctors are required to filter by patient_id when updating clinical records."
                        else:
                            err_msg = f"OPA/RBAC Access Denied: Zero Trust policy decision (User '{user_cn}', Role '{role}', Action '{mongo_action}', Collection '{collection_name}')."
                else:
                    err_msg = response.text or f"HTTP {response.status_code}"
            
            # Remove "Mongo HTTP Proxy error: " prefix for client blocks to keep UI clean and user-friendly
            display_msg = err_msg if err_type in {"waf_blocked", "policy_denied", "authorization_denied"} else f"Mongo HTTP Proxy error: {err_msg}"
            
            return jsonify({
                "status": "error",
                "error_type": err_type,
                "message": display_msg,
                "role": role,
                "translated_collection": view_name
            }), response.status_code

        res_data = response.json()
        count = res_data.get("count", 0)
        results_json = res_data.get("results", [])
        message = res_data.get("message", "Success")

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
