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
    build_mongo_client as _build_mongo_client,
    execute_mongo_operation as _execute_mongo_operation,
    prepare_combined_pem as _prepare_combined_pem,
)
from ..audit import send_audit_event_impl as _send_audit_event_impl
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

    service = current_app.config["pki_service"]

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

    def _send_audit_event(*args, **kwargs):
        _send_audit_event_impl(current_app.logger, *args, **kwargs)

    combined_pem_path = None
    if not local_proxy_port:
        try:
            combined_pem_path = _prepare_combined_pem(service, user_cn, cert_path, key_path, jwt_token)
        except Exception as e:
            return error_response(f"Failed to prepare combined PEM: {e}", 500)

    # Resolve role and hardware_mode
    role, hardware_mode = _resolve_user_metadata(service, user_cn, cert_path, jwt_token, current_app.logger)

    # Translate collection to RLS view
    view_name = collection_name
    if role != "admin":
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

        # Action-level permission check
        if not _check_action_permissions(role, collection_name, mongo_action):
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

        view_name = _get_rls_view_name(role, collection_name)

    mongo_db_name = os.environ.get("MONGO_INITDB_DATABASE", "zta_db")
    ca_path = os.path.join(service.cert_dir, "ca.crt")

    try:
        client = _build_mongo_client(user_cn, mongo_db_name, local_proxy_port, jwt_token, combined_pem_path, ca_path)
        db = client[mongo_db_name]
        
        target_collection = view_name if mongo_action == "find" else collection_name
        count, results_json, message = _execute_mongo_operation(
            db, mongo_action, target_collection, query_filter, update_fields, limit
        )
            
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
