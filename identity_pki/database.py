import os
import json
import logging
from typing import Optional, Any
from datetime import datetime, timezone
from pymongo import MongoClient as RealMongoClient
from pymongo.errors import OperationFailure
from .pki import PKIService

class MongoClientProxy:
    def __new__(cls, *args, **kwargs):
        import sys
        app_module = sys.modules.get('identity_pki.app')
        if app_module and hasattr(app_module, 'MongoClient'):
            return app_module.MongoClient(*args, **kwargs)
        return RealMongoClient(*args, **kwargs)

MongoClient = MongoClientProxy

def provision_mongo_user(service: PKIService, logger: logging.Logger, username: str, role: str) -> None:
    """Auto-provisions a MongoDB SCRAM and external OIDC user with role permissions."""
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
        
        # Load ZTA roles
        try:
            from shared.zta_roles import ZTA_ROLES
        except ImportError:
            ZTA_ROLES = {}
            
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


def build_mongo_client(user_cn: str, mongo_db_name: str, local_proxy_port: Optional[int], jwt_token: Optional[str], combined_pem_path: Optional[str], ca_path: str) -> MongoClient:
    """Build and configure the MongoClient based on credentials and proxy settings."""
    mongo_root_user = os.environ.get("MONGO_ROOT_USERNAME", "admin")
    mongo_root_pass = os.environ.get("MONGO_ROOT_PASSWORD", "secret")
    
    if jwt_token:
        from pymongo.auth_oidc import OIDCCallback, OIDCCallbackResult

        class StaticTokenCallback(OIDCCallback):
            def __init__(self, token):
                self.token = token
            def fetch(self, context):
                return OIDCCallbackResult(access_token=self.token)

        callback_instance = StaticTokenCallback(jwt_token)

        if local_proxy_port:
            return MongoClient(
                f"mongodb://host.docker.internal:{local_proxy_port}/{mongo_db_name}?authSource=$external&authMechanism=MONGODB-OIDC&directConnection=true",
                authMechanismProperties={
                    "OIDC_CALLBACK": callback_instance,
                    "authzId": f"oidc/{user_cn}"
                },
                serverSelectionTimeoutMS=8000
            )
        else:
            return MongoClient(
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
            return MongoClient(
                f"mongodb://{mongo_root_user}:{mongo_root_pass}@host.docker.internal:{local_proxy_port}/{mongo_db_name}?authSource=admin&directConnection=true",
                serverSelectionTimeoutMS=8000
            )
        else:
            return MongoClient(
                f"mongodb://{mongo_root_user}:{mongo_root_pass}@envoy:10000/{mongo_db_name}?authSource=admin&directConnection=true",
                tls=True,
                tlsCertificateKeyFile=combined_pem_path,
                tlsCAFile=ca_path,
                tlsAllowInvalidCertificates=True,
                serverSelectionTimeoutMS=4000
            )


def execute_mongo_operation(db, mongo_action: str, target_collection: str, query_filter: dict, update_fields: Optional[dict], limit: int) -> tuple[int, list, str]:
    """Execute the database action (find, update, delete) and return status/results."""
    results_json = []
    count = 0
    message = "Success"

    if mongo_action == "find":
        cursor = db[target_collection].find(query_filter).limit(limit)
        from bson import json_util
        results = list(cursor)
        results_json = json.loads(json_util.dumps(results))
        count = len(results_json)
    elif mongo_action == "update":
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
        raise ValueError(f"Unsupported action: {mongo_action}")

    return count, results_json, message


def prepare_combined_pem(service: PKIService, user_cn: str, cert_path: str, key_path: str, jwt_token: Optional[str]) -> str:
    """Prepares and writes the combined PEM cert+key file for TLS connections."""
    if jwt_token and (not os.path.exists(key_path) or not os.path.exists(cert_path)):
        # Hardware mode OIDC connection from Flask to Envoy: use Flask's own server cert/key
        cert_path = "/data/server/envoy.crt"
        key_path = "/data/server/envoy.key"
        combined_pem_path = os.path.join(service.cert_dir, "client", "envoy_combined.pem")
    else:
        combined_pem_path = os.path.join(service.cert_dir, "client", f"{user_cn}_combined.pem")
        
    with open(combined_pem_path, "w") as out:
        with open(cert_path) as c:
            out.write(c.read())
        with open(key_path) as k:
            out.write(k.read())
            
    return combined_pem_path
