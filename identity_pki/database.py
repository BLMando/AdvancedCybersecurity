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
        MONGO_USER = os.getenv("MONGO_ROOT_USERNAME", "zta_user")
        MONGO_PASS = os.getenv("MONGO_ROOT_PASSWORD", "zta_password")
        MONGO_DB = os.getenv("MONGO_DATABASE", "zta_db")
        ca_path = os.path.join(service.cert_dir, "ca.crt")
        
        client = MongoClient(
            f"mongodb://{MONGO_USER}:{MONGO_PASS}@mongo:27017/admin",
            serverSelectionTimeoutMS=2000,
            tls=True,
            tlsCertificateKeyFile="/data/server/mongo.pem",
            tlsCAFile=ca_path,
            tlsAllowInvalidCertificates=True
        )
        db = client[MONGO_DB]
        
        # Load ZTA roles
        try:
            from shared.zta_roles import ZTA_ROLES
        except ImportError:
            ZTA_ROLES = {}
            
        role_config = ZTA_ROLES.get(role, {})
        mongo_role = role_config.get("mongo_role", "read")
        
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
                roles=[{"role": mongo_role, "db": MONGO_DB}]
            )
            logger.info(f"Auto-provisioned MongoDB external OIDC user '{oidc_username}' with role '{mongo_role}'")
        except Exception as ex:
            logger.warning(f"Failed to auto-provision external OIDC user '{oidc_username}': {ex}")

        client.close()
    except Exception as e:
        logger.warning(f"Failed to auto-provision MongoDB user '{username}': {e}")

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
