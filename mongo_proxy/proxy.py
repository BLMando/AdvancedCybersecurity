import os
import json
import logging
import ssl
from flask import Flask, request, jsonify
from pymongo import MongoClient
from pymongo.errors import OperationFailure
from pymongo.auth_oidc import OIDCCallback, OIDCCallbackResult
from bson import json_util

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("mongo_proxy")

app = Flask(__name__)

MONGO_DB_NAME = os.environ.get("MONGO_INITDB_DATABASE", "zta_db")
CA_PATH = "/etc/certs/ca/ca.crt"
CLIENT_PEM_PATH = "/etc/certs/server/mongo.pem" # server cert & key

class StaticTokenCallback(OIDCCallback):
    def __init__(self, token):
        self.token = token
    def fetch(self, context):
        return OIDCCallbackResult(access_token=self.token)

def build_client(jwt_token, user_cn):
    # Connect to MongoDB via OIDC
    callback_instance = StaticTokenCallback(jwt_token)
    return MongoClient(
        f"mongodb://mongo:27017/{MONGO_DB_NAME}?authSource=$external&authMechanism=MONGODB-OIDC&directConnection=true",
        authMechanismProperties={
            "OIDC_CALLBACK": callback_instance,
            "authzId": f"oidc/{user_cn}"
        },
        tls=True,
        tlsCertificateKeyFile=CLIENT_PEM_PATH,
        tlsCAFile=CA_PATH,
        tlsAllowInvalidCertificates=True,
        serverSelectionTimeoutMS=4000
    )

@app.route("/query", methods=["POST"])
def handle_query():
    try:
        payload = request.get_json() or {}
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

    user_cn = payload.get("user")
    jwt_token = payload.get("jwt_token") or payload.get("payload")
    action = payload.get("command") or payload.get("action", "find")
    collection_name = payload.get("collection")
    query_filter = payload.get("query") or payload.get("filter") or {}
    limit = int(payload.get("limit", 10))
    update_fields = payload.get("update_fields")

    if not collection_name:
        return jsonify({"status": "error", "message": "Collection name is required"}), 400

    if not jwt_token:
        return jsonify({"status": "error", "message": "Authentication token is required"}), 401

    try:
        client = build_client(jwt_token, user_cn)
        db = client[MONGO_DB_NAME]
        
        results_json = []
        count = 0
        message = "Success"

        # Deserialize Extended JSON formats (like {"$oid": "..."})
        query_filter = json_util.loads(json_util.dumps(query_filter))

        if action == "find":
            cursor = db[collection_name].find(query_filter).limit(limit)
            results = list(cursor)
            results_json = json.loads(json_util.dumps(results))
            count = len(results_json)
        elif action == "insert":
            doc = payload.get("document") or query_filter
            doc = json_util.loads(json_util.dumps(doc))
            res = db[collection_name].insert_one(doc)
            results_json = [{"_id": str(res.inserted_id)}]
            count = 1
            message = f"Inserted document with id {res.inserted_id}"
        elif action == "update":
            if update_fields and isinstance(update_fields, dict):
                update_fields = json_util.loads(json_util.dumps(update_fields))
                # Sanitize: strip leading $ from keys to prevent operator injection
                safe_fields = {k: v for k, v in update_fields.items() if not k.startswith("$")}
                if collection_name != "providers":
                    from datetime import datetime, timezone
                    set_payload = {**safe_fields, "updated_at": datetime.now(timezone.utc)}
                else:
                    set_payload = safe_fields
            else:
                if collection_name != "providers":
                    from datetime import datetime, timezone
                    set_payload = {"updated_at": datetime.now(timezone.utc)}
                else:
                    set_payload = {}
            
            if set_payload:
                update_op = {"$set": set_payload}
                res = db[collection_name].update_many(query_filter, update_op)
                count = res.modified_count
            else:
                count = 0
            message = f"Aggiornati {count} documenti in '{collection_name}'"
        elif action == "delete":
            res = db[collection_name].delete_many(query_filter)
            count = res.deleted_count
            message = f"Eliminati {count} documenti da '{collection_name}'"
        elif action == "aggregate":
            pipeline = payload.get("pipeline", [])
            pipeline = json_util.loads(json_util.dumps(pipeline))
            results = list(db[collection_name].aggregate(pipeline))
            results_json = json.loads(json_util.dumps(results))
            count = len(results_json)
        else:
            client.close()
            return jsonify({"status": "error", "message": f"Unsupported action: {action}"}), 400

        client.close()
        return jsonify({
            "status": "success",
            "count": count,
            "results": results_json,
            "message": message
        })

    except OperationFailure as e:
        err_msg = e.details.get("errmsg", str(e)) if e.details else str(e)
        logger.error("MongoDB Operation Failure: %s", err_msg)
        return jsonify({
            "status": "error",
            "error_type": "authorization_denied",
            "message": f"MongoDB Access Denied: {err_msg}"
        }), 403
    except Exception as e:
        logger.exception("Error executing Mongo operation")
        return jsonify({
            "status": "error",
            "error_type": "connection_failed",
            "message": f"Connection failed: {e}"
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get("PROXY_PORT", "5001"))
    
    # Configure mTLS for the Flask HTTPS server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CLIENT_PEM_PATH)
    context.load_verify_locations(cafile=CA_PATH)
    context.verify_mode = ssl.CERT_REQUIRED
    
    logger.info("Starting Custom MongoDB HTTP Proxy under mTLS on port %d", port)
    app.run(host="0.0.0.0", port=port, ssl_context=context)
