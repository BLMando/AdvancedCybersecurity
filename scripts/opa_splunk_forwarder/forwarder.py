"""
Envoy-to-Splunk Forwarder + Stats API for OPA

Responsibilities:
  1) Forward Envoy access logs to Splunk HEC.
  2) Expose a lightweight stats endpoint that OPA can query to enrich
     risk evaluation with recent activity from Splunk.

OPA must not send decision logs to Splunk.
"""

import atexit
import json
import logging
import os
import threading
import urllib.parse
import urllib.request
from pathlib import Path

from flask import Flask, request, jsonify
from heclient import HEClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("forwarder")

app = Flask(__name__)

hec_envoy = HEClient(
    host=os.environ.get("SPLUNK_HOST", "splunk"),
    port=int(os.environ.get("SPLUNK_HEC_PORT", "8088")),
    token=os.environ.get("SPLUNK_HEC_TOKEN_ENVOY", ""),
    batch_size=int(os.environ.get("HEC_BATCH_SIZE", "100")),
)

ENVOY_LOG_PATH = Path("/var/log/envoy/access.log")
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "splunk")
SPLUNK_MGMT_PORT = int(os.environ.get("SPLUNK_MGMT_PORT", "8089"))
SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
SPLUNK_SEARCH_VERIFY_TLS = os.environ.get("SPLUNK_SEARCH_VERIFY_TLS", "false").lower() == "true"


def extract_envoy_fields(log_entry: dict) -> dict:
    return {
        "source_ip": log_entry.get("downstream_remote_address", "unknown"),
        "downstream_local": log_entry.get("downstream_local_address", "unknown"),
        "upstream_host": log_entry.get("upstream_host", "unknown"),
        "duration_ms": log_entry.get("duration", "0"),
        "bytes_sent": log_entry.get("bytes_sent", "0"),
        "bytes_received": log_entry.get("bytes_received", "0"),
        "user": log_entry.get("user", "unknown"),
        "device": log_entry.get("device", "no-tpm"),
        "network_ip": log_entry.get("network_ip", "0.0.0.0"),
        "resource": log_entry.get("resource", "unknown"),
        "command": log_entry.get("command", "unknown"),
        "decision": log_entry.get("decision", "unknown"),
        "risk_score": log_entry.get("risk_score", "0"),
    }


def _splunk_query_count(search: str) -> int:
    """
    Run a one-shot Splunk search and return the resulting count.
    """
    base_url = f"https://{SPLUNK_HOST}:{SPLUNK_MGMT_PORT}/services/search/jobs/export"
    query = f"search {search} | stats count"
    form = urllib.parse.urlencode(
        {
            "search": query,
            "output_mode": "json",
            "exec_mode": "oneshot",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        base_url,
        data=form,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    if not SPLUNK_SEARCH_VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, base_url, SPLUNK_USERNAME, SPLUNK_PASSWORD)
    auth_handler = urllib.request.HTTPBasicAuthHandler(password_manager)
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(auth_handler, https_handler)

    with opener.open(req, timeout=5) as resp:
        raw = resp.read().decode("utf-8").strip()

    # Splunk export endpoint may emit one JSON object per line.
    count_val = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = obj.get("result") or {}
        if "count" in result:
            try:
                count_val = int(result["count"])
            except Exception:
                pass
    return count_val


def _build_stats_search(user: str, network_ip: str, device: str, resource: str, command: str) -> str:
    """
    Build constrained query scoped to Envoy index.
    """
    def esc(value: str) -> str:
        return str(value or "unknown").replace('"', '\\"')

    # We include all identity dimensions present in the request; this keeps
    # the risk statistics context-specific.
    return (
        'index=zta_envoy earliest=-15m '
        f'user="{esc(user)}" '
        f'network_ip="{esc(network_ip)}" '
        f'device="{esc(device)}" '
        f'resource="{esc(resource)}" '
        f'command="{esc(command)}"'
    )


@app.route("/api/stats", methods=["POST"])
def handle_stats_query():
    """
    Called by OPA policy via http.send.
    Input: {user, network_ip, device, resource, command}
    Output: stats + derived risk boost.
    """
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "invalid json"}), 400

    user = str(body.get("user", "unknown"))
    network_ip = str(body.get("network_ip", "0.0.0.0"))
    device = str(body.get("device", "no-tpm"))
    resource = str(body.get("resource", "unknown"))
    command = str(body.get("command", "unknown"))

    if not SPLUNK_PASSWORD:
        logger.error("SPLUNK_PASSWORD is not configured; cannot query Splunk stats")
        return jsonify({"error": "splunk credentials not configured"}), 500

    try:
        search = _build_stats_search(user, network_ip, device, resource, command)
        event_count_15m = _splunk_query_count(search)
    except Exception as e:
        logger.error("Failed querying Splunk stats: %s", e)
        return jsonify({"error": "splunk query failed"}), 502

    # Simple risk boost model driven by observed recent frequency.
    if event_count_15m >= 200:
        risk_boost = 20
    elif event_count_15m >= 100:
        risk_boost = 10
    elif event_count_15m >= 50:
        risk_boost = 5
    else:
        risk_boost = 0

    return jsonify(
        {
            "stats": {
                "event_count_15m": event_count_15m,
            },
            "risk_boost": risk_boost,
        }
    ), 200


def tail_envoy_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the Envoy access log file."""
    logger.info("Envoy log tailer started, watching: %s", ENVOY_LOG_PATH)
    last_position = 0

    while not stop_event.is_set():
        try:
            if ENVOY_LOG_PATH.exists():
                current_size = ENVOY_LOG_PATH.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    with open(ENVOY_LOG_PATH, "r") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                log_entry = json.loads(line)
                                fields = extract_envoy_fields(log_entry)
                                hec_envoy.send_event(
                                    fields,
                                    index="zta_envoy",
                                    sourcetype="envoy:access",
                                )
                            except json.JSONDecodeError:
                                logger.warning("Skipping invalid JSON line from Envoy log")
                        last_position = f.tell()
                    hec_envoy.flush()
            else:
                logger.debug("Envoy log file not yet available: %s", ENVOY_LOG_PATH)
        except Exception as e:
            logger.error("Error tailing Envoy log: %s", e)

        stop_event.wait(timeout=2.0)

    logger.info("Envoy log tailer stopped")


MONGO_AUDIT_LOG_PATH = Path("/var/log/mongodb/audit.json")

def tail_mongo_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the MongoDB audit log file."""
    logger.info("MongoDB audit log tailer started, watching: %s", MONGO_AUDIT_LOG_PATH)
    last_position = 0

    while not stop_event.is_set():
        try:
            if MONGO_AUDIT_LOG_PATH.exists():
                current_size = MONGO_AUDIT_LOG_PATH.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    with open(MONGO_AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                log_entry = json.loads(line)
                                hec_envoy.send_event(
                                    log_entry,
                                    index="zta_envoy",
                                    sourcetype="mongo:audit",
                                )
                            except json.JSONDecodeError:
                                pass
                        last_position = f.tell()
                    hec_envoy.flush()
            else:
                logger.debug("MongoDB audit log file not yet available: %s", MONGO_AUDIT_LOG_PATH)
        except Exception as e:
            logger.error("Error tailing MongoDB audit log: %s", e)

        stop_event.wait(timeout=2.0)

    logger.info("MongoDB audit log tailer stopped")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/envoy-logs", methods=["POST"])
def handle_envoy_log():
    try:
        body = request.get_json(force=True)
        logger.debug("Received Envoy log: %s", json.dumps(body)[:500])
    except Exception:
        logger.warning("Invalid JSON from Envoy")
        return jsonify({"error": "invalid json"}), 400

    fields = extract_envoy_fields(body)
    hec_envoy.send_event(fields, index="zta_envoy", sourcetype="envoy:access")
    return jsonify({"status": "queued"}), 202


_stop_event = threading.Event()
_TAILER_LOCK = Path("/tmp/envoy_tailer.lock")


def _ensure_tailer():
    """Start the log tailers once per host (avoids duplication under Gunicorn)."""
    try:
        _TAILER_LOCK.touch(exist_ok=False)
        
        t1 = threading.Thread(target=tail_envoy_logs, args=(_stop_event,), daemon=True)
        t1.start()
        
        t2 = threading.Thread(target=tail_mongo_logs, args=(_stop_event,), daemon=True)
        t2.start()
        
        logger.info("Log tailers started (lock acquired)")
    except FileExistsError:
        logger.debug("Log tailers already running in another worker (lock exists)")
    except Exception as e:
        logger.error("Failed to start log tailers: %s", e)


atexit.register(lambda: _TAILER_LOCK.unlink(missing_ok=True))

# Start the tailer at import time — the file-level lock guarantees
# only one Gunicorn worker actually starts the background thread.
_ensure_tailer()


def main():
    port = int(os.environ.get("FORWARDER_PORT", "5000"))
    logger.info("Starting OPA Splunk Forwarder on port %d", port)
    try:
        app.run(host="0.0.0.0", port=port, debug=False)
    finally:
        _stop_event.set()


if __name__ == "__main__":
    main()
