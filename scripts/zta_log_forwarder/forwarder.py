import atexit
import json
import logging
import os
import threading
from pathlib import Path

from flask import Flask, request, jsonify
from heclient import HEClient

# Import extracted modules
from parsers import (
    extract_envoy_fields,
    extract_snort_fields,
    extract_mongo_fields,
    parse_nftables_line,
)
from risk import calculate_risk_boost
from splunk_search import run_splunk_search, SPLUNK_PASSWORD

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
SNORT_LOG_PATH = Path("/var/log/snort/alert_json.txt")
NFTABLES_LOG_PATH = Path("/var/log/nftables/nft.log")
MONGO_LOG_PATH = Path("/var/log/mongodb/mongod.log")
MONGO_AUDIT_PATH = Path("/var/log/mongodb/audit.json")


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

    # Costruiamo una singola query di aggregazione che copre tutti i vettori di rischio degli ultimi 15m
    esc = lambda s: s.replace('"', '\\"')
    splunk_query = (
        f'search (index=zta_envoy earliest=-15m) '
        f'OR (index=zta_snort src_addr="{esc(network_ip)}" earliest=-15m) '
        f'OR (index=zta_nftables action=DROP src_ip="{esc(network_ip)}" earliest=-15m) '
        f'OR (index=zta_mongodb_audit atype=authenticate result!=0 param.user="{esc(user)}" earliest=-15m) '
        f'| eval eta_min = (now() - _time) / 60 '
        f'| eval peso = if(index="zta_envoy", 1.0, exp(-0.231 * eta_min)) '
        f'| eval type=case('
        f'  index="zta_envoy" AND sourcetype="zta:app:query" AND decision="DENY" AND user="{esc(user)}", "user_denies",'
        f'  index="zta_envoy" AND sourcetype="zta:app:query" AND decision="ALLOW" AND user="{esc(user)}", "user_allows",'
        f'  index="zta_snort", "snort_alerts",'
        f'  index="zta_nftables", "nftables_drops",'
        f'  index="zta_mongodb_audit", "mongo_failures"'
        f') '
        f'| stats sum(peso) as weighted_score by type'
    )

    # Inizializziamo i contatori a zero
    counts = {
        "user_allows": 0.0,
        "user_denies": 0.0,
        "snort_alerts": 0.0,
        "nftables_drops": 0.0,
        "mongo_failures": 0.0
    }

    try:
        results = run_splunk_search(splunk_query)
        for res in results:
            t = res.get("type")
            c = res.get("weighted_score")
            if t in counts and c:
                try:
                    counts[t] = float(c)
                except ValueError:
                    pass
    except Exception as e:
        logger.error("Failed querying Splunk stats: %s", e)
        return jsonify({"error": "splunk query failed"}), 502

    # 2. Query 2: User Baseline Anomaly Detection over 7 Days (earliest=-7d)
    z_score = 0.0
    baseline_media = 0.0
    baseline_std = 0.0
    current_count = 0.0

    baseline_query = (
        f'search index=zta_envoy sourcetype="zta:app:query" user="{esc(user)}" earliest=-7d '
        f'| eval is_current = if(_time >= now() - 900, 1, 0) '
        f'| bucket _time span=15m '
        f'| stats count as query_count by _time, is_current '
        f'| stats avg(query_count) as media, stdev(query_count) as dev_std, max(eval(if(is_current=1, query_count, 0))) as current_count '
        f'| eval z_score = if(dev_std > 0, (current_count - media) / dev_std, 0)'
    )

    try:
        baseline_results = run_splunk_search(baseline_query)
        if baseline_results:
            res = baseline_results[0]
            z_score = float(res.get("z_score", 0.0) or 0.0)
            baseline_media = float(res.get("media", 0.0) or 0.0)
            baseline_std = float(res.get("dev_std", 0.0) or 0.0)
            current_count = float(res.get("current_count", 0.0) or 0.0)
            logger.info(
                "User %s 7d baseline: avg=%.2f, std=%.2f, current=%.2f, z_score=%.2f",
                user, baseline_media, baseline_std, current_count, z_score
            )
    except Exception as e:
        logger.warning("Failed querying Splunk user baseline (non-critical): %s", e)

    # Calcolo del risk boost combinato (multi-vettore)
    risk_boost = calculate_risk_boost(counts, z_score)

    return jsonify(
        {
            "stats": counts,
            "risk_boost": risk_boost,
            "z_score": z_score,
            "baseline_media": baseline_media,
            "baseline_std": baseline_std,
            "current_count": current_count
        }
    ), 200


def tail_log_file(path: Path, stop_event: threading.Event, line_handler, post_batch_handler=None, sleep_interval=2.0) -> None:
    """Generic helper to tail a log file, calling line_handler for each line and optionally post_batch_handler."""
    logger.info("Log tailer started, watching: %s", path)
    last_position = 0
    while not stop_event.is_set():
        try:
            if path.exists():
                current_size = path.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    has_lines = False
                    with open(path, "r") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if line:
                                has_lines = True
                                line_handler(line)
                        last_position = f.tell()
                    if has_lines and post_batch_handler:
                        post_batch_handler()
            else:
                logger.debug("Log file not yet available: %s", path)
        except Exception as e:
            logger.error("Error tailing log %s: %s", path, e)
        stop_event.wait(timeout=sleep_interval)
    logger.info("Log tailer stopped: %s", path)


def tail_envoy_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the Envoy access log file."""
    def handle_line(line: str) -> None:
        try:
            log_entry = json.loads(line)
            fields = extract_envoy_fields(log_entry)
            hec_envoy.send_event(fields, index="zta_envoy", sourcetype="envoy:access")
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON line from Envoy log")

    tail_log_file(
        path=ENVOY_LOG_PATH,
        stop_event=stop_event,
        line_handler=handle_line,
        post_batch_handler=hec_envoy.flush
    )


def tail_snort_logs(path: Path, sensor: str, stop_event: threading.Event) -> None:
    """Background thread that tails a Snort 3 alert_json log file."""
    def handle_line(line: str) -> None:
        try:
            log_entry = json.loads(line)
            fields = extract_snort_fields(log_entry)
            fields["sensor"] = sensor
            hec_envoy.send_event(fields, index="zta_snort", sourcetype="snort:alert_json")
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON from Snort [%s] log", sensor)

    tail_log_file(
        path=path,
        stop_event=stop_event,
        line_handler=handle_line,
        post_batch_handler=hec_envoy.flush
    )


def tail_nftables_logs(stop_event: threading.Event) -> None:
    """Background thread that tails nftables kernel log output."""
    def handle_line(line: str) -> None:
        fields = parse_nftables_line(line)
        if fields:
            hec_envoy.send_event(fields, index="zta_nftables", sourcetype="nftables:log")

    tail_log_file(
        path=NFTABLES_LOG_PATH,
        stop_event=stop_event,
        line_handler=handle_line,
        post_batch_handler=hec_envoy.flush
    )


def tail_mongo_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the MongoDB log file."""
    def handle_line(line: str) -> None:
        try:
            log_entry = json.loads(line)
            fields = extract_mongo_fields(log_entry)
            hec_envoy.send_event(fields, index="zta_mongodb", sourcetype="mongodb:json")
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON from MongoDB log")

    tail_log_file(
        path=MONGO_LOG_PATH,
        stop_event=stop_event,
        line_handler=handle_line,
        post_batch_handler=hec_envoy.flush
    )


def tail_mongo_audit_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the MongoDB Audit log file."""
    def handle_line(line: str) -> None:
        try:
            log_entry = json.loads(line)
            hec_envoy.send_event(log_entry, index="zta_mongodb_audit", sourcetype="mongodb:audit")
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON from MongoDB Audit log")

    tail_log_file(
        path=MONGO_AUDIT_PATH,
        stop_event=stop_event,
        line_handler=handle_line,
        post_batch_handler=hec_envoy.flush
    )


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


@app.route("/api/audit", methods=["POST"])
def handle_app_audit():
    """Receive application-level audit events from Flask and forward to Splunk.

    Unlike Envoy access logs (which only capture connection-level metadata),
    this endpoint receives the *actual* query details (collection, command,
    filter, result) from the Flask application layer after each /api/query
    execution.  Events are indexed separately as sourcetype 'zta:app:query'
    so Splunk dashboards can correlate them with Envoy connection logs.
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid json"}), 400

    event = {
        "timestamp": body.get("timestamp", ""),
        "user": body.get("user", "unknown"),
        "role": body.get("role", "unknown"),
        "resource": body.get("resource", "unknown"),
        "command": body.get("command", "unknown"),
        "translated_view": body.get("translated_view", "unknown"),
        "filter": body.get("filter", "{}"),
        "decision": body.get("decision", "unknown"),
        "count": body.get("count", 0),
        "error_type": body.get("error_type", ""),
        "message": body.get("message", ""),
        "jwt_auth": body.get("jwt_auth", False),
        "hardware_mode": body.get("hardware_mode", False),
        "risk_score": body.get("risk_score", 0),
    }

    hec_envoy.send_event(event, index="zta_envoy", sourcetype="zta:app:query")
    logger.info(
        "App audit: user=%s role=%s cmd=%s resource=%s decision=%s",
        event["user"], event["role"], event["command"],
        event["resource"], event["decision"],
    )
    return jsonify({"status": "queued"}), 202


_stop_event = threading.Event()
_TAILER_LOCK = Path("/tmp/envoy_tailer.lock")


def _ensure_tailer():
    """Start background sync and log tailing once per host."""
    try:
        _TAILER_LOCK.touch(exist_ok=False)
        # Thread: Envoy logs
        t = threading.Thread(target=tail_envoy_logs, args=(_stop_event,), daemon=True)
        t.start()
        logger.info("Envoy log tailer started (lock acquired)")

        # Thread: Snort logs (PEP)
        t_snort_pep = threading.Thread(
            target=tail_snort_logs, 
            args=(Path("/var/log/snort-pep/alert_json.txt"), "pep", _stop_event), 
            daemon=True
        )
        t_snort_pep.start()
        logger.info("Snort PEP log tailer started")

        # Thread: Snort logs (Resource)
        t_snort_res = threading.Thread(
            target=tail_snort_logs, 
            args=(Path("/var/log/snort-resource/alert_json.txt"), "resource", _stop_event), 
            daemon=True
        )
        t_snort_res.start()
        logger.info("Snort Resource log tailer started")

        # Thread: nftables logs
        t_nft = threading.Thread(target=tail_nftables_logs, args=(_stop_event,), daemon=True)
        t_nft.start()
        logger.info("nftables log tailer started")

        # Thread: MongoDB logs
        t_mongo = threading.Thread(target=tail_mongo_logs, args=(_stop_event,), daemon=True)
        t_mongo.start()
        logger.info("MongoDB log tailer started")

        # Thread: MongoDB Audit logs
        t_mongo_audit = threading.Thread(target=tail_mongo_audit_logs, args=(_stop_event,), daemon=True)
        t_mongo_audit.start()
        logger.info("MongoDB Audit log tailer started")
    except FileExistsError:
        logger.debug("Log tailer/sync already running in another worker (lock exists)")
    except Exception as e:
        logger.error("Failed to start log tailer/sync: %s", e)


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
