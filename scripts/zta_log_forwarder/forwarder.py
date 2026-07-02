import atexit
import json
import logging
import os
import threading
import fcntl
from pathlib import Path

from flask import Flask, request, jsonify
from heclient import HEClient

# Import extracted modules
from parsers import (
    extract_envoy_fields,
    extract_snort_fields,
    extract_mongo_fields,
    parse_nftables_line,
    extract_opa_decision_fields,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("forwarder")

app = Flask(__name__)

hec_envoy = HEClient(
    host="splunk",
    port=8088,
    token=os.environ.get("SPLUNK_HEC_TOKEN_ENVOY", ""),
    batch_size=int(os.environ.get("HEC_BATCH_SIZE", "100")),
)


# SIDs for automated L3/L4 blocking
AUTO_BLOCK_SIDS = {
    # Sonda PEP
    3000002,  # Possible SYN flood DDoS
    3000004,  # Internal lateral movement
    3000006,  # TCP SYN port scan targeting PEP
    # Sonda Risorsa
    4000001,  # Direct MongoDB access attempt (PEP bypass)
    4000002,  # MongoDB TCP connection flood
    4000003,  # Internal MongoDB port sweep
}

ENVOY_LOG_PATH = Path("/var/log/envoy/access.log")
SNORT_LOG_PATH = Path("/var/log/snort/alert_json.txt")
NFTABLES_LOG_PATH = Path("/var/log/nftables/nft.log")
MONGO_LOG_PATH = Path("/var/log/mongodb/mongod.log")
MONGO_AUDIT_PATH = Path("/var/log/mongodb/audit.json")


class LogCorrelator:
    """Correlates and merges OPA ALLOW logs with subsequent Lua WAF DENY logs in memory

    to ensure Splunk indexes a single consistent decision event per request.
    """
    def __init__(self, hec_client):
        self.hec_client = hec_client
        self.opa_logs = {}      # request_id -> fields
        self.waf_logs = {}      # request_id -> fields
        self.lock = threading.Lock()

    def add_log(self, fields):
        req_id = fields.get("request_id", "unknown")
        dec_id = fields.get("decision_id", "")
        
        if req_id == "unknown":
            self.hec_client.send_event(fields, index="zta_envoy", sourcetype="opa:decision")
            self.hec_client.flush()
            return

        is_lua = dec_id.startswith("lua-waf-")

        with self.lock:
            if is_lua:
                if req_id in self.opa_logs:
                    # OPA log is pending! Merge them and flush immediately
                    opa_fields = self.opa_logs.pop(req_id)
                    opa_fields["decision"] = "DENY"
                    opa_fields["block_reason"] = fields.get("block_reason", "WAF_BLOCKED")
                    self.hec_client.send_event(opa_fields, index="zta_envoy", sourcetype="opa:decision")
                    self.hec_client.flush()
                else:
                    # OPA log has not arrived yet, keep the WAF log
                    self.waf_logs[req_id] = fields
                    threading.Timer(5.0, self._flush_waf_fallback, args=[req_id]).start()
            else:
                if req_id in self.waf_logs:
                    # WAF log already arrived! Merge them and flush immediately
                    waf_fields = self.waf_logs.pop(req_id)
                    fields["decision"] = "DENY"
                    fields["block_reason"] = waf_fields.get("block_reason", "WAF_BLOCKED")
                    self.hec_client.send_event(fields, index="zta_envoy", sourcetype="opa:decision")
                    self.hec_client.flush()
                else:
                    # OPA log arrived first
                    if fields.get("decision") == "ALLOW":
                        # Buffer ALLOW decisions briefly to see if a WAF block comes
                        self.opa_logs[req_id] = fields
                        threading.Timer(1.5, self._flush_opa_fallback, args=[req_id]).start()
                    else:
                        # DENY decisions are sent immediately
                        self.hec_client.send_event(fields, index="zta_envoy", sourcetype="opa:decision")
                        self.hec_client.flush()

    def _flush_opa_fallback(self, req_id):
        with self.lock:
            if req_id in self.opa_logs:
                fields = self.opa_logs.pop(req_id)
                self.hec_client.send_event(fields, index="zta_envoy", sourcetype="opa:decision")
                self.hec_client.flush()

    def _flush_waf_fallback(self, req_id):
        with self.lock:
            if req_id in self.waf_logs:
                fields = self.waf_logs.pop(req_id)
                self.hec_client.send_event(fields, index="zta_envoy", sourcetype="opa:decision")
                self.hec_client.flush()


log_correlator = LogCorrelator(hec_envoy)


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


def auto_block_ip(ip: str) -> None:
    path = "/app/blocklist/blocklist.txt"
    try:
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                pass
        with open(path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            ips = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            if ip not in ips:
                f.seek(0, 2)
                f.write(f"{ip}\n")
                logger.info("IP %s automatically blocked due to severe Snort alert", ip)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        logger.error("Failed to auto-block IP %s: %s", ip, e)




def tail_snort_logs(path: Path, sensor: str, stop_event: threading.Event) -> None:
    """Background thread that tails a Snort 3 alert_json log file."""
    def handle_line(line: str) -> None:
        try:
            log_entry = json.loads(line)
            fields = extract_snort_fields(log_entry)
            fields["sensor"] = sensor
            hec_envoy.send_event(fields, index="zta_snort", sourcetype="snort:alert_json")

            src_addr = fields.get("src_addr", "0.0.0.0")
            sid = int(fields.get("sid", 0))
            if sid in AUTO_BLOCK_SIDS and src_addr not in ("0.0.0.0", "127.0.0.1", "localhost", "host.docker.internal"):
                auto_block_ip(src_addr)
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


@app.route("/logs", methods=["POST"])
@app.route("/v1/logs", methods=["POST"])
def handle_opa_logs():
    """Receive HTTP decision logs pushed by OPA, decompress if gzipped, and forward to Splunk."""
    import gzip
    try:
        content_encoding = request.headers.get("Content-Encoding", "").lower()
        if "gzip" in content_encoding:
            data = gzip.decompress(request.data)
        else:
            data = request.data
            
        logs = json.loads(data)
        if not isinstance(logs, list):
            logs = [logs]
            
        for log_entry in logs:
            if "decision_id" not in log_entry:
                continue
            fields = extract_opa_decision_fields(log_entry)
            log_correlator.add_log(fields)
            
        return "", 200
    except Exception as e:
        logger.error("Error processing OPA decision logs: %s", e)
        return jsonify({"error": str(e)}), 500


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
    logger.info("Starting OPA Splunk Forwarder on port %d", port)
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    finally:
        _stop_event.set()


if __name__ == "__main__":
    main()
