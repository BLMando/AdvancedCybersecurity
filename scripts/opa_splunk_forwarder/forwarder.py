"""
OPA-to-Splunk Log Forwarder

Receives OPA decision logs and Envoy access logs, transforms them
to Splunk HEC format, and forwards to Splunk.

Endpoints:
  POST /v1/logs        - OPA decision logs (OPA's default decision_logs path)
  POST /api/envoy-logs - Envoy access logs (manual push endpoint)
  GET  /health         - Health check

Background:
  - Tails /var/log/envoy/access.log and forwards each JSON line to Splunk HEC
"""

import gzip
import json
import logging
import os
import threading
import time
from pathlib import Path

from flask import Flask, request, jsonify
from heclient import HEClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("forwarder")

app = Flask(__name__)

hec_opa = HEClient(
    host=os.environ.get("SPLUNK_HOST", "splunk"),
    port=int(os.environ.get("SPLUNK_HEC_PORT", "8088")),
    token=os.environ.get("SPLUNK_HEC_TOKEN_OPA", ""),
    batch_size=int(os.environ.get("HEC_BATCH_SIZE", "100")),
)
hec_envoy = HEClient(
    host=os.environ.get("SPLUNK_HOST", "splunk"),
    port=int(os.environ.get("SPLUNK_HEC_PORT", "8088")),
    token=os.environ.get("SPLUNK_HEC_TOKEN_ENVOY", ""),
    batch_size=int(os.environ.get("HEC_BATCH_SIZE", "100")),
)

ENVOY_LOG_PATH = Path("/var/log/envoy/access.log")


def extract_opa_fields(raw_input: dict) -> dict:
    parsed = raw_input.get("parsed_body") or {}
    attrs = raw_input.get("attributes") or {}
    source = attrs.get("source") or {}

    return {
        "user": (
            source.get("principal")
            or parsed.get("user")
            or "unknown"
        ),
        "software": parsed.get("device", "no-tpm"),
        "device": parsed.get("device", "no-tpm"),
        "network_ip": (
            parsed.get("network_ip")
            or (source.get("address") or {}).get("address")
            or "0.0.0.0"
        ),
        "resource": parsed.get("collection", "unknown"),
        "command": parsed.get("command", "unknown"),
    }


def extract_envoy_fields(log_entry: dict) -> dict:
    return {
        "source_ip": log_entry.get("downstream_remote_address", "unknown"),
        "downstream_local": log_entry.get("downstream_local_address", "unknown"),
        "upstream_host": log_entry.get("upstream_host", "unknown"),
        "duration_ms": log_entry.get("duration", "0"),
        "bytes_sent": log_entry.get("bytes_sent", "0"),
        "bytes_received": log_entry.get("bytes_received", "0"),
    }


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
            else:
                logger.debug("Envoy log file not yet available: %s", ENVOY_LOG_PATH)
        except Exception as e:
            logger.error("Error tailing Envoy log: %s", e)

        stop_event.wait(timeout=2.0)

    logger.info("Envoy log tailer stopped")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/logs", methods=["POST"])
@app.route("/v1/logs", methods=["POST"])
@app.route("/api/logs", methods=["POST"])
def handle_opa_decision_log():
    raw = request.get_data()
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception as e:
            logger.warning("Gzip decompression failed: %s", e)
            return jsonify({"error": f"decompress failed: {e}"}), 400
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception as e:
        logger.warning("Invalid JSON from OPA: %s", e)
        return jsonify({"error": f"invalid json: {e}"}), 400

    entries = body if isinstance(body, list) else [body]
    logger.debug("Processing %d OPA decision log(s)", len(entries))
    for entry in entries:
        raw_input = entry.get("input", {})
        result = entry.get("result", False)
        decision_id = entry.get("decision_id", "")
        timestamp = entry.get("timestamp", "")

        fields = extract_opa_fields(raw_input)
        fields["decision"] = "ALLOW" if result is True else "DENY"
        fields["decision_id"] = decision_id
        fields["opa_timestamp"] = timestamp

        risk_str = "N/A"
        try:
            risk_val = raw_input.get("risk_score", "N/A")
            if isinstance(risk_val, (int, float)):
                risk_str = str(risk_val)
            elif isinstance(risk_val, str) and risk_val:
                risk_str = risk_val
        except Exception:
            pass
        fields["risk_score"] = risk_str

        hec_opa.send_event(fields, index="zta_opa", sourcetype="opa:decision")

    return jsonify({"status": "queued", "count": len(entries)}), 202


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
_tailer = threading.Thread(target=tail_envoy_logs, args=(_stop_event,), daemon=True)
_tailer.start()


def main():
    port = int(os.environ.get("FORWARDER_PORT", "5000"))
    logger.info("Starting OPA Splunk Forwarder on port %d", port)
    try:
        app.run(host="0.0.0.0", port=port, debug=False)
    finally:
        _stop_event.set()


if __name__ == "__main__":
    main()
