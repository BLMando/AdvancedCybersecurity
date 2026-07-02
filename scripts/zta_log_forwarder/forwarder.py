import json
import logging
import os

from flask import Flask, jsonify, request
from heclient import HEClient
from log_correlator import LogCorrelator

# Import extracted parser modules
from parsers import (
    extract_envoy_fields,
    extract_opa_decision_fields,
)
from tailers import start_background_tailers

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("forwarder")

app = Flask(__name__)

# Initialize Splunk client
hec_client = HEClient(
    host="splunk",
    port=8088,
    token=os.environ.get("SPLUNK_HEC_TOKEN_ENVOY", ""),
    batch_size=int(os.environ.get("HEC_BATCH_SIZE", "100")),
)

log_correlator = LogCorrelator(hec_client)


start_background_tailers(hec_client)


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
    hec_client.send_event(fields, index="zta_envoy", sourcetype="envoy:access")
    return jsonify({"status": "queued"}), 202


def main():
    port = int(os.environ.get("LOG_FORWARDER_PORT", 5000))
    logger.info("Starting OPA Splunk Forwarder on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
