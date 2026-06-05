"""
Envoy-to-Splunk Forwarder + Stats API for OPA

Responsibilities:
  1) Forward Envoy access logs to Splunk HEC.
  2) Forward Snort 3 IDS alert logs to Splunk HEC.
  3) Forward nftables firewall logs to Splunk HEC.
  4) Expose a lightweight stats endpoint that OPA can query to enrich
     risk evaluation with recent activity from Splunk.

OPA must not send decision logs to Splunk.
"""

import atexit
import json
import logging
import os
import re
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
SNORT_LOG_PATH = Path("/var/log/snort/alert_json.txt")
NFTABLES_LOG_PATH = Path("/var/log/nftables/nft.log")
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


def extract_snort_fields(log_entry: dict) -> dict:
    """Estrae i campi rilevanti dal JSON nativo di Snort 3."""
    return {
        "timestamp": log_entry.get("timestamp", ""),
        "msg": log_entry.get("msg", "unknown"),
        "src_addr": log_entry.get("src_addr", "0.0.0.0"),
        "src_port": log_entry.get("src_port", 0),
        "dst_addr": log_entry.get("dst_addr", "0.0.0.0"),
        "dst_port": log_entry.get("dst_port", 0),
        "proto": log_entry.get("proto", "unknown"),
        "action": log_entry.get("action", "alert"),
        "gid": log_entry.get("gid", 1),
        "sid": log_entry.get("sid", 0),
        "rev": log_entry.get("rev", 0),
        "priority": log_entry.get("priority", 0),
    }


def tail_snort_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the Snort 3 alert_json log file."""
    logger.info("Snort log tailer started, watching: %s", SNORT_LOG_PATH)
    last_position = 0

    while not stop_event.is_set():
        try:
            if SNORT_LOG_PATH.exists():
                current_size = SNORT_LOG_PATH.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    with open(SNORT_LOG_PATH, "r") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                log_entry = json.loads(line)
                                fields = extract_snort_fields(log_entry)
                                hec_envoy.send_event(
                                    fields,
                                    index="zta_snort",
                                    sourcetype="snort:alert_json",
                                )
                            except json.JSONDecodeError:
                                logger.warning("Skipping invalid JSON from Snort log")
                        last_position = f.tell()
                    hec_envoy.flush()
            else:
                logger.debug("Snort log file not yet available: %s", SNORT_LOG_PATH)
        except Exception as e:
            logger.error("Error tailing Snort log: %s", e)
        stop_event.wait(timeout=2.0)

    logger.info("Snort log tailer stopped")


# Regex per parsare i log del kernel nftables
# Formato: <N>NFT_DROP: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8
#          LEN=52 ... PROTO=TCP SPT=12345 DPT=27017 ...
NFT_LOG_PATTERN = re.compile(
    r"(NFT_\w+):\s+"
    r".*?IN=(\S*)\s+"
    r".*?SRC=(\S+)\s+"
    r".*?DST=(\S+)\s+"
    r".*?PROTO=(\S+)\s*"
    r"(?:.*?SPT=(\d+))?\s*"
    r"(?:.*?DPT=(\d+))?"
)


def parse_nftables_line(line: str) -> dict | None:
    """Parsa una riga di log kernel nftables in campi strutturati."""
    match = NFT_LOG_PATTERN.search(line)
    if not match:
        return None
    prefix = match.group(1)  # es. NFT_DROP, NFT_SSH_ACCEPT
    action = "DROP" if "DROP" in prefix else "ACCEPT" if "ACCEPT" in prefix else prefix
    return {
        "prefix": prefix,
        "action": action,
        "in_iface": match.group(2) or "",
        "src_ip": match.group(3) or "0.0.0.0",
        "dst_ip": match.group(4) or "0.0.0.0",
        "proto": match.group(5) or "unknown",
        "src_port": int(match.group(6)) if match.group(6) else 0,
        "dst_port": int(match.group(7)) if match.group(7) else 0,
    }


def tail_nftables_logs(stop_event: threading.Event) -> None:
    """Background thread that tails nftables kernel log output."""
    logger.info("nftables log tailer started, watching: %s", NFTABLES_LOG_PATH)
    last_position = 0

    while not stop_event.is_set():
        try:
            if NFTABLES_LOG_PATH.exists():
                current_size = NFTABLES_LOG_PATH.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    with open(NFTABLES_LOG_PATH, "r") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            fields = parse_nftables_line(line)
                            if fields:
                                hec_envoy.send_event(
                                    fields,
                                    index="zta_nftables",
                                    sourcetype="nftables:log",
                                )
                        last_position = f.tell()
                    hec_envoy.flush()
            else:
                logger.debug("nftables log file not yet available: %s", NFTABLES_LOG_PATH)
        except Exception as e:
            logger.error("Error tailing nftables log: %s", e)
        stop_event.wait(timeout=2.0)

    logger.info("nftables log tailer stopped")


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


def _splunk_query_anomalies() -> dict:
    """
    Query Splunk for recent event counts (last 15m) grouped by user.
    """
    base_url = f"https://{SPLUNK_HOST}:{SPLUNK_MGMT_PORT}/services/search/jobs/export"
    query = "search index=zta_envoy earliest=-15m | stats count by user"
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

    try:
        with opener.open(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8").strip()
    except Exception as e:
        logger.error("Failed querying Splunk for anomalies: %s", e)
        return {}

    user_counts = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = obj.get("result") or {}
        user = result.get("user")
        count_str = result.get("count")
        if user and count_str:
            try:
                user_counts[user] = int(count_str)
            except Exception:
                pass
    return user_counts


def update_opa_anomalies(user_counts: dict) -> None:
    """
    Map event counts to risk boosts and push to OPA's /v1/data/splunk/anomalies endpoint.
    """
    anomalies = {}
    for user, count in user_counts.items():
        if count >= 200:
            boost = 20
        elif count >= 100:
            boost = 10
        elif count >= 50:
            boost = 5
        else:
            boost = 0
        anomalies[user] = {"risk_boost": boost}

    # Push to OPA
    opa_url = "http://opa:8181/v1/data/splunk/anomalies"
    req = urllib.request.Request(
        opa_url,
        data=json.dumps(anomalies).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT"
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            logger.info("Successfully pushed anomalies to OPA: %s", anomalies)
    except Exception as e:
        logger.error("Failed to push anomalies to OPA: %s", e)


def _splunk_query_trust_registry() -> dict:
    """
    Query Splunk for authorized (ALLOW) historical combinations of user, device, and network_ip
    over the last 7 days, and build a trust registry.
    """
    base_url = f"https://{SPLUNK_HOST}:{SPLUNK_MGMT_PORT}/services/search/jobs/export"
    query = "search index=zta_envoy decision=ALLOW earliest=-7d | stats count by user, device, network_ip"
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

    try:
        with opener.open(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8").strip()
    except Exception as e:
        logger.error("Failed querying Splunk for trust registry: %s", e)
        return {}

    registry = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = obj.get("result") or {}
        user = result.get("user")
        device = result.get("device")
        ip = result.get("network_ip")
        if user and device and ip:
            if user not in registry:
                registry[user] = {}
            if device not in registry[user]:
                registry[user][device] = []
            if ip not in registry[user][device]:
                registry[user][device].append(ip)
    return registry


def update_opa_trust_registry(registry: dict) -> None:
    """
    Push the historical trust registry of user-device-network combinations to OPA's
    /v1/data/splunk/trust_registry endpoint.
    """
    opa_url = "http://opa:8181/v1/data/splunk/trust_registry"
    req = urllib.request.Request(
        opa_url,
        data=json.dumps(registry).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT"
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            logger.info("Successfully pushed trust registry to OPA: %s keys", len(registry))
    except Exception as e:
        logger.error("Failed to push trust registry to OPA: %s", e)


def sync_splunk_to_opa(stop_event: threading.Event) -> None:
    """
    Background sync loop to periodically fetch stats and push them to OPA.
    """
    logger.info("Splunk to OPA sync thread started")
    while not stop_event.is_set():
        if SPLUNK_PASSWORD:
            # 1. Volumetric anomaly detection (last 15m)
            user_counts = _splunk_query_anomalies()
            update_opa_anomalies(user_counts)
            
            # 2. Historical User-Device-IP correlation registry (last 24h)
            registry = _splunk_query_trust_registry()
            update_opa_trust_registry(registry)
        else:
            logger.warning("SPLUNK_PASSWORD not configured; skipping sync")
        stop_event.wait(timeout=10.0)
    logger.info("Splunk to OPA sync thread stopped")


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

        # Thread: Splunk ↔ OPA sync
        t_sync = threading.Thread(target=sync_splunk_to_opa, args=(_stop_event,), daemon=True)
        t_sync.start()
        logger.info("Splunk to OPA sync thread started (lock acquired)")

        # Thread: Snort logs
        t_snort = threading.Thread(target=tail_snort_logs, args=(_stop_event,), daemon=True)
        t_snort.start()
        logger.info("Snort log tailer started")

        # Thread: nftables logs
        t_nft = threading.Thread(target=tail_nftables_logs, args=(_stop_event,), daemon=True)
        t_nft.start()
        logger.info("nftables log tailer started")
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
