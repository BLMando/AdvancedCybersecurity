import atexit
import fcntl
import json
import logging
import os
import threading
from pathlib import Path

from parsers import (
    extract_envoy_fields,
    extract_mongo_fields,
    extract_snort_fields,
    parse_nftables_line,
)

logger = logging.getLogger("tailers")

# Paths
ENVOY_LOG_PATH = Path("/var/log/envoy/access.log")
SNORT_PEP_LOG_PATH = Path("/var/log/snort-pep/alert_json.txt")
SNORT_RESOURCE_LOG_PATH = Path("/var/log/snort-resource/alert_json.txt")
NFTABLES_LOG_PATH = Path("/var/log/nftables/nft.log")
MONGO_LOG_PATH = Path("/var/log/mongodb/mongod.log")
MONGO_AUDIT_PATH = Path("/var/log/mongodb/audit.json")

AUTO_BLOCK_SIDS = {
    # Sonda PEP
    3000005,  # Envoy admin access attempt from internal network
    3000006,  # TCP port scan attempt targeting PEP perimeter
    # Sonda Risorsa
    4000001,  # Direct MongoDB access attempt (PEP bypass)
    4000002,  # MongoDB TCP connection flood
}


def is_internal_ip(ip: str) -> bool:
    if ip.startswith("127.") or ip in ("localhost", "host.docker.internal"):
        return True
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            first = int(parts[0])
            second = int(parts[1])
            if first == 172 and (16 <= second <= 31):
                return True
    except Exception:
        pass
    return False


# Track port scan counts per IP to enforce a threshold before blocking
PORT_SCAN_BLOCK_THRESHOLD = 3
_port_scan_counts = {}
_port_scan_lock = threading.Lock()


def auto_block_ip(ip: str) -> None:
    path = "/app/blocklist/blocklist.txt"
    if is_internal_ip(ip):
        logger.info("[SOAR] IP %s is part of internal infrastructure, skipping auto-block", ip)
        return
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
                logger.info("[SOAR] IP %s automatically blocked due to severe Snort alert", ip)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        logger.error("[SOAR] Failed to auto-block IP %s: %s", ip, e)


def process_snort_alert(fields: dict) -> None:
    src_addr = fields.get("src_addr", "0.0.0.0")
    sid = int(fields.get("sid", 0))
    if sid in AUTO_BLOCK_SIDS and src_addr != "0.0.0.0" and not is_internal_ip(src_addr):
        if sid == 3000006:
            with _port_scan_lock:
                count = _port_scan_counts.get(src_addr, 0) + 1
                _port_scan_counts[src_addr] = count
            if count >= PORT_SCAN_BLOCK_THRESHOLD:
                auto_block_ip(src_addr)
            else:
                logger.info("[SOAR] IP %s port scan count: %d/%d. Skipping block.", src_addr, count, PORT_SCAN_BLOCK_THRESHOLD)
        else:
            auto_block_ip(src_addr)


class FileTailer:
    """Tails a single log file in a background thread."""

    def __init__(self, path: Path, line_handler, post_batch_handler=None, sleep_interval: float = 2.0):
        self.path = Path(path)
        self.line_handler = line_handler
        self.post_batch_handler = post_batch_handler
        self.sleep_interval = sleep_interval
        self._stop_event = threading.Event()
        self._thread = None
        self.last_position = 0

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        logger.info("Log tailer started, watching: %s", self.path)
        while not self._stop_event.is_set():
            try:
                if self.path.exists():
                    current_size = self.path.stat().st_size
                    if current_size < self.last_position:
                        self.last_position = 0
                    if current_size > self.last_position:
                        has_lines = False
                        with open(self.path) as f:
                            f.seek(self.last_position)
                            for line in f:
                                line = line.strip()
                                if line:
                                    has_lines = True
                                    self.line_handler(line)
                            self.last_position = f.tell()
                        if has_lines and self.post_batch_handler:
                            self.post_batch_handler()
                else:
                    logger.debug("Log file not yet available: %s", self.path)
            except Exception as e:
                logger.error("Error tailing log %s: %s", self.path, e)
            self._stop_event.wait(timeout=self.sleep_interval)
        logger.info("Log tailer stopped: %s", self.path)


_TAILER_LOCK = Path("/tmp/envoy_tailer.lock")
_tailers = []


def start_background_tailers(hec_client) -> None:
    """Instantiate and start all background tailers using the global lock to prevent Gunicorn workers duplicate executions."""
    try:
        _TAILER_LOCK.touch(exist_ok=False)

        # 1. Envoy Access logs
        def handle_envoy(line):
            try:
                log_entry = json.loads(line)
                fields = extract_envoy_fields(log_entry)
                hec_client.send_event(fields, index="zta_envoy", sourcetype="envoy:access")
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON line from Envoy log")

        # 2. Snort PEP alerts
        def handle_snort_pep(line):
            try:
                log_entry = json.loads(line)
                fields = extract_snort_fields(log_entry)
                fields["sensor"] = "pep"
                hec_client.send_event(fields, index="zta_snort", sourcetype="snort:alert_json")
                process_snort_alert(fields)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON from Snort [pep] log")

        # 3. Snort Resource alerts
        def handle_snort_res(line):
            try:
                log_entry = json.loads(line)
                fields = extract_snort_fields(log_entry)
                fields["sensor"] = "resource"
                hec_client.send_event(fields, index="zta_snort", sourcetype="snort:alert_json")
                process_snort_alert(fields)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON from Snort [resource] log")

        # 4. nftables logs
        def handle_nft(line):
            fields = parse_nftables_line(line)
            if fields:
                hec_client.send_event(fields, index="zta_nftables", sourcetype="nftables:log")

        # 5. MongoDB logs
        def handle_mongo(line):
            try:
                log_entry = json.loads(line)
                fields = extract_mongo_fields(log_entry)
                hec_client.send_event(fields, index="zta_mongodb", sourcetype="mongodb:json")
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON from MongoDB log")

        # 6. MongoDB Audit logs
        def handle_mongo_audit(line):
            try:
                log_entry = json.loads(line)
                hec_client.send_event(log_entry, index="zta_mongodb_audit", sourcetype="mongodb:audit")
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON from MongoDB Audit log")

        # Create tailers
        t_envoy = FileTailer(ENVOY_LOG_PATH, handle_envoy, hec_client.flush)
        t_snort_pep = FileTailer(SNORT_PEP_LOG_PATH, handle_snort_pep, hec_client.flush)
        t_snort_res = FileTailer(SNORT_RESOURCE_LOG_PATH, handle_snort_res, hec_client.flush)
        t_nft = FileTailer(NFTABLES_LOG_PATH, handle_nft, hec_client.flush)
        t_mongo = FileTailer(MONGO_LOG_PATH, handle_mongo, hec_client.flush)
        t_mongo_audit = FileTailer(MONGO_AUDIT_PATH, handle_mongo_audit, hec_client.flush)

        global _tailers
        _tailers = [t_envoy, t_snort_pep, t_snort_res, t_nft, t_mongo, t_mongo_audit]

        for t in _tailers:
            t.start()

        logger.info("All background log tailers started successfully (lock acquired)")

    except FileExistsError:
        logger.debug("Log tailers already running in another worker (lock exists)")
    except Exception as e:
        logger.error("Failed to start background log tailers: %s", e)


def stop_background_tailers() -> None:
    """Stop all active tailers and release the Gunicorn lock."""
    global _tailers
    for t in _tailers:
        t.stop()
    _TAILER_LOCK.unlink(missing_ok=True)
    logger.info("All background log tailers stopped")


atexit.register(stop_background_tailers)
