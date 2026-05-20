"""
Splunk HTTP Event Collector (HEC) client.

Handles batching, retry with backoff, authentication, and
JSON-formatted event submission to Splunk HEC endpoint.
"""

import json
import logging
import time
import urllib.error
import urllib.request

logger = logging.getLogger("heclient")


class HEClient:
    def __init__(self, host="splunk", port=8088, token="", batch_size=100, timeout=5, max_retries=3):
        self.base_url = f"https://{host}:{port}/services/collector/event"
        self.token = token
        self.batch_size = batch_size
        self.timeout = timeout
        self.max_retries = max_retries
        self._buffer: list[dict] = []
        self._last_flush = time.time()
        self._flush_interval = 5.0

    def send_event(self, event: dict, index: str = "main", sourcetype: str = "_json") -> bool:
        self._buffer.append({
            "event": event,
            "index": index,
            "sourcetype": sourcetype,
        })
        if len(self._buffer) >= self.batch_size or (time.time() - self._last_flush) >= self._flush_interval:
            return self.flush()
        return True

    def flush(self) -> bool:
        if not self._buffer:
            return True
        self._last_flush = time.time()
        payload = self._buffer[:]
        self._buffer = []
        return self._send_batch(payload)

    def _send_batch(self, events: list[dict]) -> bool:
        for attempt in range(1, self.max_retries + 1):
            try:
                body = "\n".join(json.dumps(e, default=str) for e in events).encode()
                req = urllib.request.Request(
                    self.base_url,
                    data=body,
                    headers={
                        "Authorization": f"Splunk {self.token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE

                resp = urllib.request.urlopen(req, context=ctx, timeout=self.timeout)
                response_data = json.loads(resp.read().decode())
                if response_data.get("text") == "Success":
                    logger.info("Sent %d events to Splunk HEC", len(events))
                    return True
                logger.warning("HEC response: %s", response_data)
                return False

            except urllib.error.HTTPError as e:
                logger.error("HEC HTTP %d: %s", e.code, e.read().decode())
                if attempt < self.max_retries:
                    backoff = 2 ** attempt
                    logger.info("Retrying in %ds...", backoff)
                    time.sleep(backoff)
            except Exception as e:
                logger.error("HEC send error: %s", e)
                if attempt < self.max_retries:
                    backoff = 2 ** attempt
                    time.sleep(backoff)
        logger.error("Failed to send batch after %d attempts", self.max_retries)
        return False
