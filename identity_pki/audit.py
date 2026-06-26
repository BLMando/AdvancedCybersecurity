import json
import logging
import urllib.request
from datetime import datetime, timezone
import threading as _threading

def send_audit_event_impl(logger: logging.Logger, user, role, collection, action, translated_view,
                          query_filter, decision, count=0, error_type="",
                          message="", jwt_auth=False, hardware_mode=False,
                          risk_score=0):

    def _send():
        try:
            audit_payload = json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user": user,
                "role": role,
                "resource": collection,
                "command": action,
                "translated_view": translated_view,
                "filter": query_filter,
                "decision": decision,
                "count": count,
                "error_type": error_type,
                "message": message,
                "jwt_auth": jwt_auth,
                "hardware_mode": hardware_mode,
                "risk_score": risk_score,
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://zta-log-forwarder:5000/api/audit",
                data=audit_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception as e:
            logger.debug("Audit event delivery failed (non-critical): %s", e)
    _threading.Thread(target=_send, daemon=True).start()
