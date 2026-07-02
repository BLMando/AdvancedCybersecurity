import threading


class LogCorrelator:
    """Correlates and merges OPA ALLOW logs with subsequent Lua WAF DENY logs in memory

    to ensure Splunk indexes a single consistent decision event per request.
    """

    def __init__(self, hec_client):
        self.hec_client = hec_client
        self.opa_logs = {}  # request_id -> fields
        self.waf_logs = {}  # request_id -> fields
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
