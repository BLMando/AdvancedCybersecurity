import re
import logging

logger = logging.getLogger("parsers")

# Regex to parse nftables kernel logs
NFT_LOG_PATTERN = re.compile(
    r"(NFT_\w+):\s+"
    r".*?IN=(\S*)\s+"
    r".*?SRC=(\S+)\s+"
    r".*?DST=(\S+)\s+"
    r".*?PROTO=(\S+)\s*"
    r"(?:.*?SPT=(\d+))?\s*"
    r"(?:.*?DPT=(\d+))?"
)


def extract_envoy_fields(log_entry: dict) -> dict:
    """Extract standard fields from Envoy access log JSON entries."""
    return {
        "request_id": log_entry.get("request_id") or "unknown",
        "source_ip": log_entry.get("downstream_remote_address") or "unknown",
        "downstream_local": log_entry.get("downstream_local_address") or "unknown",
        "upstream_host": log_entry.get("upstream_host") or "unknown",
        "duration_ms": log_entry.get("duration") or "0",
        "bytes_sent": log_entry.get("bytes_sent") or "0",
        "bytes_received": log_entry.get("bytes_received") or "0",
    }


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


def extract_mongo_fields(log_entry: dict) -> dict:
    """Estrae i campi dai log JSON nativi di MongoDB 4.4+."""
    t_field = log_entry.get("t")
    timestamp = t_field.get("$date") if isinstance(t_field, dict) else str(t_field) if t_field else ""
    return {
        "timestamp": timestamp,
        "severity": log_entry.get("s", "I"),
        "component": log_entry.get("c", "UNKNOWN"),
        "id": log_entry.get("id", 0),
        "context": log_entry.get("ctx", ""),
        "message": log_entry.get("msg", ""),
        "attributes": log_entry.get("attr", {}),
    }


def parse_nftables_line(line: str) -> dict | None:

    match = NFT_LOG_PATTERN.search(line)
    if match:
        prefix = match.group(1)
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

    if "counter packets" in line:
        try:
            # Estrae log prefix
            prefix_match = re.search(r'log prefix "([^"]+)"', line)
            prefix = prefix_match.group(1).strip(": ") if prefix_match else "NFT_COUNTER"
            
            # Estrae azione finale
            action = "DROP" if "drop" in line.lower() else "ACCEPT" if "accept" in line.lower() else "UNKNOWN"
            
            # Estrae packets e bytes
            packets_match = re.search(r'counter packets (\d+)', line)
            packets = int(packets_match.group(1)) if packets_match else 0
            
            bytes_match = re.search(r'bytes (\d+)', line)
            bytes_val = int(bytes_match.group(1)) if bytes_match else 0
            
            # Estrae protocollo
            proto = "tcp" if "tcp" in line else "udp" if "udp" in line else "icmp" if "icmp" in line else "ip"
            
            # Estrae porta destinazione
            dport_match = re.search(r'dport (\d+)', line)
            dst_port = int(dport_match.group(1)) if dport_match else 0
            
            return {
                "prefix": prefix,
                "action": action,
                "packets": packets,
                "bytes": bytes_val,
                "proto": proto,
                "dst_port": dst_port,
                "raw_rule": line.strip()
            }
        except Exception as e:
            logger.warning("Error parsing counter line: %s, error: %s", line, e)
            
    return None


def extract_opa_decision_fields(log_entry: dict) -> dict:
    """Extract relevant fields from an OPA console decision log entry.

    OPA decision log entries contain the full input, result and metadata
    of each policy evaluation.  We flatten the most useful fields into a
    Splunk-friendly dict.
    """
    result = log_entry.get("result", {}) or {}
    inp = log_entry.get("input", {}) or {}
    attrs = inp.get("attributes", {}) or {}
    request = (attrs.get("request", {}) or {}).get("http", {}) or {}
    source = attrs.get("source", {}) or {}
    destination = attrs.get("destination", {}) or {}

    # The result set by main.rego contains allowed, response_headers, etc.
    # Handle package-level queries where the result has the whole package structure
    allowed = result.get("allowed")
    if allowed is None:
        allowed = result.get("main", {}).get("allowed", False)

    resp_headers = (
        result.get("response_headers_to_add") or 
        result.get("main", {}).get("response_headers_to_add") or 
        result.get("response_headers") or 
        {}
    )

    headers = request.get("headers", {}) or {}
    request_id = headers.get("x-request-id") or headers.get("X-Request-ID") or "unknown"

    # Extract cryptographic hardware CN from peer certificate principal
    device_cn = source.get("principal") or "unknown"

    # Extract query filter from incoming request body parsed by Envoy/OPA
    import json
    parsed_body = inp.get("parsed_body") or {}
    query_filter = parsed_body.get("query") or parsed_body.get("filter") or {}
    query_filter_str = json.dumps(query_filter)

    # Extract human-readable username from incoming Flask header or fallback
    user = (
        headers.get("x-zta-user") or 
        headers.get("X-ZTA-User") or 
        resp_headers.get("x-zta-user") or 
        parsed_body.get("user") or 
        "unknown"
    )

    # Resolve fallbacks for other ZTA context fields
    role = resp_headers.get("x-zta-role") or "unknown"
    if role == "unknown" and user != "unknown":
        user_role_map = {
            "test.doctor": "doctor",
            "test.auditor": "auditor",
            "test.billing": "billing_staff",
            "test.receptionist": "receptionist",
            "admin": "admin"
        }
        role = user_role_map.get(user, "unknown")
    
    command = (
        resp_headers.get("x-zta-command") or 
        resp_headers.get("x-zta-action") or 
        parsed_body.get("command") or 
        "unknown"
    )
    
    collection = (
        resp_headers.get("x-zta-collection") or 
        parsed_body.get("collection") or 
        "unknown"
    )
    
    risk_score = (
        resp_headers.get("x-zta-risk-score") or 
        resp_headers.get("x-zta-eff-risk") or 
        "0"
    )
    
    device = (
        resp_headers.get("x-zta-device") or 
        parsed_body.get("device") or 
        "unknown"
    )
    
    block_reason = (
        resp_headers.get("x-zta-block-reason") or 
        "none"
    )

    return {
        "request_id": request_id,
        "decision_id": log_entry.get("decision_id", ""),
        "timestamp": log_entry.get("timestamp", ""),
        "decision": "ALLOW" if allowed else "DENY",
        "user": user,
        "device_cn": device_cn,
        "filter": query_filter_str,
        "role": role,
        "command": command,
        "collection": collection,
        "risk_score": risk_score,
        "device": device,
        "block_reason": block_reason,
        "source_address": (source.get("address", {}) or {}).get("socketAddress", {}).get("address", "unknown"),
        "destination_port": (destination.get("address", {}) or {}).get("socketAddress", {}).get("portValue", 0),
        "request_method": request.get("method", ""),
        "request_path": request.get("path", ""),
        "eval_ns": (log_entry.get("metrics", {}) or {}).get("timer_rego_query_eval_ns", 0),
    }
