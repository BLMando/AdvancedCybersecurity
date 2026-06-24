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
        "source_ip": log_entry.get("downstream_remote_address") or "unknown",
        "downstream_local": log_entry.get("downstream_local_address") or "unknown",
        "upstream_host": log_entry.get("upstream_host") or "unknown",
        "duration_ms": log_entry.get("duration") or "0",
        "bytes_sent": log_entry.get("bytes_sent") or "0",
        "bytes_received": log_entry.get("bytes_received") or "0",
        "user": log_entry.get("user") or "unknown",
        "device": log_entry.get("device") or "no-tpm",
        "network_ip": log_entry.get("network_ip") or "0.0.0.0",
        "decision": log_entry.get("decision") or "unknown",
        "risk_score": log_entry.get("risk_score") or "0",
        "command": log_entry.get("command") or "unknown",
        "collection": log_entry.get("collection") or "unknown",
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
