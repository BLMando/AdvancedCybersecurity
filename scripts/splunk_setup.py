"""
Splunk Zero Trust Architecture Setup Script

Configures Splunk for ZTA integration:
  1. Creates HEC tokens for OPA and Envoy
  2. Creates indexes: zta_opa, zta_envoy
  3. Imports ZTA monitoring dashboard
  4. Validates connectivity and configuration

Usage:
  python scripts/splunk_setup.py

Environment:
  SPLUNK_HOST       : Splunk management host (default: localhost)
  SPLUNK_MGMT_PORT  : Splunk REST API port (default: 8089)
  SPLUNK_USERNAME   : Admin username (default: admin)
  SPLUNK_PASSWORD   : Admin password (default: SplunkPassword123!)
"""

import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def log(msg: str) -> None:
    print(f"[splunk-setup] {msg}", flush=True)


# ─── Reusable SSL context (disable cert verification) ───────────────
def _ssl_ctx():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _url(host: str, port: int, path: str) -> str:
    return f"https://{host}:{port}{path}"


# ─── Splunk Authentication ─────────────────────────────────────────

def splunk_login(host: str, port: int, username: str, password: str) -> str:
    """Authenticate to Splunk and return a session key."""
    url = _url(host, port, "/services/auth/login")
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        resp = urllib.request.urlopen(req, context=_ssl_ctx(), timeout=30)
        body = resp.read().decode()
        match = re.search(r"<sessionKey>(.*?)</sessionKey>", body)
        if match:
            log("Authentication successful.")
            return match.group(1)
        log(f"ERROR: Could not parse session key from response: {body[:200]}")
        sys.exit(1)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        log(f"Login failed (HTTP {e.code}): {body[:200]}")
        sys.exit(1)
    except Exception as e:
        log(f"Login request failed: {e}")
        raise


def splunk_request(session_key: str, method: str, url: str, data: bytes | None = None,
                   content_type: str = "application/x-www-form-urlencoded") -> tuple[int, str]:
    headers = {
        "Authorization": f"Splunk {session_key}",
    }
    if data:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, context=_ssl_ctx(), timeout=30)
        return (resp.status, resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        log(f"HTTP {e.code} on {method} {url}: {err_body[:200]}")
        return (e.code, err_body)


# ─── Setup Functions ───────────────────────────────────────────────

def wait_for_splunk(host: str, port: int, retries: int = 60, delay: int = 5) -> None:
    log(f"Waiting for Splunk at {host}:{port}...")
    for attempt in range(1, retries + 1):
        try:
            ctx = _ssl_ctx()
            req = urllib.request.Request(_url(host, port, "/services/server/info"))
            urllib.request.urlopen(req, context=ctx, timeout=10)
            log("Splunk is ready.")
            return
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                log("Splunk is ready (requires authentication).")
                return
            log(f"Attempt {attempt}/{retries} - HTTP {e.code}, retrying in {delay}s...")
            time.sleep(delay)
        except Exception as e:
            log(f"Attempt {attempt}/{retries} - {e}, retrying in {delay}s...")
            time.sleep(delay)
    log("ERROR: Splunk did not become ready in time.")
    sys.exit(1)


def create_index(session_key: str, host: str, port: int, index_name: str) -> None:
    log(f"Creating index: {index_name}...")
    data = urllib.parse.urlencode({
        "name": index_name,
        "datatype": "event",
    }).encode()
    status, _ = splunk_request(session_key, "POST",
                                  _url(host, port, "/services/data/indexes"), data)
    if status in (200, 201):
        log(f"Index '{index_name}' created successfully.")
    elif status == 409:
        log(f"Index '{index_name}' already exists.")
    else:
        log(f"WARNING: Could not create index '{index_name}' (HTTP {status})")


def _api_url(host: str, port: int, path: str) -> str:
    """Build a URL for the Splunk REST API."""
    return f"https://{host}:{port}{path}"


def create_hec_token(session_key: str, host: str, port: int, token_name: str,
                     indexes: list[str]) -> str:
    """Create an HEC token and return its value."""
    import uuid
    token_value = str(uuid.uuid4())
    log(f"Creating HEC token: {token_name} (indexes={indexes})...")

    data = urllib.parse.urlencode({
        "name": token_name,
        "index": indexes[0],
        "token": token_value,
        "useAck": "0",
        "disabled": "0",
    }).encode()
    status, _ = splunk_request(session_key, "POST",
                                  _api_url(host, port, "/services/data/inputs/http"),
                                  data)
    if status == 201:
        log(f"Token '{token_name}' created: {token_value}")
        return token_value
    elif status == 409:
        log(f"Token '{token_name}' already exists, deleting and recreating...")
        splunk_request(session_key, "DELETE",
                       _api_url(host, port, f"/services/data/inputs/http/{token_name}"))
        status2, _ = splunk_request(session_key, "POST",
                                    _api_url(host, port, "/services/data/inputs/http"),
                                    data)
        if status2 == 201:
            log(f"Token '{token_name}' recreated: {token_value}")
            return token_value
        log(f"WARNING: Could not recreate token '{token_name}' (HTTP {status2})")
        return f"<{token_name}_error>"
    else:
        log(f"WARNING: Could not create token '{token_name}' (HTTP {status})")
        return f"<{token_name}_error>"


def import_dashboard(session_key: str, host: str, port: int,
                     dashboard_path: str, dashboard_name: str = "zta_overview") -> None:
    log(f"Importing dashboard: {dashboard_name}...")
    dashboard_file = Path(dashboard_path)
    if not dashboard_file.exists():
        log(f"Dashboard file not found: {dashboard_path}")
        return
    dashboard_xml = dashboard_file.read_text(encoding="utf-8")
    data = urllib.parse.urlencode({
        "name": dashboard_name,
        "eai:data": dashboard_xml,
    }).encode()
    status, _ = splunk_request(
        session_key, "POST",
        _url(host, port, "/servicesNS/admin/search/data/ui/views"),
        data,
    )
    if status in (200, 201):
        log(f"Dashboard '{dashboard_name}' imported successfully.")
    elif status == 409:
        log(f"Dashboard '{dashboard_name}' already exists.")
    else:
        log(f"WARNING: Dashboard import returned status {status}")


# ─── Main ──────────────────────────────────────────────────────────

def main():
    host = os.environ.get("SPLUNK_HOST", "localhost")
    port = int(os.environ.get("SPLUNK_MGMT_PORT", "8089"))
    username = os.environ.get("SPLUNK_USERNAME", "admin")
    password = os.environ.get("SPLUNK_PASSWORD", "SplunkPassword123!")

    wait_for_splunk(host, port)
    session_key = splunk_login(host, port, username, password)

    create_index(session_key, host, port, "zta_opa")
    create_index(session_key, host, port, "zta_envoy")

    opa_token = create_hec_token(session_key, host, port, "zta_opa_token", ["zta_opa"])
    envoy_token = create_hec_token(session_key, host, port, "zta_envoy_token", ["zta_envoy"])

    dashboard_dir = Path(__file__).resolve().parent.parent / "splunk" / "dashboards"
    dashboard_file = dashboard_dir / "zta_overview.xml"
    if dashboard_file.exists():
        import_dashboard(session_key, host, port, str(dashboard_file))
    else:
        log(f"Dashboard file not found at {dashboard_file}, skipping import.")

    log("")
    log("=" * 60)
    log("SPLUNK SETUP COMPLETE")
    log("=" * 60)
    log(f"OPA HEC Token   : {opa_token}")
    log(f"Envoy HEC Token : {envoy_token}")
    log("")
    log("Add these to your .env file:")
    log(f'  SPLUNK_HEC_TOKEN_OPA="{opa_token}"')
    log(f'  SPLUNK_HEC_TOKEN_ENVOY="{envoy_token}"')
    log("=" * 60)


if __name__ == "__main__":
    main()
