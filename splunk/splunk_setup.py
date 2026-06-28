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

SPLUNK_VERIFY_TLS = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() in ("true", "1", "yes")


def _ssl_ctx():
    import ssl
    ctx = ssl.create_default_context()
    if not SPLUNK_VERIFY_TLS:
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


def import_dashboard(session_key: str, host: str, port: int,
                     dashboard_path: str, dashboard_name: str = "zta_overview") -> None:
    log(f"Importing dashboard: {dashboard_name}...")
    dashboard_file = Path(dashboard_path)
    if not dashboard_file.exists():
        log(f"Dashboard file not found: {dashboard_path}")
        return
    dashboard_xml = dashboard_file.read_text(encoding="utf-8")
    if 'version="1.1"' not in dashboard_xml:
        log("WARNING: Dashboard XML is missing version=\"1.1\" on root <dashboard> node.")

    data = urllib.parse.urlencode({
        "name": dashboard_name,
        "eai:data": dashboard_xml,
    }).encode()

    views_url = _url(host, port, "/servicesNS/admin/search/data/ui/views")
    status, _ = splunk_request(session_key, "POST", views_url, data)

    if status in (200, 201):
        log(f"Dashboard '{dashboard_name}' imported successfully.")
        return

    if status == 409:
        log(f"Dashboard '{dashboard_name}' already exists, updating...")
        update_url = _url(host, port, f"/servicesNS/admin/search/data/ui/views/{dashboard_name}")
        # Splunk REST API updates views via POST, not PUT.
        status2, _ = splunk_request(session_key, "POST", update_url, data)
        if status2 in (200, 201):
            log(f"Dashboard '{dashboard_name}' updated successfully.")
            return

        log(f"POST update failed (HTTP {status2}), recreating dashboard...")
        splunk_request(session_key, "DELETE", update_url)
        status3, _ = splunk_request(session_key, "POST", views_url, data)
        if status3 in (200, 201):
            log(f"Dashboard '{dashboard_name}' recreated successfully.")
        else:
            log(f"WARNING: Dashboard recreate returned status {status3}")
        return

    log(f"WARNING: Dashboard import returned status {status}")


# ─── Main ──────────────────────────────────────────────────────────

def main():
    host = os.environ.get("SPLUNK_HOST", "localhost")
    port = int(os.environ.get("SPLUNK_MGMT_PORT", "8089"))
    username = os.environ.get("SPLUNK_USERNAME", "admin")
    password = os.environ.get("SPLUNK_PASSWORD", "SplunkPassword123!")

    if SPLUNK_VERIFY_TLS:
        log("TLS certificate verification enabled (SPLUNK_VERIFY_TLS=true).")
    else:
        log("TLS certificate verification disabled (lab/Docker Splunk). Set SPLUNK_VERIFY_TLS=true in production.")

    wait_for_splunk(host, port)
    session_key = splunk_login(host, port, username, password)

    create_index(session_key, host, port, "zta_envoy")
    create_index(session_key, host, port, "zta_snort")
    create_index(session_key, host, port, "zta_nftables")
    create_index(session_key, host, port, "zta_mongodb")
    create_index(session_key, host, port, "zta_mongodb_audit")

    # Support both container mount (/app/dashboards) and local execution
    dashboard_dir = Path("/app/dashboards")
    if not dashboard_dir.exists():
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
    log("Indexes: zta_envoy, zta_snort, zta_nftables, zta_mongodb, zta_mongodb_audit")
    log("HEC token: create manually in Splunk Web (HTTP Event Collector)")
    log("  index=zta_envoy,zta_snort,zta_nftables,zta_mongodb,zta_mongodb_audit")
    log("  then set SPLUNK_HEC_TOKEN_ENVOY in .env")
    log("=" * 60)


if __name__ == "__main__":
    main()