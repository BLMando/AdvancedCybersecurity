import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

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


# Splunk Authentication


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
            return match.group(1)
        sys.exit(1)
    except urllib.error.HTTPError:
        sys.exit(1)
    except Exception:
        raise


def splunk_request(
    session_key: str,
    method: str,
    url: str,
    data: bytes | None = None,
    content_type: str = "application/x-www-form-urlencoded",
) -> tuple[int, str]:
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
        return (e.code, err_body)


# Setup Functions


def wait_for_splunk(host: str, port: int, retries: int = 60, delay: int = 5) -> None:
    print(f"Waiting for Splunk at {host}:{port}...")
    for attempt in range(1, retries + 1):
        try:
            ctx = _ssl_ctx()
            req = urllib.request.Request(_url(host, port, "/services/server/info"))
            urllib.request.urlopen(req, context=ctx, timeout=10)
            print("Splunk is ready.")
            return
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                print("Splunk is ready (requires authentication).")
                return
            print(f"Attempt {attempt}/{retries} - HTTP {e.code}, retrying in {delay}s...")
            time.sleep(delay)
        except Exception as e:
            print(f"Attempt {attempt}/{retries} - {e}, retrying in {delay}s...")
            time.sleep(delay)
    print("ERROR: Splunk did not become ready in time.")
    sys.exit(1)


def create_index(session_key: str, host: str, port: int, index_name: str) -> None:
    status, _ = splunk_request(session_key, "GET", _url(host, port, f"/services/data/indexes/{index_name}"))
    if status == 200:
        print(f"Index {index_name} exists")
        return

    data = urllib.parse.urlencode(
        {
            "name": index_name,
            "datatype": "event",
        }
    ).encode()
    status, _ = splunk_request(session_key, "POST", _url(host, port, "/services/data/indexes"), data)
    if status in (200, 201):
        print(f"Index {index_name} created")
    elif status == 409:
        print(f"Index {index_name} exists")
    else:
        print(f"Index {index_name} error {status}")


def import_dashboard(
    session_key: str, host: str, port: int, dashboard_path: str, dashboard_name: str = "zta_overview"
) -> None:
    dashboard_file = Path(dashboard_path)
    if not dashboard_file.exists():
        print(f"Dashboard {dashboard_path} missing")
        return
    dashboard_xml = dashboard_file.read_text(encoding="utf-8")

    dash_url = _url(host, port, f"/servicesNS/admin/search/data/ui/views/{dashboard_name}")
    status, _ = splunk_request(session_key, "GET", dash_url)

    if status == 200:
        # Dashboard exists, update it
        update_data = urllib.parse.urlencode({"eai:data": dashboard_xml}).encode()
        status2, _ = splunk_request(session_key, "POST", dash_url, update_data)
        if status2 in (200, 201):
            print(f"Dashboard {dashboard_name} updated")
        else:
            print(f"Dashboard {dashboard_name} update error {status2}")
    else:
        # Dashboard does not exist, create it
        create_data = urllib.parse.urlencode(
            {
                "name": dashboard_name,
                "eai:data": dashboard_xml,
            }
        ).encode()
        views_url = _url(host, port, "/servicesNS/admin/search/data/ui/views")
        status3, _ = splunk_request(session_key, "POST", views_url, create_data)
        if status3 in (200, 201):
            print(f"Dashboard {dashboard_name} imported")
        else:
            print(f"Dashboard {dashboard_name} import error {status3}")


# Main


def main():
    SPLUNK_HOST = "splunk"
    SPLUNK_PORT = 8089
    SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "admin")
    SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")

    wait_for_splunk(SPLUNK_HOST, SPLUNK_PORT)
    session_key = splunk_login(SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USERNAME, SPLUNK_PASSWORD)

    create_index(session_key, SPLUNK_HOST, SPLUNK_PORT, "zta_envoy")
    create_index(session_key, SPLUNK_HOST, SPLUNK_PORT, "zta_snort")
    create_index(session_key, SPLUNK_HOST, SPLUNK_PORT, "zta_nftables")
    create_index(session_key, SPLUNK_HOST, SPLUNK_PORT, "zta_mongodb")
    create_index(session_key, SPLUNK_HOST, SPLUNK_PORT, "zta_mongodb_audit")

    # Support both container mount (/app/dashboards) and local execution
    dashboard_dir = Path("/app/dashboards")
    if not dashboard_dir.exists():
        dashboard_dir = Path(__file__).resolve().parent.parent / "splunk" / "dashboards"
    dashboard_file = dashboard_dir / "zta_overview.xml"
    if dashboard_file.exists():
        import_dashboard(session_key, SPLUNK_HOST, SPLUNK_PORT, str(dashboard_file))
    else:
        print(f"Dashboard {dashboard_file} missing, skipping")

    print("Splunk Setup complete")


if __name__ == "__main__":
    main()
