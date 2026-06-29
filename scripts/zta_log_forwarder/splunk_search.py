import os
import json
import logging
import urllib.parse
import urllib.request
import ssl as _ssl

logger = logging.getLogger("splunk_search")

SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
SPLUNK_VERIFY_TLS = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"


def run_splunk_search(query: str) -> list:
    """Run a Splunk search and return the list of raw results (dict)."""
    if not SPLUNK_PASSWORD:
        logger.error("SPLUNK_PASSWORD is not configured; cannot query Splunk stats")
        raise RuntimeError("splunk credentials not configured")

    base_url = f"https://splunk:8089/services/search/jobs/export"
    form = urllib.parse.urlencode({
        "search": query,
        "output_mode": "json",
        "exec_mode": "oneshot",
    }).encode("utf-8")
    req = urllib.request.Request(
        base_url,
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    
    ctx = _ssl.create_default_context()
    if not SPLUNK_VERIFY_TLS:
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
        logger.error("Failed running Splunk search: %s", e)
        return []

    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "result" in obj:
                results.append(obj["result"])
        except json.JSONDecodeError:
            continue
    return results
