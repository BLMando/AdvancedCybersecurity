import urllib.request
import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor

# Enable ANSI escape sequences on Windows Command Prompt / PowerShell
if sys.platform == 'win32':
    os.system('')

OPA_URL = "http://127.0.0.1:8181/v1/data/envoy/authz"

ROLE_TO_USER = {
    "doctor": "mario.rossi",
    "billing_staff": "anna.verdi",
    "auditor": "giulia.bianchi",
    "receptionist": "luca.ferrari",
    "admin": "admin"
}

COLLECTIONS = ["patients", "providers", "admissions", "clinical_records", "billing"]
COMMANDS = ["find", "insert", "update", "delete"]

# Ground truth matrix from authz.rego
EXPECTED = {
    "doctor": {
        "patients": {"find"},
        "providers": {"find"},
        "admissions": {"find", "insert", "update"},
        "clinical_records": {"find", "insert", "update"},
        "billing": set()
    },
    "billing_staff": {
        "patients": {"find"},
        "providers": {"find"},
        "admissions": {"find"},
        "clinical_records": set(),
        "billing": {"find", "insert", "update"}
    },
    "auditor": {
        "patients": {"find"},
        "providers": {"find"},
        "admissions": {"find"},
        "clinical_records": {"find"},
        "billing": {"find"}
    },
    "receptionist": {
        "patients": {"find", "insert", "update"},
        "providers": {"find"},
        "admissions": {"find", "insert", "update"},
        "clinical_records": set(),
        "billing": set()
    },
    "admin": {
        "patients": {"find", "insert", "update", "delete"},
        "providers": {"find", "insert", "update", "delete"},
        "admissions": {"find", "insert", "update", "delete"},
        "clinical_records": {"find", "insert", "update", "delete"},
        "billing": {"find", "insert", "update", "delete"}
    }
}

def query_opa(user, collection, command):
    # Pass a valid non-empty query with patient_id to bypass content inspection blocks
    payload = {
        "input": {
            "parsed_body": {
                "user": user,
                "device": "device-laptop-001",
                "network_ip": "172.20.0.5",
                "command": command,
                "collection": collection,
                "query": {"patient_id": "P001", "full_name": "John Doe"}
            }
        }
    }
    
    req = urllib.request.Request(
        OPA_URL,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        # Give ample timeout because Splunk sidecar has 1s latency per call
        # and Gunicorn has 2 workers (meaning requests queue up).
        with urllib.request.urlopen(req, timeout=60) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            result = resp_data.get("result", {})
            return result.get("allow", False)
    except Exception as e:
        # Return None on error so we can log it
        print(f"DEBUG EXCEPTION for {user} {collection} {command}: {type(e).__name__}: {e}", file=sys.stderr)
        return None

def test_single(role, user, coll, cmd):
    allowed = query_opa(user, coll, cmd)
    if allowed is None:
        return {
            "role": role,
            "coll": coll,
            "cmd": cmd,
            "allowed": False,
            "status": "ERROR",
            "msg": "OPA connection error"
        }
    expected_allowed = cmd in EXPECTED[role][coll]
    status = "PASS" if allowed == expected_allowed else "FAIL"
    return {
        "role": role,
        "coll": coll,
        "cmd": cmd,
        "allowed": allowed,
        "expected": expected_allowed,
        "status": status
    }

def main():
    print("=== Avvio Test Matrice Ruoli-Collection per Policy ZTA (in parallelo) ===")
    print("Raccolta test da eseguire...")
    
    tasks = []
    for role, user in ROLE_TO_USER.items():
        for coll in COLLECTIONS:
            for cmd in COMMANDS:
                tasks.append((role, user, coll, cmd))
                
    total = len(tasks)
    passed = 0
    failed = 0
    errors = 0
    
    print(f"Esecuzione di {total} test in parallelo (max 10 thread)...")
    
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_single, role, user, coll, cmd) for role, user, coll, cmd in tasks]
        for fut in futures:
            results.append(fut.result())
            
    # Sort results for consistent output
    results.sort(key=lambda x: (x["role"], x["coll"], x["cmd"]))
    
    print("-" * 100)
    print(f"{'Role':<15} | {'Collection':<18} | {'Command':<8} | {'OPA Decision':<12} | {'Expected':<8} | {'Status'}")
    print("-" * 100)
    
    for r in results:
        if r["status"] == "PASS":
            passed += 1
            status_str = "\033[92mPASS\033[0m" # Green
        elif r["status"] == "FAIL":
            failed += 1
            status_str = "\033[91mFAIL\033[0m" # Red
        else:
            errors += 1
            status_str = f"\033[93m{r['status']}\033[0m" # Yellow
            
        allowed_str = "ALLOW" if r.get("allowed") else "DENY"
        expected_str = "ALLOW" if r.get("expected") else "DENY"
        
        print(f"{r['role']:<15} | {r['coll']:<18} | {r['cmd']:<8} | {allowed_str:<12} | {expected_str:<8} | {status_str}")
        
    print("-" * 100)
    print(f"Risultato: {passed}/{total} superati, {failed} falliti, {errors} errori.")
    
    if failed == 0 and errors == 0:
        print("\033[92mTutti i controlli sulle policy di accesso dei ruoli sono superati con successo!\033[0m")
        sys.exit(0)
    else:
        print("\033[91mErrore: Alcune verifiche non hanno rispettato le policy previste!\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
