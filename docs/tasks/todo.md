# Task List - ZTA MongoDB TCP Proxy

- [x] **Phase 1: Swift Agent (MongoProxyManager & API)**
    - [x] Create `MongoProxyManager.swift` with `MongoProxySession` (TCP NWListener, biometrics, mTLS forwarding via SecIdentity).
    - [x] Update `LocalAPIServer.swift` to add `/proxy/start`, `/proxy/stop`, and `/proxy/status`.

- [x] **Phase 2: Python CLI (mongo_proxy_cli.py)**
    - [x] Replace direct mTLS connection with ZTA Agent proxy lifecycle (start proxy session, run query on plain local TCP port, stop proxy session).

- [x] **Phase 3: Security & OPA (authz.rego)**
    - [x] Align role definitions and resolve user privilege discrepancy for `paolo.roselli`.
    - [x] Harden the `action_name == "unknown"` fallback logic.

- [x] **Phase 4: Envoy & Docker (envoy.yaml, docker-compose.yml)**
    - [x] Fix Envoy deprecation warnings.
    - [x] Add healthcheck for Envoy to prevent race conditions during startup.

- [x] **Phase 5: Verification & Audit**
    - [x] Build and run the Swift ZTAAgent.
    - [x] Execute MongoDB CLI queries via the local proxy and verify end-to-end mTLS.
    - [x] Verify OPA policies correctly block unauthorized collections.

## Review & Verification Evidence

### 1. Dynamic Local Proxy End-to-End Connectivity
Verified that `mongo_proxy_cli.py` connects dynamically through the Swift ZTAAgent via localhost loopback (dynamic port `27024`). The mTLS handshake terminates successfully on Envoy using the client certificate and private key stored securely inside the macOS Secure Enclave.
```
[*] Test connettività ZTA → Envoy localhost:10000
[*] Contatto ZTA Agent per avviare il tunnel MongoDB per paolo.roselli...
[✓] Tunnel ZTA avviato su localhost:27024 (Token: BE767C69-38DC-46D9-BDCC-0629E092D7D2)
[*] Connessione al tunnel locale localhost:27024 come mario.rossi...
[✓] Envoy mTLS → MongoDB: CONNECTED (2592.1ms)
```

### 2. Row Level Security View Translation (Reads)
Verified that querying a raw collection (`clinical_records` or `billing`) automatically maps to the respective view for non-admin users to enforce RLS and prevent raw access:
- **Dottore (`paolo.roselli` / `mario.rossi`)**:
  - `clinical_records` -> translates to `v_clinical_doctor` (Success, returns RLS-filtered documents).
  - `billing` -> `billing` (Blocked by OPA/RBAC, no read permission).
- **Billing Staff (`anna.verdi`)**:
  - `billing` -> translates to `v_billing_staff` (Success, returns billing documents).
  - `clinical_records` -> `clinical_records` (Blocked by OPA/RBAC, no read permission).

Example doctor query:
```
[*] Query: clinical_records.find({}) limit=10
[*] Contatto ZTA Agent per avviare il tunnel MongoDB per paolo.roselli...
[✓] Tunnel ZTA avviato su localhost:27026 (Token: F48733FB-CB21-4937-8A65-4EA79B85B031)
[*] Connessione al tunnel locale localhost:27026 come mario.rossi...
[*] RLS: Traduzione collection 'clinical_records' -> 'v_clinical_doctor'
[✓] Trovati 10 documenti (3036.3ms)
```

### 3. OPA Rules Hardening & Normalization
Updated `authz.rego` to normalize view names (`v_...`) to their base collection names. This ensures all policies (sensitive tags, risk boosts, query inspection rules, and hard denies) are automatically inherited by views:
- Verification command: `docker compose exec opa ./opa_envoy_linux_amd64 test /policies -v`
- Result: **PASS: 18/18** (all tests pass, including new cases validating view normalization).
