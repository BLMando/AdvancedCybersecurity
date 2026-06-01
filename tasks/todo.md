# ZTA Roles & Delegated Auth Implementation Todo List

- `[x]` **Phase 1: Shared Roles Registry & PKI Integration**
  - `[x]` Create `shared/zta_roles.py` as the single source of truth for ZTA roles.
  - `[x]` Update `identity_pki/app.py` to expose `/api/roles` endpoint.
  - `[x]` Update `identity_pki/app.py` to validate requested roles against the registry on enrollment.
  - `[x]` Modify `identity_pki/pki.py` to generate MongoDB server certificates (`mongo.pem` combined) at startup.
  - `[x]` Mount `./shared` into `identity-pki` service in `docker-compose.yml`.

- `[x]` **Phase 2: Client Enrollment Validation**
  - `[x]` Update `scripts/enroll.py` to fetch valid roles from the PKI server and validate the requested `--role` prior to requesting a certificate.

- `[x]` **Phase 3: OPA Policy Upgrades**
  - `[x]` Update `opa/policies/authz.rego` to extract the user's role directly from the client certificate's `Title` field via X.509 parsing, rather than a hardcoded static user-role map.

- `[x]` **Phase 4: MongoDB X.509 mTLS Setup**
  - `[x]` Update `mongo/Dockerfile` to require TLS and configure certificate key file.
  - `[x]` Mount `./volumes/certs/server` and `./volumes/certs/ca` to the `mongo` container in `docker-compose.yml`.
  - `[x]` Update `mongo/init-healthcare.py` to:
    - `[x]` Import roles dynamically from `shared.zta_roles`.
    - `[x]` Create the external X.509 user `CN=envoy,O=AdvancedCybersecurity-Lab,C=IT` with appropriate role mappings.
  - `[x]` Update `envoy/envoy.yaml` to connect to MongoDB using client cert mTLS (X.509 auth).

- `[x]` **Phase 5: Client CLI Credentials Removal**
  - `[x]` Refactor `scripts/mongo_proxy_cli.py` to remove the static `CN_TO_MONGO` credentials mapping, ensuring no database passwords reside in the client.

- `[x]` **Phase 6: Verification & Validation**
  - `[x]` Fix hardcoded username check in `PKIClient.swift` to support dynamic user authentication.
  - `[x]` Fix `HardwareManager.saveCertificate` to use `security import` CLI for correct cert-key link.
  - `[x]` Make `generateHardwareKey` idempotent (reuse existing SE key on re-enrollment).
  - `[x]` Rebuild and restart the Docker environment.
  - `[x]` Verify role validation during enrollment (valid and invalid roles).
  - `[x]` Verify end-to-end queries via the local proxy using X.509 credentials-free client auth.
  - `[x]` Confirm OPA field-level masking (auditor sees `billing_amount_approx`, `insurance_masked`).
  - `[x]` Confirm role-level view routing (`v_clinical_doctor`, `v_clinical_auditor`, `v_billing_auditor`).

- `[x]` **Phase 7: Web Console Local ZTA Agent Proxy Integration**
  - `[x]` Update `docker-compose.yml` to resolve `host.docker.internal` for the `identity-pki` service.
  - `[x]` Update backend `identity_pki/pki.py` (`list_certificates`) to extract user role and `is_hardware` state.
  - `[x]` Update backend `identity_pki/app.py` (`/api/query`) to accept `local_proxy_port` and bypass private key presence validation for hardware users.
  - `[x]` Update front-end `identity_pki/templates/index.html` with hardware badges, biometrics trigger calling `/proxy/start`, and immediate teardown via `/proxy/stop`.
  - `[x]` Perform end-to-end validation of hardware-enrolled query flow and software fallback.

## Verification Evidence (Phase 7)

### 1. Active Certificates API
Calling `GET /api/admin/certificates` returns:
```json
[
  {"is_hardware":false,"role":"billing_staff","status":"active","user":"test.user.two"},
  {"is_hardware":true,"role":"auditor","status":"active","user":"test_auditor"},
  {"is_hardware":false,"role":"doctor","status":"active","user":"test.user"},
  {"is_hardware":true,"role":"doctor","status":"active","user":"paolo.roselli"}
]
```

### 2. Biometric-Enforced Local Proxy Flow (User `paolo.roselli`)
1. **Initialize Local Loopback Port (TouchID Prompted):**
   ```bash
   curl -s -X POST -H "Content-Type: application/json" -d '{"common_name": "paolo.roselli", "ttl_seconds": 60}' http://localhost:9090/proxy/start
   # Returns: {"status":"success","port":27021,"session_token":"4701FF17-2014-45B2-B2E7-7E7635114C24"}
   ```
2. **Execute Query via PKI Backend to Local Proxy:**
   ```bash
   curl -s -X POST -H "Content-Type: application/json" -d '{"user": "paolo.roselli", "collection": "clinical_records", "filter": "{\"patient_id\": \"4f781fb9-ce9f-5313-913d-7ec2be6047fa\"}", "limit": 1, "local_proxy_port": 27021}' http://localhost:8080/api/query
   # Returns: 200 OK with clinical data. RLS routed to 'v_clinical_doctor'
   ```
3. **De-allocate Port:**
   ```bash
   curl -s -X POST -H "Content-Type: application/json" -d '{"session_token": "4701FF17-2014-45B2-B2E7-7E7635114C24"}' http://localhost:9090/proxy/stop
   # Returns: {"status":"success","message":"Session stopped"}
   ```


