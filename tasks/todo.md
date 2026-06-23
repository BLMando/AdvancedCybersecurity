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

- `[x]` **Phase 8: PKI Attestation & User Identity Dropdown Fix**
  - `[x]` Modify `native/ZTAConsole/Services/PKIService.cs` to generate and sign the `proof_string` matching the original `ztaagent` enrollment payload.
  - `[x]` Modify `identity_pki/pki.py` to wrap the CSR verification fallback inside `verify_proof` in a robust try-except block, preventing cryptography ParseError exceptions from short-circuiting the validation logic.
  - `[x]` Rebuild the `identity-pki` Docker container.
  - `[x]` Compile and verify the MAUI app builds without errors.

- `[x]` **Phase 9: ZTAAgent Swift Secure Enclave & mTLS Fix**
  - `[x]` Modify `HardwareManager.swift` to use native `SecItemAdd` for certificate import.
  - `[x]` Modify `MongoProxyManager.swift` to retrieve `SecIdentity` using direct `kSecClassIdentity` query.
  - `[x]` Modify `PKIClient.swift` to retrieve `SecIdentity` using direct `kSecClassIdentity` query.
  - `[x]` Rebuild and compile the Swift ZTAAgent application.
  - `[x]` Verify the build succeeds.

- `[x]` **Phase 10: Consolidated Architectural Documentation**
  - `[x]` Write the final integrated architectural document `docs/Relazione_Architetturale_Integrata_ZTA.md` summarizing all ZTA aspects.
  - `[x]` Verify that all links are correct.

- `[x]` **Phase 11: Web Console Enrollment Delegation & CSR Cleanup**
  - `[x]` Add `/api/enroll` endpoint in `identity_pki/app.py` to delegate requests to the host local agent.
  - `[x]` Simplify `identity_pki/templates/index.html` by removing legacy CSR input and submission handlers, and wire the submit event to `/api/enroll`.
  - `[x]` Rebuild and restart the Docker environment.
  - `[x]` Verify that hardware auto-enrollment works end-to-end and populates the query dropdown.

- `[x]` **Phase 12: OIDC Federated mTLS & RFC 8705 Token Binding**
  - `[x]` Create `identity_pki/oidc.py` helper to manage keys and sign JWTs.
  - `[x]` Expose JWKS and `/api/oidc/token` endpoints in `identity_pki/app.py`.
  - `[x]` Implement local `/oidc/token` endpoint in macOS ZTAAgent (`LocalAPIServer.swift`).
  - `[x]` Implement local `/oidc/token` endpoint in Windows Agent (`tpm_agent_service.ps1`).
  - `[x]` Update Web Console frontend `index.html` to retrieve the JWT and pass it in `/api/query`.
  - `[x]` Update Web Console backend `/api/query` in `app.py` to use `MONGODB-OIDC` SASL authentication.
  - `[x]` Update Envoy `mongo_proxy` and OPA `authz.rego` to decode, verify JWT, and match the client cert thumbprint against the `cnf` claim.
  - `[x]` Rebuild, restart Docker, and verify the OIDC-bound query workflow end-to-end.
  - `[x]` Fix the PyMongo 4.17.0+ OIDC client authentication standard blocker in `/api/query` using callback-based `StaticTokenCallback` inheriting from `pymongo.auth_oidc.OIDCCallback`.

- `[x]` **Phase 13: Trusted Proxy Impersonation via Envoy & Production Stabilities**
  - `[x]` Update OPA `authz.rego` to support `trusted_proxies` bypass for OIDC connections.
  - `[x]` Update Flask backend `/api/query` in `app.py` to use the server's own client certificate when `combined_pem_path` for the user is unavailable.
  - `[x]` Update Windows agent `tpm_agent_service.ps1` to use HTTPS for PKI communications.
  - `[x]` Rebuild services and verify query execution from Web Console.
  - `[x]` Persist OIDC RSA signing private key in `identity_pki/oidc.py` to prevent signature mismatches on restarts.
  - `[x]` Automate MongoDB CA Trust store update at container startup via custom `mongo/entrypoint.sh` script.

- `[x]` **Phase 14: Single TouchID & Biometric Context Preservation**
  - `[x]` Refactor `MongoProxyManager.swift` (`findIdentity`) to query the identity directly via `kSecClassIdentity` with the active `LAContext`.
  - `[x]` Refactor `PKIClient.swift` (`urlSession didReceive challenge`) to query the identity directly via `kSecClassIdentity` and inject the active `LAContext` if available.
  - `[x]` Build and test the ZTAAgent application to ensure there are no compilation errors.
  - `[x]` Verify that starting the proxy session prompts once for TouchID, and subsequent queries (mTLS or OIDC token) use the preserved context without prompting again.

- `[x]` **Phase 15: External Identity Verification & MFA (OTP) during Enrollment**
  - `[x]` Implement standard in-memory AD users database in `app.py`.
  - `[x]` Expose `/api/auth/login` and `/api/auth/verify-otp` endpoints in `app.py`.
  - `[x]` Modify `/api/enroll` and `/api/csr` in `app.py` to validate `enrollment_session_token`.
  - `[x]` Restructure "Hardware CSR Enrollment" panel in `index.html` to integrate AD login and OTP input.

- `[x]` **Phase 16: Step-up Authentication in OPA & Flask**
  - `[x]` Update `/api/oidc/token` in `app.py` to generate Step-up claims in the JWT when requested.
  - `[x]` Update `/api/query` in `app.py` to support `update` and `delete` actions via PyMongo.
  - `[x]` Modify `identity.rego` to support JWT Step-up claims and 120s freshness checks.
  - `[x]` Modify `criteria.rego` to block write actions or high-billing-value queries if fresh step-up is missing.
  - `[x]` Update `index.html` query form to support operations select and trigger local agent `/oidc/token` with step-up.

- `[x]` **Phase 17: Certificate Revocation List (CRL) Integration**
  - `[x]` Implement `generate_crl()` in `pki.py` and call it on startup.
  - `[x]` Re-generate CRL immediately upon `revoke_certificate()` in `pki.py`.
  - `[x]` Reject OIDC token requests and queries in `app.py` if user CN is revoked.
  - `[x]` Configure `crl` file check in Envoy `DownstreamTlsContext` in `envoy.yaml`.

- `[x]` **Phase 18: Agent Updates & E2E Verification**
  - `[x]` Update macOS agent `PKIClient.swift` and `LocalAPIServer.swift` to handle enrollment session token and step-up flag.
  - `[x]` Update Windows agent `tpm_agent_service.ps1` to handle enrollment session token, step-up flag, and software key fallback.
  - `[x]` Rebuild and restart the Docker stack, run end-to-end verifications, and document results.

- `[x]` **Phase 19: Final Documentation Update**
  - `[x]` Update `docs/ZTA_AGENT_UPDATES_2026.md` with sections G (Primary Session Gating), H (401 Propagation from agents), I (Primary Auth Modal + auto-retry). Updated E2E control flow diagram to include the new Layer 0.
  - `[x]` Update `docs/Relazione_Architetturale_Integrata_ZTA.md` with Section 10 (Session Hardening Finale): tables, code snippets, 4-layer model ASCII diagram, NIST SP 800-207 alignment statement.
  - `[x]` Update `docs/ARCHITECTURE.md`: four-layer model, Windows TPM mention, 7 Security Principles (added Human Session Lifecycle, Progressive MFA, RFC 8705 Token Binding).
  - `[x]` Update `docs/README.md`: Key Features (4-layer auth, TPM agent, CRL, RFC 8705), Quick Start Step 5 (Web Console flow), Security Principles (session gating, step-up MFA, token binding).

- `[x]` **Phase 20: Certificates Revocation Tab & Doctor Update Fix**
  - `[x]` Add "Gestione Certificati" tab to `identity_pki/templates/index.html` with certificates list and "🚫 Revoca" button.
  - `[x]` Implement `loadCertsTable` and `revokeCertificateFromUI` in JavaScript in `index.html`.
  - `[x]` Add CSS rules for status classes `.status-active` and `.status-revoked` in `identity_pki/static/style.css`.
  - `[x]` Update `saveRecord` and `deleteRecord` in `index.html` to pass `patient_id` if present in the row data.
  - `[x]` Modify `/api/query` in `identity_pki/app.py` to extract `patient_id` and append it to the update/delete query filter.
  - `[x]` Rebuild the Docker environment.
  - `[x]` Verify the certificates list and revocation flow.
  - `[x]` Verify that doctor `paolo.roselli` can successfully update clinical records, and that delete is blocked by OPA.

## Verification Evidence (Phase 20)

### 1. Doctor Update & Delete Operations Test
Running `scratch/test_doctor_update.py` yields:
```
=== Testing Doctor Update & Delete Operations ===

[*] Step 1: Performing Primary AD Login for paolo.roselli@ospedale.it...
[✓] AD Login successful. Simulated OTP: 847641
[*] Verifying MFA OTP...
[✓] MFA Verified! Session token: efe53d3a-7c65-4bba-aad8-9dbf0a82a217

[*] Step 2: Fetching Step-Up OIDC JWT from local agent at http://localhost:9090/oidc/token...
[✓] Successfully retrieved OIDC token!

[*] Step 3: Finding a clinical record for patient 4f781fb9-ce9f-5313-913d-7ec2be6047fa...
[✓] Found record _id: 167a6bde-aff9-5322-8c56-9a8432d277d2, patient_id: 4f781fb9-ce9f-5313-913d-7ec2be6047fa

[*] Step 4: Attempting update WITHOUT patient_id (expecting rejection)...
[✓] Expected failure occurred! Status code: 403
Error message: {"error_type":"authorization_denied","message":"OPA/RBAC Access Denied: Document failed validation (missing patient_id)","role":"doctor","status":"error","translated_collection":"clinical_records"}

[*] Step 5: Attempting update WITH patient_id (expecting success)...
[✓] SUCCESS! Update succeeded!
Server response: Aggiornati 1 documenti in 'clinical_records'

[*] Step 6: Attempting delete (expecting 403 Access Denied)...
[✓] Expected 403 failure occurred! Status code: 403
Error message: {"error_type":"authorization_denied","message":"OPA/RBAC Access Denied: Role 'doctor' is not allowed to perform 'delete' on collection 'clinical_records'","role":"doctor","status":"error","translated_collection":"clinical_records"}
```



