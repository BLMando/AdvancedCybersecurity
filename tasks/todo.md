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

