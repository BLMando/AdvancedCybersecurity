# Procedural Memory & Lessons Learned

## User Impersonation & MongoDB RBAC Design

### Pattern to Avoid
Creating individual MongoDB SCRAM users (e.g., `paolo.roselli`) when new certificates are enrolled. This adds database provisioning overhead and clashes with the design of using OPA to manage ACLs dynamically based on certificate attributes.

### Correct Pattern
* Envoy terminates the client's mTLS certificate, extracting user identities and roles.
* Envoy/OPA acts as the PEP/PDP to authorize all queries and collections dynamically based on the client's mTLS identity.
* The underlying database connection inside the Envoy tunnel can safely fall back to using high-privileged `admin` SCRAM credentials (configured in `.env` inside `ZTA_MONGO_CREDENTIALS_JSON`).
* The CLI translates standard collections to user-specific RLS views (e.g., `clinical_records` to `v_clinical_doctor`) before sending them.
* Always ensure that `allow_admin_fallback=True` is enabled in all database client construction paths (both proxy and direct file connection fallback) so that user-specific SCRAM accounts are not required in MongoDB.
* Set the client driver's `authSource` parameter to `admin` if the SCRAM user is `admin`, as the root database user is provisioned in the MongoDB `admin` database.

## macOS Secure Enclave & Keychain Access Mappings

### Pattern to Avoid
Removing or leaving empty the `keychain-access-groups` entitlements in the macOS Xcode agent project, or starting the agent in a headless daemon/terminal context.

### Correct Pattern
* **Entitlement Requirement**: macOS Secure Enclave (`kSecAttrTokenIDSecureEnclave`) strictly requires the app to have codesigned keychain access group entitlements. Removing them throws `OSStatus error -34018` (missing entitlements).
* **Isolation Constraint**: Because the key is bound to the app's keychain access group (`com.zta.agent.keychain`), other applications (like Google Chrome, Safari, or CLI commands) cannot directly read the private key. Direct browser mTLS via Chrome is not possible; mTLS must be proxied through the ZTAAgent's local loopback proxy (`localhost:27019`).
* **Session Interactive Context**: Generating or using Secure Enclave keys with user presence checks requires display manager access (WindowServer). Running the app in a headless/non-interactive shell context throws `OSStatus error -25308` (interaction not allowed). Always launch the app bundle inside the graphical user session (e.g. via `open ZTAAgent.app`).
