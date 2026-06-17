# Procedural Memory & Lessons Learned

## Pattern to Avoid vs. Correct Pattern

### 1. Xcode Sandboxing & Keychain Import Fallback
- **Pattern to Avoid**: Assuming native GUI app enrollment `/enroll` automatically makes the X.509 certificate globally available to the macOS system login keychain.
- **Correct Pattern**: When running native GUI enrollment from python CLI, have a script or instructions to manually import the signed `.crt` file from the PKI server's issued directory into the user's login keychain (`security import ... -t cert`), ensuring the certificate is successfully linked to the private key reference stored inside the Secure Enclave.

### 2. Keychain Delete Query Constraints in Swift
- **Pattern to Avoid**: Including `kSecValueData` (cert data) in `SecItemDelete` query dictionary when trying to replace/overwrite a certificate.
- **Correct Pattern**: Exclude `kSecValueData` from the `SecItemDelete` query parameters; identify the certificate to delete using only identifier attributes like `kSecAttrLabel` or `kSecAttrApplicationLabel`. Otherwise, if the cert data differs (e.g. renewed certificate), `SecItemDelete` fails, and `SecItemAdd` returns a duplicate item error (`-25299`).

### 3. Envoy TCP ext_authz Connection-level Decisions
- **Pattern to Avoid**: Expecting Envoy's `ext_authz` network filter (running on a TCP listener) to evaluate query-level metadata on every MongoDB wire-protocol packet (e.g. query fields, JavaScript operators) dynamically.
- **Correct Pattern**: Envoy's TCP `ext_authz` filter runs **once** at connection establishment time. Real-time RLS queries and field-level permissions must be enforced at the MongoDB database level (MongoDB RBAC and Views) or using an application-level proxy filter.
