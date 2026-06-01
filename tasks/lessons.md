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
