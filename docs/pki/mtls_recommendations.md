# mTLS recommendations (lab to production)

These items focus on client behavior and PKI outputs, leaving Envoy policy details for later.

## Client-side recommendations

- Always verify the server certificate using a trusted CA bundle to prevent MITM.
- Keep the client identity tied to hardware-backed keys when possible (Keychain / TPM / Secure Enclave).
- Fail closed on TLS errors and report whether the failure is trust, hostname, or handshake.
- Keep separate CA bundles for PKI endpoints and mTLS gateways if they are distinct.

## PKI output recommendations

- Issue client certs with KeyUsage (digitalSignature, keyEncipherment) and EKU (clientAuth).
- Use deterministic SAN entries to express hardware attributes (e.g., MAC-*, CPU-*).
- Enforce strict CN validation to prevent path traversal or unexpected file writes.
- Persist issuance metadata for audit (who, when, and method).

## Operational recommendations

- Rotate client certs on a defined schedule and document the rotation workflow.
- Avoid storing private keys unencrypted unless the key is hardware protected.
- Log certificate issuance and revocation with a stable identifier (CN + serial).
