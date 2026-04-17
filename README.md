# Advanced Cybersecurity — Zero Trust Architecture

A containerized implementation of a **Zero Trust Architecture (ZTA)** with dynamic identity-based access control for MongoDB resources. This project demonstrates how to build a defense-in-depth system where every access request is evaluated in real-time before being granted.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  CLIENT (mTLS Certificate)                                   │
│  Identity: user@corp.com, device: laptop-001                 │
└────────────────────┬─────────────────────────────────────────┘
                     │ mTLS (port 10000)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  ENVOY PROXY (PEP - Policy Enforcement Point)                │
│  • mTLS Termination (require_client_certificate: true)       │
│  • Lua Filter: Extract Identity (CN, JA3, IP)               │
│  • Mongo Proxy: Decode BSON (inspect collection, command)    │
│  • Ext_authz: Forward to OPA for policy decision             │
└────────────────────┬─────────────────────────────────────────┘
                     │ gRPC (port 9002)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  OPA (PDP - Policy Decision Point)                           │
│  • Risk Score Calculation:                                    │
│    ├── user_risk (known: 0, unknown: 30)                     │
│    ├── device_risk (TPM: 0, no-TPM: 20)                      │
│    └── network_risk (internal: 0, external: 15)              │
│  • Policy Evaluation (Rego language)                         │
│  • Action Threshold Matching (find: 60, insert: 40, etc.)    │
└────────────────────┬─────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
    [ALLOW]                   [DENY]
        │                         │
        ▼                         ▼
┌──────────────┐          (Access Blocked)
│  MongoDB     │
│  (Protected) │
└──────────────┘
```

## Components

| Component    | Role                           | Port      | Technology                |
| ------------ | ------------------------------ | --------- | ------------------------- |
| **Envoy**    | PEP (Policy Enforcement Point) | 10000     | L7 Proxy, mTLS terminator |
| **OPA**      | PDP (Policy Decision Point)    | 8181/9002 | Policy engine (Rego)      |
| **MongoDB**  | Protected Resource             | 27017     | Database                  |
| **NFTables** | L3/L4 Firewall                 | -         | Kernel firewall           |
| **Snort**    | NIDS (Network IDS)             | -         | Intrusion detection       |

## Identity Layer Implementation

### Features Implemented

#### mTLS Certificate-Based Authentication

- **Client certificates** required for all connections
- **Certificate CN** extracted as user identity
- **Server certificate** verification (CA trust)
- OpenSSL-based certificate generation and management

#### Envoy Identity Extraction (Lua Filter)

- Extracts certificate Subject from mTLS handshake
- Computes JA3 fingerprint for device identification
- Captures source IP for network classification
- Stores in connection metadata for downstream filters

#### MongoDB Protocol Inspection (mongo_proxy)

- L7 protocol decoding (BSON inspection)
- Extracts: database, collection, command, query parameters
- Logs in JSON format for analysis
- No need for application-level instrumentation

#### OPA Risk Scoring

```
risk_score = user_risk + device_risk + network_risk

user_risk:
  - Known user (whitelist) = 0
  - Unknown user = 30

device_risk:
  - TPM/OID bound = 0
  - JA3 only (no-tpm) = 20

network_risk:
  - Internal (172.20.0.0/16, 10.0.0.0/8) = 0
  - External = 15

Action Thresholds:
  - find: 60   (read-only, higher threshold)
  - insert: 40 (write operation)
  - update: 30 (modify existing)
  - delete: 20 (destructive)
  - drop: DENY (always denied)
```

#### Fail-Closed Security Model

- If OPA is unavailable: **request is DENIED**
- If certificate validation fails: **connection rejected**
- No fallback to open access

## Quick Start

### Prerequisites

- Docker & Docker Compose
- bash shell
- openssl (for certificate generation)
- mongosh (for database access)

### 1. Generate Certificates

```bash
bash scripts/generate-certs.sh
```

Creates:

- Root CA (ca.crt, ca.key)
- Envoy server certificate (envoy.crt, envoy.key)
- Client certificates (mario.crt/key, unknown.crt/key)
- Client PEM files (combined cert+key)

### 2. Start Services

```bash
docker compose up -d
sleep 5
```

Starts: MongoDB, Envoy, OPA, NFTables, Snort

### 3. Test Legitimate Access

```bash
mongosh \
  --tls \
  --tlsCAFile certs/ca/ca.crt \
  --tlsCertificateKeyFile certs/clients/mario.pem \
  "mongodb://admin:secret@localhost:10000/zta_db?authSource=admin" \
  --eval "db.utenti.find().pretty()"
```

Expected: Query results returned (ALLOW)

### 4. Test Restricted Access

```bash
mongosh \
  --tls \
  --tlsCAFile certs/ca/ca.crt \
  --tlsCertificateKeyFile certs/clients/unknown.pem \
  "mongodb://admin:secret@localhost:10000/zta_db?authSource=admin" \
  --eval "db.utenti.find().pretty()"
```

Expected: Access denied or higher threshold (risk score exceeded)

### 5. Run Demo

```bash
bash scripts/demo.sh
```

Automated end-to-end demonstration (5 minutes)

## Testing

### Test Suite

```bash
# Test 1: Identity extraction
bash scripts/test-identification.sh

# Test 2: MongoDB access through Envoy
bash scripts/test-mongo-access.sh

# Test 3: Complete demo
bash scripts/demo.sh
```

### Manual Testing

#### Check mTLS Enforcement

```bash
# Should FAIL (no certificate)
openssl s_client -connect localhost:10000

# Should SUCCEED (with certificate)
openssl s_client \
  -connect localhost:10000 \
  -cert certs/clients/mario.crt \
  -key certs/clients/mario.key
```

#### Test OPA Policy

```bash
# Query OPA directly
curl -X POST http://localhost:8181/v1/data/envoy/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "parsed_body": {
        "user": "mario.rossi",
        "device": "device-laptop-001",
        "network_ip": "172.20.0.5",
        "command": "find",
        "collection": "utenti"
      }
    }
  }' | jq .
```

#### View Logs

```bash
# Envoy logs (identity extraction, requests)
docker logs envoy

# OPA logs (policy decisions)
docker logs opa -f

# MongoDB logs
docker logs mongo

# Snort alerts
docker logs snort
```

## Configuration Files

| File                      | Purpose                                             |
| ------------------------- | --------------------------------------------------- |
| `docker-compose.yml`      | Service definitions and networking                  |
| `envoy/envoy.yaml`        | Envoy proxy configuration (mTLS, filters, clusters) |
| `opa/policies/authz.rego` | OPA authorization policy (risk scoring rules)       |
| `nftables/nftables.conf`  | L3/L4 firewall rules                                |
| `snort/snort.lua`         | Snort 3 configuration                               |
| `.env`                    | Environment variables (passwords, ports)            |
| `certs/`                  | Certificates and keys (gitignored)                  |

## Known Limitations

### Device Fingerprinting (Scenario B)

- **Without TPM/OID:** Uses JA3 fingerprint only
- **Limitation:** Two machines with same OS and client (e.g., MongoDB Compass) produce identical JA3
- **Impact:** Cannot distinguish between two legitimate devices with same profile
- **Mitigation:**
  - Add HTTP headers (User-Agent, Accept-Language) to fingerprint
  - Combine JA3 with IP address historical patterns
  - Future: Integrate SPIFFE/SPIRE for cryptographic workload identity

### Risk Scoring Without Splunk History

- **Current:** Static risk calculation (user + device + network)
- **Missing:** Historical context (did this user perform suspicious actions in the past hour?)
- **Future Phase 2:** Integrate Splunk for dynamic history-based risk calculation

### Rate Limiting

- **NFTables:** Applies globally (20 syn/sec limit)
- **Per-user limits:** Not yet implemented
- **Future:** Add per-identity rate limits in OPA

## Architecture Decisions

### mTLS vs API Keys

**Decision: mTLS Certificates**

- ✓ Hardware-bindable (TPM integration possible)
- ✓ Mutual authentication (server verifies client, vice versa)
- ✓ Standard enterprise practice
- ✗ Requires certificate management infrastructure

### Envoy Lua vs Custom Proxy

**Decision: Envoy + Lua for identity extraction**

- ✓ L7 protocol awareness (mongo_proxy for BSON decoding)
- ✓ Production-grade performance
- ✓ Extensive filter ecosystem
- ✗ Lua has limited stdlib (regex, JSON parsing manual)

### OPA vs Custom Policy Engine

**Decision: OPA (Open Policy Agent)**

- ✓ Industry standard, well-tested
- ✓ Declarative policy language (Rego)
- ✓ Easy to extend and modify
- ✓ Gathers policy analytics

### Fail-Closed vs Fail-Open

**Decision: Fail-Closed (deny by default)**

- ✓ ZTA principle: trust nothing by default
- ✓ Prevents accidental data exposure
- ✗ May cause legitimate access denial during OPA outages
- Mitigation: High OPA availability (clustering in production)

## Security Considerations

### Network Isolation

- Frontend network: Client → Envoy
- Backend network: Envoy → MongoDB
- MongoDB not exposed to frontend network (NFTables + network separation)
- Snort monitors L3/L4 traffic

## References

- [Envoy Proxy Documentation](https://www.envoyproxy.io/)
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- [Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
- [MongoDB Wire Protocol](https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/)
- [mTLS Best Practices](https://www.cert-manager.io/docs/tutorials/mtls/)
