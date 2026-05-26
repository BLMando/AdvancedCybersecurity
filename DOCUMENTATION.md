# ZTA mTLS + OPA + Envoy + Splunk — Integration Documentation

## Architecture Overview

```
┌──────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌──────────┐
│  MongoDB     │◄────│  Envoy      │◄────│  mTLS Proxy      │◄────│  Client  │
│  Compass     │     │  (PEP)      │     │  (local Python)  │     │  (Any)   │
│  / mongosh   │     │  :10000     │     │  :27018          │     │          │
└──────────────┘     └──────┬──────┘     └──────────────────┘     └──────────┘
                            │
                    ┌───────┴───────┐
                    │  OPA (PDP)    │
                    │  :8181 / :9002│
                    └───────┬───────┘
                            │ decision logs
                    ┌───────┴──────────┐
                    │  Forwarder       │
                    │  opa-splunk-     │
                    │  forwarder :5000 │
                    └───────┬──────────┘
                            │ HEC
                    ┌───────┴────┐
                    │  Splunk    │
                    │  :8000     │
                    └────────────┘
```

### Data Flow (end-to-end)

1. **Client** (Compass/mongosh/script) connects to **mTLS Proxy** on `localhost:27018`
2. **mTLS Proxy** wraps the connection with a client certificate (`test.doctor.internal`) and connects to **Envoy** on `:10000`
3. **Envoy** terminates the TLS connection, extracts the client certificate identity via TLS Inspector
4. **mongo_proxy filter** inspects the MongoDB wire protocol (extracts command, collection)
5. **ext_authz filter** calls **OPA** (gRPC on `:9002`) with TLS identity + MongoDB metadata
6. **OPA** evaluates the policy (risk score, role, action), returns allow/deny
7. If **allowed**, Envoy's **tcp_proxy** forwards data to **MongoDB** (`mongo:27017`)
8. **MongoDB** responds, data flows back through Envoy → Proxy → Client
9. **OPA** asks **Forwarder** (`POST /api/stats`) for request-correlated statistics retrieved from Splunk
10. **Envoy** access logs are shipped by **Forwarder** to **Splunk HEC** (index `zta_envoy`)

### Components

| Component | Role | Ports |
|-----------|------|-------|
| `identity-pki` | Certificate Authority & Issuer | `8080` |
| `mongo` | MongoDB 7 (target database) | `27017` |
| `envoy` | Policy Enforcement Point (mTLS + authz) | `10000` (mTLS), `10001` (HTTP test), `9901` (admin) |
| `opa` | Policy Decision Point | `8181` (REST API), `9002` (gRPC ext_authz) |
| `opa-splunk-forwarder` | Decision log → Splunk bridge | `5000` |
| `splunk` | SIEM & Dashboards | `8000` (UI), `8088` (HEC), `8089` (mgmt) |
| `snort` | NIDS (network monitoring) | (host net) |
| `nftables` | L3/L4 firewall | (host net) |

---

## Prerequisites

- Docker & Docker Compose
- Python 3.10+ with `cryptography`, `requests`
- MongoDB Compass (optional, for GUI testing)
- OpenSSL (for manual certificate generation)

```powershell
pip install requests cryptography
```

---

## Setup & Startup

### 1. Environment Configuration

Copy `.env.example` to `.env` and adjust values:

```powershell
copy .env.example .env
```

Key variables in `.env`:

```
MONGO_ROOT_USERNAME=zta_user
MONGO_ROOT_PASSWORD=zta_password
SPLUNK_PASSWORD=SplunkPassword123!
```

### 2. Start All Services

```powershell
docker compose up -d --build
```

Wait for all containers to be healthy:

```powershell
docker compose ps
```

All services should show `Up`. The first startup of Splunk can take 2-5 minutes.

### 3. Initialize Splunk (index + dashboard)

```powershell
python scripts/splunk_setup.py
```

This creates the `zta_envoy` index and imports/updates the ZTA dashboard (Simple XML `version="1.1"`).

Docker Splunk uses a self-signed certificate; the script disables TLS verification by default (`SPLUNK_VERIFY_TLS=false`). If you still see `CERTIFICATE_VERIFY_FAILED`, ensure you have not set `SPLUNK_VERIFY_TLS=true` in your environment.

### 4. Create HEC token in Splunk Web

Open **Settings → Data Inputs → HTTP Event Collector** and create a token for index `zta_envoy`.  
Add the value to `.env` as `SPLUNK_HEC_TOKEN_ENVOY`.

### 5. Restart the Forwarder (to pick up new token)

```powershell
docker compose restart opa-splunk-forwarder
```

---

## Quick Verification

### 1. Verify Envoy mTLS (HTTP test endpoint)

```powershell
curl --cert certs/client/test.doctor.crt --key certs/client/test.doctor.key `
  --cacert volumes/certs/ca/ca.crt https://localhost:10001/
```

Expected output: `✓ ZTA Hardware mTLS Verified!`

### 2. Verify OPA is reachable

```powershell
curl http://localhost:8181/v1/policies
```

Expected: lists the loaded Rego policies.

### 3. Verify the full chain (automated test)

```powershell
python scripts/test_mtls_proxy.py
```

Expected output:
```
Proxy on :27019
Sending MongoDB ping through proxy...
  Sent OP_QUERY ping (45 bytes)
  Received 156 bytes
==================================================
SUCCESS: MongoDB responded through Envoy mTLS!
==================================================
```

---

## Testing with MongoDB Compass (GUI)

### Step 1: Start the mTLS proxy

```powershell
python scripts/mtls_proxy.py
```

Keep this terminal window open. The proxy listens on `localhost:27018`.

### Step 2: Configure Compass

Connect with:

| Field | Value |
|-------|-------|
| Hostname | `localhost` |
| Port | `27018` |
| Authentication | `Username/Password` |
| Username | `zta_user` |
| Password | `zta_password` |
| Authentication DB | `admin` |

**Do not enable TLS/SSL** in Compass — the proxy handles mTLS with Envoy.

### Step 3: Verify in Splunk

1. Open `http://localhost:8000` (admin / `SplunkPassword123!`)
2. Search `index=zta_envoy` to see Envoy access logs and decisions
3. Check `decision` and `risk_score` fields to inspect policy outcomes
4. Open the "ZTA Overview" dashboard to see the pre-built visualizations

---

## Testing with mongosh (CLI)

```powershell
# Using the mTLS proxy
mongosh "mongodb://zta_user:zta_password@localhost:27018/"
```

Or directly via the proxy script's forwarding port.

---

## Testing with Different Identities

Each client certificate maps to a different user in OPA policy:

| Certificate | User | Role | Risk Profile |
|------------|------|------|-------------|
| `test.doctor.crt` | `test.doctor` | doctor | Low |
| `test.user.crt` | `test.user` | auditor | Medium |

To test a different identity, stop the proxy, edit `scripts/mtls_proxy.py` to change `CERT`/`KEY` paths (lines 17-18), and restart.

---

## Generating New Client Certificates

### Software-backed (lab mode) — via PKI API

```powershell
curl -X POST http://localhost:8080/api/issue `
  -H "Content-Type: application/json" `
  -d '{\"user\":\"mario.verdi\",\"role\":\"doctor\",\"department\":\"Cardiologia\"}'
```

This generates a key pair inside the PKI server. The private key is saved to:

```
volumes/certs/ca/issued/mario.verdi/private_key.pem
```

Copy it to the client directory:

```powershell
copy volumes/certs/ca/issued/mario.verdi/private_key.pem volumes/certs/client/mario.verdi.key
```

The certificate is already at `volumes/certs/client/mario.verdi.crt`.

### Via OpenSSL (quick & dirty)

```powershell
openssl req -x509 -newkey rsa:2048 -keyout certs/client/test.user.key `
  -out certs/client/test.user.crt -days 365 -nodes -subj "/CN=test.user"
```

(For production, have the CSR signed by the PKI CA.)

### Full API reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/issue` | POST | Generate key + cert (software mode) |
| `/api/csr` | POST | Sign an external CSR (hardware mode) |
| `/api/challenge` | GET | Get a challenge for hardware attestation |
| `/api/verify` | POST | Verify a hardware identity |
| `/api/list` | GET | List all issued certificates |
| `/api/revoke` | POST | Revoke a certificate |

---

## OPA Policy Overview

File: `opa/policies/authz.rego`

The policy implements a risk-score based access control model:

```
risk_score = user_risk + device_risk + network_risk + collection_risk_boost
```

| Factor | Low Risk | High Risk |
|--------|----------|-----------|
| **User** | Known user (0) | Unknown user (+30) |
| **Device** | Has TPM (0) | No TPM (+20) |
| **Network** | Internal (0) | External (+15) |
| **Collection** | Regular (0) | Sensitive (+10) |

### Thresholds by Operation

| Operation | Max Risk Score |
|-----------|---------------|
| `find` | 60 |
| `insert` | 40 |
| `update` | 30 |
| `delete` | 20 |

### Command Groups

| Category | Commands |
|----------|----------|
| **Always allowed** | `hello`, `isMaster`, `saslStart`, `saslContinue`, `buildinfo`, `buildInfo`, `ping`, `getLog`, `getCmdLineOpts`, `serverStatus` |
| **Unparseable connections** | Any connection where `mongo_proxy` cannot decode the wire protocol (`action_name == "unknown"`) |
| **Destructive (denied)** | `drop`, `delete_database` |

### Special Rule: Unparseable Connections

Envoy's `mongo_proxy` filter does not support MongoDB OP_MSG (opcode 2013), used by MongoDB 3.6+ drivers and Compass. When an OP_MSG is received:

1. `mongo_proxy` logs `mongo decoding error: invalid mongo op 2013`
2. No `parsed_body` metadata is produced
3. `action_name` defaults to `"unknown"`
4. The OPA rule `allow if { action_name == "unknown" }` permits the connection

This means **Compass connections bypass command-level RBAC**. The connection succeeds, but OPA cannot distinguish between `find`, `insert`, `drop`, etc. A custom Envoy filter (Lua/Wasm) would be needed to parse OP_MSG.

---

## Envoy Filter Chain

File: `envoy/envoy.yaml`

The MongoDB listener on port `10000` has this filter chain (top-to-bottom):

```
TLS Termination (mTLS with client cert required)
    ↓
TLS Inspector (extracts client principal, JA3 fingerprint)
    ↓
mongo_proxy (parses MongoDB wire protocol → metadata)
    ↓
ext_authz (gRPC call to OPA for allow/deny)
    ↓
tcp_proxy (forwards to MongoDB cluster)
```

---

## Forwarder Details

File: `scripts/opa_splunk_forwarder/forwarder.py`

The forwarder serves two responsibilities:

| Source | Endpoint | Splunk Index |
|--------|----------|-------------|
| OPA stats query | `POST /api/stats` | N/A (query-only) |
| Envoy access logs | `POST /api/envoy-logs` | `zta_envoy` |
| Envoy log file (tail) | Watches `/var/log/envoy/access.log` | `zta_envoy` |

### Known Issues & Fixes Applied

1. **OPA decision logging removed**: OPA no longer pushes decision logs.
2. **Stats endpoint added**: OPA now calls `/api/stats` to get Splunk-backed frequency statistics.
3. **Risk context fields forwarded**: Envoy access logs now include `user`, `device`, `network_ip`, `resource`, `command`, `decision`, `risk_score`.
4. **Periodic flush**: Added 5-second periodic flush to HEC client so events don't get stuck in buffer.
5. **SSL context**: Fixed `ssl.create_default_context()` (was incorrectly called as `urllib.request.create_default_context()`).

---

## Troubleshooting

### mTLS connection fails: `CERTIFICATE_VERIFY_FAILED`

The lab PKI certificates lack the Authority Key Identifier extension. The mTLS proxy uses `ssl.CERT_NONE` to bypass verification. This is intentional for the lab environment.

### Connection times out (no response from MongoDB)

Check ext_authz stats:

```powershell
curl http://localhost:9901/stats?filter=ext_authz
```

If `denied` is > 0 and `ok` is 0, OPA is blocking connections. Verify:
1. OPA policy has the `action_name == "unknown"` allow rule
2. OPA is reachable from Envoy: `docker compose ps`
3. Envoy logs: `docker logs envoy --tail 30`

### Compass connects but authentication fails

1. Verify credentials: `zta_user` / `zta_password`, auth DB `admin`
2. Ensure MongoDB is running: `docker compose ps mongo`
3. Check MongoDB logs: `docker logs mongo --tail 20`

### Envoy admin interface

```powershell
# Stats
curl http://localhost:9901/stats
# Clusters
curl http://localhost:9901/clusters
# Listeners
curl http://localhost:9901/listeners
# Logging (change log level)
curl -X POST http://localhost:9901/logging?level=debug
```

### Restart individual components

```powershell
docker compose restart envoy
docker compose restart opa
```

---

## Environment Variables (.env)

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGO_ROOT_USERNAME` | MongoDB admin user | `zta_user` |
| `MONGO_ROOT_PASSWORD` | MongoDB admin password | `zta_password` |
| `MONGO_INITDB_DATABASE` | Initial database | `zta_db` |
| `SPLUNK_PASSWORD` | Splunk admin password | `SplunkPassword123!` |
| `SPLUNK_HEC_TOKEN_ENVOY` | HEC token for Envoy events | (created in Splunk Web) |
| `SPLUNK_PASSWORD` | Splunk admin password (for stats API query) | `SplunkPassword123!` |
| `ZTA_PKI_ORGANIZATION` | PKI org name (optional) | |
| `ZTA_PKI_CA_CN` | PKI CA common name (optional) | |

---

## File Reference

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Service orchestration |
| `envoy/envoy.yaml` | Envoy proxy configuration |
| `opa/policies/authz.rego` | OPA authorization policy |
| `scripts/mtls_proxy.py` | mTLS proxy for Compass |
| `scripts/test_mtls_proxy.py` | Automated end-to-end test |
| `scripts/opa_splunk_forwarder/forwarder.py` | Log forwarder service |
| `scripts/opa_splunk_forwarder/heclient.py` | Splunk HEC client library |
| `scripts/splunk_setup.py` | Splunk index + dashboard bootstrap |
| `scripts/generate_test_data.py` | Synthetic data generator |
| `identity_pki/pki.py` | PKI certificate service |
| `identity_pki/app.py` | PKI HTTP API |
| `splunk/dashboards/zta_overview.xml` | Splunk dashboard |
| `volumes/certs/` | Certificate storage (Docker volume mount) |

---

## Known Limitations

1. **OP_MSG not supported by mongo_proxy**: Envoy's `mongo_proxy` filter only understands legacy OP_QUERY/OP_REPLY (opcodes 2004/1). Modern MongoDB drivers (3.6+) use OP_MSG (opcode 2013). The connection passes through but OPA cannot extract command/collection metadata. A custom Envoy filter (Lua/Wasm) would be needed.

2. **Lab-grade PKI**: Certificates lack Authority Key Identifier extensions, requiring `CERT_NONE` in the mTLS proxy. Production deployment should use proper PKI with full X.509 extensions.

3. **No mongo_proxy metadata on initial connection**: Envoy's TCP ext_authz filter evaluates at connection time, before mongo_proxy has seen any data. The `parsed_body` is always `{}` (empty), making command-level enforcement only possible for the first command in multi-command connections.

4. **Single-threaded proxy**: The mTLS proxy uses a simple threading model. For production, use a proper sidecar proxy (e.g., Envoy itself).
