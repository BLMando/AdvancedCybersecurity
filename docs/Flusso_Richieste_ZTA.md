# Flusso delle Richieste — Sistema Zero Trust Architecture (ZTA)

Questo documento descrive nel dettaglio ogni chiamata che avviene nel sistema, dalla fase di login fino all'esecuzione di una query MongoDB, incluso il flusso di logging verso Splunk.

---

## Architettura dei componenti

```mermaid
graph LR
    Client["🖥️ Client\n(Flask Web UI / CLI)"]
    PKI["🔐 identity-pki\n:8080\nPKI + OIDC + API"]
    Envoy["🛡️ Envoy Proxy\n:10000\nmTLS + Wasm filter"]
    OPA["⚖️ OPA\n:8181\nPolicy Decision Point"]
    Mongo["🗄️ MongoDB\n:27017\n(TLS, solo via Envoy)"]
    Forwarder["📡 zta-log-forwarder\n:5000\nAggregatore log"]
    Splunk["📊 Splunk\n:8088 HEC\nSIEM"]

    Client -->|"HTTPS"| PKI
    Client -->|"mTLS :10000"| Envoy
    Envoy -->|"HTTP /v1/data/..."| OPA
    OPA -->|"HTTPS /api/revocation/..."| PKI
    Envoy -->|"TLS :27017"| Mongo
    Envoy -->|"/var/log/envoy/ volume condiviso"| Forwarder
    Forwarder -->|"HEC"| Splunk
    PKI -->|"/api/stats"| Forwarder
```

---

## FASE 1 — Enrollment (una-tantum per dispositivo)

Prima di poter fare qualsiasi richiesta, l'utente deve ottenere un certificato X.509 che Envoy userà per autenticarlo a livello TLS (mTLS).

```mermaid
sequenceDiagram
    actor User as Utente
    participant UI as Flask Web UI
    participant PKI as identity-pki

    User->>UI: Login con email + password AD simulato
    UI->>PKI: POST /api/login {email, password}
    PKI-->>UI: 200 + enrollment_session_token (15 min TTL)

    Note over UI,PKI: OTP step (MFA)
    UI->>PKI: POST /api/login/mfa {session_token, otp}
    PKI-->>UI: 200 {session_token confermato}

    Note over UI,PKI: Enrollment certificato
    UI->>PKI: POST /api/certificates {enrollment_session_token, user, role}
    PKI->>PKI: PKIService.issue_certificate() genera coppia RSA, firma CSR con CA interna
    PKI->>PKI: provision_mongo_user() crea utente MongoDB con ruolo RBAC
    PKI-->>UI: 200 {certificate_pem, private_key_pem}

    Note over User,PKI: Il certificato contiene CN=user, OU=MAC:xx. Firmato dalla CA interna
```

**Endpoint coinvolti:**
- `POST /api/login` → verifica credenziali AD, crea `ENROLLMENT_SESSIONS` entry
- `POST /api/login/mfa` → verifica OTP, marca sessione come MFA-verificata
- `POST /api/certificates` → emette certificato X.509, fa provisioning MongoDB

---

## FASE 2 — Ottenimento del JWT (OIDC Token)

Il JWT è il secondo fattore di autenticazione, **certificate-bound** (RFC 8705). Viene emesso solo dopo verifica hardware/biometrica e dura 15 minuti.

```mermaid
sequenceDiagram
    actor User as Utente
    participant UI as Flask Web UI
    participant PKI as identity-pki

    User->>UI: Richiede accesso a MongoDB
    UI->>PKI: POST /api/oidc/token {challenge_id, signature, proof_string}

    PKI->>PKI: verify_proof() verifica attestazione hardware
    PKI->>PKI: Controlla PRIMARY_SESSIONS[cn] valida 12h dalla login AD+MFA
    PKI->>PKI: Controlla revoked_dir/{cn}.rev - cert non revocato
    PKI->>PKI: issue_jwt(user, role, cert_sha256_hex)

    Note over PKI: JWT claims: sub, role, jti=uuid-v4, exp=now+900, cnf.x5t-S256=cert_fingerprint

    PKI-->>UI: 200 {access_token: "eyJ..."}

    Note over User,UI: Il JWT è certificate-bound. OPA verificherà che cnf.x5t-S256 coincida col cert mTLS presentato
```

**Endpoint coinvolti:**
- `POST /api/oidc/token` → emette JWT RS256 con `jti` UUID univoco e `cnf` (cert binding)

---

## FASE 3 — Connessione MongoDB e Autenticazione OIDC (saslStart)

Il client apre una connessione TCP verso Envoy `:10000`. Tutto il traffico MongoDB passa per il Wasm filter prima di arrivare a MongoDB.

```mermaid
sequenceDiagram
    participant Client as Client pymongo
    participant Envoy as Envoy mTLS + Wasm
    participant OPA as OPA
    participant PKI as identity-pki
    participant Mongo as MongoDB

    Note over Client,Envoy: TCP Handshake + mTLS
    Client->>Envoy: TLS ClientHello + certificato client X.509
    Envoy->>Envoy: Valida cert contro CA + CRL. Se invalido: RESET TCP immediato

    Client->>Envoy: OP_MSG cmd=hello
    Envoy->>OPA: POST /v1/data/envoy/authz/allow {command: "hello"}
    OPA-->>Envoy: {result: true} - bypass rule
    Envoy->>Mongo: forward
    Mongo-->>Client: hello response

    Note over Client,Mongo: Autenticazione MONGODB-OIDC
    Client->>Envoy: OP_MSG saslStart MONGODB-OIDC payload=BinData jwt=eyJ...

    Envoy->>Envoy: Wasm parse_op_msg cmd=saslStart
    Envoy->>Envoy: Wasm extract_jti_from_sasl_start: base64 decode payload, JWT claims, jti cached in session_jti

    Envoy->>OPA: POST /v1/data/envoy/authz/allow {command: "saslStart", mechanism: MONGODB-OIDC, jwt}

    OPA->>OPA: identity.valid_oidc_token: firma RS256, exp, aud, iss, cnf fingerprint match
    OPA->>PKI: GET /api/revocation/paolo.roselli
    PKI-->>OPA: {revoked: false}
    OPA-->>Envoy: {result: true}

    Envoy->>Envoy: log::info! WASM_AUDIT {user, cmd=saslStart, decision=ALLOW, jti}
    Envoy->>Mongo: forward
    Mongo-->>Client: saslStart response

    Client->>Envoy: OP_MSG saslContinue
    Envoy->>OPA: {command: saslContinue} - bypass rule
    Envoy->>Mongo: forward
    Mongo-->>Client: ok=1 autenticazione completata
```

**Cosa fa il Wasm in saslStart:**
1. Parsa il pacchetto BSON OP_MSG (opcode 2013)
2. Estrae il JWT dal campo `payload` (BSON Binary → JSON → JWT string)
3. Decodifica il segmento claims del JWT (base64url)
4. Estrae e **mette in cache `jti`** nel campo `session_jti` della struct (per tutta la sessione TCP)
5. Invia tutto a OPA per validazione firma + binding certificato

---

## FASE 4 — Esecuzione di una Query MongoDB (mediazione continua)

Per **ogni singolo messaggio** MongoDB sulla connessione già aperta, il Wasm filter esegue un controllo OPA completo. Non basta che la connessione sia stata autenticata.

```mermaid
sequenceDiagram
    participant Client as Client pymongo
    participant Envoy as Envoy Wasm filter
    participant OPA as OPA
    participant PKI as identity-pki
    participant Forwarder as zta-log-forwarder
    participant Mongo as MongoDB

    Client->>Envoy: OP_MSG find clinical_records filter={"patient_id":"P-123"}

    Note over Envoy: Wasm on_downstream_data()
    Envoy->>Envoy: parse_op_msg: cmd=find, coll=clinical_records, query={patient_id:P-123}
    Envoy->>Envoy: Legge TLS props: subject_peer_cert, sha256_digest, source.address
    Envoy->>Envoy: parse_subject_dn: cn=paolo.roselli, mac=AA:BB:CC
    Envoy->>Envoy: Recupera session_jti cached: jti=abc-123-uuid

    Envoy->>OPA: POST /v1/data/envoy/authz/allow {cmd:find, coll:clinical_records, query:{patient_id:P-123}, user:paolo.roselli, jti:abc-123-uuid}
    Note over Client,Envoy: dispatch_http_call Action::Pause. Pacchetto in buffer.

    Note over OPA: main.rego: cert_is_revoked - cache TTL 2s
    OPA->>PKI: GET /api/revocation/paolo.roselli
    PKI->>PKI: os.path.exists revoked/paolo.roselli.rev
    PKI-->>OPA: {revoked: false}

    Note over OPA: main.rego: jwt_is_revoked - cache TTL 2s
    OPA->>PKI: GET /api/jwt/revocation/abc-123-uuid
    PKI->>PKI: lookup in REVOKED_JTIS set - O(1)
    PKI-->>OPA: {revoked: false}

    Note over OPA: criteria.rego: RBAC + L7 WAF
    OPA->>OPA: role=doctor, action=find, coll=clinical_records. Permesso OK
    OPA->>OPA: hard_deny: find non sensibile. OK
    OPA->>OPA: inspection_violation: query contiene patient_id. OK

    Note over OPA: risk.rego: punteggio rischio + anomalia Splunk
    OPA->>Forwarder: POST /api/stats {user, ip, device, resource, command}
    Forwarder-->>OPA: {risk_boost: 0}
    OPA->>OPA: risk_score=0, adaptive_threshold=30. OK

    OPA-->>Envoy: {result: true}

    Note over Envoy: on_http_call_response: decision=ALLOW
    Envoy->>Envoy: log::info! WASM_AUDIT {user:paolo.roselli, cmd:find, coll:clinical_records, decision:ALLOW, jti:abc-123-uuid}
    Envoy->>Envoy: resume_downstream()
    Envoy->>Mongo: OP_MSG forward query originale
    Mongo-->>Client: OP_REPLY documenti
```

---

## FASE 5 — Caso di DENY (cert revocato o JWT nella denylist)

```mermaid
sequenceDiagram
    participant Admin as Admin
    participant PKI as identity-pki
    participant Client as Client
    participant Envoy as Envoy Wasm
    participant OPA as OPA

    Admin->>PKI: POST /api/admin/revoke {user: "paolo.roselli"}
    PKI->>PKI: Crea file revoked/paolo.roselli.rev
    PKI-->>Admin: {status: success}

    Note over Admin,PKI: Oppure revoca singolo JWT
    Admin->>PKI: POST /api/admin/revoke-jwt {jti: "abc-123-uuid"}
    PKI->>PKI: REVOKED_JTIS.add + persist revoked_jtis.json
    PKI-->>Admin: {status: success}

    Note over Client,Envoy: Prossima query (max 2 secondi dopo la revoca)
    Client->>Envoy: OP_MSG find clinical_records
    Envoy->>OPA: {cmd:find, jti:abc-123-uuid, user:paolo.roselli}

    OPA->>PKI: GET /api/revocation/paolo.roselli
    PKI-->>OPA: {revoked: true}

    OPA-->>Envoy: {result: false}

    Envoy->>Envoy: log::warn! Query DENIED closing TCP connection
    Envoy->>Envoy: log::info! WASM_AUDIT {decision:DENY, user:paolo.roselli, cmd:find}
    Envoy->>Client: RST TCP - close_downstream()

    Note over Client: Connessione chiusa. Non solo query negata: sessione TCP terminata.
```

> [!IMPORTANT]
> La **chiusura TCP** (RST) è fondamentale: se il filtro negasse solo la singola query lasciando aperta la connessione, l'attaccante potrebbe continuare a inviare altri comandi nella stessa sessione.

---

## FASE 6 — Pipeline di logging verso Splunk

```mermaid
flowchart TB
    subgraph Envoy_Container["Envoy Container"]
        WF["Wasm Filter\nlog::info! WASM_AUDIT\ndopo ogni OPA decision"]
        AL["Access Log\n/var/log/envoy/access.log\nJSON per connessione"]
        EL["Process Log\n/var/log/envoy/envoy.log\nvia --log-path flag"]
        WF --> EL
    end

    subgraph Volume["Shared Volume: envoy-logs"]
        V1["/var/log/envoy/access.log"]
        V2["/var/log/envoy/envoy.log"]
        AL --> V1
        EL --> V2
    end

    subgraph Forwarder_Container["zta-log-forwarder"]
        T1["tail_envoy_logs\nsourcetype: envoy:access"]
        T2["tail_wasm_audit_logs\nregex WASM_AUDIT\nsourcetype: zta:wasm:query"]
        T3["tail_snort_logs\nsourcetype: snort:alert_json"]
        T4["tail_mongo_audit_logs\nsourcetype: mongodb:audit"]
        T5["API /api/audit Flask\nsourcetype: zta:app:query"]
        V1 --> T1
        V2 --> T2
    end

    subgraph Splunk_HEC["Splunk HEC :8088"]
        HEC["index: zta_envoy\nindex: zta_snort\nindex: zta_mongodb_audit"]
        T1 --> HEC
        T2 --> HEC
        T3 --> HEC
        T4 --> HEC
        T5 --> HEC
    end
```

**Sourcetypes disponibili in Splunk:**

| Sourcetype | Contenuto | Frequenza |
|---|---|---|
| `envoy:access` | Dati connessione TCP: IP, bytes, durata, user, risk_score | Per connessione |
| `zta:wasm:query` | Ogni decisione OPA: cmd, collection, decision, jti, ctx_id | **Per singola query** |
| `zta:app:query` | Query eseguite da Flask /api/query con risultato e count | Per chiamata API |
| `snort:alert_json` | Alert IDS Snort 3 (NoSQLi signature, anomalie rete) | Per evento IDS |
| `mongodb:audit` | Audit nativo MongoDB (authenticate, find, update…) | Per operazione DB |
| `nftables:log` | Drop/accept kernel nftables | Per pacchetto filtrato |

---

## Tabella riepilogativa: chi fa cosa per ogni messaggio MongoDB

| Componente | Ruolo | Trigger |
|---|---|---|
| **TLS Inspector (Envoy)** | Valida certificato X.509, termina mTLS, estrae CN | Ogni nuova connessione TCP |
| **Wasm Filter** | Parsa OP_MSG BSON, estrae cmd/collection/query/JTI, invia a OPA | **Ogni pacchetto downstream** |
| **OPA** | Valuta RBAC + L7 WAF + risk score + revocation check | Ogni chiamata Wasm |
| **identity-pki `/api/revocation`** | Legge `.rev` file — O(1) disk stat | Ogni query OPA (cache 2s) |
| **identity-pki `/api/jwt/revocation`** | Lookup `REVOKED_JTIS` set — O(1) memory | Ogni query OPA (cache 2s) |
| **zta-log-forwarder `/api/stats`** | Query Splunk ultimi 15m per anomaly risk boost | Ogni query OPA (timeout 500ms) |
| **MongoDB** | Esegue la query, applica RLS views, restituisce documenti | Solo se Wasm+OPA → ALLOW |

---

## Latenza stimata per query

```
TCP/mTLS handshake (una-tantum per connessione):   5-10ms
Wasm BSON parse:                                   ~0.1ms
dispatch_http_call → OPA:                          ~2-5ms
  identity eval (firma JWT, CN, IP):               ~0.5ms
  cert_is_revoked (cache OPA 2s):                  ~0ms  (da cache)
  jwt_is_revoked  (cache OPA 2s):                  ~0ms  (da cache)
  risk.anomaly_risk → /api/stats → Splunk:         20-50ms (timeout 500ms)
OPA → Envoy response:                              ~1ms
Envoy → MongoDB → Client:                          variabile

Totale overhead ZTA per query (steady state):      ~25-70ms
```

> [!TIP]
> La cache OPA con `force_cache_duration_seconds: 2` garantisce che i controlli di revocation non aggiungano latenza nelle query rapide. La prima query di ogni "burst" di 2 secondi paga il costo HTTP verso il PKI; le successive usano la cache in-memory di OPA.
