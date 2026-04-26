# Healthcare Database — Design & RLS Reference

## Panoramica

Il dataset CSV (`healthcare_dataset.csv`, 55.500 righe) è stato normalizzato
in **5 collection MongoDB** con schema validation, indici e Row-Level Security
applicata su due livelli distinti:

| Livello | Dove | Cosa fa |
|---------|------|---------|
| **L1 — OPA (PDP)** | `opa/policies/authz.rego` | Policy unificata: risk score + role × collection × command matrix |
| **L2 — MongoDB RBAC** | Ruoli creati da `init-healthcare.js` | Secondo strato: anche se OPA fallisce, il DB rifiuta operazioni non autorizzate |

---

## Schema delle Collection

### Dataset originale → Collection

```
CSV (flat, 15 colonne, 55.500 righe)
│
├─ Name, Age, Gender, Blood Type          ──▶  patients
├─ Doctor, Hospital                        ──▶  providers
├─ Date of Admission, Discharge Date,
│  Admission Type, Room Number             ──▶  admissions          (FK → patients, providers)
├─ Medical Condition, Medication,
│  Test Results                            ──▶  clinical_records    (FK → patients, admissions)
└─ Insurance Provider, Billing Amount      ──▶  billing             (FK → patients, admissions)
```

### Diagramma ER

```
┌─────────────────────────────────────────────────────────────────┐
│  patients                                                       │
│  _id (UUID) | full_name | age | gender | blood_type            │
│  ● Schema: additionalProperties: false                         │
│  ● Sensitività: ALTA (PII)                                     │
└──────┬──────────────────────────────────────────────────────────┘
       │ patient_id (FK)
       ├──────────────────────────────────────────────────────────┐
       │                                                          │
       ▼                                                          ▼
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  admissions                 │        │  clinical_records            │
│  _id | patient_id           │        │  _id | patient_id            │
│  doctor_id | hospital_id    │        │  admission_id                │
│  admission_type             │        │  medical_condition           │
│  date_of_admission          │        │  medication | test_results   │
│  discharge_date | room      │◀───────│  recorded_at                 │
│  status                     │        │  ● Sensitività: MASSIMA      │
│  ● Sensitività: ALTA        │        └──────────────────────────────┘
└──────┬──────────────────────┘
       │ admission_id (FK)
       ▼
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  billing                    │        │  providers                   │
│  _id | patient_id           │        │  _id | type (doctor/hospital)│
│  admission_id               │        │  name                        │
│  insurance_provider         │        │  ● Sensitività: BASSA        │
│  billing_amount             │        └──────────────────────────────┘
│  payment_status             │
│  ● Sensitività: ALTA        │
└─────────────────────────────┘
```

---

## Matrice RLS — Role × Collection × Command

`CRUD` = find + insert + update + delete  
`R` = find only  
`—` = accesso NEGATO (hard deny in OPA)

| Collection         | admin | doctor | billing\_staff | auditor | receptionist | unknown |
|--------------------|:-----:|:------:|:--------------:|:-------:|:------------:|:-------:|
| **patients**       | CRUD  | R      | R              | R       | R + insert + update | — |
| **providers**      | CRUD  | R      | R              | R       | R           | — |
| **admissions**     | CRUD  | CRUD   | R              | R       | CRUD        | — |
| **clinical\_records** | CRUD | CRUD  | **—**         | R       | **—**       | — |
| **billing**        | CRUD  | **—**  | CRUD           | R       | **—**       | — |

---

## Risk Score Boost per Collection Sensibile

Il file `authz.rego` (policy unificata) aggiunge **+15 punti** al risk score effettivo
per le collection `clinical_records` e `billing`:

```
effective_risk_score = risk_score + collection_risk_boost

clinical_records, billing → boost = 15
Tutti gli altri → boost = 0
```

Questo significa che un medico che accede a `clinical_records` da rete esterna
(network_risk = 15) supera già la soglia di `find` (60) anche essendo un utente
noto con device noto:

```
user_risk   =  0  (noto)
device_risk =  0  (TPM)
network_risk = 15  (esterno)
collection_boost = 15
─────────────────────
effective   = 30 < 60  → ALLOW

# Ma se aggiunge no-tpm:
device_risk = 20
effective   = 50 < 60  → ALLOW ancora

# Da rete esterna + no-tpm + clinical_records:
network_risk = 15
device_risk  = 20
collection_boost = 15
effective    = 50 < 60 → ALLOW (ma vicino al limite)

# Utente sconosciuto + clinical_records:
user_risk    = 30
device_risk  = 20
network_risk = 15
boost        = 15
effective    = 80 > 60 → DENY ✓
```

---

## Utenti e Ruoli

| CN certificato (user\_identity) | Ruolo OPA | Ruolo MongoDB |
|----------------------------------|-----------|---------------|
| `mario.rossi` | `doctor` | `zta_doctor` |
| `anna.verdi` | `billing_staff` | `zta_billing` |
| `giulia.bianchi` | `auditor` | `zta_auditor` |
| `luca.ferrari` | `receptionist` | `zta_receptionist` |
| `admin` | `admin` | `zta_admin` |

---

## Installazione

### 1. Init schema e ruoli

```bash
docker exec mongo mongosh \
  -u admin -p "$MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  /docker-entrypoint-initdb.d/init-healthcare.js
```

### 2. Caricamento policy OPA unificata

La policy `authz.rego` include già tutto: risk scoring + role matrix + hard-deny.
OPA rileva automaticamente le modifiche ai file in `opa/policies/`.

```bash
# Riavvia OPA per caricare la nuova policy
docker restart opa
```

### 3. Seeding del dataset

```bash
# Via Envoy (flusso ZTA completo, usa il certificato di admin)
python3 mongo/seed-db.py \
  --uri "mongodb://admin:secret@localhost:10000/zta_db?authSource=admin" \
  --csv mongo/dataset/healthcare_dataset.csv

# Oppure diretto (solo per primo setup, bypassa OPA)
python3 mongo/seed-db.py \
  --uri "mongodb://admin:secret@localhost:27017/zta_db?authSource=admin" \
  --csv mongo/dataset/healthcare_dataset.csv
```

### 4. Test RLS

```bash
# Test OPA policy RLS
opa test opa/policies/ -v

# Test accesso clinico come medico (dovrebbe passare)
curl -s -X POST http://localhost:8181/v1/data/envoy/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": { "parsed_body": {
      "user": "mario.rossi",
      "device": "device-laptop-001",
      "network_ip": "172.20.0.5",
      "command": "find",
      "collection": "clinical_records"
    }}
  }' | jq .result.allow

# Test accesso billing come medico (deve essere DENY)
curl -s -X POST http://localhost:8181/v1/data/envoy/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": { "parsed_body": {
      "user": "mario.rossi",
      "device": "device-laptop-001",
      "network_ip": "172.20.0.5",
      "command": "find",
      "collection": "billing"
    }}
  }' | jq .result.allow
```

---

## Struttura file

```
mongo/
  init-healthcare.js            ← Schema validation + ruoli MongoDB + utenti
  Dockerfile                    ← Build context per MongoDB
  seed-db.py                     ← Popolamento DB dal CSV
  dataset/
    healthcare_dataset.csv     ← Dataset normalizzato (55.500 righe)
  HEALTHCARE_DB.md              ← Questo documento

opa/policies/
  authz.rego                    ← Policy unificata: risk score + role × collection × command matrix

scripts/                       ← Script di utilità (globali)
  generate-certs.sh            ← Generazione certificati mTLS
  demo.sh                      ← Demo script
```

---

## Policy Unificata OPA

Dalla versione attuale, le due policy precedenti (`authz.rego` + `healthcare_rls.rego`)
sono state **unificate in un singolo file** `opa/policies/authz.rego`.

### Vantaggi della merge:
- **Singola authority decisionale**: un solo `allow` rule determina l'accesso
- **Nessun OR accidentale**: evitato il rischio di regole `allow` multiple con semantica OR
- **Manutenzione semplificata**: un solo file da versionare e deployare

### Struttura della policy unificata:

```rego
# 1. Risk scoring (user + device + network + collection boost)
risk_score := user_risk + device_risk + network_risk + collection_risk_boost

# 2. Role mapping
current_role := user_role_map[user_identity]

# 3. Permission matrix
permissions := {
    "doctor": {"clinical_records": {"find", "insert", "update"}, ...}
    "billing_staff": {"billing": {"find", "insert", "update"}, ...}
    ...
}

# 4. Hard-deny rules (sempre applicati)
hard_deny if { current_role == "unknown" }
hard_deny if { current_role == "doctor" collection_name == "billing" }
...

# 5. Final allow (tutte le condizioni richieste)
allow if {
    valid_action
    risk_score <= threshold
    action_allowed
    role_action_allowed
    not hard_deny
}
```

### Test della policy unificata:

```bash
# Doctor → clinical_records (deve essere ALLOW)
curl -s -X POST http://localhost:8181/v1/data/envoy/authz \
  -H "Content-Type: application/json" \
  -d '{"input": {"parsed_body": {"user": "mario.rossi", "device": "device-laptop-001", "network_ip": "172.20.0.5", "command": "find", "collection": "clinical_records"}}}' \
  | jq .result.allow
# → true

# Doctor → billing (deve essere DENY)
curl -s -X POST http://localhost:8181/v1/data/envoy/authz \
  -H "Content-Type: application/json" \
  -d '{"input": {"parsed_body": {"user": "mario.rossi", "device": "device-laptop-001", "network_ip": "172.20.0.5", "command": "find", "collection": "billing"}}}' \
  | jq .result.allow
# → false
```

---

## Limitazioni note

- **Proiezione campi**: OPA non può filtrare i *campi* di un documento
  (es. nascondere `blood_type` ai `billing_staff`). La redazione va implementata
  a livello applicativo o con MongoDB Field-Level Encryption (FLE).
- **Aggregation pipeline**: il filtro `mongo_proxy` di Envoy non decodifica
  sempre i comandi `aggregate`. Se necessario, aggiungere validazione a livello
  applicativo.
- **Billing Amount negativi**: il dataset contiene valori negativi (rimborsi?).
  Lo schema attuale li accetta. Aggiungere `minimum: 0` se non si vuole
  permettere importi negativi.