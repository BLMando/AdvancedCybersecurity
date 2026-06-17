# Healthcare Database — Design & RLS Reference

## Panoramica

Il dataset CSV (`healthcare_dataset.csv`, 55.500 righe) è stato normalizzato
in **5 collection MongoDB** con schema validation, indici e Row-Level Security
applicata su due livelli distinti:

| Livello | Dove | Cosa fa |
|---------|------|---------|
| **L1 — OPA (PDP)** | `opa/policies/authz.rego` | Policy unificata: risk score + role × collection × command matrix |
| **L2 — MongoDB RBAC** | Ruoli creati da `init-healthcare.py` | Secondo strato: anche se OPA fallisce, il DB rifiuta operazioni non autorizzate |

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
# Dipendenze richieste: pip install pymongo
python3 mongo/init-healthcare.py \
  --uri "mongodb://admin:secret@localhost:27017"
```

### 2. Seeding del dataset

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

### 3. Test RLS

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

