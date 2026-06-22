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

## Schema Validation (JSON Schema / BSON)

Tutte le collection sono create con `validationLevel: strict` e `validationAction: error`:
ogni documento che non rispetta lo schema viene rifiutato in fase di insert/update.
Il flag `additionalProperties: false` impedisce l'inserimento di campi non dichiarati.

### `patients`

| Campo | Tipo BSON | Vincoli |
|-------|-----------|---------|
| `_id` | `string` | UUID v4 — PK, required |
| `full_name` | `string` | minLength: 2, maxLength: 120, required |
| `age` | `int` | minimum: 0, maximum: 130, required |
| `gender` | `string` | enum: `Male`, `Female`, `Other`, required |
| `blood_type` | `string` | enum: `A+`, `A-`, `B+`, `B-`, `AB+`, `AB-`, `O+`, `O-`, required |
| `created_at` | `date` | required |
| `updated_at` | `date` | opzionale |

**Indici:** `full_name ASC`, `age ASC`

### `providers`

| Campo | Tipo BSON | Vincoli |
|-------|-----------|---------|
| `_id` | `string` | PK, required |
| `type` | `string` | enum: `doctor`, `hospital`, required |
| `name` | `string` | minLength: 2, maxLength: 200, required |
| `metadata` | `object` | opzionale |

**Indici:** `(type ASC, name ASC)`

### `admissions`

| Campo | Tipo BSON | Vincoli |
|-------|-----------|---------|
| `_id` | `string` | PK, required |
| `patient_id` | `string` | FK → patients, required |
| `doctor_id` | `string` | FK → providers (type=doctor), required |
| `hospital_id` | `string` | FK → providers (type=hospital), required |
| `admission_type` | `string` | enum: `Elective`, `Emergency`, `Urgent`, required |
| `date_of_admission` | `date` | required |
| `discharge_date` | `date\|null` | opzionale |
| `room_number` | `int` | minimum: 1, required |
| `status` | `string` | enum: `active`, `discharged`, `transferred`, opzionale |
| `created_at` | `date` | required |
| `updated_at` | `date` | opzionale |

**Indici:** `patient_id ASC`, `doctor_id ASC`, `date_of_admission DESC`, `status ASC`

### `clinical_records`

| Campo | Tipo BSON | Vincoli |
|-------|-----------|---------|
| `_id` | `string` | PK, required |
| `patient_id` | `string` | FK → patients, required |
| `admission_id` | `string` | FK → admissions, required |
| `medical_condition` | `string` | enum: `Arthritis`, `Asthma`, `Cancer`, `Diabetes`, `Hypertension`, `Obesity`, required |
| `medication` | `string` | enum: `Aspirin`, `Ibuprofen`, `Lipitor`, `Paracetamol`, `Penicillin`, required |
| `test_results` | `string` | enum: `Normal`, `Abnormal`, `Inconclusive`, required |
| `notes` | `string` | maxLength: 4000, opzionale |
| `recorded_at` | `date` | required |
| `updated_at` | `date` | opzionale |

**Indici:** `patient_id ASC`, `admission_id ASC`, `medical_condition ASC`, `test_results ASC`

### `billing`

| Campo | Tipo BSON | Vincoli |
|-------|-----------|---------|
| `_id` | `string` | PK, required |
| `patient_id` | `string` | FK → patients, required |
| `admission_id` | `string` | FK → admissions, required |
| `insurance_provider` | `string` | enum: `Aetna`, `Blue Cross`, `Cigna`, `Medicare`, `UnitedHealthcare`, required |
| `billing_amount` | `double` | importo fattura, required |
| `payment_status` | `string` | enum: `pending`, `paid`, `disputed`, `written_off`, required |
| `created_at` | `date` | required |
| `updated_at` | `date` | opzionale |

**Indici:** `patient_id ASC`, `admission_id ASC`, `insurance_provider ASC`, `payment_status ASC`

---

## View MongoDB (Field-Level RLS)

Ogni ruolo legge **sempre da una view**, mai dalla collection raw. Le view applicano
un `$project` che filtra i campi in base al minimo privilegio necessario per il ruolo.
Le scritture vanno sempre alla collection raw (la schema validation è comunque attiva).

> Le view sono l'unico punto in cui viene applicato il **field-level hiding** lato database.
> Anche se un ruolo bypassasse OPA, MongoDB restituisce solo i campi esposti dalla view.

### Tabella view per collection e ruolo

| View | Collection sorgente | Ruolo | Campi nascosti rispetto alla raw |
|------|---------------------|-------|----------------------------------|
| `v_patients_doctor` | `patients` | `zta_doctor` | `updated_at` |
| `v_patients_billing` | `patients` | `zta_billing` | `gender`, `blood_type`, `created_at`, `updated_at` |
| `v_patients_reception` | `patients` | `zta_receptionist` | `blood_type`, `updated_at` |
| `v_admissions_doctor` | `admissions` | `zta_doctor` | — (full record) |
| `v_admissions_reception` | `admissions` | `zta_receptionist` | — (full record) |
| `v_admissions_billing` | `admissions` | `zta_billing` | `room_number`, `doctor_id`, `hospital_id`, `updated_at` |
| `v_admissions_auditor` | `admissions` | `zta_auditor` | — (full record + `updated_at`) |
| `v_clinical_doctor` | `clinical_records` | `zta_doctor` | `updated_at` |
| `v_clinical_auditor` | `clinical_records` | `zta_auditor` | `patient_id` → **pseudonimizzato** (vedi sotto) |
| `v_billing_staff` | `billing` | `zta_billing` | — (full record) |
| `v_billing_auditor` | `billing` | `zta_auditor` | `billing_amount`, `insurance_provider` → **mascherati** (vedi sotto) |
| `v_providers_all` | `providers` | tutti i ruoli | `metadata` |

### Matrice view — quale view usa ogni ruolo

| Ruolo | patients | providers | admissions | clinical_records | billing |
|-------|----------|-----------|------------|------------------|---------|
| `zta_admin` | raw | raw | raw | raw | raw |
| `zta_doctor` | `v_patients_doctor` | `v_providers_all` | `v_admissions_doctor` | `v_clinical_doctor` | ✗ |
| `zta_billing` | `v_patients_billing` | `v_providers_all` | `v_admissions_billing` | ✗ | `v_billing_staff` |
| `zta_auditor` | `v_patients_doctor` | `v_providers_all` | `v_admissions_auditor` | `v_clinical_auditor` | `v_billing_auditor` |
| `zta_receptionist` | `v_patients_reception` | `v_providers_all` | `v_admissions_reception` | ✗ | ✗ |

### Pseudonimizzazione in `v_clinical_auditor`

La view esegue un `$lookup` su `patients` e trasforma i dati identificativi prima di proiettarli:

- **Nome paziente** → iniziali tramite `$reduce` + `$split` su spazio  
  (`"Mario Rossi"` → `"M.R."`)
- **Età esatta** → fascia d'età tramite `$switch`  
  (`<30`, `30-50`, `50-70`, `70+`)
- **`patient_id`** non proiettato → nascosto

L'auditor può verificare pattern clinici (condizioni, farmaci, esiti) senza identificare i singoli individui.

### Mascheramento in `v_billing_auditor`

- **`billing_amount`** → arrotondato al migliaio più vicino  
  (`$round($divide(amount, 1000)) × 1000` — es. `18856.28` → `19000`)
- **`insurance_provider`** → primi 3 caratteri + `***`  
  (`"Blue Cross"` → `"Blu***"`)
- I campi originali `billing_amount` e `insurance_provider` **non sono proiettati**

---

## Ruoli MongoDB (L2 RBAC)

I ruoli vengono creati nel database `zta_db` con privilegi espliciti su singole collection/view.
Sono **idempotenti**: lo script fa prima `dropRole` (ignorando eventuali errori) e poi `createRole`.

### `zta_admin`

Accesso completo a **tutte le collection e view** del database `zta_db` tramite wildcard `collection: ""`.

| Azioni | Scope |
|--------|-------|
| `find`, `insert`, `update`, `remove` | tutte le collection |
| `createCollection`, `dropCollection`, `createIndex`, `listCollections` | tutte le collection |

### `zta_doctor`

| Risorsa | Azioni |
|---------|--------|
| `v_patients_doctor` | `find` |
| `v_providers_all` | `find` |
| `v_admissions_doctor` | `find` |
| `v_clinical_doctor` | `find` |
| `admissions` (raw) | `insert`, `update` |
| `clinical_records` (raw) | `insert`, `update` |

Nessun accesso a `billing` o alle sue view.

### `zta_billing`

| Risorsa | Azioni |
|---------|--------|
| `v_patients_billing` | `find` |
| `v_admissions_billing` | `find` |
| `v_providers_all` | `find` |
| `v_billing_staff` | `find` |
| `billing` (raw) | `insert`, `update` |

Nessun accesso a `clinical_records` o alle sue view.

### `zta_auditor`

| Risorsa | Azioni |
|---------|--------|
| `v_patients_doctor` | `find` |
| `v_providers_all` | `find` |
| `v_admissions_auditor` | `find` |
| `v_clinical_auditor` | `find` |
| `v_billing_auditor` | `find` |

Solo lettura — nessuna write su alcuna collection.

### `zta_receptionist`

| Risorsa | Azioni |
|---------|--------|
| `v_patients_reception` | `find` |
| `v_providers_all` | `find` |
| `v_admissions_reception` | `find` |
| `patients` (raw) | `insert`, `update` |
| `admissions` (raw) | `insert`, `update` |

Nessun accesso a `clinical_records` o `billing`.

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

| CN certificato (user\_identity) | Ruolo OPA | Ruolo MongoDB | Password |
|----------------------------------|-----------|---------------|----------|
| `mario.rossi` | `doctor` | `zta_doctor` | `MarioRossi2024!` |
| `anna.verdi` | `billing_staff` | `zta_billing` | `AnnaVerdi2024!` |
| `giulia.bianchi` | `auditor` | `zta_auditor` | `GiuliaBianchi2024!` |
| `luca.ferrari` | `receptionist` | `zta_receptionist` | `LucaFerrari2024!` |
| `admin` | `admin` | `zta_admin` | (da `.env` / URI) |

### Utente Envoy Proxy (X.509 — `$external`)

Lo script crea un utente speciale nel database `$external` (autenticazione X.509):

```
CN=envoy,O=AdvancedCybersecurity-Clients,C=IT
```

- Riceve tutti i ruoli MongoDB applicabili (`zta_doctor`, `zta_billing`, `zta_auditor`, `zta_receptionist`, ecc.) letti da `shared/zta_roles.py`.
- Riceve il ruolo `impersonatorRole` (creato nel database `admin`) con privilegio `impersonate` su `{db: "", collection: ""}` (scope globale).
- Questo permette al proxy Envoy di autenticarsi con il proprio certificato TLS e poi agire per conto dell'utente reale (il CN viene ricavato dal certificato client presentato nella connessione ZTA).

```python
# Creazione impersonatorRole in admin
db_admin.command("createRole", "impersonatorRole",
    privileges=[{"resource": {"db": "", "collection": ""}, "actions": ["impersonate"]}],
    roles=[]
)

# Creazione utente X.509 in $external
db_external.command("createUser", "CN=envoy,O=AdvancedCybersecurity-Clients,C=IT",
    roles=envoy_roles   # tutti i zta_* roles + impersonatorRole
)
```

---

## Connessione TLS

Lo script si connette a MongoDB con TLS mutuo obbligatorio:

```python
client = MongoClient(
    uri,
    tls=True,
    tlsCertificateKeyFile="volumes/certs/server/mongo.pem",
    tlsCAFile="volumes/certs/ca/ca.crt",
    tlsAllowInvalidCertificates=True   # solo sviluppo — rimuovere in produzione
)
db = client["zta_db"]
```

> **Attenzione:** `tlsAllowInvalidCertificates=True` disabilita la verifica del hostname. Deve essere rimosso in produzione.

---

## Installazione

### 1. Init schema e ruoli

```bash
# Dipendenze richieste: pip install pymongo python-dotenv
python3 mongo/init-healthcare.py \
  --uri "mongodb://admin:secret@localhost:27017"
```

Lo script è **idempotente**: drop e ricreazione di collection, view, ruoli e utenti a ogni esecuzione.

**Ordine delle operazioni:**
1. Drop collection esistenti (`patients`, `admissions`, `clinical_records`, `billing`, `providers`)
2. Creazione collection con schema validation (`strict` / `error`) + indici
3. Drop view esistenti (12 view)
4. Creazione view per field-level RLS (con pseudonimizzazione e mascheramento)
5. Drop e ricreazione ruoli MongoDB (`zta_admin`, `zta_doctor`, `zta_billing`, `zta_auditor`, `zta_receptionist`)
6. Drop e ricreazione utenti MongoDB applicativi
7. Creazione `impersonatorRole` nel database `admin` (skip se esiste già)
8. Creazione utente X.509 Envoy nel database `$external`

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
accesso billing come medico (deve essere DENY)
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

