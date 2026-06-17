# Documentazione: Interfaccia CLI MongoDB Proxy con integrazione TPM/Secure Enclave (ZTA)

Questa documentazione descrive l'implementazione dell'interfaccia CLI per interagire in modo sicuro con MongoDB attraverso il gateway mTLS di Envoy, sfruttando i certificati memorizzati nel TPM o Secure Enclave.

---

## 1. Architettura della Soluzione

L'interfaccia CLI fa da ponte tra l'operatore/client e le risorse protette da Zero Trust (ZTA), seguendo questo flusso:

```
[ CLI: mongo_proxy_cli.py ]
        │
        ├─▶ [ ZTA Agent: LocalAPIServer (Port 9090) ]  ──▶ Recupera Cert PEM dal Keychain/Secure Enclave
        │
        └─▶ [ Envoy Gateway (Port 10000) ]  ── mTLS Handshake ──▶ [ OPA: authz.rego ] (Policy Check)
                                                                            │
                                                                            ▼
                                                                  [ MongoDB Database ]
                                                         (Autenticazione con utente specifico)
```

### Componenti Principali:
1. **ZTA Agent (Swift, macOS)**: Espone un'API locale sulla porta `9090`. Gestisce le chiavi crittografiche nel Secure Enclave (SEP). La chiave privata non viene mai esposta.
2. **Envoy Gateway**: Gestisce la terminazione mTLS. Richiede il certificato client per verificare l'identità del richiedente e inoltra la connessione a MongoDB solo se la policy OPA dà esito positivo.
3. **MongoDB RBAC**: Gli utenti MongoDB sono associati ai rispettivi ruoli aziendali con permessi granulari (Row-Level Security / Collection-Level Security).

---

## 2. Dettagli di Implementazione

### 2.1 Estensione del ZTA Agent (`LocalAPIServer.swift`)
È stato introdotto l'endpoint `POST /cert` che consente alla CLI di estrarre il certificato pubblico in formato PEM dal Keychain di sistema dato il Common Name (`cn`), mantenendo la chiave privata al sicuro all'interno del Secure Enclave:

- **Endpoint**: `http://localhost:9090/cert`
- **Payload**: `{"common_name": "mario.rossi"}`
- **Risposta**: `{"cert_pem": "-----BEGIN CERTIFICATE...", "key_available": false, ...}`

### 2.2 Client CLI MongoDB Proxy (`scripts/mongo_proxy_cli.py`)
Lo script CLI Python gestisce in maniera trasparente la cifratura TLS e l'autenticazione a MongoDB.

#### Caratteristiche principali:
- **Dual-Path Certificate Loading**: Tenta automaticamente di recuperare il certificato tramite il ZTA Agent (Secure Enclave). Se non è disponibile (ad esempio su OS diversi da macOS o se l'agent è spento), effettua il fallback sui certificati fisici in `certs/client/`.
- **Identity & Credentials Mapping**: Associa il CN del certificato alle credenziali MongoDB create in fase di inizializzazione:
  - `mario.rossi` (doctor) ──▶ `zta_doctor`
  - `anna.verdi` (billing_staff) ──▶ `zta_billing`
  - `giulia.bianchi` (auditor) ──▶ `zta_auditor`
  - `luca.ferrari` (receptionist) ──▶ `zta_receptionist`
  - `admin` (admin) ──▶ `admin`

---

## 3. Guida all'uso della CLI

La CLI supporta diverse modalità di esecuzione.

### 3.1 Identità e Permessi (`whoami`)
Visualizza le informazioni sull'utente specificato e i relativi permessi teorici sulle collezioni MongoDB:
```bash
python3 scripts/mongo_proxy_cli.py --cn mario.rossi whoami
```

### 3.2 Verifica Connessione mTLS (`status`)
Verifica che Envoy sia raggiungibile ed esegua correttamente l'handshake mTLS:
```bash
python3 scripts/mongo_proxy_cli.py --cn mario.rossi status
```
*Nota: In ambiente di test locale, è possibile forzare l'uso dei certificati da file con `--file --insecure`.*

### 3.3 Esecuzione Query (`query`)
Esegue una `find` sulla collezione selezionata filtrando i risultati. I campi sensibili (es. dati clinici o importi di fatturazione) vengono evidenziati graficamente:
```bash
python3 scripts/mongo_proxy_cli.py --cn mario.rossi query --collection clinical_records --limit 5
```

Con filtro JSON:
```bash
python3 scripts/mongo_proxy_cli.py --cn mario.rossi query --collection patients --filter '{"age": {"$gt": 60}}'
```

### 3.4 Inserimento Documenti (`insert`)
Inserisce un nuovo record nel database (soggetto a policy OPA e permessi MongoDB):
```bash
python3 scripts/mongo_proxy_cli.py --cn admin insert --collection providers --doc '{"name": "Dr. Gianni", "type": "doctor"}'
```

### 3.5 Aggregazione Dati (`aggregate`)
Esegue pipeline di aggregazione complesse:
```bash
python3 scripts/mongo_proxy_cli.py --cn anna.verdi aggregate --collection billing --pipeline '[{"$group": {"_id": "$insurance_provider", "total": {"$sum": "$billing_amount"}}}]'
```

### 3.6 REPL Interattivo (`repl`)
Avvia una shell interattiva all'interno del contesto di sicurezza dell'utente:
```bash
python3 scripts/mongo_proxy_cli.py --cn mario.rossi repl
```
Comandi REPL disponibili: `find <collection> [filter]`, `count <collection>`, `collections`, `whoami`, `exit`.
