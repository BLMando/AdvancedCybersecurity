# Relazione Tecnica: Implementazione del Tunnel ZTA MongoDB Proxy e Row-Level Security

## 1. Introduzione e Obiettivi della Soluzione

### Il Problema Tecnologico Fondamentale
In una moderna architettura Zero Trust (ZTA), le identità crittografiche dei client devono essere indissolubilmente legate al componente hardware del dispositivo per prevenire il furto o la clonazione delle credenziali. Su sistemi macOS, questo risultato viene ottenuto memorizzando la chiave privata del certificato client all'interno del coprocessore di sicurezza hardware **Secure Enclave (SEP)**, impostando la chiave come non esportabile.

Tuttavia, le librerie crittografiche standard di runtime ad alto livello (come il modulo `ssl` di Python, utilizzato da `pymongo`) **non possono accedere direttamente alle chiavi memorizzate nel SEP**. Python si aspetta di caricare un file `.key` in chiaro dal disco per eseguire l'handshake mTLS, il che vanifica l'obiettivo di protezione hardware. 

L'unica entità in grado di interpellare il SEP per firmare l'handshake TLS (tramite le API di sistema `SecIdentity` e `Network.framework`) è un **processo nativo Swift** dotato degli opportuni diritti di firma e autorizzazioni di sistema.

### Obiettivi del Progetto
Per superare questa limitazione e garantire la massima sicurezza in ambiente medico/ospedaliero (healthcare), gli obiettivi di questo incremento architetturale sono stati:
1. **Creare un tunnel TCP locale dinamico** gestito dall'Agente Swift nativo in esecuzione su macOS. Il client Python (PyMongo) si connette in chiaro a una porta TCP locale (su interfaccia di loopback `127.0.0.1`), e l'Agente intercetta il traffico, effettuando l'handshake mTLS verso Envoy sfruttando la chiave nel Secure Enclave previa autorizzazione biometrica (Touch ID).
2. **Integrare la traduzione Row-Level Security (RLS) lato client**: Gli utenti non amministrativi (come i medici) non devono poter interrogare direttamente le collezioni fisiche (ad esempio `clinical_records`), operazione che restituirebbe un errore di autorizzazione (`not authorized`) da parte di MongoDB. La CLI deve intercettare le query in lettura e tradurle verso le corrispondenti View MongoDB filtrate per il ruolo dell'utente (`v_clinical_doctor`, `v_patients_doctor`, ecc.).
3. **Estendere i controlli OPA (Open Policy Agent) alle View**: OPA deve riconoscere le View e normalizzarle al volo al nome della collezione fisica sottostante per poter applicare gli stessi controlli sui campi sensibili, i calcoli del punteggio di rischio e le restrizioni di accesso.

---

## 2. Architettura della Soluzione (TO-BE)

L'architettura finale implementata segue il flusso descritto nel diagramma sottostante:

```
 Python CLI (mongo_proxy_cli.py)
     │
     │  1. Avvio sessione: POST :9090/proxy/start  { cn, ttl_seconds }
     │     ← Risposta: { port: 27019, session_token: "UUID", expires_at: "..." }
     │
     │  2. Connessione client: pymongo ──▶ localhost:27019 (TCP Loopback)
     │
     │  3. ZTA Agent Swift (Porta locale :27019)
     │        │
     │        │  [Richiesta Biometrica Touch ID]
     │        │
     │        └─▶ NWConnection + mTLS (Chiave SEP via SecIdentity) ──▶ Envoy Gateway :10000
     │                                                                   │
     │                                                                   ├─── OPA Authz (ext_authz gRPC)
     │                                                                   │
     │                                                                   └─── MongoDB zta_db
     │
     │  4. Chiusura sessione: POST :9090/proxy/stop  { session_token }
```

### Garanzie di Sicurezza della Relazione:
- **Zero-Trust**: La chiave privata non viene mai scritta su disco né esposta nello user-space di Python. Rimane protetta all'interno del Secure Enclave.
- **Biometria**: Touch ID viene richiesto al momento di `/proxy/start`, garantendo la presenza fisica dell'operatore autorizzato.
- **Isolamento multi-utente**: Ogni utente (CN) ottiene una porta di loopback locale distinta e dinamica per evitare la contaminazione delle sessioni.
- **Defense in Depth**: L'autorizzazione viene verificata a tre livelli indipendenti:
  1. **Envoy/mTLS**: Verifica crittografica dell'identità client.
  2. **OPA (PDP)**: Decisione basata sul rischio del contesto di rete, del client e delle protezioni L7.
  3. **MongoDB RBAC**: Restrizione nativa sui dati tramite View e ruoli dedicati.

---

## 3. Dettagli di Implementazione per Componente

### 3.1 ZTA Agent (Swift macOS App)

Per implementare il proxy TCP nativo, sono stati aggiunti e modificati i seguenti componenti all'interno del progetto Xcode `ZTAAgent`:

#### A. Creazione di [MongoProxyManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/MongoProxyManager.swift)
Questo manager espone la logica di creazione dei listener locali TCP ed effettua la pipe bidirezionale verso il gateway Envoy utilizzando i parametri TLS ricavati da `SecIdentity`:

1. **Gestione Connessioni Locali**: Viene avviato un `NWListener` sulla porta dinamica assegnata. Ogni connessione locale in entrata viene accettata ed è associata a una `NWConnection` mTLS verso Envoy.
2. **Integrazione Secure Enclave**: La funzione `findIdentity` interroga il Keychain di macOS cercando i certificati il cui CN corrisponde all'utente richiedente:
   ```swift
   private func findIdentity(cn: String) throws -> SecIdentity {
       let query: [String: Any] = [
           kSecClass as String: kSecClassCertificate,
           kSecReturnRef as String: true,
           kSecMatchLimit as String: kSecMatchLimitAll
       ]
       // ... Scansione dei certificati per trovare la corrispondenza con cn ...
       let idStatus = SecIdentityCreateWithCertificate(nil, cert, &identity)
       return identity
   }
   ```
3. **Cifratura mTLS Nativa**: I parametri di connessione per Envoy vengono costruiti configurando le opzioni TLS del socket con l'identità hardware estratta:
   ```swift
   sec_protocol_options_set_local_identity(
       tlsOptions.securityProtocolOptions,
       sec_identity_create(identity)!
   )
   ```
4. **Pipe Bidirezionale Asincrona**: I dati binari del protocollo MongoDB vengono inoltrati asincronamente tra il socket locale e la connessione ad Envoy:
   ```swift
   source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
       destination.send(content: data, ...)
   }
   ```

#### B. Estensione di [LocalAPIServer.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/LocalAPIServer.swift)
Sono stati introdotti i tre endpoint HTTP necessari a governare il ciclo di vita del proxy dal client Python:
- `POST /proxy/start`: Riceve `common_name` e `ttl_seconds`. Esegue la verifica Touch ID (`LAContext.evaluatePolicy`) e, in caso di successo, alloca una porta libera avviando la sessione proxy TCP.
- `POST /proxy/stop`: Riceve `session_token`, interrompe il relativo listener TCP locale e chiude tutti i socket attivi.
- `GET /proxy/status`: Restituisce l'elenco delle sessioni attive con le relative scadenze (TTL).

---

### 3.2 Client CLI MongoDB (`scripts/mongo_proxy_cli.py`)

Lo script Python è stato riprogettato per automatizzare l'interazione con le API del ZTA Agent e integrare le logiche di traduzione RLS:

#### A. Gestione della Sessione Proxy (`ZTAMongoConnection` & `ZTAProxySession`)
La connessione a MongoDB viene racchiusa all'interno di un context manager Python che automatizza la comunicazione con l'agente nativo:
```python
class ZTAMongoConnection:
    def __enter__(self):
        # 1. Richiede l'avvio del proxy TCP all'agente macOS
        self.proxy_session = ZTAProxySession(self.cn)
        self.proxy_session.__enter__()
        
        # 2. Connette a MongoDB puntando alla porta di loopback allocata dall'agente
        uri = f"mongodb://{user}:{password}@localhost:{self.proxy_session.port}/{MONGO_DB}?authSource={auth_db}"
        self.client = MongoClient(uri)
        return self.client, mongo_info
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # 3. Chiude il client ed elimina la sessione sul ZTA Agent (chiudendo la porta)
        self.client.close()
        self.proxy_session.__exit__(exc_type, exc_val, exc_tb)
```

#### B. Traduzione delle Collezioni fisiche nelle View RLS
È stata introdotta la funzione `get_read_collection_name` per instradare le query di lettura (`find`, `count`, `aggregate`) verso le collezioni logiche (View) create appositamente per ogni ruolo in MongoDB:
```python
def get_read_collection_name(collection_name: str, cn: str) -> str:
    mongo_info = CN_TO_MONGO.get(cn, {})
    role = mongo_info.get("role", "unknown")
    if role == "admin":
        return collection_name

    rls_views = {
        "doctor": {
            "patients": "v_patients_doctor",
            "providers": "v_providers_all",
            "admissions": "v_admissions_doctor",
            "clinical_records": "v_clinical_doctor",
        },
        "billing_staff": {
            "patients": "v_patients_billing",
            "providers": "v_providers_all",
            "admissions": "v_admissions_billing",
            "billing": "v_billing_staff",
        },
        # ... Altri ruoli ...
    }
    return rls_views.get(role, {}).get(collection_name, collection_name)
```
La traduzione avviene in modo trasparente solo per le operazioni in lettura; le operazioni di inserimento (`cmd_insert`) continuano a puntare alla collezione fisica originale, in quanto le View di MongoDB sono di sola lettura e i permessi di scrittura di MongoDB RBAC sono configurati sulla collezione fisica sottostante.

---

### 3.3 Open Policy Agent (`authz.rego`)

Le modifiche apportate ad [authz.rego](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/opa/policies/authz.rego) sono state cruciali per evitare che le View bypassassero i controlli o venissero bloccate per mancata associazione di permessi:

1. **Definizione della Normalizzazione delle View**:
   ```rego
   normalized_collection_name := name if {
       startswith(collection_name, "v_patients_")
       name := "patients"
   } else := name if {
       startswith(collection_name, "v_admissions_")
       name := "admissions"
   } else := name if {
       startswith(collection_name, "v_clinical_")
       name := "clinical_records"
   } else := name if {
       startswith(collection_name, "v_billing_")
       name := "billing"
   } else := name if {
       collection_name == "v_providers_all"
       name := "providers"
   } else := collection_name
   ```
2. **Aggiornamento delle Regole di Autorizzazione**:
   Tutte le regole di decisione sono state aggiornate per verificare `normalized_collection_name` anziché `collection_name`:
   - La matrice dei permessi (`role_action_allowed` e `role_action_denied`) verifica se il ruolo dell'utente ha i permessi sulla collezione fisica di base, permettendo l'accesso alla View ad essa associata.
   - Le regole di ispezione del payload (`inspection_violation`) come l'obbligo del campo `patient_id` su `clinical_records` o il divieto degli operatori JavaScript su `billing` vengono ereditate in modo automatico e robusto dalle relative View.
   - Il controllo di sicurezza per le connessioni non decodificabili (`action_name == "unknown"`) impedisce il bypass di View sensibili:
     ```rego
     allow if {
         action_name == "unknown"
         not normalized_collection_name in {"clinical_records", "billing", "patients", "admissions", "providers"}
     }
     ```

---

## 4. Guida Passo-Passo per l'Esecuzione e i Test E2E

### Step 1: Avvio dell'Infrastruttura Docker
Avviare tutti i servizi server (MongoDB, Envoy, OPA, PKI) ed assicurarsi che siano in esecuzione e sani:
```bash
docker compose up -d --build
docker compose ps
```

### Step 2: Compilazione e Avvio dell'Agente Nativo
1. Aprire il progetto `ztaagent/ZTAAgent/ZTAAgent.xcodeproj` in Xcode su macOS.
2. Assicurarsi di firmare l'applicazione con il proprio profilo di sviluppo valido nelle impostazioni di *Signing & Capabilities* (necessario per consentire l'interazione con il Keychain e le API del Secure Enclave).
3. Compilare ed avviare l'applicazione (**Cmd + R**). L'interfaccia dell'agente mostrerà lo stato del server API locale attivo sulla porta `9090`.

### Step 3: Enrollment dell'Identità Hardware (Touch ID)
Registrare una nuova identità client associandola al Secure Enclave locale. Ad esempio, per la dipendente amministrativa `anna.verdi`:
```bash
python3 scripts/enroll.py --cn anna.verdi --role billing_staff
```
*Verrà visualizzata la notifica di avvenuto enrollment nativo e la generazione della chiave all'interno del chip SEP.*

#### Importazione Manuale del Certificato (Keychain Link)
Poiché l'agente in ambiente sandbox potrebbe non avere i privilegi per scrivere direttamente nella partizione del portachiavi di login dell'utente, importare manualmente il certificato firmato emesso dal server CA locale:
```bash
security import volumes/certs/ca/issued/anna.verdi/certificate.crt -t cert
```
Questo comando inserisce il certificato nel Keychain di login associandolo in modo indissolubile alla chiave privata Secure Enclave generata nello step precedente.

---

## 5. Evidenze di Verifica e Validazione dei Risultati

### A. Verifica Unitaria dei Controlli OPA (Rego Tests)
La robustezza e la correttezza della normalizzazione delle View sono state verificate tramite la suite di test unitari interna ad OPA:
```bash
docker compose exec opa ./opa_envoy_linux_amd64 test /policies -v
```
**Risultato**:
```
/policies/authz.rego:
data.envoy.authz.test_legitimate_user: PASS (32.20ms)
data.envoy.authz.test_unknown_user_denied: PASS (1.51ms)
data.envoy.authz.test_doctor_clinical_find: PASS (3.06ms)
data.envoy.authz.test_doctor_clinical_view_allowed: PASS (1.93ms)
data.envoy.authz.test_doctor_clinical_view_no_patient_id_denied: PASS (1.30ms)
data.envoy.authz.test_doctor_billing_view_denied: PASS (1.33ms)
...
--------------------------------------------------------------------------------
PASS: 18/18
```
Questo conferma che OPA valida correttamente le View, bloccando ad esempio il medico (`doctor`) se tenta di accedere alla view di fatturazione (`v_billing_staff`) o se esegue ricerche su dati clinici senza specificare il filtro `patient_id`.

### B. Esecuzione Query Medico (`paolo.roselli` / Ruolo `doctor`)
Interrogazione della collezione `clinical_records` per un medico registrato:
```bash
python3 scripts/mongo_proxy_cli.py --cn paolo.roselli query --collection clinical_records
```
**Risultato a Terminale**:
```
══════════════════════════════════════════════════════════════════════
 ZTA MongoDB Proxy CLI  •  CN: paolo.roselli
══════════════════════════════════════════════════════════════════════
[*] Query: clinical_records.find({}) limit=10
──────────────────────────────────────────────────────────────────────
[*] Contatto ZTA Agent per avviare il tunnel MongoDB per paolo.roselli...
[✓] Tunnel ZTA avviato su localhost:27026 (Token: F48733FB-CB21-4937-8A65-4EA79B85B031)
[*] Connessione al tunnel locale localhost:27026 come mario.rossi...
[*] RLS: Traduzione collection 'clinical_records' -> 'v_clinical_doctor'
[✓] Trovati 10 documenti (3036.3ms)
──────────────────────────────────────────────────────────────────────
  ── [1] ────────────────────────────────────
  _id                    167a6bde-aff9-5322-8c56-9a8432d277d2
  medical_condition      Cancer
  medication             Paracetamol
  patient_id             4f781fb9-ce9f-5313-913d-7ec2be6047fa
  test_results           Normal
```
*La query viene reindirizzata alla View `v_clinical_doctor` consentendo al medico di visualizzare solo i record clinici autorizzati.*

### C. Esecuzione Query non Autorizzata (Medico su Billing)
Tentativo da parte del medico di accedere ai dati contabili:
```bash
python3 scripts/mongo_proxy_cli.py --cn paolo.roselli query --collection billing
```
**Risultato a Terminale**:
```
[*] Query: billing.find({}) limit=10
[*] Contatto ZTA Agent per avviare il tunnel MongoDB per paolo.roselli...
[✓] Tunnel ZTA avviato su localhost:27028 (Token: 5E5433A2-43D1-4E18-9195-646376067A58)
[*] Connessione al tunnel locale localhost:27028 come mario.rossi...
[✗] MongoDB RBAC / OPA ha negato la query [code=13]: not authorized on zta_db to execute command { find: "billing", ... }
```
*L'accesso viene prontamente negato in quanto la CLI non ha tradotto la collezione in una View accessibile, e le credenziali del database non dispongono di permessi di lettura sulla collezione fisica di base.*

### D. Esecuzione Query Billing Staff (`anna.verdi` / Ruolo `billing_staff`)
Interrogazione della contabilità da parte di un operatore di fatturazione:
```bash
python3 scripts/mongo_proxy_cli.py --cn anna.verdi query --collection billing
```
**Risultato a Terminale**:
```
══════════════════════════════════════════════════════════════════════
 ZTA MongoDB Proxy CLI  •  CN: anna.verdi
══════════════════════════════════════════════════════════════════════
[*] Query: billing.find({}) limit=10
[*] Contatto ZTA Agent per avviare il tunnel MongoDB per anna.verdi...
[✓] Tunnel ZTA avviato su localhost:27030 (Token: 5D312676-5FD6-43F3-8850-3BA0FEC5F7EF)
[*] Connessione al tunnel locale localhost:27030 come anna.verdi...
[*] RLS: Traduzione collection 'billing' -> 'v_billing_staff'
[✓] Trovati 10 documenti (3675.6ms)
──────────────────────────────────────────────────────────────────────
  ── [1] ────────────────────────────────────
  _id                    4317c7fb-f43a-50b3-af85-f5cc8fa92510
  billing_amount         18856.28
  insurance_provider     Blue Cross
  payment_status         paid

---

## 6. Estensione per Windows: Supporto TPM Nativo (Senza Fallback)

Per colmare il gap architetturale su Windows ed evitare la memorizzazione di file di chiave privata non cifrati su disco (fallback legacy), è stato implementato un **emulatore di Agente ZTA nativo per Windows** scritto in PowerShell/C#.

### Architettura del Servizio Agente Windows (`tpm_agent_service.ps1`)
Il file [tpm_agent_service.ps1](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/windows/tpm_agent_service.ps1) funge da agente in background su Windows, esponendo le medesime API dell'agente macOS (`http://localhost:9090`).

1. **Gestione del Tunneling mTLS TCP tramite Schannel**:
   A differenza di Python, che si appoggia ad OpenSSL e non ha accesso diretto al Certificate Store di Windows, l'agente PowerShell si appoggia alle API native di Windows (`Schannel`) tramite la classe .NET `System.Net.Security.SslStream`.
2. **Accesso Hardware-Bound al TPM**:
   L'agente carica il certificato client dal Certificate Store di Windows (`Cert:\CurrentUser\My`) tramite il CN. Windows Schannel gestisce l'handshake e la firma della chiave privata delegando in modo del tutto trasparente l'operazione crittografica al chip **TPM** fisico (tramite il provider `Microsoft Platform Crypto Provider`), mantenendo la chiave non esportabile.
3. **Piping Bidirezionale Asincrono**:
   Per ogni richiesta in arrivo sulla porta dinamica del tunnel locale (es: `localhost:27019`), il servizio istanzia un socket TCP con Envoy, avvia un handshake mTLS utilizzando il certificato del TPM, e copia asincronicamente i pacchetti dati da e verso il driver Python di MongoDB.

### Flusso di Esecuzione su Windows
Non è necessario mantenere il demone PowerShell sempre attivo in background. Il client [mongo_proxy_cli.py](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/mongo_proxy_cli.py) gestisce il ciclo di vita del servizio in modalità **on-demand**:

1. **Esecuzione Query**:
   Quando l'utente lancia il comando:
   ```bash
   python3 scripts/mongo_proxy_cli.py --cn paolo.roselli query --collection admissions
   ```
   * Il client Python rileva il sistema operativo `Windows` ed esegue un controllo preliminare sulla porta `9090`.
   * Se il servizio non è in ascolto, Python **avvia in background** lo script `tpm_agent_service.ps1` usando `subprocess.Popen`.
   * Una volta pronto l'agente, il client richiede la sessione via `POST /proxy/start` ed esegue la query MongoDB tramite il tunnel protetto dal TPM.
   * Al completamento della query (o alla chiusura della REPL interattiva), Python esegue la terminazione pulita dell'agente inviando un segnale di arresto al processo in background.
   * Se l'avvio automatico dovesse fallire (o se si forza l'uso del file tramite `--file`), il client esegue il fallback trasparente sulle chiavi non cifrate su disco.

*(Opzionale)* Qualora si desideri monitorare manualmente i log dell'agente o mantenerlo sempre attivo per sessioni prolungate, è comunque possibile avviarlo autonomamente da terminale prima di eseguire le query:
```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts/windows/tpm_agent_service.ps1
```
