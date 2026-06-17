# Architettura ZTA: Web Console & Proxy Locale (Secure Enclave / TPM)

Questa documentazione descrive il funzionamento dell'architettura di tunneling locale implementata per consentire alla console web (Web Console) di effettuare query cifrate e autenticate via hardware-bound mTLS senza compromettere o esportare le chiavi private.

---

## 1. Visione d'Insieme & Obiettivi

Nelle architetture tradizionali, l'autenticazione mTLS (Client Certificate Authentication) direttamente dal browser verso servizi protetti (come un Envoy Gateway davanti a MongoDB) presenta gravi limitazioni:
2. **Esportabilità delle Chiavi**: Forzare l'uso di certificati software costringerebbe a memorizzare la chiave privata nel filesystem dell'utente o nel server PKI, eliminando la proprietà di non-ripudiabilità dell'hardware.

Per risolvere questo problema, l'architettura implementata introduce un **Proxy Locale Loopback delegato in Spazio Utente gestito direttamente dal Backend**:
- La chiave privata **non lascia mai il Secure Enclave** del client.
- Il browser si limita a fare una singola richiesta `/api/query` al server PKI.
- Il server PKI rileva se l'utente è hardware-bound e, in tal caso, coordina l'avvio e l'arresto del tunnel locale contattando l'agente locale dell'utente su `host.docker.internal:9090`.

---

## 2. Diagramma di Flusso dell'Architettura

Il flusso dati si articola come segue:

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                Macchina Host del Client                 │
                  │                                                         │
                  │  ┌──────────────┐                                       │
                  │  │ Web Console  │                                       │
                  │  │   Browser    │                                       │
                  │  └──────┬───────┘                                       │
                  │         │                                               │
                  │  1. api/query (Single Call)                             │
                  │         │                                               │
                  │         ▼                                               │
                  │  ┌──────────────┐  2. proxy/start  ┌─────────────────┐  │
                  │  │ PKI Server   │─────────────────▶│    ZTA Agent    │  │
                  │  │  (Docker)    │                  │  (localhost:90) │  │
                  │  └──────┬───────┘                  └────────┬────────┘  │
                  │         │                                   │           │
                  │         │                               (Start tunnel)  │
                  │         │                                   │           │
                  │         │                                   ▼           │
                  │         │                          ┌─────────────────┐  │
                  │         │                          │ Loopback Proxy  │  │
                  │         │                          │  (:27022 tcp)   │  │
                  │         │                          └────────▲────────┘  │
                  │         │                                   │           │
                  │  3. Connect plain TCP                       │           │
                  │  (host.docker.internal:27022)               │           │
                  │         └───────────────────────────────────┘           │
                  │                                                         │
                  │  ┌──────────────┐    4. mTLS (Hardware Signed)          │
                  │  │    Envoy     │◀──────────────────────────────────────┘  │
                  │  │  (Docker)    │                                       │
                  │  └──────┬───────┘                                       │
                  └─────────┼───────────────────────────────────────────────┘
                            │ 5. DB Command
                            ▼
                     ┌──────────────┐
                     │   MongoDB    │
                     │  (Docker)    │
                     └──────────────┘
```

---

## 3. Descrizione del Ciclo di Vita (Step-by-Step)

### A. Rilevamento della Tipologia di Certificato
1. Quando la pagina [index.html](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/templates/index.html) viene caricata, effettua una chiamata a `/api/admin/certificates` gestita dalla classe Flask [app.py](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/app.py).
2. Il metodo [list_certificates](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/pki.py#L756) esamina se la chiave privata del certificato esiste sul server. Se non esiste, imposta il flag `"is_hardware": true`.
3. Il frontend riceve l'elenco e mostra dinamicamente un badge `🛡️ Hardware Bound (Secure Enclave/TPM)` o `🧪 Software Cert (Lab Mode)`.

### B. Inizializzazione del Tunnel (Gating Biometrico)
Se l'utente selezionato è hardware-bound, il browser intercetta l'evento di submit della query:
1. Chiama in locale `POST http://localhost:9090/proxy/start` passando il Common Name dell'utente.
2. La richiesta viene intercettata dal server API locale integrato nello [ZTAAgent](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/LocalAPIServer.swift#L231).
3. Il gestore [MongoProxyManager](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/MongoProxyManager.swift#L179) attiva una verifica biometrica tramite il framework `LocalAuthentication` (`LAContext`).
4. Se l'utente si autentica con successo via Touch ID o Password di sistema, il proxy alloca una porta TCP locale libera (es. `27021`) e vi si mette in ascolto bindato solo su `127.0.0.1`.
5. Viene restituito un JSON contenente la porta allocata e un `session_token` temporaneo.

### C. Esecuzione della Query
1. Il browser esegue una richiesta `POST /api/query` verso il server PKI (`identity-pki` in Docker), inserendo nel payload il parametro `local_proxy_port: 27021`.
2. All'interno di [api_query](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/app.py#L267), il backend rileva il parametro:
   - Salta il controllo di presenza della chiave privata locale.
   - Stabilisce una connessione TCP standard diretta a `host.docker.internal:27021` (che si risolve sull'indirizzo localhost dell'host fisico).
3. Il tunnel locale intercetta la connessione. Tramite la libreria `Network` di Apple, crea una socket mTLS verso l'endpoint reale di Envoy (`localhost:10000`), associando la `SecIdentity` estratta dal Keychain di sistema.
4. Ogni operazione crittografica di firma (durante l'handshake mTLS) viene gestita dal Secure Enclave.
5. Il client PyMongo si autentica sul database usando il meccanismo passwordless `MONGODB-X509` con lo username `CN=envoy,O=AdvancedCybersecurity-Clients,C=IT`. 
6. Quando il comando attraversa il tunnel, Envoy (che si presenta a MongoDB con il proprio certificato `CN=envoy`) convalida la connessione. MongoDB riconosce il certificato di Envoy (registrato nel database `$external` con tutti i ruoli combinati) e accetta l'autenticazione.
7. Envoy e OPA intercettano la chiamata originaria del client, estraggono il CN reale dell'utente (`CN=paolo.roselli`) e validano le policy di accesso a livello L7 (consentendo o bloccando la query).

### D. Teardown
1. Non appena il server PKI riceve la risposta da MongoDB e la restituisce al browser, il frontend invia una richiesta di chiusura `POST http://localhost:9090/proxy/stop` con il `session_token`.
2. Il proxy chiude immediatamente il socket e libera la porta, garantendo che il tunnel rimanga aperto solo per la durata strettamente necessaria all'esecuzione della query.

---

## 4. Dettaglio Componenti e File Chiave

### 1. Backend PKI Flask ([identity_pki](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki))
* **[app.py](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/app.py)**: Definisce l'endpoint `/api/query` che supporta la deviazione della stringa di connessione MongoClient verso `host.docker.internal:{local_proxy_port}` se presente.
* **[pki.py](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/pki.py)**: Riconosce i certificati registrati senza chiavi sul server, marcandoli come `is_hardware: true`.

### 2. Native ZTA Agent ([ztaagent](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent))
* **[LocalAPIServer.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/LocalAPIServer.swift)**: Riceve i comandi HTTP locali (porta 9090) del browser.
* **[MongoProxyManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/MongoProxyManager.swift)**: Gestisce il ciclo di vita delle porte allocate ed esegue il piping asincrono delle socket tra locale plain e remoto TLS.
* **[HardwareManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/HardwareManager.swift)**: Interagisce con il Secure Enclave per la generazione delle chiavi crittografiche hardware.

### 3. Docker Gateway Routing ([docker-compose.yml](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/docker-compose.yml))
* Configura la mappatura `host.docker.internal` tramite `extra_hosts` per consentire ai container interni alla rete virtuale Docker di raggiungere le porte in ascolto sulla interfaccia di loopback dell'host.

---

## 5. Vantaggi in termini di Sicurezza

1. **Zero-Knowledge sul Server**: Il server PKI e il database non memorizzano né entrano in contatto con le chiavi private degli utenti hardware-bound.
2. **Limitazione di Superficie di Attacco**: La porta TCP temporanea alloca solo socket bindati su `127.0.0.1`, impedendo ad altre macchine della LAN di sfruttare il tunnel mTLS dell'utente.
3. **Consenso Attivo**: Qualsiasi transazione o avvio di tunnel richiede esplicita interazione e consenso biometrico dell'utente fisico (Touch ID).
4. **Ciclo di vita Ephemeral**: Il tunnel viene deallocato istantaneamente al termine di ogni richiesta HTTP, riducendo a frazioni di secondo la finestra temporale di un eventuale abuso del canale aperto.
5. **Autenticazione Passwordless via Impersonation**: L'uso del meccanismo `MONGODB-X509` (con Envoy registrato come utente attendibile in `$external`) elimina completamente la necessità di memorizzare o trasmettere password SCRAM del database lato client. Tutta la logica di limitazione dei privilegi (RBAC) e la traduzione delle viste (RLS) è gestita via OPA ed Envoy in modo centralizzato e trasparente.
