# Aggiornamenti dell'Agente ZTA (Swift/macOS) — Relazione e Changelog 2026

Questo documento documenta le modifiche architetturali, i bug fix e i refactoring effettuati di recente sull'agente nativo macOS Swift (**ZTAAgent**), al fine di stabilizzare il tunnel locale mTLS verso MongoDB, consentire la corretta visualizzazione dei prompt biometrici e permettere la comunicazione con l'applicazione web console.

---

## 1. Modifiche apportate all'Agente ZTA (Swift/macOS)

### A. Supporto alle Richieste CORS Preflight (OPTIONS)
* **File Modificato**: [LocalAPIServer.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/LocalAPIServer.swift)
* **Problema**: La Web Console (servita su `http://localhost:8080`) e l'agente (in ascolto su `http://localhost:9090`) si trovano su origini differenti. Quando il client web inviava una richiesta `POST /proxy/start` con payload JSON, il browser effettuava automaticamente una chiamata CORS preflight di tipo `OPTIONS`. L'agente locale rispondeva con un `404 Not Found`, bloccando le successive chiamate.
* **Soluzione**: È stato implementato un gestore globale delle richieste `OPTIONS` all'interno del metodo `parseRequest` dell'agente. L'agente ora risponde immediatamente con uno stato `204 No Content` ed include gli header CORS corretti (`Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`), consentendo al browser di inoltrare la richiesta di autenticazione ed avviare il tunnel.

### B. Attivazione in Primo Piano per Prompt Biometrici (Touch ID)
* **File Modificato**: [MongoProxyManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/MongoProxyManager.swift)
* **Problema**: Per ragioni di sicurezza, macOS limita la visualizzazione dei dialoghi di autenticazione biometrica (Touch ID) se il processo chiamante è in esecuzione in background (ad esempio, quando l'utente si trova sulla finestra del browser web). Questo causava il blocco della richiesta in uno stato di attesa infinito, senza che venisse mostrato alcun prompt.
* **Soluzione**: È stata inserita la chiamata nativa all'API AppKit `NSApp.activate(ignoringOtherApps: true)` subito prima della chiamata ad `evaluatePolicy` di `LAContext`. Questo forza l'applicazione ZTAAgent in primo piano (attirando il focus dell'utente) e sblocca l'apparizione immediata del pop-up di Touch ID.

### C. Importazione Certificato nel Keychain tramite API Native
* **File Modificato**: [HardwareManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/HardwareManager.swift)
* **Problema**: Precedentemente, l'importazione del certificato DER firmato dalla PKI avveniva eseguendo il comando di shell `/usr/bin/security import`. Questo inseriva il certificato nel keychain globale di login dell'utente, mentre la chiave privata creata nel Secure Enclave veniva registrata nella partizione/Access Group esclusiva dell'applicazione (`com.zta.agent.keychain`). La discrepanza di partizione impediva a `SecIdentityCreateWithCertificate` di collegare il certificato alla sua chiave privata, restituendo l'errore `errSecItemNotFound` (-25300).
* **Soluzione**: Il comando shell è stato sostituito con le API native `SecItemAdd` di Apple, forzando la memorizzazione del certificato all'interno dello stesso contesto di Keychain dell'applicazione. In questo modo macOS collega correttamente il certificato alla sua chiave privata nel Secure Enclave creando una `SecIdentity` valida.

### D. Risoluzione dei Crash del Tunnel (Errore 96 - Stream EOF)
* **File Modificato**: [MongoProxyManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/MongoProxyManager.swift)
* **Problema**: Nel ciclo di instradamento TCP bidirezionale (`pipe`), la ricezione di un indicatore `isComplete = true` (EOF/FIN TCP inviato da Envoy o dal client) in concomitanza con la presenza di dati in coda causava una chiamata ricorsiva asincrona a `receive`. Poiché il canale era già in chiusura, questa chiamata aggiuntiva restituiva immediatamente un errore POSIX 96 (`ENODATA` / "No message available on STREAM"). Il proxy interpretava questo evento come un errore critico di rete ed annullava bruscamente entrambe le connessioni prima che l'invio asincrono dei dati in sospeso fosse completato.
* **Soluzione**: È stato corretto il flusso di pipe in modo che l'indicatore `isComplete` venga inoltrato direttamente nella stessa chiamata `send` (tramite il parametro `isComplete: isComplete` di `NWConnection.send`). Inoltre, la chiamata ricorsiva a `pipe` avviene solo se `isComplete` è `false`, bloccando le letture successive sul socket chiuso e prevenendo la generazione dell'errore 96.

### E. Correzione delle Flag di Query in mongosh locale
* **File Modificato**: [ContentView.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/ContentView.swift)
* **Problema**: Durante l'esecuzione delle query dirette dall'applicazione, `mongosh` restituiva errori legati all'impossibilità di stabilire l'autenticazione passwordless `MONGODB-X509` (a causa della connessione locale non-TLS al proxy) o fallimenti di topologia (replica set lookup).
* **Soluzione**:
  1. È stata aggiunta l'opzione `--username "CN=envoy,O=AdvancedCybersecurity-Clients,C=IT"` per dichiarare esplicitamente il soggetto del certificato che Envoy userà a valle con MongoDB.
  2. È stato aggiunto il parametro `?directConnection=true` alla stringa di connessione per disabilitare il discovery delle repliche di MongoDB, evitando timeout di rete non necessari.

---

### F. Ottimizzazione UX Touch ID (Esattamente 1 prompt Touch ID per Richiesta)
* **File Modificati**: [MongoProxyManager.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/MongoProxyManager.swift), [PKIClient.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/PKIClient.swift), [LocalAPIServer.swift](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/LocalAPIServer.swift), [index.html](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/templates/index.html)
* **Problema**: A causa delle connessioni mTLS concorrenti del pool driver MongoDB, della generazione del token OIDC crittografico e dell'avvio della sessione del proxy locale, l'utente era costretto a inserire l'impronta Touch ID (o il PIN) ben **5 volte** per una singola query.
* **Soluzione**:
  1. **Condivisione dell'`LAContext`**: L'oggetto `LAContext` sbloccato all'avvio del tunnel viene memorizzato all'interno di `MongoProxySession` e associato alle query crittografiche del Keychain tramite la chiave `kSecUseAuthenticationContext`. Questo consente a tutte le successive connessioni mTLS del pool di bypassare i prompt biometrici ripetuti.
  2. **Token OIDC via Active Context**: L'endpoint `/oidc/token` interroga `MongoProxyManager.shared.getContextForCN(cn:)` per riutilizzare lo stesso `LAContext` precedentemente autenticato, impiegandolo per firmare la challenge OIDC senza richiedere un secondo Touch ID.
  3. **Ciclo di Vita del Proxy a Richiesta (Zero Trust)**: Per garantire che la sessione non rimanga aperta in background (rispettando il principio di mediazione completa), la Web Console avvia il proxy con un TTL molto breve (60 secondi) all'inizio della query e lo arresta programmaticamente inviando una richiesta `POST /proxy/stop` subito dopo il completamento della query. In questo modo l'utente deve fornire esattamente un Touch ID per ogni singola query.

---

### G. Primary Session Gating lato Server (12h) e Step-Up Authentication (120s)
* **File Modificati**: [`app.py`](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/app.py), [`oidc.py`](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/oidc.py)
* **Problema**: Dopo l'enrollment, qualsiasi agente con un certificato valido poteva richiedere un token OIDC senza che il server avesse mai verificato la sessione dell'operatore umano. Non esisteva un meccanismo di "scadenza sessione" indipendente dalla validità del certificato X.509, né un controllo di "freschezza" aggiuntivo per operazioni sensibili (update, delete, billing ad alto valore).
* **Soluzione**: È stato introdotto il dizionario in-memory `PRIMARY_SESSIONS` in `app.py`:
  ```python
  PRIMARY_SESSIONS = {}  # cn -> {"login_time": datetime, "last_mfa_time": datetime}
  ```
  L'endpoint `/api/oidc/token` applica due livelli di gating:
  1. **Primary Session Gate (12h)**: Se `PRIMARY_SESSIONS` non contiene una sessione attiva per il `cn` richiedente, oppure se la sessione è scaduta (> 12 ore dal `login_time`), il server risponde con `401 Unauthorized` e il payload `{"reason": "primary_session_required"}`. Il client deve re-autenticarsi tramite il flusso AD Login + OTP prima di poter ricevere un nuovo token.
  2. **Step-Up Freshness Gate (120s)**: Quando il client richiede il token con `step_up: true` (necessario per `update`, `delete`, o query billing > 5000), il server verifica che `last_mfa_time` della sessione corrente sia stata registrata meno di 120 secondi prima. Se la finestra di freschezza è scaduta, il server risponde con `401` e `{"reason": "step_up_required"}`. Il client deve eseguire un nuovo ciclo OTP prima di procedere.
  Il login AD con OTP riuscito aggiorna sia `login_time` che `last_mfa_time` in `PRIMARY_SESSIONS[cn]`, resettando entrambe le finestre temporali.

### H. Propagazione degli Errori 401 dagli Agenti Locali alla Web Console
* **File Modificati**: [`LocalAPIServer.swift`](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent/ZTAAgent/LocalAPIServer.swift), [`tpm_agent_service.ps1`](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/windows/tpm_agent_service.ps1)
* **Problema**: Quando il server PKI rispondeva con `401 Unauthorized`, gli agenti locali assorbivano l'errore HTTP a livello di rete e restituivano al browser un payload di errore generico (es. `"error": "request failed"`), perdendo l'informazione critica sul `reason` del rifiuto. La Web Console non era quindi in grado di distinguere tra un errore di rete e un errore di sessione scaduta, impedendo il workflow di riautenticazione automatica.
* **Soluzione (macOS)**: L'handler HTTP in `LocalAPIServer.swift` è stato aggiornato per leggere lo `statusCode` della risposta ricevuta dall'upstream PKI server. Se lo `statusCode` è `401`, il server locale rispedisce al browser esattamente lo stesso status code e lo stesso body JSON ricevuto dalla PKI, mantenendo intatto il campo `reason`. In questo modo il browser riceve un `401` con `{"reason": "primary_session_required"}` o `{"reason": "step_up_required"}` e può reagire di conseguenza.
* **Soluzione (Windows)**: In `tpm_agent_service.ps1`, il blocco `try-catch` che gestisce le `WebException` (errori HTTP non-2xx) è stato aggiornato per estrarre sia lo `StatusCode` che il body testuale della risposta di errore, replicando lo stesso status code e il body JSON nel Response dell'agente locale verso il browser.

### I. Primary Auth Modal e Auto-Retry nella Web Console
* **File Modificati**: [`index.html`](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/templates/index.html), [`style.css`](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/identity_pki/static/style.css)
* **Problema**: Anche con la corretta propagazione del `401`, il browser non aveva un meccanismo per raccogliere le credenziali dell'utente (AD Login + OTP), re-autenticarsi e poi riprovare automaticamente la query originale che aveva fallito.
* **Soluzione**: È stato introdotto il componente `primary-auth-modal` nell'interfaccia web:
  1. **Modal di Riautenticazione**: Un modale overlay (`#primary-auth-modal`) con form AD Login (email + password) e campo OTP viene visualizzato automaticamente quando il gestore della risposta della query rileva un `401` con `reason` di tipo `primary_session_required` o `step_up_required`.
  2. **Promise-based Workflow**: La logica JS utilizza una `Promise` (`promptPrimaryAuth()`) che si risolve solo quando il ciclo AD Login + OTP completa con successo. Il form di submit della query viene sospeso in attesa di tale Promise.
  3. **Auto-Retry**: Non appena la Promise si risolve (sessione ripristinata), il handler originale della query viene rieseguito automaticamente con gli stessi parametri, in modo trasparente per l'utente e senza richiedere un secondo click.

---

## 2. Flusso di Controllo Aggiornato (Fine-a-Fine)

Il flusso completo di autenticazione e interrogazione avviene ora secondo questa sequenza ad ogni click/richiesta:

```
╔══════════════════════════════════════════════════════════════════╗
║  LAYER 0: PRIMARY SESSION GATE (12h) — SERVER-SIDE              ║
║  Richiede login AD + OTP al primo accesso o dopo scadenza        ║
║  → Aggiorna PRIMARY_SESSIONS[cn] con login_time + last_mfa_time  ║
╚══════════════════════════════════════════════════════════════════╝
                              │
                              ▼
[ Browser / Web Console :8080 ]
          │
          │ (1) POST /proxy/start (Avvia proxy locale con TTL 60s)
          │
          ├──► [ ZTA Agent ] ──► Prompt Touch ID (1 sola volta, sblocca LAContext)
          │
          │ (2) POST /oidc/token  [→ PKI: controlla PRIMARY_SESSIONS]
          │    ├─ Se sessione scaduta (> 12h) → 401 primary_session_required
          │    │   └─► [ Browser ] mostra modal → AD Login + OTP → auto-retry
          │    ├─ Se step_up=true e last_mfa_time > 120s → 401 step_up_required
          │    │   └─► [ Browser ] mostra modal → OTP → auto-retry
          │    └─ Sessione valida → JWT emesso (cnf RFC 8705 bound)
          │
          ├──► [ ZTA Agent ] ──► Firma challenge OIDC (0 Touch ID: Riutilizza LAContext)
          │
          │ (3) Connessione TCP del pool MongoDB a Local Proxy
          ▼
[ Local Proxy Listener ]
          │
          │ (4) Handshake mTLS multipli (0 Touch ID: Riutilizzano LAContext)
          ▼
[ Envoy PEP :10000 ] ◄──► [ OPA Engine :9002 ] (Controllo JWT + cnf Token Binding RFC 8705)
          │
          ▼ (5) Connessione TLS interna con Proxy Impersonation (PROXY_USER)
[ MongoDB :27017 ] (Esecuzione query ed applicazione viste RLS)
          │
          ▼ [ Query Completata ]
[ Browser / Web Console :8080 ]
          │
          │ (6) POST /proxy/stop (Arresta immediatamente la sessione e distrugge il tunnel)
          ▼
[ ZTA Agent ] (Tunnel chiuso e LAContext invalidato)
```
