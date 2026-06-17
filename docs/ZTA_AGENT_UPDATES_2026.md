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

## 2. Flusso di Controllo Aggiornato (Fine-a-Fine)

Il flusso di autenticazione e interrogazione a ciclo di vita breve avviene ora secondo questa sequenza ad ogni click/richiesta:

```
[ Browser / Web Console :8080 ]
          │
          │ (1) POST /proxy/start (Avvia proxy locale con TTL 60s)
          │
          ├──► [ ZTA Agent ] ──► Prompt Touch ID (1 sola volta, sblocca LAContext)
          │
          │ (2) POST /oidc/token
          ├──► [ ZTA Agent ] ──► Genera token OIDC (0 Touch ID: Riutilizza LAContext sbloccato)
          │
          │ (3) Connessione TCP del pool MongoDB a Local Proxy
          ▼
[ Local Proxy Listener ]
          │
          │ (4) Handshake mTLS multipli (0 Touch ID: Riutilizzano LAContext)
          ▼
[ Envoy PEP :10000 ] ◄──► [ OPA Engine :9002 ] (Controllo OIDC + Token Binding RFC 8705)
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
