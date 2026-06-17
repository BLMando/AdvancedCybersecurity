# Relazione Tecnica: Integrazione della Sicurezza Hardware (Secure Enclave & TPM) in ZTA

Questo documento fornisce una relazione tecnica sull'architettura di sicurezza hardware utilizzata nel progetto per l'autenticazione mTLS, descrivendo l'integrazione con **Apple Secure Enclave** (macOS) e **TPM** (Windows), e fornendo le motivazioni ingegneristiche alla base dell'uso di un **Proxy TCP Loopback**.

---

## 1. Riferimenti di Piattaforma

Il sistema adotta un modello ibrido per supportare i chip di sicurezza fisici in base al sistema operativo del client:

### A. macOS: Apple Secure Enclave Processor (SEP)
* **Agente Nativo**: Applicazione Swift ([ZTAAgent](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/ztaagent/ZTAAgent)).
* **Gestione Chiavi**: La chiave privata viene generata direttamente nel chip hardware dedicato tramite l'attributo `kSecAttrTokenIDSecureEnclave` delle API di sistema di Apple.
* **Biometria**: L'accesso alle operazioni di firma è subordinato a un controllo di accesso biometrico hardware (`kSecAccessControlUserPresence`), che attiva il prompt di Touch ID.

### B. Windows: Trusted Platform Module (TPM)
* **Agente Nativo**: Script PowerShell ([tpm_agent_service.ps1](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/windows/tpm_agent_service.ps1)) ed helper C# ([hw_attestation.ps1](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/windows/hw_attestation.ps1)).
* **Gestione Chiavi**: Sfrutta le API **Windows CNG (Cryptography Next Generation)** interagendo con il `Microsoft Platform Crypto Provider` (il KSP legato al chip TPM 2.0 fisico della scheda madre).

---

## 2. Giustificazione Tecnica: Limitazioni dei Driver e Architettura Proxy

### Il Problema: Limitazioni di TLS e Driver MongoDB
I driver database standard (come `pymongo` in Python o i driver Node.js usati da `mongosh` e MongoDB Compass) e le librerie TLS a basso livello su cui poggiano (principalmente **OpenSSL**, **BoringSSL** o **LibreSSL**) hanno una limitazione fondamentale:
1. **Esportazione della Chiave Privata**: Si aspettano che le chiavi crittografiche private vengano fornite come file fisici su disco (es. file PEM/DER `.key`) o caricate in memoria RAM come array di byte.
2. **Vincolo Hardware**: Per progettazione, sia il Secure Enclave di Apple che lo standard TPM **impediscono categoricamente l'esportazione della chiave privata**. La chiave privata non può mai risiedere nella memoria RAM del processo applicativo né essere salvata su disco; può essere utilizzata unicamente delegando le operazioni di firma all'interno del chip crittografico fisico.
3. **Mancanza di Astrazione negli SDK**: I driver di database commerciali non implementano interfacce per agganciarsi alle API crittografiche native dei singoli sistemi operativi (come Apple Security Framework o Windows CNG/Schannel) per delegare la firma durante il TLS handshake.

### La Soluzione: Il Proxy Loopback Locale (PEP Broker)
Per abilitare l'autenticazione Zero Trust forte (mTLS hardware-bound) senza dover modificare il codice sorgente dei driver MongoDB o compromettere la sicurezza esportando le chiavi, è stato adottato il pattern **Local TCP Loopback Proxy**:

```
[ mongosh / Python Client ]  (Connessione standard non crittografata)
         │
         ▼  (localhost:27019 / plain TCP)
[ ZTA Agent Local Proxy ]    (Risolve Touch ID / Schannel ed esegue l'handshake mTLS native)
         │
         ▼  (mTLS Tunnel con Certificato Hardware-Bound)
[ Envoy Proxy (PEP) ]        (Termina mTLS, valida l'identità del client con OPA)
         │
         ▼  (TLS interno)
[ MongoDB Instance ]         (Esegue le query su viste RLS dedicate)
```

1. **Integrazione Nativa**: L'agente locale (scritto in Swift su macOS e PowerShell/.NET su Windows) è in grado di dialogare direttamente con le API crittografiche del sistema operativo (Security/LocalAuthentication e CNG/Schannel).
2. **Delega della Firma**: Il proxy intercetta il traffico MongoDB non crittografato inviato dal client a `localhost:27019`, avvia una connessione TLS verso Envoy, e delega la firma del TLS Handshake all'hardware sicuro (previa verifica di Touch ID o Windows Hello).
3. **Compatibilità Universale**: Qualsiasi strumento di terze parti (`mongosh`, MongoDB Compass, script Python) può usufruire dei vantaggi dell'autenticazione hardware senza richiedere modifiche ai driver: è sufficiente indirizzare le query sulla porta locale del proxy.

---

## 3. Flusso Operativo della Web Console

Quando si utilizza la console di amministrazione web del PKI (`http://localhost:8080`):

1. **Richiesta di Avvio Proxy**: All'invio della query, la pagina web contatta l'agente ZTA locale all'indirizzo `http://localhost:9090/proxy/start`.
2. **Prompt Biometrico**: L'agente viene portato in primo piano (`NSApp.activate` su macOS) e mostra la richiesta di Touch ID / Windows Hello per autorizzare l'uso della chiave privata protetta.
3. **Apertura del Tunnel**: L'agente alloca una porta locale casuale (es. `27019`), stabilisce il tunnel mTLS verso Envoy usando l'identità hardware, e restituisce il numero di porta alla Web Console.
4. **Esecuzione Query**: La Web Console (all'interno del container Docker) effettua la query MongoDB parlando con `host.docker.internal:<porta_proxy>`. Il traffico viene incanalato in sicurezza ed Envoy convalida la transazione tramite OPA.
5. **Chiusura**: Al completamento della query, viene inviata una richiesta a `/proxy/stop` per chiudere il tunnel ed evitare sessioni latenti.
