# Valutazione Critica delle Policy OPA in Ottica Zero Trust

Questo documento fornisce un'analisi dettagliata sull'efficienza, la sufficienza e la correttezza delle policy OPA (`main.rego`, `criteria.rego`, `risk.rego`, `identity.rego`) rispetto ai requisiti teorici dello standard **NIST SP 800-207**.

---

## ⚡ 1. Efficienza (Performance e Scalabilità)

L'efficienza del motore di calcolo delle policy è mista:

* **Punto di Forza (Cache In-Memory)**: 
  La scelta di aggiornare asincronamente tabelle come `trust_registry`, `snort_alerts` e `nftables_alerts` ogni 10 secondi tramite il thread di sync è estremamente efficiente. OPA valuta queste regole in-memory in microsecondi, senza impatto sulla latenza della connessione database.
* **Collo di Bottiglia Critico (Query Sincrone su Splunk)**: 
  L'uso di `http.send` all'interno di OPA verso l'endpoint `/api/stats` della forwarder è un grave errore di design prestazionale. La forwarder esegue una ricerca "oneshot" su Splunk ad ogni singola richiesta di connessione. Le ricerche su Splunk sono operazioni pesanti che possono richiedere da centinaia di millisecondi a diversi secondi. Questo introduce un ritardo inaccettabile su database transazionali come MongoDB.
  * **Raccomandazione**: Rimuovere la chiamata sincrona `/api/stats`. OPA dovrebbe basarsi *esclusivamente* sulle metriche aggregate spinte in cache asincrona ogni 10 secondi.

---

## 🔍 2. Sufficienza (Copertura delle Minacce)

La copertura delle policy è molto ampia, ma soffre di alcune lacune strutturali dovute al protocollo di trasporto:

* **Punto di Forza (Multidimensionalità)**:
  La policy non si limita a un controllo statico del ruolo (RBAC), ma implementa una valutazione del rischio basata sul contesto del dispositivo (TPM), della rete (IP interno/esterno), del comportamento dell'utente (comandi inviati) e del contenuto delle query (WAF per SQL/NoSQL injection).
* **Mancanza di ABAC nativo nel PEP**:
  La traduzione Row-Level Security (RLS) (es. riscrivere la query da `clinical_records` a `v_clinical_doctor`) è demandata al server web [app.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/identity_pki/app.py). OPA non applica filtri basati su attributi (ABAC) in modo autonomo. Se un utente scavalca la web console e si connette direttamente con Compass, OPA può solo consentire o negare l'intera collezione, ma non può filtrare i singoli record (es. impedire a un medico di vedere pazienti non suoi).
  * **Raccomandazione**: Spostare le logiche di filtraggio RLS/ABAC direttamente all'interno delle policy OPA basandosi su attributi utente e risorse.

---

## 🛡️ 3. Correttezza Zero Trust (NIST SP 800-207)

Rispetto ai 7 principi fondamentali del NIST, le policy mostrano alcune deviazioni importanti:

### A. Autorizzazione a Livello di Connessione vs Transazione (Principio 3 NIST)
* **Principio NIST**: "L'accesso alle singole risorse aziendali è concesso su base temporanea e per singola sessione/transazione."
* **Stato Attuale**: Le policy OPA vengono valutate solo all'instaurazione del canale TCP mTLS. Una volta aperta la connessione a MongoDB, l'utente può inviare infiniti comandi differenti senza che OPA effettui alcuna rivalutazione dinamica.
* **Valutazione**: **Non conforme**. Un'architettura ZTA corretta richiede una valutazione transazionale L7 su ogni singola richiesta/messaggio database.

### B. Gestione dei Comandi Sconosciuti (Principio di Default Deny)
* **Principio NIST**: "L'accesso è negato di default e consentito solo tramite policy esplicita (Fail-Closed)."
* **Stato Attuale**: A causa della mancata decodifica di `OP_MSG`, in [main.rego](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/opa/policies/main.rego) è presente la regola:
  ```rego
  allow if {
      identity.action_name == "unknown"
      identity.current_role in {"admin", "doctor", ...}
      risk.risk_score_allow
  }
  ```
* **Valutazione**: **Grave violazione del principio Zero Trust**. Consentire un'azione "sconosciuta" solo perché il ruolo è valido crea una falla enorme: un attaccante che ha compromesso un account medico può eseguire qualsiasi operazione distruttiva sul database (es. `dropDatabase`) sfruttando il protocollo `OP_MSG`, poiché OPA classificherà l'azione come `unknown` e la consentirà.

### C. Bypass dei Comandi di Sistema (Bypass Rules)
* **Descrizione**: I comandi come `hello`, `isMaster`, `ping`, `saslStart` e `saslContinue` bypassano completamente il calcolo del rischio e sono sempre consentiti.
* **Valutazione**: **Accettabile ma rischioso**. È necessario per il funzionamento del driver di MongoDB, ma espone a potenziali canali di evasione se l'attaccante riesce a incapsulare informazioni o sfruttare vulnerabilità (es. Denial of Service) all'interno dei pacchetti di handshake.

---

## 🏁 Verdetto Finale

L'architettura ha **eccellenti basi teoriche** e l'integrazione con Splunk è all'avanguardia. Tuttavia, le policy correnti **non possono essere considerate pienamente corrette o sufficienti** per un vero modello Zero Trust a causa dei bypass introdotti per far funzionare i client moderni (ammissione delle azioni `unknown`) e della mancanza di rivalutazione transazionale sulle connessioni persistenti.
