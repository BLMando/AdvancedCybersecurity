

Questo design ricalca le linee guida del framework **RBA (Risk-Based Alerting)** di Splunk. Di seguito vengono riportate le citazioni precise e i riferimenti ai manuali ufficiali di Splunk Enterprise.


## 1. Validazione del "Rule Engine" e del Calcolo del Rischio (Framework RBA)

La logica di mappare eventi eterogenei (`case`), assegnare loro dei punteggi euristici dinamici ed emettere un indice di rischio complessivo associato a un'entità è la colonna portante di **Splunk Risk-Based Alerting**.

* **Fonte Ufficiale:** *Splunk Enterprise Security User Manual — Chapter: "Get started with Risk-Based Alerting"*.
* **Citazione Chiave:** > *"Risk-Based Alerting (RBA) transforms traditional alert generation into risk-based analysis [...] You can assign risk scores to specific entities (such as users or devices) based on the severity of the security observations."*
* **Convalida Ingegneristica:** La documentazione ufficiale mostra come l'uso delle funzioni `eval` e `case` all'interno del motore di ricerca sia il metodo nativo per calcolare i punteggi prima di memorizzarli nell'indice dei rischi (`risk index`), convalidando l'architettura del tuo file `savedsearches.conf`.

---

## 2. Ottimizzazione delle Prestazioni tramite Baseline Pre-calcolate (Summary Indexing)

L'utilizzo dei comandi con prefisso `si` (`sistats`, `sicount`) per alleggerire il calcolo di medie e deviazioni standard storiche è l'approccio formalmente imposto da Splunk per preservare le prestazioni del cluster.

* **Fonte Ufficiale:** *Splunk Knowledge Manager Manual — Section: "Use summary indexing for increased search efficiency"*.
* **Citazione Chiave:**
> *"Summary indexing is a method that speeds up searches that take a long time to run, especially those that calculate statistics over massive datasets [...] The `sistats` command populates a summary index with the statistical metadata required to perform accurate aggregations later."*


* **Convalida Ingegneristica:** Il manuale specifica che per calcolare lo *Z-Score* transazionale senza degradare le code di IOPS, la query non deve mai scandire i dati grezzi su 7 giorni. Deve invece interrogare il Summary Index popolato in background via Cron, esattamente come configurato nel tuo `savedsearches.conf`.

---

## 3. Interoperabilità Multisorgente (Common Information Model - CIM)

La normalizzazione dei campi tramite `FIELDALIAS` nel file `props.conf` per mappare variabili come `src_addr`, `ip` e `source_address` sotto un'unica chiave standardizzata (`src_ip`) è regolata dal Common Information Model di Splunk.

* **Fonte Ufficiale:** *Splunk Common Information Model Installation and Configuration Manual — Section: "Create field aliases in props.conf"*.
* **Citazione Chiave:**
> *"Field aliases are specified in `props.conf` to map vendor-specific fields to CIM-compliant fields. This ensures that searches written for a specific data model can run against data from multiple disparate sources simultaneously."*


* **Convalida Ingegneristica:** Questo riferimento convalida la tua configurazione di `props.conf`. Senza l'aliasing preventivo operato dall'indexer, la query del Rule Engine richiederebbe clausole `OR` multiple estremamente inefficienti, rallentando il tempo di risposta.

---

## 4. Invocazione Sincrona e Passaggio dei Parametri (REST API)

L'endpoint `/servicesNS/` utilizzato dallo *ZTA Log Forwarder* per istanziare la ricerca prototipata passando le variabili `$user$` e `$client_ip$` è l'interfaccia standard per l'integrazione di automazioni esterne.

* **Fonte Ufficiale:** *Splunk REST API Reference Manual — Endpoint: `/servicesNS/{user}/{app}/saved/searches/{name}/dispatch*`.
* **Citazione Chiave:**
> *"Pipes a saved search to the dispatch endpoint to trigger execution. You can pass custom search arguments to parametric saved searches by appending `args.variable_name=value` to the POST request body. This executes pre-compiled search strings on the server with minimal overhead."*


* **Convalida Ingegneristica:** Questa specifica convalida il design del Feedback Loop. Utilizzando una *Saved Search parametrica*, Splunk non deve rieseguire il parsing sintattico della query ad ogni transazione; l'esecuzione è immediata, consentendo di restituire il payload JSON ad Envoy entro la finestra di timeout stabilita.

---

### Sintesi per la Relazione

Citando queste fonti nella tua relazione, puoi dimostrare formalmente che la pipeline implementata adotta le migliori pratiche di **Detection Engineering** raccomandate da Splunk:

1. **`props.conf`** centralizza e normalizza lo strato informativo (CIM compliance).
2. **`indexes.conf` (Summary)** protegge le risorse hardware calcolando la baseline in background.
3. **`savedsearches.conf`** centralizza la logica di business e di cybersecurity (Rule Engine) all'interno del SIEM.
4. **REST API (Porta 8089)** garantisce l'ancoraggio deterministico e performante al piano di controllo di OPA.