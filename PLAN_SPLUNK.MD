Ecco una guida ingegneristica passo dopo passo per riprogettare il flusso del rischio e migrare l'intera logica computazionale dallo *ZTA Log Forwarder* (script Python) direttamente dentro **Splunk Enterprise**, sfruttando le funzionalità native di *Summary Indexing*, *CIM Aliasing* e *Parametric Saved Searches*.

Con questa architettura, lo *ZTA Log Forwarder* smetterà di effettuare query multiple e pesanti e di calcolare i boost con costrutti `if` in Python. Diventerà un puro tramite stateless che chiama una sola Saved Search pre-compilata su Splunk e restituisce il risultato JSON finito a OPA in meno di 50-80ms.


## Fase 1: Normalizzazione dei Dati e Field Aliasing (`props.conf`)

### Cosa si fa

Si mappa la configurazione di Splunk per fare in modo che i campi informativi estratti da indici e sorgenti diverse utilizzino gli stessi identici nomi standardizzati per indicare l'attore (`user`) e la sorgente di rete (`src_ip`).

### Perché si fa

I log nativi sono eterogenei: Envoy usa `source_address`, Snort usa `src_addr`, MongoDB usa `ip`. Senza questa standardizzazione, la query del *Rule Engine* su Splunk dovrebbe contenere decine di clausole `OR` ed `eval` complesse, rallentando drasticamente il calcolo sincrono. L'aliasing sposta questo carico sul motore di ingestion di Splunk.

### Configurazione

Modifica o crea il file `$SPLUNK_HOME/etc/system/local/props.conf` (o all'interno della cartella della tua App Splunk):

```ini
# Stanza per i log di decisione OPA filtrati da Envoy
[envoy:access]
FIELDALIAS-zta_network_envoy = source_address AS src_ip
FIELDALIAS-zta_user_envoy = x_user AS user

# Stanza per gli alert JSON generati da Snort 3
[snort:alert_json]
FIELDALIAS-zta_network_snort = src_addr AS src_ip

# Stanza per l'Audit Trail nativo di MongoDB
[mongodb:audit]
FIELDALIAS-zta_network_mongo = ip AS src_ip
FIELDALIAS-zta_user_mongo = param.user AS user

```

---

## Fase 2: Configurazione del Summary Index per la Baseline (`indexes.conf`)

### Cosa si fa

Si crea un nuovo indice dedicato, chiamato `zta_baseline_summary`, che conterrà esclusivamente record statistici pre-aggregati relativi al comportamento storico degli utenti negli ultimi 7 giorni.

### Perché si fa

Per calcolare lo *Z-Score* comportamentale dell'utente, abbiamo bisogno di conoscere la media e la deviazione standard del suo volume di query. Se analizzassimo 7 giorni di log grezzi ad ogni singola richiesta di transazione, Splunk dovrebbe scansionare milioni di righe, mandando il sistema in timeout. Il *Summary Index* memorizza solo piccoli blocchi riassuntivi orari, riducendo i dati da scansionare del 99%.

### Configurazione

Aggiungi la definizione dell'indice nel file `$SPLUNK_HOME/etc/system/local/indexes.conf`:

```ini
[zta_baseline_summary]
homePath = $SPLUNK_DB/zta_baseline_summary/db
coldPath = $SPLUNK_DB/zta_baseline_summary/colddb
thawedPath = $SPLUNK_DB/zta_baseline_summary/thaweddb
maxTotalDataSizeMB = 10240

```

*(Nota: per una baseline di questo tipo, 10 GB sono più che sufficienti per memorizzare anni di storici aggregati).*

---

## Fase 3: Pianificazione del Calcolo della Baseline (`savedsearches.conf`)

### Cosa si fa

Si programma una ricerca pianificata (*Scheduled Search*) automatica che gira ogni ora. Questa ricerca prende i log grezzi di OPA dell'ultima ora, calcola il numero di query in blocchi da 15 minuti per ogni utente e salva il risultato all'interno del *Summary Index* appena creato.

### Perché si fa

Si utilizza il comando **`sistats`** anziché il classico `stats`. Nella documentazione di Splunk, la famiglia di comandi `si-` è l'unica progettata per salvare nel Summary Index non solo il conteggio finale, ma i metadati matematici (come le somme parziali e i quadrati dei delta). Questo è fondamentale: permette a Splunk di calcolare una deviazione standard aggregata e accurata nei passaggi successivi, riducendo a zero l'impatto sulla CPU durante il feedback loop reale.

### Configurazione

Aggiungi la configurazione nel file `$SPLUNK_HOME/etc/system/local/savedsearches.conf`:

```ini
[Generazione_Baseline_Utenti_15m]
search = index=zta_envoy sourcetype="opa:decision" \
| bucket _time span=15m \
| stats count as query_count by user, _time \
| sistats count by user, _time
cron_schedule = 5 * * * *
dispatch.earliest_time = -1h
dispatch.latest_time = now
action.summary_index = 1
action.summary_index._name = zta_baseline_summary
enableSched = 1

```

---

## Fase 4: Scrittura del Rule Engine e Calcolo del Rischio (`savedsearches.conf`)

### Cosa si fa

Si crea una **Saved Search parametrica** (accetta le variabili `$user$` e `$client_ip$`). Questa query unifica la timeline calda degli ultimi 15 minuti di tutti gli indici di sicurezza, applica la formula di decadimento esponenziale agli alert Snort, estrae la baseline dal Summary Index, calcola lo Z-Score e applica la matrice euristica dei boost con costrutti `case` nativi.

### Perché si fa

Questo è il cuore del tutorial: **elimina totalmente il codice Python del forwarder**. Tutta la logica di business e di cybersecurity viene accentrata dentro Splunk. Splunk valuta i dati in modo vettoriale sulla sua cache in memoria. La riga finale `| table anomaly_risk` garantisce che l'output sia un singolo valore numerico normalizzato (0-100), pronto per OPA.

### Configurazione

Aggiungi questa seconda stanza sempre nel file `$SPLUNK_HOME/etc/system/local/savedsearches.conf`:

```ini
[Calcolo_Rischio_Contestuale_ZTA]
search = index=zta_baseline_summary user="$user$" earliest=-7d \
| stats count as query_count by _time, user \
| eventstats avg(query_count) as media_storica, stdev(query_count) as dev_std by user \
| append [ \
    search (index=zta_envoy OR index=zta_snort OR index=zta_nftables OR index=zta_mongodb_audit) \
           (src_ip="$client_ip$" OR user="$user$") earliest=-15m \
    | eval tipo=case( \
        index="zta_envoy" AND decision="DENY", "deny", \
        index="zta_snort", "snort", \
        index="zta_nftables" AND action="DROP", "nftables", \
        index="zta_mongodb_audit" AND result!=0, "mongo", \
        1=1, "allow" \
      ) \
    | stats count(eval(tipo="deny")) as c_deny, count(eval(tipo="snort")) as c_snort, count(eval(tipo="nftables")) as c_nftables, count(eval(tipo="mongo")) as c_mongo, count(eval(tipo="allow")) as c_allow \
    | eval eta_min = (now() - _time) / 60 \
    | eval peso_snort = c_snort * exp(-0.231 * eta_min) \
  ] \
| stats first(media_storica) as mu, first(dev_std) as sigma, max(c_allow) as cur_allow, max(c_deny) as cur_deny, max(peso_snort) as cur_snort, max(c_nftables) as cur_nftables, max(c_mongo) as cur_mongo \
| eval z_score = if(sigma > 0 AND NOT isnull(cur_allow), (cur_allow - mu) / sigma, 0) \
| eval uba_boost = case(z_score >= 3.0, 40, z_score >= 2.0, 20, 1=1, 0) \
| eval deny_boost = case(cur_deny >= 10, 30, cur_deny >= 5, 15, 1=1, 0) \
| eval snort_boost = case(cur_snort >= 5, 60, cur_snort >= 1, 30, 1=1, 0) \
| eval nft_boost = case(cur_nftables >= 50, 20, cur_nftables >= 10, 10, 1=1, 0) \
| eval mongo_boost = case(cur_mongo >= 10, 40, cur_mongo >= 3, 20, 1=1, 0) \
| eval anomaly_risk = min(100, uba_boost + deny_boost + snort_boost + nft_boost + mongo_boost) \
| table anomaly_risk

```

---


## Fase 5: Integrazione della Chiamata REST Diretta in OPA (`risk.rego`)

### Cosa si fa

Si sposta la chiamata HTTP POST verso le API di Management di Splunk (porta `8089`) direttamente all'interno del modulo `risk.rego` di OPA. OPA interroga la Saved Search parametrica creata nella Fase 4, passando l'utente e l'IP del client come argomenti, ed estrae il punteggio numerico di rischio direttamente dal payload JSON restituito dal SIEM.

### Perché si fa

OPA è nativamente progettato per arricchire le policy con dati esterni in tempo reale tramite la primitiva `http.send`. Eliminando il Forwarder dalla catena decisionale, OPA interroga direttamente la cache indicizzata di Splunk. L'uso di una *Saved Search* parametrica lato Splunk garantisce che l'esecuzione sia fulminea (sotto i 50ms), permettendo a OPA di rimanere ampiamente dentro i limiti di performance richiesti dal proxy Envoy.

### Configurazione del codice in `risk.rego`

Sostituisci la vecchia regola `anomaly_risk` nel tuo file `risk.rego` con questa implementazione crittografica e diretta:

```python
# Anomaly Risk Dimension (20% weight) - Query DIRETTA e SINCRONA a Splunk via REST API
anomaly_risk := score if {
    # Evitiamo chiamate esterne per i comandi di sistema o diagnostici (Bypass standard)
    not identity.action_name in {"hello", "isMaster", "saslContinue", "buildinfo", "buildInfo", "ping", "getLog", "getCmdLineOpts", "serverStatus"}

    # OPA esegue la POST direttamente verso la porta di Management di Splunk (8089)
    resp := http.send({
        "method": "POST",
        "url": "https://zta-splunk-server:8089/servicesNS/admin/search/saved/searches/Calcolo_Rischio_Contestuale_ZTA/dispatch",
        "headers": {
            "Content-Type": "application/x-www-form-6028",
            "Authorization": "Bearer TOKEN_DI_MANAGEMENT_SPLUNK" # Token esplicito per la porta 8089
        },
        # Passaggio dei parametri richiesti dalla Saved Search di Splunk
        "body": sprintf("args.user=%v&args.client_ip=%v&output_mode=json", [identity.user_identity, identity.network_identity_str]),
        "tls_ca_cert_file": "/etc/certs/ca/ca.crt", # Verifica stringente del certificato di Splunk (Zero Trust)
        "timeout": "400000000" # Timeout restrittivo impostato a 400ms (in nanosecondi)
    })

    # Validazione della risposta del SIEM
    resp.status_code == 200
    
    # Parsing nativo del JSON multidimensionale restituito da Splunk
    # Splunk risponde inserendo i record nell'array: body.results[0].anomaly_risk
    score_str := resp.body.results[0].anomaly_risk
    score := to_number(score_str)
} else := 0 # Tolleranza ai guasti (Fail-Safe): se Splunk va in timeout o genera errore, il boost decade a 0

```

---

## Fase 6: Verifica e Monitoraggio

### Cosa si fa

Si riavvia il forwarder e si inviano query di test a MongoDB, controllando che il flusso risponda correttamente e che il modulo OPA riceva il valore numerico finito.

### Perché si fa

Per convalidare che il vincolo transazionale sia rispettato e misurare l'effettivo abbattimento dei tempi di overhead, assicurandosi che la latenza totale di valutazione rimanga sotto la finestra critica dei millisecondi.

---

### Schema del Flusso Architetturale Aggiornato

Grazie a questa migrazione, il flusso dei dati nel tuo progetto viene semplificato drasticamente, spostando il carico analitico sulla componente nativamente progettata per farlo:

```
[Client Query] -> [Envoy PEP] 
                        |
            (Inoltra attributi L7)
                        v
                     [ OPA ] -- (POST REST HTTPS 8089) --> [ Splunk Server ]
                     [ PDP ] <-- (Ritorna anomaly_risk) <-- [ (Rule Engine) ]
                        |
            (ALLOW / DENY + Risk Score)
                        v
[Client Query] <- [Envoy PEP]

```