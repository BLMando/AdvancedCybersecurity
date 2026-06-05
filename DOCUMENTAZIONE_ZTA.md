# Documentazione ZTA: Integrazione Envoy WAF, OPA PDP e Splunk Trust Registry

Questo documento descrive l'architettura, le modifiche apportate e la razionalità ingegneristica dietro l'implementazione del modello **Hybrid Zero Trust Architecture (ZTA)** basato su Envoy, Open Policy Agent (OPA) e Splunk.

---

## 1. Architettura della Decisione (Perché Asincrona?)

Nel workflow originario, era stato proposto di interrogare Splunk in tempo reale durante il flusso di transito della richiesta. Tale approccio è stato scartato in favore di un **motore di sincronizzazione asincrono in background** per tre motivi fondamentali:

1. **Latenza del Servizio**: OPA valuta le policy locali in memoria in meno di **1 ms**. Una query di ricerca sincrona a Splunk impiegherebbe **tra 500 ms e 2 secondi**, rallentando in modo inaccettabile l'intera applicazione.
2. **Resilienza (Fail-Safe)**: Se Splunk dovesse andare offline per manutenzione o sovraccarico, un sistema sincrono bloccherebbe tutto il traffico (_Fail-Closed_). Con la sincronizzazione asincrona, OPA continua a funzionare istantaneamente usando l'ultimo stato noto salvato in RAM.
3. **Prevenzione del Sovraccarico su Splunk**: Inviare una query di ricerca per ogni singola connessione manderebbe immediatamente in crash lo scheduler delle ricerche di Splunk. Il daemon asincrono effettua **una sola query aggregata ogni 10 secondi**.

---

## 2. Dettaglio delle Modifiche Apportate

L'integrazione è stata potenziata con tre miglioramenti di livello enterprise per proteggere il sistema da falsi positivi (IP dinamici) e attacchi di spoofing.

### 2.1 Estensione della Finestra di Storico a 7 Giorni

- **Modifica**: In [forwarder.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/scripts/opa_splunk_forwarder/forwarder.py), la query a Splunk è stata configurata con una finestra di ricerca di 7 giorni (`earliest=-7d`).
- **Razionalità**: Impedisce il "decadimento" dello storico durante i weekend o i periodi di ferie dell'utente, evitando che il lunedì mattina gli account vengano trattati come "cold-start" (privi di storico) esponendo il sistema a bypass temporanei.

### 2.2 Matching Flessibile per Sotto-rete DHCP (`/24` Prefix)

- **Modifica**: Introdotta in [authz.rego](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/opa/policies/authz.rego) la funzione di utilità `subnet_24` che estrae i primi tre ottetti dell'IP (classe C).
- **Razionalità**: Nelle reti aziendali o domestiche con indirizzamento DHCP, l'IP esatto del client può variare (es. da `.5` a `.6`). Il matching esatto provocherebbe falsi allarmi bloccando le transazioni legittime. Confrontando la sottorete `/24`, il sistema tollera le variazioni all'interno della stessa rete (+0 risk boost), ma continua a bloccare IP provenienti da classi o reti geografiche estranee (+60 risk boost).

### 2.3 Estrazione Crittografica del Dispositivo (Anti-Spoofing)

- **Modifica**: Configurato `device_identity` in [authz.rego](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/opa/policies/authz.rego) per estrarre l'indirizzo MAC del client dall'attributo `OrganizationalUnit` (OU) del certificato mTLS client (es. `OU=MAC:AA-BB-CC-DD-EE-FF`).
- **Razionalità**: Se il sistema si basasse solo sul campo `device` fornito nel payload JSON della richiesta, un attaccante potrebbe facilmente falsificarlo inserendo il nome del computer della vittima. Estraendo il MAC direttamente dal certificato firmato dalla CA e legato crittograficamente al chip TPM del client, l'identità del dispositivo diventa non falsificabile.

---

## 3. Workflow Decisionale Ibrido

Quando arriva una richiesta a Envoy (es. update su database clinico):

1. **Filtro Envoy Lua (L7 WAF)**: Controlla e respinge immediatamente tentativi di NoSQL injection (es. `$where`).
2. **Chiamata gRPC a OPA**: Envoy inoltra i metadati e il certificato client.
3. **OPA PDP Rule Evaluation**:
   - **RBAC rigido**: Verifica che il ruolo dell'utente (es. `doctor`) sia autorizzato sulla collezione (es. `clinical_records`).
   - **Rischio dinamico**: Calcola il punteggio di rischio (Identity, Behavior, Content, Splunk Anomalies) e lo confronta con la soglia del comando (es. 15 per comandi `update`).
     - Se il dispositivo (MAC estratto da Certificato) è sconosciuto per l'utente $\implies$ **+100 risk boost** (Scatta **DENY**).
     - Se il dispositivo è noto, ma l'IP corrente appartiene a una classe `/24` sconosciuta $\implies$ **+60 risk boost** (Scatta **DENY**).
     - Se l'utente non ha alcuno storico (bootstrap iniziale) o se dispositivo e IP sono congrui con la sottorete storica $\implies$ **+0 risk boost**.

---

## 4. Istruzioni per la Validazione dei Test

### Test Unitari OPA

Per verificare la logica offline e le regressioni delle policy, esegui il motore dei test di OPA nel container:

```powershell
docker compose exec opa /opa test /policies -v
```

_Tutti i 28 test (compresi quelli per il parsing del MAC crittografico e il matching DHCP della sottorete) devono restituire `PASS`._

### Test Diagnostico a Runtime

È possibile simulare i diversi scenari di IP fidati, DHCP e dispositivi non autorizzati lanciando lo script diagnostico Python locale:

```powershell
.venv\Scripts\python.exe C:\Users\matti\.gemini\antigravity-cli\brain\5755abe8-1c42-49c5-a642-d0fcb4cc90b0\scratch\test_trust_evaluation.py
```

Lo script inietterà temporaneamente chiavi di prova e valuterà le risposte di OPA stampando in output i punteggi di rischio e le decisioni finali.

# Calcolo rischio

### 1. Il Calcolo del Rischio Totale ( total_risk_score )

Il rischio complessivo è una media ponderata di 4 macro-dimensioni, ciascuna con un peso percentuale specifico:

                     (Identity × 30) + (Behavior × 30) + (Content × 20) + (Anomaly × 20)
    Rischio Totale = ───────────────────────────────────────────────────────────────────
                                                     100

Il punteggio finale viene poi arrotondato all'intero più vicino ( risk_score = round(total_risk_score) ). Ciascuna dimensione è valutata su una scala da 0 a 100:

#### A. Rischio d'Identità ( identity_risk - Peso 30%)

Misura l'affidabilità del soggetto, del dispositivo e del network di provenienza:

    identity\_risk = user\_risk\_val + device\_risk\_val + network\_risk\_val

• User ( user_risk_val ): 0 se l'utente è censito nel database, 30 se sconosciuto.  
 • Device ( device_risk_val ): 0 se il dispositivo è verificato tramite TPM hardware (non è "no-tpm" ), altrimenti 20 .  
 • Network ( network_risk_val ): 0 se l'IP sorgente appartiene alla sottorete interna autorizzata ( 172.20.0.0/16 , 172.21.0.0/16 , 10.0.0.0/8 ), altrimenti 15 (rete esterna).

#### B. Rischio di Comportamento ( behavior_risk - Peso 30%)

Valuta la pericolosità intrinseca dell'operazione richiesta e del target:

    behavior\_risk = action\_risk\_val + collection\_sensitivity\_val

• Action ( action_risk_val ):  
 • find (lettura): 0  
 • aggregate (aggregazione): 10  
 • insert (creazione): 20  
 • update (modifica): 30  
 • delete (cancellazione): 50  
 • drop / delete_database (distruzione): 100  
 • Sensitivity ( collection_sensitivity_val ): 15 se si accede a collezioni critiche (es. clinical_records o billing ), altrimenti 0 .

#### C. Rischio di Contenuto ( content_risk - Peso 20%)

Controlla la query MongoDB a livello di WAF per rilevare tentativi di estrazione abusiva di dati:

• 100 se si interroga clinical_records senza un filtro preciso per patient_id (previene lo scanning di cartelle altrui).  
 • 100 se si interrogano dati di fatturazione usando operatori JavaScript non sicuri ( where o function ).  
 • 100 se un utente non amministratore fa una ricerca vuota {} sulla collezione patients (previene il dump completo della tabella).  
 • 0 se la query è considerata sicura.

Filtro Lua (Envoy WAF a monte): Effettua un controllo sintattico grezzo. Cerca pattern di iniezione generici (es. la presenza di keyword distruttive come where o function nel JSON) o payload troppo pesanti.  
 • Cosa non sa: Il filtro Lua non conosce l'identità dell'utente, il suo ruolo, né le regole di business dell'applicazione.  
 • Content Risk (OPA a valle): Effettua un controllo semantico sensibile al contesto. Non cerca codice malevolo, ma controlla la legittimità della query in base a chi la sta facendo.  
 • Esempio: Una query vuota ( {} ) è sintatticamente perfetta e sicura per il WAF Lua (che la lascia passare). Tuttavia, se un receptionist esegue {} sulla collezione patients , sta provando a scaricare l'intero database dei pazienti. OPA rileva questo comportamento come un'anomalia di contenuto ad alto rischio e lo blocca.  
 • Altro esempio: Un medico può cercare cartelle cliniche, ma la policy aziendale impone che debba sempre cercare una cartella specifica (deve includere patient_id nella query). Il WAF non può saperlo; OPA sì.

#### D. Rischio di Anomalia ( anomaly_risk - Peso 20%)

Valuta lo scostamento rispetto allo storico ricavato da Splunk nelle ultime 24h/7d:

• 100 se il dispositivo (MAC estratto dal certificato TPM) non è mai stato usato prima da quell'utente.  
 • 60 se il dispositivo è noto, ma si collega da una sotto-rete /24 mai usata prima per quel dispositivo.  
 • 5 / 10 / 20 in base ad anomalie di frequenza volumetrica (se l'utente esegue troppe richieste negli ultimi 15 minuti, es. >50, > 100, > 200).  
 • 0 se non ci sono anomalie o se l'utente non ha storico (fase di apprendimento iniziale/cold start).  
 ──────

### 2. La Soglia Adattiva ( adaptive_threshold )

La decisione finale non si basa su una soglia fissa, ma su una soglia dinamica. Più l'azione è critica o distruttiva per il sistema, più la soglia è bassa e restrittiva:

• Ruolo Admin: La soglia è alzata a 60 per consentire operazioni flessibili agli amministratori, bloccando comunque accessi gravemente compromessi.  
 • Comando find (Lettura): La soglia è 30.  
 • Comando insert (Creazione): La soglia è 20.  
 • Comando update (Modifica): La soglia è 15 (restrittiva).  
 • Comando delete (Cancellazione): La soglia è 10 (estremamente protetta, basta un minimo sospetto per bloccare).  
 • Default: Per tutti gli altri contesti, la soglia è 15.  
 ──────

### 3. La Regola Decisionale di OPA (Enforcement)

La richiesta viene autorizzata ( ALLOW ) se e solo se sono verificate entrambe le condizioni:

    allow if {
        criteria_allow                    # 1. Controlli RBAC rigidi soddisfatti (ruolo autorizzato ad accedere alla collezione)
        risk_score <= adaptive_threshold  # 2. Il rischio calcolato è inferiore o uguale alla soglia adattiva
    }

• Se l'utente cerca di fare una update sensibile da un dispositivo non registrato, il risk boost di 100 nell'anomalia porta il punteggio totale a 34 (ben oltre la soglia di 15) implies DENY.  
 • Se l'utente fa la stessa update dal suo laptop aziendale registrato, l'anomalia è 0 , il rischio totale calcolato è 14 (sotto la soglia di 15) implies ALLOW.
