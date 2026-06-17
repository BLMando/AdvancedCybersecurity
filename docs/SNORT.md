# Network Intrusion Detection System (NIDS) con Snort 3

Questa sezione descrive la configurazione e le regole di **Snort 3** utilizzato come sonda NIDS (Network Intrusion Detection System) per monitorare e rilevare minacce in tempo reale all'interno dell'architettura Zero Trust.

## 1. Architettura di Deployment Multi-Sonda

Per garantire una visibilità completa sul traffico di rete senza compromettere l'isolamento dei container, Snort 3 è configurato con due distinte sonde indipendenti implementate in modalità sidecar:

```
[Client] ──> [Sonda Snort PEP] ──> [Envoy PEP] ──(mTLS/OPA)──> [Sonda Snort Risorsa] ──> [MongoDB]
```

### Sonda 1: `snort-pep` (Sidecar di Envoy)
* **Posizione**: Condivide il namespace di rete con il proxy Envoy (PEP).
* **Visibilità**: Monitora il traffico grezzo in ingresso (pre-autenticazione mTLS e pre-autorizzazione OPA).
* **Scopo**: Rilevare attacchi a livello di rete e tentativi di sfruttamento/exploit prima che vengano elaborati dai sistemi di autenticazione.

### Sonda 2: `snort-resource` (Sidecar di MongoDB)
* **Posizione**: Condivide il namespace di rete con il database MongoDB.
* **Visibilità**: Monitora il traffico post-autenticazione (post-mTLS, post-OPA).
* **Scopo**: Rilevare comportamenti anomali o comandi dannosi eseguiti da client già autenticati e autorizzati (es. anomalie comportamentali, tentativi di abuso di privilegi o exfiltration).

---

## 2. Analisi delle Regole di Rilevamento (Rulesets)

Ciascuna sonda ha un file di regole specifico ottimizzato per la sua posizione nella rete:

### A. Regole Sonda PEP (`pep.rules`)
Il file [pep.rules](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/snort/rules/pep.rules) si concentra sul traffico non autenticato diretto al PEP (porta 10000) ed Envoy Admin (porta 9901):

1. **Rilevamento NoSQL Injection (MongoDB over HTTP/gRPC)**:
   * **ZTA-PEP-001/002**: Identifica tentativi di injection NoSQL nei payload inviati alla porta `10000` contenenti parole chiave sensibili come `$where` e `$function`.
   * **ZTA-PEP-003**: Rileva l'uso dell'operatore `$regex` per prevenire attacchi di tipo ReDoS (Regular Expression Denial of Service) che potrebbero mandare in crash Envoy o MongoDB.
2. **Movimento Laterale (Scansione Est-Ovest)**:
   * **ZTA-PEP-004**: Monitora se un container interno tenta di effettuare una scansione su porte multiple di altri host interni, rilevando tentativi di ricognizione da container compromessi.
3. **Accesso Amministrativo Non Autorizzato**:
   * **ZTA-PEP-005**: Rileva tentativi di connessione alla porta di amministrazione di Envoy (`9901`) provenienti da host esterni al localhost.
4. **Scansioni di Porta (Port Scanning)**:
   * **ZTA-PEP-006**: Monitora tentativi di port scanning di tipo TCP SYN diretti al PEP.

### B. Regole Sonda Risorsa (`resource.rules`)
Il file [resource.rules](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/snort/rules/resource.rules) protegge direttamente MongoDB (porta `27017`):

1. **Rilevamento Exfiltration (Bulk Read)**:
   * **ZTA-RES-001**: Monitora anomalie nei volumi di lettura, generando un alert se lo stesso IP effettua più di 100 connessioni a MongoDB in 10 secondi (possibile copia/dump di database).
2. **Comandi Amministrativi Distruttivi**:
   * **ZTA-RES-002/003/005**: Rileva comandi amministrativi impartiti a MongoDB come `dropDatabase`, `shutdown` o `dropUser`.
   * **ZTA-RES-004**: Blocca l'accesso alla collection di sistema `system.users` per prevenire la lettura degli hash delle password.
3. **Privilege Escalation**:
   * **ZTA-RES-006**: Monitora comandi di creazione utente (`createUser`) che potrebbero indicare una compromissione con scalata di privilegi.
4. **Bypass del PEP (Violazione dell'Architettura)**:
   * **ZTA-RES-007**: **Critico**. Qualsiasi tentativo di accesso a MongoDB (porta 27017) che NON provenga dal range di indirizzi IP Docker riservato a Envoy (ovvero al di fuori di `172.16.0.0/12`) viene segnalato come tentativo di bypass dell'agente PEP.

---

## 3. Integrazione con lo Stack SIEM (Splunk) e OPA

Snort è parte integrante del sistema di Threat Intelligence della nostra ZTA:

```
[Sonde Snort 3] ──> alert_json.txt ──> [forwarder.py] ──> [Splunk HEC]
                                                               │
[OPA (Decide Accesso)] <─── [forwarder.py (Pushes IP Alerts)] <┘
```

1. **Output in Formato Strutturato**: Le sonde Snort 3 sono configurate per generare alert in formato JSON nel file `/var/log/snort/alert_json.txt` (vedi [snort.lua](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/snort/snort.lua)).
2. **Parser e Forwarder**: Il daemon [forwarder.py](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/opa_splunk_forwarder/forwarder.py) legge in tempo reale le nuove entry del file log, le normalizza ed esegue l'upload tramite Splunk HEC su indice `zta_snort` con sourcetype `snort:alert_json`.
3. **Dynamic Risk Engine**:
   * Periodicamente, il forwarder interroga Splunk per calcolare il numero di alert recenti per ciascun IP sorgente.
   * Gli IP sospetti vengono inviati all'endpoint `/v1/data/splunk/snort_alerts` di **OPA**.
   * Le policy di OPA (es. [risk.rego](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/opa/policies/risk.rego)) applicano un incremento di rischio in base alla gravità degli alert Snort (es. un tentativo di bypass o un drop database genera un boost immediato di 100, con conseguente diniego di qualsiasi richiesta futura).
