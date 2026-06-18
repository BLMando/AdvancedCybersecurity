# Zero Trust Architecture - Recap Regole Firewall (nftables) e NIDS (Snort 3)

Questo documento fornisce un riepilogo dettagliato delle regole e delle policy di sicurezza implementate a livello di firewall di rete (`nftables`) e a livello di rilevamento intrusioni (`Snort 3`) all'interno dell'infrastruttura Zero Trust per la protezione del database MongoDB.

---

## 1. Regole del Firewall (`nftables`)

Il firewall è configurato per implementare una **micro-segmentazione dinamica** e limitare il traffico diretto verso il Policy Enforcement Point (PEP) di Envoy e le altre risorse interne.

**File di Configurazione:** [nftables.conf](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/nftables/nftables.conf)  
**Tabella principale:** `inet zero_trust_fw`

### Set Dinamici (Micro-segmentazione)
* `blocklist`: Mappa gli indirizzi IP bloccati in seguito a comportamenti anomali rilevati. I record scadono automaticamente dopo **1 ora** (`timeout 1h`).
* `trusted_agents`: Insieme di IP autorizzati popolatili dinamicamente.

### Regole della Catena `input` (Default Policy: DROP)

| ID | Regola / Condizione | Azione | Descrizione |
|:---|:--------------------|:-------|:------------|
| 1 | `ip saddr @blocklist` | **DROP** | Blocca immediatamente i client inseriti nella blocklist dinamica, loggando l'evento con prefisso `NFT_BLOCKLIST_DROP: `. |
| 2 | `iif lo` (loopback) | **ACCEPT** | Consente il traffico locale intra-container. |
| 3 | `ct state established, related` | **ACCEPT** | Stateful inspection: permette il traffico di ritorno per le connessioni già stabilite. |
| 4 | `ct state invalid` | **DROP** | Scarta e logga i pacchetti non validi o corrotti (`NFT_INVALID_DROP: `). |
| 5 | `tcp dport 10000` (Envoy PEP) | **ACCEPT** | Consente il traffico verso la porta di Envoy con rate limiting anti-DDoS: max **100 pkts/sec** con burst a **200**. Logga come `NFT_ENVOY_ACCEPT: `. |
| 6 | `tcp dport 10000` (Eccesso rate-limit) | **DROP** | Scarta e logga il traffico che supera la soglia di rate-limit (`NFT_ENVOY_RATE_DROP: `). |
| 7 | `tcp dport 10001` (Envoy HTTP test) | **ACCEPT** | Consente traffico di test limitato a **50 pkts/sec** (burst 100). |
| 8 | `tcp dport 9901` (Envoy Admin) | **ACCEPT** | Consente l'accesso all'interfaccia amministrativa di Envoy. |
| 9 | `icmp type echo-request` | **ACCEPT** | Consente i pacchetti ping limitandoli a **5/sec** (burst 10) per prevenire attacchi ICMP Flood. |
| 10 | `icmp type echo-request` (Eccesso) | **DROP** | Scarta e logga i ping oltre la soglia (`NFT_ICMP_DROP: `). |
| 11 | `tcp flags syn` | **ACCEPT** | Consente pacchetti SYN per l'apertura TCP limitandoli a **200/sec** (burst 500) per mitigazione SYN Flood. |
| 12 | `tcp flags syn` (Eccesso) | **DROP** | Scarta e logga il traffico SYN eccessivo (`NFT_SYN_FLOOD: `). |
| 13 | *Qualsiasi altra cosa* | **DROP** | Default drop globale loggato con prefisso `NFT_DEFAULT_DROP: `. |

### Regole della Catena `output` (Default Policy: ACCEPT)
* Logga qualsiasi connessione in uscita diretta verso IP esterni (escludendo gli indirizzi privati definiti in RFC1918) con il prefisso `NFT_EGRESS_EXTERNAL: `. Questa regola serve a rilevare tentativi di esfiltrazione dati o connessioni verso server di Command & Control (C2).

---

## 2. Regole di Rilevamento Intrusioni (`Snort 3`)

La rete è monitorata da due sonde Snort distinte per garantire visibilità su entrambi i lati del perimetro di sicurezza (traffico pre-auth e post-auth).

### A. Regole Generali / Rete Complessiva
**File di Configurazione:** [local.rules](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/rules/local.rules)

* **ZTA-001 (Bypass del PEP)**: `alert tcp any any -> any 27017`
  * Rileva qualsiasi tentativo di connessione diretta alla porta `27017` di MongoDB che non passi attraverso Envoy.
* **ZTA-002 (Port Scan)**: Rileva scansioni TCP SYN (20 pacchetti in 5 secondi da uno stesso IP sorgente).
* **ZTA-003 & ZTA-004 (NoSQL Injection L7)**: Rileva stringhe contenenti `$where` o `$function` inviate verso la porta `10000` di Envoy.
* **ZTA-005 (ICMP Tunneling)**: Rileva pacchetti ICMP echo-request con un payload superiore a **100 byte** (potenziale canale di esfiltrazione).
* **ZTA-006 (SSH Brute Force)**: Rileva più di 5 tentativi di connessione SSH (porta 22) in 60 secondi dallo stesso IP.
* **ZTA-007 (Movimento Laterale)**: Rileva tentativi di scansione interna est-ovest (50 pacchetti SYN in 30 secondi tra host della subnet interna `$HOME_NET`).
* **ZTA-008 (DNS Tunneling)**: Rileva query DNS su porta UDP 53 con payload superiore a **200 byte** (potenziale canale C2).

---

### B. Sonda PEP (Envoy Sidecar)
Questa sonda lavora nel namespace di rete condiviso con Envoy e analizza il traffico **post-firewall ma pre-autorizzazione**.
**File di Configurazione:** [pep.rules](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/rules/pep.rules)

* **ZTA-PEP-001 & 002 (NoSQL Injection $where/$function)**: Rileva gli operatori NoSQL nel traffico HTTP/MongoDB destinato alla porta `10000`.
* **ZTA-PEP-003 (ReDoS via Regex)**: Identifica l'uso dell'operatore `$regex` destinato ad Envoy, potenziale vettore di Denial of Service algoritmico (Regex DoS).
* **ZTA-PEP-004 (Movimento Laterale)**: Rileva scansioni est-ovest tra i container Docker.
* **ZTA-PEP-005 (Accesso Admin non autorizzato)**: Rileva tentativi di connessione alla porta amministrativa di Envoy (`9901`) provenienti da IP diversi da localhost.
* **ZTA-PEP-006 (Port Scan verso il PEP)**: Rileva scansioni TCP dirette specificamente verso Envoy.
* **ZTA-PEP-007 (ICMP Tunneling via PEP)**: Rileva ICMP con payload anomalo (>100 byte) transitante per il namespace del PEP.

---

### C. Sonda Risorsa (MongoDB Sidecar)
Lavora nel namespace di rete condiviso con MongoDB. Analizza il traffico che ha già superato le verifiche mTLS di Envoy e le autorizzazioni di OPA. Si concentra su **abusi interni e violazioni delle policy amministrative**.
**File di Configurazione:** [resource.rules](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/rules/resource.rules)

* **ZTA-RES-001 (Bulk Read / Esfiltrazione)**: Genera un allarme se uno stesso client effettua più di 100 connessioni a MongoDB in 10 secondi.
* **ZTA-RES-002 (Drop Database)**: Rileva il comando amministrativo `dropDatabase`.
* **ZTA-RES-003 (Shutdown Database)**: Rileva il comando di spegnimento del database `shutdown`.
* **ZTA-RES-004 (Accesso alle tabelle di sistema)**: Rileva l'accesso diretto alla collezione interna `system.users`.
* **ZTA-RES-005 & 006 (Modifica Utenti / Privilege Escalation)**: Identifica l'esecuzione dei comandi `dropUser` o `createUser`.
* **ZTA-RES-007 (Accesso diretto non Docker - PEP Bypass)**: Allerta se una connessione alla porta `27017` proviene da un indirizzo IP esterno alla subnet Docker standard (`!172.16.0.0/12`).
* **ZTA-RES-008 (Reconfig del Replica Set)**: Allerta su tentativi di riconfigurazione dei nodi di replica tramite `replSetReconfig`.
