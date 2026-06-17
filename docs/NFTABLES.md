# Micro-segmentazione e Controllo degli Accessi L3/L4 con nftables

Questa sezione descrive la configurazione del firewall di rete **nftables** utilizzato come difesa di micro-segmentazione all'interno dell'architettura Zero Trust (ZTA).

## 1. Architettura di Rete e Deployment

Il firewall **nftables** è implementato come container sidecar all'interno della stessa rete e namespace del proxy **Envoy (PEP)**. Questo isolamento garantisce che tutto il traffico in ingresso e in uscita dal perimetro di attendibilità sia sottoposto a rigidi controlli a livello di trasporto e di rete (L3/L4) prima di raggiungere i controlli a livello applicativo (L7) gestiti da Envoy e OPA.

### Flusso del Traffico
1. Il client effettua la connessione verso il PEP.
2. **nftables** intercetta il pacchetto nel namespace di rete di Envoy.
3. Se conforme alle regole, il traffico viene accettato e passa a Envoy.
4. Envoy esegue la validazione mTLS del certificato e consulta OPA.
5. In caso di esito positivo, Envoy inoltra il traffico a MongoDB.

---

## 2. Analisi delle Regole del Firewall (`nftables.conf`)

Il file di configurazione [nftables.conf](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/nftables/nftables.conf) definisce una tabella di tipo `inet` chiamata `zero_trust_fw` con le seguenti catene e politiche:

### Catena INPUT (Policy: DROP)
La catena di ingresso applica una politica di tipo **Default Drop** (nega tutto il traffico non esplicitamente autorizzato) ed esegue i seguenti controlli in ordine:

1. **Protezione da Host Malevoli (Blocklist)**:
   * I pacchetti provenienti da indirizzi IP inseriti nel set dinamico `@blocklist` vengono registrati nei log del kernel con il prefisso `NFT_BLOCKLIST_DROP: ` e immediatamente scartati.
   * Il set `@blocklist` supporta un timeout automatico (default: 1 ora) e viene popolato dinamicamente.

2. **Interfaccia Loopback**:
   * Tutto il traffico sull'interfaccia di loopback (`lo`) è consentito per permettere la comunicazione locale interna al namespace (es. tra i moduli interni di Envoy).

3. **Ispezione Stateful (Connection Tracking)**:
   * Vengono accettati i pacchetti appartenenti a connessioni già stabilite o correlate (`established, related`). Questo include il traffico di risposta dalle connessioni avviate da Envoy verso OPA o MongoDB.
   * I pacchetti con stato `invalid` vengono registrati con il prefisso `NFT_INVALID_DROP: ` e scartati.

4. **Protezione Anti-DDoS e Rate Limiting per il PEP**:
   * Il traffico TCP diretto alla porta di Envoy PEP (`10000`) è limitato a un massimo di **100 pacchetti al secondo** con un burst di **200**.
   * Le connessioni che superano tale soglia vengono registrate come `NFT_ENVOY_RATE_DROP: ` e scartate.
   * La porta di test HTTP (`10001`) ha una limitazione analoga a **50 pacchetti al secondo** (burst 100).
   * L'accesso alla porta di amministrazione di Envoy (`9901`) è consentito localmente.

5. **Protezione SYN Flood**:
   * I pacchetti di sincronizzazione TCP (`flags syn`) sono limitati a **200 pacchetti al secondo** (burst 500) per mitigare attacchi di tipo SYN flood.
   * Il superamento di questo limite genera un log `NFT_SYN_FLOOD: ` e il drop del pacchetto.

6. **Limitazione del Traffico ICMP (Anti-Exfiltration)**:
   * Le richieste di ping (`echo-request`) sono limitate a un massimo di **5 al secondo** (burst 10) per prevenire canali di esfiltrazione o tunneling basati su ICMP.
   * Le risposte ping (`echo-reply`) sono accettate.

### Catena OUTPUT (Policy: ACCEPT)
La catena di uscita monitora ed effettua l'egress filtering:
* Monitora le connessioni in uscita dirette verso indirizzi IP esterni (non appartenenti alle subnet private RFC1918 come `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` o `127.0.0.0/8`).
* Eventuali connessioni anomale verso l'esterno vengono loggate con il prefisso `NFT_EGRESS_EXTERNAL: `, permettendo l'individuazione tempestiva di potenziali callback di Command & Control (C2) o tentativi di esfiltrazione dati.

---

## 3. Integrazione con lo Stack SIEM (Splunk) e OPA

Un aspetto fondamentale di nftables in questa architettura è il suo ruolo attivo nel calcolo del rischio in tempo reale:

```
[nftables (Kernel)] ──> /var/log/nftables/nft.log ──> [forwarder.py] ──> [Splunk HEC]
                                                                             │
[OPA (Decide Accesso)] <─── [forwarder.py (Pushes IP Alerts)] <──────────────┘
```

1. **Raccolta Log**: Il container `nftables` scrive i log di drop e le statistiche dei contatori nel file condiviso `/var/log/nftables/nft.log`.
2. **Inoltro a Splunk**: Il daemon [forwarder.py](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/scripts/opa_splunk_forwarder/forwarder.py) esegue il parsing continuo di questo log, estraendo i campi rilevanti (IP sorgente, porta, azione, interfaccia) e inoltrandoli tramite HTTP Event Collector (HEC) a Splunk nell'indice `zta_nftables` con sourcetype `nftables:log`.
3. **Aggiornamento Dinamico del Rischio (Feedback Loop)**:
   * `forwarder.py` esegue una query periodica (ogni 15 secondi) su Splunk per identificare gli IP che hanno generato drop su nftables negli ultimi 15 minuti.
   * Questi IP e il loro rispettivo fattore di rischio (risk boost) vengono inviati all'endpoint `/v1/data/splunk/nftables_alerts` di **Open Policy Agent (OPA)**.
   * Quando lo stesso IP tenta una richiesta di accesso a MongoDB, le regole di rischio di OPA in [risk.rego](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/opa/policies/risk.rego) rilevano l'incremento di rischio e bloccano dinamicamente la transazione, realizzando un sistema di difesa reattiva e integrata.
