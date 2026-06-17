Ecco una guida in formato Markdown progettata per un **agente autonomo** (o per documentazione tecnica interna). La guida spiega come implementare i principi di un'architettura **Zero Trust** utilizzando **nftables**, integrando i concetti fondamentali presenti nelle slide del laboratorio con le best practice di sicurezza di rete.

---

```markdown
# Guida Tecnica: Implementazione Zero Trust con Nftables

## 1. Obiettivo dell'Agente
[cite_start]Questo documento descrive come configurare `nftables` (il successore unificato di `iptables`, `ip6tables`, `arptables` ed `ebtables`) [cite: 84, 85] [cite_start]per implementare un'architettura **Zero Trust** all'interno di un host o di un gateway di rete[cite: 94, 114]. 

L'approccio Zero Trust si basa sul principio: **"Mai fidarsi, verificare sempre"**. Nessun traffico è considerato sicuro per default, indipendentemente dal fatto che provenga dall'esterno o dall'interno della LAN.

---

## 2. Principi Zero Trust applicati a Nftables

Per mappare la teoria Zero Trust sulle funzionalità di `nftables`, l'agente deve applicare le seguenti regole strutturali:

* [cite_start]**Default Drop (Micro-segmentazione):** Ogni catena di base (`base chain`) deve avere una policy predefinita impostata su `drop`[cite: 94, 309]. [cite_start]Tutto ciò che non è esplicitamente permesso viene bloccato in modo silenzioso[cite: 124, 384].
* [cite_start]**Analisi Multi-livello (Defense in Depth):** Utilizzo combinato delle famiglie di `nftables` per filtrare a livello di collegamento (L2 `bridge`), di rete (L3 ARP/IP) e di trasporto (L4 TCP/UDP)[cite: 106, 271, 286, 303].
* [cite_start]**Controlli di Identità Rigidi:** Limitazione del traffico non solo tramite IP, ma vincolando gli IP a specifici indirizzi MAC (Hardware) per prevenire lo spoofing[cite: 284, 292, 293].
* [cite_start]**Minimo Privilegio e Rate Limiting:** Limitazione rigorosa degli accessi ai soli servizi necessari, applicando politiche di mitigazione DoS/Brute-force direttamente sull'ingresso del pacchetto[cite: 147, 313].

---

## 3. Struttura Gerarchica Zero Trust in Nftables

[cite_start]A differenza dei vecchi strumenti, `nftables` non ha tabelle predefinite[cite: 155]. [cite_start]L'agente organizzerà l'architettura sfruttando la flessibilità del framework gerarchico[cite: 91]:


### Componenti Chiave da Configurare:
1.  [cite_start]**Famiglia `inet` (Consigliata):** Consente di definire regole unificate valide simultaneamente per IPv4 e IPv6, riducendo la superficie di attacco dovuta a disallineamenti di configurazione[cite: 85, 106, 204, 304].
2.  [cite_start]**Famiglia `arp`:** Essenziale in una rete Zero Trust per bloccare attacchi di tipo *ARP Spoofing* e *Man-in-the-Middle* all'interno del segmento locale[cite: 284, 286].
3.  [cite_start]**Famiglia `bridge`:** Per ispezionare il traffico a livello macro (L2/Ethernet) se l'host funge da switch/firewall di segmentazione[cite: 106, 270, 271].

---

## 4. Ricettario di Configurazione (Zero Trust Policy)

Di seguito viene fornito il set di comandi per inizializzare un ambiente blindato.

### Fase 1: Protezione dei Livelli Inferiori (L2 - ARP & MAC)
In ambiente Zero Trust non possiamo fidarci della LAN. [cite_start]Vincoliamo le risposte ARP esclusivamente a coppie IP/MAC legittime ed esplicite[cite: 284, 289]:

```bash
# Inizializzazione tabella ARP
[cite_start]nft add table arp filter_arp [cite: 290]
nft add chain arp filter_arp input { type filter hook input priority 0; [cite_start]} [cite: 291]

# Regola restrittiva: accetta solo l'IP del gateway/host autorizzato accoppiato al suo MAC reale
# Sostituire IP e MAC con i valori reali dell'infrastruttura
[cite_start]nft add rule arp filter_arp input arp saddr ip 192.168.1.100 arp sha 00:aa:bb:cc:dd:ee accept [cite: 292, 293]

# Drop implicito per qualsiasi altra associazione ARP non censita
[cite_start]nft add rule arp filter_arp input drop [cite: 294]

```

Se necessario, bloccare esplicitamente a livello di frame Ethernet i nodi compromessi o non autorizzati:

```bash
[cite_start]nft add table bridge filter_bridge [cite: 275]
nft add chain bridge filter_bridge ingress_check { type filter hook input priority 0; [cite_start]} [cite: 276]
[cite_start]nft add rule bridge filter_bridge ingress_check ether saddr 00:11:22:33:44:55 drop [cite: 277]

```

---

### Fase 2: Configurazione del Firewall di Rete (L3/L4 - Inet)

Inizializziamo una tabella unificata per il controllo degli accessi applicativi.

```bash
# Crea la tabella per il firewall di micro-segmentazione
[cite_start]nft add table inet zero_trust_fw [cite: 308]

# Crea la catena di ingresso con POLICY DROP (Principio Zero Trust fondamentale)
nft add chain inet zero_trust_fw inbound { type filter hook input priority 0; policy drop; [cite_start]} [cite: 309]

```

#### Applicazione delle Regole di Accesso Minimo Privilegio:

1. 
**Gestione dello Stato (Conntrack):** Accetta solo i pacchetti che fanno parte di connessioni già verificate e stabilite dall'interno.


```bash
[cite_start]nft add rule inet zero_trust_fw inbound ct state established, related accept [cite: 311]

```


2. **Accesso Amministrativo (es. SSH) con Protezione da Brute-Force:**
L'accesso ai servizi critici deve essere limitato nel tempo e nella frequenza per mitigare attacchi DoS o tentativi di violazione delle credenziali.


```bash
[cite_start]nft add rule inet zero_trust_fw inbound tcp dport 22 limit rate 10/minute accept [cite: 313]

```


3. **Whitelisting Tramite Named Sets (Segmentazione Dinamica):**
Invece di aprire le porte a intere subnet, usiamo i `Named Sets` per definire in modo dinamico i soli IP che superano la verifica di identità dell'architettura Zero Trust.


```bash
# Definizione del set di nodi verificati/autenticati
nft add set inet zero_trust_fw trusted_agents { type ipv4_addr \; [cite_start]} [cite: 379]

# Popolamento dinamico (es. nodi che hanno superato l'autenticazione mTLS o IAM)
[cite_start]nft add element inet zero_trust_fw trusted_agents { 192.168.1.50, 10.0.0.100 } [cite: 381]

# Regola: Consenti l'accesso ai servizi web (es. 80, 443) solo ai nodi presenti nel set
[cite_start]nft add rule inet zero_trust_fw inbound ip saddr @trusted_agents tcp dport { 80, 443 } accept [cite: 315, 373, 383]

```



---

### Fase 3: Monitoraggio e Auditing Continuo

Una rete Zero Trust richiede visibilità totale. Ogni pacchetto scartato o anomalo deve lasciare una traccia tracciabile tramite verdetti non terminali (`counter` e `log`).

```bash
# Monitora la quantità di traffico scartata e registra l'evento nei log di sistema (syslog/dmesg)
[cite_start]nft add rule inet zero_trust_fw inbound counter log prefix "ZERO_TRUST_DROP: " drop [cite: 124, 145, 146]

```

---

## 5. Controllo dell'Instradamento (Gateway Zero Trust)

Se l'agente sta configurando un dispositivo che agisce da Gateway/Router di rete, l'isolamento dei segmenti (es. DMZ, Database, Utenti) avviene tramite la catena di `forward`.

```bash
# Abilitare il forwarding a livello di Kernel Linux
[cite_start]sudo sysctl -w net.ipv4.ip_forward=1 [cite: 364]

# Creare catena di forward con policy drop
nft add chain inet zero_trust_fw forward { type filter hook forward priority 0; policy drop; }

```

Se è necessario esporre un servizio interno (es. un server di validazione dell'identità), usa il Destination NAT (`DNAT`) in modo condizionale e controllato:

```bash
nft add chain inet zero_trust_fw prerouting { type nat hook prerouting priority dstnat \; [cite_start]} [cite: 349]
[cite_start]nft add rule inet zero_trust_fw prerouting iifname "eth0" tcp dport 443 dnat ip to 192.168.1.10 [cite: 351]

```

---

## 6. Checklist di Verifica per l'Agente

Prima di considerare la configurazione operativa, l'agente deve verificare che:

1. La policy di default di tutte le catene `input` e `forward` sia tassativamente su `drop`.


2. Non siano presenti regole legacy conflittuali (`iptables -L` deve risultare vuoto o disabilitato).


3. Il logging sia attivo per identificare tentativi di movimento laterale non autorizzato nella rete.
