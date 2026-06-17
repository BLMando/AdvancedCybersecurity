# Integrazione NFTables e Snort 3 nell'Architettura Zero Trust

## Decisioni Prese

| Decisione | Scelta |
|-----------|--------|
| Token HEC Splunk | **Singolo** — riusare `SPLUNK_HEC_TOKEN_ENVOY` per tutti i sourcetype |
| Logging nftables | **dmesg -w \| grep** — semplice, adeguato per il lab |
| Interfaccia Snort | **`-i any`** — cattura tutto il traffico (principio ZTA "assume breach") |
| Regole Snort | **Solo custom ZTA** — no community rules (falsi positivi in Docker, meno valore didattico) |

---

## Proposed Changes

### Componente 1: NFTables — Container + Regole Zero Trust

#### [MODIFY] [nftables.conf](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/nftables/nftables.conf)

Riscrittura completa. Ogni regola ha `counter` per le statistiche e `log prefix "NFT_*"` per il forwarding a Splunk:

```nft
#!/usr/bin/nft -f
flush ruleset

table inet zero_trust_fw {

    # ── Named Sets (Micro-segmentazione dinamica) ──
    set blocklist {
        type ipv4_addr
        flags interval, timeout
        timeout 1h
    }

    set trusted_agents {
        type ipv4_addr
        flags interval
        # Popolato dinamicamente via API o script
    }

    # ── INPUT: Default Drop (Principio ZTA fondamentale) ──
    chain input {
        type filter hook input priority 0; policy drop;

        # 1. Blocklist → log + drop immediato
        ip saddr @blocklist counter log prefix "NFT_BLOCKLIST_DROP: " drop

        # 2. Loopback → accept (necessario per funzionamento interno)
        iif lo accept

        # 3. Connessioni stabilite → accept (stateful inspection)
        ct state established,related accept

        # 4. Pacchetti invalidi → log + drop
        ct state invalid counter log prefix "NFT_INVALID_DROP: " drop

        # 5. SSH con rate limiting anti-brute-force
        tcp dport 22 limit rate 10/minute burst 5 packets counter log prefix "NFT_SSH_ACCEPT: " accept
        tcp dport 22 counter log prefix "NFT_SSH_RATE_DROP: " drop

        # 6. Envoy PEP (porta 10000) con rate limiting anti-DDoS
        tcp dport 10000 limit rate 100/second burst 200 packets counter log prefix "NFT_ENVOY_ACCEPT: " accept
        tcp dport 10000 counter log prefix "NFT_ENVOY_RATE_DROP: " drop

        # 7. Envoy HTTP test (porta 10001)
        tcp dport 10001 limit rate 50/second burst 100 packets counter accept

        # 8. Envoy Admin (solo localhost — già filtrato da Docker port binding)
        tcp dport 9901 counter accept

        # 9. BLOCCO accesso diretto MongoDB (bypass del PEP)
        tcp dport 27017 counter log prefix "NFT_MONGO_DIRECT_DROP: " drop

        # 10. OPA API/gRPC (necessario per comunicazione interna)
        tcp dport { 8181, 9002 } counter accept

        # 11. Splunk HEC + UI + Management
        tcp dport { 8000, 8088, 8089, 9997 } counter accept

        # 12. Forwarder API
        tcp dport 5000 counter accept

        # 13. Identity PKI
        tcp dport 8080 counter accept

        # 14. ICMP rate limiting (anti-tunneling/exfiltration)
        icmp type echo-request limit rate 5/second burst 10 packets counter accept
        icmp type echo-request counter log prefix "NFT_ICMP_RATE_DROP: " drop
        icmp type echo-reply accept

        # 15. SYN flood protection globale
        tcp flags syn limit rate 200/second burst 500 packets accept
        tcp flags syn counter log prefix "NFT_SYN_FLOOD_DROP: " drop

        # 16. Default: log + drop tutto il resto
        counter log prefix "NFT_DEFAULT_DROP: " drop
    }

    # ── FORWARD: Traffico inter-container (restrittivo) ──
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Blocklist
        ip saddr @blocklist counter log prefix "NFT_FWD_BLOCKLIST: " drop

        # Connessioni stabilite
        ct state established,related accept
        ct state invalid counter log prefix "NFT_FWD_INVALID: " drop

        # Docker inter-network: frontend-net ↔ backend-net via Envoy
        # Le subnet Docker vengono assegnate dinamicamente; accettare
        # il forwarding solo per le porte dei servizi ZTA
        tcp dport { 10000, 10001, 27017, 8181, 9002, 8088, 5000 } counter accept

        # Log + drop tutto il resto
        counter log prefix "NFT_FWD_DEFAULT_DROP: " drop
    }

    # ── OUTPUT: Egress (monitoraggio) ──
    chain output {
        type filter hook output priority 0; policy accept;

        # Log connessioni in uscita verso IP esterni (non RFC1918)
        # Utile per rilevare C2 callback o data exfiltration
        ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 } \
            counter log prefix "NFT_EGRESS_EXTERNAL: "
    }
}
```

**Differenze rispetto alla versione attuale:**
- `chain forward` ora ha regole esplicite per porta, non più `accept` generico
- Ogni regola ha `counter log prefix` per il tracking su Splunk
- Named set `trusted_agents` per micro-segmentazione
- Rate limiting granulare su SSH, Envoy, ICMP, SYN
- Blocco esplicito MongoDB diretto con logging dedicato
- Monitoraggio egress per rilevare comunicazioni C2

#### [MODIFY] [docker-compose.yml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/docker-compose.yml) — Servizio nftables

```yaml
  nftables:
    image: alpine:latest
    container_name: nftables
    restart: unless-stopped
    entrypoint: [ "/bin/sh", "-c" ]
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN        # Necessario per leggere /proc/kmsg (dmesg)
    network_mode: host
    volumes:
      - ./nftables/nftables.conf:/etc/nftables.conf:ro
      - nftables-logs:/var/log/nftables
    command:
      - |
        apk add --no-cache nftables
        
        # Crea directory log
        mkdir -p /var/log/nftables
        
        # Applica regole nftables
        if [ "$${APPLY_NFT_RULES:-0}" = "1" ]; then
          tr -d '\r' < /etc/nftables.conf > /tmp/nftables.conf
          if nft -f /tmp/nftables.conf; then
            echo "[nftables] Rules applied successfully"
            nft list ruleset
          else
            echo "[nftables] ERROR: Rules failed to apply"
          fi
        else
          echo "[nftables] Safe mode: rules NOT applied (set APPLY_NFT_RULES=1)"
        fi
        
        # Avvia cattura log dal kernel ring buffer
        # I log nftables con prefisso NFT_ vengono scritti su file
        # per il forwarding a Splunk
        echo "[nftables] Starting kernel log capture..."
        cat /proc/kmsg 2>/dev/null | grep --line-buffered "NFT_" > /var/log/nftables/nft.log &
        
        echo "[nftables] Container ready. Logs at /var/log/nftables/nft.log"
        tail -f /dev/null
```

**Cambiamenti:**
- Aggiunta capability `SYS_ADMIN` per lettura `/proc/kmsg`
- Usa `cat /proc/kmsg | grep` per catturare log kernel in background → scrive su file nel volume condiviso
- Volume `nftables-logs` (named) per condivisione con il forwarder
- Logging startup migliorato

---

### Componente 2: Snort 3 — Container + Config + Regole

#### [MODIFY] [snort.lua](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/snort.lua)

Riscrittura completa con tutti i moduli necessari:

```lua
---------------------------------------------------------------------------
-- Snort 3 Configuration — Zero Trust Architecture NIDS
---------------------------------------------------------------------------

-- ─── Network Variables ─────────────────────────────
-- Definizione dei micro-segmenti ZTA
-- Le subnet Docker bridge sono tipicamente in 172.x.0.0/16
HOME_NET = [[ 172.16.0.0/12 10.0.0.0/8 192.168.0.0/16 ]]
EXTERNAL_NET = '!$HOME_NET'

-- ─── Decoder Settings ──────────────────────────────
decode = {
    enable_deep_teredo_inspection = true,
}

-- ─── Active Response ───────────────────────────────
-- IDS mode: solo alert, nessuna risposta attiva
active = { }

-- ─── Stream Inspection (TCP Reassembly) ────────────
-- Essenziale per anti-evasion: riassembla gli stream TCP
-- prima di passarli al detection engine
stream = { }
stream_tcp = {
    policy = 'linux',
    session_timeout = 300,
    max_window = 0,
    overlap_limit = 10,
    max_pdu = 16384,
    reassemble_async = true,
}

-- ─── Protocol Inspectors ──────────────────────────
-- Attivare gli inspector per i protocolli rilevanti
-- nel contesto ZTA (HTTP per la porta test, SSH, ecc.)
http_inspect = { }
ssh = { }
dns = { }
ssl = { }

-- ─── Port Scan Detection ──────────────────────────
-- Rileva tentativi di mappatura della rete interna
port_scan = {
    memcap = 10000000,
    protos = 'all',
    scan_types = 'all',
}

-- ─── Normalizer (Anti-Evasion) ────────────────────
-- Normalizza i pacchetti per impedire tecniche di evasione
-- basate su frammenti, TTL manipulation, overlapping segments
normalizer = {
    tcp = {
        ips = false,    -- IDS mode, non modifica pacchetti
    },
}

-- ─── IPS / Rules Engine ───────────────────────────
ips = {
    enable_builtin_rules = true,
    include = '/etc/snort/rules/local.rules',
    variables = {
        nets = {
            HOME_NET = HOME_NET,
            EXTERNAL_NET = EXTERNAL_NET,
        },
        ports = {
            HTTP_PORTS = '80 443 8000 8080 10001',
            SSH_PORTS = '22',
        },
    },
}

-- ─── Output: Alert JSON ──────────────────────────
-- Output in formato JSON per il parsing automatico
-- da parte del forwarder → Splunk HEC
alert_json = {
    file = true,
    limit = 500,
    fields = 'timestamp msg src_addr src_port dst_addr dst_port proto action gid sid rev priority',
}

-- ─── Performance / Threading ─────────────────────
process = {
    daemon = false,
}

---------------------------------------------------------------------------
print("Snort 3 ZTA configuration loaded successfully")
---------------------------------------------------------------------------
```

**Differenze rispetto alla versione attuale:**
- Aggiunte variabili `HOME_NET` / `EXTERNAL_NET` per mappare la topologia ZTA
- Modulo `ips` con riferimento a `local.rules`
- `port_scan` per rilevamento scansioni di rete
- `normalizer` per anti-evasion TCP
- `stream_tcp` per riassemblaggio stream (DPI)
- Inspector per HTTP, SSH, DNS, SSL
- `alert_json` con campo estesi per Splunk

#### [NEW] [snort/rules/local.rules](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/rules/local.rules)

```
# ═══════════════════════════════════════════════════════════════════
# Snort 3 — Regole Zero Trust Architecture
# ═══════════════════════════════════════════════════════════════════

# ── REGOLA 1: Accesso diretto a MongoDB (bypass del PEP Envoy) ──
# In architettura ZTA, MongoDB (porta 27017) deve essere raggiunto
# SOLO attraverso Envoy. Qualsiasi altro tentativo è una violazione.
alert tcp any any -> any 27017 ( \
    msg:"ZTA-001: Direct MongoDB access attempt - PEP bypass"; \
    flow:to_server,established; \
    classtype:policy-violation; \
    sid:1000001; rev:1; \
)

# ── REGOLA 2: Port Scan Detection ──
# Tentativi di mappatura della rete interna (ricognizione)
alert tcp any any -> $HOME_NET any ( \
    msg:"ZTA-002: TCP SYN port scan detected"; \
    flags:S; \
    threshold:type both, track by_src, count 20, seconds 5; \
    classtype:attempted-recon; \
    sid:1000002; rev:1; \
)

# ── REGOLA 3: NoSQL Injection nel traffico verso Envoy ──
# Rileva tentativi di injection MongoDB ($where, $function)
# nel traffico applicativo che transita verso il PEP
alert tcp any any -> any 10000 ( \
    msg:"ZTA-003: NoSQL injection attempt ($where) in MongoDB traffic"; \
    flow:to_server,established; \
    content:"$where"; nocase; \
    classtype:web-application-attack; \
    sid:1000003; rev:1; \
)

alert tcp any any -> any 10000 ( \
    msg:"ZTA-004: NoSQL injection attempt ($function) in MongoDB traffic"; \
    flow:to_server,established; \
    content:"$function"; nocase; \
    classtype:web-application-attack; \
    sid:1000004; rev:1; \
)

# ── REGOLA 5: ICMP Exfiltration / Tunnel ──
# Pacchetti ICMP con payload anomalo (>100 bytes)
# possono indicare tunneling o esfiltrazione dati
alert icmp any any -> any any ( \
    msg:"ZTA-005: Suspicious ICMP packet with large payload (possible exfiltration)"; \
    dsize:>100; \
    itype:8; \
    classtype:misc-activity; \
    sid:1000005; rev:1; \
)

# ── REGOLA 6: SSH Brute Force ──
# Troppi tentativi SSH in poco tempo
alert tcp any any -> any 22 ( \
    msg:"ZTA-006: SSH brute force attempt detected"; \
    flow:to_server,established; \
    threshold:type both, track by_src, count 5, seconds 60; \
    classtype:attempted-admin; \
    sid:1000006; rev:1; \
)

# ── REGOLA 7: Lateral Movement (scansione interna est-ovest) ──
# Un host interno che tenta di raggiungere molte porte
# su altri host interni indica movimento laterale
alert tcp $HOME_NET any -> $HOME_NET any ( \
    msg:"ZTA-007: Internal lateral movement detected (east-west scan)"; \
    flags:S; \
    threshold:type both, track by_src, count 50, seconds 30; \
    classtype:attempted-recon; \
    sid:1000007; rev:1; \
)

# ── REGOLA 8: DNS Tunneling ──
# Query DNS con dominio molto lungo (possibile canale C2)
alert udp any any -> any 53 ( \
    msg:"ZTA-008: Possible DNS tunneling (long query)"; \
    dsize:>200; \
    classtype:misc-activity; \
    sid:1000008; rev:1; \
)
```

#### [MODIFY] [docker-compose.yml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/docker-compose.yml) — Servizio Snort

```yaml
  snort:
    image: ciscotalos/snort3:latest
    container_name: snort
    restart: unless-stopped
    entrypoint: [ "/bin/sh", "-c" ]
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host
    volumes:
      - ./snort/snort.lua:/etc/snort/snort.lua:ro
      - ./snort/rules:/etc/snort/rules:ro
      - snort-logs:/var/log/snort
    command:
      - |
        echo "[snort] Starting Snort 3 NIDS in IDS mode..."
        echo "[snort] Listening on ALL interfaces (-i any)"
        echo "[snort] Log output: /var/log/snort/alert_json.txt"
        
        mkdir -p /var/log/snort
        
        # Avvia Snort 3 in modalità IDS su tutte le interfacce
        # -i any    → cattura su tutte le interfacce (principio ZTA: visibilità totale)
        # -c        → file di configurazione Lua
        # -l        → directory di output log
        # -A json   → output in formato JSON per Splunk
        # --tweaks  → ottimizzazioni preset
        if ! snort -c /etc/snort/snort.lua -i any -l /var/log/snort 2>&1; then
          echo "[snort] ERROR: Snort failed to start"
          echo "[snort] Container kept alive for debugging"
        fi
        tail -f /dev/null
```

**Cambiamenti rispetto alla versione attuale:**
- `-i any` invece di `-i eth0` (visibilità totale ZTA)
- Rimossa flag `-A alert_json` (ora configurata in `snort.lua`)
- Rimossa flag `--alert-before-pass` (non standard in Snort 3)
- Volume `snort-logs` (named) per condivisione con il forwarder
- Logging di startup migliorato

---

### Componente 3: Forwarder — Tail Snort + nftables

#### [MODIFY] [forwarder.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/scripts/opa_splunk_forwarder/forwarder.py)

Aggiungere queste funzioni (stesso pattern di `tail_envoy_logs`):

**Funzione 1: `tail_snort_logs()`**
```python
SNORT_LOG_PATH = Path("/var/log/snort/alert_json.txt")

def extract_snort_fields(log_entry: dict) -> dict:
    """Estrae i campi rilevanti dal JSON nativo di Snort 3."""
    return {
        "timestamp": log_entry.get("timestamp", ""),
        "msg": log_entry.get("msg", "unknown"),
        "src_addr": log_entry.get("src_addr", "0.0.0.0"),
        "src_port": log_entry.get("src_port", 0),
        "dst_addr": log_entry.get("dst_addr", "0.0.0.0"),
        "dst_port": log_entry.get("dst_port", 0),
        "proto": log_entry.get("proto", "unknown"),
        "action": log_entry.get("action", "alert"),
        "gid": log_entry.get("gid", 1),
        "sid": log_entry.get("sid", 0),
        "rev": log_entry.get("rev", 0),
        "priority": log_entry.get("priority", 0),
    }

def tail_snort_logs(stop_event: threading.Event) -> None:
    """Background thread that tails the Snort 3 alert_json log file."""
    logger.info("Snort log tailer started, watching: %s", SNORT_LOG_PATH)
    last_position = 0

    while not stop_event.is_set():
        try:
            if SNORT_LOG_PATH.exists():
                current_size = SNORT_LOG_PATH.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    with open(SNORT_LOG_PATH, "r") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                log_entry = json.loads(line)
                                fields = extract_snort_fields(log_entry)
                                hec_envoy.send_event(
                                    fields,
                                    index="zta_snort",
                                    sourcetype="snort:alert_json",
                                )
                            except json.JSONDecodeError:
                                logger.warning("Skipping invalid JSON from Snort log")
                        last_position = f.tell()
                    hec_envoy.flush()
        except Exception as e:
            logger.error("Error tailing Snort log: %s", e)
        stop_event.wait(timeout=2.0)
```

**Funzione 2: `tail_nftables_logs()`**
```python
import re

NFTABLES_LOG_PATH = Path("/var/log/nftables/nft.log")

# Regex per parsare i log del kernel nftables
# Formato: <N>NFT_DROP: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8
#          LEN=52 ... PROTO=TCP SPT=12345 DPT=27017 ...
NFT_LOG_PATTERN = re.compile(
    r"(NFT_\w+):\s+"
    r".*?IN=(\S*)\s+"
    r".*?SRC=(\S+)\s+"
    r".*?DST=(\S+)\s+"
    r".*?PROTO=(\S+)\s*"
    r"(?:.*?SPT=(\d+))?\s*"
    r"(?:.*?DPT=(\d+))?"
)

def parse_nftables_line(line: str) -> dict | None:
    """Parsa una riga di log kernel nftables in campi strutturati."""
    match = NFT_LOG_PATTERN.search(line)
    if not match:
        return None
    prefix = match.group(1)  # es. NFT_DROP, NFT_SSH_ACCEPT
    action = "DROP" if "DROP" in prefix else "ACCEPT" if "ACCEPT" in prefix else prefix
    return {
        "prefix": prefix,
        "action": action,
        "in_iface": match.group(2) or "",
        "src_ip": match.group(3) or "0.0.0.0",
        "dst_ip": match.group(4) or "0.0.0.0",
        "proto": match.group(5) or "unknown",
        "src_port": int(match.group(6)) if match.group(6) else 0,
        "dst_port": int(match.group(7)) if match.group(7) else 0,
    }

def tail_nftables_logs(stop_event: threading.Event) -> None:
    """Background thread that tails nftables kernel log output."""
    logger.info("nftables log tailer started, watching: %s", NFTABLES_LOG_PATH)
    last_position = 0

    while not stop_event.is_set():
        try:
            if NFTABLES_LOG_PATH.exists():
                current_size = NFTABLES_LOG_PATH.stat().st_size
                if current_size < last_position:
                    last_position = 0
                if current_size > last_position:
                    with open(NFTABLES_LOG_PATH, "r") as f:
                        f.seek(last_position)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            fields = parse_nftables_line(line)
                            if fields:
                                hec_envoy.send_event(
                                    fields,
                                    index="zta_nftables",
                                    sourcetype="nftables:log",
                                )
                        last_position = f.tell()
                    hec_envoy.flush()
        except Exception as e:
            logger.error("Error tailing nftables log: %s", e)
        stop_event.wait(timeout=2.0)
```

**Modifica a `_ensure_tailer()`**: aggiungere i due nuovi thread:
```python
def _ensure_tailer():
    try:
        _TAILER_LOCK.touch(exist_ok=False)
        # Thread esistente: Envoy logs
        threading.Thread(target=tail_envoy_logs, args=(_stop_event,), daemon=True).start()
        # Thread esistente: Splunk ↔ OPA sync
        threading.Thread(target=sync_splunk_to_opa, args=(_stop_event,), daemon=True).start()
        # NUOVO: Snort logs
        threading.Thread(target=tail_snort_logs, args=(_stop_event,), daemon=True).start()
        logger.info("Snort log tailer started")
        # NUOVO: nftables logs
        threading.Thread(target=tail_nftables_logs, args=(_stop_event,), daemon=True).start()
        logger.info("nftables log tailer started")
    except FileExistsError:
        pass
```

#### [MODIFY] [docker-compose.yml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/docker-compose.yml) — Forwarder

Aggiungere i nuovi volumi read-only:
```yaml
  opa-splunk-forwarder:
    # ... existing config ...
    volumes:
      - envoy-logs:/var/log/envoy:ro
      - snort-logs:/var/log/snort:ro          # NUOVO
      - nftables-logs:/var/log/nftables:ro    # NUOVO
```

#### [MODIFY] [docker-compose.yml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/docker-compose.yml) — Volumi

```yaml
volumes:
  splunk-var:
  splunk-etc:
  mongdata:
  envoy-logs:
  snort-logs:        # NUOVO
  nftables-logs:     # NUOVO
```

---

### Componente 4: Splunk — Indici + Dashboard

#### [MODIFY] [scripts/splunk_setup.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/scripts/splunk_setup.py)

Aggiungere la creazione dei due nuovi indici:
```python
# Indici da creare
INDEXES = ["zta_envoy", "zta_snort", "zta_nftables"]
```

#### [MODIFY] [zta_overview.xml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/splunk/dashboards/zta_overview.xml)

Aggiungere 4 nuove row dopo i pannelli esistenti:

```xml
  <!-- ═══ SNORT IDS ALERTS ═══ -->
  <row>
    <panel>
      <title>Snort IDS — Alert Timeline</title>
      <chart>
        <search>
          <query>index=zta_snort sourcetype="snort:alert_json"
            | timechart span=5m count by msg</query>
          <earliest>$timerange.earliest$</earliest>
          <latest>$timerange.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <title>Snort IDS — Top Alerts</title>
      <chart>
        <search>
          <query>index=zta_snort sourcetype="snort:alert_json"
            | top limit=10 msg
            | table msg count percent</query>
          <earliest>$timerange.earliest$</earliest>
          <latest>$timerange.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>

  <!-- ═══ NFTABLES FIREWALL ═══ -->
  <row>
    <panel>
      <title>Firewall — Attività per Azione</title>
      <chart>
        <search>
          <query>index=zta_nftables sourcetype="nftables:log"
            | timechart span=5m count by action</query>
          <earliest>$timerange.earliest$</earliest>
          <latest>$timerange.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    <panel>
      <title>Firewall — Top IP Bloccati</title>
      <chart>
        <search>
          <query>index=zta_nftables sourcetype="nftables:log" action="DROP"
            | top limit=10 src_ip
            | table src_ip count percent</query>
          <earliest>$timerange.earliest$</earliest>
          <latest>$timerange.latest$</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>

  <!-- ═══ CORRELAZIONE CROSS-INDEX ═══ -->
  <row>
    <panel>
      <title>Correlazione Snort Alert + OPA Deny (stesso IP)</title>
      <table>
        <search>
          <query>index=zta_snort OR index=zta_envoy
            | eval src=coalesce(src_addr, source_ip)
            | eval event_type=if(index="zta_snort", "SNORT: ".msg, "OPA: ".decision)
            | where index="zta_snort" OR decision="DENY"
            | stats count by src event_type
            | sort -count
            | head 20</query>
          <earliest>$timerange.earliest$</earliest>
          <latest>$timerange.latest$</latest>
        </search>
        <option name="wrap">false</option>
        <option name="rowNumbers">true</option>
      </table>
    </panel>
  </row>
```

---

## Riepilogo File Modificati

| File | Azione | Descrizione |
|------|--------|-------------|
| [nftables.conf](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/nftables/nftables.conf) | MODIFY | Riscrittura regole Zero Trust + logging strutturato |
| [snort.lua](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/snort.lua) | MODIFY | Config completa: HOME_NET, ips, inspectors, alert_json |
| [local.rules](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/snort/rules/local.rules) | NEW | 8 regole IDS custom per scenari ZTA |
| [docker-compose.yml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/docker-compose.yml) | MODIFY | Container snort/nftables rivisti, volumi condivisi |
| [forwarder.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/scripts/opa_splunk_forwarder/forwarder.py) | MODIFY | +tail_snort_logs(), +tail_nftables_logs() |
| [zta_overview.xml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/splunk/dashboards/zta_overview.xml) | MODIFY | +4 pannelli: Snort alerts, nftables, correlazione |
| [splunk_setup.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/scripts/splunk_setup.py) | MODIFY | +indici zta_snort, zta_nftables |

---

## Verification Plan

### Automated Tests

```powershell
# 1. Verificare caricamento regole nftables
docker compose exec nftables nft list ruleset

# 2. Verificare Snort avvio con regole
docker logs snort --tail 30

# 3. Verificare indici Splunk
curl -k -u admin:SplunkPassword123! "https://localhost:8089/services/data/indexes?output_mode=json"

# 4. Verificare forwarder (3 tailer attivi)
docker logs opa-splunk-forwarder --tail 50

# 5. Test: port scan → Snort alert
# nmap -sS localhost  (da altra shell)
# Poi: index=zta_snort msg="*port scan*" in Splunk

# 6. Test: accesso diretto MongoDB → nftables DROP
# nc -zv localhost 27017
# Poi: index=zta_nftables prefix="NFT_MONGO_DIRECT_DROP"
```
