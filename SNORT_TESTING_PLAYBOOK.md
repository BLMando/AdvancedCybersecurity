# Snort 3 - Security Testing Playbook

Questo playbook raccoglie le procedure pratiche e i comandi per forzare e convalidare il funzionamento di ogni singola regola di sicurezza attiva sulle sonde NIDS di **Snort 3** nel laboratorio.

Tutti i comandi di attacco/simulazione sfruttano le utilità già presenti all'interno dell'infrastruttura (in particolare l'interprete Python in `identity-pki` o le utilità di rete in `nftables`).

---

## 1. Sonda PEP (`pep.rules`) - Sidecar di Envoy

I seguenti comandi testano le regole per la sonda a protezione del proxy di ingresso (Envoy, porta `10000` / `9901`).

| SID | Nome Regola | Tipo Minaccia | Comando di Test (da eseguire in Git Bash / Terminale) |
| :--- | :--- | :--- | :--- |
| **3000001** | Legacy TLS version / SSL downgrade attempt | Downgrade crittografico | `docker compose exec -T identity-pki openssl s_client -connect envoy:10000 -tls1_1` |
| **3000002** | Possible SYN flood DDoS targeting PEP Envoy | Volumetrico / DDoS | `docker compose exec -T identity-pki python -c "import socket; [socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex(('envoy', 10000)) for _ in range(110)]"` |
| **3000004** | Internal lateral movement detected (east-west) | Scansione di rete interna | `docker compose exec -T identity-pki python -c "import socket; [socket.socket().connect_ex(('envoy', port)) for port in range(10000, 10060)]"` |
| **3000005** | Envoy admin access attempt | Policy / Violazione perimetro | `docker compose exec -T identity-pki python -c "import socket; socket.socket().connect_ex(('envoy', 9901))"` |
| **3000006** | TCP SYN port scan targeting PEP | Ricognizione perimetrale | `docker compose exec -T identity-pki python -c "import socket; [socket.socket().connect_ex(('envoy', port)) for port in range(10000, 10025)]"` |
| **3000007** | Suspicious ICMP large payload (exfiltration) | Tunneling / Data Exfiltration | `docker compose exec -T nftables ping -s 150 -c 3 envoy` |

---

## 2. Sonda Risorsa (`resource.rules`) - Sidecar di MongoDB

I seguenti comandi testano le regole per la sonda a protezione diretta del database MongoDB (porta `27017`).

| SID | Nome Regola | Tipo Minaccia | Comando di Test (da eseguire in Git Bash / Terminale) |
| :--- | :--- | :--- | :--- |
| **4000001** | Bulk MongoDB access | Data Exfiltration massiva | `docker compose exec -T identity-pki python -c "import socket; [socket.create_connection(('mongo', 27017)) for _ in range(110)]"` |
| **4000002** | MongoDB TCP connection flood | Saturazione delle connessioni | `docker compose exec -T identity-pki python -c "import socket; [socket.socket().connect_ex(('mongo', 27017)) for _ in range(60)]"` |
| **4000003** | Internal MongoDB port sweep | Ricognizione interna al DB | `docker compose exec -T identity-pki python -c "import socket; [socket.socket().connect_ex(('mongo', 27017)) for _ in range(15)]"` |
| **4000007** | MongoDB access from non-Docker network (PEP bypass) | Bypass del PEP | **Da PowerShell/Cmd su PC Host (Windows):**<br>`Test-NetConnection -ComputerName localhost -Port 27017` |

---

## 3. Verifica dei Log di Snort

Dopo aver eseguito uno dei comandi del playbook, è possibile verificare l'emissione dell'alert stampando le ultime righe del file di log all'interno del container della rispettiva sonda:

### Per la Sonda PEP (Envoy):
```bash
docker compose exec -T snort-pep tail -n 20 /var/log/snort/alert_json.txt
```

### Per la Sonda Risorsa (MongoDB):
```bash
docker compose exec -T snort-resource tail -n 20 /var/log/snort/alert_json.txt
```

I log sono formattati in JSON e verranno immediatamente intercettati dallo *ZTA Log Forwarder* per essere indicizzati su Splunk negli indici `zta_snort`.
