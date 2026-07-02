# Guida alla Riproduzione della Configurazione di Splunk (ZTA App)

Questa guida documenta i passi necessari affinché il team possa riprodurre localmente l'integrazione di Splunk Enterprise come **Rule Engine per il calcolo del rischio di OPA (Open Policy Agent)**.

---

## 1. Struttura dei File dell'App Splunk
Tutta la logica di business e configurazione di Splunk è centralizzata nella cartella `./splunk` (montata come applicazione nativa denominata `zta`). Assicurarsi che la struttura delle cartelle sia la seguente:

```text
splunk/
└── default/
    ├── app.conf              # Metadati dell'app (stato enabled)
    ├── indexes.conf          # Definizione del Summary Index zta_baseline_summary
    ├── props.conf            # Regole di CIM Aliasing (src_addr/ip -> src_ip)
    ├── savedsearches.conf    # Baseline pianificata e Calcolo_Rischio_Contestuale_ZTA
    ├── server.conf           # Associazione certificati CA/Server per la porta 8089
    └── data/
        └── ui/
            └── views/
                └── dashboard.xml   # Dashboard XML per la visualizzazione dei log
```

---

## 2. Configurazione dei Certificati SSL/TLS
I certificati per la connessione sicura sulla porta di management `8089` vengono autogenerati ad ogni avvio dal container `identity-pki` (tramite CA interna) in `./volumes/certs/splunk/`.
Nel `docker-compose.yml`, il container `splunk` monta questi certificati e li unisce all'avvio in un unico bundle PEM:
*   `/opt/splunk/etc/auth/mycerts/server_combined.pem` (unione di `splunk.crt` e `splunk.key`).
*   `/opt/splunk/etc/auth/mycerts/cacert.pem` (copia della CA di progetto).

Questo garantisce che la comunicazione OPA <-> Splunk sia cifrata e verificata crittograficamente (Zero Trust).

## 3. Procedura per Avviare l'Infrastruttura
Grazie alle configurazioni presenti in `default/app.conf` (`state = enabled`, `is_visible = 1`) e in `metadata/default.meta`, l'applicazione viene **automaticamente caricata, abilitata e resa visibile** fin dal primo avvio.

I tuoi colleghi devono semplicemente eseguire:

```bash
docker compose up -d
```

E attendere circa 30-45 secondi per il completamento del boot di Splunk prima di effettuare test o query. Non sono necessari comandi manuali di abilitazione via CLI o riavvii intermedi.


---

## 4. Test e Verifica del Funzionamento REST

Una volta che Splunk è avviato ed è *healthy*, è possibile testare l'endpoint REST utilizzato da OPA inviando una richiesta `POST` con la Saved Search parametrica nel namespace dell'app `zta`:

```bash
curl -k -u admin:SplunkPassword123! \
  -d 'search=| savedsearch Calcolo_Rischio_Contestuale_ZTA user="test.doctor" client_ip="172.19.0.4"' \
  -d 'exec_mode=oneshot' \
  -d 'output_mode=json' \
  https://localhost:8089/servicesNS/admin/zta/search/jobs
```

### Risultato atteso (HTTP 200):
```json
{
  "preview": false,
  "results": [
    {
      "anomaly_risk": "0"
    }
  ]
}
```

---

## 5. Integrazione con OPA (`risk.rego`)
Per garantire il corretto recupero del rischio, accertarsi che il file `risk.rego` interroghi l'URL di Splunk includendo il percorso specifico dell'app `zta`:

```rego
resp := http.send({
    "method": "POST",
    "url": "https://splunk:8089/servicesNS/admin/zta/search/jobs",
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic YWRtaW46U3BsdW5rUGFzc3dvcmQxMjMh" # admin:SplunkPassword123!
    },
    "body": sprintf("search=%%7C+savedsearch+Calcolo_Rischio_Contestuale_ZTA+user%%3D%%22%v%%22+client_ip%%3D%%22%v%%22&exec_mode=oneshot&output_mode=json", [identity.user_identity, identity.network_identity_str]),
    "tls_ca_cert_file": "/etc/certs/ca/ca.crt",
    "timeout": "400000000"
})
```
