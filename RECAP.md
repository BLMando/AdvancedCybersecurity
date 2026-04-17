# Recap delle prime due fasi

## Obiettivo del progetto

L'obiettivo e costruire una Zero Trust Architecture containerizzata in cui ogni accesso a MongoDB passa da una catena di controllo precisa: identita del client, valutazione di policy, ispezione del traffico e difesa di rete.

## Fase 0 - Setup infrastruttura

Questa fase prepara il terreno. Senza di lei non esiste un ambiente coerente da proteggere.

### Cosa e stato fatto

- Definita la topologia Docker con MongoDB, Envoy, OPA, Snort e NFTables in [docker-compose.yml](docker-compose.yml).
- Separati i ruoli dei componenti: MongoDB come risorsa, Envoy come punto di ingresso, OPA come motore decisionale, Snort e NFTables come difese di rete.
- Creati i file di configurazione iniziali per [nftables/nftables.conf](nftables/nftables.conf) e [snort/snort.lua](snort/snort.lua).
- Organizzata la configurazione condivisa in [.env](.env).
- Predisposta la struttura per certificati, script e policy.

### Perche questa fase conta

- Definisce i confini di fiducia tra rete esterna, proxy e database.
- Impedisce al client di raggiungere direttamente MongoDB.
- Prepara i punti dove poi si innestano mTLS, policy e ispezione del traffico.

### Riferimenti al codice

- Servizi e reti: [docker-compose.yml](docker-compose.yml)
- Firewall L3/L4: [nftables/nftables.conf](nftables/nftables.conf)
- IDS di rete: [snort/snort.lua](snort/snort.lua)
- Variabili condivise: [.env](.env)

## Fase 1 - Identification layer

Questa e la fase piu importante per capire il progetto. Qui il sistema inizia a sapere chi sta parlando, da dove parla e con quale dispositivo.

### Cosa e stato fatto

- Configurato Envoy con mTLS obbligatorio in [envoy/envoy.yaml](envoy/envoy.yaml).
- Creati gli script per i certificati in [scripts/generate-certs.sh](scripts/generate-certs.sh).
- Implementata l'estrazione dell'identita tramite filtro Lua in [envoy/envoy.yaml](envoy/envoy.yaml).
- Attivato `mongo_proxy` per leggere il traffico MongoDB e produrre log strutturati.
- Estesa la policy OPA con rischio basato su utente, device e rete in [opa/policies/authz.rego](opa/policies/authz.rego).
- Creati gli script di test in [scripts/test-identification.sh](scripts/test-identification.sh), [scripts/test-mongo-access.sh](scripts/test-mongo-access.sh) e [scripts/demo.sh](scripts/demo.sh).

### Come leggere la fase 1

1. Il client si presenta con un certificato.
2. Envoy verifica il certificato e ricava il Common Name, che diventa l'utente.
3. Lo stesso Envoy prova a dedurre il device con JA3 o OID.
4. L'IP sorgente identifica la rete di provenienza.
5. Questi dati vengono passati alla decisione di policy.
6. OPA assegna un rischio e decide allow o deny.

### Riferimenti al codice

- mTLS, Lua, mongo_proxy e cluster: [envoy/envoy.yaml](envoy/envoy.yaml)
- Risk scoring e regole decisionali: [opa/policies/authz.rego](opa/policies/authz.rego)
- Generazione certificati: [scripts/generate-certs.sh](scripts/generate-certs.sh)
- Verifica identita: [scripts/test-identification.sh](scripts/test-identification.sh)
- Verifica accesso end-to-end: [scripts/test-mongo-access.sh](scripts/test-mongo-access.sh)
- Demo automatica: [scripts/demo.sh](scripts/demo.sh)

## Mappa mentale dei componenti

### 1. Envoy come punto di ingresso

Envoy e il primo filtro reale del sistema. Non si limita a inoltrare traffico: termina TLS, verifica il certificato, estrae identita e invia le richieste a OPA per l'autorizzazione.

Nel codice questo si vede in [envoy/envoy.yaml](envoy/envoy.yaml):

- `tls_inspector` per leggere informazioni del handshake TLS.
- `DownstreamTlsContext` per imporre mTLS.
- filtro Lua per costruire `zta.identity`.
- `mongo_proxy` per leggere i comandi MongoDB.
- `ext_authz` per chiamare OPA.

### 2. OPA come motore di decisione

OPA non esegue logica applicativa generica. Calcola un punteggio di rischio e decide se una richiesta deve passare o no.

Nel codice questo si vede in [opa/policies/authz.rego](opa/policies/authz.rego):

- `user_risk`, `device_risk`, `network_risk`.
- `threshold` diverso per ogni comando.
- `allow` come decisione finale.

### 3. Gli script come strato operativo

Gli script servono a non fare tutto a mano: generano certificati, testano il layer di identificazione e simulano il comportamento atteso.

Nel codice questo si vede in:

- [scripts/generate-certs.sh](scripts/generate-certs.sh)
- [scripts/test-identification.sh](scripts/test-identification.sh)
- [scripts/test-mongo-access.sh](scripts/test-mongo-access.sh)
- [scripts/demo.sh](scripts/demo.sh)

## Come interpretare il flusso end-to-end

Il flusso corretto, in termini semplici, e questo:

1. Il client si connette a Envoy con certificato.
2. Envoy identifica utente, device e rete.
3. Envoy inoltra il contesto a OPA.
4. OPA valuta il rischio in [opa/policies/authz.rego](opa/policies/authz.rego).
5. Se la soglia e superata, la richiesta viene bloccata.
6. Se la policy consente, la richiesta arriva a MongoDB.

## Cosa significa in pratica per le prime due fasi

- La Fase 0 crea l'ambiente e separa i domini di rete.
- La Fase 1 trasforma un accesso anonimo in un accesso valutato e tracciato.
- Il risultato e che il sistema non ragiona piu solo su porta aperta o porta chiusa, ma su identita e rischio.

## Come studiare il codice senza perderti

- Parti da [docker-compose.yml](docker-compose.yml) per capire quali servizi esistono e come parlano tra loro.
- Poi leggi [envoy/envoy.yaml](envoy/envoy.yaml) per vedere dove entra l'identita.
- Poi apri [opa/policies/authz.rego](opa/policies/authz.rego) per capire come nasce la decisione.
- Infine guarda [scripts/demo.sh](scripts/demo.sh) per vedere l'ordine operativo dei test.

## Stato attuale

Le prime due fasi sono impostate e leggibili come catena completa: infrastruttura, identita, valutazione e prima autorizzazione. Il passo successivo naturale e la **Fase 2**, cioe il livello PEP con enforcement piu profondo e logging piu strutturato.

## Nota

Splunk non e stato incluso in questa fase, come richiesto.
