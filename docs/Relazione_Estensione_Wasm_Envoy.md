# Relazione Tecnica: Estensione Envoy WebAssembly (Wasm) per la Mediazione Completa L7 su MongoDB

## 1. Introduzione e Contesto di Sicurezza

Nelle architetture tradizionali, il controllo degli accessi e la prevenzione delle vulnerabilità applicative (come la NoSQL Injection) vengono spesso implementati all'interno del codice dell'applicazione stessa (in questo caso, l'applicazione Flask). Tuttavia, questo approccio presenta due gravi vulnerabilità architetturali:
1. **Mancanza di Mediazione Completa (Complete Mediation)**: Un utente o un utente malintenzionato che riesca a compromettere l'applicazione Flask, o a bypassarne l'endpoint, potrebbe inviare query arbitrarie direttamente al database MongoDB senza passare da alcun Policy Enforcement Point (PEP).
2. **Bypass del Payload**: Se l'applicazione esegue un controllo preventivo inviando una query ad OPA e poi, in caso di successo, inoltra la richiesta al database, esiste una finestra temporale (o una discrepanza logica) in cui il payload inviato ad OPA per la verifica differisce da quello effettivamente inviato a MongoDB.

Per soddisfare i requisiti della **Zero Trust Architecture (ZTA)**, la validazione delle query deve essere eseguita in modo trasparente e ininterrompibile a livello di rete (L7) da parte del proxy di front-end (**Envoy Proxy**), agendo come un PEP trasparente posizionato davanti a MongoDB.

Dato che MongoDB utilizza il protocollo di comunicazione wire binario **OP_MSG (opcode 2013)** basato sulla serializzazione **BSON**, i filtri di rete standard non sono in grado di analizzare nativamente la struttura interna delle query. Per risolvere questo problema, è stata sviluppata un'**estensione custom in Rust compilata in WebAssembly (Wasm)** e integrata direttamente nella catena dei filtri di Envoy.

---

## 2. Architettura della Soluzione (Separazione dei Compiti)

L'architettura implementata separa nettamente le responsabilità di trasporto (L4/TLS) da quelle applicative (L7/BSON):

```
  Client (pymongo / Swift Proxy)
       │
       │ (Traffico cifrato TLS)
       ▼
 ┌────────────────────────────────────────────────────────┐
 │ ENVOY PROXY (Porta :10000)                             │
 │                                                        │
 │ 1. TLS/mTLS (DownstreamTlsContext)                     │
 │    - Termina la connessione TLS                        │
 │    - Valida il certificato mTLS del client             │
 │    - Verifica le revoche sulla CRL (ca.crl)            │
 │                                                        │
 │ 2. Decifrazione dei Dati                               │
 │    - Traduce il flusso cifrato in byte in chiaro       │
 │                                                        │
 │ 3. Catena dei Filtri di Rete (Wasm L7 Filter)          │
 │    - Riceve i byte in chiaro                           │
 │    - Estrae CN e MAC dal DN del certificato            │
 │    - Effettua il parsing di MongoDB OP_MSG (BSON)      │
 │                                                        │
 └───────────────────────┬────────────────────────────────┘
                         │
                         │ 4. HTTP POST /allow (JSON)
                         ▼
             ┌───────────────────────┐
             │  OPA (Porta :8181)    │
             │                       │
             │ - Valuta la query     │
             │ - Controllo NoSQLi    │
             │ - Calcola Risk Score  │
             └───────────┬───────────┘
                         │
                         │ 5. Decision (true/false)
                         ▼
 ┌────────────────────────────────────────────────────────┐
 │ ENVOY PROXY (Decision Enforcement)                     │
 │                                                        │
 │   Se ALLOW:                                            │
 │     Forwarding dei byte in chiaro ──▶ MongoDB (:27017) │
 │   Se DENY:                                             │
 │     Interruzione immediata TCP (Fail-Closed)           │
 └────────────────────────────────────────────────────────┘
```

### A. Livello 4 - Envoy Native DownstreamTlsContext
La gestione delle connessioni sicure, della crittografia, della validazione mTLS e della revoca tramite Certificate Revocation List (CRL) rimane delegata ai moduli standard e ottimizzati di Envoy.
Come configurato in [envoy.yaml](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/envoy/envoy.yaml#L38-L59):
* Envoy richiede obbligatoriamente il certificato client (`require_client_certificate: true`).
* Envoy verifica l'autenticità del certificato tramite la CA fidata (`trusted_ca`).
* Envoy controlla in tempo reale che il seriale del certificato non sia presente nella CRL (`ca.crl`).

### B. Livello 7 - MongoDB Wasm Filter (Rust Crate)
L'estensione WebAssembly, caricata dinamicamente come filtro di rete in Envoy ([envoy.yaml:L61-L72](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/envoy/envoy.yaml#L61-L72)), opera sul flusso TCP decifrato. L'estensione non si occupa della crittografia, ma unicamente del parsing dei messaggi e dell'interfacciamento con OPA.

---

## 3. Dettaglio di Implementazione dell'Estensione Rust

Il codice dell'estensione si trova in [lib.rs](file:///Users/paoloroselli/Projects/AdvancedCybersecurity/envoy/wasm/src/lib.rs) ed è strutturato come segue:

### 3.1 Bufferizzazione dello Stream TCP
Poiché il protocollo TCP garantisce la consegna dei dati ma non preserva i confini dei messaggi applicativi, l'estensione accumula i byte in arrivo all'interno di un buffer persistente associato alla sessione (`MongoAuthzStream`):
```rust
struct MongoAuthzStream {
    context_id: u32,
    buffer: Vec<u8>,
    is_authorized: bool,
    opa_token: Option<u32>,
}
```
All'arrivo di nuovi dati downstream, il filtro legge l'header (primi 4 byte) per determinare la lunghezza totale (`msg_len`) del pacchetto MongoDB. Se il buffer contiene byte insufficienti, il filtro restituisce `Action::Pause` per attendere i successivi frammenti TCP.

### 3.2 Parsing del Protocollo MongoDB OP_MSG
Una volta ottenuto l'intero pacchetto MongoDB, l'estensione verifica che l'opcode sia `2013` (corrispondente al moderno protocollo `OP_MSG` introdotto in MongoDB 3.6 e utilizzato da tutti i driver recenti):
```rust
fn parse_op_msg(packet: &[u8]) -> Option<(String, String, serde_json::Value)> {
    // Opcode si trova ai byte 12..16 dell'header
    let opcode = i32::from_le_bytes(packet[12..16].try_into().ok()?);
    if opcode != 2013 { return None; }
    
    // Il payload BSON di Sezione 0 inizia all'offset 21
    let bson_data = &packet[21..];
    let mut cursor = std::io::Cursor::new(bson_data);
    let doc = bson::Document::from_reader(&mut cursor).ok()?;
    
    // Il primo elemento della mappa BSON indica il comando eseguito (find, update, insert, ecc.)
    let cmd_name = doc.keys().next()?.clone();
    ...
}
```
L'estensione deserializza il BSON utilizzando la crate `bson`, mappa il documento in JSON (tramite la funzione `bson_to_json`) ed estrae:
* **Comando**: es. `"find"`, `"update"`, `"delete"`.
* **Collezione fisica**: es. `"clinical_records"`.
* **Filtro di ricerca / Payload della query**: Il sotto-documento contenente i criteri di selezione (`filter` per find, `updates` per update, `deletes` per delete).

### 3.3 Estrazione dell'Identità Client (mTLS Metadata)
Per associare la query MongoDB all'identità reale dell'operatore, l'estensione interroga le proprietà TLS fornite dall'host Envoy relative alla connessione corrente:
```rust
let subject_peer_cert = self.get_property(vec!["connection", "subject_peer_certificate"])
    .map(|b| String::from_utf8_lossy(&b).to_string())
    .unwrap_or_default();
```
La funzione `parse_subject_dn` analizza la stringa del Subject Distinguished Name (DN) del certificato per estrarre:
* Il **Common Name (CN)**: corrispondente all'identificativo utente (es. `paolo.roselli`).
* L'**Organizational Unit (OU) o MAC address**: contenente l'indirizzo fisico del dispositivo autorizzato hardware (es. `00:1A:2B:3C:4D:5E`).

### 3.4 Interrogazione Asincrona ad OPA
Le informazioni sulla query e sull'identità client vengono incapsulate in una struttura JSON ed inviate ad OPA tramite una chiamata HTTP POST asincrona:
```rust
let token = self.dispatch_http_call(
    "opa_cluster",
    vec![
        (":method", "POST"),
        (":path", "/v1/data/envoy/authz/allow"),
        (":authority", "opa"),
        ("content-type", "application/json"),
    ],
    Some(&payload_bytes),
    vec![],
    std::time::Duration::from_millis(500),
);
```
Il flusso downstream viene temporaneamente sospeso (`Action::Pause`) per bloccare l'inoltro di qualsiasi pacchetto a MongoDB fino al verdetto di OPA.

### 3.5 Applicazione della Decisione (Enforcement)
Nella funzione `on_http_call_response`:
* **Se OPA risponde `true` (ALLOW)**: Lo stream viene sbloccato, l'estensione rimuove il pacchetto analizzato dal buffer locale e chiama `resume_downstream()` per inviare i byte a MongoDB.
* **Se OPA risponde `false` (DENY)**: L'estensione chiama `close_downstream()`, provocando l'abbattimento immediato della sessione TCP a livello di proxy (Fail-Closed) e impedendo a MongoDB di ricevere o elaborare il payload.

---

## 4. Protezione NoSQL Injection (L7 WAF)

L'integrazione con OPA consente di effettuare controlli statici e dinamici avanzati direttamente sul payload JSON estratto dal filtro Wasm. In particolare, OPA valuta la query per individuare tentativi di NoSQL Injection che sfruttano gli operatori JavaScript di MongoDB (`$where`, `$accumulator`, `$function`).

Nel file delle policy di OPA (`identity.rego`), è definita la regola di controllo del payload:
```rego
# Controlla la presenza di operatori JavaScript potenzialmente dannosi
nosql_injection_detected {
    # Cerca la chiave "$where" ricorsivamente all'interno dell'oggetto query
    walk(input.parsed_body.query, [_, value])
    value["$where"]
}

nosql_injection_detected {
    walk(input.parsed_body.query, [_, value])
    value["$function"]
}
```
Se `nosql_injection_detected` è vera, OPA restituisce `allow = false` ed Envoy chiude immediatamente la connessione TCP, neutralizzando l'attacco prima che questo possa raggiungere il database.

---

## 5. Flusso dei Dati Completo (Sequence Diagram)

Il diagramma di sequenza seguente illustra il ciclo di vita di una query protetta dall'estensione Wasm:

```mermaid
sequenceDiagram
    autonumber
    actor Client as Python Client / Agent
    participant Envoy as Envoy Proxy (mTLS + Wasm)
    participant OPA as Open Policy Agent
    participant DB as MongoDB

    Client->>Envoy: TCP Handshake + TLS Client Hello
    Note over Envoy: Valida il certificato mTLS e controlla la CRL
    Envoy-->>Client: TLS Handshake Completo (Tunnel cifrato)
    
    Client->>Envoy: Invia MongoDB Query (Cifrata)
    Note over Envoy: Envoy decifra lo stream TLS in chiaro
    Note over Envoy: Il filtro Wasm accumula i byte nel buffer TCP
    
    opt Al completamento del pacchetto OP_MSG
        Note over Envoy: Il filtro Wasm estrae CN/MAC dal certificato e la query JSON dal BSON
        Envoy->>OPA: HTTP POST /v1/data/envoy/authz/allow (JSON Payload)
        Note over Envoy: Lo stream client verso MongoDB viene messo in PAUSA
        OPA->>OPA: Valutazione policy e controllo NoSQL Injection
        OPA-->>Envoy: HTTP Response { "result": true / false }
    end
    
    alt Risultato = true (ALLOW)
        Note over Envoy: Il filtro Wasm rilascia il buffer
        Envoy->>DB: Inoltra MongoDB Query in chiaro
        DB-->>Envoy: Risultato query
        Envoy-->>Client: Invia Risultato (Cifrato TLS)
    alt Risultato = false (DENY / NoSQL Injection)
        Note over Envoy: Il filtro Wasm esegue close_downstream()
        Envoy--xClient: Abbattimento connessione TCP (Connection Closed)
    end
```

---

## 6. Vantaggi in ottica Zero Trust Architecture (ZTA)

1. **Complete Mediation (Mediazione Completa)**: Nessuna query, per nessun motivo, può raggiungere il demone `mongod` senza essere stata prima validata. Il bypass del controllo d'accesso è tecnicamente impossibile, anche in caso di compromissione totale del container dell'applicazione web.
2. **Nessun Downgrade del Protocollo**: Altre soluzioni basate su proxy MongoDB obsoleti richiedevano il downgrade del protocollo MongoDB a `OP_QUERY` (deprecato e non supportato da driver moderni e autenticazione OIDC). Questa estensione lavora direttamente sul moderno opcode `OP_MSG`, consentendo l'uso delle ultime versioni di MongoDB e delle funzionalità di federazione delle identità.
3. **Isolamento e Sicurezza delle Chiavi**: L'handshake crittografico è protetto a livello L4 dall'integrazione hardware dell'Agente (SEP/Touch ID), mentre il controllo di conformità L7 avviene all'interno della sandbox Wasm di Envoy, un ambiente altamente isolato e protetto da attacchi di memory corruption.
