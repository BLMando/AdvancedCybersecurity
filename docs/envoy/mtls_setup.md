# Configurazione mTLS (Mutual TLS) su Envoy

Envoy agisce come **Policy Enforcement Point (PEP)**. La mTLS è il primo livello di difesa che garantisce che solo i dispositivi con un certificato valido possano comunicare con la rete interna.

## Configurazione del Listener

Il listener sulla porta `10000` è configurato per richiedere obbligatoriamente un certificato client:

```yaml
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      tls_certificates:
        - certificate_chain: { filename: "/etc/certs/server/envoy.crt" }
          private_key: { filename: "/etc/certs/server/envoy.key" }
      validation_context:
        trusted_ca: { filename: "/etc/certs/ca/ca.crt" }
    require_client_certificate: true
```

## Logica di Validazione

1. **Integrità**: Il certificato deve essere firmato dalla Root CA specificata.
2. **Validità Temporale**: Il certificato deve essere nel periodo di validità.
3. **Revoca**: (Pianificato) Controllo tramite CRL o OCSP.

---
*Vedi anche: docs/zta/system_overview.md*
