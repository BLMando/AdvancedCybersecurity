# Direttiva: Production Readiness

Questa sezione descrive i requisiti necessari per trasformare l'attuale Proof-of-Concept (PoC) in un'infrastruttura pronta per l'ambiente di produzione.

## 1. Gestione dei Segreti (Secret Management)
**Stato Attuale:** I certificati e le chiavi private sono mappati tramite volumi Docker (`./certs:/etc/certs`).
**Requisito Produzione:**
- Utilizzare **Envoy SDS (Secret Discovery Service)** per la distribuzione dinamica dei segreti.
- Integrare un Vault (es. **HashiCorp Vault**) per lo storage sicuro delle chiavi private.
- Nessuna chiave privata deve essere scritta in chiaro sul file system dell'host.

## 2. Infrastruttura PKI
**Stato Attuale:** CA gestita da un server Flask semplificato.
**Requisito Produzione:**
- Utilizzare una gerarchia di CA (Root CA offline -> Intermediate CA online).
- Supporto per **OCSP (Online Certificate Status Protocol)** per la revoca in tempo reale.
- HSM (Hardware Security Module) per la protezione della chiave privata della Root CA.

## 3. Policy Enforcement (Envoy & OPA)
**Stato Attuale:** Comunicazione via gRPC locale.
**Requisito Produzione:**
- Implementazione di mTLS anche tra Envoy e OPA.
- Ridondanza dei nodi Envoy (High Availability) con load balancer esterno.
- Monitoring e Tracing (Jaeger/Prometheus) per ogni transazione negata.

---
*Ultimo aggiornamento: 2026-05-03*
