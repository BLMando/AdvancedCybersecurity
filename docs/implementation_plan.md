# Implementation Plan: MongoDB OP_MSG Wasm Filter & Transactional Authz

Implement a custom WebAssembly (Wasm) network filter for Envoy Proxy to parse MongoDB `OP_MSG` (opcode 2013) wire protocol packets, extract command and collection metadata, and enforce message-level transactional authorization via Open Policy Agent (OPA).

---

## User Review Required

> [!IMPORTANT]
> **Performance Overhead & Latency**: 
> Moving from connection-level L4 authorization to message-level L7 authorization means OPA will evaluate rules for *every single database request* instead of only once per TCP connection. This will add slight overhead (approx. 1-3ms per query depending on OPA and network speeds).
> To minimize latency, OPA and the Wasm filter should run in close proximity (local network or shared socket) and utilize persistent gRPC streams or fast HTTP connections.

> [!WARNING]
> **Compilation Toolchain**:
> Building the Wasm filter requires the Rust compilation toolchain (`cargo`, `rustup`) configured for the target `wasm32-wasip1` or `wasm32-unknown-unknown`. This build step will take place in the developer environment or inside a multi-stage Docker build.

---

## Open Questions

> [!NOTE]
> 1. **Protocol Error Handling**: If the Wasm parser encounters a malformed MongoDB message or protocol fragmentation, should it fail-closed (terminating the TCP connection) or fail-open (allowing traffic to bypass validation)? *Standard Zero Trust dictates fail-closed.*
> 2. **Wasm Language Choice**: Rust is proposed due to its mature BSON parsing ecosystem (`bson` crate) and official Proxy-Wasm SDK. Is Rust acceptable, or would you prefer a Go-based TinyGo filter?

---

## Proposed Changes

### Component 1: Envoy Proxy

#### [MODIFY] [envoy.yaml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/envoy/envoy.yaml)
* Modify the TCP filter chain on port `10000`.
* Replace the legacy L4 `envoy.filters.network.ext_authz` and `envoy.filters.network.mongo_proxy` filters with the new custom Wasm network filter under `envoy.filters.network.wasm`.
* Configure the Wasm filter with the compiled `.wasm` path and local cluster definitions for OPA.

```yaml
# Proposed changes to envoy.yaml listener:
- name: mongo_listener
  filter_chains:
    - filters:
        - name: envoy.filters.network.wasm
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.wasm.v3.Wasm
            config:
              name: "mongo_op_msg_authz"
              vm_config:
                runtime: "envoy.wasm.runtime.v8"
                code:
                  local:
                    filename: "/etc/envoy/wasm/mongo_op_msg_filter.wasm"
              configuration:
                "@type": "type.googleapis.com/google.protobuf.StringValue"
                value: |
                  {
                    "opa_authz_url": "http://opa_cluster/v1/data/envoy/authz",
                    "fail_open": false
                  }
        - name: envoy.filters.network.tcp_proxy
          # tcp_proxy remains as the final destination filter
```

#### [NEW] [Dockerfile](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/envoy/Dockerfile)
* Update the Envoy Dockerfile to support a multi-stage build:
  1. Build stage: compile the Rust Wasm code using `rust:latest` and cargo-wasi.
  2. Final stage: copy the compiled `mongo_op_msg_filter.wasm` into Envoy's execution directory (`/etc/envoy/wasm/`).

---

### Component 2: Wasm Filter Source Code

#### [NEW] [Cargo.toml](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/envoy/wasm/Cargo.toml)
* Configure Rust dependencies including `proxy-wasm` SDK, `bson` parser, `serde`, and `serde_json`.

#### [NEW] [lib.rs](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/envoy/wasm/src/lib.rs)
* Implement the network filter logic:
  * **OnDownstreamData**: Intercepts binary TCP chunks. Buffer and reassemble fragments into complete MongoDB wire protocol messages (reading the 4-byte header length).
  * **MongoDB Parser**:
    - Identify opcode `2013` (`OP_MSG`).
    - Parse BSON sections (Section 0) to extract the command name (e.g., `find`, `insert`), target collection, and query filter details.
  * **Message-level OPA Request**:
    - For each message, format a JSON payload representing the context (user CN, device MAC, network IP, command, collection, query filter).
    - Send an out-of-band asynchronous HTTP dispatch call to OPA.
    - If OPA returns `allow: true`, forward the data upstream.
    - If denied, inject a MongoDB response error or drop the TCP connection immediately.

---

### Component 3: OPA Policy Engine

#### [MODIFY] [main.rego](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/opa/policies/main.rego)
* Add a new package endpoint `/v1/data/envoy/authz` to handle the specific input payload schema emitted by the Wasm filter.
* Standardize input properties (`input.command`, `input.collection`, etc.) so that they integrate seamlessly with `criteria.rego` and `risk.rego` without breaking existing HTTP mTLS tests.

---

## Verification Plan

### Automated Tests
1. **Compilation Validation**:
   ```bash
   cd envoy/wasm
   cargo build --target wasm32-wasi --release
   ```
2. **End-to-End Verification**:
   Execute the automated test script [test_mtls_proxy.py](file:///C:/Users/matti/Desktop/UNI/AdvancedCybersecurity/scripts/test_mtls_proxy.py) and check that standard queries still function.
3. **OP_MSG Command Enforcement Test**:
   Write a Python test script using a modern client (e.g. `pymongo`) which enforces modern `OP_MSG` syntax:
   * Perform an authorized query (`find` collection `patients` with `patient_id` filter) -> verify connection **allowed**.
   * Perform an unauthorized command (`drop` collection `clinical_records`) -> verify connection **dropped** mid-session (Message-level enforcement).

### Manual Verification
* Start the mTLS local proxy and connect with MongoDB Compass.
* Attempt to delete a collection or run a query without a required filter in Compass.
* Verify in the Envoy console logs and Splunk index (`index=zta_envoy`) that OPA evaluates and denies the specific command, generating individual log records for each message transaction rather than just a single log at connection start.
