# Advanced Cybersecurity — Zero Trust Architecture (Native macOS)

A state-of-the-art **Zero Trust Architecture (ZTA)** implementation featuring hardware-bound identities, Secure Enclave integration, and dynamic identity-based access control for MongoDB.

This project demonstrates a production-grade defense-in-depth system where identity is cryptographically tied to the physical device and every request is evaluated in real-time.

## 🚀 Key Features

*   **Native macOS Agent**: Swift 6 agent managing Secure Enclave keys and mTLS handshakes.
*   **Hardware-Bound Identity**: Private keys are non-exportable, stored in the **Secure Enclave (SEP)**.
*   **Automated PKI**: Dynamic CA with automated Envoy server certificate synchronization.
*   **Protocol-Aware Protection**: Envoy L7 inspection of MongoDB BSON traffic.
*   **Risk-Based Authorization**: OPA policy engine evaluating user, device, and network risk.

## 🏗️ Architecture

For a deep dive into the 3-layer security model, see [ARCHITECTURE.md](./ARCHITECTURE.md). For the detailed technical report on the MongoDB TCP Proxy and Row-Level Security (RLS) implementation, see [Relazione_Implementazione_ZTA_MongoDB.md](./Relazione_Implementazione_ZTA_MongoDB.md) (in Italian).

## 🛠️ Quick Start

### 1. Prerequisites
*   **macOS**: Required for the Native Agent and Secure Enclave features.
*   **Docker & Docker Compose**: For the server-side stack.
*   **Xcode**: To run the Native Agent.
*   **Python 3.10+**: For CLI tools.

### 2. Launch the Infrastructure
```bash
docker compose up -d --build
```
This starts the PKI Service, Envoy Proxy, OPA, and MongoDB.

### 3. Start the Native Agent
1.  Open `ztaagent/ZTAAgent/ZTAAgent.xcodeproj` in Xcode.
2.  Run the app (**Cmd + R**).
3.  Ensure the status shows: `API Server: ready`.

### 4. Hardware Enrollment
Enroll your identity and bind it to your Mac's Secure Enclave:
```bash
python3 scripts/enroll.py --cn "paolo.roselli" --role "doctor" --department "Cardiologia"
```
*Note: This will trigger a Touch ID / Password prompt to authorize key generation.*

### 5. Multi-Layer Authentication
Verify your identity and access the protected resource:
```bash
python3 scripts/authenticate.py --cn "paolo.roselli"
```
*   **Layer 1**: Proof of Possession of the hardware key.
*   **Layer 2**: mTLS handshake with Envoy (Hardware identity).

## 📁 Repository Structure

| Directory | Description |
| :--- | :--- |
| `ztaagent/` | **Native macOS Agent** (Swift 6) |
| `identity_pki/` | Dynamic PKI Service (Python/Flask) |
| `envoy/` | Envoy PEP configuration & Lua filters |
| `opa/` | OPA PDP policies (Rego) |
| `scripts/` | CLI tools for enrollment and testing |
| `volumes/` | Persistent data, certificates, and metadata |

## ⚖️ Security Principles

*   **Trust Nothing**: Every request is authenticated and authorized.
*   **Hardware Roots of Trust**: Identity cannot be cloned or exported from the device.
*   **Fail-Closed**: Access is denied if any security layer fails.
*   **Least Privilege**: Access granted only to the specific resources required.

## 📜 References
* [NIST SP 800-207 (Zero Trust Architecture)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
* [Envoy Proxy Documentation](https://www.envoyproxy.io/)
* [Open Policy Agent](https://www.openpolicyagent.org/)
