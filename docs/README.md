# Advanced Cybersecurity — Zero Trust Architecture (Native macOS)

A state-of-the-art **Zero Trust Architecture (ZTA)** implementation featuring hardware-bound identities, Secure Enclave integration, and dynamic identity-based access control for MongoDB.

This project demonstrates a production-grade defense-in-depth system where identity is cryptographically tied to the physical device and every request is evaluated in real-time.

## 🚀 Key Features

*   **Native macOS Agent**: Swift 6 agent managing Secure Enclave keys and mTLS handshakes.
*   **Windows TPM Agent**: PowerShell/.NET agent leveraging TPM 2.0 via Windows CNG/Schannel for hardware-bound mTLS.
*   **Hardware-Bound Identity**: Private keys are non-exportable, stored in the **Secure Enclave (SEP)** or **TPM 2.0**.
*   **4-Layer Authentication**: Primary Session (12h MFA) → Hardware Certificate → Biometrics → Step-Up MFA (120s freshness for sensitive ops).
*   **Automated PKI with OIDC & RFC 8705**: Dynamic CA with RFC 8705 Token Binding — JWTs are cryptographically bound to the hardware certificate.
*   **Protocol-Aware Protection**: Envoy L7 inspection of MongoDB BSON traffic with Row-Level Security (RLS) views.
*   **Risk-Based Authorization**: OPA policy engine evaluating user role, device hardware health, network risk, and Splunk-fed dynamic risk scoring.
*   **CRL Integration**: Automatic CRL generation and Envoy-side certificate revocation enforcement.

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

### 5. Authenticate and Query
Open the Web Console at `http://localhost:8080`:
1. **Primary Authentication** (first time or after 12h): Enter your AD credentials (email + password) and the OTP shown on screen to establish a primary session.
2. **Hardware Biometric Query**: Select a user and collection, then click **Submit mTLS Query**. Touch ID / Windows Hello will be prompted once per session.
3. **Step-Up Auth** (for `update`/`delete` or billing > 5000): The console automatically prompts for a fresh OTP before executing sensitive operations.
4. **Auto-Retry**: If a session expires mid-workflow, the console re-prompts for auth and automatically retries the original query.

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

*   **Trust Nothing**: Every request is authenticated and authorized — no implicit trust based on network location.
*   **Hardware Roots of Trust**: Identity cannot be cloned or exported from the device (SEP / TPM).
*   **Human Session Gating**: Certificate validity ≠ session validity. A 12-hour primary session (AD Login + OTP) ensures a human is present, independent of the certificate's cryptographic validity.
*   **Step-Up MFA**: Sensitive operations require a fresh OTP within 120 seconds, reducing the blast radius of compromised sessions.
*   **RFC 8705 Token Binding**: JWTs are bound to the hardware certificate via `cnf` claim — stolen tokens cannot be reused from another machine.
*   **Fail-Closed**: Access is denied if any security layer fails, expires, or is unavailable.
*   **Least Privilege**: Access granted only to the specific resources required (RLS views, OPA policy matrix).

## 📜 References
* [NIST SP 800-207 (Zero Trust Architecture)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
* [Envoy Proxy Documentation](https://www.envoyproxy.io/)
* [Open Policy Agent](https://www.openpolicyagent.org/)
