# Task List - Non-Exportable Hardware-Bound Keys

- [x] **Phase 1: Server-side Support (pki.py)**
    - [x] Update `_load_public_key` to support Elliptic Curve PEM.
    - [x] Update `verify_proof` to handle both RSA and EC signature verification.
    - [x] Add `cryptography.hazmat.primitives.asymmetric.ec` imports.

- [x] **Phase 2: macOS Helper (Swift)**
    - [x] Update `hw_attestation.swift` to use `ECSECPrimeRandom` (256 bits).
    - [x] Bind key to `SecureEnclave`.
    - [x] Update signing to `ecdsaSignatureMessageX962SHA256`.
    - [x] Recompile `hw_attestation_helper`.

- [x] **Phase 3: Windows Helper (PowerShell/C#)**
    - [x] Update `hw_attestation.ps1` to use `Microsoft Platform Crypto Provider`.
    - [x] Enforce `CngExportPolicies.None`.
    - [x] Implement EC with RSA fallback.

- [x] **Phase 4: Orchestration (enroll.py & authenticate.py)**
    - [x] Update `enroll.py` to handle EC public keys in the helper output.
    - [x] Ensure proper JSON parsing for new hardware metadata.
    - [x] Add Windows-specific Certificate Store import and repair to `enroll.py`.
    - [x] Add Windows-specific real mTLS handshake execution using Schannel and .NET HttpClient to `authenticate.py`.

- [ ] **Phase 5: Verification**
    - [ ] Test enrollment on macOS.
    - [ ] Test enrollment on Windows.
    - [ ] Verify mTLS handshake on Windows.
    - [ ] Verify non-exportability in OS Keychain/Certificate Manager.
