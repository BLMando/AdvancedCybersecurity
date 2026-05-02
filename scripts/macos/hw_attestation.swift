import Foundation
import Security
import CryptoKit

// ZTA Native Hardware CSR Generator
// Uses Apple Security Framework to create a real PKCS#10 CSR

struct StandardError: TextOutputStream {
    static var shared = StandardError()
    func write(_ string: String) {
        fputs(string, stderr)
    }
}

let arguments = CommandLine.arguments
if arguments.count < 2 {
    print("Usage: generate_csr <common_name>")
    exit(1)
}

let cn = arguments[1]
let label = "ZTA-HW-\(cn)"

func deepClean(label: String) {
    print("Performing deep clean for label: \(label)...", to: &StandardError.shared)
    let classes = [kSecClassKey, kSecClassCertificate, kSecClassIdentity, kSecClassGenericPassword]
    for secClass in classes {
        let query: [String: Any] = [
            kSecClass as String: secClass,
            kSecAttrLabel as String: label,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecItemNotFound && status != errSecSuccess {
            print("Warning: Failed to delete \(secClass) (status \(status))", to: &StandardError.shared)
        }
    }
}

func generateNativeCSR() {
    // 1. Try to find existing key first (Specific query)
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrLabel as String: label,
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecReturnRef as String: true,
        kSecReturnAttributes as String: true
    ]
    var item: CFTypeRef?
    var securityError: Unmanaged<CFError>?
    var privateKey: SecKey?
    
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecSuccess {
        if let dict = item as? [String: Any], let keyVal = dict[kSecValueRef as String] {
            let keyRef = (keyVal as! SecKey)
            privateKey = keyRef
            print("Found existing hardware key in Keychain.", to: &StandardError.shared)
            if let attrs = SecKeyCopyAttributes(keyRef) as? [String: Any] {
                let usage = attrs[kSecAttrCanSign as String] ?? "unknown"
                print("Key Attributes -> CanSign: \(usage), Label: \(attrs[kSecAttrLabel as String] ?? "none")", to: &StandardError.shared)
            }
        }
    } else {
        print("Existing key not found. Creating new hardware-bound key...", to: &StandardError.shared)
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrIsPermanent as String: true,
            kSecAttrLabel as String: label,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &securityError)
        
        if privateKey == nil {
            let errorMsg = securityError != nil ? "\(securityError!.takeRetainedValue())" : "Unknown error"
            print("Error: Could not create hardware key: \(errorMsg)", to: &StandardError.shared)
            exit(1)
        }
    }
    
    guard let key = privateKey else {
        print("Error: Key reference is null.", to: &StandardError.shared)
        exit(1)
    }
    
    // 2. Generate a "Proof of Possession" Challenge
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let proofString = "ZTA-CERT-BINDING|CN=\(cn)|TIME=\(timestamp)"
    let dataToSign = proofString.data(using: .utf8)!
    
    // 3. Signing (Using Message algorithm instead of Digest for better compatibility)
    guard let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, dataToSign as CFData, &securityError) else {
        let error = securityError?.takeRetainedValue()
        let code = error.map { CFErrorGetCode($0) } ?? 0
        let errorMsg = error.map { "\($0)" } ?? "Unknown error"
        
        if code == -50 {
            print("Detected incompatible legacy key (Error -50). Performing auto-reset...", to: &StandardError.shared)
            deepClean(label: label)
            print("[!] Legacy key removed. Please run the script again to enroll/authenticate with a fresh hardware key.", to: &StandardError.shared)
        } else {
            print("Error: Signature failed (Code \(code)): \(errorMsg)", to: &StandardError.shared)
            print("[!] Hint: Check Keychain permissions or run with sudo if needed.", to: &StandardError.shared)
        }
        exit(1)
    }
    
    // 5. Get Public Key in PEM format
    let publicKey = SecKeyCopyPublicKey(key)!
    let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
    let pubKeyBase64 = pubKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    let pubKeyPEM = "-----BEGIN RSA PUBLIC KEY-----\n\(pubKeyBase64)\n-----END RSA PUBLIC KEY-----"
    
    // 6. Output JSON result
    let response: [String: String] = [
        "signature_b64": (signature as Data).base64EncodedString(),
        "pub_key_b64": pubKeyData.base64EncodedString(),
        "pub_key_pem": pubKeyPEM,
        "csr_pem": proofString,
        "is_native_proof": "true"
    ]
    
    if let jsonData = try? JSONSerialization.data(withJSONObject: response),
       let jsonString = String(data: jsonData, encoding: .utf8) {
        print(jsonString)
    }
}

generateNativeCSR()
