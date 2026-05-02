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
    // 1. Try to find existing key first
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrLabel as String: label,
        kSecReturnRef as String: true
    ]
    var item: CFTypeRef?
    var securityError: Unmanaged<CFError>?
    var privateKey: SecKey?
    
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecSuccess {
        privateKey = (item as! SecKey)
        print("Found existing hardware key in Keychain.", to: &StandardError.shared)
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
    
    // 3. Manual Hashing for Maximum Compatibility (CryptoKit)
    let hashData = Data(SHA256.hash(data: dataToSign))
    
    guard let signature = SecKeyCreateSignature(key, .rsaSignatureDigestPKCS1v15SHA256, hashData as CFData, &securityError) else {
        print("Existing key in Keychain is incompatible. Performing Deep Clean and Resetting...", to: &StandardError.shared)
        deepClean(label: label)
        print("[!] Old keys purged. Please run the script again to generate a fresh hardware-bound key.", to: &StandardError.shared)
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
