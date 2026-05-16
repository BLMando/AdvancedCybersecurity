import Foundation
import Security
import CryptoKit

class HardwareManager {
    static let shared = HardwareManager()
    
    enum HardwareError: Error {
        case secureEnclaveNotAvailable
        case keyGenerationFailed(Error?)
        case keyNotFound
        case signingFailed(Error?)
    }
    
    func generateHardwareKey(for cn: String) throws -> SecKey {
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            nil
        )!
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
                kSecAttrLabel as String: label
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw HardwareError.keyGenerationFailed(error?.takeRetainedValue())
        }
        return privateKey
    }
    
    func getPublicKeyDER(for cn: String) throws -> Data {
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let privateKey = item as! SecKey? else {
            throw HardwareError.keyNotFound
        }
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let representation = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            throw HardwareError.keyNotFound
        }
        
        let rawData = representation as Data
        let key = try P256.Signing.PublicKey(x963Representation: rawData)
        return key.derRepresentation
    }
    
    func sign(data: Data, cn: String) throws -> Data {
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let privateKey = item as! SecKey? else {
            throw HardwareError.keyNotFound
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) else {
            throw HardwareError.signingFailed(error?.takeRetainedValue())
        }
        return signature as Data
    }
    
    func saveCertificate(cn: String, certData: Data) throws {
        let label = "com.zta.certificate.\(cn)"
        
        // 1. Recuperiamo la chiave pubblica per calcolarne l'hash (Subject Key Identifier)
        let keyLabel = "com.zta.identity.\(cn)"
        let tag = keyLabel.data(using: .utf8)!
        let queryKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let statusKey = SecItemCopyMatching(queryKey as CFDictionary, &item)
        guard statusKey == errSecSuccess, let privateKey = item as! SecKey?,
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            print("[!] Impossibile trovare la chiave pubblica per il link.")
            return
        }
        
        // Calcoliamo l'hash SHA1 della chiave pubblica (standard macOS per il link identity)
        let publicKeyHash = Insecure.SHA1.hash(data: publicKeyData as Data)
        let hashData = Data(publicKeyHash)

        // 2. Salviamo il certificato con il riferimento all'hash della chiave
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
            kSecValueData as String: certData,
            kSecAttrApplicationLabel as String: hashData, // LINK CRUCIALE
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecSuccess {
            print("[✓] Certificato salvato e collegato alla chiave hardware.")
        } else {
            print("[!] Errore salvataggio certificato: \(status)")
        }
    }
}
