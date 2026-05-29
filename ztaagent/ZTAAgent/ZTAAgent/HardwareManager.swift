import Foundation
import Security
import CryptoKit
import IOKit

class HardwareManager {
    static let shared = HardwareManager()
    
    enum HardwareError: Error {
        case secureEnclaveNotAvailable
        case keyGenerationFailed(Error?)
        case keyNotFound
        case signingFailed(Error?)
    }
    
    func getHardwareInfo() -> [String: String] {
        var info = ["mac": "unknown", "cpu": "unknown"]
        print("[DEBUG] Recupero info hardware...")
        
        // 1. Get Hardware UUID (Mac equivalent of stable ID)
        let platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        if platformExpert != 0 {
            if let serialNumberAsCFString = IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0) {
                let uuid = (serialNumberAsCFString.takeRetainedValue() as? String) ?? "unknown"
                info["mac"] = uuid
                print("[DEBUG] UUID trovato: \(uuid)")
            }
            IOObjectRelease(platformExpert)
        } else {
            print("[!] Impossibile trovare IOPlatformExpertDevice")
        }
        
        // 2. Get CPU Model
        var size = 0
        sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
        if size > 0 {
            var brand = [CChar](repeating: 0, count: size)
            sysctlbyname("machdep.cpu.brand_string", &brand, &size, nil, 0)
            let cpu = String(cString: brand)
            info["cpu"] = cpu
            print("[DEBUG] CPU trovata: \(cpu)")
        }
        
        return info
    }
    
    func generateHardwareKey(for cn: String) throws -> SecKey {
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        
        // Se la chiave esiste già nel SE, la restituiamo (idempotente su re-enrollment)
        let existsQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        var existingItem: CFTypeRef?
        if SecItemCopyMatching(existsQuery as CFDictionary, &existingItem) == errSecSuccess,
           let existing = existingItem as! SecKey? {
            print("[✓] Chiave SE già esistente per \(cn), riutilizzo.")
            return existing
        }
        
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
        // Scriviamo il certificato DER su un file temporaneo, poi usiamo
        // 'security import' che lega automaticamente il cert alla chiave SE
        // tramite confronto della chiave pubblica (stesso meccanismo di enroll.py).
        let tmpFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("zta_cert_\(cn).cer")
        
        try certData.write(to: tmpFile)
        defer { try? FileManager.default.removeItem(at: tmpFile) }
        
        // security import lega cert ↔ chiave SE per fingerprint della chiave pubblica
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["import", tmpFile.path, "-t", "cert", "-k",
                             FileManager.default.homeDirectoryForCurrentUser
                                 .appendingPathComponent("Library/Keychains/login.keychain-db").path]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        try process.run()
        process.waitUntilExit()
        
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        
        if process.terminationStatus == 0 {
            print("[✓] Certificato per \(cn) importato nel Keychain e collegato alla chiave SE.")
        } else {
            // errSecDuplicateItem (-25299) = il cert è già nel Keychain, non è un errore
            if output.contains("already exists") || output.contains("duplicate") {
                print("[✓] Certificato per \(cn) già presente nel Keychain (duplicato ignorato).")
            } else {
                print("[!] Errore 'security import' per \(cn) (status \(process.terminationStatus)): \(output)")
            }
        }
    }
}

