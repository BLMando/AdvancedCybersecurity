import Foundation
import Security
import CryptoKit
import IOKit
import LocalAuthentication

class HardwareManager {
    static let shared = HardwareManager()
    
    enum HardwareError: Error, CustomNSError, LocalizedError {
        case secureEnclaveNotAvailable
        case keyGenerationFailed(Error?)
        case keyNotFound
        case signingFailed(Error?)
        
        static var errorDomain: String { return "com.zta.HardwareError" }
        
        var errorCode: Int {
            switch self {
            case .secureEnclaveNotAvailable: return 1001
            case .keyGenerationFailed: return 1002
            case .keyNotFound: return 1003
            case .signingFailed: return 1004
            }
        }
        
        var errorDescription: String? {
            switch self {
            case .secureEnclaveNotAvailable:
                return "Secure Enclave not available on this device"
            case .keyGenerationFailed(let underlying):
                if let u = underlying {
                    return "Key generation failed: \(u.localizedDescription)"
                }
                return "Key generation failed (unknown reason)"
            case .keyNotFound:
                return "Hardware key not found in Secure Enclave"
            case .signingFailed(let underlying):
                if let u = underlying {
                    return "Hardware signing failed: \(u.localizedDescription)"
                }
                return "Hardware signing failed"
            }
        }
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
    
    var ztaDir: URL {
        let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".zta")
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func generateHardwareKey(for cn: String) throws -> SecKey {
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        let keyFile = ztaDir.appendingPathComponent("\(cn).key")
        
        // Se la chiave esiste già nel file system, la riutilizziamo
        if FileManager.default.fileExists(atPath: keyFile.path) {
            if let data = try? Data(contentsOf: keyFile),
               let privateKey = SecKeyCreateWithData(data as CFData, [
                   kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                   kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                   kSecAttrKeySizeInBits as String: 256
               ] as CFDictionary, nil) {
                print("[✓] Chiave file-based trovata per \(cn), riutilizzo.")
                return privateKey
            }
        }
        
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
        if let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            return privateKey
        }
        
        let err = error?.takeRetainedValue()
        print("[!] SecKeyCreateRandomKey (SecureEnclave) fallito: \(String(describing: err)). Provo fallback in Software Keychain...")
        
        // Fallback to Software Keychain EC Key
        let softAccess = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            nil
        )!
        
        let softAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: softAccess,
                kSecAttrLabel as String: label
            ]
        ]
        
        var softError: Unmanaged<CFError>?
        if let privateKey = SecKeyCreateRandomKey(softAttributes as CFDictionary, &softError) {
            print("[✓] Chiave Software Keychain creata con successo come fallback.")
            return privateKey
        }
        
        let sErr = softError?.takeRetainedValue()
        print("[!] SecKeyCreateRandomKey (Software Keychain) fallito: \(String(describing: sErr)). Provo fallback in File System...")
        
        // Fallback to CryptoKit File-based Software P256 EC Key (Completamente in user-space, bypassa Keychain)
        do {
            let privateKey = P256.Signing.PrivateKey()
            let keyData = privateKey.x963Representation // SEC1 representation
            try keyData.write(to: keyFile)
            print("[✓] Chiave file-based creata con successo tramite CryptoKit in \(keyFile.path).")
            
            guard let secKey = SecKeyCreateWithData(keyData as CFData, [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 256
            ] as CFDictionary, nil) else {
                throw NSError(domain: "com.zta", code: -1, userInfo: [NSLocalizedDescriptionKey: "SecKeyCreateWithData failed"])
            }
            return secKey
        } catch {
            print("[!] Generazione chiave file-based tramite CryptoKit fallita: \(error)")
            throw HardwareError.keyGenerationFailed(error)
        }
    }
    
    func getPublicKeyDER(for cn: String) throws -> Data {
        // 1. Prova file-based
        let keyFile = ztaDir.appendingPathComponent("\(cn).key")
        if FileManager.default.fileExists(atPath: keyFile.path) {
            if let data = try? Data(contentsOf: keyFile),
               let privateKey = SecKeyCreateWithData(data as CFData, [
                   kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                   kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                   kSecAttrKeySizeInBits as String: 256
               ] as CFDictionary, nil),
               let publicKey = SecKeyCopyPublicKey(privateKey),
               let representation = SecKeyCopyExternalRepresentation(publicKey, nil) {
                let rawData = representation as Data
                let key = try P256.Signing.PublicKey(x963Representation: rawData)
                return key.derRepresentation
            }
        }

        // 2. Prova Keychain lookup
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
    
    func sign(data: Data, cn: String, context: LAContext? = nil) throws -> Data {
        // 1. Prova file-based
        let keyFile = ztaDir.appendingPathComponent("\(cn).key")
        if FileManager.default.fileExists(atPath: keyFile.path) {
            if let keyData = try? Data(contentsOf: keyFile),
               let privateKey = SecKeyCreateWithData(keyData as CFData, [
                   kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                   kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                   kSecAttrKeySizeInBits as String: 256
               ] as CFDictionary, nil) {
                var error: Unmanaged<CFError>?
                guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) else {
                    throw HardwareError.signingFailed(error?.takeRetainedValue())
                }
                return signature as Data
            }
        }

        // 2. Prova Keychain
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }
        
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
        // Scriviamo il certificato DER su file in ~/.zta/<cn>.crt per il fallback
        let certFile = ztaDir.appendingPathComponent("\(cn).crt")
        try certData.write(to: certFile)
        print("[✓] Certificato per \(cn) salvato nel file system in \(certFile.path).")

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

    func getIdentity(for cn: String, context: LAContext? = nil) -> SecIdentity? {
        let keyFile = ztaDir.appendingPathComponent("\(cn).key")
        let certFile = ztaDir.appendingPathComponent("\(cn).crt")
        
        print("[DEBUG] getIdentity checking CN: \(cn)")
        print("[DEBUG] keyFile: \(keyFile.path) exists: \(FileManager.default.fileExists(atPath: keyFile.path))")
        print("[DEBUG] certFile: \(certFile.path) exists: \(FileManager.default.fileExists(atPath: certFile.path))")
        
        // 1. Tentativo file-based (robusto e indipendente da Keychain)
        if FileManager.default.fileExists(atPath: keyFile.path) &&
           FileManager.default.fileExists(atPath: certFile.path) {
            do {
                let keyData = try Data(contentsOf: keyFile)
                let certData = try Data(contentsOf: certFile)
                
                guard let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
                    print("[DEBUG] SecCertificateCreateWithData failed for \(cn)")
                    return nil
                }
                
                var error: Unmanaged<CFError>?
                let privateKey = SecKeyCreateWithData(keyData as CFData, [
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                    kSecAttrKeySizeInBits as String: 256
                ] as CFDictionary, &error)
                
                guard let key = privateKey else {
                    print("[DEBUG] SecKeyCreateWithData failed for \(cn): \(String(describing: error?.takeRetainedValue()))")
                    return nil
                }
                
                guard let identity = SecIdentityCreate(nil, cert, key) else {
                    print("[DEBUG] SecIdentityCreate failed for \(cn)")
                    return nil
                }
                
                print("[✓] Identità file-based caricata con successo per \(cn)!")
                return identity
            } catch {
                print("[DEBUG] Error loading file-based identity for \(cn): \(error)")
            }
        }
        
        // 2. Tentativo Keychain lookup
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess else { return nil }
        
        let certificates: [SecCertificate]
        if CFGetTypeID(items!) == CFArrayGetTypeID() {
            certificates = items as! [SecCertificate]
        } else {
            certificates = [items as! SecCertificate]
        }
        
        var targetCert: SecCertificate?
        for cert in certificates {
            let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Senza nome"
            if summary == cn {
                targetCert = cert
                break
            }
        }
        
        guard let cert = targetCert else { return nil }
        
        let label = "com.zta.identity.\(cn)"
        let tag = label.data(using: .utf8)!
        var keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        if let context = context {
            keyQuery[kSecUseAuthenticationContext as String] = context
        }
        
        var keyItem: CFTypeRef?
        let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyItem)
        
        if keyStatus == errSecSuccess, let privateKey = keyItem as! SecKey?,
           let identity = SecIdentityCreate(nil, cert, privateKey) {
            print("[✓] Identità mTLS da Keychain creata con successo combinando Certificato e SecKey per \(cn)!")
            return identity
        }
        
        var identity: SecIdentity?
        let idStatus = SecIdentityCreateWithCertificate(nil, cert, &identity)
        if idStatus == errSecSuccess {
            print("[✓] Identità mTLS da Keychain creata con successo per \(cn) (SecIdentityCreateWithCertificate)!")
            return identity
        }
        
        return nil
    }
}

