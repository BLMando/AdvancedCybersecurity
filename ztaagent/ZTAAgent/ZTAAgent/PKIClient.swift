import Foundation
import Security

class PKIClient: NSObject, URLSessionDelegate {
    static let shared = PKIClient()
    private let serverUrl = "http://127.0.0.1:8080"
    private let envoyUrl = "https://localhost:10001"
    
    func enroll(cn: String, role: String, department: String) async throws -> String {
        // ... (metodo enroll già implementato e funzionante)
        let challengeUrl = URL(string: "\(serverUrl)/api/challenge")!
        let (cData, _) = try await URLSession.shared.data(from: challengeUrl)
        let challengeJson = try JSONSerialization.jsonObject(with: cData) as! [String: Any]
        let challengeId = challengeJson["challenge_id"] as! String
        
        _ = try HardwareManager.shared.generateHardwareKey(for: cn)
        let pubKeyData = try HardwareManager.shared.getPublicKeyDER(for: cn)
        let pubKeyPEM = "-----BEGIN PUBLIC KEY-----\n\(pubKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]))\n-----END PUBLIC KEY-----"
        
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let proofString = "ZTA-CERT-BINDING|CN=\(cn)|TIME=\(timestamp)"
        let signature = try HardwareManager.shared.sign(data: proofString.data(using: .utf8)!, cn: cn)
        
        let enrollUrl = URL(string: "\(serverUrl)/api/csr")!
        var request = URLRequest(url: enrollUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "user": cn, "role": role, "department": department,
            "public_key_pem": pubKeyPEM, "attestation_sig_b64": signature.base64EncodedString(),
            "proof_string": proofString, "challenge_id": challengeId
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (eData, eResp) = try await URLSession.shared.data(for: request)
        let httpResp = eResp as! HTTPURLResponse
        
        if httpResp.statusCode == 200 {
            let resJson = try JSONSerialization.jsonObject(with: eData) as! [String: Any]
            guard let certPem = resJson["certificate_pem"] as? String else { return "Errore" }
            let cleanCert = certPem.replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "").replacingOccurrences(of: "-----END CERTIFICATE-----", with: "").replacingOccurrences(of: "\n", with: "")
            if let certData = Data(base64Encoded: cleanCert) {
                try HardwareManager.shared.saveCertificate(cn: cn, certData: certData)
            }
            return "Enrollment completato!"
        }
        return "Errore Server"
    }
    
    func testAuthentication(cn: String) async throws -> String {
        // Usiamo un URLSession con delegato per gestire mTLS
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        
        // Puntiamo a una risorsa protetta dietro Envoy
        // Aggiungiamo un timestamp per evitare cache
        let url = URL(string: "\(envoyUrl)/api/resource?t=\(Date().timeIntervalSince1970)")!
        
        print("[*] Avvio richiesta mTLS a Envoy...")
        let (data, response) = try await session.data(from: url)
        let httpResponse = response as! HTTPURLResponse
        
        let responseBody = String(data: data, encoding: .utf8) ?? ""
        print("[✓] Risposta da Envoy ricevuta correttamente!")
        return "Status: \(httpResponse.statusCode), Data: \(responseBody.replacingOccurrences(of: "\n", with: " "))"
    }
    
    // GESTIONE mTLS e TRUST
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // 1. Gestione Server Trust (Accettiamo il certificato di Envoy del lab)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            print("[*] Challenge Server Trust ricevuta.")
            
            if let serverTrust = challenge.protectionSpace.serverTrust {
                let count = SecTrustGetCertificateCount(serverTrust)
                for i in 0..<count {
                    if let cert = SecTrustGetCertificateAtIndex(serverTrust, i) {
                        let subject = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Unknown"
                        print("[DEBUG] Server Cert \(i) Subject: \(subject)")
                    }
                }
            }
            
            completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
            return
        }
        
        // 2. Gestione Client Certificate (mTLS)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            print("[*] Envoy ha richiesto il certificato client (mTLS). Cerco l'identità hardware...")
            
            // 1. Cerchiamo il CERTIFICATO nel Keychain
            let query: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll
            ]
            
            var items: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &items)
            
            if status == errSecSuccess {
                var certificates: [SecCertificate] = []
                
                if CFGetTypeID(items!) == CFArrayGetTypeID() {
                    certificates = items as! [SecCertificate]
                } else {
                    certificates = [items as! SecCertificate]
                }
                
                print("[DEBUG] Trovati \(certificates.count) certificati nel Keychain.")
                var foundIdentity: SecIdentity?
                
                for cert in certificates {
                    let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Senza nome"
                    print("[DEBUG] Esamino certificato: '\(summary)'")
                    
                    if summary == "paolo.roselli" {
                        print("[✓] Certificato ZTA trovato! Cerco di creare l'identità (link alla chiave privata)...")
                        
                        // Chiediamo al sistema di trovare la chiave privata associata
                        var identity: SecIdentity?
                        let idStatus = SecIdentityCreateWithCertificate(nil, cert, &identity)
                        
                        if idStatus == errSecSuccess, let id = identity {
                            foundIdentity = id
                            print("[✓] IDENTITÀ COMPLETA CREATA CON SUCCESSO!")
                            break
                        } else {
                            print("[!] Errore: Certificato trovato ma chiave privata NON associata (Status: \(idStatus))")
                        }
                    }
                }
                
                if let identity = foundIdentity {
                    print("[*] Richiedo autorizzazione SEP per l'identità ZTA...")
                    completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
                } else {
                    print("[!] Nessuna identità ZTA autentica trovata. Hai cancellato i vecchi cert e rifatto l'enrollment?")
                    completionHandler(.performDefaultHandling, nil)
                }
            } else {
                print("[!] Nessuna identità mTLS trovata nel Keychain.")
                completionHandler(.performDefaultHandling, nil)
            }
            return
        }
        
        completionHandler(.performDefaultHandling, nil)
    }
}
