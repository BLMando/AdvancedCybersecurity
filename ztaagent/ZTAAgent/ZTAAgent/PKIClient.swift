import Foundation
import Security
import LocalAuthentication


class PKIClient: NSObject, URLSessionDelegate {
    static let shared = PKIClient()
    var activeLAContext: LAContext?
    private let serverUrl = "https://127.0.0.1:8080"
    private let envoyUrl = "https://localhost:10000"
    private var activeCNs: [URLSession: String] = [:]
    private let activeCNsLock = NSLock()
    private var pkiSession: URLSession!
    
    override init() {
        super.init()
        pkiSession = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
    }
    
    func enroll(cn: String, role: String, department: String, enrollmentSessionToken: String = "") async throws -> String {
        let challengeUrl = URL(string: "\(serverUrl)/api/challenge")!
        let (cData, _) = try await pkiSession.data(from: challengeUrl)
        let challengeJson = try JSONSerialization.jsonObject(with: cData) as! [String: Any]
        let challengeId = challengeJson["challenge_id"] as! String
        
        _ = try await HardwareManager.shared.generateHardwareKey(for: cn)
        let pubKeyData = try await HardwareManager.shared.getPublicKeyDER(for: cn)
        let pubKeyPEM = "-----BEGIN PUBLIC KEY-----\n\(pubKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]))\n-----END PUBLIC KEY-----"
        
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let proofString = "ZTA-CERT-BINDING|CN=\(cn)|TIME=\(timestamp)"
        let signature = try await HardwareManager.shared.sign(data: proofString.data(using: .utf8)!, cn: cn, context: activeLAContext)
        
        let enrollUrl = URL(string: "\(serverUrl)/api/csr")!
        var request = URLRequest(url: enrollUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let hwInfo = HardwareManager.shared.getHardwareInfo()
        let body: [String: Any] = [
            "user": cn, "role": role, "department": department,
            "public_key_pem": pubKeyPEM, "attestation_sig_b64": signature.base64EncodedString(),
            "proof_string": proofString, "challenge_id": challengeId,
            "mac_address": hwInfo["mac"] ?? "unknown",
            "cpu_id": hwInfo["cpu"] ?? "unknown",
            "enrollment_session_token": enrollmentSessionToken
        ]
        print("Payload Enrollment: user=\(cn), role=\(role), department=\(department), enrollment_session_token=(redacted)")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (eData, eResp) = try await pkiSession.data(for: request)
        let httpResp = eResp as! HTTPURLResponse
        
        if httpResp.statusCode == 200 {
            let resJson = try JSONSerialization.jsonObject(with: eData) as! [String: Any]
            guard let certPem = resJson["certificate_pem"] as? String else { return "Errore" }
            let cleanCert = certPem.replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "").replacingOccurrences(of: "-----END CERTIFICATE-----", with: "").replacingOccurrences(of: "\n", with: "")
            if let certData = Data(base64Encoded: cleanCert) {
                try await HardwareManager.shared.saveCertificate(cn: cn, certData: certData)
            }
            return "Enrollment completato!"
        }
        return "Errore Server"
    }
    
    func testAuthentication(cn: String) async throws -> String {
        // Use URLSession with delegate for mTLS
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        
        activeCNsLock.lock()
        activeCNs[session] = cn
        activeCNsLock.unlock()
        
        defer {
            activeCNsLock.lock()
            activeCNs.removeValue(forKey: session)
            activeCNsLock.unlock()
        }
        
        // Point to a resource protected by Envoy
        // Add a timestamp to prevent caching
        let url = URL(string: "\(envoyUrl)/api/resource?t=\(Date().timeIntervalSince1970)")!
        
        print("Starting mTLS request to Envoy...")
        let (data, response) = try await session.data(from: url)
        let httpResponse = response as! HTTPURLResponse
        
        let responseBody = String(data: data, encoding: .utf8) ?? ""
        print("Response from Envoy successfully received!")
        return "Status: \(httpResponse.statusCode), Data: \(responseBody.replacingOccurrences(of: "\n", with: " "))"
    }
    
    // mTLS and TRUST MANAGEMENT
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // 1. Server Trust Management (Accept the lab's Envoy certificate)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            print("Server Trust Challenge received.")
            
            if let serverTrust = challenge.protectionSpace.serverTrust {
                if let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
                    for (i, cert) in chain.enumerated() {
                        let subject = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Unknown"
                        print("Server Cert \(i) Subject: \(subject)")
                    }
                }
            }
            
            completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
            return
        }
        
        // 2. Client Certificate Management (mTLS)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            activeCNsLock.lock()
            guard let expectedCN = activeCNs[session] else {
                activeCNsLock.unlock()
                print("No active CN found for this session. mTLS failed.")
                completionHandler(.performDefaultHandling, nil)
                return
            }
            activeCNsLock.unlock()
            
            print("Envoy requested client certificate (mTLS). Looking for hardware identity for \(expectedCN)...")
            
            if let identity = HardwareManager.shared.getIdentity(for: expectedCN, context: activeLAContext) {
                print("mTLS identity successfully loaded for \(expectedCN)!")
                completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
            } else {
                print("No valid ZTA identity found for \(expectedCN).")
                completionHandler(.performDefaultHandling, nil)
            }
            return
        }
        
        completionHandler(.performDefaultHandling, nil)
    }

    func getOidcToken(cn: String, stepUp: Bool = false) async throws -> String {
        let challengeUrl = URL(string: "\(serverUrl)/api/challenge")!
        let (cData, _) = try await pkiSession.data(from: challengeUrl)
        let challengeJson = try JSONSerialization.jsonObject(with: cData) as! [String: Any]
        let challengeId = challengeJson["challenge_id"] as! String
        
        _ = try await HardwareManager.shared.generateHardwareKey(for: cn)
        let pubKeyData = try await HardwareManager.shared.getPublicKeyDER(for: cn)
        let pubKeyPEM = "-----BEGIN PUBLIC KEY-----\n\(pubKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]))\n-----END PUBLIC KEY-----"
        
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let proofString = "ZTA-CERT-BINDING|CN=\(cn)|TIME=\(timestamp)"
        let signature = try await HardwareManager.shared.sign(data: proofString.data(using: .utf8)!, cn: cn, context: activeLAContext)
        
        let oidcUrl = URL(string: "\(serverUrl)/api/oidc/token")!
        var request = URLRequest(url: oidcUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        var body: [String: Any] = [
            "challenge_id": challengeId,
            "signature": signature.base64EncodedString(),
            "public_key_pem": pubKeyPEM,
            "proof_string": proofString
        ]
        if stepUp {
            body["step_up"] = true
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (tData, tResp) = try await pkiSession.data(for: request)
        let httpResp = tResp as! HTTPURLResponse
        
        if httpResp.statusCode == 200 {
            let resJson = try JSONSerialization.jsonObject(with: tData) as! [String: Any]
            if let token = resJson["access_token"] as? String {
                return token
            }
            throw NSError(domain: "com.zta", code: 500, userInfo: [NSLocalizedDescriptionKey: "Token not found in response"])
        }
        
        let errorMsg = String(data: tData, encoding: .utf8) ?? "HTTP \(httpResp.statusCode)"
        throw NSError(domain: "com.zta", code: httpResp.statusCode, userInfo: [NSLocalizedDescriptionKey: "Server error: \(errorMsg)"])
    }
}

