import Foundation
import Network
import LocalAuthentication
import Security

class MongoProxySession {
    let cn: String
    let sessionToken: String
    let port: UInt16
    let expiresAt: Date
    private var listener: NWListener?
    private var activeConnections: [NWConnection] = []
    private var isStopped = false
    
    init(cn: String, port: UInt16, ttl: TimeInterval) {
        self.cn = cn
        self.sessionToken = UUID().uuidString
        self.port = port
        self.expiresAt = Date().addingTimeInterval(ttl)
    }
    
    func start() throws {
        let localPort = NWEndpoint.Port(rawValue: self.port)!
        // Bind parameters on localhost loopback ONLY to prevent external clients from connecting to our local plain socket
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(IPv4Address("127.0.0.1")!), port: localPort)
        
        listener = try NWListener(using: parameters, on: localPort)
        
        listener?.stateUpdateHandler = { state in
            print("[*] Proxy Listener per \(self.cn) sulla porta \(self.port) stato: \(state)")
        }
        
        listener?.newConnectionHandler = { [weak self] localConnection in
            guard let self = self, !self.isStopped else {
                localConnection.cancel()
                return
            }
            self.handleIncomingConnection(localConnection)
        }
        
        listener?.start(queue: .main)
        print("[✓] Sessione proxy avviata per \(self.cn) sulla porta \(self.port)")
    }
    
    private func handleIncomingConnection(_ localConnection: NWConnection) {
        do {
            print("[*] Nuova connessione locale sulla porta \(self.port) per \(self.cn)")
            let parameters = try buildTLSParameters(for: self.cn)
            
            // Connessione ad Envoy su localhost:10000
            let remoteEndpoint = NWEndpoint.hostPort(host: "localhost", port: 10000)
            let remoteConnection = NWConnection(to: remoteEndpoint, using: parameters)
            
            self.activeConnections.append(localConnection)
            self.activeConnections.append(remoteConnection)
            
            // Avvia la connessione locale
            localConnection.stateUpdateHandler = { state in
                if case .cancelled = state {
                    remoteConnection.cancel()
                }
            }
            localConnection.start(queue: .main)
            
            // Avvia la connessione remota mTLS
            remoteConnection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    print("[✓] Tunnel mTLS Envoy pronto per \(self.cn)")
                    self.pipe(from: localConnection, to: remoteConnection)
                    self.pipe(from: remoteConnection, to: localConnection)
                case .failed(let error):
                    print("[!] Connessione mTLS Envoy fallita: \(error)")
                    localConnection.cancel()
                case .cancelled:
                    localConnection.cancel()
                default:
                    break
                }
            }
            remoteConnection.start(queue: .main)
            
        } catch {
            print("[!] Impossibile configurare TLS per \(self.cn): \(error.localizedDescription)")
            localConnection.cancel()
        }
    }
    
    private func pipe(from source: NWConnection, to destination: NWConnection) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self, !self.isStopped else { return }
            
            if let data = data, !data.isEmpty {
                destination.send(content: data, completion: .contentProcessed({ [weak self] error in
                    if let error = error {
                        print("[!] Errore di invio nel tunnel: \(error.localizedDescription)")
                        source.cancel()
                        destination.cancel()
                    } else {
                        self?.pipe(from: source, to: destination)
                    }
                }))
            }
            
            if isComplete {
                destination.send(content: nil, contentContext: .defaultStream, isComplete: true, completion: .contentProcessed({ _ in }))
            }
            
            if let error = error {
                print("[!] Errore di ricezione nel tunnel: \(error.localizedDescription)")
                source.cancel()
                destination.cancel()
            }
        }
    }
    
    func stop() {
        guard !isStopped else { return }
        isStopped = true
        listener?.cancel()
        for conn in activeConnections {
            conn.cancel()
        }
        activeConnections.removeAll()
        print("[✓] Sessione proxy fermata per \(self.cn) sulla porta \(self.port)")
    }
    
    private func findIdentity(cn: String) throws -> SecIdentity {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess else {
            throw NSError(domain: "ZTA", code: 1, userInfo: [NSLocalizedDescriptionKey: "Keychain vuoto"])
        }
        
        let certificates: [SecCertificate]
        if CFGetTypeID(items!) == CFArrayGetTypeID() {
            certificates = items as! [SecCertificate]
        } else {
            certificates = [items as! SecCertificate]
        }
        
        for cert in certificates {
            let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? ""
            if summary == cn {
                var identity: SecIdentity?
                let idStatus = SecIdentityCreateWithCertificate(nil, cert, &identity)
                if idStatus == errSecSuccess, let id = identity {
                    return id
                }
            }
        }
        throw NSError(domain: "ZTA", code: 2, userInfo: [NSLocalizedDescriptionKey: "Identità per \(cn) non trovata nel Keychain"])
    }
    
    private func buildTLSParameters(for cn: String) throws -> NWParameters {
        let identity = try findIdentity(cn: cn)
        let tlsOptions = NWProtocolTLS.Options()
        
        sec_protocol_options_set_local_identity(
            tlsOptions.securityProtocolOptions,
            sec_identity_create(identity)!
        )
        
        // Accetta il certificato di Envoy auto-firmato per il lab
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, _, complete in
            complete(true)
        }, .main)
        
        return NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
    }
}

class MongoProxyManager {
    static let shared = MongoProxyManager()
    
    private var sessions: [String: MongoProxySession] = [:] // token -> session
    private var nextPort: UInt16 = 27019
    private let lock = NSLock()
    
    func startSession(cn: String, ttl: TimeInterval) async throws -> (port: UInt16, token: String) {
        // Gating biometrico: prompt Touch ID / password
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            let reason = "Consenti a ZTA Agent di avviare il tunnel MongoDB per \(cn)"
            let success = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            guard success else {
                throw NSError(domain: "ZTA", code: 401, userInfo: [NSLocalizedDescriptionKey: "Autenticazione biometrica fallita"])
            }
        } else {
            print("[*] Biometria non configurata o disponibile sul sistema. Procedo in bypass (contesto dev).")
        }
        
        lock.lock()
        defer { lock.unlock() }
        
        // Ricerca di una porta libera
        var port = nextPort
        while sessions.values.contains(where: { $0.port == port }) {
            port += 1
        }
        nextPort = port + 1
        
        let session = MongoProxySession(cn: cn, port: port, ttl: ttl)
        try session.start()
        
        sessions[session.sessionToken] = session
        
        // Rilascio automatico dopo il TTL
        let delay = Int(ttl)
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(delay)) {
            self.stopSession(token: session.sessionToken)
        }
        
        return (port, session.sessionToken)
    }
    
    func stopSession(token: String) {
        lock.lock()
        defer { lock.unlock() }
        
        if let session = sessions[token] {
            session.stop()
            sessions.removeValue(forKey: token)
        }
    }
    
    func stopAllSessions() {
        lock.lock()
        defer { lock.unlock() }
        
        for (_, session) in sessions {
            session.stop()
        }
        sessions.removeAll()
    }
    
    func getActiveSessions() -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        
        return sessions.values.map { session in
            return [
                "common_name": session.cn,
                "port": session.port,
                "expires_at": ISO8601DateFormatter().string(from: session.expiresAt)
            ]
        }
    }
}
