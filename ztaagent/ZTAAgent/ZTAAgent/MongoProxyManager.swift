import Foundation
import Network
import LocalAuthentication
import Security
#if os(macOS)
import AppKit
#endif

@_silgen_name("SecIdentityCreate")
func SecIdentityCreate(_ allocator: CFAllocator?, _ certificate: SecCertificate, _ privateKey: SecKey) -> SecIdentity?


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
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(IPv4Address("127.0.0.1")!), port: .any)
        
        listener = try NWListener(using: parameters, on: localPort)
        
        listener?.stateUpdateHandler = { state in
            print("Proxy Listener for \(self.cn) on port \(self.port) state: \(state)")
        }
        
        listener?.newConnectionHandler = { [weak self] localConnection in
            guard let self = self, !self.isStopped else {
                localConnection.cancel()
                return
            }
            self.handleIncomingConnection(localConnection)
        }
        
        listener?.start(queue: .main)
        print("Proxy session started for \(self.cn) on port \(self.port)")
    }
    
    private func handleIncomingConnection(_ localConnection: NWConnection) {
        do {
            print("New local connection on port \(self.port) for \(self.cn)")
            let parameters = try buildTLSParameters(for: self.cn)
            
            // Connection to Envoy on localhost:10000
            let remoteEndpoint = NWEndpoint.hostPort(host: "localhost", port: 10000)
            let remoteConnection = NWConnection(to: remoteEndpoint, using: parameters)
            
            self.activeConnections.append(localConnection)
            self.activeConnections.append(remoteConnection)
            
            // Start local connection
            localConnection.stateUpdateHandler = { state in
                if case .cancelled = state {
                    remoteConnection.cancel()
                }
            }
            localConnection.start(queue: .main)
            
            // Start remote mTLS connection
            remoteConnection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    print("Envoy mTLS tunnel ready for \(self.cn)")
                    self.pipe(from: localConnection, to: remoteConnection)
                    self.pipe(from: remoteConnection, to: localConnection)
                case .failed(let error):
                    print("Envoy mTLS connection failed: \(error)")
                    localConnection.cancel()
                case .cancelled:
                    localConnection.cancel()
                default:
                    break
                }
            }
            remoteConnection.start(queue: .main)
            
        } catch {
            print("Unable to configure TLS for \(self.cn): \(error.localizedDescription)")
            localConnection.cancel()
        }
    }
    
    private func pipe(from source: NWConnection, to destination: NWConnection) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self, !self.isStopped else { return }
            
            if let error = error {
                let errDesc = error.localizedDescription
                if !errDesc.contains("No message available on STREAM") &&
                   !errDesc.contains("Operation canceled") &&
                   !errDesc.contains("Socket is not connected") {
                    print("Tunnel receive error: \(errDesc)")
                }
                source.cancel()
                destination.cancel()
                return
            }
            
            if (data != nil && !data!.isEmpty) || isComplete {
                destination.send(content: data, contentContext: .defaultStream, isComplete: isComplete, completion: .contentProcessed({ [weak self] sendError in
                    guard let self = self, !self.isStopped else { return }
                    if let sendError = sendError {
                        let errDesc = sendError.localizedDescription
                        if !errDesc.contains("Operation canceled") && !errDesc.contains("Socket is not connected") {
                            print("Tunnel send error: \(errDesc)")
                        }
                        source.cancel()
                        destination.cancel()
                    } else if !isComplete {
                        self.pipe(from: source, to: destination)
                    }
                }))
            } else if !isComplete {
                self.pipe(from: source, to: destination)
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
        print("Proxy session stopped for \(self.cn) on port \(self.port)")
    }
    
    private func findIdentity(cn: String) throws -> SecIdentity {
        if let identity = HardwareManager.shared.getIdentity(for: cn, context: PKIClient.shared.activeLAContext) {
            return identity
        }
        throw NSError(domain: "ZTA", code: 2, userInfo: [NSLocalizedDescriptionKey: "Identità per \(cn) non trovata"])
    }
    
    private func buildTLSParameters(for cn: String) throws -> NWParameters {
        let identity = try findIdentity(cn: cn)
        let tlsOptions = NWProtocolTLS.Options()
        
        sec_protocol_options_set_local_identity(
            tlsOptions.securityProtocolOptions,
            sec_identity_create(identity)!
        )
        
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
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 60.0
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            #if os(macOS)
            await MainActor.run {
                NSApp.activate(ignoringOtherApps: true)
            }
            #endif
            let reason = "Consenti a ZTA Agent di avviare il tunnel MongoDB per \(cn)"
            let success = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            guard success else {
                throw NSError(domain: "ZTA", code: 401, userInfo: [NSLocalizedDescriptionKey: "Autenticazione biometrica fallita"])
            }
            PKIClient.shared.activeLAContext = context
        } else {
            print("Biometrics not configured or available on system. Proceeding with bypass (dev context).")
        }
        
        lock.lock()
        defer { lock.unlock() }
        
        var port = nextPort
        while sessions.values.contains(where: { $0.port == port }) {
            port += 1
        }
        nextPort = port + 1
        
        let session = MongoProxySession(cn: cn, port: port, ttl: ttl)
        try session.start()
        
        sessions[session.sessionToken] = session
        
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
        
        if sessions.isEmpty {
            PKIClient.shared.activeLAContext = nil
            print("No active session, biometric context removed.")
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
