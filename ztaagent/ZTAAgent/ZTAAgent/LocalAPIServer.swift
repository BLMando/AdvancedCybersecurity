import Foundation
import Network

class LocalAPIServer {
    static let shared = LocalAPIServer()
    private var listener: NWListener?
    
    func start() {
        do {
            let port = NWEndpoint.Port(rawValue: 9090)!
            listener = try NWListener(using: .tcp, on: port)
            
            listener?.stateUpdateHandler = { state in
                print("[*] API Server State: \(state)")
            }
            
            listener?.newConnectionHandler = { connection in
                self.handleConnection(connection)
            }
            
            listener?.start(queue: .main)
            print("[*] ZTA Agent API listening on localhost:9090")
        } catch {
            print("[!] Failed to start API Server: \(error)")
        }
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: .main)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if let data = data, let request = String(data: data, encoding: .utf8) {
                self.parseRequest(request, connection: connection)
            }
        }
    }
    
    private func parseRequest(_ request: String, connection: NWConnection) {
        let lines = request.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else { return }
        
        let parts = firstLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return }
        
        let method = parts[0]
        let path = parts[1]
        
        if method == "POST" && path.contains("/enroll") {
            self.handleEnroll(request: request, connection: connection)
        } else if method == "POST" && path.contains("/auth") {
            self.handleAuth(request: request, connection: connection)
        } else if method == "POST" && path.contains("/sign") {
            self.handleSign(request: request, connection: connection)
        } else {
            self.sendResponse(body: "{\"error\": \"Not Found\"}", status: "404 Not Found", connection: connection)
        }
    }
    
    private func handleEnroll(request: String, connection: NWConnection) {
        let components = request.components(separatedBy: "\r\n\r\n")
        guard components.count > 1, let bodyData = components[1].data(using: .utf8) else {
            self.sendResponse(body: "{\"error\": \"Invalid Body\"}", status: "400 Bad Request", connection: connection)
            return
        }
        
        Task {
            do {
                let json = try JSONSerialization.jsonObject(with: bodyData) as? [String: String]
                let cn = json?["common_name"] ?? "unknown"
                let role = json?["role"] ?? "doctor"
                let dept = json?["department"] ?? "Cardiologia"
                
                let result = try await PKIClient.shared.enroll(cn: cn, role: role, department: dept)
                let responseDict = ["status": "success", "message": result]
                if let responseData = try? JSONSerialization.data(withJSONObject: responseDict),
                   let responseString = String(data: responseData, encoding: .utf8) {
                    self.sendResponse(body: responseString, connection: connection)
                }
            } catch {
                self.sendResponse(body: "{\"status\": \"error\", \"message\": \"\(error.localizedDescription)\"}", status: "500 Error", connection: connection)
            }
        }
    }
    
    private func handleSign(request: String, connection: NWConnection) {
        let components = request.components(separatedBy: "\r\n\r\n")
        guard components.count > 1, let bodyData = components[1].data(using: .utf8) else {
            self.sendResponse(body: "{\"error\": \"Invalid Body\"}", status: "400 Bad Request", connection: connection)
            return
        }
        
        Task {
            do {
                let json = try JSONSerialization.jsonObject(with: bodyData) as? [String: String]
                let cn = json?["common_name"] ?? "paolo.roselli"
                guard let dataB64 = json?["data_b64"], let rawData = Data(base64Encoded: dataB64) else {
                    self.sendResponse(body: "{\"status\": \"error\", \"message\": \"Missing data_b64\"}", status: "400 Bad Request", connection: connection)
                    return
                }
                
                print("[*] Richiesta Firma Hardware per: \(cn)")
                let signature = try await HardwareManager.shared.sign(data: rawData, cn: cn)
                let pubKey = try await HardwareManager.shared.getPublicKeyDER(for: cn)
                let pubKeyPEM = "-----BEGIN PUBLIC KEY-----\n\(pubKey.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]))\n-----END PUBLIC KEY-----"
                
                let responseDict = [
                    "status": "success",
                    "signature_b64": signature.base64EncodedString(),
                    "pub_key_pem": pubKeyPEM
                ]
                
                if let responseData = try? JSONSerialization.data(withJSONObject: responseDict),
                   let responseString = String(data: responseData, encoding: .utf8) {
                    self.sendResponse(body: responseString, connection: connection)
                }
            } catch {
                self.sendResponse(body: "{\"status\": \"error\", \"message\": \"\(error.localizedDescription)\"}", status: "500 Error", connection: connection)
            }
        }
    }
    
    private func handleAuth(request: String, connection: NWConnection) {
        let components = request.components(separatedBy: "\r\n\r\n")
        guard components.count > 1, let bodyData = components[1].data(using: .utf8) else {
            self.sendResponse(body: "{\"error\": \"Invalid Body\"}", status: "400 Bad Request", connection: connection)
            return
        }
        
        Task {
            do {
                let json = try JSONSerialization.jsonObject(with: bodyData) as? [String: String]
                let cn = json?["common_name"] ?? "paolo.roselli"
                
                print("[*] Richiesta Auth mTLS per: \(cn)")
                let result = try await PKIClient.shared.testAuthentication(cn: cn)
                let responseDict = ["status": "success", "response": result]
                if let responseData = try? JSONSerialization.data(withJSONObject: responseDict),
                   let responseString = String(data: responseData, encoding: .utf8) {
                    self.sendResponse(body: responseString, connection: connection)
                }
            } catch {
                self.sendResponse(body: "{\"status\": \"error\", \"message\": \"\(error.localizedDescription)\"}", status: "500 Error", connection: connection)
            }
        }
    }
    
    private func sendResponse(body: String, status: String = "200 OK", connection: NWConnection) {
        let bodyData = body.data(using: .utf8) ?? Data()
        let response = "HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(bodyData.count)\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n\(body)"
        connection.send(content: response.data(using: .utf8), completion: .contentProcessed({ _ in
            connection.cancel()
        }))
    }
}
