import SwiftUI

struct ContentView: View {
    @State private var cn: String = "paolo.roselli"
    @State private var status = "Pronto."
    @State private var isWorking = false

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill")
                .resizable().frame(width: 50, height: 60).foregroundColor(.blue)
            
            Text("ZTA Native Agent").font(.headline)
            
            TextField("Common Name", text: $cn).textFieldStyle(.roundedBorder).padding(.horizontal)
            
            HStack {
                Button("Enroll Hardware") { runEnroll() }.buttonStyle(.borderedProminent)
                Button("Test Envoy") { runTest() }.buttonStyle(.bordered)
            }.disabled(isWorking)
            
            ScrollView {
                Text(status)
                    .font(.system(.caption, design: .monospaced))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Color.gray.opacity(0.1))
            .cornerRadius(5)
            .padding(.horizontal)
        }
        .padding().frame(width: 400, height: 350)
    }

    func runEnroll() {
        isWorking = true; status = "[*] Richiesta TouchID..."
        Task {
            do {
                let res = try await PKIClient.shared.enroll(cn: cn, role: "admin", department: "IT")
                status = "[✓] \(res)"
            } catch { status = "[!] Errore: \(error.localizedDescription)" }
            isWorking = false
        }
    }

    func runTest() {
        isWorking = true; status = "[*] Connessione mTLS..."
        Task {
            do {
                let res = try await PKIClient.shared.testAuthentication(cn: cn)
                status = "[✓] \(res)"
            } catch { status = "[!] Errore mTLS: \(error.localizedDescription)" }
            isWorking = false
        }
    }
}

#Preview {
    ContentView()
}
