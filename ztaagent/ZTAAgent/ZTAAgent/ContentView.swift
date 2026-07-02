import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill")
                .resizable().frame(width: 50, height: 60).foregroundColor(.blue)
            
            Text("ZTA Native Agent").font(.headline)
            
            Text("Running in background on port 9090...")
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            Text("The agent intercepts requests from the web browser to communicate securely with the Mac's Secure Enclave.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundColor(.gray)
                .padding(.horizontal)
        }
        .padding().frame(width: 400, height: 350)
    }
}

#Preview {
    ContentView()
}
