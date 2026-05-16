import SwiftUI

@main
struct ZTAAgentApp: App {
    init() {
        // Avvia il server locale per Python
        LocalAPIServer.shared.start()
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
