import SwiftUI

@main
struct ZTAAgentApp: App {
    init() {
        // Start the local server for Python
        LocalAPIServer.shared.start()
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
