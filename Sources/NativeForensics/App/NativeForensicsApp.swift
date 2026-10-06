import AppKit
import SwiftUI

@main
struct NativeForensicsApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup("Native Forensics", id: "workbench") {
            WorkbenchWindow()
        }
        .defaultSize(width: 1180, height: 760)
        .commands { ForensicCommands() }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

private struct WorkbenchWindow: View {
    @State private var workspace = WorkspaceStore()

    var body: some View {
        ContentView(workspace: workspace)
            .focusedSceneValue(\.forensicWorkspace, workspace)
            .onOpenURL { workspace.openCase(at: $0) }
            .onDisappear { workspace.cancelCurrentJob() }
    }
}
