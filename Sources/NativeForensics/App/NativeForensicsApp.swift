import AppKit
import SwiftUI

@main
struct NativeForensicsApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup("Native Forensics", id: "workbench") {
            WorkbenchWindow()
        }
        .defaultSize(width: 1280, height: 800)
        .commands { ForensicCommands() }

        Settings {
            WorkbenchSettingsView()
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        if let iconURL = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let icon = NSImage(contentsOf: iconURL) {
            NSApp.applicationIconImage = icon
        }
        NSApp.activate(ignoringOtherApps: true)
    }
}

private struct WorkbenchWindow: View {
    @State private var workspace = WorkspaceStore()
    @AppStorage("workbenchAppearance") private var appearance = "system"

    var body: some View {
        ContentView(workspace: workspace)
            .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
            .focusedSceneValue(\.forensicWorkspace, workspace)
            .onOpenURL { workspace.openCase(at: $0) }
            .onDisappear { workspace.cancelCurrentJob() }
    }
}
