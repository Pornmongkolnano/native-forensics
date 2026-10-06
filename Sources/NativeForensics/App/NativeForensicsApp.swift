import AppKit
import Darwin
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
    private var terminationTask: Task<Void, Never>?
    private var terminationSignal: DispatchSourceSignal?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        if let iconURL = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let icon = NSImage(contentsOf: iconURL) {
            NSApp.applicationIconImage = icon
        }
        NSApp.activate(ignoringOtherApps: true)
        // The owned build workflow stops the app with SIGTERM. Route that
        // graceful signal through the same cancellation/drain path as Quit.
        Darwin.signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler {
            Task { @MainActor in NSApp.terminate(nil) }
        }
        source.resume()
        terminationSignal = source
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard terminationTask == nil else { return .terminateLater }
        let lifecycle = WorkspaceLifecycle.shared
        lifecycle.prepareForTermination()
        CasePanelService.cancelActivePanels()
        guard lifecycle.hasActiveWork else { return .terminateNow }
        terminationTask = Task {
            await lifecycle.shutdownAll()
            sender.reply(toApplicationShouldTerminate: true)
            terminationTask = nil
        }
        return .terminateLater
    }
}

private struct WorkbenchWindow: View {
    @State private var workspace = WorkspaceStore()
    @AppStorage("workbenchAppearance") private var appearance = "system"

    var body: some View {
        ContentView(workspace: workspace)
            .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
            .focusedSceneValue(\.forensicWorkspace, workspace)
            .onAppear { WorkspaceLifecycle.shared.register(workspace) }
            .onOpenURL { workspace.openCase(at: $0) }
            .onDisappear { WorkspaceLifecycle.shared.close(workspace) }
    }
}
