import AppKit
import Darwin
import ForensicsCore
import SwiftUI

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
    static weak var current: AppDelegate?
    private var terminationTask: Task<Void, Never>?
    private var requestedTerminationTask: Task<Void, Never>?
    private var terminationSignal: DispatchSourceSignal?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.current = self
        WorkEnergyMonitor.shared.start()
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
        source.setEventHandler { [weak self] in
            Task { @MainActor [weak self] in self?.requestGracefulTermination() }
        }
        source.resume()
        terminationSignal = source
    }

    func requestGracefulTermination() {
        guard requestedTerminationTask == nil else { return }
        let lifecycle = WorkspaceLifecycle.shared
        guard UnsavedNotesGuard.confirmDiscardForQuit(count: lifecycle.unsavedNoteCount) else { return }
        lifecycle.discardUnsavedNotes()
        lifecycle.prepareForTermination()
        CasePanelService.cancelActivePanels()
        requestedTerminationTask = Task { [weak self] in
            await ForensicWorkScheduler.shared.close()
            await lifecycle.shutdownAll()
            // Allow SwiftUI's dismissed sheet transition to finish before the
            // AppKit request; never force-kill an in-flight publication.
            for _ in 0..<250 {
                if NSApp.modalWindow == nil && !NSApp.windows.contains(where: { $0.attachedSheet != nil }) { break }
                try? await Task.sleep(for: .milliseconds(20))
            }
            NSApp.terminate(nil)
            self?.requestedTerminationTask = nil
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard terminationTask == nil else { return .terminateLater }
        let lifecycle = WorkspaceLifecycle.shared
        guard UnsavedNotesGuard.confirmDiscardForQuit(count: lifecycle.unsavedNoteCount) else { return .terminateCancel }
        lifecycle.discardUnsavedNotes()
        lifecycle.prepareForTermination()
        CasePanelService.cancelActivePanels()
        guard lifecycle.hasActiveWork else { return .terminateNow }
        terminationTask = Task {
            await ForensicWorkScheduler.shared.close()
            await lifecycle.shutdownAll()
            sender.reply(toApplicationShouldTerminate: true)
            terminationTask = nil
        }
        return .terminateLater
    }

    func applicationWillTerminate(_ notification: Notification) {
        _ = UIInteractionTiming.shared.writeRequestedReport()
        WorkEnergyMonitor.shared.stop()
    }
}

private struct WorkbenchWindow: View {
    @State private var workspace = WorkspaceStore()
    @AppStorage("workbenchAppearance") private var appearance = "system"

    var body: some View {
        ContentView(workspace: workspace)
            .background(UnsavedNotesWindowGuard {
                UnsavedNotesGuard.confirmDiscardForClose(count: workspace.caseWork.retainedDraftCount + workspace.recovery.retainedDraftCount)
            })
            .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
            .focusedSceneValue(\.forensicWorkspace, workspace)
            .onAppear { WorkspaceLifecycle.shared.register(workspace) }
            .onOpenURL { workspace.openCase(at: $0) }
            .onDisappear { WorkspaceLifecycle.shared.close(workspace) }
    }
}
