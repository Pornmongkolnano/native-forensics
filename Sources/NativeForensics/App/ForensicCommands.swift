import AppKit
import SwiftUI

private struct WorkspaceFocusedValueKey: FocusedValueKey {
    typealias Value = WorkspaceStore
}

extension FocusedValues {
    var forensicWorkspace: WorkspaceStore? {
        get { self[WorkspaceFocusedValueKey.self] }
        set { self[WorkspaceFocusedValueKey.self] = newValue }
    }
}

struct ForensicCommands: Commands {
    @FocusedValue(\.forensicWorkspace) private var workspace
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appTermination) {
            Button("Quit Native Forensics") {
                if let delegate = AppDelegate.current { delegate.requestGracefulTermination() }
                else { NSApp.terminate(nil) }
            }
            .keyboardShortcut("q")
        }
        CommandGroup(replacing: .newItem) {
            Button("New Case…") {
                if let workspace { workspace.createCase() }
                else { openWindow(id: "workbench") }
            }
            .keyboardShortcut("n")
            .disabled(workspace?.isBusy == true)

            Button("Open Case…") { workspace?.chooseCase() }
                .keyboardShortcut("o")
                .disabled(workspace == nil || workspace?.isBusy == true)

            Button("New Workbench Window") { openWindow(id: "workbench") }
                .keyboardShortcut("n", modifiers: [.command, .shift])
        }

        CommandMenu("Evidence") {
            Button("Inspect Disk Image…") { workspace?.chooseImage() }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(workspace?.canInspectImage != true)

            Button("Analyze Selected Filesystem") { workspace?.analyzeSelectedImage() }
                .keyboardShortcut("a", modifiers: [.command, .shift])
                .disabled(workspace?.canAnalyzeFilesystem != true)

            Button("Extract Selected File…") { workspace?.chooseExtractionDestination() }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(workspace?.canExtractFilesystemFile != true)

            Button("Cancel Current Job") { workspace?.cancelCurrentJob() }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(workspace?.isInspecting != true && workspace?.isEngineRunning != true && workspace?.assistant.isWorking != true)

            Button("Analyze with Codex…") { workspace?.openAssistant() }
                .keyboardShortcut("a", modifiers: [.command, .option])
                .disabled(workspace?.canOpenAssistant != true)
        }

        CommandGroup(after: .sidebar) {
            Button("Toggle Evidence Inspector") {
                workspace?.showInspector.toggle()
            }
            .keyboardShortcut("i", modifiers: [.command, .option])
            .disabled(workspace == nil)
        }
    }
}
