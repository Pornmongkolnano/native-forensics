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

            Button("Inspect UDF History") { workspace?.inspectSelectedOpticalHistory() }
                .keyboardShortcut("u", modifiers: [.command, .option])
                .disabled(workspace?.canInspectOpticalHistory != true)

            Button("Recover Files from Selected RAW Image") { workspace?.recoverSelectedEvidence() }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(workspace?.canRecoverFiles != true)

            Button("Extract Selected File…") { workspace?.chooseExtractionDestination() }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(workspace?.canExtractFilesystemFile != true)

            Button("Decrypt Selected EFS File…") { workspace?.showEFSKeyInput() }
                .disabled(workspace?.canDecryptSelectedEFSFile != true)

            Button("Export Matching Files…") { workspace?.exportMatchingFilesystemFiles() }
                .keyboardShortcut("e", modifiers: [.command, .option, .shift])
                .disabled(workspace?.canExtractAllMatched != true)

            Button("Cancel Current Job") { workspace?.cancelCurrentJob() }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(workspace?.hasActiveWork != true)

            Button("Analyze with Codex…") { workspace?.openAssistant() }
                .keyboardShortcut("a", modifiers: [.command, .option])
                .disabled(workspace?.canOpenAssistant != true)

            Divider()
            Button("Search Case Content") { workspace?.showContentSearch() }
                .keyboardShortcut("f", modifiers: [.command, .option])
                .disabled(workspace?.currentCase == nil || workspace?.isBusy == true)
            Button("Compare Two Files with Codex") { workspace?.showComparison() }
                .disabled(workspace?.selectedEvidence == nil || workspace?.isBusy == true)
            Button("Recorded Timeline") { workspace?.showTimeline() }
                .disabled(workspace?.selectedEvidence == nil || workspace?.isBusy == true)
            Button("Audit Case Integrity") { workspace?.showCaseIntegrity() }
                .disabled(workspace?.currentCase == nil || workspace?.isBusy == true)
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
