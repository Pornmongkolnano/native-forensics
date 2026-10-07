import AppKit
import UniformTypeIdentifiers

/// Only AppKit owns panel presentation. SwiftUI owns the resulting case state.
@MainActor
enum CasePanelService {
    private static let caseType = UTType(exportedAs: "io.github.pornmongkolnano.nativeforensics.case", conformingTo: .package)
    private static var activePanels: [UUID: NSSavePanel] = [:]

    static func cancelActivePanels() {
        for panel in Array(activePanels.values) { panel.cancel(nil) }
    }

    static func newCaseDestination() async -> URL? {
        let panel = NSSavePanel()
        panel.title = "Create Forensic Case"
        panel.message = "Choose where to store the case manifest. Keep the case separate from your evidence source."
        panel.nameFieldLabel = "Case name:"
        panel.nameFieldStringValue = "Untitled Case.nativecase"
        panel.allowedContentTypes = [caseType]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = true
        return await present(panel)
    }

    static func existingCase() async -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Open Forensic Case"
        panel.message = "Choose a .nativecase case folder."
        panel.prompt = "Open Case"
        // Configure types/packages before explicit eligibility: macOS 27
        // rewrites canChooseFiles/canChooseDirectories in those setters.
        panel.treatsFilePackagesAsDirectories = false
        panel.allowedContentTypes = [caseType, .folder]
        // Registered .nativecase folders are packages, so permit both their
        // file representation and legacy folders. CaseStore validates the URL.
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        return await present(panel)
    }

    static func imageSource() async -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Inspect Disk Image"
        panel.message = "The selected file is read without modification. SHA-256 covers this file's bytes; split image sets are not combined."
        panel.prompt = "Inspect Image"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        return await present(panel)
    }

    static func newExtractedFile(named filename: String) async -> URL? {
        let panel = NSSavePanel()
        let delegate = NewFilePanelDelegate()
        panel.delegate = delegate
        panel.title = "Extract File"
        panel.message = "Create a new output file outside the evidence image. Existing files cannot be replaced. SHA-256 will describe the extracted bytes."
        panel.prompt = "Extract"
        panel.nameFieldLabel = "Output filename:"
        // NSSavePanel displays a colon as a slash on macOS. Suggest a plain
        // filename for NTFS streams while retaining the original path in metadata.
        let name = URL(fileURLWithPath: filename).lastPathComponent.replacingOccurrences(of: ":", with: " - ")
        panel.nameFieldStringValue = name.isEmpty || name == "." || name == ".." ? "Extracted file" : name
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        // NSSavePanel's delegate is weak; keep validation alive until completion.
        withExtendedLifetime(delegate) {}
        return result
    }

    static func newFilesystemBatchDestination() async -> URL? {
        let panel = NSSavePanel()
        let delegate = NewFilePanelDelegate()
        panel.delegate = delegate
        panel.title = "Export Matching Files to a New Folder"
        panel.message = "Enter a new folder name outside the evidence source and case. All matching regular files, including rows on other table pages, are exported with hash receipts. Existing folders cannot be replaced."
        panel.nameFieldLabel = "New export folder:"
        panel.nameFieldStringValue = "Filesystem Export"
        panel.prompt = "Export Files"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        withExtendedLifetime(delegate) {}
        return result
    }

    static func newOpticalFile(named filename: String) async -> URL? {
        let panel = NSSavePanel()
        let delegate = NewFilePanelDelegate()
        panel.delegate = delegate
        panel.title = "Export Recorded UDF File"
        panel.message = "Create a new file from the recorded UDF extents after source and payload verification. Existing files cannot be replaced."
        panel.prompt = "Export UDF File"
        panel.nameFieldStringValue = URL(fileURLWithPath: filename).lastPathComponent.replacingOccurrences(of: ":", with: " - ")
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        withExtendedLifetime(delegate) {}
        return result
    }

    static func newOpticalReport() async -> URL? {
        let panel = NSSavePanel()
        let delegate = NewFilePanelDelegate()
        panel.delegate = delegate
        panel.title = "Export UDF Inventory Report"
        panel.message = "Create a new Markdown report with recorded paths, current and historical states, UDF timestamp fields, source extents and hashes."
        panel.prompt = "Export Report"
        panel.nameFieldStringValue = "UDF Inventory Report.md"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        withExtendedLifetime(delegate) {}
        return result
    }

    /// Folder-only configuration is kept separate for pure AppKit regression
    /// checks. Types/package policies come first; selection eligibility is last
    /// because panel presentation can otherwise derive file-only eligibility.
    static func timelineReportParentPanel() -> NSOpenPanel {
        let panel = NSOpenPanel()
        panel.title = "Export Timeline Reports"
        panel.message = "Choose a parent folder outside evidence and case bundles. A new report folder will be created."
        panel.prompt = "Choose Folder"
        panel.treatsFilePackagesAsDirectories = false
        panel.allowedContentTypes = [.folder]
        panel.resolvesAliases = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        return panel
    }

    static func timelineReportParent() async -> URL? {
        await present(timelineReportParentPanel())
    }

    static func newRecoveryReport() async -> URL? {
        let panel = NSSavePanel()
        let delegate = NewFilePanelDelegate()
        panel.delegate = delegate
        panel.title = "Export Recovery Report"
        panel.message = "Create a new Markdown report with source and recovered-file hashes, decoder results and saved examiner assessments. Unsaved note drafts are excluded."
        panel.prompt = "Export Report"
        panel.nameFieldStringValue = "Recovery Report.md"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        withExtendedLifetime(delegate) {}
        return result
    }

    static func newRecoveredFile(named filename: String) async -> URL? {
        let panel = NSSavePanel()
        let delegate = NewFilePanelDelegate()
        panel.delegate = delegate
        panel.title = "Export Recovered File"
        panel.message = "Export verified historical recovered bytes to a new file. Existing files cannot be replaced. This does not establish that the original file was deleted."
        panel.prompt = "Export"
        panel.nameFieldStringValue = URL(fileURLWithPath: filename).lastPathComponent.replacingOccurrences(of: ":", with: " - ")
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        withExtendedLifetime(delegate) {}
        return result
    }

    static func additionalImageSegments() async -> [URL]? {
        let panel = NSOpenPanel()
        panel.title = "Add Image Segments"
        panel.message = "Select only the additional segments belonging to this image. Review and reorder them in the workbench before analysis. No sibling files are added automatically."
        panel.prompt = "Add Segments"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        let panelID = UUID()
        activePanels[panelID] = panel
        defer { activePanels[panelID] = nil }
        NSApp.activate(ignoringOtherApps: true)
        return await withCheckedContinuation { continuation in
            let completion: (NSApplication.ModalResponse) -> Void = { response in
                continuation.resume(returning: response == .OK ? panel.urls : nil)
            }
            if let window = presentationWindow() {
                window.makeKeyAndOrderFront(nil)
                panel.beginSheetModal(for: window, completionHandler: completion)
            } else {
                panel.begin(completionHandler: completion)
            }
        }
    }

    private static func present(_ panel: NSSavePanel) async -> URL? {
        let panelID = UUID()
        activePanels[panelID] = panel
        defer { activePanels[panelID] = nil }
        NSApp.activate(ignoringOtherApps: true)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let completion: (NSApplication.ModalResponse) -> Void = { response in
                    continuation.resume(returning: response == .OK ? panel.url : nil)
                }
                if let window = presentationWindow() {
                    window.makeKeyAndOrderFront(nil)
                    panel.beginSheetModal(for: window, completionHandler: completion)
                } else {
                    panel.begin(completionHandler: completion)
                }
            }
        } onCancel: {
            // Cancel only this task's panel; other workbench windows retain
            // their own dialogs. Resuming its completion also drains shutdown.
            Task { @MainActor in activePanels[panelID]?.cancel(nil) }
        }
    }

    /// A recently dismissed panel can remain key momentarily. Never attach a
    /// subsequent panel to that hidden panel or another sheet.
    private static func presentationWindow() -> NSWindow? {
        func isContentWindow(_ window: NSWindow) -> Bool {
            window.isVisible && !window.isMiniaturized && !(window is NSPanel)
                && window.sheetParent == nil && window.attachedSheet == nil
        }
        if let key = NSApp.keyWindow, isContentWindow(key) { return key }
        if let main = NSApp.mainWindow, isContentWindow(main) { return main }
        return NSApp.orderedWindows.first(where: isContentWindow)
    }
}

private final class NewFilePanelDelegate: NSObject, NSOpenSavePanelDelegate {
    func panel(_ sender: Any, validate url: URL) throws {
        guard !FileManager.default.fileExists(atPath: url.path),
              (try? FileManager.default.destinationOfSymbolicLink(atPath: url.path)) == nil else {
            throw NSError(domain: "NativeForensics.Export", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "This path already exists. Choose a new output name; exports cannot replace files or folders."])
        }
    }
}
