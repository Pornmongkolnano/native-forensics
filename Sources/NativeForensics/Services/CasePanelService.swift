import AppKit
import UniformTypeIdentifiers

/// Only AppKit owns panel presentation. SwiftUI owns the resulting case state.
@MainActor
enum CasePanelService {
    private static let caseType = UTType(exportedAs: "io.github.pornmongkolnano.nativeforensics.case", conformingTo: .package)

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
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [caseType]
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

    private static func present(_ panel: NSSavePanel) async -> URL? {
        NSApp.activate(ignoringOtherApps: true)
        return await withCheckedContinuation { continuation in
            let completion: (NSApplication.ModalResponse) -> Void = { response in
                continuation.resume(returning: response == .OK ? panel.url : nil)
            }
            if let window = NSApp.keyWindow ?? NSApp.mainWindow {
                panel.beginSheetModal(for: window, completionHandler: completion)
            } else {
                panel.begin(completionHandler: completion)
            }
        }
    }
}
