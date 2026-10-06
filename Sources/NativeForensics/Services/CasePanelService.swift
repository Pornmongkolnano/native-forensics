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
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = true
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
        let name = URL(fileURLWithPath: filename).lastPathComponent
        panel.nameFieldStringValue = name.isEmpty || name == "." || name == ".." ? "Extracted file" : name
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        let result = await present(panel)
        // NSSavePanel's delegate is weak; keep validation alive until completion.
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
        NSApp.activate(ignoringOtherApps: true)
        return await withCheckedContinuation { continuation in
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
                          userInfo: [NSLocalizedDescriptionKey: "This path already exists. Choose a new filename; extraction cannot replace files."])
        }
    }
}
