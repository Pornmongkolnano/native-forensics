import AppKit
import ForensicsCore

@MainActor
enum CaseIntegrityPanelService {
    private static var activePanels: [UUID: NSSavePanel] = [:]

    static func chooseDestination(format: CaseIntegrityReportFormat) async -> URL? {
        let panel = NSSavePanel()
        let id = UUID()
        panel.title = "Export Case Integrity Report"
        panel.message = "Create a new report outside case storage and evidence. Existing files cannot be replaced. Host paths are omitted unless explicitly selected in the audit view."
        panel.nameFieldStringValue = "Case Integrity Audit.\(format == .json ? "json" : "md")"
        panel.prompt = "Export Report"
        panel.canCreateDirectories = true; panel.isExtensionHidden = false
        activePanels[id] = panel
        defer { activePanels[id] = nil }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let completion: (NSApplication.ModalResponse) -> Void = { response in
                    continuation.resume(returning: response == .OK ? panel.url : nil)
                }
                if let window = NSApp.orderedWindows.first(where: { $0.isVisible && !($0 is NSPanel) && $0.sheetParent == nil && $0.attachedSheet == nil }) {
                    panel.beginSheetModal(for: window, completionHandler: completion)
                } else { panel.begin(completionHandler: completion) }
            }
        } onCancel: { Task { @MainActor in activePanels[id]?.cancel(nil) } }
    }
}
