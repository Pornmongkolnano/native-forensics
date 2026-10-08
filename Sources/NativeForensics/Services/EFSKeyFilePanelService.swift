import AppKit

enum EFSKeyFileRole: Sendable, Equatable { case privateKey, certificate }

/// Narrow panel bridge. SwiftUI owns file choices; this service owns only each
/// concrete panel and its task's cancellation. It never reads key file bytes.
@MainActor
enum EFSKeyFilePanelService {
    private static var active: [UUID: NSOpenPanel] = [:]

    static func choose(_ role: EFSKeyFileRole) async -> URL? {
        guard !Task.isCancelled else { return nil }
        let panel = NSOpenPanel(), id = UUID()
        panel.title = role == .privateKey ? "Choose RSA Private DER" : "Choose Certificate DER"
        panel.message = role == .privateKey
            ? "Choose an explicit PKCS#1 RSA private key in DER form (up to 64 KiB). PFX, P12, PEM and PKCS#8 are not supported. The key is used for one extraction only."
            : "Choose the DER certificate matching that private key (up to 128 KiB). This operation does not import an identity into a keychain or evaluate certificate trust."
        panel.prompt = "Choose"
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false; panel.resolvesAliases = false
        active[id] = panel; defer { active[id] = nil }
        return await withTaskCancellationHandler {
            guard !Task.isCancelled else { return nil }
            return await withCheckedContinuation { continuation in
                panel.begin { response in continuation.resume(returning: response == .OK ? panel.url : nil) }
            }
        } onCancel: { Task { @MainActor in active[id]?.cancel(nil) } }
    }
}
