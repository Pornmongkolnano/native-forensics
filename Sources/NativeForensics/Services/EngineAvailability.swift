import Foundation

/// A cheap packaging check before spending time hashing a large source image.
/// The engine client still performs its stricter identity/launch validation.
enum EngineAvailability {
    static func issue(for helperURL: URL) -> String? {
        guard helperURL.isFileURL,
              let attributes = try? FileManager.default.attributesOfItem(atPath: helperURL.path),
              attributes[.type] as? FileAttributeType == .typeRegular else {
            return "The native engine helper is missing or is not a regular file. Reinstall the complete NativeForensics app bundle, or rebuild it with script/build_and_run.sh. Your case and evidence can still be opened."
        }
        guard FileManager.default.isExecutableFile(atPath: helperURL.path) else {
            return "The native engine helper is not executable. Reinstall the complete NativeForensics app bundle, or rebuild it with script/build_and_run.sh. Your case and evidence can still be opened."
        }
        return nil
    }
}
