import Foundation

enum CodexCLIAvailability {
    static var defaultPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates = ["/opt/homebrew/bin/codex", "/usr/local/bin/codex",
            home.appendingPathComponent("Applications/Codex.app/Contents/Resources/codex").path,
            "/Applications/Codex.app/Contents/Resources/codex"]
        return candidates.first(where: { issue(for: $0) == nil }) ?? ""
    }

    static var configuredPath: String {
        UserDefaults.standard.string(forKey: "codexCLIPath") ?? defaultPath
    }

    static func issue(for path: String) -> String? {
        guard path.hasPrefix("/"), !path.utf8.contains(0),
              !path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return "Choose the installed Codex CLI path in Settings."
        }
        let resolved = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: resolved.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              FileManager.default.isExecutableFile(atPath: resolved.path) else {
            return "Codex CLI was not found or is not executable. Set its installed path in Settings."
        }
        return nil
    }
}
