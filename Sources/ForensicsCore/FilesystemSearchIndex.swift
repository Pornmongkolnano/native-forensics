import Foundation

/// An immutable, bounded snapshot for path searches outside the UI actor.
/// The original entries and order are retained; timestamps and evidence bytes
/// are never transformed by this presentation-only index.
public struct FilesystemSearchIndex: Sendable {
    public static let maximumEntries = 50_000

    private let files: [FilesystemEntry]

    public init(files: [FilesystemEntry]) {
        self.files = files.count <= Self.maximumEntries
            ? files : Array(files.prefix(Self.maximumEntries))
    }

    public var count: Int { files.count }

    /// Preserves the app's Foundation localized, case-insensitive substring
    /// behavior, including Unicode. Call from a cancellable background task.
    public func rows(matching query: String) throws -> [FilesystemEntry] {
        try Task.checkCancellation()
        guard !query.isEmpty else { return files }

        var matching: [FilesystemEntry] = []
        for (offset, file) in files.enumerated() {
            if offset.isMultiple(of: 128) { try Task.checkCancellation() }
            if file.path.localizedCaseInsensitiveContains(query) {
                matching.append(file)
            }
        }
        try Task.checkCancellation()
        return matching
    }
}
