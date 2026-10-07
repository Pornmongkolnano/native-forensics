import Foundation
import ForensicsCore

/// Presentation views based on a recorded filename, never detected content.
enum FilesystemCategory: String, CaseIterable, Identifiable, Sendable {
    case all, deleted, documents, images, archives, media

    var id: Self { self }

    var title: String {
        switch self {
        case .all: "All Files"
        case .deleted: "Deleted Files"
        case .documents: "Documents"
        case .images: "Images"
        case .archives: "Archives"
        case .media: "Audio & Video"
        }
    }

    var symbol: String {
        switch self {
        case .all: "doc.on.doc"
        case .deleted: "trash"
        case .documents: "doc.text"
        case .images: "photo"
        case .archives: "archivebox"
        case .media: "play.rectangle"
        }
    }

    var help: String {
        switch self {
        case .all: "Browse all recorded filesystem entries for the selected data source."
        case .deleted: "Entries whose filesystem metadata marks them as deleted. Recovery is not guaranteed."
        default: "Filter by filename extension. This view does not identify file content."
        }
    }

    func matches(_ file: FilesystemEntry) -> Bool {
        switch self {
        case .all: return true
        case .deleted: return file.isDeleted
        default: return Self.category(for: file) == self
        }
    }

    static func category(for file: FilesystemEntry) -> Self {
        guard !file.isDirectory else { return .all }
        let suffix = filenameExtension(for: file)
        if documentExtensions.contains(suffix) { return .documents }
        if imageExtensions.contains(suffix) { return .images }
        if archiveExtensions.contains(suffix) { return .archives }
        if mediaExtensions.contains(suffix) { return .media }
        return .all
    }

    static func filenameExtension(for file: FilesystemEntry) -> String {
        // NTFS DATA entries carry a named stream after ':'. Preserve ordinary
        // colon-containing filenames from other filesystems as recorded.
        let filename = file.attributeType == 128
            ? file.name.split(separator: ":", maxSplits: 1).first.map(String.init) ?? file.name
            : file.name
        return (filename as NSString).pathExtension.lowercased()
    }

    /// Keep both category matching and Unicode path search in one cancellable
    /// pass. The common All Files path retains the existing snapshot fast path.
    static func rows(in index: FilesystemSearchIndex, matching query: String, category: Self) throws -> [FilesystemEntry] {
        guard category != .all else { return try index.rows(matching: query) }
        let files = try index.rows(matching: "")
        var matching: [FilesystemEntry] = []
        for (offset, file) in files.enumerated() {
            if offset.isMultiple(of: 128) { try Task.checkCancellation() }
            if category.matches(file), query.isEmpty || file.path.localizedCaseInsensitiveContains(query) {
                matching.append(file)
            }
        }
        try Task.checkCancellation()
        return matching
    }

    private static let documentExtensions: Set<String> = [
        "txt", "md", "pdf", "doc", "docx", "rtf", "odt", "xls", "xlsx", "ods",
        "ppt", "pptx", "odp", "csv", "log", "json", "xml", "html", "htm"
    ]
    private static let imageExtensions: Set<String> = [
        "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "tif", "tiff", "bmp", "svg", "ico"
    ]
    private static let archiveExtensions: Set<String> = [
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz", "tbz", "tbz2", "txz"
    ]
    private static let mediaExtensions: Set<String> = [
        "wav", "mp3", "m4a", "aac", "flac", "ogg", "aif", "aiff", "mp4", "mov", "avi",
        "mkv", "webm", "mpeg", "mpg", "m4v"
    ]
}

enum WorkspaceNavigationSelection: Hashable {
    case overview
    case dataSource(UUID)
    case fileView(FilesystemCategory)
    case caseDetails
    case recovery
    case optical
}
