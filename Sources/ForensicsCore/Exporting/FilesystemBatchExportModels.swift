import Foundation

public enum FilesystemBatchExportStatus: String, Codable, Sendable, Equatable {
    case completed, partial, cancelled
}

public struct FilesystemBatchExportEntry: Codable, Sendable, Equatable {
    public let sourceFile: FilesystemEntry
    public let outputFilename: String?
    public let byteCount: Int64?
    public let sha256: String?
    public let errorMessage: String?

    public init(sourceFile: FilesystemEntry, outputFilename: String?, byteCount: Int64?, sha256: String?, errorMessage: String?) {
        self.sourceFile = sourceFile; self.outputFilename = outputFilename
        self.byteCount = byteCount; self.sha256 = sha256; self.errorMessage = errorMessage
    }
}

/// The manifest records exact filesystem records, rather than treating an
/// exported basename as the identity of an evidence file or alternate stream.
public struct FilesystemBatchExportResult: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let destinationPath: String
    public let manifestPath: String
    public let status: FilesystemBatchExportStatus
    public let entries: [FilesystemBatchExportEntry]
    /// Hashes cover each ordered source container file, not a decompressed image.
    public let sourcePaths: [String]
    public let sourceFileHashes: [String: String]
    public let analysisEngineVersion: String
    public let analysisPatchDigest: String
    /// SHA-256 of the current extraction helper executable, verified before
    /// and after the batch. Linked library bytes are outside this hash scope.
    public let extractionHelperSha256: String?
    /// Compatibility accessors refer to enumeration provenance. The JSON uses
    /// explicit analysis names to avoid attributing exports to an older helper.
    public var engineVersion: String { analysisEngineVersion }
    public var patchDigest: String { analysisPatchDigest }
    public let analysisSavedAt: Date?
    public let evidenceTimezone: String
    public var requestedCount: Int { entries.count }
    public var successfulCount: Int { entries.filter { $0.outputFilename != nil && $0.errorMessage == nil }.count }
    public var failedCount: Int { requestedCount - successfulCount }

    public init(destinationPath: String, manifestPath: String, status: FilesystemBatchExportStatus, entries: [FilesystemBatchExportEntry], sourcePaths: [String] = [], sourceFileHashes: [String: String] = [:], engineVersion: String = "", patchDigest: String = "", analysisSavedAt: Date? = nil, evidenceTimezone: String = "UTC", extractionHelperSha256: String? = nil) {
        schemaVersion = 1
        self.destinationPath = destinationPath; self.manifestPath = manifestPath
        self.status = status; self.entries = entries
        self.sourcePaths = sourcePaths; self.sourceFileHashes = sourceFileHashes
        analysisEngineVersion = engineVersion; analysisPatchDigest = patchDigest
        self.extractionHelperSha256 = extractionHelperSha256
        self.analysisSavedAt = analysisSavedAt; self.evidenceTimezone = evidenceTimezone
    }
}

public struct FilesystemBatchExportProgress: Sendable, Equatable {
    public let completedFiles: Int
    public let totalFiles: Int
    public let currentFilename: String?

    public init(completedFiles: Int, totalFiles: Int, currentFilename: String?) {
        self.completedFiles = completedFiles; self.totalFiles = totalFiles; self.currentFilename = currentFilename
    }
}
