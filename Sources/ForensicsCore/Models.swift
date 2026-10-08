import Foundation

public enum ImageContainer: String, Codable, Sendable, CaseIterable {
    case raw
    case ewf
    case unknown
}

public enum FileHashScope {
    /// A container-file hash, never the logical/decompressed image hash.
    public static let selectedFileBytes = "selected-file-bytes"
}

public struct InspectionProgress: Codable, Sendable {
    public let bytesRead: Int64
    public let totalBytes: Int64
    public let fraction: Double

    public init(bytesRead: Int64, totalBytes: Int64, fraction: Double) {
        self.bytesRead = bytesRead
        self.totalBytes = totalBytes
        self.fraction = fraction
    }
}

public struct InspectedImage: Codable, Sendable {
    public let sourceURL: URL
    public let byteCount: Int64
    public let sha256: String
    public let container: ImageContainer
    public let filesystemHint: String?
    public let hashScope: String

    // Local provenance is deliberately not persisted. Deserialized inspection
    // results must be inspected again before being added to a case.
    var sourceIdentity: SourceIdentity? = nil

    private enum CodingKeys: String, CodingKey {
        case sourceURL, byteCount, sha256, container, filesystemHint, hashScope
    }

    public init(
        sourceURL: URL,
        byteCount: Int64,
        sha256: String,
        container: ImageContainer,
        filesystemHint: String?,
        hashScope: String = FileHashScope.selectedFileBytes
    ) {
        self.sourceURL = sourceURL
        self.byteCount = byteCount
        self.sha256 = sha256
        self.container = container
        self.filesystemHint = filesystemHint
        self.hashScope = hashScope
    }
}

public struct EvidenceRecord: Codable, Sendable, Equatable {
    public let id: UUID
    public let sourcePath: String
    public let byteCount: Int64
    public let sha256: String
    public let container: ImageContainer
    public let filesystemHint: String?
    public let addedAt: Date
    public let hashScope: String

    public init(
        id: UUID = UUID(),
        sourcePath: String,
        byteCount: Int64,
        sha256: String,
        container: ImageContainer,
        filesystemHint: String?,
        addedAt: Date = Date(),
        hashScope: String = FileHashScope.selectedFileBytes
    ) {
        self.id = id
        self.sourcePath = sourcePath
        self.byteCount = byteCount
        self.sha256 = sha256
        self.container = container
        self.filesystemHint = filesystemHint
        self.addedAt = addedAt
        self.hashScope = hashScope
    }
}

public struct CaseManifest: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let id: UUID
    public let name: String
    public let createdAt: Date
    public let evidence: [EvidenceRecord]
    /// Present only after an explicit schema 1 → 2 migration.
    public let provenance: CaseManifestProvenance?

    public init(id: UUID = UUID(), name: String, createdAt: Date = Date(), evidence: [EvidenceRecord] = [],
                schemaVersion: Int = 1, provenance: CaseManifestProvenance? = nil) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.name = name
        self.createdAt = createdAt
        self.evidence = evidence
        self.provenance = provenance
    }
}

public struct ForensicCase: Codable, Sendable {
    public let bundleURL: URL
    public let manifest: CaseManifest

    public init(bundleURL: URL, manifest: CaseManifest) {
        self.bundleURL = bundleURL
        self.manifest = manifest
    }
}

public enum ForensicsError: Error, LocalizedError, Sendable, Equatable {
    case invalidFileURL
    case invalidSource(String)
    case sourceChanged
    case invalidCaseName
    case caseAlreadyExists
    case invalidCase(String)
    case duplicateEvidence
    case staleCase
    case invalidInspection(String)
    case io(String)

    public var errorDescription: String? {
        switch self {
        case .invalidFileURL:
            "Choose a local file or folder."
        case .invalidSource(let reason):
            "Cannot inspect this source: \(reason)"
        case .sourceChanged:
            "The source changed during or after inspection. Inspect it again before adding it to a case."
        case .invalidCaseName:
            "Use a case name with 1–100 characters, without path separators or control characters."
        case .caseAlreadyExists:
            "A case already exists at this destination. Choose another name or open the existing case."
        case .invalidCase(let reason):
            "Cannot open this case: \(reason)"
        case .duplicateEvidence:
            "This source path is already recorded in the case."
        case .staleCase:
            "The case changed since it was opened. Reopen it before adding evidence."
        case .invalidInspection(let reason):
            "Cannot add this inspection: \(reason)"
        case .io(let reason):
            "File operation failed: \(reason)"
        }
    }
}
