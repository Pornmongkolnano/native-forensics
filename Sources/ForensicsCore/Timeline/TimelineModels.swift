import CryptoKit
import Foundation

public enum TimelineError: Error, LocalizedError, Sendable, Equatable {
    case invalidInput(String), unsupported(String), inconsistentSnapshot(String), limitExceeded(String), sourceChanged, publication(String)
    public var errorDescription: String? {
        switch self {
        case .invalidInput(let text), .unsupported(let text), .inconsistentSnapshot(let text), .limitExceeded(let text), .publication(let text): text
        case .sourceChanged: "The artifact bytes or recorded evidence binding changed. The timeline was rejected."
        }
    }
}

/// A recorded snapshot reference, never a claim that source bytes were freshly read.
/// Host source paths are absent from reports; file paths are paths inside evidence.
public struct TimelineSourceBinding: Codable, Sendable, Equatable {
    public let caseID: UUID
    public let evidenceID: UUID
    public let snapshotSHA256: String
    public let orderedContainerSHA256: [String]
    public let logicalImageSHA256: String?
    public let engineVersion: String
    public let engineTimezone: String
    public let snapshotSavedAt: Date
    public let listingStatus: EngineTerminalStatus
    public let historical: Bool

    public init(caseID: UUID, evidenceID: UUID, snapshotSHA256: String, orderedContainerSHA256: [String], logicalImageSHA256: String?, engineVersion: String, engineTimezone: String, snapshotSavedAt: Date, listingStatus: EngineTerminalStatus, historical: Bool) {
        self.caseID = caseID; self.evidenceID = evidenceID; self.snapshotSHA256 = snapshotSHA256
        self.orderedContainerSHA256 = orderedContainerSHA256; self.logicalImageSHA256 = logicalImageSHA256
        self.engineVersion = engineVersion; self.engineTimezone = engineTimezone; self.snapshotSavedAt = snapshotSavedAt
        self.listingStatus = listingStatus; self.historical = historical
    }

    public static func make(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult, historical: Bool) throws -> Self {
        try EngineValidation.result(result)
        guard evidence.hashScope == FileHashScope.selectedFileBytes, result.sourcePaths.first == evidence.sourcePath,
              result.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
              result.sourceIdentities.first.map({ $0.size == evidence.byteCount }) ?? true else { throw TimelineError.sourceChanged }
        var hasher = SHA256()
        func append<T: Encodable>(_ value: T) throws {
            let bytes = try TimelineCoding.encode(value)
            hasher.update(data: Data(String(bytes.count).utf8)); hasher.update(data: Data([0])); hasher.update(data: bytes)
        }
        let hashes = result.sourcePaths.map { result.sourceFileHashes[$0]! }
        try append("NativeForensics.timeline-filesystem-snapshot.v1")
        try append(result.schemaVersion); try append(evidence.byteCount)
        try append(EngineImageMetadata(imageType: result.image.imageType, logicalSize: result.image.logicalSize, sectorSize: result.image.sectorSize, logicalSha256: result.image.logicalSha256))
        try append(result.engineVersion); try append(result.patchDigest); try append(result.options)
        try append(result.status); try append(result.savedAt); try append(hashes); try append(result.volumes)
        for file in result.files { try Task.checkCancellation(); try append(file) }
        return Self(caseID: caseID, evidenceID: evidence.id, snapshotSHA256: TimelineCoding.hex(hasher.finalize()),
                    orderedContainerSHA256: hashes, logicalImageSHA256: result.image.logicalSha256,
                    engineVersion: result.engineVersion, engineTimezone: result.options.timezone,
                    snapshotSavedAt: result.savedAt, listingStatus: result.status, historical: historical)
    }

    func validate() throws {
        guard EngineValidation.validHash(snapshotSHA256), !orderedContainerSHA256.isEmpty,
              orderedContainerSHA256.count <= 1024, orderedContainerSHA256.allSatisfy(EngineValidation.validHash),
              logicalImageSHA256.map(EngineValidation.validHash) ?? true,
              EngineValidation.text(engineVersion, maximum: 256), TimeZone(identifier: engineTimezone) != nil,
              snapshotSavedAt.timeIntervalSince1970.isFinite, [.completed, .partial].contains(listingStatus) else {
            throw TimelineError.invalidInput("Invalid timeline snapshot provenance.")
        }
    }
}

public enum TimelineEventKind: String, Codable, Sendable, CaseIterable { case filesystemCreated, filesystemModified, filesystemAccessed, filesystemChanged, browserVisit, downloadStarted, downloadEnded }

public struct TimelineEvent: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let kind: TimelineEventKind
    public let timestamp: TimelineTimestamp
    public let fileID: String
    public let evidencePath: String
    public let title: String
    public let detail: String
    public let isDeleted: Bool
    public let parser: String
    /// Artifact row ID or filesystem locator; kept distinct from event identity.
    public let recordID: String
    public let artifactSHA256: String?
    public init(id: String, kind: TimelineEventKind, timestamp: TimelineTimestamp, fileID: String, evidencePath: String, title: String, detail: String, isDeleted: Bool = false, parser: String, recordID: String, artifactSHA256: String? = nil) {
        self.id = id; self.kind = kind; self.timestamp = timestamp; self.fileID = fileID
        self.evidencePath = evidencePath; self.title = title; self.detail = detail; self.isDeleted = isDeleted
        self.parser = parser; self.recordID = recordID; self.artifactSHA256 = artifactSHA256
    }
}

public struct VerifiedArtifactFile: Codable, Sendable, Equatable {
    /// Runtime-only path to extracted bytes. Never included in exported timeline reports.
    public let url: URL
    public let fileID: String
    public let evidencePath: String
    public let byteCount: Int64
    public let sha256: String
    public init(url: URL, fileID: String, evidencePath: String, byteCount: Int64, sha256: String) {
        self.url = url; self.fileID = fileID; self.evidencePath = evidencePath; self.byteCount = byteCount; self.sha256 = sha256
    }
}

/// Explicit complete artifact set from one selected evidence listing/extraction.
/// A known WAL in the listing must be supplied, even when the caller thinks it empty.
public struct VerifiedBrowserArtifact: Sendable {
    public let binding: TimelineSourceBinding
    public let database: VerifiedArtifactFile
    public let wal: VerifiedArtifactFile?
    public let shm: VerifiedArtifactFile?
    public let expectedWAL: Bool
    public let expectedSHM: Bool
    public init(binding: TimelineSourceBinding, database: VerifiedArtifactFile, wal: VerifiedArtifactFile? = nil, shm: VerifiedArtifactFile? = nil, expectedWAL: Bool = false, expectedSHM: Bool = false) {
        self.binding = binding; self.database = database; self.wal = wal; self.shm = shm
        self.expectedWAL = expectedWAL; self.expectedSHM = expectedSHM
    }
}

public struct TimelineArtifactReceipt: Codable, Sendable, Equatable {
    public let evidencePath: String
    public let fileID: String
    public let byteCount: Int64
    public let sha256: String
    public let role: String
    public init(file: VerifiedArtifactFile, role: String) {
        evidencePath = file.evidencePath; fileID = file.fileID; byteCount = file.byteCount; sha256 = file.sha256; self.role = role
    }
}

public struct TimelineReport: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let parserVersion: String
    public let binding: TimelineSourceBinding
    public let events: [TimelineEvent]
    public let artifactReceipts: [TimelineArtifactReceipt]
    public let warnings: [String]
    public let coverage: String
    /// Deliberately separate from deterministic parser observations.
    public let aiInterpretation: String?
    public let examinerNotes: String
    public init(binding: TimelineSourceBinding, events: [TimelineEvent], artifactReceipts: [TimelineArtifactReceipt] = [], warnings: [String], coverage: String, aiInterpretation: String? = nil, examinerNotes: String = "") {
        schemaVersion = 1; parserVersion = "timeline.v1"; self.binding = binding; self.events = events
        self.artifactReceipts = artifactReceipts; self.warnings = warnings; self.coverage = coverage
        self.aiInterpretation = aiInterpretation; self.examinerNotes = examinerNotes
    }
}

public enum TimelineLimits {
    public static let maximumFilesystemEvents = 200_000
    public static let maximumBrowserEvents = 20_000
    public static let maximumReportBytes = 64 * 1_048_576
    public static let maximumNotesBytes = 32_768
}

enum TimelineCoding {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }
    static func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 { bytes.map { String(format: "%02x", $0) }.joined() }
    static func digest<T: Encodable>(_ value: T) throws -> String { hex(SHA256.hash(data: try encode(value))) }
}
