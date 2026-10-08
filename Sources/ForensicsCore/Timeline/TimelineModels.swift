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
    /// Absent in historical v1 reports. New snapshots carry readable engine
    /// inputs/options as well as the opaque snapshot digest; no host paths.
    public let engineProvenance: TimelineEngineProvenance?
    public let hashScopes: [String: String]?
    public static let currentHashScopes = ["snapshot": "length-framed-serialized-filesystem-snapshot-v1", "selectedContainers": "selected-file-bytes",
        "logicalImage": "logical-image-bytes", "artifactContent": "extracted-file-bytes", "derivedText": "derived-utf8-text-bytes"]

    public init(caseID: UUID, evidenceID: UUID, snapshotSHA256: String, orderedContainerSHA256: [String], logicalImageSHA256: String?, engineVersion: String, engineTimezone: String, snapshotSavedAt: Date, listingStatus: EngineTerminalStatus, historical: Bool, engineProvenance: TimelineEngineProvenance? = nil, hashScopes: [String: String]? = nil) {
        self.caseID = caseID; self.evidenceID = evidenceID; self.snapshotSHA256 = snapshotSHA256
        self.orderedContainerSHA256 = orderedContainerSHA256; self.logicalImageSHA256 = logicalImageSHA256
        self.engineVersion = engineVersion; self.engineTimezone = engineTimezone; self.snapshotSavedAt = snapshotSavedAt
        self.listingStatus = listingStatus; self.historical = historical
        self.engineProvenance = engineProvenance
        self.hashScopes = hashScopes
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
                    snapshotSavedAt: result.savedAt, listingStatus: result.status, historical: historical,
                    engineProvenance: TimelineEngineProvenance(result: result, evidence: evidence), hashScopes: currentHashScopes)
    }

    func validate() throws {
        guard EngineValidation.validHash(snapshotSHA256), !orderedContainerSHA256.isEmpty,
              orderedContainerSHA256.count <= 1024, orderedContainerSHA256.allSatisfy(EngineValidation.validHash),
              logicalImageSHA256.map(EngineValidation.validHash) ?? true,
              EngineValidation.text(engineVersion, maximum: 256), TimeZone(identifier: engineTimezone) != nil,
              snapshotSavedAt.timeIntervalSince1970.isFinite, [.completed, .partial].contains(listingStatus) else {
            throw TimelineError.invalidInput("Invalid timeline snapshot provenance.")
        }
        guard hashScopes == nil || hashScopes == Self.currentHashScopes else { throw TimelineError.invalidInput("Unknown or incomplete timeline hash scopes.") }
        if let provenance = engineProvenance {
            try provenance.options.validate()
            try EngineValidation.image(provenance.image)
            guard provenance.schemaVersion == 1, EngineValidation.text(provenance.patchDigest, maximum: 256),
                  provenance.options.timezone == engineTimezone, provenance.image.imagePaths == nil,
                  provenance.image.logicalSha256 == logicalImageSHA256,
                  !provenance.options.hashLogicalImage || provenance.image.logicalSha256 != nil,
                  provenance.orderedInputs.count == orderedContainerSHA256.count,
                  provenance.orderedInputs.enumerated().allSatisfy({ index, input in
                      input.ordinal == index && input.sha256 == orderedContainerSHA256[index]
                        && input.hashScope == FileHashScope.selectedFileBytes && (input.byteCount.map { $0 >= 0 } ?? true)
                  }), provenance.volumes.count <= 4096, Set(provenance.volumes.map(\.id)).count == provenance.volumes.count,
                  provenance.volumes.allSatisfy({ EngineValidation.text($0.id, maximum: 1024)
                      && EngineValidation.text($0.filesystem, maximum: 128) && $0.offsetBytes >= 0 && $0.blockSize > 0 && $0.blockCount >= 0 }) else {
                throw TimelineError.invalidInput("Invalid readable engine provenance.")
            }
        }
    }
}

public struct TimelineOrderedInput: Codable, Sendable, Equatable {
    public let ordinal: Int
    public let byteCount: Int64?
    public let sha256: String
    public let hashScope: String
}

public struct TimelineEngineProvenance: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let patchDigest: String
    public let options: EngineOptions
    public let image: EngineImageMetadata
    public let orderedInputs: [TimelineOrderedInput]
    public let volumes: [EngineVolume]
    init(result: EnumerationResult, evidence: EvidenceRecord) {
        schemaVersion = result.schemaVersion; patchDigest = result.patchDigest; options = result.options
        image = EngineImageMetadata(imageType: result.image.imageType, logicalSize: result.image.logicalSize,
            sectorSize: result.image.sectorSize, logicalSha256: result.image.logicalSha256)
        orderedInputs = result.sourcePaths.enumerated().map { index, path in
            TimelineOrderedInput(ordinal: index, byteCount: result.sourceIdentities.first(where: { $0.path == path })?.size ?? (index == 0 ? evidence.byteCount : nil),
                sha256: result.sourceFileHashes[path]!, hashScope: FileHashScope.selectedFileBytes)
        }
        volumes = result.volumes
    }
}

public enum TimelineEventKind: String, Codable, Sendable, CaseIterable { case filesystemCreated, filesystemModified, filesystemAccessed, filesystemChanged, browserVisit, downloadStarted, downloadEnded, syslogRecord }

public struct TimelineTextSourceReference: Codable, Sendable, Equatable {
    public let derivedTextSHA256: String
    public let unit: Int
    public let unitKind: String
    public let line: Int
    /// These are UTF-8 offsets in the derived text. With raw-utf8.v1 the
    /// derived text is byte-identical to extracted content, including CR/LF.
    public let utf8Offset: Int
    public let utf8Length: Int
    public init(derivedTextSHA256: String, unit: Int, unitKind: String, line: Int, utf8Offset: Int, utf8Length: Int) {
        self.derivedTextSHA256 = derivedTextSHA256; self.unit = unit; self.unitKind = unitKind; self.line = line
        self.utf8Offset = utf8Offset; self.utf8Length = utf8Length
    }
}

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
    public let sourceReference: TimelineTextSourceReference?
    public let filesystemTimestamp: FilesystemCivilTimestamp?
    public init(id: String, kind: TimelineEventKind, timestamp: TimelineTimestamp, fileID: String, evidencePath: String, title: String, detail: String, isDeleted: Bool = false, parser: String, recordID: String, artifactSHA256: String? = nil, sourceReference: TimelineTextSourceReference? = nil, filesystemTimestamp: FilesystemCivilTimestamp? = nil) {
        self.id = id; self.kind = kind; self.timestamp = timestamp; self.fileID = fileID
        self.evidencePath = evidencePath; self.title = title; self.detail = detail; self.isDeleted = isDeleted
        self.parser = parser; self.recordID = recordID; self.artifactSHA256 = artifactSHA256
        self.sourceReference = sourceReference
        self.filesystemTimestamp = filesystemTimestamp
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
    public let hashScope: String?
    public init(file: VerifiedArtifactFile, role: String) {
        evidencePath = file.evidencePath; fileID = file.fileID; byteCount = file.byteCount; sha256 = file.sha256; self.role = role
        hashScope = "extracted-file-bytes"
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
    public let parserReceipts: [TimelineParserReceipt]?
    public init(binding: TimelineSourceBinding, events: [TimelineEvent], artifactReceipts: [TimelineArtifactReceipt] = [], warnings: [String], coverage: String, aiInterpretation: String? = nil, examinerNotes: String = "", parserReceipts: [TimelineParserReceipt]? = nil) {
        schemaVersion = 1; parserVersion = "timeline.v2"; self.binding = binding; self.events = events
        self.artifactReceipts = artifactReceipts; self.warnings = warnings; self.coverage = coverage
        self.aiInterpretation = aiInterpretation; self.examinerNotes = examinerNotes
        self.parserReceipts = parserReceipts
    }
}

public struct TimelineParserReceipt: Codable, Sendable, Equatable {
    public let parser: String
    public let version: String
    public let parameters: [String: String]
    public let sourceSHA256: String?
    public let derivedTextSHA256: String?
    public let unitCount: Int?
    public let lineCount: Int?
    public let eventCount: Int
    public let sourceHashScope: String?
    public let derivedTextHashScope: String?
    public init(parser: String, version: String, parameters: [String: String], sourceSHA256: String? = nil,
                derivedTextSHA256: String? = nil, unitCount: Int? = nil, lineCount: Int? = nil, eventCount: Int) {
        self.parser = parser; self.version = version; self.parameters = parameters; self.sourceSHA256 = sourceSHA256
        self.derivedTextSHA256 = derivedTextSHA256; self.unitCount = unitCount; self.lineCount = lineCount; self.eventCount = eventCount
        sourceHashScope = sourceSHA256 == nil ? nil : "extracted-file-bytes"
        derivedTextHashScope = derivedTextSHA256 == nil ? nil : "derived-utf8-text-bytes"
    }
}

public enum TimelineLimits {
    public static let maximumFilesystemEvents = 200_000
    public static let maximumBrowserEvents = 20_000
    public static let maximumSyslogEvents = 20_000
    public static let maximumSyslogBytes = 1_048_576
    public static let maximumSyslogLineBytes = 16_384
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
