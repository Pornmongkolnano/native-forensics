import Foundation

/// A deliberately bounded reader profile, rather than a claim of general UDF support.
public struct UDFInspectionOptions: Codable, Sendable, Equatable {
    public var maximumSourceBytes: Int64
    public var maximumSnapshots: Int
    public var maximumFiles: Int
    public var maximumFileBytes: Int64
    public var maximumPayloadBytes: Int64
    public var maximumMetadataBlocks: Int
    public var maximumDirectoryBytes: Int
    public var tailSearchBlocks: Int
    public var timeoutSeconds: Double

    public init(maximumSourceBytes: Int64 = 32 * 1_024 * 1_024 * 1_024,
                maximumSnapshots: Int = 32, maximumFiles: Int = 5_000,
                maximumFileBytes: Int64 = 512 * 1_024 * 1_024,
                maximumPayloadBytes: Int64 = 2 * 1_024 * 1_024 * 1_024,
                maximumMetadataBlocks: Int = 50_000,
                maximumDirectoryBytes: Int = 8 * 1_024 * 1_024,
                tailSearchBlocks: Int = 4_096, timeoutSeconds: Double = 300) {
        self.maximumSourceBytes = maximumSourceBytes; self.maximumSnapshots = maximumSnapshots
        self.maximumFiles = maximumFiles; self.maximumFileBytes = maximumFileBytes
        self.maximumPayloadBytes = maximumPayloadBytes; self.maximumMetadataBlocks = maximumMetadataBlocks
        self.maximumDirectoryBytes = maximumDirectoryBytes; self.tailSearchBlocks = tailSearchBlocks
        self.timeoutSeconds = timeoutSeconds
    }

    func validate() throws {
        guard (1...(32 * 1_024 * 1_024 * 1_024)).contains(maximumSourceBytes),
              (1...32).contains(maximumSnapshots), (1...5_000).contains(maximumFiles),
              (1...(512 * 1_024 * 1_024)).contains(maximumFileBytes),
              (1...(2 * 1_024 * 1_024 * 1_024)).contains(maximumPayloadBytes),
              (1...50_000).contains(maximumMetadataBlocks),
              (1...(8 * 1_024 * 1_024)).contains(maximumDirectoryBytes),
              (1...4_096).contains(tailSearchBlocks), timeoutSeconds.isFinite,
              (0.001...600).contains(timeoutSeconds) else { throw UDFError.invalidOptions }
    }
}

public struct UDFInspectionProgress: Sendable {
    public let stage: String
    public let completedBytes: Int64
    public let totalBytes: Int64
    public let files: Int
    public init(stage: String, completedBytes: Int64, totalBytes: Int64, files: Int = 0) {
        self.stage = stage; self.completedBytes = completedBytes; self.totalBytes = totalBytes; self.files = files
    }
}

public enum UDFEntryState: String, Codable, Sendable {
    case current
    /// The child FID need not itself have its deleted bit set.
    case historicalDeletedAncestor
    case historical
    case fidDeleted
}

public struct UDFSourceExtent: Codable, Sendable, Equatable {
    /// Absolute byte range in the original selected raw source, including inline allocations.
    public let offset: Int64
    public let byteCount: Int64
    public let allocation: String
    public init(offset: Int64, byteCount: Int64, allocation: String = "recorded") {
        self.offset = offset; self.byteCount = byteCount; self.allocation = allocation
    }
}

public struct UDFTimestamp: Codable, Sendable, Equatable {
    public let rawHex: String
    public let sourceOffset: Int64
    public let type: UInt16
    public let timezoneMinutes: Int?
    /// Nil for an unspecified/agreement timezone; the raw fields remain available.
    public let utcDate: Date?
    public let microsecond: Int
    public init(rawHex: String, sourceOffset: Int64, type: UInt16,
                timezoneMinutes: Int?, utcDate: Date?, microsecond: Int) {
        self.rawHex = rawHex; self.sourceOffset = sourceOffset; self.type = type
        self.timezoneMinutes = timezoneMinutes; self.utcDate = utcDate; self.microsecond = microsecond
    }
}

public struct UDFEntryTimestamps: Codable, Sendable, Equatable {
    public let access: UDFTimestamp
    public let modification: UDFTimestamp
    public let attribute: UDFTimestamp
    public let creation: UDFTimestamp?
    public init(access: UDFTimestamp, modification: UDFTimestamp, attribute: UDFTimestamp, creation: UDFTimestamp?) {
        self.access = access; self.modification = modification; self.attribute = attribute; self.creation = creation
    }
}

public struct UDFDeletedAncestorProof: Codable, Sendable, Equatable {
    public let originalPath: String
    public let latestSnapshotID: String
    public let fidSourceOffset: Int64
    public let fidCharacteristics: UInt8
    public let nullICB: Bool
    public let rawNameHex: String
    public init(originalPath: String, latestSnapshotID: String, fidSourceOffset: Int64,
                fidCharacteristics: UInt8, nullICB: Bool, rawNameHex: String) {
        self.originalPath = originalPath; self.latestSnapshotID = latestSnapshotID
        self.fidSourceOffset = fidSourceOffset; self.fidCharacteristics = fidCharacteristics
        self.nullICB = nullICB; self.rawNameHex = rawNameHex
    }
}

public struct UDFEntryAddress: Codable, Sendable, Equatable {
    public let logicalBlock: UInt32
    public let partitionReference: UInt16
    public let sourceOffset: Int64
    public let tagIdentifier: UInt16
    public init(logicalBlock: UInt32, partitionReference: UInt16, sourceOffset: Int64, tagIdentifier: UInt16) {
        self.logicalBlock = logicalBlock; self.partitionReference = partitionReference
        self.sourceOffset = sourceOffset; self.tagIdentifier = tagIdentifier
    }
}

public struct UDFFileEntry: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let originalPath: String
    public let state: UDFEntryState
    public let fidCharacteristics: UInt8
    public let fidSourceOffset: Int64
    public let deletedAncestorProof: [UDFDeletedAncestorProof]
    public let byteCount: Int64
    public let sha256: String
    public let icb: UDFEntryAddress
    public let sourceExtents: [UDFSourceExtent]
    public let timestamps: UDFEntryTimestamps
    public let snapshotIDs: [String]
    /// Other recorded namespace paths for this same ICB/content across linked VAT states.
    public let historicalPaths: [String]
    public var name: String { (originalPath as NSString).lastPathComponent }
    public init(id: String, originalPath: String, state: UDFEntryState, fidCharacteristics: UInt8,
                fidSourceOffset: Int64, deletedAncestorProof: [UDFDeletedAncestorProof], byteCount: Int64,
                sha256: String, icb: UDFEntryAddress, sourceExtents: [UDFSourceExtent],
                timestamps: UDFEntryTimestamps, snapshotIDs: [String], historicalPaths: [String] = []) {
        self.id = id; self.originalPath = originalPath; self.state = state
        self.fidCharacteristics = fidCharacteristics; self.fidSourceOffset = fidSourceOffset
        self.deletedAncestorProof = deletedAncestorProof; self.byteCount = byteCount; self.sha256 = sha256
        self.icb = icb; self.sourceExtents = sourceExtents; self.timestamps = timestamps; self.snapshotIDs = snapshotIDs
        self.historicalPaths = historicalPaths
    }
}

public struct UDFSnapshot: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let vatICBSourceOffset: Int64
    public let previousVATLogicalBlock: UInt32?
    public let mappedBlockCount: Int
    public let namespaceFileCount: Int
    public let modification: UDFTimestamp
    public init(id: String, vatICBSourceOffset: Int64, previousVATLogicalBlock: UInt32?,
                mappedBlockCount: Int, namespaceFileCount: Int, modification: UDFTimestamp) {
        self.id = id; self.vatICBSourceOffset = vatICBSourceOffset
        self.previousVATLogicalBlock = previousVATLogicalBlock; self.mappedBlockCount = mappedBlockCount
        self.namespaceFileCount = namespaceFileCount; self.modification = modification
    }
}

public struct UDFInspectionResult: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let caseID: UUID
    public let sourceEvidenceID: UUID
    public let sourceSHA256: String
    public let sourceByteCount: Int64
    public let jobID: UUID
    public let parserVersion: String
    public let profile: String
    public let volumeIdentifier: String
    public let udfRevision: String
    public let blockSize: Int
    public let latestSnapshotID: String
    public let snapshots: [UDFSnapshot]
    public let entries: [UDFFileEntry]
    public let deletedAncestors: [UDFDeletedAncestorProof]
    public let limitations: [String]
    public let options: UDFInspectionOptions
    public let savedAt: Date
    public init(schemaVersion: Int = 1, caseID: UUID, sourceEvidenceID: UUID, sourceSHA256: String,
                sourceByteCount: Int64, jobID: UUID = UUID(), parserVersion: String = "native-udf-1",
                profile: String = "raw-2048-udf201-physical-virtual-vat", volumeIdentifier: String,
                udfRevision: String, blockSize: Int = 2048, latestSnapshotID: String,
                snapshots: [UDFSnapshot], entries: [UDFFileEntry], deletedAncestors: [UDFDeletedAncestorProof],
                limitations: [String], options: UDFInspectionOptions, savedAt: Date = Date()) {
        self.schemaVersion = schemaVersion; self.caseID = caseID; self.sourceEvidenceID = sourceEvidenceID
        self.sourceSHA256 = sourceSHA256; self.sourceByteCount = sourceByteCount; self.jobID = jobID
        self.parserVersion = parserVersion; self.profile = profile; self.volumeIdentifier = volumeIdentifier
        self.udfRevision = udfRevision; self.blockSize = blockSize; self.latestSnapshotID = latestSnapshotID
        self.snapshots = snapshots; self.entries = entries; self.deletedAncestors = deletedAncestors
        self.limitations = limitations; self.options = options; self.savedAt = savedAt
    }
}

public struct UDFExportReceipt: Codable, Sendable, Equatable {
    public let caseID: UUID
    public let sourceEvidenceID: UUID
    public let jobID: UUID
    public let entryID: String
    public let destinationPath: String
    public let byteCount: Int64
    public let sha256: String
    public let sourceSHA256: String
    public let exportedAt: Date
    public init(caseID: UUID, sourceEvidenceID: UUID, jobID: UUID, entryID: String, destinationPath: String,
                byteCount: Int64, sha256: String, sourceSHA256: String, exportedAt: Date = Date()) {
        self.caseID = caseID; self.sourceEvidenceID = sourceEvidenceID; self.jobID = jobID
        self.entryID = entryID; self.destinationPath = destinationPath; self.byteCount = byteCount
        self.sha256 = sha256; self.sourceSHA256 = sourceSHA256; self.exportedAt = exportedAt
    }
}

public enum UDFError: Error, LocalizedError, Sendable, Equatable {
    case unsupported(String), malformed(String), limitExceeded(String), invalidOptions, invalidResult(String), timeout
    public var errorDescription: String? {
        switch self {
        case .unsupported(let reason): "Unsupported UDF profile: \(reason)"
        case .malformed(let reason): "Invalid UDF metadata: \(reason)"
        case .limitExceeded(let reason): "UDF inspection stopped at its safety limit: \(reason)"
        case .invalidOptions: "The UDF inspection limits are invalid."
        case .invalidResult(let reason): "Cannot use this UDF result: \(reason)"
        case .timeout: "UDF inspection exceeded its time limit."
        }
    }
}
