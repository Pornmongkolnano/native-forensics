import CryptoKit
import Foundation

/// Rebuildable local text, independent of manifest/listing and examiner records.
/// Byte offsets below are UTF-16 offsets in decoder output, never image offsets.
public enum ContentIndexFileStatus: String, Codable, Sendable, CaseIterable {
    case indexed, skipped, failed, pending
}

public struct ContentIndexLimits: Codable, Sendable, Equatable {
    public var maximumFiles: Int
    public var maximumFileBytes: Int64
    public var maximumInputBytes: Int64
    public var maximumTextBytes: Int
    public var timeoutSeconds: Double
    public static let maximumSources = 128
    public static let maximumListingEntries = 50_000
    public static let maximumListingBytes = 64 * 1_048_576
    public static let maximumSerializedBytes = 32 * 1_048_576
    public static let maximumQueryBytes = 4_096
    public static let maximumHits = 200

    public init(maximumFiles: Int = 512, maximumFileBytes: Int64 = 32 * 1_048_576,
                maximumInputBytes: Int64 = 256 * 1_048_576, maximumTextBytes: Int = 16 * 1_048_576,
                timeoutSeconds: Double = 600) {
        self.maximumFiles = maximumFiles; self.maximumFileBytes = maximumFileBytes
        self.maximumInputBytes = maximumInputBytes; self.maximumTextBytes = maximumTextBytes
        self.timeoutSeconds = timeoutSeconds
    }
    func validate() throws {
        guard (1...512).contains(maximumFiles), (1...32 * 1_048_576).contains(maximumFileBytes),
              (1...256 * 1_048_576).contains(maximumInputBytes), (1...16 * 1_048_576).contains(maximumTextBytes),
              timeoutSeconds.isFinite, timeoutSeconds > 0, timeoutSeconds <= 600 else { throw ContentIndexError.invalidSnapshot }
    }
}

/// Limits the aggregate listing set retained for decoding. A declined listing
/// is an explicitly uncovered source, not a claim that its files were searched.
public struct ContentIndexListingBudget: Sendable {
    private var entries = 0, bytes = 0
    public init() {}
    public mutating func admit(_ result: EnumerationResult) throws -> Bool {
        guard [.completed, .partial].contains(result.status),
              result.files.count <= ContentIndexLimits.maximumListingEntries - entries else { return false }
        // A public in-memory DTO is not necessarily a bounded engine/cache
        // response. Reject a conservative serialized upper bound before JSON
        // encoding could allocate hundreds of MiB merely to decline the input.
        var upper = 1_048_576 + result.files.count * 1_024 + result.volumes.count * 512 + result.sourceIdentities.count * 512
        func add(_ text: String) { upper += 6 * text.utf8.count + 2 }
        for file in result.files {
            add(file.id); add(file.path); add(file.name)
            if upper > ContentIndexLimits.maximumListingBytes - bytes { return false }
        }
        for warning in result.warnings { add(warning) }
        for path in result.sourcePaths { add(path) }
        for path in result.sourceFileHashes.keys { add(path) }
        for path in result.image.imagePaths ?? [] { add(path) }
        for identity in result.sourceIdentities { add(identity.path) }
        for volume in result.volumes { add(volume.id); add(volume.filesystem) }
        add(result.engineVersion); add(result.patchDigest); add(result.options.timezone); add(result.options.imageType)
        guard upper <= ContentIndexLimits.maximumListingBytes - bytes else { return false }
        try EngineValidation.result(result)
        let count = try CaseWorkCoding.encode(result).count
        guard count <= ContentIndexLimits.maximumListingBytes - bytes else { return false }
        entries += result.files.count; bytes += count; return true
    }
}

public struct ContentIndexInput: Sendable, Equatable {
    public let evidence: EvidenceRecord
    public let result: EnumerationResult?
    public init(evidence: EvidenceRecord, result: EnumerationResult?) { self.evidence = evidence; self.result = result }
}

public struct ContentIndexSource: Codable, Sendable, Equatable, Identifiable {
    public let evidenceID: UUID
    public let selectedContainerSHA256: String
    public let selectedContainerByteCount: Int64
    public let orderedContainerSHA256: [String]
    public let listingSHA256: String?
    public let listingEntryCount: Int
    public let listingIsPartial: Bool
    public var id: UUID { evidenceID }

    private enum CodingKeys: String, CodingKey {
        case evidenceID, selectedContainerSHA256, selectedContainerByteCount, orderedContainerSHA256, listingSHA256, listingEntryCount, listingIsPartial
    }
    init(evidenceID: UUID, selectedContainerSHA256: String, selectedContainerByteCount: Int64,
         orderedContainerSHA256: [String], listingSHA256: String?, listingEntryCount: Int, listingIsPartial: Bool) {
        self.evidenceID = evidenceID; self.selectedContainerSHA256 = selectedContainerSHA256
        self.selectedContainerByteCount = selectedContainerByteCount; self.orderedContainerSHA256 = orderedContainerSHA256
        self.listingSHA256 = listingSHA256; self.listingEntryCount = listingEntryCount; self.listingIsPartial = listingIsPartial
    }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        evidenceID = try values.decode(UUID.self, forKey: .evidenceID)
        selectedContainerSHA256 = try values.decode(String.self, forKey: .selectedContainerSHA256)
        selectedContainerByteCount = try values.decode(Int64.self, forKey: .selectedContainerByteCount)
        listingSHA256 = try values.decodeIfPresent(String.self, forKey: .listingSHA256)
        listingEntryCount = try values.decode(Int.self, forKey: .listingEntryCount)
        listingIsPartial = try values.decode(Bool.self, forKey: .listingIsPartial)
        var valuesArray = try values.nestedUnkeyedContainer(forKey: .orderedContainerSHA256), hashes: [String] = []
        while !valuesArray.isAtEnd {
            guard hashes.count < 1_024 else { throw ContentIndexError.invalidSnapshot }
            let hash = try valuesArray.decode(String.self)
            guard EngineValidation.validHash(hash) else { throw ContentIndexError.invalidSnapshot }
            hashes.append(hash)
        }
        orderedContainerSHA256 = hashes
    }

    public static func make(_ input: ContentIndexInput) throws -> Self {
        let evidence = input.evidence
        guard EngineValidation.validHash(evidence.sha256), evidence.byteCount >= 0,
              evidence.hashScope == FileHashScope.selectedFileBytes else { throw ContentIndexError.invalidSnapshot }
        guard let result = input.result, [.completed, .partial].contains(result.status) else {
            return Self(evidenceID: evidence.id, selectedContainerSHA256: evidence.sha256,
                selectedContainerByteCount: evidence.byteCount, orderedContainerSHA256: [evidence.sha256],
                listingSHA256: nil, listingEntryCount: 0, listingIsPartial: true)
        }
        try EngineValidation.result(result)
        guard result.sourcePaths.first == evidence.sourcePath,
              result.sourceFileHashes[evidence.sourcePath] == evidence.sha256 else { throw ContentIndexError.sourceChanged }
        // Canonical digest excludes host paths, identities and diagnostics. All
        // entries participate exactly once, rather than once per indexed file.
        var hash = SHA256()
        func append<T: Encodable>(_ value: T) throws {
            let bytes = try CaseWorkCoding.encode(value)
            hash.update(data: Data(String(bytes.count).utf8)); hash.update(data: Data([0])); hash.update(data: bytes)
        }
        try append("NativeForensics.content-listing.v1"); try append(result.options)
        try append(result.engineVersion); try append(result.patchDigest); try append(result.status)
        try append(result.volumes)
        // EngineResultStore persists ISO-8601 at whole-second precision. The
        // same live job and its reopened listing must have the same identity.
        try append(Date(timeIntervalSince1970: floor(result.savedAt.timeIntervalSince1970)))
        let hashes = try result.sourcePaths.map { path in
            guard let value = result.sourceFileHashes[path], EngineValidation.validHash(value) else { throw ContentIndexError.invalidSnapshot }
            return value
        }
        try append(hashes)
        for entry in result.files { try Task.checkCancellation(); try append(entry) }
        return Self(evidenceID: evidence.id, selectedContainerSHA256: evidence.sha256,
            selectedContainerByteCount: evidence.byteCount, orderedContainerSHA256: hashes,
            listingSHA256: CaseWorkCoding.hex(hash.finalize()), listingEntryCount: result.files.count,
            listingIsPartial: result.status != .completed)
    }
}

public struct ContentIndexDocument: Codable, Sendable, Equatable, Identifiable {
    public let evidenceID: UUID
    public let file: FilesystemEntry
    public let locatorSHA256: String
    public let status: ContentIndexFileStatus
    public let reason: String?
    public let contentSHA256: String?
    public let derivedTextSHA256: String?
    public let textPages: [DocumentTextPage]
    public let textIsComplete: Bool
    public var id: String { evidenceID.uuidString.lowercased() + ":" + file.id }

    private enum CodingKeys: String, CodingKey {
        case evidenceID, file, locatorSHA256, status, reason, contentSHA256, derivedTextSHA256, textPages, textIsComplete
    }
    init(evidenceID: UUID, file: FilesystemEntry, locatorSHA256: String, status: ContentIndexFileStatus, reason: String?,
         contentSHA256: String?, derivedTextSHA256: String?, textPages: [DocumentTextPage], textIsComplete: Bool) {
        self.evidenceID = evidenceID; self.file = file; self.locatorSHA256 = locatorSHA256; self.status = status
        self.reason = reason; self.contentSHA256 = contentSHA256; self.derivedTextSHA256 = derivedTextSHA256
        self.textPages = textPages; self.textIsComplete = textIsComplete
    }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        evidenceID = try values.decode(UUID.self, forKey: .evidenceID)
        file = try values.decode(FilesystemEntry.self, forKey: .file); try EngineValidation.file(file)
        locatorSHA256 = try values.decode(String.self, forKey: .locatorSHA256)
        status = try values.decode(ContentIndexFileStatus.self, forKey: .status)
        reason = try values.decodeIfPresent(String.self, forKey: .reason)
        contentSHA256 = try values.decodeIfPresent(String.self, forKey: .contentSHA256)
        derivedTextSHA256 = try values.decodeIfPresent(String.self, forKey: .derivedTextSHA256)
        textIsComplete = try values.decode(Bool.self, forKey: .textIsComplete)
        var pages = try values.nestedUnkeyedContainer(forKey: .textPages), decoded: [DocumentTextPage] = []
        var bytes = 0
        while !pages.isAtEnd {
            guard decoded.count < DocumentLimits.maximumPages else { throw ContentIndexError.invalidSnapshot }
            let page = try pages.decode(DocumentTextPage.self)
            bytes += page.text.utf8.count
            guard bytes <= DocumentLimits.maximumTextBytes else { throw ContentIndexError.invalidSnapshot }
            decoded.append(page)
        }
        textPages = decoded
    }

    static func locator(_ file: FilesystemEntry) throws -> String {
        struct Address: Encodable {
            let id: String; let path: String; let fsOffsetBytes: Int64; let metaAddress: UInt64
            let attributeType: Int32?; let attributeID: Int32?
        }
        return try CaseWorkCoding.digest(Address(id: file.id, path: file.path, fsOffsetBytes: file.fsOffsetBytes,
            metaAddress: file.metaAddress, attributeType: file.attributeType, attributeID: file.attributeID))
    }

    static func make(evidenceID: UUID, file: FilesystemEntry, status: ContentIndexFileStatus,
                     reason: String? = nil, contentSHA256: String? = nil,
                     pages: [DocumentTextPage] = [], complete: Bool = false) throws -> Self {
        Self(evidenceID: evidenceID, file: file, locatorSHA256: try locator(file), status: status,
            reason: reason, contentSHA256: contentSHA256,
            derivedTextSHA256: status == .indexed ? try CaseWorkCoding.digest(pages) : nil,
            textPages: pages, textIsComplete: complete)
    }
}

public struct CaseContentIndexSnapshot: Codable, Sendable, Equatable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let caseID: UUID
    public let builtAt: Date
    public let decoderContract: String
    public let decoderBinarySHA256: String
    public let limits: ContentIndexLimits
    public let sources: [ContentIndexSource]
    public let documents: [ContentIndexDocument]
    public let omittedRegularFiles: Int
    public let skippedDirectories: Int
    public var indexedCount: Int { documents.filter { $0.status == .indexed }.count }
    public var skippedCount: Int { documents.filter { $0.status == .skipped }.count }
    public var failedCount: Int { documents.filter { $0.status == .failed }.count }
    public var pendingCount: Int { documents.filter { $0.status == .pending }.count + omittedRegularFiles }
    public var missingListingCount: Int { sources.filter { $0.listingSHA256 == nil }.count }
    public var isPartial: Bool {
        skippedCount > 0 || failedCount > 0 || pendingCount > 0 || missingListingCount > 0
            || sources.contains(where: { $0.listingIsPartial }) || documents.contains(where: { !$0.textIsComplete })
    }
    public var textByteCount: Int { documents.reduce(0) { $0 + $1.textPages.reduce(0) { $0 + $1.text.utf8.count } } }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, id, caseID, builtAt, decoderContract, decoderBinarySHA256, limits, sources, documents, omittedRegularFiles, skippedDirectories
    }
    init(schemaVersion: Int, id: UUID, caseID: UUID, builtAt: Date, decoderContract: String, decoderBinarySHA256: String,
         limits: ContentIndexLimits, sources: [ContentIndexSource], documents: [ContentIndexDocument], omittedRegularFiles: Int, skippedDirectories: Int) {
        self.schemaVersion = schemaVersion; self.id = id; self.caseID = caseID; self.builtAt = builtAt
        self.decoderContract = decoderContract; self.decoderBinarySHA256 = decoderBinarySHA256; self.limits = limits
        self.sources = sources; self.documents = documents; self.omittedRegularFiles = omittedRegularFiles; self.skippedDirectories = skippedDirectories
    }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try values.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == 1 else { throw ContentIndexError.invalidSnapshot }
        id = try values.decode(UUID.self, forKey: .id); caseID = try values.decode(UUID.self, forKey: .caseID)
        builtAt = try values.decode(Date.self, forKey: .builtAt)
        decoderContract = try values.decode(String.self, forKey: .decoderContract)
        decoderBinarySHA256 = try values.decode(String.self, forKey: .decoderBinarySHA256)
        limits = try values.decode(ContentIndexLimits.self, forKey: .limits); try limits.validate()
        var sourceValues = try values.nestedUnkeyedContainer(forKey: .sources), decodedSources: [ContentIndexSource] = []
        while !sourceValues.isAtEnd {
            guard decodedSources.count < ContentIndexLimits.maximumSources else { throw ContentIndexError.invalidSnapshot }
            decodedSources.append(try sourceValues.decode(ContentIndexSource.self))
        }
        sources = decodedSources
        var documentValues = try values.nestedUnkeyedContainer(forKey: .documents), decodedDocuments: [ContentIndexDocument] = []
        var textBytes = 0
        while !documentValues.isAtEnd {
            guard decodedDocuments.count < limits.maximumFiles else { throw ContentIndexError.invalidSnapshot }
            let document = try documentValues.decode(ContentIndexDocument.self)
            textBytes += document.textPages.reduce(0) { $0 + $1.text.utf8.count }
            guard textBytes <= limits.maximumTextBytes else { throw ContentIndexError.invalidSnapshot }
            decodedDocuments.append(document)
        }
        documents = decodedDocuments
        omittedRegularFiles = try values.decode(Int.self, forKey: .omittedRegularFiles)
        skippedDirectories = try values.decode(Int.self, forKey: .skippedDirectories)
    }

    public func validate() throws {
        try limits.validate()
        guard schemaVersion == 1, builtAt.timeIntervalSince1970.isFinite,
              decoderContract == "NFDocumentDecoder.document-analysis.v1", EngineValidation.validHash(decoderBinarySHA256),
              sources.count <= ContentIndexLimits.maximumSources, documents.count <= limits.maximumFiles,
              omittedRegularFiles >= 0, omittedRegularFiles <= ContentIndexLimits.maximumListingEntries, skippedDirectories >= 0,
              skippedDirectories <= ContentIndexLimits.maximumListingEntries, Set(sources.map(\.evidenceID)).count == sources.count,
              Set(documents.map(\.id)).count == documents.count, textByteCount <= limits.maximumTextBytes else {
            throw ContentIndexError.invalidSnapshot
        }
        for source in sources {
            guard EngineValidation.validHash(source.selectedContainerSHA256), source.selectedContainerByteCount >= 0,
                  !source.orderedContainerSHA256.isEmpty, source.orderedContainerSHA256.count <= 1_024,
                  source.orderedContainerSHA256.allSatisfy(EngineValidation.validHash),
                  source.orderedContainerSHA256.first == source.selectedContainerSHA256,
                  (0...50_000).contains(source.listingEntryCount),
                  source.listingSHA256.map(EngineValidation.validHash) ?? (source.listingEntryCount == 0 && source.listingIsPartial) else {
                throw ContentIndexError.invalidSnapshot
            }
            guard documents.filter({ $0.evidenceID == source.evidenceID }).count <= source.listingEntryCount else { throw ContentIndexError.invalidSnapshot }
        }
        let listed = sources.reduce(0) { $0 + $1.listingEntryCount }
        guard listed <= ContentIndexLimits.maximumListingEntries,
              listed == documents.count + omittedRegularFiles + skippedDirectories else { throw ContentIndexError.invalidSnapshot }
        for document in documents {
            try Task.checkCancellation(); try EngineValidation.file(document.file)
            guard !document.file.isDirectory, sources.contains(where: { $0.evidenceID == document.evidenceID && $0.listingSHA256 != nil }),
                  document.locatorSHA256 == (try ContentIndexDocument.locator(document.file)),
                  (document.reason?.utf8.count ?? 0) <= 256,
                  document.textPages.count <= DocumentLimits.maximumPages else { throw ContentIndexError.invalidSnapshot }
            if document.status == .indexed {
                guard document.file.size <= limits.maximumFileBytes,
                      document.contentSHA256.map(EngineValidation.validHash) == true,
                      document.derivedTextSHA256 == (try CaseWorkCoding.digest(document.textPages)),
                      !document.textPages.isEmpty,
                      document.textPages.reduce(0, { $0 + $1.text.utf8.count }) <= DocumentLimits.maximumTextBytes,
                      document.textPages.map(\.pageNumber) == document.textPages.map(\.pageNumber).sorted(),
                      Set(document.textPages.map(\.pageNumber)).count == document.textPages.count,
                      document.textPages.allSatisfy({ $0.pageNumber > 0 && $0.pageNumber <= 1_000_000 && ($0.referenceLabel?.utf8.count ?? 0) <= 4_096 }),
                      !document.textIsComplete || !document.textPages.contains(where: { $0.isTruncated }),
                      document.reason == (document.textIsComplete ? nil : "PARTIAL_DECODER_COVERAGE") else { throw ContentIndexError.invalidSnapshot }
            } else {
                guard document.textPages.isEmpty, document.contentSHA256 == nil, document.derivedTextSHA256 == nil,
                      !document.textIsComplete else { throw ContentIndexError.invalidSnapshot }
                let reasons: [String]
                switch document.status {
                case .skipped: reasons = ["FILE_BYTE_LIMIT", "UNSUPPORTED_CONTENT", "NO_TEXT_LAYER_OR_BODY"]
                case .failed: reasons = ["DECODE_FAILED", "EXTRACTION_OR_DECODE_FAILED"]
                case .pending: reasons = ["INPUT_BYTE_BUDGET", "DERIVED_TEXT_BUDGET"]
                case .indexed: reasons = []
                }
                guard let reason = document.reason, reasons.contains(reason) else { throw ContentIndexError.invalidSnapshot }
            }
        }
    }
}

public struct ContentIndexReference: Sendable, Equatable {
    public let snapshotID: UUID
    public let evidenceID: UUID
    public let listingSHA256: String
    public let file: FilesystemEntry
    public let locatorSHA256: String
    public let orderedContainerSHA256: [String]
    public let contentSHA256: String
    public let derivedTextSHA256: String
    public let decoderBinarySHA256: String
    public let pageNumber: Int
    public let utf16Offset: Int
    public let utf16Length: Int
    public let referenceLabel: String?
    public let referenceKind: DocumentTextReferenceKind?
}

public struct CaseContentSearchHit: Sendable, Equatable, Identifiable {
    public let id: Int
    public let reference: ContentIndexReference
    public let snippet: String
}

public struct CaseContentSearchOutcome: Sendable, Equatable {
    public let query: String
    public let hits: [CaseContentSearchHit]
    public let hitLimitReached: Bool
    public let coverageIsPartial: Bool
}

public enum ContentIndexError: Error, LocalizedError, Sendable, Equatable {
    case invalidSnapshot, sourceChanged, staleGeneration, unsafeStore, storageLimit, timeout, publicationUncertain
    public var errorDescription: String? {
        switch self {
        case .invalidSnapshot: "The content index is malformed, outside its budgets, or uses an unsupported schema."
        case .sourceChanged: "The recorded source bytes or listing changed. Reanalyze the source before rebuilding the content index."
        case .staleGeneration: "A different content index was saved while this rebuild was running. The saved generation was preserved. Reload before rebuilding."
        case .unsafeStore: "The content index storage or case changed. Reopen the case; the previous index was preserved."
        case .storageLimit: "The content index exceeds its bounded storage budget. The previous index was preserved."
        case .timeout: "The content index reached its configured rebuild time budget (maximum 600 seconds). The previous index was preserved."
        case .publicationUncertain: "Index publication reached atomic commit, but final durability or case validation failed. Reload the index to inspect the saved generation."
        }
    }
}
