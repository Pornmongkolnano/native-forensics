import CryptoKit
import Foundation

/// Immutable selection provenance. Host source paths and engine diagnostics are
/// intentionally absent; these hashes describe a recorded job, not current bytes.
public struct CaseWorkBinding: Codable, Equatable, Sendable {
    public let caseID: UUID
    public let evidenceID: UUID
    public let selectedEntry: FilesystemEntry
    public let locatorSHA256: String
    public let entrySHA256: String
    public let snapshotSHA256: String
    public let selectedContainerHash: AssistantScopedHash
    public let selectedContainerByteCount: Int64
    public let containerHashes: [AssistantContainerHash]
    public let logicalImageHash: AssistantScopedHash?
    public let engineVersion: String
    public let patchDigest: String
    public let options: EngineOptions
    public let status: EngineTerminalStatus
    public let snapshotSavedAt: Date
    public let analysisSnapshot: AssistantAnalysisSnapshot
    public let warnings: [String]

    public static func make(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) throws -> Self {
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
        // Incremental canonical components avoid serializing a second copy of
        // the complete, potentially 64 MiB, listing to calculate its identity.
        var digest = SHA256()
        func append<T: Encodable>(_ value: T) throws {
            let data = try CaseWorkCoding.encode(value)
            digest.update(data: Data(String(data.count).utf8)); digest.update(data: Data([0]))
            digest.update(data: data)
        }
        try append("NativeForensics.redacted-filesystem-snapshot.v1")
        try append(result.schemaVersion); try append(context.analysis)
        try append(evidence.byteCount)
        try append(EngineImageMetadata(imageType: result.image.imageType, logicalSize: result.image.logicalSize,
            sectorSize: result.image.sectorSize, logicalSha256: result.image.logicalSha256))
        try append(result.options); try append(context.containerHashes)
        try append(context.logicalImageHash); try append(result.volumes)
        for entry in result.files { try Task.checkCancellation(); try append(entry) }
        return Self(
            caseID: caseID, evidenceID: evidence.id, selectedEntry: file,
            locatorSHA256: try locatorDigest(file), entrySHA256: try CaseWorkCoding.digest(file),
            snapshotSHA256: CaseWorkCoding.hex(digest.finalize()),
            selectedContainerHash: context.selectedContainerHash, selectedContainerByteCount: evidence.byteCount,
            containerHashes: context.containerHashes,
            logicalImageHash: context.logicalImageHash, engineVersion: result.engineVersion,
            patchDigest: result.patchDigest, options: result.options, status: result.status,
            snapshotSavedAt: result.savedAt, analysisSnapshot: context.analysis, warnings: context.warnings
        )
    }

    /// Ignores the recorded snapshot so earlier notes remain discoverable after
    /// reanalysis; includes path/attribute address rather than just an inode ID.
    public func refersToSameFile(as other: Self) -> Bool {
        caseID == other.caseID && evidenceID == other.evidenceID && locatorSHA256 == other.locatorSHA256
    }

    private static func locatorDigest(_ file: FilesystemEntry) throws -> String {
        struct Locator: Encodable {
            let id: String; let path: String; let fsOffsetBytes: Int64
            let metaAddress: UInt64; let attributeType: Int32?; let attributeID: Int32?
        }
        return try CaseWorkCoding.digest(Locator(id: file.id, path: file.path,
            fsOffsetBytes: file.fsOffsetBytes, metaAddress: file.metaAddress,
            attributeType: file.attributeType, attributeID: file.attributeID))
    }

    func validate() throws {
        try EngineValidation.file(selectedEntry); try options.validate()
        guard EngineValidation.validHash(locatorSHA256), EngineValidation.validHash(entrySHA256),
              EngineValidation.validHash(snapshotSHA256),
              locatorSHA256 == (try Self.locatorDigest(selectedEntry)),
              entrySHA256 == (try CaseWorkCoding.digest(selectedEntry)),
              [.completed, .partial].contains(status), snapshotSavedAt.timeIntervalSince1970.isFinite,
              analysisSnapshot.engineVersion == engineVersion, analysisSnapshot.patchDigest == patchDigest,
              analysisSnapshot.status == status, analysisSnapshot.savedAt == snapshotSavedAt,
              analysisSnapshot.timezone == options.timezone, !analysisSnapshot.sourceBytesVerifiedForContent,
              EngineValidation.text(analysisSnapshot.imageType, maximum: 64), analysisSnapshot.logicalImageByteCount >= 0,
              (1...options.maxFiles).contains(analysisSnapshot.enumeratedFileCount),
              (0...1_024).contains(analysisSnapshot.engineWarningCount),
              EngineValidation.text(engineVersion, maximum: 256), EngineValidation.text(patchDigest, maximum: 256),
              !containerHashes.isEmpty, containerHashes.count <= 1_024,
              selectedContainerHash.scope == FileHashScope.selectedFileBytes,
              selectedContainerByteCount >= 0,
              EngineValidation.validHash(selectedContainerHash.sha256),
              containerHashes.enumerated().allSatisfy({ $0.offset == $0.element.index &&
                  $0.element.scope == FileHashScope.selectedFileBytes && EngineValidation.validHash($0.element.sha256) }),
              containerHashes[0].sha256 == selectedContainerHash.sha256,
              logicalImageHash.map({ $0.scope == "logical-image-bytes" && EngineValidation.validHash($0.sha256) }) ?? true,
              warnings.count <= 32, warnings.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) else {
            throw CaseWorkError.invalidRecord
        }
    }
}

public enum AnalysisRetention: String, Codable, Sendable, CaseIterable { case full, digestOnly }
public enum FindingReviewStatus: String, Codable, Sendable, CaseIterable { case unreviewed, verified, rejected }
public enum CaseWorkKind: String, Codable, Sendable, CaseIterable { case analysis, finding, extraction }

public struct AnalysisRecord: Codable, Equatable, Sendable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let createdAt: Date
    public let binding: CaseWorkBinding
    public let retention: AnalysisRetention
    /// Exact app-to-CLI UTF-8 bytes, never a reconstructed or HTTP payload.
    public let prompt: String?
    public let requestSHA256: String
    public let question: String
    public let result: CodexAnalysisResult
    public let cliVersion: String?
    public let promptTemplateVersion: String
    /// CLI execution label is available; the actual provider/model version is
    /// unknown unless a future validated execution receipt supplies it.
    public let modelVersion: String?
    public let contentHash: AssistantScopedHash?
    public let completeContentByteCount: Int64?
    public let disclosedContentByteCount: Int
    public let sourceBytesVerifiedForContentAtRequest: Bool
    public let warnings: [String]

    public static func make(binding: CaseWorkBinding, context: EvidenceAnalysisContext, prompt: String,
        question: String, result: CodexAnalysisResult, retention: AnalysisRetention,
        cliVersion: String? = nil, promptTemplateVersion: String = "1", id: UUID = UUID()) throws -> Self {
        try binding.validate(); try result.response.validate()
        let requestDigest = CaseWorkCoding.hex(SHA256.hash(data: Data(prompt.utf8)))
        guard !prompt.isEmpty, prompt.utf8.count <= CaseWorkStore.maximumRecordBytes,
              requestDigest == result.requestSHA256,
              context.schemaVersion == 1, context.evidenceID == binding.evidenceID,
              context.file == binding.selectedEntry, context.selectedContainerHash == binding.selectedContainerHash,
              context.containerHashes == binding.containerHashes, context.logicalImageHash == binding.logicalImageHash,
              context.analysis.engineVersion == binding.engineVersion, context.analysis.patchDigest == binding.patchDigest,
              context.analysis.status == binding.status, context.analysis.timezone == binding.options.timezone,
              context.analysis.savedAt == binding.snapshotSavedAt,
              context.analysis.imageType == binding.analysisSnapshot.imageType,
              context.analysis.logicalImageByteCount == binding.analysisSnapshot.logicalImageByteCount,
              context.analysis.enumeratedFileCount == binding.analysisSnapshot.enumeratedFileCount,
              context.analysis.engineWarningCount == binding.analysisSnapshot.engineWarningCount else {
            throw CaseWorkError.requestMismatch
        }
        let record = Self(schemaVersion: 1, id: id, createdAt: result.completedAt, binding: binding,
            retention: retention, prompt: retention == .full ? prompt : nil, requestSHA256: requestDigest,
            question: question, result: result, cliVersion: cliVersion, promptTemplateVersion: promptTemplateVersion,
            modelVersion: nil, contentHash: context.textContent?.fullFileHash,
            completeContentByteCount: context.textContent?.completeByteCount,
            disclosedContentByteCount: context.textContent?.includedByteCount ?? 0,
            sourceBytesVerifiedForContentAtRequest: context.analysis.sourceBytesVerifiedForContent,
            warnings: context.warnings)
        try record.validate(); return record
    }

    func validate() throws {
        guard schemaVersion == 1 else { throw CaseWorkError.unsupportedVersion }
        try binding.validate(); try result.response.validate()
        guard createdAt.timeIntervalSince1970.isFinite, createdAt == result.completedAt,
              EngineValidation.validHash(requestSHA256), result.requestSHA256 == requestSHA256,
              EngineValidation.text(question, maximum: 8_192),
              EngineValidation.text(promptTemplateVersion, maximum: 128),
              cliVersion.map({ EngineValidation.text($0, maximum: 128) }) ?? true, modelVersion == nil,
              result.provider == "Codex CLI", result.executionMode == "Reviewed context; restricted filesystem permissions",
              (0...4).contains(result.startupDiagnosticCount),
              (0...32_768).contains(disclosedContentByteCount),
              warnings.count <= 32, warnings.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) else {
            throw CaseWorkError.invalidRecord
        }
        switch retention {
        case .full:
            guard let prompt, !prompt.isEmpty, prompt.utf8.count <= CaseWorkStore.maximumRecordBytes,
                  CaseWorkCoding.hex(SHA256.hash(data: Data(prompt.utf8))) == requestSHA256 else { throw CaseWorkError.requestMismatch }
        case .digestOnly:
            guard prompt == nil else { throw CaseWorkError.invalidRecord }
        }
        if let contentHash, let completeContentByteCount {
            guard contentHash.scope == "extracted-file-bytes", EngineValidation.validHash(contentHash.sha256),
                  completeContentByteCount >= 0, completeContentByteCount <= AssistantContextBuilder.maximumFileBytes,
                  completeContentByteCount == binding.selectedEntry.size,
                  Int64(disclosedContentByteCount) <= completeContentByteCount,
                  sourceBytesVerifiedForContentAtRequest else { throw CaseWorkError.invalidRecord }
        } else {
            guard contentHash == nil, completeContentByteCount == nil, disclosedContentByteCount == 0,
                  !sourceBytesVerifiedForContentAtRequest else { throw CaseWorkError.invalidRecord }
        }
    }
}

/// A user-authored revision, separate from AI receipts and deterministic facts.
public struct FindingRecord: Codable, Equatable, Sendable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let findingID: UUID
    public let revision: Int
    public let previousRevisionID: UUID?
    public let createdAt: Date
    public let binding: CaseWorkBinding
    public let note: String
    public let bookmarked: Bool
    public let tags: [String]
    public let reviewStatus: FindingReviewStatus
    public let reviewReason: String

    public static func create(binding: CaseWorkBinding, note: String, bookmarked: Bool = false,
        tags: [String] = [], reviewStatus: FindingReviewStatus = .unreviewed, reviewReason: String = "") throws -> Self {
        let record = Self(schemaVersion: 1, id: UUID(), findingID: UUID(), revision: 1,
            previousRevisionID: nil, createdAt: Date(), binding: binding, note: note,
            bookmarked: bookmarked, tags: tags, reviewStatus: reviewStatus, reviewReason: reviewReason)
        try record.validate(); return record
    }

    public func revised(note: String, bookmarked: Bool, tags: [String],
        reviewStatus: FindingReviewStatus, reviewReason: String, binding: CaseWorkBinding? = nil) throws -> Self {
        guard revision < Int.max, binding.map({ self.binding.refersToSameFile(as: $0) }) ?? true else {
            throw CaseWorkError.invalidRecord
        }
        let record = Self(schemaVersion: 1, id: UUID(), findingID: findingID, revision: revision + 1,
            previousRevisionID: id, createdAt: Date(), binding: binding ?? self.binding, note: note,
            bookmarked: bookmarked, tags: tags, reviewStatus: reviewStatus, reviewReason: reviewReason)
        try record.validate(); return record
    }

    func validate() throws {
        guard schemaVersion == 1 else { throw CaseWorkError.unsupportedVersion }
        try binding.validate()
        guard revision > 0, (revision == 1) == (previousRevisionID == nil), previousRevisionID != id,
              createdAt.timeIntervalSince1970.isFinite, EngineValidation.text(note, maximum: 65_536, allowEmpty: true),
              tags.count <= 32, Set(tags).count == tags.count,
              tags.allSatisfy({ EngineValidation.text($0, maximum: 128) }),
              EngineValidation.text(reviewReason, maximum: 8_192, allowEmpty: reviewStatus == .unreviewed),
              reviewStatus == .unreviewed || !reviewReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw CaseWorkError.invalidRecord
        }
    }
}

/// Historical receipt of a completed, independently checked EngineClient export.
/// Reopening this record does not rehash a source or a user export destination.
public struct ExtractionRecord: Codable, Equatable, Sendable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let createdAt: Date
    public let binding: CaseWorkBinding
    public let outputHash: AssistantScopedHash
    public let outputByteCount: Int64
    public let verificationDescription: String

    /// Call only after EngineClient's output verification/publication succeeds.
    /// The DTO itself cannot establish that the caller performed an extraction.
    public static func make(binding: CaseWorkBinding, receipt: ExtractionResult, verifiedAt: Date = Date()) throws -> Self {
        let record = Self(schemaVersion: 1, id: UUID(), createdAt: verifiedAt, binding: binding,
            outputHash: AssistantScopedHash(sha256: receipt.sha256, scope: receipt.hashScope),
            outputByteCount: receipt.byteCount,
            verificationDescription: "Recorded extraction receipt; verification described at export time, not current source/output verification")
        try record.validate(); return record
    }

    func validate() throws {
        guard schemaVersion == 1 else { throw CaseWorkError.unsupportedVersion }
        try binding.validate()
        guard !binding.selectedEntry.isDirectory, createdAt.timeIntervalSince1970.isFinite,
              outputByteCount == binding.selectedEntry.size, outputByteCount >= 0,
              outputHash.scope == "extracted-file-bytes", EngineValidation.validHash(outputHash.sha256),
              verificationDescription == "Recorded extraction receipt; verification described at export time, not current source/output verification" else {
            throw CaseWorkError.invalidRecord
        }
    }
}

public struct CaseWorkSummary: Equatable, Sendable, Identifiable {
    public let id: UUID
    public let kind: CaseWorkKind
    public let createdAt: Date
    public let title: String
    public let snapshotSHA256: String
    public let reviewStatus: FindingReviewStatus?
    public let retention: AnalysisRetention?
    public let revision: Int?
}

public struct CaseWorkCursor: Equatable, Sendable {
    let bindingLocator: String
    let caseID: UUID
    let evidenceID: UUID
    let kind: CaseWorkKind
    let createdAt: Date
    let id: UUID
}

public struct CaseWorkDiagnostic: Equatable, Sendable {
    public let recordID: UUID?
    public let message: String
}

public struct CaseWorkHistoryPage: Equatable, Sendable {
    public let items: [CaseWorkSummary]
    public let diagnostics: [CaseWorkDiagnostic]
    public let totalDiagnosticCount: Int
    public let nextCursor: CaseWorkCursor?
    /// Each scan holds one serialized record and at most 51 small summaries.
    public let maximumSerializedRecordBytesObserved: Int
}

public enum CaseWorkError: Error, LocalizedError, Equatable, Sendable {
    case invalidRecord, unsupportedVersion, requestMismatch, sizeLimit, invalidCase, scopeMismatch
    case alreadyExists, staleRevision, unsafePath, changedDuringOperation, historyUnavailable
    public var errorDescription: String? {
        switch self {
        case .invalidRecord: "The case-work record is malformed; the original was preserved."
        case .unsupportedVersion: "This case-work schema version is unsupported; the original was preserved."
        case .requestMismatch: "The saved analysis does not match its exact reviewed request and selection."
        case .sizeLimit: "The case-work record exceeds the 1 MiB limit; nothing was truncated or saved."
        case .invalidCase: "The case directory or lock is unavailable. Reopen the case."
        case .scopeMismatch: "The record does not belong to this case and its recorded evidence hash."
        case .alreadyExists: "This immutable record already exists; it was not overwritten."
        case .staleRevision: "The finding changed since it was opened. Reload it before saving a new revision."
        case .unsafePath: "A case-work path is not a safe regular file or directory."
        case .changedDuringOperation: "The case or record changed during the operation. Reopen it before retrying."
        case .historyUnavailable: "Some finding history is unreadable or unsupported; reload after resolving it before saving."
        }
    }
}

enum CaseWorkCoding {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        // Lossless Foundation reference-date seconds preserve the original
        // Double exactly. Epoch conversion can round fractional instants and
        // would destabilize equality and page cursor boundaries after reopening.
        encoder.dateEncodingStrategy = .deferredToDate
        return try encoder.encode(value)
    }
    static func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .deferredToDate
        return try decoder.decode(type, from: data)
    }
    static func digest<T: Encodable>(_ value: T) throws -> String { hex(SHA256.hash(data: try encode(value))) }
    static func hex<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
