import CryptoKit
import Foundation

/// Receipt for fresh, independently verified extracted bytes. It intentionally
/// contains no host source or temporary output paths.
public struct VerifiedContentReceipt: Codable, Sendable, Equatable {
    public let evidenceID: UUID
    public let fileID: String
    public let byteCount: Int64
    public let sha256: String
    public let verifiedAt: Date
    public let orderedContainerSHA256: [String]
    public var hashScope: String { "extracted-file-bytes" }
    public var containerHashScope: String { FileHashScope.selectedFileBytes }
    public var metadataWasRefreshed: Bool { false }
    public var logicalImageHashWasRefreshed: Bool { false }
}

public struct VerifiedContent: Sendable {
    public let bytes: Data
    public let receipt: VerifiedContentReceipt
}

public enum VerifiedContentError: Error, LocalizedError, Sendable, Equatable {
    case staleEvidence, unknownSelection, directoryContent, contentTooLarge, extractedContentMismatch

    public var errorDescription: String? {
        switch self {
        case .staleEvidence: "The selected evidence and recorded source hashes do not match. Analyze the source again."
        case .unknownSelection: "The selected file does not exactly match this recorded analysis. Select it again."
        case .directoryContent: "Select a regular file to preview its bytes."
        case .contentTooLarge: "Local preview supports complete files up to 1 MiB and shows a prefix up to 32 KiB."
        case .extractedContentMismatch: "The extracted bytes failed their independent size/hash check. No preview was prepared."
        }
    }
}

/// Shared local-only extraction for preview and optional assistant disclosure.
/// Every ordered container is rehashed; all returned bytes have an independent
/// digest/size check after descriptor-owned reading. Scratch is gone on return.
public enum VerifiedContentService {
    public static let maximumFileBytes: Int64 = 1_048_576
    public static let maximumPreviewBytes = 32_768

    public static func extract(
        evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry,
        engine: EngineClient, progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }
    ) async throws -> VerifiedContent {
        try validateSelection(evidence: evidence, result: result, file: file)
        guard !file.isDirectory else { throw VerifiedContentError.directoryContent }
        guard file.size <= maximumFileBytes else { throw VerifiedContentError.contentTooLarge }
        try Task.checkCancellation()
        let scratch = try ContentScratch()
        defer { scratch.cleanup() }
        var options = result.options
        options.hashLogicalImage = false
        let owned = try await engine.extractOwned(
            imagePaths: result.sourcePaths.map { URL(fileURLWithPath: $0) }, file: file,
            outputURL: scratch.outputURL, options: options,
            expectedSourceHashes: result.sourceFileHashes, progress: progress)
        // Claim the published leaf before checking cancellation so its owned
        // bytes are still removed if cancellation arrives at this boundary.
        let extraction = owned.receipt
        try scratch.claimPublished(receipt: extraction, identity: owned.identity)
        try Task.checkCancellation()
        let bytes = try scratch.readVerified(receipt: extraction, expectedSize: file.size)
        try verify(bytes: bytes, receipt: extraction, expectedSize: file.size)
        try Task.checkCancellation()
        return VerifiedContent(bytes: bytes, receipt: VerifiedContentReceipt(
            evidenceID: evidence.id, fileID: file.id, byteCount: extraction.byteCount,
            sha256: extraction.sha256, verifiedAt: Date(),
            orderedContainerSHA256: try result.sourcePaths.map { path in
                guard let hash = result.sourceFileHashes[path] else { throw VerifiedContentError.staleEvidence }
                return hash
            }))
    }

    static func validateSelection(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) throws {
        try EngineValidation.result(result)
        guard evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.byteCount >= 0, EngineValidation.validHash(evidence.sha256),
              result.sourcePaths.first == evidence.sourcePath,
              result.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
              result.sourceIdentities.first.map({ $0.size == evidence.byteCount }) ?? true else {
            throw VerifiedContentError.staleEvidence
        }
        guard result.files.first(where: { $0.id == file.id }) == file else { throw VerifiedContentError.unknownSelection }
        try Task.checkCancellation()
    }

    static func verify(bytes: Data, receipt: ExtractionResult, expectedSize: Int64) throws {
        guard bytes.count <= maximumFileBytes, Int64(bytes.count) == expectedSize,
              receipt.byteCount == expectedSize, EngineValidation.validHash(receipt.sha256),
              SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == receipt.sha256 else {
            throw VerifiedContentError.extractedContentMismatch
        }
    }
}
