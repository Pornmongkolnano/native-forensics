import Darwin
import Foundation

/// A local document inspection is separate from recovery success. A matching
/// extraction hash does not assert that the recovered document is readable.
public struct FilesystemDocumentPreview: Sendable, Equatable {
    public let file: FilesystemEntry
    public let receipt: VerifiedContentReceipt
    public let analysis: DocumentAnalysis

    public init(file: FilesystemEntry, receipt: VerifiedContentReceipt, analysis: DocumentAnalysis) {
        self.file = file; self.receipt = receipt; self.analysis = analysis
    }
}

public struct FilesystemDocumentPreviewService: Sendable {
    public let engine: EngineClient
    public let documents: DocumentAnalysisClient

    public init(engine: EngineClient, documents: DocumentAnalysisClient) {
        self.engine = engine; self.documents = documents
    }

    public func preview(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) async throws -> FilesystemDocumentPreview {
        try VerifiedContentService.validateSelection(evidence: evidence, result: result, file: file)
        guard !file.isDirectory else { throw VerifiedContentError.directoryContent }
        guard file.size <= DocumentLimits.maximumInputBytes else { throw DocumentAnalysisError.invalidInput }
        let scratch = try FilesystemDocumentScratch()
        defer { scratch.cleanup() }
        var options = result.options
        options.hashLogicalImage = false
        let output = try await engine.extractOwned(imagePaths: result.sourcePaths.map { URL(fileURLWithPath: $0) },
            file: file, outputURL: scratch.outputURL, options: options, expectedSourceHashes: result.sourceFileHashes)
        try scratch.claim(output.receipt, identity: output.identity)
        try Task.checkCancellation()
        let analysis = try await documents.analyze(DocumentInput(fileURL: scratch.outputURL,
            expectedSHA256: output.receipt.sha256, expectedByteCount: output.receipt.byteCount))
        try scratch.validate()
        // The isolated decoder may take seconds. Recheck every container after
        // it returns instead of presenting a result for an edited source set.
        var sourceIdentities: [(URL, SourceIdentity)] = []
        for path in result.sourcePaths {
            let image = try await ImageInspector.inspect(url: URL(fileURLWithPath: path), progress: { _ in })
            guard image.sourceURL.path == path, image.sha256 == result.sourceFileHashes[path],
                  let identity = image.sourceIdentity else {
                throw EngineError.sourceChanged
            }
            sourceIdentities.append((image.sourceURL, identity))
        }
        guard sourceIdentities.allSatisfy({ (try? FileAccess.identity(at: $0.0)) == $0.1 }) else {
            throw EngineError.sourceChanged
        }
        try scratch.validate()
        try Task.checkCancellation()
        return FilesystemDocumentPreview(file: file, receipt: VerifiedContentReceipt(evidenceID: evidence.id,
            fileID: file.id, byteCount: output.receipt.byteCount, sha256: output.receipt.sha256, verifiedAt: Date(),
            orderedContainerSHA256: try result.sourcePaths.map {
                guard let hash = result.sourceFileHashes[$0] else { throw VerifiedContentError.staleEvidence }
                return hash
            }), analysis: analysis)
    }
}

/// Only the leaf published by the engine may be cleaned up. The directory is
/// held across path replacement; unknown contents and replacement paths stay.
private final class FilesystemDocumentScratch {
    let outputURL: URL
    private let parentURL: URL
    private let rootURL: URL
    private let parent: Int32
    private let root: Int32
    private let name: String
    private var outputIdentity: SourceIdentity?
    private var cleaned = false

    init() throws {
        parentURL = try FileAccess.localURL(FileManager.default.temporaryDirectory)
        parent = try EvidenceViewFiles.openDirectory(parentURL)
        name = ".native-document-\(UUID().uuidString.lowercased())"
        rootURL = parentURL.appendingPathComponent(name, isDirectory: true)
        outputURL = rootURL.appendingPathComponent("document-bytes")
        guard Darwin.mkdirat(parent, name, mode_t(0o700)) == 0 else {
            let error = FileAccess.posixError("Cannot create document preview storage")
            Darwin.close(parent); throw error
        }
        let descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            let error = FileAccess.posixError("Cannot open document preview storage")
            // Without an opened identity, do not remove a pathname that may
            // already have been replaced by another directory.
            Darwin.close(parent); throw error
        }
        root = descriptor
    }

    func claim(_ receipt: ExtractionResult, identity: SourceIdentity) throws {
        outputIdentity = identity
        guard receipt.outputPath == outputURL.path, receipt.byteCount == identity.size else {
            throw VerifiedContentError.extractedContentMismatch
        }
        try validate()
    }

    func validate() throws {
        try EvidenceViewFiles.validateDirectory(parentURL, descriptor: parent)
        try EvidenceViewFiles.validateDirectory(rootURL, descriptor: root)
        var metadata = stat()
        guard Darwin.fstat(root, &metadata) == 0, metadata.st_mode & 0o777 == 0o700 else {
            throw VerifiedContentError.extractedContentMismatch
        }
        guard let outputIdentity,
              (try? FileAccess.identity(at: "document-bytes", in: root)) == outputIdentity else {
            throw VerifiedContentError.extractedContentMismatch
        }
    }

    func cleanup() {
        guard !cleaned else { return }
        cleaned = true
        if let outputIdentity,
           (try? FileAccess.identity(at: "document-bytes", in: root)) == outputIdentity {
            _ = Darwin.unlinkat(root, "document-bytes", 0)
        }
        if (try? EvidenceViewFiles.validateDirectory(rootURL, descriptor: root)) != nil {
            _ = Darwin.unlinkat(parent, name, AT_REMOVEDIR)
        }
        Darwin.close(root); Darwin.close(parent)
    }

    deinit { cleanup() }
}
