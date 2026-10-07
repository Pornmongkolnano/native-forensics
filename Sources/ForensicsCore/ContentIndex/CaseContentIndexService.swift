import Foundation

public struct ContentIndexProgress: Sendable, Equatable {
    public let finishedFiles: Int
    public let plannedFiles: Int
    public let filename: String
}

/// Sequential, budgeted use of the existing independently verified extraction
/// and isolated decoder. No source or reconstructed document is written to the
/// index; only bounded derived text and receipts survive scratch cleanup.
public struct CaseContentIndexService: Sendable {
    public typealias Preview = @Sendable (EvidenceRecord, EnumerationResult, FilesystemEntry) async throws -> FilesystemDocumentPreview
    public typealias VerifySources = @Sendable ([ContentIndexInput]) async throws -> Void
    public typealias DecoderFingerprint = @Sendable () async throws -> String
    private let preview: Preview
    private let verifySources: VerifySources
    private let decoderFingerprint: DecoderFingerprint

    public init(preview: @escaping Preview, verifySources: @escaping VerifySources = Self.verify,
                decoderFingerprint: @escaping DecoderFingerprint) {
        self.preview = preview; self.verifySources = verifySources; self.decoderFingerprint = decoderFingerprint
    }

    public init(engineHelperURL: URL, documentHelperURL: URL) {
        let service = FilesystemDocumentPreviewService(engine: EngineClient(helperURL: engineHelperURL),
            documents: DocumentAnalysisClient(helperURL: documentHelperURL))
        self.init(preview: { try await service.preview(evidence: $0, result: $1, file: $2) },
            decoderFingerprint: { try await ImageInspector.inspect(url: documentHelperURL, progress: { _ in }).sha256 })
    }

    public func rebuild(caseID: UUID, inputs: [ContentIndexInput], limits: ContentIndexLimits = .init(),
                        progress: @escaping @Sendable (ContentIndexProgress) -> Void = { _ in }) async throws -> CaseContentIndexSnapshot {
        try limits.validate(); try Task.checkCancellation()
        guard inputs.count <= ContentIndexLimits.maximumSources, Set(inputs.map { $0.evidence.id }).count == inputs.count else {
            throw ContentIndexError.invalidSnapshot
        }
        // The timeout also cancels an in-flight hashing/extraction/decoder and
        // waits for its owner to drain before returning. No detached work leaks.
        return try await withThrowingTaskGroup(of: CaseContentIndexSnapshot.self) { group in
            group.addTask { try await build(caseID: caseID, inputs: inputs, limits: limits, progress: progress) }
            group.addTask {
                try await Task.sleep(for: .seconds(limits.timeoutSeconds))
                throw ContentIndexError.timeout
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw ContentIndexError.invalidSnapshot }
            try Task.checkCancellation(); return result
        }
    }

    private func build(caseID: UUID, inputs: [ContentIndexInput], limits: ContentIndexLimits,
                       progress: @escaping @Sendable (ContentIndexProgress) -> Void) async throws -> CaseContentIndexSnapshot {
        var listingBudget = ContentIndexListingBudget(), boundedInputs: [ContentIndexInput] = []
        for input in inputs {
            try Task.checkCancellation()
            let result = try input.result.flatMap { try listingBudget.admit($0) ? $0 : nil }
            boundedInputs.append(ContentIndexInput(evidence: input.evidence, result: result))
        }
        let sources = try boundedInputs.map(ContentIndexSource.make)
        let decoderHash = try await decoderFingerprint()
        guard EngineValidation.validHash(decoderHash) else { throw ContentIndexError.invalidSnapshot }
        try await verifySources(boundedInputs); try Task.checkCancellation()
        var work: [(ContentIndexInput, FilesystemEntry)] = []
        var omitted = 0, directories = 0
        for input in boundedInputs {
            guard let result = input.result, [.completed, .partial].contains(result.status) else { continue }
            for file in result.files {
                try Task.checkCancellation()
                if file.isDirectory { directories += 1; continue }
                if work.count < limits.maximumFiles { work.append((input, file)) } else { omitted += 1 }
            }
        }
        var documents: [ContentIndexDocument] = []
        var inputBytes: Int64 = 0, textBytes = 0
        for (input, file) in work {
            try Task.checkCancellation()
            progress(ContentIndexProgress(finishedFiles: documents.count, plannedFiles: work.count, filename: file.name))
            func record(_ status: ContentIndexFileStatus, _ reason: String) throws -> ContentIndexDocument {
                try .make(evidenceID: input.evidence.id, file: file, status: status, reason: reason)
            }
            if file.size > limits.maximumFileBytes { documents.append(try record(.skipped, "FILE_BYTE_LIMIT")); continue }
            if file.size > limits.maximumInputBytes - inputBytes { documents.append(try record(.pending, "INPUT_BYTE_BUDGET")); continue }
            guard let result = input.result else { throw ContentIndexError.invalidSnapshot }
            inputBytes += file.size
            do {
                let value = try await preview(input.evidence, result, file)
                try Task.checkCancellation()
                guard value.file == file, value.receipt.evidenceID == input.evidence.id, value.receipt.fileID == file.id,
                      value.receipt.byteCount == file.size, EngineValidation.validHash(value.receipt.sha256),
                      value.receipt.orderedContainerSHA256 == sources.first(where: { $0.evidenceID == input.evidence.id })?.orderedContainerSHA256,
                      value.analysis.sourceSHA256 == value.receipt.sha256,
                      value.analysis.sourceByteCount == value.receipt.byteCount else { throw ContentIndexError.sourceChanged }
                // Validate the same decoder contract even for injected clients.
                try DocumentAnalysisClient.validate(value.analysis, for: DocumentInput(fileURL: URL(fileURLWithPath: "/derived"),
                    expectedSHA256: value.receipt.sha256, expectedByteCount: value.receipt.byteCount))
                if value.analysis.status == .unsupported { documents.append(try record(.skipped, "UNSUPPORTED_CONTENT")); continue }
                if value.analysis.status == .failed { documents.append(try record(.failed, "DECODE_FAILED")); continue }
                if value.analysis.textPages.isEmpty || value.analysis.textPages.allSatisfy({ $0.text.isEmpty }) {
                    documents.append(try record(.skipped, "NO_TEXT_LAYER_OR_BODY")); continue
                }
                let bytes = value.analysis.textPages.reduce(0) { $0 + $1.text.utf8.count }
                if bytes > limits.maximumTextBytes - textBytes { documents.append(try record(.pending, "DERIVED_TEXT_BUDGET")); continue }
                textBytes += bytes
                documents.append(try .make(evidenceID: input.evidence.id, file: file, status: .indexed,
                    reason: value.analysis.textIsComplete ? nil : "PARTIAL_DECODER_COVERAGE", contentSHA256: value.receipt.sha256,
                    pages: value.analysis.textPages, complete: value.analysis.textIsComplete))
            } catch {
                if error is CancellationError { throw error }
                try Task.checkCancellation()
                if error as? ContentIndexError == .sourceChanged || error as? EngineError == .sourceChanged
                    || error as? ForensicsError == .sourceChanged || error as? VerifiedContentError == .staleEvidence {
                    throw ContentIndexError.sourceChanged
                }
                // Host paths/decoder stderr are not copied to a persisted index.
                documents.append(try record(.failed, "EXTRACTION_OR_DECODE_FAILED"))
            }
        }
        try await verifySources(boundedInputs)
        guard try await decoderFingerprint() == decoderHash else { throw ContentIndexError.sourceChanged }
        try Task.checkCancellation()
        let snapshot = CaseContentIndexSnapshot(schemaVersion: 1, id: UUID(), caseID: caseID, builtAt: Date(),
            decoderContract: "NFDocumentDecoder.document-analysis.v1", decoderBinarySHA256: decoderHash,
            limits: limits, sources: sources, documents: documents, omittedRegularFiles: omitted, skippedDirectories: directories)
        try snapshot.validate()
        guard try CaseWorkCoding.encode(snapshot).count <= ContentIndexLimits.maximumSerializedBytes else { throw ContentIndexError.storageLimit }
        progress(ContentIndexProgress(finishedFiles: documents.count, plannedFiles: work.count, filename: ""))
        return snapshot
    }

    public static func verify(_ inputs: [ContentIndexInput]) async throws {
        // Rehash the whole ordered source set; inode/mtime alone do not certify
        // a content index. Duplicate paths must declare the same expected hash.
        var expected: [String: String] = [:], sizes: [String: Int64] = [:]
        for input in inputs {
            let result = input.result.flatMap { [.completed, .partial].contains($0.status) ? $0 : nil }
            let paths = result?.sourcePaths ?? [input.evidence.sourcePath]
            for path in paths {
                guard let hash = result?.sourceFileHashes[path] ?? (path == input.evidence.sourcePath ? input.evidence.sha256 : nil),
                      expected[path].map({ $0 == hash }) ?? true else { throw ContentIndexError.sourceChanged }
                expected[path] = hash
            }
            guard sizes[input.evidence.sourcePath].map({ $0 == input.evidence.byteCount }) ?? true else { throw ContentIndexError.sourceChanged }
            sizes[input.evidence.sourcePath] = input.evidence.byteCount
        }
        var identities: [(URL, SourceIdentity)] = []
        for path in expected.keys.sorted() {
            try Task.checkCancellation()
            let image: InspectedImage
            do { image = try await ImageInspector.inspect(url: URL(fileURLWithPath: path), progress: { _ in }) }
            catch {
                try Task.checkCancellation()
                if error as? ForensicsError == .sourceChanged { throw ContentIndexError.sourceChanged }
                throw error
            }
            guard image.sha256 == expected[path], sizes[path].map({ $0 == image.byteCount }) ?? true,
                  let identity = image.sourceIdentity else { throw ContentIndexError.sourceChanged }
            identities.append((image.sourceURL, identity))
        }
        guard identities.allSatisfy({ (try? FileAccess.identity(at: $0.0)) == $0.1 }) else { throw ContentIndexError.sourceChanged }
    }
}
