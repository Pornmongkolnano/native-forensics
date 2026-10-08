import Foundation

public struct ContentIndexProgress: Sendable, Equatable {
    public let finishedFiles: Int
    public let plannedFiles: Int
    public let filename: String
    public let reusedFiles: Int
    public let rebuiltFiles: Int
    public init(finishedFiles: Int, plannedFiles: Int, filename: String, reusedFiles: Int = 0, rebuiltFiles: Int = 0) {
        self.finishedFiles = finishedFiles; self.plannedFiles = plannedFiles; self.filename = filename
        self.reusedFiles = reusedFiles; self.rebuiltFiles = rebuiltFiles
    }
}

/// Sequential, budgeted use of the existing independently verified extraction
/// and isolated decoder. No source or reconstructed document is written to the
/// index; only bounded derived text and receipts survive scratch cleanup.
public struct CaseContentIndexService: Sendable {
    public typealias Preview = @Sendable (EvidenceRecord, EnumerationResult, FilesystemEntry) async throws -> FilesystemDocumentPreview
    public typealias VerifySources = @Sendable ([ContentIndexInput]) async throws -> Void
    public typealias DecoderFingerprint = @Sendable () async throws -> String
    public typealias DecoderIdentityProvider = @Sendable () async throws -> DocumentDecoderIdentity
    private let preview: Preview
    private let verifySources: VerifySources
    private let decoderFingerprint: DecoderFingerprint
    private let decoderIdentityProvider: DecoderIdentityProvider?

    public init(preview: @escaping Preview, verifySources: @escaping VerifySources = Self.verify,
                decoderFingerprint: @escaping DecoderFingerprint, decoderIdentity: DecoderIdentityProvider? = nil) {
        self.preview = preview; self.verifySources = verifySources; self.decoderFingerprint = decoderFingerprint
        self.decoderIdentityProvider = decoderIdentity
    }

    public init(engineHelperURL: URL, documentHelperURL: URL) {
        let decoder = DocumentAnalysisClient(helperURL: documentHelperURL)
        let service = FilesystemDocumentPreviewService(engine: EngineClient(helperURL: engineHelperURL),
            documents: decoder)
        self.init(preview: { try await service.preview(evidence: $0, result: $1, file: $2) },
            decoderFingerprint: { try await decoder.decoderBinarySHA256() },
            decoderIdentity: { try await decoder.currentDecoderIdentity() })
    }

    public func rebuild(caseID: UUID, inputs: [ContentIndexInput], limits: ContentIndexLimits = .init(),
                        progress: @escaping @Sendable (ContentIndexProgress) -> Void = { _ in }) async throws -> CaseContentIndexSnapshot {
        try await perform(caseID: caseID, inputs: inputs, previous: nil, limits: limits, progress: progress)
    }

    /// Reuses only indexed documents whose entire source/listing and decoder
    /// binding survives fresh full-byte verification at both build boundaries.
    public func update(caseID: UUID, inputs: [ContentIndexInput], previous: CaseContentIndexSnapshot,
                       limits: ContentIndexLimits = .init(),
                       progress: @escaping @Sendable (ContentIndexProgress) -> Void = { _ in }) async throws -> CaseContentIndexSnapshot {
        try Task.checkCancellation(); try previous.validate()
        guard previous.caseID == caseID else { throw ContentIndexError.invalidSnapshot }
        return try await perform(caseID: caseID, inputs: inputs, previous: previous, limits: limits, progress: progress)
    }

    private func perform(caseID: UUID, inputs: [ContentIndexInput], previous: CaseContentIndexSnapshot?, limits: ContentIndexLimits,
                         progress: @escaping @Sendable (ContentIndexProgress) -> Void) async throws -> CaseContentIndexSnapshot {
        try limits.validate(); try Task.checkCancellation()
        guard inputs.count <= ContentIndexLimits.maximumSources, Set(inputs.map { $0.evidence.id }).count == inputs.count else {
            throw ContentIndexError.invalidSnapshot
        }
        // The timeout also cancels an in-flight hashing/extraction/decoder and
        // waits for its owner to drain before returning. No detached work leaks.
        return try await withThrowingTaskGroup(of: CaseContentIndexSnapshot.self) { group in
            group.addTask { try await build(caseID: caseID, inputs: inputs, previous: previous, limits: limits, progress: progress) }
            group.addTask {
                try await Task.sleep(for: .seconds(limits.timeoutSeconds))
                throw ContentIndexError.timeout
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw ContentIndexError.invalidSnapshot }
            try Task.checkCancellation(); return result
        }
    }

    private func build(caseID: UUID, inputs: [ContentIndexInput], previous: CaseContentIndexSnapshot?, limits: ContentIndexLimits,
                       progress: @escaping @Sendable (ContentIndexProgress) -> Void) async throws -> CaseContentIndexSnapshot {
        var listingBudget = ContentIndexListingBudget(), boundedInputs: [ContentIndexInput] = []
        for input in inputs {
            try Task.checkCancellation()
            let result = try input.result.flatMap { try listingBudget.admit($0) ? $0 : nil }
            boundedInputs.append(ContentIndexInput(evidence: input.evidence, result: result))
        }
        let sources = try boundedInputs.map(ContentIndexSource.make)
        let decoderIdentity = try await readDecoderIdentity()
        let decoderHash: String
        if let decoderIdentity {
            do { try decoderIdentity.validateMetadata() }
            catch { throw ContentIndexError.invalidSnapshot }
            decoderHash = decoderIdentity.decoderExecutableSHA256
        } else { decoderHash = try await decoderFingerprint() }
        guard EngineValidation.validHash(decoderHash) else { throw ContentIndexError.invalidSnapshot }
        try await verifySources(boundedInputs); try Task.checkCancellation()
        let reusable = try reusableDocuments(previous: previous, inputs: boundedInputs, sources: sources,
                                             decoderHash: decoderHash, decoderIdentity: decoderIdentity, limits: limits)
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
        var inputBytes: Int64 = 0, textBytes = 0, reusedFiles = 0, rebuiltFiles = 0
        for (input, file) in work {
            try Task.checkCancellation()
            progress(ContentIndexProgress(finishedFiles: documents.count, plannedFiles: work.count, filename: file.name,
                                          reusedFiles: reusedFiles, rebuiltFiles: rebuiltFiles))
            func record(_ status: ContentIndexFileStatus, _ reason: String) throws -> ContentIndexDocument {
                try .make(evidenceID: input.evidence.id, file: file, status: status, reason: reason)
            }
            if file.size > limits.maximumFileBytes { documents.append(try record(.skipped, "FILE_BYTE_LIMIT")); continue }
            if file.size > limits.maximumInputBytes - inputBytes { documents.append(try record(.pending, "INPUT_BYTE_BUDGET")); continue }
            guard let result = input.result else { throw ContentIndexError.invalidSnapshot }
            inputBytes += file.size
            let documentID = input.evidence.id.uuidString.lowercased() + ":" + file.id
            if let previous = reusable[documentID] {
                let bytes = previous.textPages.reduce(0) { $0 + $1.text.utf8.count }
                if bytes > limits.maximumTextBytes - textBytes {
                    documents.append(try record(.pending, "DERIVED_TEXT_BUDGET"))
                } else {
                    textBytes += bytes; documents.append(previous); reusedFiles += 1
                }
                continue
            }
            rebuiltFiles += 1
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
                if let decoderIdentity {
                    guard let provenance = value.analysis.provenance, decoderIdentity.matches(provenance) else {
                        throw ContentIndexError.sourceChanged
                    }
                } else if value.analysis.provenance != nil {
                    // The injected legacy branch is explicitly unknown. A v2
                    // receipt cannot be downgraded by omitting current identity.
                    throw ContentIndexError.sourceChanged
                }
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
                    pages: value.analysis.textPages, complete: value.analysis.textIsComplete,
                    decoderProvenance: value.analysis.provenance))
            } catch {
                if error is CancellationError { throw error }
                try Task.checkCancellation()
                if error as? ContentIndexError == .sourceChanged || error as? EngineError == .sourceChanged
                    || error as? ForensicsError == .sourceChanged || error as? VerifiedContentError == .staleEvidence {
                    throw ContentIndexError.sourceChanged
                }
                if error as? DocumentAnalysisError == .sourceChanged { throw ContentIndexError.sourceChanged }
                // Host paths/decoder stderr are not copied to a persisted index.
                documents.append(try record(.failed, "EXTRACTION_OR_DECODE_FAILED"))
            }
        }
        try await verifySources(boundedInputs)
        if decoderIdentityProvider != nil {
            guard try await readDecoderIdentity() == decoderIdentity else { throw ContentIndexError.sourceChanged }
        } else {
            guard try await decoderFingerprint() == decoderHash else { throw ContentIndexError.sourceChanged }
        }
        try Task.checkCancellation()
        let snapshot = CaseContentIndexSnapshot(schemaVersion: 1, id: UUID(), caseID: caseID, builtAt: Date(),
            decoderContract: decoderIdentity.map { $0.decoderIdentifier + "@" + $0.decoderVersion } ?? "NFDocumentDecoder.document-analysis.v1",
            decoderBinarySHA256: decoderHash,
            limits: limits, sources: sources, documents: documents, omittedRegularFiles: omitted, skippedDirectories: directories,
            decoderIdentity: decoderIdentity)
        try snapshot.validate()
        guard try CaseWorkCoding.encode(snapshot).count <= ContentIndexLimits.maximumSerializedBytes else { throw ContentIndexError.storageLimit }
        progress(ContentIndexProgress(finishedFiles: documents.count, plannedFiles: work.count, filename: "",
                                      reusedFiles: reusedFiles, rebuiltFiles: rebuiltFiles))
        return snapshot
    }

    private func reusableDocuments(previous: CaseContentIndexSnapshot?, inputs: [ContentIndexInput], sources: [ContentIndexSource],
                                   decoderHash: String, decoderIdentity: DocumentDecoderIdentity?, limits: ContentIndexLimits) throws -> [String: ContentIndexDocument] {
        guard let previous, previous.decoderBinarySHA256 == decoderHash,
              previous.decoderIdentity == decoderIdentity,
              previous.decoderContract == (decoderIdentity.map { $0.decoderIdentifier + "@" + $0.decoderVersion } ?? "NFDocumentDecoder.document-analysis.v1"),
              previous.limits == limits else { return [:] }
        var reusable: [String: ContentIndexDocument] = [:]
        for input in inputs {
            try Task.checkCancellation()
            guard let current = sources.first(where: { $0.evidenceID == input.evidence.id }), current.listingSHA256 != nil,
                  previous.sources.first(where: { $0.evidenceID == input.evidence.id }) == current,
                  let result = input.result else { continue }
            var remaining = Dictionary(uniqueKeysWithValues: previous.documents.filter { $0.evidenceID == input.evidence.id }
                .map { ($0.file.id, $0) })
            // A source-equal prior generation must contain actual files from
            // that exact listing. Validate even nonindexed records; never turn
            // a corrupt membership into an opportunistic successful update.
            for file in result.files {
                try Task.checkCancellation()
                guard let document = remaining.removeValue(forKey: file.id) else { continue }
                guard document.file == file, document.locatorSHA256 == (try ContentIndexDocument.locator(file)),
                      try CaseWorkCoding.encode(document.file) == CaseWorkCoding.encode(file) else { throw ContentIndexError.invalidSnapshot }
                if document.status == .indexed { reusable[document.id] = document }
            }
            guard remaining.isEmpty else { throw ContentIndexError.invalidSnapshot }
        }
        return reusable
    }

    private func readDecoderIdentity() async throws -> DocumentDecoderIdentity? {
        do { return try await decoderIdentityProvider?() }
        catch {
            if error as? DocumentAnalysisError == .sourceChanged { throw ContentIndexError.sourceChanged }
            throw error
        }
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
