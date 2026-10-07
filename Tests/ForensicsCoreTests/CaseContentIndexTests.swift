import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("CaseContentIndexTests")
struct CaseContentIndexTests {
    @Test("Content-only literal hits preserve two evidence locators, pages and digests")
    func caseWideReferences() async throws {
        let first = IndexFixture(texts: ["ไม่เกี่ยวข้อง", "ภาษาไทยhiddenneedle"])
        let second = IndexFixture(texts: ["Another hiddenneedle"])
        let snapshot = try await service().rebuild(caseID: UUID(), inputs: [first.input, second.input])
        let result = try CaseContentIndexSearch.search("hiddenneedle", in: snapshot)
        #expect(result.hits.count == 2)
        #expect(Set(result.hits.map { $0.reference.evidenceID }) == [first.evidence.id, second.evidence.id])
        #expect(result.hits.allSatisfy { !$0.reference.file.path.contains("hiddenneedle") })
        #expect(result.hits[0].reference.pageNumber == 2)
        #expect(result.hits[0].reference.utf16Offset == 7)
        #expect(result.hits[0].reference.utf16Length == 12)
        #expect(result.hits[0].reference.contentSHA256 == first.hashes[first.files[0].id])
        #expect(result.hits[0].reference.derivedTextSHA256 == snapshot.documents[0].derivedTextSHA256)
        #expect(CaseContentIndexSearch.resolve(result.hits[0].reference, in: snapshot)?.text == "ภาษาไทยhiddenneedle")
        #expect(!result.coverageIsPartial)
    }

    @Test("Short Thai, combining marks, punctuation and case sensitivity have literal semantics")
    func unicodeLiteral() async throws {
        let fixture = IndexFixture(texts: ["ภาษาไทยไม่มีช่องว่าง cafe\u{0301} CAFÉ [literal] XY"])
        let snapshot = try await service().rebuild(caseID: UUID(), inputs: [fixture.input])
        for query in ["ภ", "ภา", "ภาษา", "\u{0301}", "[literal]", "XY"] {
            #expect(try CaseContentIndexSearch.search(query, in: snapshot, caseSensitive: true).hits.count == 1)
        }
        #expect(try CaseContentIndexSearch.search("café", in: snapshot).hits.count == 1)
        #expect(try CaseContentIndexSearch.search("café", in: snapshot, caseSensitive: true).hits.isEmpty)
        #expect(try CaseContentIndexSearch.search("cafe\u{0301}", in: snapshot, caseSensitive: true).hits.count == 1)
        #expect(try CaseContentIndexSearch.search(".*", in: snapshot).hits.isEmpty)
        #expect(try CaseContentIndexSearch.search("xy", in: snapshot, caseSensitive: true).hits.isEmpty)
    }

    @Test("Hit/query caps and pathological graphemes never silently claim complete matches")
    func boundedSearch() async throws {
        let fixture = IndexFixture(texts: [String(repeating: "😀 needle ", count: 210) + "A" + String(repeating: "\u{0301}", count: 10_000)])
        let snapshot = try await service().rebuild(caseID: UUID(), inputs: [fixture.input])
        let outcome = try CaseContentIndexSearch.search("needle", in: snapshot, maximumHits: 2)
        #expect(outcome.hits.count == 2); #expect(outcome.hitLimitReached)
        #expect(outcome.hits.allSatisfy { $0.snippet.utf16.count <= 168 })
        #expect(!outcome.hits[0].snippet.contains("�"))
        #expect(try CaseContentIndexSearch.search(String(repeating: "a", count: 4_097), in: snapshot).coverageIsPartial)
        #expect(try CaseContentIndexSearch.search("", in: snapshot).hits.isEmpty)
    }

    @Test("Independent expected budget statuses distinguish omitted, oversized, pending and partial decoder text")
    func budgetsAndCoverage() async throws {
        let fixture = IndexFixture(texts: ["one"], fileSizes: [5, 40, 5, 5, 5])
        let snapshot = try await service().rebuild(caseID: UUID(), inputs: [fixture.input],
            limits: .init(maximumFiles: 4, maximumFileBytes: 10, maximumInputBytes: 6, maximumTextBytes: 10))
        #expect(snapshot.documents.map(\.status) == [.indexed, .skipped, .pending, .pending])
        #expect(snapshot.documents.map(\.reason) == [nil, "FILE_BYTE_LIMIT", "INPUT_BYTE_BUDGET", "INPUT_BYTE_BUDGET"])
        #expect(snapshot.omittedRegularFiles == 1); #expect(snapshot.pendingCount == 3)
        #expect(snapshot.isPartial)
        let textLimited = try await service().rebuild(caseID: UUID(), inputs: [fixture.input], limits: .init(maximumTextBytes: 2))
        #expect(textLimited.indexedCount == 0); #expect(textLimited.pendingCount == 5)
        let partial = try await service(truncated: true).rebuild(caseID: UUID(), inputs: [fixture.input])
        #expect(partial.documents.allSatisfy { !$0.textIsComplete }); #expect(partial.isPartial)
    }

    @Test("Missing listings and supported images without text remain visibly uncovered")
    func missingAndUnsupported() async throws {
        let fixture = IndexFixture(texts: ["some text"], fileSizes: [5, 5, 5])
        let missing = IndexFixture(texts: ["not indexed"])
        let decoder = service(transform: { analysis, file in
            if file.id == "file-0" {
                return DocumentAnalysis(contentKind: .image, mimeType: "image/png", status: .decoded,
                    sourceSHA256: analysis.sourceSHA256, sourceByteCount: file.size, pixelWidth: 1, pixelHeight: 1)
            }
            if file.id == "file-1" {
                return DocumentAnalysis(contentKind: .unknown, mimeType: "application/octet-stream", status: .unsupported,
                    sourceSHA256: analysis.sourceSHA256, sourceByteCount: file.size)
            }
            throw DocumentAnalysisError.timeout
        })
        let result = try await decoder.rebuild(caseID: UUID(), inputs: [fixture.input, .init(evidence: missing.evidence, result: nil)])
        #expect(result.documents.map(\.status) == [.skipped, .skipped, .failed])
        #expect(result.documents.map(\.reason) == ["NO_TEXT_LAYER_OR_BODY", "UNSUPPORTED_CONTENT", "EXTRACTION_OR_DECODE_FAILED"])
        #expect(result.missingListingCount == 1); #expect(result.isPartial)
        #expect(try CaseContentIndexSearch.search("missing", in: result).coverageIsPartial)
    }

    @Test("A mismatched verified-content receipt rejects the whole new generation")
    func receiptMismatch() async throws {
        let fixture = IndexFixture(texts: ["text"])
        let client = CaseContentIndexService(preview: { evidence, _, file in
            let normal = try fixture.preview(evidence, file)
            return FilesystemDocumentPreview(file: file, receipt: VerifiedContentReceipt(evidenceID: UUID(), fileID: file.id,
                byteCount: file.size, sha256: normal.receipt.sha256, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]), analysis: normal.analysis)
        }, verifySources: { _ in }, decoderFingerprint: { String(repeating: "d", count: 64) })
        await #expect(throws: ContentIndexError.sourceChanged) { try await client.rebuild(caseID: UUID(), inputs: [fixture.input]) }
    }

    @Test("A real source mutation after decoding rejects publication and leaves source bytes as found")
    func sourceMutation() async throws {
        let folder = try temporaryFolder(); defer { try? FileManager.default.removeItem(at: folder) }
        let source = folder.appendingPathComponent("container.dd")
        try Data("source-oracle".utf8).write(to: source)
        let fixture = IndexFixture(texts: ["text"], sourceURL: source, sourceBytes: Data("source-oracle".utf8))
        let changed = Data("edited-oracle".utf8)
        let client = CaseContentIndexService(preview: { evidence, _, file in
            let value = try fixture.preview(evidence, file)
            try changed.write(to: source); return value
        }, decoderFingerprint: { String(repeating: "d", count: 64) })
        await #expect(throws: ContentIndexError.sourceChanged) { try await client.rebuild(caseID: UUID(), inputs: [fixture.input]) }
        #expect(try Data(contentsOf: source) == changed)
    }

    @Test("Cancellation waits for the active owner to unwind, without returning a partial successful snapshot")
    func cancellationDrain() async throws {
        let fixture = IndexFixture(texts: ["text"]), gate = IndexCancellationGate()
        let client = CaseContentIndexService(preview: { _, _, _ in
            await gate.started()
            defer { Task { await gate.cleaned() } }
            try await Task.sleep(for: .seconds(30)); throw ContentIndexError.invalidSnapshot
        }, verifySources: { _ in }, decoderFingerprint: { String(repeating: "d", count: 64) })
        let task = Task { try await client.rebuild(caseID: UUID(), inputs: [fixture.input]) }
        await gate.waitStarted(); task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        await gate.waitCleaned()
        #expect(await gate.didClean)
    }

    @Test("Whole rebuild deadline cancels its child decoder and returns no generation")
    func deadlineDrain() async throws {
        let fixture = IndexFixture(texts: ["text"])
        let client = CaseContentIndexService(preview: { _, _, _ in
            try await Task.sleep(for: .seconds(30)); throw ContentIndexError.invalidSnapshot
        }, verifySources: { _ in }, decoderFingerprint: { String(repeating: "d", count: 64) })
        await #expect(throws: ContentIndexError.timeout) {
            try await client.rebuild(caseID: UUID(), inputs: [fixture.input], limits: .init(timeoutSeconds: 0.02))
        }
    }

    @Test("Stored generations round-trip offline, preserve previous data on faults, and reject stale concurrent save")
    func atomicStore() async throws {
        let (folder, forensicCase, fixture) = try persistedCase(); defer { try? FileManager.default.removeItem(at: folder) }
        let first = try await service().rebuild(caseID: forensicCase.manifest.id, inputs: [fixture.input])
        try CaseContentIndexStore.save(first, expectedSnapshotID: nil, in: forensicCase.bundleURL)
        let bytes = try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename))
        let second = try await service().rebuild(caseID: forensicCase.manifest.id, inputs: [fixture.input])
        #expect(throws: ContentIndexError.storageLimit) {
            try CaseContentIndexStore.save(second, expectedSnapshotID: first.id, in: forensicCase.bundleURL,
                beforePublish: { throw ContentIndexError.storageLimit })
        }
        #expect(try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename)) == bytes)
        #expect(throws: ContentIndexError.staleGeneration) {
            try CaseContentIndexStore.save(second, expectedSnapshotID: nil, in: forensicCase.bundleURL)
        }
        try CaseContentIndexStore.save(second, expectedSnapshotID: first.id, in: forensicCase.bundleURL)
        try FileManager.default.removeItem(at: URL(fileURLWithPath: fixture.evidence.sourcePath))
        #expect(try CaseContentIndexStore.load(in: forensicCase.bundleURL) == second)
        #expect(try FileManager.default.contentsOfDirectory(atPath: forensicCase.bundleURL.path).filter { $0.hasPrefix(".content-index-") }.isEmpty)
    }

    @Test("Symlink destination/root replacement and corrupt/oversized generations are rejected without following writes")
    func maliciousStore() async throws {
        let (folder, forensicCase, fixture) = try persistedCase(); defer { try? FileManager.default.removeItem(at: folder) }
        let snapshot = try await service().rebuild(caseID: forensicCase.manifest.id, inputs: [fixture.input])
        let victim = folder.appendingPathComponent("victim"), leaf = forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename)
        try Data("preserve-me".utf8).write(to: victim)
        try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: victim)
        #expect(throws: ContentIndexError.unsafeStore) { try CaseContentIndexStore.save(snapshot, expectedSnapshotID: nil, in: forensicCase.bundleURL) }
        #expect(try Data(contentsOf: victim) == Data("preserve-me".utf8))
        try FileManager.default.removeItem(at: leaf)
        try Data("{\"schemaVersion\":999}".utf8).write(to: leaf)
        #expect(throws: ContentIndexError.invalidSnapshot) { try CaseContentIndexStore.load(in: forensicCase.bundleURL) }
        try FileManager.default.removeItem(at: leaf)
        let descriptor = open(leaf.path, O_CREAT | O_WRONLY | O_EXCL, mode_t(0o600)); defer { close(descriptor) }
        #expect(descriptor >= 0); #expect(ftruncate(descriptor, off_t(ContentIndexLimits.maximumSerializedBytes + 1)) == 0)
        #expect(throws: ContentIndexError.storageLimit) { try CaseContentIndexStore.load(in: forensicCase.bundleURL) }
    }

    @Test("A durability failure after atomic publication reports uncertainty and the committed generation stays readable")
    func postCommitFailure() async throws {
        let (folder, forensicCase, fixture) = try persistedCase(); defer { try? FileManager.default.removeItem(at: folder) }
        let snapshot = try await service().rebuild(caseID: forensicCase.manifest.id, inputs: [fixture.input])
        #expect(throws: ContentIndexError.publicationUncertain) {
            try CaseContentIndexStore.save(snapshot, expectedSnapshotID: nil, in: forensicCase.bundleURL,
                beforePublish: {}, afterPublish: { throw ContentIndexError.storageLimit })
        }
        #expect(try CaseContentIndexStore.load(in: forensicCase.bundleURL) == snapshot)
    }

    @Test("Root replacement at synchronized staging boundary cannot redirect index publication")
    func rootReplacement() async throws {
        let (folder, forensicCase, fixture) = try persistedCase(); defer { try? FileManager.default.removeItem(at: folder) }
        let snapshot = try await service().rebuild(caseID: forensicCase.manifest.id, inputs: [fixture.input])
        let moved = folder.appendingPathComponent("moved.nativecase")
        #expect(throws: ContentIndexError.unsafeStore) {
            try CaseContentIndexStore.save(snapshot, expectedSnapshotID: nil, in: forensicCase.bundleURL, beforePublish: {
                try FileManager.default.moveItem(at: forensicCase.bundleURL, to: moved)
                try FileManager.default.createDirectory(at: forensicCase.bundleURL, withIntermediateDirectories: false)
            })
        }
        #expect(!FileManager.default.fileExists(atPath: forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename).path))
        #expect(!FileManager.default.fileExists(atPath: moved.appendingPathComponent(CaseContentIndexStore.filename).path))
    }

    @Test("Persisted canonical listing identity ignores cache timestamp precision but catches content/locator changes")
    func listingIdentity() throws {
        let fixture = IndexFixture(texts: ["text"])
        let encoded = JSONEncoder(); encoded.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let reopened = try decoder.decode(EnumerationResult.self, from: encoded.encode(fixture.result))
        #expect(try ContentIndexSource.make(fixture.input) == ContentIndexSource.make(.init(evidence: fixture.evidence, result: reopened)))
        let changed = IndexFixture(texts: ["text"], fileSizes: [6], evidenceID: fixture.evidence.id)
        #expect(try ContentIndexSource.make(fixture.input).listingSHA256 != ContentIndexSource.make(changed.input).listingSHA256)
    }

    @Test("A derived text mutation is detected by its stored digest on read")
    func textDigestTamper() async throws {
        let (folder, forensicCase, fixture) = try persistedCase(); defer { try? FileManager.default.removeItem(at: folder) }
        let snapshot = try await service().rebuild(caseID: forensicCase.manifest.id, inputs: [fixture.input])
        try CaseContentIndexStore.save(snapshot, expectedSnapshotID: nil, in: forensicCase.bundleURL)
        let leaf = forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename)
        var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: leaf)) as? [String: Any])
        var documents = try #require(object["documents"] as? [[String: Any]])
        var pages = try #require(documents[0]["textPages"] as? [[String: Any]])
        pages[0]["text"] = "tampered"; documents[0]["textPages"] = pages; object["documents"] = documents
        try JSONSerialization.data(withJSONObject: object).write(to: leaf)
        #expect(throws: ContentIndexError.invalidSnapshot) { try CaseContentIndexStore.load(in: forensicCase.bundleURL) }
    }

    @Test("Dropped records cannot claim complete coverage by altering aggregate status counts")
    func countTamper() async throws {
        let fixture = IndexFixture(texts: ["text"], fileSizes: [5, 5])
        let snapshot = try await service().rebuild(caseID: UUID(), inputs: [fixture.input])
        var object = try #require(JSONSerialization.jsonObject(with: CaseWorkCoding.encode(snapshot)) as? [String: Any])
        var documents = try #require(object["documents"] as? [[String: Any]])
        documents.removeLast(); object["documents"] = documents
        let altered = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, JSONSerialization.data(withJSONObject: object))
        #expect(throws: ContentIndexError.invalidSnapshot) { try altered.validate() }
    }

    @Test("Oversized in-memory listing is declined before serializing its repeated long paths")
    func listingPreflight() throws {
        let fixture = IndexFixture(texts: ["text"]), long = String(repeating: "x", count: 8_192)
        let entries = (0..<5_000).map { index in
            FilesystemEntry(id: "\(index)", path: "/" + long, name: long, fsOffsetBytes: 0,
                metaAddress: UInt64(index), size: 1, isDirectory: false, isDeleted: false)
        }
        let result = EnumerationResult(engineVersion: fixture.result.engineVersion, patchDigest: fixture.result.patchDigest,
            sourcePaths: fixture.result.sourcePaths, sourceFileHashes: fixture.result.sourceFileHashes,
            options: fixture.result.options, image: fixture.result.image, volumes: [], files: entries, warnings: [], status: .completed)
        var budget = ContentIndexListingBudget()
        #expect(try !budget.admit(result))
        #expect(try budget.admit(fixture.result))
    }

    @Test("Decoder binary replacement invalidates the entire derived generation")
    func decoderReplacement() async throws {
        let fixture = IndexFixture(texts: ["text"]), fingerprint = IndexDecoderFingerprint()
        let client = CaseContentIndexService(preview: { evidence, _, file in try fixture.preview(evidence, file) },
            verifySources: { _ in }, decoderFingerprint: { await fingerprint.next() })
        await #expect(throws: ContentIndexError.sourceChanged) { try await client.rebuild(caseID: UUID(), inputs: [fixture.input]) }
    }

    @Test("Stored array budgets are rejected during decoding", arguments: ["sources", "hashes", "documents", "pages"])
    func decodeCollectionBudget(kind: String) async throws {
        let fixture = IndexFixture(texts: ["text"])
        let snapshot = try await service().rebuild(caseID: UUID(), inputs: [fixture.input])
        var object = try #require(JSONSerialization.jsonObject(with: CaseWorkCoding.encode(snapshot)) as? [String: Any])
        var sources = try #require(object["sources"] as? [[String: Any]])
        var documents = try #require(object["documents"] as? [[String: Any]])
        switch kind {
        case "sources": sources = Array(repeating: sources[0], count: 129)
        case "hashes": sources[0]["orderedContainerSHA256"] = Array(repeating: fixture.evidence.sha256, count: 1_025)
        case "documents": documents = Array(repeating: documents[0], count: 513)
        case "pages":
            let pages = try #require(documents[0]["textPages"] as? [[String: Any]])
            documents[0]["textPages"] = Array(repeating: pages[0], count: 201)
        default: Issue.record("Unknown fixture")
        }
        object["sources"] = sources; object["documents"] = documents
        let bytes = try JSONSerialization.data(withJSONObject: object)
        #expect(throws: ContentIndexError.invalidSnapshot) { try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, bytes) }
    }

    private func service(truncated: Bool = false,
                         transform: (@Sendable (DocumentAnalysis, FilesystemEntry) throws -> DocumentAnalysis)? = nil) -> CaseContentIndexService {
        CaseContentIndexService(preview: { evidence, result, file in
            let text = result.warnings
            let pages = text.enumerated().map { DocumentTextPage(pageNumber: $0.offset + 1, text: $0.element,
                isTruncated: truncated, referenceLabel: "Page \($0.offset + 1)", referenceKind: .page) }
            let hash = digest(Data("payload-\(file.id)".utf8))
            let analysis = DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
                sourceSHA256: hash, sourceByteCount: file.size, pageCount: pages.count, textPages: pages)
            return FilesystemDocumentPreview(file: file,
                receipt: VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id, byteCount: file.size,
                    sha256: hash, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]),
                analysis: try transform?(analysis, file) ?? analysis)
        }, verifySources: { _ in }, decoderFingerprint: { String(repeating: "d", count: 64) })
    }
}

private struct IndexFixture: Sendable {
    let evidence: EvidenceRecord
    let result: EnumerationResult
    var input: ContentIndexInput { .init(evidence: evidence, result: result) }
    var files: [FilesystemEntry] { result.files }
    var hashes: [String: String] { Dictionary(uniqueKeysWithValues: files.map { ($0.id, digest(Data("payload-\($0.id)".utf8))) }) }
    init(texts: [String], fileSizes: [Int64] = [5], sourceURL: URL = URL(fileURLWithPath: "/synthetic/source.dd"),
         sourceBytes: Data = Data("container".utf8), evidenceID: UUID = UUID()) {
        evidence = EvidenceRecord(id: evidenceID, sourcePath: sourceURL.path, byteCount: Int64(sourceBytes.count),
            sha256: digest(sourceBytes), container: .raw, filesystemHint: "synthetic")
        let entries = fileSizes.enumerated().map { FilesystemEntry(id: "file-\($0.offset)", path: "/file\($0.offset).pdf",
            name: "file\($0.offset).pdf", fsOffsetBytes: 0, metaAddress: UInt64($0.offset + 1), size: $0.element, isDirectory: false, isDeleted: false) }
        result = EnumerationResult(engineVersion: "synthetic-v1", patchDigest: "fixture", sourcePaths: [sourceURL.path],
            sourceFileHashes: [sourceURL.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 1_024, sectorSize: 512), volumes: [], files: entries,
            warnings: texts, status: .completed)
    }
    func preview(_ evidence: EvidenceRecord, _ file: FilesystemEntry) throws -> FilesystemDocumentPreview {
        let hash = digest(Data("payload-\(file.id)".utf8))
        let pages = result.warnings.enumerated().map { DocumentTextPage(pageNumber: $0.offset + 1, text: $0.element, referenceKind: .page) }
        return FilesystemDocumentPreview(file: file, receipt: VerifiedContentReceipt(evidenceID: evidence.id,
            fileID: file.id, byteCount: file.size, sha256: hash, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]),
            analysis: DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
                sourceSHA256: hash, sourceByteCount: file.size, pageCount: pages.count, textPages: pages))
    }
}

private func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
private func temporaryFolder() throws -> URL {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("native-index-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false); return folder
}
private func persistedCase() throws -> (URL, ForensicCase, IndexFixture) {
    let folder = try temporaryFolder(), source = folder.appendingPathComponent("container.dd"), bytes = Data("container".utf8)
    try bytes.write(to: source)
    let base = try CaseStore.create(name: "Synthetic Content", in: folder)
    let evidence = EvidenceRecord(sourcePath: source.path, byteCount: Int64(bytes.count), sha256: digest(bytes), container: .raw, filesystemHint: nil)
    let manifest = CaseManifest(id: base.manifest.id, name: base.manifest.name, createdAt: base.manifest.createdAt, evidence: [evidence])
    let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
    try encoder.encode(manifest).write(to: base.bundleURL.appendingPathComponent("manifest.json"))
    let forensicCase = try CaseStore.open(at: base.bundleURL)
    let fixture = IndexFixture(texts: ["literal body"], sourceURL: source, sourceBytes: bytes, evidenceID: evidence.id)
    return (folder, forensicCase, fixture)
}

private actor IndexCancellationGate {
    var didStart = false, didClean = false
    private var starters: [CheckedContinuation<Void, Never>] = [], cleaners: [CheckedContinuation<Void, Never>] = []
    func started() { didStart = true; starters.forEach { $0.resume() }; starters = [] }
    func cleaned() { didClean = true; cleaners.forEach { $0.resume() }; cleaners = [] }
    func waitStarted() async { if !didStart { await withCheckedContinuation { starters.append($0) } } }
    func waitCleaned() async { if !didClean { await withCheckedContinuation { cleaners.append($0) } } }
}

private actor IndexDecoderFingerprint {
    private var count = 0
    func next() -> String { count += 1; return String(repeating: count == 1 ? "d" : "c", count: 64) }
}
