import Foundation
import Testing
@testable import ForensicsCore

@Suite("ContentIndexDecoderBindingTests")
struct ContentIndexDecoderBindingTests {
    @Test("Nil decoder additions preserve independent legacy canonical bytes")
    func legacyBytes() async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let spy = DecoderIndexSpy(), service = decoderIndexService(fixture, identity: nil, spy: spy)
        let snapshot = try await service.rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        let encoded = try CaseWorkCoding.encode(snapshot)
        #expect(encoded == (try CaseWorkCoding.encode(LegacyDecoderIndex(snapshot))))
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let documents = try #require(object["documents"] as? [[String: Any]])
        #expect(object["decoderIdentity"] == nil); #expect(documents.first?["decoderProvenance"] == nil)
        let reopened = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, encoded)
        try reopened.validate()
        #expect(reopened.decoderIdentity == nil); #expect(reopened.documents.first?.decoderProvenance == nil)
        #expect(reopened.decoderContract == "NFDocumentDecoder.document-analysis.v1")
        #expect(await spy.identityCount == 0); #expect(await spy.legacyCount == 2)
        #expect(await spy.sourceCount == 2)
    }

    @Test("Current and partial indexed text retain the exact complete decoder receipt through reopen", arguments: [false, true])
    func retainedProof(_ partial: Bool) async throws {
        let fixture = try await DecoderIndexFixture(partial: partial); defer { fixture.remove() }
        let identity = try decoderIndexIdentity(), spy = DecoderIndexSpy()
        let snapshot = try await decoderIndexService(fixture, identity: identity, spy: spy)
            .rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        #expect(snapshot.decoderIdentity == identity)
        #expect(snapshot.decoderContract == identity.decoderIdentifier + "@" + identity.decoderVersion)
        let document = try #require(snapshot.documents.first)
        #expect(document.decoderProvenance == (try fixture.proof(identity)))
        #expect(document.derivedTextSHA256 == document.decoderProvenance?.derivedTextSHA256)
        #expect(document.derivedTextSHA256 == (try CaseWorkCoding.digest(fixture.pages)))
        #expect(document.textIsComplete == !partial)
        try CaseContentIndexStore.save(snapshot, expectedSnapshotID: nil, in: fixture.forensicCase.bundleURL)
        let reopened = try #require(try CaseContentIndexStore.load(in: fixture.forensicCase.bundleURL))
        #expect(try CaseWorkCoding.encode(reopened) == CaseWorkCoding.encode(snapshot))
        #expect(reopened.documents == snapshot.documents)
        #expect(await spy.identityCount == 2); #expect(await spy.legacyCount == 0)
        #expect(await spy.sourceCount == 2)
    }

    @Test("Complete decoder binding reuses unchanged proofs only across two fresh source and identity fences")
    func completeReuse() async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let identity = try decoderIndexIdentity(), spy = DecoderIndexSpy(), progress = DecoderIndexProgress()
        let service = decoderIndexService(fixture, identity: identity, spy: spy)
        let old = try await service.rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        let oldHit = try #require(CaseContentIndexSearch.search("needle", in: old, mode: .phrase).hits.first)
        let next = try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: old, progress: progress.record)
        #expect(next.id != old.id); #expect(next.documents == old.documents); #expect(next.sources == old.sources)
        #expect(next.decoderIdentity == old.decoderIdentity)
        #expect(await spy.previewCount == 1); #expect(await spy.sourceCount == 4)
        #expect(await spy.identityCount == 4); #expect(await spy.legacyCount == 0)
        #expect(progress.latest?.reusedFiles == 1); #expect(progress.latest?.rebuiltFiles == 0)
        #expect(CaseContentIndexSearch.resolve(oldHit.reference, in: next) == nil)
        let hit = try #require(CaseContentIndexSearch.search("needle", in: next, mode: .phrase).hits.first)
        #expect(hit.reference.indexReference.decoderProvenanceSHA256 == (try CaseWorkCoding.digest(fixture.proof(identity))))
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: next) != nil)
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("A historical nil identity is rebuilt rather than promoted from equal worker SHA")
    func legacyRebuild() async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let spy = DecoderIndexSpy(), progress = DecoderIndexProgress()
        let old = try await decoderIndexService(fixture, identity: nil, spy: spy)
            .rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        let identity = try decoderIndexIdentity()
        let next = try await decoderIndexService(fixture, identity: identity, spy: spy)
            .update(caseID: old.caseID, inputs: [fixture.input], previous: old, progress: progress.record)
        #expect(next.decoderBinarySHA256 == old.decoderBinarySHA256)
        #expect(next.decoderIdentity == identity); #expect(next.documents.first?.decoderProvenance != nil)
        #expect(await spy.previewCount == 2); #expect(await spy.sourceCount == 4)
        #expect(progress.latest?.reusedFiles == 0); #expect(progress.latest?.rebuiltFiles == 1)
    }

    @Test("Same worker with changed broker, signing, options or backend forces decoding", arguments: ["broker", "worker-signing", "broker-signing", "options", "backend"])
    func bindingRefresh(_ kind: String) async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let spy = DecoderIndexSpy(), progress = DecoderIndexProgress(), original = try decoderIndexIdentity()
        let old = try await decoderIndexService(fixture, identity: original, spy: spy)
            .rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        let changed = try decoderIndexIdentity(kind)
        #expect(changed.decoderExecutableSHA256 == original.decoderExecutableSHA256)
        #expect(changed != original)
        let next = try await decoderIndexService(fixture, identity: changed, spy: spy)
            .update(caseID: old.caseID, inputs: [fixture.input], previous: old, progress: progress.record)
        #expect(next.decoderIdentity == changed); #expect(next.documents.first?.decoderProvenance == (try fixture.proof(changed)))
        #expect(await spy.previewCount == 2); #expect(await spy.sourceCount == 4)
        #expect(progress.latest?.reusedFiles == 0); #expect(progress.latest?.rebuiltFiles == 1)
    }

    @Test("A full identity change at the closing fence rejects the whole generation", arguments: ["broker", "options", "backend"])
    func closingFence(_ kind: String) async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let initial = try decoderIndexIdentity(), changed = try decoderIndexIdentity(kind), spy = DecoderIndexSpy()
        let service = decoderIndexService(fixture, identity: initial, spy: spy, provider: {
            await spy.identityRead() == 1 ? initial : changed
        })
        await #expect(throws: ContentIndexError.sourceChanged) {
            try await service.rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        }
        #expect(await spy.sourceCount == 2); #expect(await spy.identityCount == 2)
        #expect(try CaseContentIndexStore.load(in: fixture.forensicCase.bundleURL) == nil)
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Valid but mismatched receipt, missing proof and unbound current proof cannot publish", arguments: ["mismatch", "missing", "unbound", "source-changed"])
    func receiptMismatch(_ kind: String) async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let identity = try decoderIndexIdentity(), spy = DecoderIndexSpy()
        let service = decoderIndexService(fixture, identity: kind == "unbound" ? nil : identity, spy: spy,
            receiptIdentity: kind == "mismatch" ? try decoderIndexIdentity("broker") : identity,
            legacyPreview: kind == "missing", sourceChanged: kind == "source-changed")
        await #expect(throws: ContentIndexError.sourceChanged) {
            try await service.rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        }
        #expect(try CaseContentIndexStore.load(in: fixture.forensicCase.bundleURL) == nil)
    }

    @Test("Closed identity/proof shape rejects crossed modes and changed derived reference metadata", arguments: ["missing-proof", "missing-identity", "legacy-marker", "worker", "nonindexed", "derived", "label", "truncation", "options-digest"])
    func invalidSnapshots(_ kind: String) async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let identity = try decoderIndexIdentity()
        let snapshot = try await decoderIndexService(fixture, identity: identity, spy: DecoderIndexSpy())
            .rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        let bytes = try mutatedDecoderIndex(snapshot) { object in
            var documents = object["documents"] as! [[String: Any]], document = documents[0]
            switch kind {
            case "missing-proof": document.removeValue(forKey: "decoderProvenance")
            case "missing-identity": object.removeValue(forKey: "decoderIdentity"); object["decoderContract"] = "NFDocumentDecoder.document-analysis.v1"
            case "legacy-marker": object["decoderContract"] = "NFDocumentDecoder.document-analysis.v1"
            case "worker": object["decoderBinarySHA256"] = String(repeating: "f", count: 64)
            case "nonindexed":
                document["status"] = "failed"; document["reason"] = "DECODE_FAILED"; document["textPages"] = []
                document.removeValue(forKey: "contentSHA256"); document.removeValue(forKey: "derivedTextSHA256"); document["textIsComplete"] = false
            case "label", "truncation":
                var pages = document["textPages"] as! [[String: Any]]
                if kind == "label" { pages[0]["referenceLabel"] = "Different raw reference" }
                else { pages[0]["isTruncated"] = true; document["textIsComplete"] = false; document["reason"] = "PARTIAL_DECODER_COVERAGE" }
                document["textPages"] = pages
            default:
                var proof = document["decoderProvenance"] as! [String: Any]
                proof[kind == "derived" ? "derivedTextSHA256" : "optionsSHA256"] = String(repeating: "f", count: 64)
                document["decoderProvenance"] = proof
            }
            documents[0] = document; object["documents"] = documents
        }
        #expect(throws: ContentIndexError.invalidSnapshot) {
            let invalid = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, bytes)
            try invalid.validate()
        }
    }

    @Test("References reject same-generation header changes, altered proof and stripped receipt digest")
    func boundReferences() async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let identity = try decoderIndexIdentity(), changed = try decoderIndexIdentity("broker")
        let snapshot = try await decoderIndexService(fixture, identity: identity, spy: DecoderIndexSpy())
            .rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        let hit = try #require(CaseContentIndexSearch.search("needle", in: snapshot, mode: .phrase).hits.first)
        let reference = hit.reference.indexReference
        let changedHeader = try JSONSerialization.jsonObject(with: CaseWorkCoding.encode(changed))
        let headerBytes = try mutatedDecoderIndex(snapshot) { $0["decoderIdentity"] = changedHeader }
        let header = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, headerBytes)
        #expect(header.id == snapshot.id)
        #expect(CaseContentIndexSearch.resolve(reference, in: header) == nil)
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: header) == nil)
        let stripped = ContentIndexReference(snapshotID: reference.snapshotID, evidenceID: reference.evidenceID,
            listingSHA256: reference.listingSHA256, file: reference.file, locatorSHA256: reference.locatorSHA256,
            orderedContainerSHA256: reference.orderedContainerSHA256, contentSHA256: reference.contentSHA256,
            derivedTextSHA256: reference.derivedTextSHA256, decoderBinarySHA256: reference.decoderBinarySHA256,
            pageNumber: reference.pageNumber, utf16Offset: reference.utf16Offset, utf16Length: reference.utf16Length,
            referenceLabel: reference.referenceLabel, referenceKind: reference.referenceKind)
        #expect(stripped.decoderProvenanceSHA256 == nil)
        #expect(CaseContentIndexSearch.resolve(stripped, in: snapshot) == nil)
        let proofBytes = try mutatedDecoderIndex(snapshot) { object in
            var documents = object["documents"] as! [[String: Any]], proof = documents[0]["decoderProvenance"] as! [String: Any]
            proof["brokerExecutableSHA256"] = changed.brokerExecutableSHA256
            documents[0]["decoderProvenance"] = proof; object["documents"] = documents
        }
        let altered = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, proofBytes)
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: altered) == nil)
        let bodyBytes = try mutatedDecoderIndex(snapshot) { object in
            var documents = object["documents"] as! [[String: Any]], pages = documents[0]["textPages"] as! [[String: Any]]
            pages[0]["text"] = "😀 needle altered"
            documents[0]["textPages"] = pages; object["documents"] = documents
        }
        let changedBody = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, bodyBytes)
        #expect(changedBody.id == snapshot.id)
        #expect(CaseContentIndexSearch.resolve(reference, in: changedBody) == nil)
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: changedBody) == nil)
        #expect(throws: ContentIndexError.invalidSnapshot) { try CaseContentIndexSearch.search("needle", in: changedBody) }
    }

    @Test("Corrupt persisted provenance fails closed without rewriting historical bytes")
    func corruptedStore() async throws {
        let fixture = try await DecoderIndexFixture(); defer { fixture.remove() }
        let identity = try decoderIndexIdentity()
        let snapshot = try await decoderIndexService(fixture, identity: identity, spy: DecoderIndexSpy())
            .rebuild(caseID: fixture.forensicCase.manifest.id, inputs: [fixture.input])
        try CaseContentIndexStore.save(snapshot, expectedSnapshotID: nil, in: fixture.forensicCase.bundleURL)
        let corrupted = try mutatedDecoderIndex(snapshot) { object in
            var documents = object["documents"] as! [[String: Any]], proof = documents[0]["decoderProvenance"] as! [String: Any]
            proof["optionsSHA256"] = String(repeating: "f", count: 64)
            documents[0]["decoderProvenance"] = proof; object["documents"] = documents
        }
        let path = fixture.forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename)
        try corrupted.write(to: path)
        #expect(throws: ContentIndexError.invalidSnapshot) { try CaseContentIndexStore.load(in: fixture.forensicCase.bundleURL) }
        #expect(try Data(contentsOf: path) == corrupted)
    }
}

private let decoderIndexWorkerHash = String(repeating: "d", count: 64)

private func decoderIndexIdentity(_ variant: String = "base") throws -> DocumentDecoderIdentity {
    if variant == "backend" {
        return try DocumentDecoderIdentity(executableSHA256: decoderIndexWorkerHash, codeSigningCDHash: nil,
            isolation: .requiredDevelopmentSeatbelt, timeout: 5)
    }
    return try DocumentDecoderIdentity(executableSHA256: decoderIndexWorkerHash,
        codeSigningCDHash: String(repeating: variant == "worker-signing" ? "e" : "a", count: 40),
        isolation: .appSandboxXPC, timeout: variant == "options" ? 9 : 5,
        brokerExecutableSHA256: String(repeating: variant == "broker" ? "e" : "b", count: 64),
        brokerCodeSigningCDHash: String(repeating: variant == "broker-signing" ? "e" : "c", count: 40), ipcProtocolVersion: 2)
}

private struct DecoderIndexFixture: Sendable {
    let folder: URL
    let source: URL
    let forensicCase: ForensicCase
    let input: ContentIndexInput
    let pages: [DocumentTextPage]
    init(partial: Bool = false) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("decoder-index-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        folder = root; source = root.appendingPathComponent("source.dd")
        try Data("abc".utf8).write(to: source)
        let opened = try CaseStore.create(name: "Decoder Binding", in: root)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        #expect(inspected.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        let persisted = try CaseStore.adding(image: inspected, to: opened)
        forensicCase = persisted
        let evidence = try #require(persisted.manifest.evidence.first)
        let file = FilesystemEntry(id: "body", path: "/body.txt", name: "body.txt", fsOffsetBytes: 0,
            metaAddress: 9, size: 3, isDirectory: false, isDeleted: false)
        let result = EnumerationResult(engineVersion: "synthetic-decoder-binding", patchDigest: "fixture",
            sourcePaths: [evidence.sourcePath], sourceFileHashes: [evidence.sourcePath: evidence.sha256],
            options: EngineOptions(hashLogicalImage: false), image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512),
            volumes: [], files: [file], warnings: [], status: .completed)
        input = .init(evidence: evidence, result: result)
        pages = [.init(pageNumber: 1, text: "😀 needle กำ", isTruncated: partial, referenceLabel: "Raw body", referenceKind: .document)]
    }
    func proof(_ identity: DocumentDecoderIdentity) throws -> DocumentDecodeProvenance {
        try DocumentDecodeProvenance(executableSHA256: identity.decoderExecutableSHA256,
            codeSigningCDHash: identity.decoderCodeSigningCDHash, isolation: identity.isolation,
            timeout: identity.options.timeoutSeconds, pages: pages,
            brokerExecutableSHA256: identity.brokerExecutableSHA256, brokerCodeSigningCDHash: identity.brokerCodeSigningCDHash)
    }
    func remove() { try? FileManager.default.removeItem(at: folder) }
}

private func decoderIndexService(_ fixture: DecoderIndexFixture, identity: DocumentDecoderIdentity?, spy: DecoderIndexSpy,
                                 receiptIdentity: DocumentDecoderIdentity? = nil, legacyPreview: Bool = false,
                                 sourceChanged: Bool = false, provider: CaseContentIndexService.DecoderIdentityProvider? = nil) -> CaseContentIndexService {
    let identityProvider: CaseContentIndexService.DecoderIdentityProvider?
    if let provider { identityProvider = provider }
    else if let identity { identityProvider = { _ = await spy.identityRead(); return identity } }
    else { identityProvider = nil }
    let received = legacyPreview ? nil : (receiptIdentity ?? identity)
    return CaseContentIndexService(preview: { evidence, _, file in
        await spy.previewed()
        if sourceChanged { throw DocumentAnalysisError.sourceChanged }
        let proof = try received.map(fixture.proof)
        return FilesystemDocumentPreview(file: file, receipt: VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id,
            byteCount: file.size, sha256: evidence.sha256, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]),
            analysis: DocumentAnalysis(schemaVersion: proof == nil ? 1 : 2, contentKind: .text, mimeType: "text/plain", status: .decoded,
                sourceSHA256: evidence.sha256, sourceByteCount: file.size, textPages: fixture.pages, provenance: proof))
    }, verifySources: { inputs in
        await spy.sourceChecked(); try await CaseContentIndexService.verify(inputs)
    }, decoderFingerprint: { await spy.legacyRead(); return decoderIndexWorkerHash }, decoderIdentity: identityProvider)
}

private actor DecoderIndexSpy {
    private(set) var sourceCount = 0, identityCount = 0, legacyCount = 0, previewCount = 0
    func sourceChecked() { sourceCount += 1 }
    func identityRead() -> Int { identityCount += 1; return identityCount }
    func legacyRead() { legacyCount += 1 }
    func previewed() { previewCount += 1 }
}

private final class DecoderIndexProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var value: ContentIndexProgress?
    func record(_ value: ContentIndexProgress) { lock.withLock { self.value = value } }
    var latest: ContentIndexProgress? { lock.withLock { value } }
}

private func mutatedDecoderIndex(_ snapshot: CaseContentIndexSnapshot, _ mutation: (inout [String: Any]) throws -> Void) throws -> Data {
    let document = try #require(snapshot.documents.first)
    _ = try #require(document.decoderProvenance)
    try #require(document.status == .indexed)
    var object = try #require(JSONSerialization.jsonObject(with: CaseWorkCoding.encode(snapshot)) as? [String: Any])
    try mutation(&object)
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

/// Independent pre-extension shape, not encoding a new DTO then removing keys.
private struct LegacyDecoderIndex: Encodable {
    let schemaVersion: Int; let id: UUID; let caseID: UUID; let builtAt: Date
    let decoderContract: String; let decoderBinarySHA256: String; let limits: ContentIndexLimits
    let sources: [ContentIndexSource]; let documents: [LegacyDecoderIndexDocument]
    let omittedRegularFiles: Int; let skippedDirectories: Int
    init(_ value: CaseContentIndexSnapshot) {
        schemaVersion = value.schemaVersion; id = value.id; caseID = value.caseID; builtAt = value.builtAt
        decoderContract = value.decoderContract; decoderBinarySHA256 = value.decoderBinarySHA256; limits = value.limits
        sources = value.sources; documents = value.documents.map(LegacyDecoderIndexDocument.init)
        omittedRegularFiles = value.omittedRegularFiles; skippedDirectories = value.skippedDirectories
    }
}

private struct LegacyDecoderIndexDocument: Encodable {
    let evidenceID: UUID; let file: FilesystemEntry; let locatorSHA256: String; let status: ContentIndexFileStatus
    let reason: String?; let contentSHA256: String?; let derivedTextSHA256: String?; let textPages: [DocumentTextPage]; let textIsComplete: Bool
    init(_ value: ContentIndexDocument) {
        evidenceID = value.evidenceID; file = value.file; locatorSHA256 = value.locatorSHA256; status = value.status
        reason = value.reason; contentSHA256 = value.contentSHA256; derivedTextSHA256 = value.derivedTextSHA256
        textPages = value.textPages; textIsComplete = value.textIsComplete
    }
}
