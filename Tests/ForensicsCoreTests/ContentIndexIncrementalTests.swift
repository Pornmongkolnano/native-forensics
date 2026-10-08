import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

@Suite("ContentIndexIncrementalTests")
struct ContentIndexIncrementalTests {
    @Test("An unchanged update reuses indexed documents only after two fresh verification boundaries")
    func unchangedReuse() async throws {
        let fixture = IncrementalFixture(texts: ["alpha", "beta"]), spy = IncrementalSpy(), progress = IncrementalProgressBox()
        let service = incrementalService(spy: spy)
        let old = try await service.rebuild(caseID: UUID(), inputs: [fixture.input])
        let oldHit = try #require(CaseContentIndexSearch.search("alpha", in: old).hits.first)
        let next = try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: old, progress: progress.record)
        #expect(next.id != old.id); #expect(next.documents == old.documents)
        #expect(await spy.previewCount == 2); #expect(await spy.verificationCount == 4)
        #expect(progress.latest?.reusedFiles == 2); #expect(progress.latest?.rebuiltFiles == 0)
        #expect(progress.latest?.finishedFiles == 2)
        #expect(CaseContentIndexSearch.resolve(oldHit.reference, in: next) == nil)
    }

    @Test("A changed source rebuilds all its eligible files and retains unchanged evidence")
    func changedSourceIsolation() async throws {
        let first = IncrementalFixture(texts: ["first", "other"], sourceURL: URL(fileURLWithPath: "/synthetic/changed-source.dd"))
        let second = IncrementalFixture(texts: ["stable"], sourceURL: URL(fileURLWithPath: "/synthetic/stable-source.dd"))
        let spy = IncrementalSpy(), service = incrementalService(spy: spy), progress = IncrementalProgressBox()
        let old = try await service.rebuild(caseID: UUID(), inputs: [first.input, second.input])
        let changed = IncrementalFixture(texts: ["fresh", "bytes"], evidenceID: first.evidence.id,
            sourceURL: URL(fileURLWithPath: first.evidence.sourcePath),
            sourceBytes: Data("changed-container".utf8))
        let next = try await service.update(caseID: old.caseID, inputs: [changed.input, second.input], previous: old, progress: progress.record)
        #expect(await spy.previewCount == 5)
        #expect(progress.latest?.reusedFiles == 1); #expect(progress.latest?.rebuiltFiles == 2)
        #expect(next.documents[0].textPages[0].text == "fresh")
        #expect(next.documents[1].textPages[0].text == "bytes")
        #expect(next.documents[2] == old.documents[2])
    }

    @Test("Decoder, engine, options, file and limit changes disable reuse", arguments: ["decoder", "engine", "options", "file", "limits"])
    func bindingInvalidation(kind: String) async throws {
        let fixture = IncrementalFixture(texts: ["alpha"]), spy = IncrementalSpy()
        let old = try await incrementalService(spy: spy).rebuild(caseID: UUID(), inputs: [fixture.input])
        let current: IncrementalFixture
        var limits = ContentIndexLimits(), decoderHash = String(repeating: "d", count: 64)
        switch kind {
        case "engine": current = IncrementalFixture(texts: ["alpha"], evidenceID: fixture.evidence.id, engineVersion: "changed-engine")
        case "options": current = IncrementalFixture(texts: ["alpha"], evidenceID: fixture.evidence.id,
            options: .init(timezone: "UTC", hashLogicalImage: false))
        case "file": current = IncrementalFixture(texts: ["alpha"], fileSizes: [6], evidenceID: fixture.evidence.id)
        case "limits": current = fixture; limits.maximumTextBytes = 1_000
        default: current = fixture; decoderHash = String(repeating: "e", count: 64)
        }
        let progress = IncrementalProgressBox()
        _ = try await incrementalService(spy: spy, decoderHash: decoderHash).update(caseID: old.caseID,
            inputs: [current.input], previous: old, limits: limits, progress: progress.record)
        #expect(await spy.previewCount == 2)
        #expect(progress.latest?.reusedFiles == 0); #expect(progress.latest?.rebuiltFiles == 1)
    }

    @Test("Reuse preserves budget, omitted and partial records while retrying failed files")
    func budgetsPartialAndRetry() async throws {
        let fixture = IncrementalFixture(texts: ["alpha", "other", "third", "four", "fifth"], fileSizes: [5, 40, 5, 5, 5])
        let limits = ContentIndexLimits(maximumFiles: 4, maximumFileBytes: 10, maximumInputBytes: 6, maximumTextBytes: 10)
        let spy = IncrementalSpy(), service = incrementalService(spy: spy), progress = IncrementalProgressBox()
        let old = try await service.rebuild(caseID: UUID(), inputs: [fixture.input], limits: limits)
        let next = try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: old, limits: limits, progress: progress.record)
        #expect(next.documents.map(\.status) == [.indexed, .skipped, .pending, .pending])
        #expect(next.documents.map(\.reason) == [nil, "FILE_BYTE_LIMIT", "INPUT_BYTE_BUDGET", "INPUT_BYTE_BUDGET"])
        #expect(next.omittedRegularFiles == 1); #expect(next.pendingCount == 3); #expect(next.isPartial)
        #expect(await spy.previewCount == 1); #expect(progress.latest?.reusedFiles == 1); #expect(progress.latest?.rebuiltFiles == 0)
        let partial = IncrementalFixture(texts: ["partial"])
        let partialOld = try await incrementalService(spy: spy, truncated: true).rebuild(caseID: UUID(), inputs: [partial.input])
        let partialNext = try await service.update(caseID: partialOld.caseID, inputs: [partial.input], previous: partialOld)
        #expect(partialNext.isPartial); #expect(partialNext.documents[0].reason == "PARTIAL_DECODER_COVERAGE")
        let retry = IncrementalFixture(texts: ["okay", "retry"])
        let failed = try await incrementalService(spy: spy, failingFileIDs: ["file-1"]).rebuild(caseID: UUID(), inputs: [retry.input])
        #expect(failed.documents.map(\.status) == [.indexed, .failed])
        let retried = try await service.update(caseID: failed.caseID, inputs: [retry.input], previous: failed, progress: progress.record)
        #expect(retried.documents.map(\.status) == [.indexed, .indexed])
        #expect(progress.latest?.reusedFiles == 1); #expect(progress.latest?.rebuiltFiles == 1)
    }

    @Test("Corrupt prior derived text, wrong case and forged unchanged-source file membership fail closed")
    func invalidPrevious() async throws {
        let fixture = IncrementalFixture(texts: ["alpha"]), spy = IncrementalSpy(), service = incrementalService(spy: spy)
        let old = try await service.rebuild(caseID: UUID(), inputs: [fixture.input])
        await #expect(throws: ContentIndexError.invalidSnapshot) {
            try await service.update(caseID: UUID(), inputs: [fixture.input], previous: old)
        }
        let document = old.documents[0]
        let corrupt = ContentIndexDocument(evidenceID: document.evidenceID, file: document.file,
            locatorSHA256: document.locatorSHA256, status: .indexed, reason: nil, contentSHA256: document.contentSHA256,
            derivedTextSHA256: document.derivedTextSHA256,
            textPages: [.init(pageNumber: 1, text: "corrupt", referenceKind: .document)], textIsComplete: true)
        await #expect(throws: ContentIndexError.invalidSnapshot) {
            try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: replacingDocuments(old, [corrupt]))
        }
        let forgedFile = FilesystemEntry(id: document.file.id, path: "/not-in-listing.txt", name: "not-in-listing.txt",
            fsOffsetBytes: 0, metaAddress: document.file.metaAddress, size: document.file.size, isDirectory: false, isDeleted: false)
        let forged = try ContentIndexDocument.make(evidenceID: document.evidenceID, file: forgedFile, status: .indexed,
            contentSHA256: document.contentSHA256, pages: document.textPages, complete: true)
        let invalidMembership = replacingDocuments(old, [forged])
        try invalidMembership.validate() // General snapshot validation cannot prove listing membership.
        await #expect(throws: ContentIndexError.invalidSnapshot) {
            try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: invalidMembership)
        }
        #expect(await spy.previewCount == 1)
    }

    @Test("Real ordered-source hashes detect a changed secondary container before and after an all-reuse update")
    func realOrderedSourceBoundaries() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("native-index-incremental-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let primary = folder.appendingPathComponent("primary.dd"), secondary = folder.appendingPathComponent("secondary.dd")
        let original = Data("source-original".utf8), other = Data("second-original".utf8), changed = Data("second-modified".utf8)
        try original.write(to: primary); try other.write(to: secondary)
        let fixture = IncrementalFixture(texts: ["alpha"], sourceURL: primary, sourceBytes: original,
            secondarySource: (secondary, other))
        let spy = IncrementalSpy(), verified = incrementalService(spy: spy, verify: CaseContentIndexService.verify)
        let old = try await verified.rebuild(caseID: UUID(), inputs: [fixture.input])
        try changed.write(to: secondary)
        await #expect(throws: ContentIndexError.sourceChanged) {
            try await verified.update(caseID: old.caseID, inputs: [fixture.input], previous: old)
        }
        try other.write(to: secondary)
        let boundary = IncrementalBoundary()
        let mutateAfterFirst: CaseContentIndexService.VerifySources = { inputs in
            try await CaseContentIndexService.verify(inputs)
            if await boundary.next() == 1 { try changed.write(to: secondary) }
        }
        await #expect(throws: ContentIndexError.sourceChanged) {
            try await incrementalService(spy: spy, verify: mutateAfterFirst).update(caseID: old.caseID,
                inputs: [fixture.input], previous: old)
        }
        #expect(await spy.previewCount == 1)
        #expect(try Data(contentsOf: secondary) == changed)
    }

    @Test("A decoder replacement at the closing boundary rejects an otherwise reusable generation")
    func closingDecoderBoundary() async throws {
        let fixture = IncrementalFixture(texts: ["alpha"]), spy = IncrementalSpy()
        let old = try await incrementalService(spy: spy).rebuild(caseID: UUID(), inputs: [fixture.input])
        let fingerprint = IncrementalBoundary()
        let service = CaseContentIndexService(preview: { evidence, result, file in
            await spy.preview(); return incrementalPreview(evidence, result, file)
        }, verifySources: { _ in await spy.verify() }, decoderFingerprint: {
            await fingerprint.next() == 1 ? String(repeating: "d", count: 64) : String(repeating: "e", count: 64)
        })
        await #expect(throws: ContentIndexError.sourceChanged) {
            try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: old)
        }
        #expect(await spy.previewCount == 1)
    }

    @Test("Update cancellation and deadlines drain the owned verification task")
    func updateDrain() async throws {
        let fixture = IncrementalFixture(texts: ["alpha"]), spy = IncrementalSpy()
        let old = try await incrementalService(spy: spy).rebuild(caseID: UUID(), inputs: [fixture.input])
        let gate = IncrementalDrainGate()
        let service = incrementalService(spy: spy, verify: { _ in
            await gate.started()
            do { try await Task.sleep(for: .seconds(30)) }
            catch { await gate.drained(); throw error }
        })
        let task = Task { try await service.update(caseID: old.caseID, inputs: [fixture.input], previous: old) }
        await gate.waitStarted(); task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(await gate.didDrain)
        let deadlineGate = IncrementalDrainGate()
        let timed = incrementalService(spy: spy, verify: { _ in
            await deadlineGate.started()
            do { try await Task.sleep(for: .seconds(30)) }
            catch { await deadlineGate.drained(); throw error }
        })
        await #expect(throws: ContentIndexError.timeout) {
            try await timed.update(caseID: old.caseID, inputs: [fixture.input], previous: old, limits: .init(timeoutSeconds: 0.02))
        }
        #expect(await deadlineGate.didDrain)
    }
}

private func replacingDocuments(_ snapshot: CaseContentIndexSnapshot, _ documents: [ContentIndexDocument]) -> CaseContentIndexSnapshot {
    .init(schemaVersion: snapshot.schemaVersion, id: snapshot.id, caseID: snapshot.caseID, builtAt: snapshot.builtAt,
        decoderContract: snapshot.decoderContract, decoderBinarySHA256: snapshot.decoderBinarySHA256, limits: snapshot.limits,
        sources: snapshot.sources, documents: documents, omittedRegularFiles: snapshot.omittedRegularFiles, skippedDirectories: snapshot.skippedDirectories)
}

private struct IncrementalFixture: Sendable {
    let evidence: EvidenceRecord
    let result: EnumerationResult
    var input: ContentIndexInput { .init(evidence: evidence, result: result) }
    init(texts: [String], fileSizes: [Int64]? = nil, evidenceID: UUID = UUID(),
         sourceURL: URL = URL(fileURLWithPath: "/synthetic/incremental.dd"), sourceBytes: Data = Data("container".utf8),
         engineVersion: String = "synthetic-incremental-v1", options: EngineOptions = .init(hashLogicalImage: false),
         secondarySource: (URL, Data)? = nil) {
        evidence = EvidenceRecord(id: evidenceID, sourcePath: sourceURL.path, byteCount: Int64(sourceBytes.count),
            sha256: incrementalDigest(sourceBytes), container: .raw, filesystemHint: nil)
        let sizes = fileSizes ?? texts.map { Int64($0.utf8.count) }
        let files = sizes.enumerated().map { FilesystemEntry(id: "file-\($0.offset)", path: "/file\($0.offset).txt",
            name: "file\($0.offset).txt", fsOffsetBytes: 0, metaAddress: UInt64($0.offset + 1), size: $0.element,
            isDirectory: false, isDeleted: false) }
        let paths = [sourceURL.path] + (secondarySource.map { [$0.0.path] } ?? [])
        var hashes = [sourceURL.path: evidence.sha256]
        if let secondarySource { hashes[secondarySource.0.path] = incrementalDigest(secondarySource.1) }
        result = EnumerationResult(engineVersion: engineVersion, patchDigest: "fixture", sourcePaths: paths,
            sourceFileHashes: hashes, options: options,
            image: .init(imageType: "raw", logicalSize: 1_024, sectorSize: 512, imagePaths: paths),
            volumes: [], files: files, warnings: texts, status: .completed, savedAt: Date(timeIntervalSince1970: 100))
    }
}

private func incrementalService(spy: IncrementalSpy, decoderHash: String = String(repeating: "d", count: 64),
                                verify: CaseContentIndexService.VerifySources? = nil, truncated: Bool = false,
                                failingFileIDs: Set<String> = []) -> CaseContentIndexService {
    CaseContentIndexService(preview: { evidence, result, file in
        await spy.preview()
        if failingFileIDs.contains(file.id) { throw DocumentAnalysisError.invalidResponse }
        return incrementalPreview(evidence, result, file, truncated: truncated)
    }, verifySources: { inputs in
        await spy.verify()
        if let verify { try await verify(inputs) }
    }, decoderFingerprint: { decoderHash })
}

private func incrementalPreview(_ evidence: EvidenceRecord, _ result: EnumerationResult, _ file: FilesystemEntry,
                                truncated: Bool = false) -> FilesystemDocumentPreview {
    let index = Int(file.id.dropFirst("file-".count)) ?? 0
    let text = result.warnings[index], hash = incrementalDigest(Data("payload-\(file.id)".utf8))
    return FilesystemDocumentPreview(file: file,
        receipt: .init(evidenceID: evidence.id, fileID: file.id, byteCount: file.size, sha256: hash,
            verifiedAt: Date(), orderedContainerSHA256: result.sourcePaths.map { result.sourceFileHashes[$0]! }),
        analysis: .init(contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: hash, sourceByteCount: file.size,
            textPages: [.init(pageNumber: 1, text: text, isTruncated: truncated, referenceKind: .document)]))
}

private func incrementalDigest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
private actor IncrementalSpy {
    var previewCount = 0, verificationCount = 0
    func preview() { previewCount += 1 }
    func verify() { verificationCount += 1 }
}
private final class IncrementalProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: ContentIndexProgress?
    func record(_ progress: ContentIndexProgress) { lock.withLock { value = progress } }
    var latest: ContentIndexProgress? { lock.withLock { value } }
}
private actor IncrementalBoundary {
    private var value = 0
    func next() -> Int { value += 1; return value }
}
private actor IncrementalDrainGate {
    private var didStart = false
    var didDrain = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func started() { didStart = true; waiters.forEach { $0.resume() }; waiters = [] }
    func drained() { didDrain = true }
    func waitStarted() async { if !didStart { await withCheckedContinuation { waiters.append($0) } } }
}
