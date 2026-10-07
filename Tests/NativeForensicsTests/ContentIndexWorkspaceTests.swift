import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("ContentIndexWorkspaceTests")
@MainActor
struct ContentIndexWorkspaceTests {
    @Test("Rebuild resolves saved listings for every case source and searches content-only text")
    func allCaseSources() async throws {
        let fixture = ContentIndexUIFixture(sourceCount: 2), saved = ContentIndexSavedBox()
        let store = makeStore(fixture, saved: saved)
        store.configure(forensicCase: fixture.forensicCase, results: [fixture.evidence[0].id: fixture.results[fixture.evidence[0].id]!])
        await store.operationTask?.value
        #expect(store.missingListingCount == 0); #expect(store.canRebuild)
        store.rebuild(); await store.operationTask?.value
        #expect(store.snapshot?.indexedCount == 2); #expect(saved.count == 1)
        #expect(!store.isHistorical); #expect(!store.isStale); #expect(!store.hasActiveWork)
        store.query = "content-only-needle"; await store.searchTask?.value
        #expect(store.searchOutcome?.hits.count == 2)
        #expect(Set(store.searchOutcome?.hits.map { $0.reference.evidenceID } ?? []) == Set(fixture.evidence.map(\.id)))
    }

    @Test("Reopened generation remains historical without rebuilding or reading source bytes")
    func historicalAndStale() async throws {
        let fixture = ContentIndexUIFixture(), snapshot = try await fixture.snapshot()
        let counter = ContentIndexSavedBox()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { _, _, _ in counter.record(snapshot); return snapshot }, load: { _ in snapshot },
            save: { _, _, _ in }, loadListing: { id, _ in fixture.results[id] })
        store.configure(forensicCase: fixture.forensicCase, results: [:]); await store.operationTask?.value
        #expect(store.snapshot == snapshot); #expect(store.isHistorical); #expect(!store.isStale)
        #expect(counter.count == 0)
        store.query = "content-only-needle"; await store.searchTask?.value
        #expect(store.searchOutcome?.hits.count == 1)
        let modified = ContentIndexUIFixture(caseID: fixture.forensicCase.manifest.id,
            evidenceIDs: fixture.evidence.map(\.id), byteSize: 10)
        store.configure(forensicCase: modified.forensicCase, results: modified.results); await store.operationTask?.value
        #expect(store.isStale); #expect(store.isHistorical); #expect(counter.count == 0)
    }

    @Test("Case replacement drains the canceled rebuild owner and never saves its stale result")
    func generationReplacement() async throws {
        let first = ContentIndexUIFixture(), second = ContentIndexUIFixture(), gate = ContentIndexBuildGate()
        let saved = ContentIndexSavedBox()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { id, inputs, _ in try await gate.build(id, inputs) }, load: { _ in nil },
            save: { value, _, _ in saved.record(value) }, loadListing: { _, _ in nil })
        store.configure(forensicCase: first.forensicCase, results: first.results); await store.operationTask?.value
        store.rebuild(); let firstTask = try #require(store.operationTask)
        let request = await gate.next()
        store.configure(forensicCase: second.forensicCase, results: second.results)
        #expect(store.hasActiveWork)
        await gate.succeed(request, value: try await first.snapshot())
        await firstTask.value; await store.operationTask?.value
        #expect(store.snapshot == nil); #expect(saved.count == 0); #expect(!store.hasActiveWork)
        #expect(store.canRebuild)
    }

    @Test("Cancel and close retain active owners until real completion, preserving the previous index")
    func cancelAndShutdownDrain() async throws {
        let fixture = ContentIndexUIFixture(), existing = try await fixture.snapshot(), gate = ContentIndexBuildGate()
        let saved = ContentIndexSavedBox()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { id, inputs, _ in try await gate.build(id, inputs) }, load: { _ in existing },
            save: { value, _, _ in saved.record(value) }, loadListing: { _, _ in nil })
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.rebuild(); let task = try #require(store.operationTask), request = await gate.next()
        store.cancel(); #expect(store.hasActiveWork)
        await gate.succeed(request, value: try await fixture.snapshot())
        await task.value
        #expect(store.snapshot == existing); #expect(saved.count == 0); #expect(!store.hasActiveWork)
        store.rebuild(); let next = await gate.next()
        let shutdown = try #require(store.beginShutdown())
        #expect(store.hasActiveWork); #expect(!store.canRebuild)
        await gate.succeed(next, value: try await fixture.snapshot()); await shutdown.value
        #expect(!store.hasActiveWork); #expect(saved.count == 0); #expect(store.snapshot == nil)
    }

    @Test("Failed compare/save and mismatched source snapshots leave the previous displayed generation")
    func rejectedSave() async throws {
        let fixture = ContentIndexUIFixture(), existing = try await fixture.snapshot()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { _, _, _ in try await fixture.snapshot() }, load: { _ in existing },
            save: { _, _, _ in throw ContentIndexError.staleGeneration }, loadListing: { _, _ in nil })
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.rebuild(); await store.operationTask?.value
        #expect(store.snapshot == existing); #expect(store.errorMessage != nil); #expect(store.isHistorical)
        #expect(!store.hasActiveWork)
    }

    @Test("Rapid query replacement and index reset cannot publish superseded hits")
    func searchRaces() async throws {
        let fixture = ContentIndexUIFixture(), snapshot = try await fixture.snapshot()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            load: { _ in snapshot }, save: { _, _, _ in }, loadListing: { _, _ in nil })
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.query = "content-only-needle"; let old = store.searchTask
        store.query = "not present"; await old?.value; await store.searchTask?.value
        #expect(store.searchOutcome?.query == "not present"); #expect(store.searchOutcome?.hits.isEmpty == true)
        store.query = "content-only-needle"; let pending = store.searchTask
        store.reset(); await pending?.value
        #expect(store.searchOutcome == nil); #expect(store.snapshot == nil); #expect(!store.hasActiveWork)
    }

    @Test("Unreadable saved listing remains explicitly uncovered instead of stopping every source")
    func unreadableListing() async throws {
        let fixture = ContentIndexUIFixture(sourceCount: 2)
        let firstID = fixture.evidence[0].id
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { id, inputs, _ in try await fixture.service.rebuild(caseID: id, inputs: inputs) },
            load: { _ in nil }, save: { _, _, _ in }, loadListing: { id, _ in
                if id == firstID { return fixture.results[id] }
                throw ContentIndexError.invalidSnapshot
            })
        store.configure(forensicCase: fixture.forensicCase, results: [:]); await store.operationTask?.value
        #expect(store.missingListingCount == 1); #expect(store.errorMessage != nil)
        store.rebuild(); await store.operationTask?.value
        #expect(store.snapshot?.indexedCount == 1); #expect(store.snapshot?.missingListingCount == 1)
        #expect(store.snapshot?.isPartial == true)
    }

    private func makeStore(_ fixture: ContentIndexUIFixture, saved: ContentIndexSavedBox) -> ContentIndexWorkspaceStore {
        ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { id, inputs, update in try await fixture.service.rebuild(caseID: id, inputs: inputs, progress: update) },
            load: { _ in nil }, save: { value, _, _ in saved.record(value) }, loadListing: { id, _ in fixture.results[id] })
    }
}

private struct ContentIndexUIFixture: Sendable {
    let forensicCase: ForensicCase
    let evidence: [EvidenceRecord]
    let results: [UUID: EnumerationResult]
    var service: CaseContentIndexService {
        CaseContentIndexService(preview: { evidence, _, file in
            let hash = String(repeating: "c", count: 64)
            return FilesystemDocumentPreview(file: file, receipt: VerifiedContentReceipt(evidenceID: evidence.id,
                fileID: file.id, byteCount: file.size, sha256: hash, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]),
                analysis: DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
                    sourceSHA256: hash, sourceByteCount: file.size,
                    textPages: [DocumentTextPage(pageNumber: 1, text: "ภาษาไทย content-only-needle", referenceKind: .document)]))
        }, verifySources: { _ in }, decoderFingerprint: { String(repeating: "d", count: 64) })
    }
    init(sourceCount: Int = 1, caseID: UUID = UUID(), evidenceIDs: [UUID]? = nil, byteSize: Int64 = 5) {
        evidence = (0..<sourceCount).map { index in
            EvidenceRecord(id: evidenceIDs?[index] ?? UUID(), sourcePath: "/synthetic/container-\(index).dd",
                byteCount: 1_024, sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
        }
        results = Dictionary(uniqueKeysWithValues: evidence.map { source in
            let file = FilesystemEntry(id: "same-inode-file", path: "/unrelated.txt", name: "unrelated.txt", fsOffsetBytes: 0,
                metaAddress: 9, size: byteSize, isDirectory: false, isDeleted: false)
            return (source.id, EnumerationResult(engineVersion: "synthetic-v1", patchDigest: "test", sourcePaths: [source.sourcePath],
                sourceFileHashes: [source.sourcePath: source.sha256], options: EngineOptions(hashLogicalImage: false),
                image: EngineImageMetadata(imageType: "raw", logicalSize: 1_024, sectorSize: 512), volumes: [], files: [file],
                warnings: [], status: .completed, savedAt: Date(timeIntervalSince1970: 100)))
        })
        forensicCase = ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/content.nativecase"),
            manifest: CaseManifest(id: caseID, name: "Synthetic Content", evidence: evidence))
    }
    func snapshot() async throws -> CaseContentIndexSnapshot {
        try await service.rebuild(caseID: forensicCase.manifest.id,
            inputs: evidence.map { ContentIndexInput(evidence: $0, result: results[$0.id]) })
    }
}

private final class ContentIndexSavedBox: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [CaseContentIndexSnapshot] = []
    var count: Int { lock.withLock { values.count } }
    func record(_ value: CaseContentIndexSnapshot) { lock.withLock { values.append(value) } }
}

private actor ContentIndexBuildGate {
    struct Request: Sendable { let id: UUID; let caseID: UUID; let inputs: [ContentIndexInput] }
    private var requests: [Request] = []
    private var waiting: [CheckedContinuation<Request, Never>] = []
    private var builds: [UUID: CheckedContinuation<CaseContentIndexSnapshot, Error>] = [:]
    func build(_ caseID: UUID, _ inputs: [ContentIndexInput]) async throws -> CaseContentIndexSnapshot {
        let request = Request(id: UUID(), caseID: caseID, inputs: inputs)
        return try await withCheckedThrowingContinuation { continuation in
            builds[request.id] = continuation
            if waiting.isEmpty { requests.append(request) } else { waiting.removeFirst().resume(returning: request) }
        }
    }
    func next() async -> Request {
        if !requests.isEmpty { return requests.removeFirst() }
        return await withCheckedContinuation { waiting.append($0) }
    }
    func succeed(_ request: Request, value: CaseContentIndexSnapshot) { builds.removeValue(forKey: request.id)?.resume(returning: value) }
}
