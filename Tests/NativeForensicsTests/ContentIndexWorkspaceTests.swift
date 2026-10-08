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
        #expect(Set(store.searchOutcome?.hits.map { $0.reference.indexReference.evidenceID } ?? []) == Set(fixture.evidence.map(\.id)))
    }

    @Test("Reopened generation remains historical without rebuilding or reading source bytes")
    func historicalAndStale() async throws {
        let fixture = ContentIndexUIFixture(), snapshot = try await fixture.snapshot()
        let counter = ContentIndexSavedBox()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { _, _, _ in counter.record(snapshot); return snapshot }, load: { _ in snapshot },
            save: { _, _, _ in }, loadListing: { id, _ in fixture.results[id] }, scheduler: ForensicWorkScheduler())
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
            save: { value, _, _ in saved.record(value) }, loadListing: { _, _ in nil }, scheduler: ForensicWorkScheduler())
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
            save: { value, _, _ in saved.record(value) }, loadListing: { _, _ in nil }, scheduler: ForensicWorkScheduler())
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
            save: { _, _, _ in throw ContentIndexError.staleGeneration }, loadListing: { _, _ in nil }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.rebuild(); await store.operationTask?.value
        #expect(store.snapshot == existing); #expect(store.errorMessage != nil); #expect(store.isHistorical)
        #expect(!store.hasActiveWork)
    }

    @Test("Rapid query replacement and index reset cannot publish superseded hits")
    func searchRaces() async throws {
        let fixture = ContentIndexUIFixture(), snapshot = try await fixture.snapshot()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            load: { _ in snapshot }, save: { _, _, _ in }, loadListing: { _, _ in nil }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.query = "content-only-needle"; let old = store.searchTask
        store.query = "not present"; await old?.value; await store.searchTask?.value
        #expect(store.searchOutcome?.query == "not present"); #expect(store.searchOutcome?.hits.isEmpty == true)
        store.query = "content-only-needle"; let pending = store.searchTask
        store.reset(); await pending?.value
        #expect(store.searchOutcome == nil); #expect(store.snapshot == nil); #expect(!store.hasActiveWork)
    }

    @Test("Mode and sensitivity changes cancel superseded requests while preserving raw query text")
    func queryModeRaces() async throws {
        let fixture = ContentIndexUIFixture(), snapshot = try await fixture.snapshot()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            load: { _ in snapshot }, save: { _, _, _ in }, loadListing: { _, _ in nil }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.query = "needle"; let old = store.searchTask
        store.searchMode = .tokenPrefix; await old?.value; await store.searchTask?.value
        #expect(store.searchOutcome?.mode == .tokenPrefix)
        #expect(store.searchOutcome?.hits.count == 1)
        store.searchMode = .phrase; let phrase = store.searchTask
        store.caseSensitive = true
        await phrase?.value; await store.searchTask?.value
        #expect(store.searchOutcome?.request == ContentIndexQueryRequest(query: "needle", mode: .phrase, caseSensitive: true))
        store.query = "[needle]"; await store.searchTask?.value
        #expect(store.searchOutcome?.query == "[needle]")
        #expect(store.searchOutcome?.queryIssue == .phraseContainsNonWordText)
        store.searchMode = .literal; await store.searchTask?.value
        #expect(store.searchOutcome?.queryIssue == nil)
        #expect(store.searchOutcome?.hits.isEmpty == true)
        store.searchMode = .tokenPrefix; store.query = "content"; let pending = store.searchTask
        let shutdown = store.beginShutdown(); await pending?.value; await shutdown?.value
        #expect(store.searchOutcome == nil); #expect(!store.hasActiveWork)
    }

    @Test("Update publishes a fresh generation and retains explicit final reuse counters")
    func incrementalUpdate() async throws {
        let fixture = ContentIndexUIFixture(), existing = try await fixture.snapshot(), saved = ContentIndexSavedBox()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { _, _, _ in throw ContentIndexError.invalidSnapshot },
            update: { id, inputs, previous, progress in
                #expect(previous.id == existing.id)
                return try await fixture.service.update(caseID: id, inputs: inputs, previous: previous, progress: progress)
            }, load: { _ in existing }, save: { value, expected, _ in
                #expect(expected == existing.id); saved.record(value)
            }, loadListing: { _, _ in nil }, scheduler: ForensicWorkScheduler())
        #expect(!store.canUpdate)
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        #expect(store.canUpdate)
        store.query = "content-only-needle"; await store.searchTask?.value
        let oldHit = try #require(store.searchOutcome?.hits.first)
        store.update(); await store.operationTask?.value; await store.searchTask?.value
        let next = try #require(store.snapshot)
        #expect(next.id != existing.id); #expect(saved.count == 1)
        #expect(next.sources == existing.sources)
        #expect(next.documents == existing.documents)
        #expect(next.decoderBinarySHA256 == existing.decoderBinarySHA256)
        #expect(store.progress?.reusedFiles == 1); #expect(store.progress?.rebuiltFiles == 0)
        #expect(store.phase.contains("Reused 1; rebuilt 0."))
        #expect(!store.isHistorical); #expect(!store.isStale)
        #expect(CaseContentIndexSearch.resolve(oldHit.reference, in: next) == nil)
        let freshHit = try #require(store.searchOutcome?.hits.first)
        #expect(freshHit.reference.indexReference.snapshotID == next.id)
        #expect(freshHit.reference.indexReference.contentSHA256 == oldHit.reference.indexReference.contentSHA256)
        #expect(freshHit.reference.indexReference.derivedTextSHA256 == oldHit.reference.indexReference.derivedTextSHA256)
        #expect(CaseContentIndexSearch.resolve(freshHit.reference, in: next) != nil)
    }

    @Test("Two content workbenches cancel queued load or update before any worker starts", arguments: [false, true])
    func queuedCancellation(_ queuedUpdate: Bool) async throws {
        let scheduler = ForensicWorkScheduler(), ownerFixture = ContentIndexUIFixture(), queuedFixture = ContentIndexUIFixture()
        let ownerValue = try await ownerFixture.snapshot(), previous = try await queuedFixture.snapshot()
        let gate = ContentIndexBuildGate(), calls = ContentIndexSchedulerCalls()
        let owner = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { id, inputs, _ in try await gate.build(id, inputs) }, load: { _ in nil },
            save: { _, _, _ in }, loadListing: { _, _ in nil }, scheduler: scheduler)
        let queued = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { _, _, _ in calls.record("rebuild"); return previous },
            update: { _, _, _, _ in calls.record("update"); return previous },
            load: { _ in calls.record("load"); return previous },
            save: { _, _, _ in calls.record("save") },
            loadListing: { id, _ in calls.record("listing"); return queuedFixture.results[id] }, scheduler: scheduler)
        owner.configure(forensicCase: ownerFixture.forensicCase, results: ownerFixture.results)
        await owner.operationTask?.value
        if queuedUpdate {
            queued.configure(forensicCase: queuedFixture.forensicCase, results: [:])
            await queued.operationTask?.value
            #expect(queued.canUpdate); calls.clear()
        }
        owner.rebuild()
        let ownerTask = try #require(owner.operationTask), request = await gate.next()
        if queuedUpdate { queued.update() }
        else { queued.configure(forensicCase: queuedFixture.forensicCase, results: [:]) }
        let queuedOwner = queued.operationTask
        do {
            let queuedTask = try #require(queuedOwner)
            try await waitForContentScheduler(scheduler) { $0.queuedKinds == [.contentIndex] }
            let activeID = try #require(await scheduler.state().active?.id)
            queued.cancel(); await queuedTask.value
            #expect(calls.values.isEmpty)
            #expect(await scheduler.state().active?.id == activeID)
            #expect(await scheduler.state().queuedKinds.isEmpty)
            #expect(owner.hasActiveWork); #expect(!queued.hasActiveWork)
            if queuedUpdate { #expect(queued.snapshot == previous) }
            await gate.succeed(request, value: ownerValue); await ownerTask.value
            #expect(await scheduler.state().active == nil)
        } catch {
            queued.cancel()
            await gate.succeed(request, value: ownerValue)
            await ownerTask.value; await queuedOwner?.value
            throw error
        }
    }

    @Test("An admitted atomic publisher keeps its slot through late cancellation and close", arguments: [false, true])
    func publisherLifetime(_ close: Bool) async throws {
        let scheduler = ForensicWorkScheduler(), fixture = ContentIndexUIFixture(), other = ContentIndexUIFixture()
        let existing = try await fixture.snapshot(), next = try await fixture.snapshot()
        let gate = ContentIndexPublisherGate(), saved = ContentIndexSavedBox(), otherCalls = ContentIndexSchedulerCalls()
        let store = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { _, _, _ in
                #expect(ForensicWorkExecutionContext.requestedPriority == .utility)
                return next
            }, load: { _ in existing }, save: { value, expected, _ in
                #expect(expected == existing.id)
                try gate.publish()
                saved.record(value)
            }, loadListing: { _, _ in nil }, scheduler: scheduler)
        let waiting = ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            load: { _ in otherCalls.record("load"); return nil }, save: { _, _, _ in otherCalls.record("save") },
            loadListing: { id, _ in otherCalls.record("listing"); return other.results[id] }, scheduler: scheduler)
        store.configure(forensicCase: fixture.forensicCase, results: fixture.results); await store.operationTask?.value
        store.rebuild(); let operation = try #require(store.operationTask)
        do {
            try await waitForContentCondition { gate.hasEntered }
            let activeID = try #require(await scheduler.state().active?.id)
            // Saved-text matching stays responsive while the publisher owns
            // the heavy slot; it cannot queue a nested heavy admission.
            store.query = "content-only-needle"; await store.searchTask?.value
            #expect(store.searchOutcome?.hits.count == 1)
            #expect(await scheduler.state().active?.id == activeID)
            waiting.configure(forensicCase: other.forensicCase, results: [:])
            let waitingTask = try #require(waiting.operationTask)
            try await waitForContentScheduler(scheduler) { $0.queuedKinds == [.contentIndex] }
            store.cancel()
            let shutdown = close ? store.beginShutdown() : nil
            #expect(store.hasActiveWork)
            #expect(saved.count == 0); #expect(otherCalls.values.isEmpty)
            #expect(await scheduler.state().active?.id == activeID)
            #expect(await scheduler.state().queuedKinds == [.contentIndex])
            gate.release()
            await operation.value; await shutdown?.value; await waitingTask.value
            if !close {
                await store.searchTask?.value
                #expect(store.searchOutcome?.hits.count == 1)
                #expect(store.searchOutcome?.hits.first?.reference.indexReference.snapshotID == next.id)
            }
            #expect(saved.count == 1); #expect(!store.hasActiveWork)
            #expect(otherCalls.values == ["load", "listing"])
            #expect(await scheduler.state().active == nil)
            if close { #expect(store.snapshot == nil) }
            else {
                #expect(store.snapshot == next)
                #expect(store.phase.contains("Derived index saved"))
                #expect(!store.isHistorical)
            }
        } catch {
            gate.release(); waiting.cancel()
            await operation.value; await waiting.beginShutdown()?.value
            await store.beginShutdown()?.value
            throw error
        }
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
            }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: fixture.forensicCase, results: [:]); await store.operationTask?.value
        #expect(store.missingListingCount == 1); #expect(store.errorMessage != nil)
        store.rebuild(); await store.operationTask?.value
        #expect(store.snapshot?.indexedCount == 1); #expect(store.snapshot?.missingListingCount == 1)
        #expect(store.snapshot?.isPartial == true)
    }

    private func makeStore(_ fixture: ContentIndexUIFixture, saved: ContentIndexSavedBox) -> ContentIndexWorkspaceStore {
        ContentIndexWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"),
            rebuild: { id, inputs, update in try await fixture.service.rebuild(caseID: id, inputs: inputs, progress: update) },
            load: { _ in nil }, save: { value, _, _ in saved.record(value) }, loadListing: { id, _ in fixture.results[id] }, scheduler: ForensicWorkScheduler())
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

private final class ContentIndexSchedulerCalls: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [String] = []
    func record(_ value: String) { lock.withLock { recorded.append(value) } }
    func clear() { lock.withLock { recorded.removeAll() } }
    var values: [String] { lock.withLock { recorded } }
}

private final class ContentIndexPublisherGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false, released = false
    var hasEntered: Bool {
        condition.lock(); defer { condition.unlock() }; return entered
    }
    func publish() throws {
        condition.lock(); entered = true; condition.broadcast()
        let deadline = Date(timeIntervalSinceNow: 10)
        while !released {
            guard condition.wait(until: deadline) else {
                condition.unlock(); throw ContentIndexSchedulingTestError.gateTimedOut
            }
        }
        condition.unlock()
        // A late owner cancellation must not reach the atomic worker.
        try Task.checkCancellation()
    }
    func release() {
        condition.lock(); released = true; condition.broadcast(); condition.unlock()
    }
}

private enum ContentIndexSchedulingTestError: Error { case gateTimedOut }

@MainActor
private func waitForContentScheduler(_ scheduler: ForensicWorkScheduler,
                                     _ predicate: (ForensicSchedulerState) -> Bool) async throws {
    let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(5))
    while !predicate(await scheduler.state()) {
        guard clock.now < deadline else { throw ContentIndexSchedulingTestError.gateTimedOut }
        try await Task.sleep(for: .milliseconds(5))
    }
}

@MainActor
private func waitForContentCondition(_ predicate: () -> Bool) async throws {
    let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(5))
    while !predicate() {
        guard clock.now < deadline else { throw ContentIndexSchedulingTestError.gateTimedOut }
        try await Task.sleep(for: .milliseconds(5))
    }
}
