import CryptoKit
import Foundation
@testable import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("Case-only saved comparison history") @MainActor
struct MultiEvidenceHistoryStoreTests {
    @Test("Full and digest-only comparisons open with unavailable source and no filesystem listing", arguments: ["missing", "changed"])
    func offlineHistory(_ sourceState: String) async throws {
        let fixture = try await ComparisonHistoryFixture.make(); defer { fixture.remove() }
        let records = try fixture.savePair(), calls = ComparisonHistoryCalls()
        if sourceState == "missing" { try FileManager.default.removeItem(at: fixture.source) }
        else { try Data("changed owned synthetic source\n".utf8).write(to: fixture.source) }
        let before = try fixture.caseBytes()
        let sourceBefore = try? Data(contentsOf: fixture.source)
        #expect(!FileManager.default.fileExists(atPath: fixture.forensicCase.bundleURL.appendingPathComponent("filesystem").path))
        let store = unavailableLiveStore(calls: calls)
        store.configureHistory(forensicCase: fixture.forensicCase)
        await (try #require(store.jobTask)).value
        #expect(store.isPresented && store.isHistoryOnly)
        #expect(store.history.map(\.id) == records.reversed().map(\.id))
        #expect(store.connectionStatus == "Local history · source bytes remain unverified")
        #expect(store.verifiedFiles.isEmpty && store.context == nil && store.filePaths.isEmpty)
        for record in records {
            store.loadRecord(id: record.id)
            await (try #require(store.jobTask)).value
            #expect(store.savedRecord == record && store.result == record.result)
            #expect(store.references == record.references)
            #expect(!store.canAnalyze && !store.canPrepareContext && !store.canSaveAnalysis && !store.canBeginFollowUp)
            #expect(store.outboundPrompt.isEmpty)
            for reference in store.references {
                #expect(!store.canOpenReference(reference)); store.openReference(reference)
            }
            store.prepareContext(); store.rebuildDisclosure(); store.beginFollowUp()
            store.analyze(confirmedPrompt: "unexpected live request")
            store.saveAnalysis(retention: .full); store.copyContextPrompt()
            #expect(!store.hasActiveWork && store.openedReferenceText == nil && store.parentRecord == nil)
        }
        #expect(await calls.values.isEmpty)
        #expect(try fixture.caseBytes() == before)
        #expect((try? Data(contentsOf: fixture.source)) == sourceBefore)
    }

    @Test("Case-only history clears old live proof and explicit matching preparation restores action eligibility")
    func preparationTransition() async throws {
        let fixture = try await ComparisonHistoryFixture.make(); defer { fixture.remove() }
        let records = try fixture.savePair(), calls = ComparisonHistoryCalls(), files = fixture.files
        let store = MultiEvidenceAnalysisStore(executableURL: fixture.executable,
            prepare: { _, _, _, _, _ in await calls.record("prepare"); return files },
            verify: { _, _ in await calls.record("verify") },
            analyze: { _, _ in await calls.record("provider"); throw ComparisonHistoryTestError.unexpectedLiveOperation },
            scheduler: ForensicWorkScheduler())
        configureLive(store, fixture); await (try #require(store.jobTask)).value
        store.loadRecord(id: records[0].id); await (try #require(store.jobTask)).value
        let reference = try #require(store.references.first)
        #expect(store.canOpenReference(reference) && store.canBeginFollowUp)
        let preparedCalls = await calls.values
        store.configureHistory(forensicCase: fixture.forensicCase); await (try #require(store.jobTask)).value
        store.loadRecord(id: records[0].id); await (try #require(store.jobTask)).value
        #expect(store.isHistoryOnly && store.verifiedFiles.isEmpty && store.context == nil)
        #expect(!store.canOpenReference(reference) && !store.canBeginFollowUp && !store.canAnalyze)
        #expect(await calls.values == preparedCalls)
        configureLive(store, fixture); await (try #require(store.jobTask)).value
        store.loadRecord(id: records[0].id); await (try #require(store.jobTask)).value
        #expect(!store.isHistoryOnly && store.canOpenReference(reference) && store.canBeginFollowUp)
        store.beginFollowUp()
        #expect(store.parentRecord?.id == records[0].id)
        store.firstRedactions = "0:1"; store.rebuildDisclosure()
        #expect(store.parentRecord == nil && !store.canBeginFollowUp)
        #expect(await calls.values == ["prepare", "prepare"])
    }

    @Test("A foreign-case record or absent record cannot inherit the previous historical answer")
    func wrongCaseAndMissingRecord() async throws {
        let first = try await ComparisonHistoryFixture.make(), second = try await ComparisonHistoryFixture.make()
        defer { first.remove(); second.remove() }
        let foreign = try first.savePair()[0], local = try second.savePair()[0]
        let calls = ComparisonHistoryCalls(), store = unavailableLiveStore(calls: calls)
        store.configureHistory(forensicCase: second.forensicCase); await (try #require(store.jobTask)).value
        store.loadRecord(id: local.id); await (try #require(store.jobTask)).value
        #expect(store.savedRecord == local)
        let foreignBytes = try Data(contentsOf: first.recordURL(foreign.id))
        try foreignBytes.write(to: second.recordURL(foreign.id), options: .withoutOverwriting)
        let before = try second.caseBytes()
        store.loadRecord(id: foreign.id); await (try #require(store.jobTask)).value
        #expect(store.errorMessage != nil && store.savedRecord == nil && store.result == nil && store.references.isEmpty)
        store.loadRecord(id: UUID()); await (try #require(store.jobTask)).value
        #expect(store.errorMessage != nil && store.savedRecord == nil && store.openedReferenceText == nil)
        store.loadHistory(); await (try #require(store.jobTask)).value
        #expect(store.errorMessage != nil)
        #expect(try second.caseBytes() == before)
        #expect(try Data(contentsOf: second.recordURL(foreign.id)) == foreignBytes)
        #expect(await calls.values.isEmpty)
    }

    @Test("Historical pages replace rather than accumulate bounded summaries")
    func boundedPaging() async throws {
        let fixture = try await ComparisonHistoryFixture.make(); defer { fixture.remove() }
        var records: [MultiEvidenceAnalysisRecord] = []
        for offset in 0..<53 {
            let record = try fixture.record(retention: offset.isMultiple(of: 2) ? .full : .digestOnly, offset: offset)
            try MultiEvidenceRecordStore.save(record, in: fixture.forensicCase.bundleURL); records.append(record)
        }
        let before = try fixture.caseBytes(), calls = ComparisonHistoryCalls(), store = unavailableLiveStore(calls: calls)
        store.configureHistory(forensicCase: fixture.forensicCase); await (try #require(store.jobTask)).value
        #expect(store.history.count == 50 && store.canLoadOlderHistory)
        #expect(store.history.map(\.id) == records.reversed().prefix(50).map(\.id))
        store.loadHistory(older: true); await (try #require(store.jobTask)).value
        #expect(store.history.count == 3 && store.historyShowsOlderPage && !store.canLoadOlderHistory)
        #expect(store.history.map(\.id) == records.reversed().suffix(3).map(\.id))
        store.loadHistory(); await (try #require(store.jobTask)).value
        #expect(store.history.count == 50 && !store.historyShowsOlderPage)
        #expect(try fixture.caseBytes() == before)
        #expect(await calls.values.isEmpty)
    }

    @Test("Queued history cancellation starts no case reader and preserves the other workflow owner")
    func queuedCancellation() async throws {
        let fixture = try await ComparisonHistoryFixture.make(); defer { fixture.remove() }
        _ = try fixture.savePair()
        let scheduler = ForensicWorkScheduler(), calls = ComparisonHistoryCalls()
        let permit = try await scheduler.acquireImmediately(.imageInspection)
        let store = unavailableLiveStore(calls: calls, scheduler: scheduler,
            history: { url, before in await calls.record("history"); return try MultiEvidenceRecordStore.history(in: url, before: before) })
        store.configureHistory(forensicCase: fixture.forensicCase)
        let pending = try #require(store.jobTask)
        do {
            try await waitForHistoryScheduler(scheduler) { $0.queuedKinds == [.historyRead] }
            store.cancel(); await pending.value
            #expect(await calls.values.isEmpty)
            #expect(await scheduler.state().active?.id == permit.admission.id)
            #expect(await scheduler.state().queuedKinds.isEmpty)
            #expect(!store.hasActiveWork && store.history.isEmpty)
            _ = await permit.release()
        } catch {
            store.cancel(); await pending.value; _ = await permit.release(); throw error
        }
    }

    @Test("Closing an admitted history reader retains its owner through drain and prevents a late cross-case page")
    func activeHistoryDrain() async throws {
        let first = try await ComparisonHistoryFixture.make(), second = try await ComparisonHistoryFixture.make()
        defer { first.remove(); second.remove() }
        _ = try first.savePair(); let secondRecords = try second.savePair()
        let rows = try MultiEvidenceRecordStore.history(in: first.forensicCase.bundleURL)
        let gate = ComparisonHistoryGate<[MultiEvidenceRecordSummary]>(), scheduler = ForensicWorkScheduler(), calls = ComparisonHistoryCalls()
        let firstURL = first.forensicCase.bundleURL
        let store = unavailableLiveStore(calls: calls, scheduler: scheduler, history: { url, before in
            await calls.record("history")
            if url == firstURL { return await gate.hold() }
            return try MultiEvidenceRecordStore.history(in: url, before: before)
        })
        store.configureHistory(forensicCase: first.forensicCase)
        let pending = try #require(store.jobTask)
        var waiting: Task<ForensicWorkPermit, Error>?
        do {
            try await waitForHistoryCondition { await gate.hasEntered }
            let owner = try #require(await scheduler.state().active)
            #expect(owner.kind == .historyRead)
            waiting = Task { try await scheduler.acquire(.extraction) }
            try await waitForHistoryScheduler(scheduler) { $0.queuedKinds == [.extraction] }
            store.close(); store.configureHistory(forensicCase: second.forensicCase)
            #expect(store.hasActiveWork && store.isWorking && store.isPresented)
            #expect(await scheduler.state().active?.id == owner.id)
            await gate.release(rows); await pending.value
            try await waitForHistoryCondition { !store.isPresented }
            let queued = try #require(waiting)
            let next = try await queued.value
            #expect(next.admission.kind == .extraction && next.admission.id != owner.id)
            #expect(store.history.isEmpty && store.savedRecord == nil && !store.hasActiveWork)
            _ = await next.release()
            store.configureHistory(forensicCase: second.forensicCase); await (try #require(store.jobTask)).value
            #expect(store.history.map(\.id) == secondRecords.reversed().map(\.id))
            #expect(await calls.values == ["history", "history"])
        } catch {
            store.cancel(); waiting?.cancel(); await gate.release(rows); await pending.value
            if let waiting, let admitted = try? await waiting.value { _ = await admitted.release() }
            throw error
        }
    }

    @Test("Cancelled or closed record loading discards a late answer and keeps fresh actions unavailable", arguments: [false, true])
    func activeRecordDrain(_ close: Bool) async throws {
        let fixture = try await ComparisonHistoryFixture.make(), other = try await ComparisonHistoryFixture.make()
        defer { fixture.remove(); other.remove() }
        let record = try fixture.savePair()[0], gate = ComparisonHistoryGate<MultiEvidenceAnalysisRecord?>()
        let calls = ComparisonHistoryCalls(), scheduler = ForensicWorkScheduler()
        let store = unavailableLiveStore(calls: calls, scheduler: scheduler, loadRecord: { _, _ in await gate.hold() })
        store.configureHistory(forensicCase: fixture.forensicCase); await (try #require(store.jobTask)).value
        store.loadRecord(id: record.id)
        let pending = try #require(store.jobTask)
        do {
            try await waitForHistoryCondition { await gate.hasEntered }
            if close { store.close() } else { store.cancel() }
            store.configureHistory(forensicCase: other.forensicCase)
            #expect(store.hasActiveWork && store.isWorking)
            #expect(await scheduler.state().active?.kind == .historyRead)
            await gate.release(record); await pending.value
            if close { try await waitForHistoryCondition { !store.isPresented } }
            #expect(store.savedRecord == nil && store.result == nil && store.references.isEmpty)
            #expect(!store.hasActiveWork && !store.canBeginFollowUp && !store.canAnalyze)
            #expect(await scheduler.state().active == nil)
            #expect(await calls.values.isEmpty)
        } catch { store.cancel(); await gate.release(record); await pending.value; throw error }
    }

    @Test("Saved Comparisons entry requires a case but no evidence selection, listing or helper")
    func workspaceEntryPoint() async throws {
        let fixture = try await ComparisonHistoryFixture.make(); defer { fixture.remove() }
        let records = try fixture.savePair()
        try FileManager.default.removeItem(at: fixture.source)
        let workspace = WorkspaceStore(helperURL: fixture.helper, scheduler: ForensicWorkScheduler())
        #expect(!workspace.canOpenComparisonHistory)
        workspace.currentCase = fixture.forensicCase
        #expect(workspace.selectedEvidence == nil && workspace.selectedFilesystemResult == nil)
        #expect(!workspace.canOpenComparison && workspace.canOpenComparisonHistory)
        workspace.openComparisonHistory(); await (try #require(workspace.comparisonAssistant.jobTask)).value
        #expect(workspace.comparisonAssistant.isHistoryOnly)
        #expect(workspace.comparisonAssistant.history.map(\.id) == records.reversed().map(\.id))
        #expect(workspace.isBusy && !workspace.canOpenComparisonHistory)
    }

    private func unavailableLiveStore(calls: ComparisonHistoryCalls, scheduler: ForensicWorkScheduler = ForensicWorkScheduler(),
                                      history: MultiEvidenceAnalysisStore.History? = nil,
                                      loadRecord: MultiEvidenceAnalysisStore.LoadRecord? = nil) -> MultiEvidenceAnalysisStore {
        MultiEvidenceAnalysisStore(executableURL: URL(fileURLWithPath: "/unavailable-synthetic-history-cli"),
            prepare: { _, _, _, _, _ in await calls.record("prepare"); throw ComparisonHistoryTestError.unexpectedLiveOperation },
            verify: { _, _ in await calls.record("verify"); throw ComparisonHistoryTestError.unexpectedLiveOperation },
            save: { _, _ in await calls.record("save"); throw ComparisonHistoryTestError.unexpectedLiveOperation },
            analyze: { _, _ in await calls.record("provider"); throw ComparisonHistoryTestError.unexpectedLiveOperation },
            history: history, loadRecord: loadRecord, scheduler: scheduler)
    }

    private func configureLive(_ store: MultiEvidenceAnalysisStore, _ fixture: ComparisonHistoryFixture) {
        store.configure(evidence: fixture.evidence, result: fixture.result, files: fixture.entries,
            helperURL: fixture.helper, forensicCase: fixture.forensicCase)
    }
}

private actor ComparisonHistoryCalls {
    private(set) var values: [String] = []
    func record(_ value: String) { values.append(value) }
}

/// A deliberately cancellation-insensitive reader tests that its UI owner waits
/// for drainage and rejects a late value. It never runs a decoder or provider.
private actor ComparisonHistoryGate<Value: Sendable> {
    private(set) var hasEntered = false
    private var continuation: CheckedContinuation<Value, Never>?
    func hold() async -> Value {
        await withCheckedContinuation { continuation in
            hasEntered = true; self.continuation = continuation
        }
    }
    func release(_ value: Value) { continuation?.resume(returning: value); continuation = nil }
}

private enum ComparisonHistoryTestError: Error { case unexpectedLiveOperation, gateTimedOut }

@MainActor private func waitForHistoryCondition(_ predicate: @MainActor () async -> Bool) async throws {
    let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(5))
    while !(await predicate()) {
        guard clock.now < deadline else { throw ComparisonHistoryTestError.gateTimedOut }
        try await Task.sleep(for: .milliseconds(5))
    }
}

@MainActor private func waitForHistoryScheduler(_ scheduler: ForensicWorkScheduler,
                                              _ predicate: (ForensicSchedulerState) -> Bool) async throws {
    try await waitForHistoryCondition { predicate(await scheduler.state()) }
}

/// Owned synthetic UTF-8 receipts exercise real immutable storage and offline
/// reads. The extracted-file receipts are fabricated; no engine is executed.
private struct ComparisonHistoryFixture: Sendable {
    let directory: URL, source: URL, helper: URL, executable: URL
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let result: EnumerationResult
    let entries: [FilesystemEntry]
    let files: [MultiEvidenceVerifiedFile]

    static func make() async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ComparisonHistory-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let source = directory.appendingPathComponent("owned-synthetic-source.dd"), helper = directory.appendingPathComponent("never-run-engine")
        let executable = directory.appendingPathComponent("never-run-provider")
        let sourceBytes = Data("owned history source\n".utf8)
        try sourceBytes.write(to: source, options: .withoutOverwriting)
        try Data("synthetic executable marker; never executed\n".utf8).write(to: executable, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let created = try CaseStore.create(name: "Owned Comparison History", in: directory)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspected, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let texts = ["one synthetic comparison", "two synthetic comparison"]
        let entries = texts.enumerated().map { offset, text in FilesystemEntry(id: "0:\(offset + 1)",
            path: "/FILE\(offset + 1).txt", name: "FILE\(offset + 1).txt", fsOffsetBytes: 0,
            metaAddress: UInt64(offset + 1), size: Int64(text.utf8.count), isDirectory: false, isDeleted: false) }
        let result = EnumerationResult(engineVersion: "synthetic-history", patchDigest: "synthetic-only", sourcePaths: [source.path],
            sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: Int64(sourceBytes.count), sectorSize: 512), volumes: [], files: entries,
            warnings: [], status: .completed, savedAt: Date(timeIntervalSinceReferenceDate: 813_457_690.125))
        let files = try entries.enumerated().map { offset, entry in
            let bytes = Data(texts[offset].utf8)
            let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entry)
            let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entry.id, byteCount: entry.size,
                sha256: Self.digest(bytes), verifiedAt: Date(timeIntervalSinceReferenceDate: 813_457_691.25), orderedContainerSHA256: [evidence.sha256])
            return try MultiEvidenceVerifiedFile(binding: binding, content: .init(bytes: bytes, receipt: receipt))
        }
        return Self(directory: directory, source: source, helper: helper, executable: executable,
            forensicCase: forensicCase, evidence: evidence, result: result, entries: entries, files: files)
    }

    func record(retention: AnalysisRetention, offset: Int = 0, parent: MultiEvidenceAnalysisRecord? = nil) throws -> MultiEvidenceAnalysisRecord {
        let context = try MultiEvidenceContext.make(files: files, selections: files.map(\.defaultSelection))
        let question = "Owned synthetic history question \(offset)", prompt = try MultiEvidencePrompt.make(context: context, question: question, parent: parent)
        let response = CodexAnalysisResult(response: .init(summary: "Historical \(offset) [[A1:0:3]] [[B1:0:3]]",
            observations: [], hypotheses: [], limitations: ["Fabricated synthetic response; no provider"], nextSteps: []),
            requestSHA256: Self.digest(Data(prompt.utf8)), completedAt: Date(timeIntervalSinceReferenceDate: 813_457_692.5 + Double(offset)))
        return try MultiEvidenceAnalysisRecord.make(context: context, question: question, prompt: prompt, result: response, retention: retention, parent: parent)
    }
    func savePair() throws -> [MultiEvidenceAnalysisRecord] {
        let parent = try record(retention: .full), child = try record(retention: .digestOnly, offset: 1, parent: parent)
        try MultiEvidenceRecordStore.save(parent, in: forensicCase.bundleURL)
        try MultiEvidenceRecordStore.save(child, in: forensicCase.bundleURL)
        return [parent, child]
    }
    func recordURL(_ id: UUID) -> URL {
        forensicCase.bundleURL.appendingPathComponent("comparisons").appendingPathComponent(id.uuidString.lowercased() + ".json")
    }
    func caseBytes() throws -> [String: Data] {
        var result = ["manifest.json": try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json"))]
        for url in try FileManager.default.contentsOfDirectory(at: forensicCase.bundleURL.appendingPathComponent("comparisons"), includingPropertiesForKeys: nil) {
            result["comparisons/" + url.lastPathComponent] = try Data(contentsOf: url)
        }
        return result
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    private static func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}
