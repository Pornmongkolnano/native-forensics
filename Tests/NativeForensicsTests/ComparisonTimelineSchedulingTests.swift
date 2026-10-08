import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("Comparison and timeline shared admission", .serialized)
@MainActor
struct ComparisonTimelineSchedulingTests {
    @Test("Canceling two queued stores never invokes either local preparation or timeline loading")
    func queuedOwnersNeverStartAfterCancellation() async throws {
        let fixture = try await ComparisonSchedulingFixture.make()
        defer { fixture.remove() }
        let scheduler = ForensicWorkScheduler(), preparation = ComparisonSchedulingCounter(), loading = ComparisonSchedulingCounter()
        let blocker = try await scheduler.acquire(.filesystemAnalysis)
        let comparison = makeComparison(fixture, scheduler: scheduler, prepare: { _, _, _, _, _ in
            await preparation.increment(); return fixture.files
        })
        configure(comparison, fixture)
        let queuedComparison = try #require(comparison.jobTask)
        try await waitForQueue(scheduler, count: 1)
        let timeline = makeTimeline(fixture, scheduler: scheduler, load: { caseID, evidence, result, historical in
            await loading.increment()
            return try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        })
        timeline.loadFilesystem()
        try await waitForQueue(scheduler, count: 2)
        comparison.cancel(); await queuedComparison.value
        try await waitForQueue(scheduler, count: 1)
        #expect(await scheduler.state().queuedKinds == [.timeline])
        timeline.cancel(); try await settle(timeline)
        #expect(await preparation.value == 0)
        #expect(await loading.value == 0)
        #expect(comparison.context == nil && timeline.report == nil)
        #expect(await scheduler.state().active?.id == blocker.admission.id)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        #expect(await blocker.release())
        #expect(await scheduler.state().active == nil)
    }

    @Test("An active comparison keeps admission through cancellation and owned child cleanup")
    func canceledPreparationDrainsBeforeTimelineAdmission() async throws {
        let fixture = try await ComparisonSchedulingFixture.make()
        defer { fixture.remove() }
        let scheduler = ForensicWorkScheduler(), cleanup = ComparisonSchedulingGate(), loading = ComparisonSchedulingCounter()
        let comparison = makeComparison(fixture, scheduler: scheduler, prepare: { _, _, _, _, _ in
            await cleanup.hold()
            try Task.checkCancellation()
            return fixture.files
        })
        configure(comparison, fixture)
        let preparation = try #require(comparison.jobTask)
        try await waitStarted(cleanup)
        let owner = try #require(await scheduler.state().active?.id)
        let timeline = makeTimeline(fixture, scheduler: scheduler, load: { caseID, evidence, result, historical in
            await loading.increment()
            return try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        })
        timeline.loadFilesystem(); try await waitForQueue(scheduler, count: 1)
        comparison.cancel()
        try await waitCancellation(cleanup)
        #expect(comparison.hasActiveWork)
        #expect(await scheduler.state().active?.id == owner)
        #expect(await scheduler.state().queuedKinds == [.timeline])
        #expect(await loading.value == 0)
        await cleanup.open()
        await preparation.value
        try await settle(timeline)
        #expect(await cleanup.cancelledAtRelease == true)
        #expect(comparison.context == nil && !comparison.hasActiveWork)
        #expect(await loading.value == 1)
        #expect(timeline.report?.events.count == 2)
        #expect(await scheduler.state().active == nil)
    }

    @Test("A begun immutable PDF comparison save drains before timeline work, including late cancellation", arguments: [false, true])
    func immutablePDFSaveRetainsAdmission(cancelAfterWriterStarted: Bool) async throws {
        let fixture = try await ComparisonSchedulingFixture.make()
        defer { fixture.remove() }
        let scheduler = ForensicWorkScheduler(), writer = ComparisonSchedulingGate(), writes = ComparisonSchedulingCounter(), loading = ComparisonSchedulingCounter()
        let comparison = makeComparison(fixture, scheduler: scheduler, save: { record, caseURL in
            await writer.hold()
            // This is an actual immutable record publisher, not a fake success.
            // A late cancellation must not cancel the explicitly begun child.
            try Task.checkCancellation()
            try await MultiEvidenceRecordStore.saveAsync(record, in: caseURL)
            await writes.increment()
        })
        configure(comparison, fixture)
        await (try #require(comparison.jobTask)).value
        #expect(comparison.context?.schemaVersion == 2)
        comparison.analyze(confirmedPrompt: comparison.outboundPrompt)
        await (try #require(comparison.jobTask)).value
        #expect(comparison.canSaveAnalysis)
        comparison.saveAnalysis(retention: .full)
        let publication = try #require(comparison.jobTask)
        try await waitStarted(writer)
        let owner = try #require(await scheduler.state().active?.id)
        let timeline = makeTimeline(fixture, scheduler: scheduler, load: { caseID, evidence, result, historical in
            await loading.increment()
            // The queued owner independently reads the published immutable
            // sidecar; a save flag alone would not prove publication drained.
            let saved = try MultiEvidenceRecordStore.history(in: fixture.forensicCase.bundleURL)
            guard saved.count == 1,
                  let record = try MultiEvidenceRecordStore.load(id: saved[0].id, in: fixture.forensicCase.bundleURL),
                  record.schemaVersion == 2, record.retention == .full,
                  record.context.files[0].pdf != nil else { throw ComparisonSchedulingFailure.missingPublication }
            return try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        })
        timeline.loadFilesystem(); try await waitForQueue(scheduler, count: 1)
        if cancelAfterWriterStarted { comparison.cancel() }
        #expect(await scheduler.state().active?.id == owner)
        #expect(await scheduler.state().queuedKinds == [.timeline])
        #expect(await loading.value == 0)
        #expect(await writes.value == 0)
        await writer.open()
        await publication.value
        try await settle(timeline)
        #expect(await writer.cancelledAtRelease == false)
        #expect(await writer.cancellationObserved == false)
        #expect(await writes.value == 1)
        #expect(await loading.value == 1)
        let record = try #require(comparison.savedRecord)
        #expect(record.schemaVersion == 2 && record.retention == .full)
        #expect(comparison.phase.hasPrefix("Comparison saved"))
        #expect(!comparison.canSaveAnalysis) // An already committed save cannot be retried as a new receipt.
        if cancelAfterWriterStarted { #expect(comparison.phase.contains("History refresh cancelled")) }
        #expect(comparison.errorMessage == nil)
        #expect(try MultiEvidenceRecordStore.load(id: record.id, in: fixture.forensicCase.bundleURL) == record)
        if !cancelAfterWriterStarted { #expect(comparison.history.map(\.id) == [record.id]) }
        #expect(timeline.report?.events.count == 2)
        #expect(await scheduler.state().active == nil)
    }

    @Test("Only fresh local verification holds admission; a pending provider frees it and citation preparation queues")
    func providerWaitIsOutsideHeavyAdmission() async throws {
        let fixture = try await ComparisonSchedulingFixture.make()
        defer { fixture.remove() }
        let scheduler = ForensicWorkScheduler(), verification = ComparisonSchedulingGate(), provider = ComparisonSchedulingGate()
        let preparations = ComparisonSchedulingCounter(), loading = ComparisonSchedulingCounter(), timelineWorker = ComparisonSchedulingGate()
        let comparison = makeComparison(fixture, scheduler: scheduler, prepare: { _, _, _, _, _ in
            await preparations.increment(); return fixture.files
        }, verify: { _, _ in await verification.hold(); try Task.checkCancellation() }, analyze: { prompt, _ in
            await provider.hold(); try Task.checkCancellation()
            return ComparisonSchedulingFixture.answer(prompt)
        })
        configure(comparison, fixture)
        await (try #require(comparison.jobTask)).value
        comparison.analyze(confirmedPrompt: comparison.outboundPrompt)
        let request = try #require(comparison.jobTask)
        try await waitStarted(verification)
        let verificationOwner = try #require(await scheduler.state().active?.id)
        let timeline = makeTimeline(fixture, scheduler: scheduler, load: { caseID, evidence, result, historical in
            await loading.increment(); await timelineWorker.hold()
            return try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        })
        timeline.loadFilesystem(); try await waitForQueue(scheduler, count: 1)
        #expect(await scheduler.state().active?.id == verificationOwner)
        #expect(await loading.value == 0)
        await verification.open()
        try await waitStarted(provider)
        try await waitStarted(timelineWorker)
        #expect(comparison.hasActiveWork && comparison.result == nil)
        #expect(await scheduler.state().active?.kind == .timeline)
        #expect(await scheduler.state().active?.id != verificationOwner)
        await timelineWorker.open(); try await settle(timeline)
        #expect(await scheduler.state().active == nil)
        #expect(comparison.hasActiveWork) // The synthetic provider still waits.
        await provider.open(); await request.value
        let citation = try #require(comparison.references.first)
        #expect(citation.state == .disclosed)
        let preparedBeforeCitation = await preparations.value
        let blocker = try await scheduler.acquire(.filesystemAnalysis)
        comparison.openReference(citation)
        let referenceRead = try #require(comparison.jobTask)
        try await waitForQueue(scheduler, count: 1)
        #expect(await preparations.value == preparedBeforeCitation)
        #expect(comparison.openedReferenceText == nil)
        comparison.cancel(); await referenceRead.value
        #expect(await preparations.value == preparedBeforeCitation)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        #expect(await scheduler.state().active?.id == blocker.admission.id)
        #expect(await blocker.release())
        #expect(await scheduler.state().active == nil)
    }

    private func makeComparison(_ fixture: ComparisonSchedulingFixture, scheduler: ForensicWorkScheduler,
        prepare: MultiEvidenceAnalysisStore.Prepare? = nil, verify: MultiEvidenceAnalysisStore.Verify? = nil,
        save: MultiEvidenceAnalysisStore.Save? = nil, analyze: MultiEvidenceAnalysisStore.Analyze? = nil) -> MultiEvidenceAnalysisStore {
        .init(executableURL: fixture.executable,
              prepare: prepare ?? { _, _, _, _, _ in fixture.files },
              verify: verify ?? { _, _ in }, save: save,
              analyze: analyze ?? { prompt, _ in ComparisonSchedulingFixture.answer(prompt) }, scheduler: scheduler)
    }
    private func configure(_ comparison: MultiEvidenceAnalysisStore, _ fixture: ComparisonSchedulingFixture) {
        comparison.configure(evidence: fixture.evidence, result: fixture.result, files: fixture.entries,
            helperURL: fixture.helper, forensicCase: fixture.forensicCase)
    }
    private func makeTimeline(_ fixture: ComparisonSchedulingFixture, scheduler: ForensicWorkScheduler,
                              load: @escaping TimelineWorkspaceStore.FilesystemLoad) -> TimelineWorkspaceStore {
        let store = TimelineWorkspaceStore(engineHelperURL: fixture.helper, filesystemLoad: load, scheduler: scheduler)
        store.configure(caseID: fixture.forensicCase.manifest.id, evidence: fixture.evidence, result: fixture.result,
            historical: false, caseURL: fixture.forensicCase.bundleURL)
        return store
    }
    private func settle(_ timeline: TimelineWorkspaceStore) async throws {
        try await waitUntil { !timeline.hasActiveWork }
    }
    private func waitForQueue(_ scheduler: ForensicWorkScheduler, count: Int) async throws {
        try await waitUntil { await scheduler.state().queuedKinds.count == count }
    }
    private func waitStarted(_ gate: ComparisonSchedulingGate) async throws {
        try await waitUntil { await gate.started }
    }
    private func waitCancellation(_ gate: ComparisonSchedulingGate) async throws {
        try await waitUntil { await gate.cancellationObserved }
    }
    private func waitUntil(_ condition: @MainActor () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw ComparisonSchedulingFailure.timeout }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
}

private enum ComparisonSchedulingFailure: Error { case timeout, missingPublication }
private actor ComparisonSchedulingCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}
private actor ComparisonSchedulingGate {
    private(set) var started = false
    private(set) var cancellationObserved = false
    private(set) var cancelledAtRelease: Bool?
    private var continuation: CheckedContinuation<Void, Never>?
    private var isOpen = false
    func hold() async {
        started = true
        await withTaskCancellationHandler {
            if !isOpen { await withCheckedContinuation { continuation = $0 } }
        } onCancel: { Task { await self.observeCancellation() } }
        cancelledAtRelease = Task.isCancelled
    }
    private func observeCancellation() { cancellationObserved = true }
    func open() { isOpen = true; continuation?.resume(); continuation = nil }
}

/// Synthetic decoder receipts isolate scheduling. These tests do not claim
/// actual PDF parsing, source extraction, XPC isolation or a provider response.
private struct ComparisonSchedulingFixture: Sendable {
    let directory: URL, helper: URL, executable: URL
    let forensicCase: ForensicCase, evidence: EvidenceRecord
    let result: EnumerationResult, entries: [FilesystemEntry], files: [MultiEvidenceVerifiedFile]

    static func make() async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("ComparisonScheduling-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let source = directory.appendingPathComponent("synthetic-source.dd"), helper = directory.appendingPathComponent("never-launch-engine")
        let executable = directory.appendingPathComponent("never-launch-provider")
        try Data("synthetic image".utf8).write(to: source)
        try Data("synthetic, never executed\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let created = try CaseStore.create(name: "Scheduling oracle", in: directory)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspected, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let entries = [FilesystemEntry(id: "0:1", path: "/PDF-by-content.dat", name: "PDF-by-content.dat",
            fsOffsetBytes: 0, metaAddress: 1, size: 2 * 1_024 * 1_024, isDirectory: false, isDeleted: false, modifiedEpoch: 1_700_000_000),
            FilesystemEntry(id: "0:2", path: "/second.txt", name: "second.txt", fsOffsetBytes: 0,
                metaAddress: 2, size: 6, isDirectory: false, isDeleted: false, modifiedEpoch: 1_700_000_002)]
        let result = EnumerationResult(engineVersion: "synthetic", patchDigest: "synthetic", sourcePaths: [source.path],
            sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: inspected.byteCount, sectorSize: 512), volumes: [], files: entries,
            warnings: [], status: .completed)
        let pdfBinding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entries[0])
        let pdfReceipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entries[0].id, byteCount: entries[0].size,
            sha256: String(repeating: "b", count: 64), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
        let analysis = try DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: pdfReceipt.sha256, sourceByteCount: pdfReceipt.byteCount, pageCount: 1,
            textPages: [.init(pageNumber: 1, text: "one SECRET ก😀 tail", isTruncated: false, referenceLabel: "Page 1", referenceKind: .page)])
            .attachingProvenance(executableSHA256: String(repeating: "d", count: 64), codeSigningCDHash: nil,
                isolation: .requiredDevelopmentSeatbelt, timeout: 12)
        let pdf = try MultiEvidenceVerifiedFile(binding: pdfBinding, preview: .init(file: entries[0], receipt: pdfReceipt, analysis: analysis))
        let bytes = Data("second".utf8)
        let textBinding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entries[1])
        let textReceipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entries[1].id, byteCount: entries[1].size,
            sha256: MultiEvidenceCoding.digest(bytes), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
        let text = try MultiEvidenceVerifiedFile(binding: textBinding, content: .init(bytes: bytes, receipt: textReceipt))
        return .init(directory: directory, helper: helper, executable: executable, forensicCase: forensicCase,
            evidence: evidence, result: result, entries: entries, files: [pdf, text])
    }
    static func answer(_ prompt: String) -> CodexAnalysisResult {
        .init(response: .init(summary: "Synthetic scheduling answer [[A1:0:3]]", observations: [], hypotheses: [],
            limitations: ["Injected provider; no external request"], nextSteps: []),
            requestSHA256: MultiEvidenceCoding.digest(Data(prompt.utf8)), completedAt: Date())
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
}
