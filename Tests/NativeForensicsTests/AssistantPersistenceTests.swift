import CryptoKit
import Darwin
import Foundation
import Testing
import ForensicsCore
@testable import NativeForensics

@_silgen_name("flock")
private func assistantPersistenceFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

@Suite("AssistantPersistenceTests")
@MainActor
struct AssistantPersistenceTests {
    @Test("Full retention saves the exact completed request and reopens without a source or provider")
    func fullSaveReopen() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let store = makeStore(fixture, provider: provider)
        try await prepare(store, fixture: fixture)
        store.question = "คำถามไทย\nPreserve literal \"quotes\" and trailing spaces.  "
        let prompt = try await complete(store, provider: provider)
        let response = try #require(store.result)
        #expect(store.canSaveAnalysis)
        store.saveAnalysis(retention: .full)
        await (try #require(store.jobTask)).value
        let recordID = try #require(store.savedAnalysisID)
        #expect(!store.canSaveAnalysis)
        #expect(!store.isSaving)
        #expect(!store.hasActiveWork)
        store.prepareForTermination()
        await store.beginShutdown()?.value

        // Case reopening reads historical sidecars, even while original bytes
        // are offline. No helper or provider is involved in this path.
        try FileManager.default.removeItem(at: fixture.source)
        let reopened = try CaseStore.open(at: fixture.forensicCase.bundleURL)
        let record = try #require(try CaseWorkStore.loadAnalysis(id: recordID, in: reopened.bundleURL))
        #expect(record.prompt == prompt)
        #expect(record.requestSHA256 == AssistantPersistenceFixture.hash(Data(prompt.utf8)))
        #expect(record.result == response)
        #expect(record.question == store.question)
        #expect(record.binding.caseID == reopened.manifest.id)
        #expect(record.binding.evidenceID == fixture.evidence.id)
        #expect(record.binding.selectedEntry == fixture.file)
        #expect(!record.sourceBytesVerifiedForContentAtRequest)
        #expect(record.contentHash == nil)
        #expect(await provider.callCount == 1)
        #expect(try Data(contentsOf: fixture.manifestURL) == fixture.manifestBytes)
    }

    @Test("Digest-only retention excludes prompt and undisclosed source text while keeping the response")
    func digestOnlySave() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let store = makeStore(fixture, provider: provider)
        try await prepare(store, fixture: fixture)
        let prompt = try await complete(store, provider: provider)
        store.saveAnalysis(retention: .digestOnly)
        await (try #require(store.jobTask)).value
        let recordID = try #require(store.savedAnalysisID)
        let record = try #require(try CaseWorkStore.loadAnalysis(id: recordID, in: fixture.forensicCase.bundleURL))
        #expect(record.retention == .digestOnly)
        #expect(record.prompt == nil)
        #expect(record.requestSHA256 == AssistantPersistenceFixture.hash(Data(prompt.utf8)))
        #expect(record.result.response.summary == "Synthetic advisory answer")
        let serialized = try String(contentsOf: fixture.analysisURL(recordID), encoding: .utf8)
        #expect(!serialized.contains("REVIEWED_QUESTION_JSON"))
        #expect(!serialized.contains("BEGIN_UNTRUSTED_EVIDENCE_JSON"))
        #expect(!serialized.contains(fixture.sourceText))
        #expect(!serialized.contains(fixture.source.path))
        #expect(!serialized.contains("textContent"))
        #expect(!serialized.contains("prompt\":\""))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: fixture.manifestURL) == fixture.manifestBytes)
    }

    @Test("Question, content disclosure and rebuilding context invalidate an unsaved completed answer")
    func invalidationRequiresNewAnswer() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let store = makeStore(fixture, provider: provider)
        try await prepare(store, fixture: fixture)
        _ = try await complete(store, provider: provider)
        #expect(store.canSaveAnalysis)
        store.question = "A changed question"
        #expect(store.result == nil)
        #expect(!store.canSaveAnalysis)
        store.saveAnalysis(retention: .full)
        #expect(store.jobTask == nil)

        _ = try await complete(store, provider: provider)
        #expect(store.canSaveAnalysis)
        store.includeText = true
        #expect(store.result == nil)
        #expect(!store.canSaveAnalysis)
        #expect(store.contextNeedsPreparation)
        store.includeText = false
        _ = try await complete(store, provider: provider)
        #expect(store.canSaveAnalysis)
        store.prepareContext()
        #expect(!store.canSaveAnalysis)
        await (try #require(store.jobTask)).value
        #expect(store.result == nil)
        #expect(!store.canSaveAnalysis)
        #expect(!FileManager.default.fileExists(atPath: fixture.forensicCase.bundleURL.appendingPathComponent("analyses").path))
        #expect(await provider.callCount == 3)
    }

    @Test("An answer without an owning case can be viewed but cannot be saved")
    func noCaseCannotSave() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let store = makeStore(fixture, provider: provider)
        try await prepare(store, fixture: fixture, includeCase: false)
        _ = try await complete(store, provider: provider)
        #expect(store.result != nil)
        #expect(!store.canSaveAnalysis)
        store.saveAnalysis(retention: .full)
        #expect(store.jobTask == nil)
        #expect(store.savedAnalysisID == nil)
        #expect(!FileManager.default.fileExists(atPath: fixture.forensicCase.bundleURL.appendingPathComponent("analyses").path))
    }

    @Test("A mismatched provider request hash never becomes a saveable transaction")
    func wrongRequestCannotSave() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let store = makeStore(fixture, provider: provider)
        try await prepare(store, fixture: fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        let pending = try #require(store.jobTask)
        await provider.succeed(await provider.nextRequest(), hash: String(repeating: "0", count: 64))
        await pending.value
        #expect(store.result == nil)
        #expect(!store.canSaveAnalysis)
        #expect(store.errorMessage == CodexAnalysisError.invalidProtocol.localizedDescription)
        store.saveAnalysis(retention: .digestOnly)
        #expect(store.jobTask == nil)
        #expect(store.savedAnalysisID == nil)
    }

    @Test("A response and save keep the original selection frozen while their operations own it")
    func completedSelectionIsFrozen() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let store = makeStore(fixture, provider: provider)
        try await prepare(store, fixture: fixture)
        let prompt = store.outboundPrompt
        store.analyze(confirmedPrompt: prompt)
        let pending = try #require(store.jobTask)
        let request = await provider.nextRequest()
        let replacement = FilesystemEntry(id: "other-file", path: "/OTHER.TXT", name: "OTHER.TXT",
            fsOffsetBytes: 0, metaAddress: 11, size: 3, isDirectory: false, isDeleted: false)
        store.configure(evidence: fixture.evidence, result: fixture.enumeration,
            file: replacement, helperURL: fixture.helper, forensicCase: fixture.forensicCase)
        #expect(store.selectedFilePath == fixture.file.path)
        await provider.succeed(request)
        await pending.value
        store.saveAnalysis(retention: .full)
        await (try #require(store.jobTask)).value
        let recordID = try #require(store.savedAnalysisID)
        let record = try #require(try CaseWorkStore.loadAnalysis(id: recordID, in: fixture.forensicCase.bundleURL))
        #expect(record.binding.selectedEntry == fixture.file)
        #expect(record.prompt == prompt)
        #expect(record.requestSHA256 == request.hash)
    }

    @Test("A save under an owned case lock keeps the UI responsive and close drains cancellation without publishing")
    func blockedSaveCancellationDrains() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let heldLock = try PersistenceCaseLock(caseURL: fixture.forensicCase.bundleURL)
        defer { heldLock.unlock() }
        let provider = PersistenceProviderGate()
        let started = PersistenceSaveStartGate()
        let store = makeStore(fixture, provider: provider, save: { record, caseURL in
            await started.announce(record)
            // The real store must wait for our LOCK_EX. Its synchronous lock
            // loop runs in the owning detached worker, never on MainActor.
            try CaseWorkStore.saveAnalysis(record, in: caseURL)
        })
        try await prepare(store, fixture: fixture)
        _ = try await complete(store, provider: provider)
        store.saveAnalysis(retention: .full)
        let pending = try #require(store.jobTask)
        let stagedRecord = await started.next()
        let heartbeat = Task { @MainActor in true }
        #expect(await heartbeat.value)
        #expect(store.isSaving)
        #expect(store.hasActiveWork)
        #expect(!store.canSaveAnalysis)
        #expect(!FileManager.default.fileExists(atPath: fixture.analysisURL(stagedRecord.id).path))

        store.close()
        #expect(store.isPresented)
        #expect(store.hasActiveWork)
        #expect(pending.isCancelled)
        // Do not release the lock until the worker acknowledges cancellation:
        // a blocking/orphaned lock wait would hang instead of passing this gate.
        await pending.value
        await dismissFinishedClose(store)
        #expect(!store.isPresented)
        #expect(!store.hasActiveWork)
        #expect(!store.isSaving)
        #expect(store.savedAnalysisID == nil)
        #expect(store.phase.contains("cancelled"))
        heldLock.unlock()
        #expect(try CaseWorkStore.loadAnalysis(id: stagedRecord.id, in: fixture.forensicCase.bundleURL) == nil)
        #expect(try Data(contentsOf: fixture.manifestURL) == fixture.manifestBytes)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Cancellation after real publication drains the owning operation and reports the committed receipt")
    func committedSaveStillAcknowledged() async throws {
        let fixture = try await AssistantPersistenceFixture.make()
        defer { fixture.remove() }
        let provider = PersistenceProviderGate()
        let committed = PersistenceCommittedSaveGate()
        let store = makeStore(fixture, provider: provider, save: { record, caseURL in
            try CaseWorkStore.saveAnalysis(record, in: caseURL)
            // This actor deliberately ignores cancellation until the publication
            // receipt is released, modelling a noninterruptible final boundary.
            await committed.hold(record)
        })
        try await prepare(store, fixture: fixture)
        let prompt = try await complete(store, provider: provider)
        store.saveAnalysis(retention: .full)
        let pending = try #require(store.jobTask)
        let record = await committed.next()
        #expect(try CaseWorkStore.loadAnalysis(id: record.id, in: fixture.forensicCase.bundleURL)?.prompt == prompt)
        store.prepareForTermination()
        #expect(!store.isPresented)
        #expect(store.hasActiveWork)
        #expect(pending.isCancelled)
        await committed.release()
        await pending.value
        #expect(store.savedAnalysisID == record.id)
        #expect(store.phase.contains("saved"))
        #expect(!store.hasActiveWork)
        #expect(!store.isSaving)
        #expect(try CaseWorkStore.loadAnalysis(id: record.id, in: fixture.forensicCase.bundleURL) != nil)
        #expect(try Data(contentsOf: fixture.manifestURL) == fixture.manifestBytes)
    }

    private func makeStore(_ fixture: AssistantPersistenceFixture, provider: PersistenceProviderGate,
        save: AssistantAnalysisStore.Save? = nil) -> AssistantAnalysisStore {
        AssistantAnalysisStore(executableURL: fixture.executable, save: save) { prompt, _ in
            try await provider.analyze(prompt)
        }
    }

    private func prepare(_ store: AssistantAnalysisStore, fixture: AssistantPersistenceFixture, includeCase: Bool = true) async throws {
        store.configure(evidence: fixture.evidence, result: fixture.enumeration, file: fixture.file,
            helperURL: fixture.helper, forensicCase: includeCase ? fixture.forensicCase : nil)
        await (try #require(store.jobTask)).value
        _ = try #require(store.context)
        #expect(!store.canSaveAnalysis)
    }

    private func complete(_ store: AssistantAnalysisStore, provider: PersistenceProviderGate) async throws -> String {
        let prompt = store.outboundPrompt
        store.analyze(confirmedPrompt: prompt)
        let pending = try #require(store.jobTask)
        await provider.succeed(await provider.nextRequest())
        await pending.value
        _ = try #require(store.result)
        return prompt
    }

    private func dismissFinishedClose(_ store: AssistantAnalysisStore) async {
        // No I/O readiness assumptions: pending.value already drained the job;
        // only its scheduled MainActor close continuation remains.
        let deadline = ContinuousClock.now + .seconds(2)
        while store.isPresented && ContinuousClock.now < deadline { await Task.yield() }
    }
}

private actor PersistenceProviderGate {
    struct Request: Sendable {
        let id: UUID
        let prompt: String
        var hash: String { AssistantPersistenceFixture.hash(Data(prompt.utf8)) }
    }
    private var ready: [Request] = []
    private var responses: [UUID: CheckedContinuation<CodexAnalysisResult, any Error>] = [:]
    private var waiters: [CheckedContinuation<Request, Never>] = []
    private(set) var callCount = 0
    func analyze(_ prompt: String) async throws -> CodexAnalysisResult {
        callCount += 1
        let request = Request(id: UUID(), prompt: prompt)
        return try await withCheckedThrowingContinuation { continuation in
            responses[request.id] = continuation
            if waiters.isEmpty { ready.append(request) }
            else { waiters.removeFirst().resume(returning: request) }
        }
    }
    func nextRequest() async -> Request {
        if !ready.isEmpty { return ready.removeFirst() }
        return await withCheckedContinuation { waiters.append($0) }
    }
    func succeed(_ request: Request, hash: String? = nil) {
        let answer = CodexAnalysisResponse(summary: "Synthetic advisory answer", observations: ["The recorded file is present"],
            hypotheses: ["Its purpose is unknown"], limitations: ["Historical metadata only"], nextSteps: ["Inspect verified bytes locally"])
        responses.removeValue(forKey: request.id)?.resume(returning: CodexAnalysisResult(response: answer,
            requestSHA256: hash ?? request.hash, completedAt: Date(timeIntervalSince1970: 1_700_000_001.125)))
    }
}

private actor PersistenceSaveStartGate {
    private var ready: AnalysisRecord?
    private var waiter: CheckedContinuation<AnalysisRecord, Never>?
    func announce(_ record: AnalysisRecord) {
        if let waiter { self.waiter = nil; waiter.resume(returning: record) }
        else { ready = record }
    }
    func next() async -> AnalysisRecord {
        if let ready { self.ready = nil; return ready }
        return await withCheckedContinuation { waiter = $0 }
    }
}

private actor PersistenceCommittedSaveGate {
    private var ready: AnalysisRecord?
    private var waiter: CheckedContinuation<AnalysisRecord, Never>?
    private var finish: CheckedContinuation<Void, Never>?
    func hold(_ record: AnalysisRecord) async {
        await withCheckedContinuation { continuation in
            finish = continuation
            if let waiter { self.waiter = nil; waiter.resume(returning: record) }
            else { ready = record }
        }
    }
    func next() async -> AnalysisRecord {
        if let ready { self.ready = nil; return ready }
        return await withCheckedContinuation { waiter = $0 }
    }
    func release() { finish?.resume(); finish = nil }
}

private final class PersistenceCaseLock {
    private var descriptor: Int32
    init(caseURL: URL) throws {
        descriptor = Darwin.open(caseURL.appendingPathComponent(".case.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CaseWorkError.invalidCase }
        guard assistantPersistenceFlock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(descriptor); descriptor = -1; throw CaseWorkError.invalidCase
        }
    }
    func unlock() {
        guard descriptor >= 0 else { return }
        _ = assistantPersistenceFlock(descriptor, LOCK_UN)
        Darwin.close(descriptor); descriptor = -1
    }
    deinit { unlock() }
}

private struct AssistantPersistenceFixture: Sendable {
    let directory: URL
    let source: URL
    let executable: URL
    let helper: URL
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let file: FilesystemEntry
    let enumeration: EnumerationResult
    let manifestBytes: Data
    let sourceText = "Undisclosed synthetic private source text สวัสดี"
    var sourceBytes: Data { Data(sourceText.utf8) }
    var manifestURL: URL { forensicCase.bundleURL.appendingPathComponent("manifest.json") }
    func analysisURL(_ id: UUID) -> URL {
        forensicCase.bundleURL.appendingPathComponent("analyses").appendingPathComponent(id.uuidString.lowercased() + ".json")
    }

    static func make() async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("AssistantPersistence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            let source = directory.appendingPathComponent("synthetic.raw")
            let bytes = Data("Undisclosed synthetic private source text สวัสดี".utf8)
            try bytes.write(to: source)
            let executable = directory.appendingPathComponent("fake-codex-never-executed")
            try Data("Synthetic fixture, never launched\n".utf8).write(to: executable)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
            let created = try CaseStore.create(name: "Synthetic Analysis Case", in: directory)
            let image = try await ImageInspector.inspect(url: source) { _ in }
            let forensicCase = try CaseStore.adding(image: image, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let file = FilesystemEntry(id: "selected-file", path: "/NOTE.TXT", name: "NOTE.TXT", fsOffsetBytes: 0,
                metaAddress: 10, size: Int64(bytes.count), isDirectory: false, isDeleted: false,
                modifiedEpoch: 1_700_000_000)
            let enumeration = EnumerationResult(engineVersion: "synthetic-persistence-test", patchDigest: "synthetic-persistence-test",
                sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256],
                options: EngineOptions(hashLogicalImage: false),
                image: EngineImageMetadata(imageType: "raw", logicalSize: Int64(bytes.count), sectorSize: 512, imagePaths: [source.path]),
                volumes: [], files: [file], warnings: [], status: .completed, savedAt: Date(timeIntervalSince1970: 1_700_000_000))
            return Self(directory: directory, source: source, executable: executable,
                helper: directory.appendingPathComponent("must-not-launch-helper"), forensicCase: forensicCase,
                evidence: evidence, file: file, enumeration: enumeration,
                manifestBytes: try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json")))
        } catch { try? FileManager.default.removeItem(at: directory); throw error }
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}
