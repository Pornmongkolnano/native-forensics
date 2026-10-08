import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("MultiEvidenceAnalysisStore") @MainActor
struct MultiEvidenceStoreTests {
    @Test("Two-file preparation and range/redaction review remain local until the exact send action")
    func localReviewAndExactSend() async throws {
        let fixture = try await MultiEvidenceStoreFixture.make(); defer { fixture.remove() }
        let gate = MultiEvidenceProviderGate()
        let store = makeStore(fixture, gate: gate)
        await configure(store, fixture)
        #expect(await gate.calls == 0); #expect(store.context?.files.count == 2)
        #expect(!store.outboundPrompt.contains(fixture.source.path)); #expect(store.canAnalyze)
        let oldPrompt = store.outboundPrompt
        store.firstRedactions = "4:10"
        #expect(store.context == nil); #expect(!store.canAnalyze)
        store.rebuildDisclosure()
        #expect(!store.outboundPrompt.contains("SECRET")); #expect(store.outboundPrompt != oldPrompt)
        store.analyze(confirmedPrompt: oldPrompt)
        #expect(await gate.calls == 0); #expect(store.jobTask == nil)
        let exact = store.outboundPrompt
        store.analyze(confirmedPrompt: exact)
        let pending = try #require(store.jobTask)
        let sent = await gate.started()
        #expect(sent == exact)
        await gate.succeed(prompt: exact)
        await pending.value
        #expect(store.result != nil); #expect(store.references.first?.state == .disclosed)
        #expect(!store.isWorking); #expect(!store.hasActiveWork)
    }

    @Test("A source hash mismatch at Send stops disclosure before the fake provider is called")
    func sourceChangedBeforeSend() async throws {
        let fixture = try await MultiEvidenceStoreFixture.make(); defer { fixture.remove() }
        let gate = MultiEvidenceProviderGate()
        let store = makeStore(fixture, gate: gate)
        await configure(store, fixture)
        let prompt = store.outboundPrompt
        try Data("changed image!!".utf8).write(to: fixture.source)
        store.analyze(confirmedPrompt: prompt)
        await (try #require(store.jobTask)).value
        #expect(await gate.calls == 0); #expect(store.result == nil); #expect(store.errorMessage != nil)
    }

    @Test("Question changes and cancellation discard late provider answers but keep owned work until drain", arguments: ["question", "cancel", "close"])
    func ownedDrain(_ mode: String) async throws {
        let fixture = try await MultiEvidenceStoreFixture.make(); defer { fixture.remove() }
        let gate = MultiEvidenceProviderGate(), store = makeStore(fixture, gate: gate)
        await configure(store, fixture)
        let prompt = store.outboundPrompt
        store.analyze(confirmedPrompt: prompt)
        let pending = try #require(store.jobTask)
        _ = await gate.started()
        if mode == "question" { store.question = "A changed question" }
        else if mode == "close" { store.close() }
        else { store.cancel() }
        #expect(store.hasActiveWork); #expect(store.isWorking)
        store.configure(evidence: fixture.evidence, result: fixture.result, files: Array(fixture.entries.reversed()), helperURL: fixture.helper, forensicCase: fixture.forensicCase)
        #expect(store.filePaths == fixture.entries.map(\.path))
        await gate.succeed(prompt: prompt)
        await pending.value
        #expect(store.result == nil); #expect(!store.hasActiveWork)
    }

    @Test("Explicit save creates an immutable case receipt; follow-up is reviewed as a new request")
    func saveAndFollowUp() async throws {
        let fixture = try await MultiEvidenceStoreFixture.make(); defer { fixture.remove() }
        let gate = MultiEvidenceProviderGate(), store = makeStore(fixture, gate: gate)
        await configure(store, fixture)
        let prompt = store.outboundPrompt
        store.analyze(confirmedPrompt: prompt)
        let send = try #require(store.jobTask); _ = await gate.started(); await gate.succeed(prompt: prompt); await send.value
        #expect(store.canSaveAnalysis)
        store.saveAnalysis(retention: .digestOnly)
        await (try #require(store.jobTask)).value
        let saved = try #require(store.savedRecord)
        #expect(saved.prompt == nil); #expect(store.history.map(\.id) == [saved.id])
        #expect(await gate.calls == 1)
        store.beginFollowUp()
        #expect(store.parentRecord?.id == saved.id)
        #expect(store.result == nil)
        store.question = "Which uncertainty should be checked next?"
        #expect(store.outboundPrompt.contains(saved.id.uuidString)); #expect(store.outboundPrompt.contains("priorUntrustedInterpretation"))
        #expect(await gate.calls == 1)
        let followup = store.outboundPrompt
        store.analyze(confirmedPrompt: followup)
        let send2 = try #require(store.jobTask); _ = await gate.started(); await gate.succeed(prompt: followup); await send2.value
        store.saveAnalysis(retention: .full)
        await (try #require(store.jobTask)).value
        #expect(store.savedRecord?.parentRecordID == saved.id)
        #expect(store.history.count == 2)
        store.beginFollowUp()
        #expect(store.parentRecord != nil)
        store.firstRedactions = "4:10"
        #expect(store.parentRecord == nil); #expect(store.context == nil)
        store.rebuildDisclosure()
        #expect(!store.outboundPrompt.contains("priorUntrustedInterpretation"))
        #expect(!store.outboundPrompt.contains("SECRET"))
        #expect(await gate.calls == 2)
    }

    @Test("Opening a citation reextracts verified bytes locally and never calls the provider again")
    func freshCitationOpen() async throws {
        let fixture = try await MultiEvidenceStoreFixture.make(); defer { fixture.remove() }
        let gate = MultiEvidenceProviderGate(), store = makeStore(fixture, gate: gate)
        await configure(store, fixture)
        let prompt = store.outboundPrompt
        store.analyze(confirmedPrompt: prompt)
        let send = try #require(store.jobTask); _ = await gate.started(); await gate.succeed(prompt: prompt); await send.value
        store.openReference(try #require(store.references.first))
        await (try #require(store.jobTask)).value
        #expect(store.openedReferenceText == "one"); #expect(await gate.calls == 1)
    }

    private func makeStore(_ fixture: MultiEvidenceStoreFixture, gate: MultiEvidenceProviderGate) -> MultiEvidenceAnalysisStore {
        let verified = fixture.files
        return MultiEvidenceAnalysisStore(executableURL: fixture.executable,
            prepare: { _, _, _, _, _ in verified },
            analyze: { prompt, _ in try await gate.analyze(prompt) }, scheduler: ForensicWorkScheduler())
    }
    private func configure(_ store: MultiEvidenceAnalysisStore, _ fixture: MultiEvidenceStoreFixture) async {
        store.configure(evidence: fixture.evidence, result: fixture.result, files: fixture.entries,
            helperURL: fixture.helper, forensicCase: fixture.forensicCase)
        await store.jobTask?.value
    }
}

private actor MultiEvidenceProviderGate {
    private(set) var calls = 0
    private var request: String?
    private var waiting: CheckedContinuation<String, Never>?
    private var answer: CheckedContinuation<CodexAnalysisResult, Error>?
    func analyze(_ prompt: String) async throws -> CodexAnalysisResult {
        calls += 1; request = prompt; waiting?.resume(returning: prompt); waiting = nil
        return try await withCheckedThrowingContinuation { answer = $0 }
    }
    func started() async -> String {
        if let request { self.request = nil; return request }
        return await withCheckedContinuation { waiting = $0 }
    }
    func succeed(prompt: String) {
        let result = CodexAnalysisResult(response: .init(summary: "Synthetic comparison [[A1:0:3]]", observations: [], hypotheses: [], limitations: ["Fake provider only"], nextSteps: []),
            requestSHA256: SHA256.hash(data: Data(prompt.utf8)).map { String(format: "%02x", $0) }.joined(), completedAt: Date())
        answer?.resume(returning: result); answer = nil; request = nil
    }
}
private struct MultiEvidenceStoreFixture: Sendable {
    let directory: URL, source: URL, helper: URL, executable: URL
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let result: EnumerationResult
    let entries: [FilesystemEntry]
    let files: [MultiEvidenceVerifiedFile]
    static func make() async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("MultiEvidenceStore-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let source = directory.appendingPathComponent("private-source.dd"), helper = directory.appendingPathComponent("never-launch-engine"), executable = directory.appendingPathComponent("never-launch-codex")
        try Data("synthetic image".utf8).write(to: source)
        try Data("fake, never run\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let created = try CaseStore.create(name: "Synthetic Reviewed Comparison", in: directory)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspected, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let texts = ["one SECRET two", "second text"]
        let entries = texts.enumerated().map { index, text in FilesystemEntry(id: "0:\(index + 1)", path: "/FILE\(index + 1).txt", name: "FILE\(index + 1).txt",
            fsOffsetBytes: 0, metaAddress: UInt64(index + 1), size: Int64(text.utf8.count), isDirectory: false, isDeleted: false) }
        let result = EnumerationResult(engineVersion: "synthetic", patchDigest: "synthetic", sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256],
            options: EngineOptions(hashLogicalImage: false), image: .init(imageType: "raw", logicalSize: 15, sectorSize: 512), volumes: [], files: entries, warnings: [], status: .completed)
        let files = try entries.enumerated().map { index, entry in
            let bytes = Data(texts[index].utf8)
            let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entry)
            let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entry.id, byteCount: entry.size,
                sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
            return try MultiEvidenceVerifiedFile(binding: binding, content: .init(bytes: bytes, receipt: receipt))
        }
        return .init(directory: directory, source: source, helper: helper, executable: executable, forensicCase: forensicCase,
            evidence: evidence, result: result, entries: entries, files: files)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
}
