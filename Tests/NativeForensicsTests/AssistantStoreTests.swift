import CryptoKit
import Foundation
import Testing
import ForensicsCore
@testable import NativeForensics

@Suite("AssistantStoreTests")
@MainActor
struct AssistantStoreTests {
    @Test("Preparing historical metadata never calls a provider and discloses no host source path")
    func localPreparationOnly() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)

        #expect(await gate.callCount == 0)
        #expect(store.isPresented)
        #expect(store.canAnalyze)
        #expect(!store.isWorking)
        #expect(!store.hasActiveWork)
        #expect(store.context?.textContent == nil)
        #expect(store.context?.analysis.sourceBytesVerifiedForContent == false)
        #expect(store.outboundPrompt.contains(fixture.file.id))
        #expect(!store.outboundPrompt.contains(fixture.source.path))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Transmission accepts only the exact current reviewed question and context")
    func exactReviewedPromptBinding() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        let oldPrompt = store.outboundPrompt
        store.question = "Which recorded timestamps are present?"
        let currentPrompt = store.outboundPrompt
        #expect(currentPrompt != oldPrompt)

        store.analyze(confirmedPrompt: oldPrompt)
        #expect(store.jobTask == nil)
        #expect(await gate.callCount == 0)
        #expect(store.errorMessage != nil)
        store.analyze(confirmedPrompt: currentPrompt + " ")
        #expect(store.jobTask == nil)
        #expect(await gate.callCount == 0)

        store.analyze(confirmedPrompt: currentPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        #expect(request.prompt == currentPrompt)
        #expect(request.executable == fixture.executable.standardizedFileURL.resolvingSymlinksInPath())
        #expect(await gate.callCount == 1)
        await gate.succeed(request)
        await pending.value

        #expect(store.result?.requestSHA256 == AssistantStoreFixture.hash(Data(currentPrompt.utf8)))
        #expect(store.errorMessage == nil)
        #expect(!store.hasActiveWork)
    }

    @Test("Changing text disclosure invalidates transmission until the new context is prepared")
    func changedDisclosureRequiresPreparation() async throws {
        let fixture = try AssistantStoreFixture(directory: true)
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        let metadataPrompt = store.outboundPrompt

        store.includeText = true
        #expect(store.contextNeedsPreparation)
        #expect(!store.canAnalyze)
        #expect(store.outboundPrompt.isEmpty)
        store.analyze(confirmedPrompt: metadataPrompt)
        #expect(await gate.callCount == 0)
        store.prepareContext()
        await (try #require(store.jobTask)).value
        #expect(store.context == nil)
        #expect(store.errorMessage == AssistantContextError.directoryContent.localizedDescription)
        #expect(await gate.callCount == 0)

        store.includeText = false
        store.prepareContext()
        await (try #require(store.jobTask)).value
        #expect(!store.contextNeedsPreparation)
        #expect(store.canAnalyze)
        #expect(store.outboundPrompt == metadataPrompt)
    }

    @Test("Changing the question clears the previous response and updates the copyable prompt")
    func questionChangeInvalidatesResponse() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        let firstPrompt = store.outboundPrompt
        store.analyze(confirmedPrompt: firstPrompt)
        let pending = try #require(store.jobTask)
        await gate.succeed(await gate.nextRequest())
        await pending.value
        #expect(store.result != nil)

        store.question = "What facts remain unknown?"
        #expect(store.result == nil)
        #expect(store.outboundPrompt != firstPrompt)
        #expect(store.outboundPrompt.contains("What facts remain unknown?"))
        #expect(store.canAnalyze)

        store.question = "   "
        #expect(store.outboundPrompt.isEmpty)
        #expect(!store.canAnalyze)
        #expect(await gate.callCount == 1)
    }

    @Test("A late response to a superseded question cannot populate the current sheet")
    func lateResponseAfterQuestionChange() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        store.question = "A different reviewed question"
        await gate.succeed(request)
        await pending.value

        #expect(store.result == nil)
        #expect(store.outboundPrompt != request.prompt)
        #expect(!store.isWorking)
        #expect(!store.hasActiveWork)
    }

    @Test("Cancellation drains an already-started operation and discards its response")
    func cancellationDrainsOperation() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        store.cancel()
        #expect(store.isWorking)
        #expect(store.hasActiveWork)
        #expect(store.isPresented)

        // This injected operation deliberately ignores cancellation until its
        // resource-owning work finishes, like a subprocess cleanup boundary.
        await gate.succeed(request)
        await pending.value
        #expect(store.result == nil)
        #expect(!store.isWorking)
        #expect(!store.hasActiveWork)
        #expect(store.isPresented)
        #expect(store.phase.contains("cancelled"))
        #expect(store.canAnalyze)
    }

    @Test("Close retains the sheet until work drains, rejects replacement selection, and allows reopening")
    func closeDrainsBeforeDismissal() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        store.close()
        #expect(store.isPresented)
        #expect(store.hasActiveWork)
        #expect(!store.canAnalyze)

        let other = FilesystemEntry(id: "replacement", path: "/replacement.txt", name: "replacement.txt",
            fsOffsetBytes: 0, metaAddress: 11, size: 3, isDirectory: false, isDeleted: false)
        store.configure(evidence: fixture.evidence, result: fixture.enumeration, file: other, helperURL: fixture.helper)
        #expect(store.selectedFilePath == fixture.file.path)
        await gate.succeed(request)
        await pending.value
        // Only scheduler yields are needed: the work's completion is controlled
        // by the actor gate, rather than a wall-clock delay.
        for _ in 0..<100 where store.isPresented { await Task.yield() }
        #expect(!store.isPresented)
        #expect(store.context == nil)
        #expect(store.result == nil)
        #expect(!store.hasActiveWork)

        try await prepare(store, fixture: fixture)
        #expect(store.isPresented)
        #expect(store.canAnalyze)
        #expect(store.selectedFilePath == fixture.file.path)
        #expect(await gate.callCount == 1)
    }

    @Test("Provider failure preserves the prepared evidence snapshot and source bytes for retry")
    func providerFailurePreservesEvidence() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        let context = store.context
        let reviewedPrompt = store.outboundPrompt
        store.analyze(confirmedPrompt: reviewedPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        await gate.fail(request, error: .providerFailed)
        await pending.value

        #expect(store.context == context)
        #expect(store.outboundPrompt == reviewedPrompt)
        #expect(store.result == nil)
        #expect(store.errorMessage == CodexAnalysisError.providerFailed.localizedDescription)
        #expect(store.canAnalyze)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("A response bound to another request hash is rejected")
    func wrongResponseBinding() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        await gate.succeed(request, requestHash: String(repeating: "0", count: 64))
        await pending.value

        #expect(store.result == nil)
        #expect(store.errorMessage == CodexAnalysisError.invalidProtocol.localizedDescription)
        #expect(!store.hasActiveWork)
        #expect(store.canAnalyze)
    }

    @Test("Assistant disclosure freezes case operations and is available only for a stable selected file")
    func workspaceAssistantGuard() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let first = try CaseStore.create(name: "Preserved", in: fixture.directory)
        let second = try CaseStore.create(name: "Other", in: fixture.directory)
        let manifestURL = first.bundleURL.appendingPathComponent("manifest.json")
        let originalManifest = try Data(contentsOf: manifestURL)
        let workspace = WorkspaceStore(helperURL: fixture.helper)
        workspace.currentCase = ForensicCase(bundleURL: first.bundleURL,
            manifest: CaseManifest(id: first.manifest.id, name: first.manifest.name, evidence: [fixture.evidence]))
        workspace.filesystemResults[fixture.evidence.id] = fixture.enumeration
        workspace.selectedEvidenceID = fixture.evidence.id
        workspace.selectedFileID = fixture.file.id
        workspace.assistant.cliPath = fixture.executable.path
        #expect(workspace.canOpenAssistant)

        workspace.isLoadingFilesystem = true
        #expect(!workspace.canOpenAssistant)
        workspace.isLoadingFilesystem = false
        workspace.isFilteringFilesystem = true
        #expect(!workspace.canOpenAssistant)
        workspace.isFilteringFilesystem = false
        workspace.selectedFileID = nil
        #expect(!workspace.canOpenAssistant)
        workspace.selectedFileID = fixture.file.id

        workspace.openAssistant()
        await (try #require(workspace.assistant.jobTask)).value
        #expect(workspace.assistant.context?.evidenceID == fixture.evidence.id)
        #expect(workspace.assistant.context?.file == fixture.file)
        #expect(workspace.isBusy)
        #expect(!workspace.canOpenAssistant)
        #expect(!workspace.canAnalyzeFilesystem)
        #expect(!workspace.canExtractFilesystemFile)
        #expect(!workspace.canInspectImage)
        workspace.openCase(at: second.bundleURL)
        #expect(workspace.currentCase?.manifest.id == first.manifest.id)
        #expect(workspace.selectedFileID == fixture.file.id)
        #expect(try Data(contentsOf: manifestURL) == originalManifest)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)

        workspace.assistant.close()
        for _ in 0..<100 where workspace.assistant.isPresented { await Task.yield() }
        #expect(!workspace.isBusy)
        #expect(workspace.canOpenAssistant)
        await workspace.shutdown()
        #expect(!workspace.hasActiveWork)
    }

    @Test("Termination dismisses the modal review sheet while retaining cancellation cleanup")
    func terminationDismissesAndDrains() async throws {
        let fixture = try AssistantStoreFixture()
        defer { fixture.remove() }
        let gate = AssistantRequestGate()
        let store = makeStore(fixture, gate: gate)
        try await prepare(store, fixture: fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        let pending = try #require(store.jobTask)
        let request = await gate.nextRequest()
        store.prepareForTermination()
        #expect(!store.isPresented)
        #expect(!store.canAnalyze)
        #expect(pending.isCancelled)
        #expect(store.hasActiveWork)
        #expect(store.isWorking)
        await gate.succeed(request)
        await pending.value
        #expect(!store.hasActiveWork)
        #expect(!store.isWorking)
        #expect(store.result == nil)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    private func makeStore(_ fixture: AssistantStoreFixture, gate: AssistantRequestGate) -> AssistantAnalysisStore {
        AssistantAnalysisStore(executableURL: fixture.executable) { prompt, executable in
            try await gate.analyze(prompt: prompt, executable: executable)
        }
    }

    private func prepare(_ store: AssistantAnalysisStore, fixture: AssistantStoreFixture) async throws {
        store.configure(evidence: fixture.evidence, result: fixture.enumeration, file: fixture.file, helperURL: fixture.helper)
        await (try #require(store.jobTask)).value
        _ = try #require(store.context)
    }
}

private actor AssistantRequestGate {
    struct Request: Sendable {
        let id: UUID
        let prompt: String
        let executable: URL
    }
    private var requests: [Request] = []
    private var continuations: [UUID: CheckedContinuation<CodexAnalysisResult, any Error>] = [:]
    private var waiters: [CheckedContinuation<Request, Never>] = []
    private(set) var callCount = 0

    func analyze(prompt: String, executable: URL) async throws -> CodexAnalysisResult {
        callCount += 1
        let request = Request(id: UUID(), prompt: prompt, executable: executable)
        return try await withCheckedThrowingContinuation { continuation in
            continuations[request.id] = continuation
            if waiters.isEmpty { requests.append(request) }
            else { waiters.removeFirst().resume(returning: request) }
        }
    }

    func nextRequest() async -> Request {
        if !requests.isEmpty { return requests.removeFirst() }
        return await withCheckedContinuation { waiters.append($0) }
    }

    func succeed(_ request: Request, requestHash: String? = nil) {
        let response = CodexAnalysisResponse(summary: "Synthetic interpretation", observations: ["Recorded entry exists"],
            hypotheses: ["Its purpose is unknown"], limitations: ["Metadata only"], nextSteps: ["Inspect locally"])
        continuations.removeValue(forKey: request.id)?.resume(returning: CodexAnalysisResult(response: response,
            requestSHA256: requestHash ?? AssistantStoreFixture.hash(Data(request.prompt.utf8)),
            completedAt: Date(timeIntervalSince1970: 1_700_000_001)))
    }

    func fail(_ request: Request, error: CodexAnalysisError) {
        continuations.removeValue(forKey: request.id)?.resume(throwing: error)
    }
}

private struct AssistantStoreFixture {
    let directory: URL
    let source: URL
    let executable: URL
    let helper: URL
    let evidence: EvidenceRecord
    let file: FilesystemEntry
    let enumeration: EnumerationResult
    let sourceBytes = Data("abc".utf8)

    init(directory isDirectory: Bool = false) throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("AssistantStore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        source = directory.appendingPathComponent("synthetic.raw")
        try sourceBytes.write(to: source)
        executable = directory.appendingPathComponent("synthetic-codex")
        // Its executable bit tests availability. Injected operations ensure this
        // file is never launched and no account/provider is contacted.
        try Data("synthetic fixture, never executed\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        helper = directory.appendingPathComponent("must-not-launch-helper")
        evidence = EvidenceRecord(sourcePath: source.path, byteCount: 3, sha256: Self.hash(sourceBytes),
            container: .raw, filesystemHint: "synthetic", addedAt: Date(timeIntervalSince1970: 1_700_000_000))
        file = FilesystemEntry(id: "selected-synthetic-file", path: "/NOTE.txt", name: "NOTE.txt", fsOffsetBytes: 0,
            metaAddress: 10, size: isDirectory ? 0 : 3, isDirectory: isDirectory, isDeleted: false,
            modifiedEpoch: 1_700_000_000)
        enumeration = EnumerationResult(engineVersion: "synthetic-store-test", patchDigest: "synthetic-store-test",
            sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256],
            options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512, imagePaths: [source.path]),
            volumes: [], files: [file], warnings: [], status: .completed,
            savedAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }

    static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
