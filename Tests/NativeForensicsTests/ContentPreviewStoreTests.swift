import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("ContentPreviewStoreTests")
@MainActor
struct ContentPreviewStoreTests {
    @Test("Configure is local-only and explicit load publishes a bounded, identified preview")
    func explicitLoad() async throws {
        let fixture = ContentStoreFixture()
        let gate = ContentLoadGate()
        let store = makeStore(gate)
        configure(store, fixture)
        #expect(await gate.callCount == 0)
        #expect(store.preview == nil)
        #expect(!store.hasActiveWork)
        #expect(store.canLoad)
        store.load()
        let task = try #require(store.loadTask)
        let request = await gate.nextRequest()
        await gate.succeed(request, with: try fixture.preview())
        await task.value
        #expect(store.preview?.receipt.fileID == fixture.file.id)
        #expect(store.preview?.text == "ภาษาไทย\n")
        #expect(!store.hasActiveWork)
        #expect(store.errorMessage == nil)
    }

    @Test("Rapid replacement cancels and retains every older owner until drain; stale results cannot populate UI")
    func selectionReplacement() async throws {
        let first = ContentStoreFixture(id: "first")
        let second = ContentStoreFixture(id: "second")
        let third = ContentStoreFixture(id: "third")
        let gate = ContentLoadGate()
        let store = makeStore(gate)
        configure(store, first)
        store.load()
        let firstTask = try #require(store.loadTask)
        let oldRequest = await gate.nextRequest()
        configure(store, second)
        #expect(store.preview == nil && store.hasActiveWork)
        store.load()
        let secondTask = try #require(store.loadTask)
        configure(store, third)
        store.load()
        let thirdTask = try #require(store.loadTask)
        #expect(await gate.callCount == 1)
        #expect(store.hasActiveWork && store.isLoading)
        // The fake deliberately ignores cancellation until its resource-owner
        // completes, exercising the same drain boundary as an extraction.
        await gate.succeed(oldRequest, with: try first.preview())
        await firstTask.value
        await secondTask.value
        let newRequest = await gate.nextRequest()
        #expect(newRequest.fileID == third.file.id)
        #expect(await gate.callCount == 2)
        #expect(store.preview == nil)
        await gate.succeed(newRequest, with: try third.preview())
        await thirdTask.value
        #expect(store.preview?.receipt.fileID == third.file.id)
        #expect(!store.hasActiveWork)
    }

    @Test("Superseded failure cannot overwrite new selection and arbitrary host diagnostics are never shown")
    func safeErrors() async throws {
        let first = ContentStoreFixture(id: "first")
        let second = ContentStoreFixture(id: "second")
        let gate = ContentLoadGate()
        let store = makeStore(gate)
        configure(store, first)
        store.load()
        let task = try #require(store.loadTask)
        let request = await gate.nextRequest()
        configure(store, second)
        await gate.fail(request, error: EngineError.helperFailed("private temporary path /private/tmp/sensitive"))
        await task.value
        #expect(store.errorMessage == nil)
        #expect(store.preview == nil)
        store.load()
        let current = try #require(store.loadTask)
        await gate.fail(await gate.nextRequest(), error: EngineError.helperFailed("private temporary path /private/tmp/sensitive"))
        await current.value
        #expect(store.errorMessage != nil)
        #expect(store.errorMessage?.contains("sensitive") == false)
        #expect(store.errorMessage?.contains("/private/") == false)
    }

    @Test("Cancel and shutdown drain owners before reporting no active work")
    func shutdownDrain() async throws {
        let fixture = ContentStoreFixture()
        let gate = ContentLoadGate()
        let store = makeStore(gate)
        configure(store, fixture)
        store.load()
        let request = await gate.nextRequest()
        store.cancel()
        #expect(store.hasActiveWork && store.isLoading)
        let drain = try #require(store.beginShutdown())
        #expect(store.hasActiveWork)
        #expect(!store.canLoad)
        configure(store, ContentStoreFixture(id: "ignored"))
        await gate.succeed(request, with: try fixture.preview())
        await drain.value
        #expect(!store.hasActiveWork)
        #expect(store.preview == nil)
        store.reset()
        configure(store, fixture)
        #expect(store.canLoad)
        #expect(await gate.callCount == 1)
    }

    @Test("A response for a different file is rejected instead of previewing incorrect bytes")
    func identityMismatch() async throws {
        let fixture = ContentStoreFixture()
        let gate = ContentLoadGate()
        let store = makeStore(gate)
        configure(store, fixture)
        store.load()
        let task = try #require(store.loadTask)
        await gate.succeed(await gate.nextRequest(), with: try ContentStoreFixture(id: "foreign").preview())
        await task.value
        #expect(store.preview == nil)
        #expect(store.errorMessage == VerifiedContentError.extractedContentMismatch.localizedDescription)
    }

    @Test("Text and hex page rendering stay capped at 50 rows and changing mode resets page")
    func paging() async throws {
        let bytes = Data((String(repeating: "line\n", count: 150)).utf8)
        let fixture = ContentStoreFixture(payload: bytes)
        let gate = ContentLoadGate()
        let store = makeStore(gate)
        configure(store, fixture)
        store.load()
        let task = try #require(store.loadTask)
        await gate.succeed(await gate.nextRequest(), with: try fixture.preview())
        await task.value
        #expect(store.visibleTextFragments.count == 50)
        #expect(store.pageCount == 4)
        store.page = 3
        #expect(store.visibleTextFragments.count == 1)
        store.mode = .hex
        #expect(store.page == 0)
        #expect(store.visibleHexRows.count <= 50)
        store.reset()
        #expect(store.preview == nil)
        #expect(!store.hasSelection)
    }

    private func makeStore(_ gate: ContentLoadGate) -> ContentPreviewStore {
        ContentPreviewStore(load: { _, _, file, _ in try await gate.load(fileID: file.id) }, scheduler: ForensicWorkScheduler())
    }
    private func configure(_ store: ContentPreviewStore, _ fixture: ContentStoreFixture) {
        store.configure(evidence: fixture.evidence, result: fixture.result, file: fixture.file,
                        helperURL: URL(fileURLWithPath: "/synthetic/helper"))
    }
}

private actor ContentLoadGate {
    struct Request: Sendable { let id: UUID; let fileID: String }
    private var queued: [Request] = []
    private var waiting: [CheckedContinuation<Request, Never>] = []
    private var responses: [UUID: CheckedContinuation<LocalContentPreview, Error>] = [:]
    private(set) var callCount = 0

    func load(fileID: String) async throws -> LocalContentPreview {
        callCount += 1
        let request = Request(id: UUID(), fileID: fileID)
        return try await withCheckedThrowingContinuation { continuation in
            responses[request.id] = continuation
            if waiting.isEmpty { queued.append(request) } else { waiting.removeFirst().resume(returning: request) }
        }
    }
    func nextRequest() async -> Request {
        if !queued.isEmpty { return queued.removeFirst() }
        return await withCheckedContinuation { waiting.append($0) }
    }
    func succeed(_ request: Request, with value: LocalContentPreview) {
        responses.removeValue(forKey: request.id)?.resume(returning: value)
    }
    func fail(_ request: Request, error: EngineError) {
        responses.removeValue(forKey: request.id)?.resume(throwing: error)
    }
}

private struct ContentStoreFixture {
    let payload: Data
    let evidence: EvidenceRecord
    let file: FilesystemEntry
    let result: EnumerationResult
    init(id: String = "content-1", payload: Data = Data("ภาษาไทย\n".utf8)) {
        self.payload = payload
        let source = "/synthetic/content.dd"
        let hash = Self.hash(Data("image".utf8))
        evidence = EvidenceRecord(sourcePath: source, byteCount: 5, sha256: hash, container: .raw, filesystemHint: nil)
        file = FilesystemEntry(id: id, path: "/\(id).txt", name: "\(id).txt", fsOffsetBytes: 0, metaAddress: 1,
            size: Int64(payload.count), isDirectory: false, isDeleted: false)
        result = EnumerationResult(engineVersion: "fixture", patchDigest: "synthetic-only", sourcePaths: [source],
            sourceFileHashes: [source: hash], options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 5, sectorSize: 512),
            volumes: [], files: [file], warnings: [], status: .completed)
    }
    func preview() throws -> LocalContentPreview {
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
        let content = VerifiedContent(bytes: payload, receipt: VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id,
            byteCount: Int64(payload.count), sha256: Self.hash(payload), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]))
        return ContentPreviewBuilder.render(content: content, context: context)
    }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}
