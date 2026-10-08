import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("WorkspaceSchedulingTests")
@MainActor
struct WorkspaceSchedulingTests {
    @Test("Independent preview stores share one admission; queued cancel never extracts")
    func multiwindowQueuedCancellation() async throws {
        let scheduler = ForensicWorkScheduler(), gate = SchedulingPreviewGate()
        try await withSchedulingCleanup(gate) {
        let first = makeStore(scheduler, gate: gate), second = makeStore(scheduler, gate: gate)
        configure(first, fileID: "first"); configure(second, fileID: "second")
        first.load()
        let firstTask = try #require(first.loadTask)
        let request = await gate.nextRequest()
        #expect(request == "first")
        let activeID = try #require(await scheduler.state().active?.id)
        second.load()
        let secondTask = try #require(second.loadTask)
        try await schedulingWait(scheduler, queued: 1)
        #expect(first.hasActiveWork && second.hasActiveWork)
        #expect(await gate.started == ["first"])
        second.cancel(); await secondTask.value
        #expect(await gate.started == ["first"])
        #expect(!second.hasActiveWork && second.preview == nil)
        #expect(second.phase.contains("canceled"))
        #expect(await scheduler.state().active?.id == activeID)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        await gate.finish("first")
        await firstTask.value
        #expect(!first.hasActiveWork)
        #expect(await scheduler.state().active == nil)
        }
    }

    @Test("Closing one active window drains its child before another window can start")
    func multiwindowCloseDrain() async throws {
        let scheduler = ForensicWorkScheduler(), gate = SchedulingPreviewGate()
        try await withSchedulingCleanup(gate) {
        let first = makeStore(scheduler, gate: gate), second = makeStore(scheduler, gate: gate)
        configure(first, fileID: "first"); configure(second, fileID: "second")
        first.load(); #expect(await gate.nextRequest() == "first")
        let activeID = try #require(await scheduler.state().active?.id)
        second.load()
        let secondTask = try #require(second.loadTask)
        try await schedulingWait(scheduler, queued: 1)
        let shutdown = try #require(first.beginShutdown())
        #expect(first.hasActiveWork)
        #expect(await scheduler.state().active?.id == activeID)
        #expect(await gate.started == ["first"])
        await gate.finish("first"); await shutdown.value
        #expect(!first.hasActiveWork)
        #expect(await gate.nextRequest() == "second")
        #expect(await gate.started == ["first", "second"])
        #expect(!(await scheduler.state().isClosed))
        await gate.finish("second"); await secondTask.value
        #expect(!second.hasActiveWork)
        #expect(await scheduler.state().active == nil)
        }
    }

    private func makeStore(_ scheduler: ForensicWorkScheduler, gate: SchedulingPreviewGate) -> ContentPreviewStore {
        ContentPreviewStore(load: { _, _, file, _ in try await gate.load(file.id) }, scheduler: scheduler)
    }

    private func configure(_ store: ContentPreviewStore, fileID: String) {
        let source = "/synthetic/scheduling-source.raw", digest = String(repeating: "a", count: 64)
        let evidence = EvidenceRecord(sourcePath: source, byteCount: 5, sha256: digest,
            container: .raw, filesystemHint: nil)
        let file = FilesystemEntry(id: fileID, path: "/\(fileID).txt", name: "\(fileID).txt",
            fsOffsetBytes: 0, metaAddress: 1, size: 5, isDirectory: false, isDeleted: false)
        let result = EnumerationResult(engineVersion: "synthetic", patchDigest: "synthetic-only",
            sourcePaths: [source], sourceFileHashes: [source: digest], options: .init(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 5, sectorSize: 512), volumes: [],
            files: [file], warnings: [], status: .completed)
        store.configure(evidence: evidence, result: result, file: file,
            helperURL: URL(fileURLWithPath: "/synthetic/helper"))
    }
}

private actor SchedulingPreviewGate {
    private(set) var started: [String] = []
    private var pendingRequests: [String] = []
    private var waiting: [CheckedContinuation<String, Never>] = []
    private var completions: [String: CheckedContinuation<LocalContentPreview, Error>] = [:]
    private var isClosing = false

    /// Intentionally ignores cancellation until its child/scratch owner drains.
    func load(_ fileID: String) async throws -> LocalContentPreview {
        guard !isClosing else { throw EngineError.sourceChanged }
        started.append(fileID)
        return try await withCheckedThrowingContinuation { continuation in
            completions[fileID] = continuation
            if waiting.isEmpty { pendingRequests.append(fileID) }
            else { waiting.removeFirst().resume(returning: fileID) }
        }
    }
    func nextRequest() async -> String {
        if !pendingRequests.isEmpty { return pendingRequests.removeFirst() }
        return await withCheckedContinuation { waiting.append($0) }
    }
    func finish(_ fileID: String) {
        completions.removeValue(forKey: fileID)?.resume(throwing: EngineError.sourceChanged)
    }
    func finishAll() {
        isClosing = true
        let owners = Array(completions.values); completions.removeAll()
        for owner in owners { owner.resume(throwing: EngineError.sourceChanged) }
        for waiter in waiting { waiter.resume(returning: "closed") }
        waiting.removeAll(); pendingRequests.removeAll()
    }
}

@MainActor
private func withSchedulingCleanup(_ gate: SchedulingPreviewGate,
                                   operation: @MainActor () async throws -> Void) async throws {
    do {
        try await operation()
        await gate.finishAll()
    } catch {
        await gate.finishAll()
        throw error
    }
}

private enum SchedulingNativeTestError: Error { case waitExpired }
private func schedulingWait(_ scheduler: ForensicWorkScheduler, queued count: Int) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while await scheduler.state().queuedKinds.count != count {
        if ContinuousClock.now >= deadline { throw SchedulingNativeTestError.waitExpired }
        try await Task.sleep(for: .milliseconds(1))
    }
}
