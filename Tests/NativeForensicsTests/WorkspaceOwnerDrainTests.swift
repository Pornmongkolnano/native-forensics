import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("WorkspaceOwnerDrainTests")
@MainActor
struct WorkspaceOwnerDrainTests {
    @Test("Superseding a running query waits for its canceled worker before starting the newest query")
    func supersededWorkerDrainsBeforeNewestStarts() async throws {
        let gate = WorkspaceRowWorkerGate()
        defer { gate.releaseAll() }
        let fixture = makeWorkspace(gate: gate)
        let workspace = fixture.workspace

        workspace.filesystemSearchText = "alpha"
        let oldID = try #require(workspace.filesystemSearchID)
        let oldOwner = try #require(workspace.filesystemSearchTask)
        try await gate.waitForEntry("alpha")

        workspace.filesystemSearchText = "beta"
        let intermediateOwner = try #require(workspace.filesystemSearchTask)
        workspace.filesystemSearchText = "gamma"
        let newestID = try #require(workspace.filesystemSearchID)
        let newestOwner = try #require(workspace.filesystemSearchTask)

        #expect(workspace.filesystemSearchJobs[oldID] != nil)
        #expect(workspace.filesystemSearchJobs[newestID] != nil)
        #expect(workspace.hasActiveWork)
        #expect(workspace.isFilteringFilesystem)
        try await gate.expectOnlyEntries(["alpha"], for: .milliseconds(250))
        #expect(workspace.filesystemRows == fixture.firstFiles)

        gate.release("alpha")
        await oldOwner.value
        await intermediateOwner.value
        try await gate.waitForEntry("gamma")
        #expect(gate.events == [.entered("alpha"), .returned("alpha", canceled: true), .entered("gamma")])
        #expect(workspace.filesystemSearchJobs[oldID] == nil)
        #expect(workspace.filesystemSearchJobs[newestID] != nil)
        // The old worker deliberately returned its completed match after being
        // canceled. Only the current owner's publication guards may accept it.
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(workspace.isFilteringFilesystem)

        gate.release("gamma")
        await newestOwner.value
        #expect(workspace.filesystemRows == [fixture.firstFiles[2]])
        #expect(workspace.filesystemSearchText == "gamma")
        #expect(workspace.filesystemSearchJobs.isEmpty)
        #expect(!workspace.isFilteringFilesystem)
        #expect(!gate.didExpire)
        await workspace.shutdown()
        #expect(!workspace.hasActiveWork)
    }

    @Test("Changing evidence retains the old search owner and rejects its delayed rows")
    func evidenceChangeCannotPublishOldWorker() async throws {
        let gate = WorkspaceRowWorkerGate()
        defer { gate.releaseAll() }
        let fixture = makeWorkspace(gate: gate)
        let workspace = fixture.workspace

        workspace.filesystemSearchText = "alpha"
        let oldID = try #require(workspace.filesystemSearchID)
        let oldOwner = try #require(workspace.filesystemSearchTask)
        try await gate.waitForEntry("alpha")

        workspace.selectedEvidenceID = fixture.secondEvidence.id
        #expect(workspace.selectedEvidence == fixture.secondEvidence)
        #expect(workspace.filesystemRows == fixture.secondFiles)
        #expect(workspace.filesystemSearchJobs[oldID] != nil)
        #expect(workspace.hasActiveWork)
        #expect(workspace.filesystemSearchTask == nil)
        #expect(!workspace.isFilteringFilesystem)
        #expect(workspace.filesystemFilesByID[fixture.firstFiles[0].id] == nil)

        workspace.filesystemSearchText = "delta"
        let newOwner = try #require(workspace.filesystemSearchTask)
        try await gate.expectOnlyEntries(["alpha"], for: .milliseconds(250))
        gate.release("alpha")
        await oldOwner.value
        try await gate.waitForEntry("delta")
        #expect(gate.events == [.entered("alpha"), .returned("alpha", canceled: true), .entered("delta")])
        #expect(workspace.selectedEvidence == fixture.secondEvidence)
        #expect(workspace.filesystemRows == fixture.secondFiles)
        #expect(workspace.filesystemFilesByID[fixture.firstFiles[0].id] == nil)

        gate.release("delta")
        await newOwner.value
        #expect(workspace.filesystemRows == [fixture.secondFiles[0]])
        #expect(workspace.selectedEvidence == fixture.secondEvidence)
        #expect(workspace.filesystemSearchJobs.isEmpty)
        #expect(!gate.didExpire)
        await workspace.shutdown()
        #expect(!workspace.hasActiveWork)
    }

    @Test("Cancel and close keep a running search owned until its detached worker drains")
    func canceledSearchKeepsQuitWaitingForDrain() async throws {
        let gate = WorkspaceRowWorkerGate()
        defer { gate.releaseAll() }
        let fixture = makeWorkspace(gate: gate)
        let workspace = fixture.workspace

        workspace.filesystemSearchText = "alpha"
        let oldID = try #require(workspace.filesystemSearchID)
        let oldOwner = try #require(workspace.filesystemSearchTask)
        try await gate.waitForEntry("alpha")
        workspace.cancelCurrentJob()

        #expect(workspace.filesystemSearchText.isEmpty)
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(workspace.filesystemSearchTask == nil)
        #expect(workspace.filesystemSearchID == nil)
        #expect(!workspace.isFilteringFilesystem)
        #expect(workspace.filesystemSearchJobs[oldID] != nil)
        #expect(workspace.hasActiveWork)

        var shutdownReturned = false
        let shutdown = Task { @MainActor in
            await workspace.shutdown()
            shutdownReturned = true
        }
        try await waitUntilClosing(workspace)
        // A fresh UI actor task can execute while the real detached worker is
        // held; closing still waits for that worker, rather than its task handle.
        let heartbeat = Task { @MainActor in
            #expect(workspace.isClosing)
            #expect(workspace.hasActiveWork)
            #expect(workspace.filesystemSearchJobs[oldID] != nil)
            #expect(!shutdownReturned)
        }
        await heartbeat.value
        #expect(gate.events == [.entered("alpha")])

        gate.release("alpha")
        await oldOwner.value
        await shutdown.value
        #expect(shutdownReturned)
        #expect(workspace.filesystemSearchJobs.isEmpty)
        #expect(!workspace.hasActiveWork)
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(gate.events == [.entered("alpha"), .returned("alpha", canceled: true)])
        #expect(!gate.didExpire)
    }

    private func waitUntilClosing(_ workspace: WorkspaceStore) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !workspace.isClosing {
            guard ContinuousClock.now < deadline else { throw WorkspaceRowGateError.entryWaitExpired }
            try await Task.sleep(for: .milliseconds(2))
        }
    }

    private func makeWorkspace(gate: WorkspaceRowWorkerGate) -> Fixture {
        let caseID = UUID()
        // DTOs only: neither this case nor these sources are created on disk.
        let caseURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("WorkspaceOwnerDrain-\(caseID.uuidString).nativecase")
        let first = evidence(name: "first.raw", caseURL: caseURL)
        let second = evidence(name: "second.raw", caseURL: caseURL)
        let firstFiles = [entry(id: "first-alpha", name: "alpha.txt"),
                          entry(id: "first-beta", name: "beta.txt"),
                          entry(id: "first-gamma", name: "gamma.txt")]
        let secondFiles = [entry(id: "second-delta", name: "delta.txt"),
                           entry(id: "second-other", name: "other.txt")]
        let workspace = WorkspaceStore(scheduler: ForensicWorkScheduler(), rowSearch: { index, query, category in
            let rows = try FilesystemCategory.rows(in: index, matching: query, category: category)
            // Cancellation intentionally cannot interrupt this bounded external
            // owner; return the completed rows after release to test publication.
            try gate.hold(query)
            return rows
        })
        workspace.currentCase = ForensicCase(bundleURL: caseURL,
            manifest: CaseManifest(id: caseID, name: "Owner Drain", evidence: [first, second]))
        workspace.filesystemResults = [first.id: result(evidence: first, files: firstFiles),
                                       second.id: result(evidence: second, files: secondFiles)]
        workspace.selectedEvidenceID = first.id
        return Fixture(workspace: workspace, secondEvidence: second,
                       firstFiles: firstFiles, secondFiles: secondFiles)
    }

    private func evidence(name: String, caseURL: URL) -> EvidenceRecord {
        EvidenceRecord(sourcePath: caseURL.deletingLastPathComponent().appendingPathComponent(name).path,
                       byteCount: 4096, sha256: String(repeating: "a", count: 64),
                       container: .raw, filesystemHint: "FAT16")
    }

    private func entry(id: String, name: String) -> FilesystemEntry {
        FilesystemEntry(id: id, path: "/Reports/\(name)", name: name, fsOffsetBytes: 0,
                        metaAddress: 10, size: 52, isDirectory: false, isDeleted: false)
    }

    private func result(evidence: EvidenceRecord, files: [FilesystemEntry]) -> EnumerationResult {
        EnumerationResult(engineVersion: "owner-drain-test", patchDigest: "synthetic-only",
            sourcePaths: [evidence.sourcePath], sourceFileHashes: [evidence.sourcePath: evidence.sha256],
            options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: evidence.byteCount,
                                       sectorSize: 512, imagePaths: [evidence.sourcePath]),
            volumes: [], files: files, warnings: [], status: .completed)
    }

    private struct Fixture {
        let workspace: WorkspaceStore
        let secondEvidence: EvidenceRecord
        let firstFiles: [FilesystemEntry]
        let secondFiles: [FilesystemEntry]
    }
}

private enum WorkspaceRowGateError: Error { case entryWaitExpired, workerWaitExpired, unexpectedWorkerEntry }

/// Only the actual detached search worker blocks here. NSCondition's own wall
/// clock deadline releases a stalled test independently of cooperative tasks.
private final class WorkspaceRowWorkerGate: @unchecked Sendable {
    enum Event: Equatable, Sendable {
        case entered(String)
        case returned(String, canceled: Bool)
    }
    private let condition = NSCondition()
    private var recordedEvents: [Event] = []
    private var releasedQueries: Set<String> = []
    private var allReleased = false
    private var expired = false

    var events: [Event] {
        condition.lock(); defer { condition.unlock() }
        return recordedEvents
    }
    var didExpire: Bool {
        condition.lock(); defer { condition.unlock() }
        return expired
    }

    func hold(_ query: String) throws {
        condition.lock(); defer { condition.unlock() }
        recordedEvents.append(.entered(query))
        condition.broadcast()
        let deadline = Date().addingTimeInterval(8)
        while !allReleased && !releasedQueries.contains(query) {
            if !condition.wait(until: deadline) {
                expired = true
                throw WorkspaceRowGateError.workerWaitExpired
            }
        }
        recordedEvents.append(.returned(query, canceled: Task.isCancelled))
        condition.broadcast()
    }

    func release(_ query: String) {
        condition.lock(); defer { condition.unlock() }
        releasedQueries.insert(query)
        condition.broadcast()
    }

    func releaseAll() {
        condition.lock(); defer { condition.unlock() }
        allReleased = true
        condition.broadcast()
    }

    func waitForEntry(_ query: String) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !events.contains(.entered(query)) {
            guard ContinuousClock.now < deadline else { throw WorkspaceRowGateError.entryWaitExpired }
            try await Task.sleep(for: .milliseconds(2))
        }
    }

    func expectOnlyEntries(_ expected: [String], for duration: Duration) async throws {
        let deadline = ContinuousClock.now.advanced(by: duration)
        repeat {
            let entries = events.compactMap { event -> String? in
                if case .entered(let query) = event { return query }
                return nil
            }
            guard entries == expected else { throw WorkspaceRowGateError.unexpectedWorkerEntry }
            try await Task.sleep(for: .milliseconds(2))
        } while ContinuousClock.now < deadline
    }
}
