import Darwin
import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@_silgen_name("flock")
private func readinessFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

@Suite("WorkspaceReadinessTests")
@MainActor
struct WorkspaceReadinessTests {
    @Test("External case opening cannot replace a workspace while a panel, job or close is active")
    func guardedCaseOpening() throws {
        let root = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try CaseStore.create(name: "First", in: root)
        let second = try CaseStore.create(name: "Second", in: root)
        let workspace = WorkspaceStore()
        workspace.openCase(at: first.bundleURL)
        let originalManifest = try Data(contentsOf: first.bundleURL.appendingPathComponent("manifest.json"))

        workspace.isPresentingPanel = true
        workspace.openCase(at: second.bundleURL)
        #expect(workspace.currentCase?.manifest.id == first.manifest.id)
        #expect(workspace.errorMessage?.contains("file dialog") == true)
        workspace.isPresentingPanel = false
        workspace.isEngineRunning = true
        workspace.openCase(at: second.bundleURL)
        #expect(workspace.currentCase?.manifest.id == first.manifest.id)
        workspace.isEngineRunning = false
        workspace.isInspecting = true
        workspace.openCase(at: second.bundleURL)
        #expect(workspace.currentCase?.manifest.id == first.manifest.id)
        workspace.isInspecting = false
        workspace.prepareForClosing()
        workspace.openCase(at: second.bundleURL)
        #expect(workspace.currentCase?.manifest.id == first.manifest.id)
        #expect(!workspace.canInspectImage)
        #expect(try Data(contentsOf: first.bundleURL.appendingPathComponent("manifest.json")) == originalManifest)
    }

    @Test("An invalid case preserves the current selection and a later valid open clears its stale alert")
    func failedCaseOpenIsRecoverable() throws {
        let root = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try CaseStore.create(name: "First", in: root)
        let second = try CaseStore.create(name: "Second", in: root)
        let workspace = WorkspaceStore()
        workspace.openCase(at: first.bundleURL)
        workspace.searchText = "preserved"
        workspace.openCase(at: root.appendingPathComponent("missing.nativecase"))
        #expect(workspace.currentCase?.bundleURL.path == first.bundleURL.path)
        #expect(workspace.searchText == "preserved")
        #expect(workspace.errorMessage != nil)
        workspace.openCase(at: second.bundleURL)
        #expect(workspace.currentCase?.manifest.id == second.manifest.id)
        #expect(workspace.searchText.isEmpty)
        #expect(workspace.errorMessage == nil)
    }

    @Test("A malformed saved cache remains untouched, shows recovery guidance and does not lock out analysis")
    func malformedCacheIsPreserved() async throws {
        let fixture = try await recordedFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = fixture.forensicCase.bundleURL.appendingPathComponent("filesystem", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let cache = directory.appendingPathComponent(fixture.evidence.id.uuidString.lowercased() + ".json")
        let corrupt = Data("{not-json}".utf8)
        try corrupt.write(to: cache)
        let manifest = try Data(contentsOf: fixture.forensicCase.bundleURL.appendingPathComponent("manifest.json"))
        let source = try Data(contentsOf: fixture.source)
        let workspace = WorkspaceStore()
        workspace.openCase(at: fixture.forensicCase.bundleURL)
        let loading = try #require(workspace.filesystemLoadTask)
        await loading.value
        #expect(workspace.selectedFilesystemResult == nil)
        #expect(!workspace.isLoadingFilesystem)
        #expect(workspace.errorMessage?.contains("cache was preserved") == true)
        #expect(workspace.errorMessage?.contains("Reanalyze") == true)
        #expect(workspace.canAnalyzeFilesystem)
        #expect(try Data(contentsOf: cache) == corrupt)
        #expect(try Data(contentsOf: fixture.source) == source)
        #expect(try Data(contentsOf: fixture.forensicCase.bundleURL.appendingPathComponent("manifest.json")) == manifest)
        await workspace.shutdown()
    }

    @Test("Missing engine packaging is reported before source hashing or output selection begins")
    func missingHelperPreflight() async throws {
        let fixture = try await recordedFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let workspace = WorkspaceStore(helperURL: fixture.root.appendingPathComponent("missing-helper"))
        workspace.openCase(at: fixture.forensicCase.bundleURL)
        await workspace.filesystemLoadTask?.value
        workspace.analyzeSelectedImage()
        #expect(workspace.errorMessage?.contains("Reinstall the complete") == true)
        #expect(workspace.statusMessage.contains("preserved"))
        #expect(!workspace.isEngineRunning)
        #expect(workspace.engineTask == nil)
        #expect(workspace.verificationProgress == nil)
        #expect(!workspace.isPresentingPanel)
        #expect(workspace.currentCase?.manifest == fixture.forensicCase.manifest)
        await workspace.shutdown()
    }

    @Test("Helper preflight rejects folders, symlinks and non-executables while accepting a plain executable")
    func helperPackagingChecks() throws {
        let root = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(EngineAvailability.issue(for: root) != nil)
        let helper = root.appendingPathComponent("helper")
        try Data("synthetic fixture".utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: helper.path)
        #expect(EngineAvailability.issue(for: helper)?.contains("not executable") == true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        #expect(EngineAvailability.issue(for: helper) == nil)
        let symlink = root.appendingPathComponent("helper-link")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: helper)
        #expect(EngineAvailability.issue(for: symlink) != nil)
    }

    @Test("Closing before inspection starts drains cancellation without publishing an evidence record")
    func inspectionShutdownBeforeCommit() async throws {
        let root = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let forensicCase = try CaseStore.create(name: "Cancelled", in: root)
        let source = root.appendingPathComponent("source.raw")
        try Data(repeating: 0x42, count: 4096).write(to: source)
        let workspace = WorkspaceStore()
        workspace.openCase(at: forensicCase.bundleURL)
        workspace.inspectImage(at: source)
        #expect(workspace.isInspecting)
        await workspace.shutdown()
        #expect(workspace.isClosing)
        #expect(!workspace.isInspecting)
        #expect(!workspace.hasActiveWork)
        #expect(workspace.currentCase?.manifest.evidence.isEmpty == true)
        #expect(try CaseStore.open(at: forensicCase.bundleURL).manifest.evidence.isEmpty)
        #expect(workspace.statusMessage.contains("No evidence record"))
    }

    @Test("Waiting for an atomic manifest commit leaves the UI responsive and close drains publication")
    func pendingManifestCommitDrains() async throws {
        let root = try temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let forensicCase = try CaseStore.create(name: "Locked", in: root)
        let source = root.appendingPathComponent("source.raw")
        try Data(repeating: 0x43, count: 4096).write(to: source)
        let descriptor = Darwin.open(forensicCase.bundleURL.appendingPathComponent(".case.lock").path, O_RDWR)
        #expect(descriptor >= 0)
        defer { _ = readinessFlock(descriptor, LOCK_UN); Darwin.close(descriptor) }
        #expect(readinessFlock(descriptor, LOCK_EX) == 0)
        let watchdogState = WatchdogState()
        // The fallback prevents the regression itself from hanging this test.
        let watchdog = Task.detached {
            do { try await Task.sleep(for: .seconds(2)); try Task.checkCancellation() }
            catch { return }
            await watchdogState.markReleased()
            _ = readinessFlock(descriptor, LOCK_UN)
        }
        let workspace = WorkspaceStore()
        workspace.openCase(at: forensicCase.bundleURL)
        workspace.inspectImage(at: source)
        let deadline = ContinuousClock.now + .seconds(3)
        while workspace.isInspecting && workspace.progress?.fraction != 1 && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        try await Task.sleep(for: .milliseconds(20))
        #expect(workspace.isInspecting)
        #expect(await !watchdogState.released)
        let shuttingDown = Task { await workspace.shutdown() }
        await Task.yield()
        #expect(workspace.isClosing)
        #expect(workspace.isInspecting)
        _ = readinessFlock(descriptor, LOCK_UN)
        watchdog.cancel()
        await watchdog.value
        await shuttingDown.value
        #expect(!workspace.hasActiveWork)
        #expect(!workspace.isInspecting)
        #expect(workspace.currentCase?.manifest.evidence.count == 1)
        #expect(try CaseStore.open(at: forensicCase.bundleURL).manifest.evidence.count == 1)
        #expect(workspace.statusMessage.contains("saved before cancellation"))
    }

    @Test("Termination cancels every workspace and waits for their cleanup acknowledgements")
    func allWorkspaceJobsDrain() async throws {
        let lifecycle = WorkspaceLifecycle()
        let first = WorkspaceStore()
        let second = WorkspaceStore()
        let firstGate = CleanupGate()
        let secondGate = CleanupGate()
        first.isEngineRunning = true
        second.isEngineRunning = true
        let firstJob = Task { await firstGate.wait(); first.isEngineRunning = false; first.engineTask = nil }
        let secondJob = Task { await secondGate.wait(); second.isEngineRunning = false; second.engineTask = nil }
        first.engineTask = firstJob
        second.engineTask = secondJob
        lifecycle.register(first)
        lifecycle.register(second)
        lifecycle.prepareForTermination()
        #expect(first.isClosing && second.isClosing)
        #expect(lifecycle.hasActiveWork)
        let drain = Task { await lifecycle.shutdownAll() }
        let cancellationDeadline = ContinuousClock.now + .seconds(2)
        while (!firstJob.isCancelled || !secondJob.isCancelled) && ContinuousClock.now < cancellationDeadline {
            await Task.yield()
        }
        #expect(firstJob.isCancelled && secondJob.isCancelled)
        #expect(lifecycle.count == 2)
        #expect(first.isEngineRunning && second.isEngineRunning)
        await firstGate.release()
        await Task.yield()
        #expect(lifecycle.count == 2)
        await secondGate.release()
        await drain.value
        #expect(lifecycle.count == 0)
        #expect(!lifecycle.hasActiveWork)
        #expect(!first.isEngineRunning && !second.isEngineRunning)
    }

    @Test("A closed window stays registered until its native job completes cleanup")
    func closedWorkspaceIsRetained() async throws {
        let lifecycle = WorkspaceLifecycle()
        let workspace = WorkspaceStore()
        let gate = CleanupGate()
        workspace.isEngineRunning = true
        let job = Task { await gate.wait(); workspace.isEngineRunning = false; workspace.engineTask = nil }
        workspace.engineTask = job
        lifecycle.register(workspace)
        lifecycle.close(workspace)
        #expect(workspace.isClosing)
        let cancellationDeadline = ContinuousClock.now + .seconds(2)
        while !job.isCancelled && ContinuousClock.now < cancellationDeadline { await Task.yield() }
        #expect(job.isCancelled)
        #expect(lifecycle.count == 1)
        #expect(lifecycle.hasActiveWork)
        await gate.release()
        await job.value
        let retirementDeadline = ContinuousClock.now + .seconds(2)
        while lifecycle.count != 0 && ContinuousClock.now < retirementDeadline { await Task.yield() }
        #expect(lifecycle.count == 0)
        #expect(!lifecycle.hasActiveWork)
    }

    private func temporaryRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("WorkspaceReadiness-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }

    private func recordedFixture() async throws -> RecordedFixture {
        let root = try temporaryRoot()
        do {
            let source = root.appendingPathComponent("source.raw")
            try Data(repeating: 0x44, count: 4096).write(to: source)
            let image = try await ImageInspector.inspect(url: source) { _ in }
            let forensicCase = try CaseStore.adding(image: image, to: CaseStore.create(name: "Recorded", in: root))
            return RecordedFixture(root: root, source: source, forensicCase: forensicCase,
                                   evidence: try #require(forensicCase.manifest.evidence.first))
        } catch {
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private struct RecordedFixture {
        let root: URL
        let source: URL
        let forensicCase: ForensicCase
        let evidence: EvidenceRecord
    }
}

private actor WatchdogState {
    private(set) var released = false
    func markReleased() { released = true }
}

private actor CleanupGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var isReleased = false
    func wait() async {
        if isReleased { return }
        await withCheckedContinuation { continuation = $0 }
    }
    func release() {
        isReleased = true
        continuation?.resume()
        continuation = nil
    }
}
