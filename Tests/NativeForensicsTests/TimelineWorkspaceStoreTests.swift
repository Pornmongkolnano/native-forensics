import AppKit
import Foundation
import UniformTypeIdentifiers
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("Timeline workspace ownership", .serialized)
@MainActor
struct TimelineWorkspaceStoreTests {
    private func selection() -> (UUID, EvidenceRecord, EnumerationResult) {
        let hash = String(repeating: "a", count: 64)
        let evidence = EvidenceRecord(sourcePath: "/synthetic/source.dd", byteCount: 4096, sha256: hash, container: .raw, filesystemHint: nil)
        let files = [FilesystemEntry(id: "file", path: "/one.txt", name: "one.txt", fsOffsetBytes: 0, metaAddress: 1, size: 4, isDirectory: false, isDeleted: false, modifiedEpoch: 1_700_000_000),
            FilesystemEntry(id: "history", path: "/browser/History", name: "History", fsOffsetBytes: 0, metaAddress: 2, size: 1024, isDirectory: false, isDeleted: false, modifiedEpoch: 1_700_000_002)]
        let result = EnumerationResult(engineVersion: "test", patchDigest: "test", sourcePaths: [evidence.sourcePath], sourceFileHashes: [evidence.sourcePath: hash], options: EngineOptions(hashLogicalImage: false), image: EngineImageMetadata(imageType: "raw", logicalSize: 4096, sectorSize: 512), volumes: [], files: files, warnings: [], status: .completed, savedAt: Date(timeIntervalSince1970: 1_700_000_010))
        return (UUID(), evidence, result)
    }
    private func configure(_ store: TimelineWorkspaceStore, _ value: (UUID, EvidenceRecord, EnumerationResult), historical: Bool = false) {
        store.configure(caseID: value.0, evidence: value.1, result: value.2, historical: historical, caseURL: URL(fileURLWithPath: "/synthetic/case.nativecase"))
    }
    private func settle(_ store: TimelineWorkspaceStore) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while store.hasActiveWork {
            guard ContinuousClock.now < deadline else { throw TimelineTestFailure.timeout }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    @Test func buildsSelectedEvidenceAndFiltersAllEvents() async throws {
        let value = selection()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"))
        configure(store, value); store.loadFilesystem(); try await settle(store)
        #expect(store.report?.events.count == 2)
        #expect(store.binding?.evidenceID == value.1.id)
        store.query = "one.txt"; try await settle(store)
        #expect(store.rows.count == 1); #expect(store.rows.first?.fileID == "file")
        #expect(store.browserCandidates.map(\.id) == ["history"])
    }
    @Test func staleCompletionCannotReplaceNewEvidence() async throws {
        let value = selection(), gate = TimelineLoadGate()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), filesystemLoad: { caseID, evidence, result, historical in
            await gate.hold()
            return try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        })
        configure(store, value); store.loadFilesystem()
        try await gate.waitStarted()
        store.reset(); await gate.release(); try await settle(store)
        #expect(store.report == nil); #expect(store.rows.isEmpty); #expect(!store.hasSource)
    }
    @Test func shutdownDrainsOwnedWorkerAndDoesNotReopenOnReset() async throws {
        let value = selection(), gate = TimelineLoadGate()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), filesystemLoad: { caseID, evidence, result, historical in
            await gate.hold()
            return try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        })
        configure(store, value); store.loadFilesystem(); try await gate.waitStarted()
        let drain = store.beginShutdown()
        #expect(drain != nil); #expect(store.hasActiveWork)
        await gate.release(); await drain?.value
        #expect(!store.hasActiveWork); #expect(store.report == nil)
        store.reset(); configure(store, value); #expect(!store.canLoad)
    }
    @Test func malformedBrowserReceiptRejectedPriorReportRetained() async throws {
        let value = selection()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), browserLoad: { caseID, evidence, result, file in
            let binding = try TimelineSourceBinding.make(caseID: UUID(), evidence: evidence, result: result, historical: false)
            return BrowserTimelineResult(events: [], receipts: [], binding: binding)
        })
        configure(store, value); store.loadFilesystem(); try await settle(store)
        let original = store.report
        store.loadSelectedBrowserHistory(); try await settle(store)
        #expect(store.errorMessage != nil); #expect(store.report == original)
    }
    @Test func filtersCannotReduceExportAndCasePathIsForbidden() async throws {
        let value = selection(), capture = TimelineExportCapture()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), export: { report, output, forbidden in
            await capture.record(report, forbidden)
            return try await TimelineReportExporter.export(report, to: output, forbiddenURLs: forbidden)
        })
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.query = "one.txt"; try await settle(store); #expect(store.rows.count == 1)
        store.examinerNotes = "Examiner note"
        let output = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-store-\(UUID())")
        defer { try? FileManager.default.removeItem(at: output) }
        store.exportReport(to: output); try await settle(store)
        #expect(store.exportReceipt?.eventCount == 2)
        let captured = await capture.value
        #expect(captured?.0.events.count == 2)
        #expect(captured?.0.examinerNotes == "Examiner note")
        #expect(captured?.0.aiInterpretation == nil)
        #expect(captured?.1.contains(URL(fileURLWithPath: "/synthetic/case.nativecase")) == true)
    }
    @Test func oversizeNotesDoNotStartExporter() async throws {
        let value = selection()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"))
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.examinerNotes = String(repeating: "x", count: TimelineLimits.maximumNotesBytes + 1)
        store.exportReport(to: URL(fileURLWithPath: "/unused"))
        #expect(store.errorMessage != nil); #expect(!store.hasActiveWork)
    }
    @Test func visibleFilterCancellationDrainsAndCannotPublishRows() async throws {
        let value = selection()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"))
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.query = "one.txt"
        #expect(store.isFiltering)
        store.cancel(); try await settle(store)
        #expect(!store.isFiltering); #expect(store.rows.isEmpty)
        #expect(store.phase.contains("filtering canceled"))
        store.query = "History"; try await settle(store)
        #expect(store.rows.map(\.fileID) == ["history"])
    }
    @Test func timelineFolderPanelHasExplicitDirectoryEligibility() {
        let panel = CasePanelService.timelineReportParentPanel()
        #expect(panel.allowedContentTypes == [.folder])
        #expect(panel.canChooseDirectories)
        #expect(!panel.canChooseFiles)
        #expect(!panel.allowsMultipleSelection)
        #expect(panel.canCreateDirectories)
        #expect(!panel.treatsFilePackagesAsDirectories)
        #expect(!panel.resolvesAliases)
    }
    @Test func asynchronousFolderChoicePublishesCompleteReport() async throws {
        let value = selection()
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-chosen-parent-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: parent) }
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), chooseExportParent: { parent })
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.chooseExport()
        #expect(store.isPresentingPanel)
        try await settle(store)
        let receipt = try #require(store.exportReceipt)
        #expect(receipt.eventCount == 2)
        #expect(URL(fileURLWithPath: receipt.destinationPath).deletingLastPathComponent().path == parent.path)
        #expect(!store.isPresentingPanel)
        #expect(FileManager.default.fileExists(atPath: URL(fileURLWithPath: receipt.destinationPath).appendingPathComponent("timeline.json").path))
    }
    @Test func canceledFolderChoiceDrainsAndWritesNothing() async throws {
        let value = selection(), gate = TimelineFolderGate()
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-canceled-parent-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: parent) }
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), chooseExportParent: { await gate.hold() })
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.chooseExport(); try await gate.waitStarted()
        #expect(store.isPresentingPanel); #expect(store.hasActiveWork)
        store.cancel(); await gate.release(parent); try await settle(store)
        #expect(!store.isPresentingPanel); #expect(store.exportReceipt == nil)
        #expect(store.phase.contains("selection canceled"))
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
        #expect(store.canExport)
    }
    @Test func lateFolderChoiceAfterResetCannotPublishAndNewSelectionWorks() async throws {
        let value = selection(), gate = TimelineFolderGate()
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-stale-parent-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: parent) }
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), chooseExportParent: { await gate.hold() })
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.chooseExport(); try await gate.waitStarted()
        store.reset()
        #expect(!store.isPresentingPanel); #expect(store.hasActiveWork)
        configure(store, value)
        await gate.release(parent); try await settle(store)
        #expect(store.exportReceipt == nil); #expect(store.report == nil)
        #expect(!store.isPresentingPanel); #expect(store.canLoad)
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
        store.loadFilesystem(); try await settle(store)
        #expect(store.report?.events.count == 2)
    }
    @Test func shutdownDrainsPendingFolderChoiceWithoutPublication() async throws {
        let value = selection(), gate = TimelineFolderGate()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"), chooseExportParent: { await gate.hold() })
        configure(store, value); store.loadFilesystem(); try await settle(store)
        store.chooseExport(); try await gate.waitStarted()
        let drain = store.beginShutdown()
        #expect(drain != nil); #expect(store.hasActiveWork); #expect(!store.isPresentingPanel)
        await gate.release(nil); await drain?.value
        #expect(!store.hasActiveWork); #expect(!store.isPresentingPanel)
        #expect(store.exportReceipt == nil); #expect(!store.canLoad)
    }
    @Test func timelineViewConstructionDoesNotRequireLiveEngine() async throws {
        let value = selection()
        let store = TimelineWorkspaceStore(engineHelperURL: URL(fileURLWithPath: "/unused"))
        configure(store, value); store.loadFilesystem(); try await settle(store)
        _ = TimelineWorkspaceView(store: store, openFile: { _, _ in })
        #expect(store.rows.count == 2)
    }
}

private enum TimelineTestFailure: Error { case timeout }
private actor TimelineLoadGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var started = false
    func hold() async { started = true; await withCheckedContinuation { continuation = $0 } }
    func release() { continuation?.resume(); continuation = nil }
    func waitStarted() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !started { guard ContinuousClock.now < deadline else { throw TimelineTestFailure.timeout }; try await Task.sleep(for: .milliseconds(2)) }
    }
}
private actor TimelineExportCapture {
    var value: (TimelineReport, [URL])?
    func record(_ report: TimelineReport, _ forbidden: [URL]) { value = (report, forbidden) }
}

private actor TimelineFolderGate {
    private var continuation: CheckedContinuation<URL?, Never>?
    private var started = false
    func hold() async -> URL? { started = true; return await withCheckedContinuation { continuation = $0 } }
    func release(_ parent: URL?) { continuation?.resume(returning: parent); continuation = nil }
    func waitStarted() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !started { guard ContinuousClock.now < deadline else { throw TimelineTestFailure.timeout }; try await Task.sleep(for: .milliseconds(2)) }
    }
}
