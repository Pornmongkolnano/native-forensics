import Foundation
@testable import ForensicsCore
import Observation
import Testing
@testable import NativeForensics

/// Parent controls derive their disabled/progress state from hasActiveWork.
/// Exercise Observation's notifications rather than merely reading its value
/// after an async operation: the old ignored dictionaries passed those reads.
@Suite("WorkspaceWorkObservationTests")
@MainActor
struct WorkspaceWorkObservationTests {
    @Test("Recovery metadata ownership notifies parent controls on start and final drain")
    func recoveryOwnership() async throws {
        let fixture = WorkObservationFixture()
        let gate = WorkObservationGate<CarvingResult?>()
        let store = RecoveryWorkspaceStore(photoRecURL: fixture.helper,
            load: { _, _ in try await gate.request() },
            examination: RecoveryExaminationStore(loadAnnotations: { _, _ in [:] }))
        let start = WorkObservationChanges()
        #expect(!observe({ store.hasActiveWork }, changes: start))
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        #expect(start.count == 1)
        await gate.waitForRequest()
        let task = try #require(store.activeTask)
        let drain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: drain))
        await gate.succeed(nil)
        await task.value
        #expect(drain.count == 1)
        #expect(!store.hasActiveWork)
    }

    @Test("Recovery examination jobs independently notify nested parent controls after completion")
    func examinationOwnership() async throws {
        let fixture = WorkObservationFixture()
        let gate = WorkObservationGate<[UUID: RecoveryAnnotation]>()
        let store = RecoveryExaminationStore(loadAnnotations: { _, _ in try await gate.request() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        let start = WorkObservationChanges()
        #expect(!observe({ store.hasActiveWork }, changes: start))
        store.configure(result: fixture.carving)
        #expect(start.count == 1)
        await gate.waitForRequest()
        let drain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: drain))
        await gate.succeed([:])
        await store.waitForPendingWork()
        #expect(drain.count == 1)
        #expect(!store.hasActiveWork)
        #expect(store.canExportReport)
    }

    @Test("A parent recovery subscription can rearm from its own owner to pending examination cleanup")
    func nestedRecoveryDrain() async throws {
        let fixture = WorkObservationFixture()
        let load = WorkObservationGate<CarvingResult?>()
        let notes = WorkObservationGate<[UUID: RecoveryAnnotation]>()
        let store = RecoveryWorkspaceStore(photoRecURL: fixture.helper,
            load: { _, _ in try await load.request() },
            examination: RecoveryExaminationStore(loadAnnotations: { _, _ in try await notes.request() }))
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await load.waitForRequest()
        let ownTask = try #require(store.activeTask)
        let ownDrain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: ownDrain))
        await load.succeed(fixture.carving)
        await ownTask.value
        await notes.waitForRequest()
        #expect(ownDrain.count == 1)
        #expect(store.hasActiveWork)
        #expect(!store.canRecover)
        let nestedDrain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: nestedDrain))
        await notes.succeed([:])
        await store.examination.waitForPendingWork()
        #expect(nestedDrain.count == 1)
        #expect(!store.hasActiveWork)
        #expect(store.canRecover)
        #expect(store.examination.canExportReport)
    }

    @Test("Optical ownership notifies start and final drain even when loaded metadata is empty")
    func opticalOwnership() async throws {
        let fixture = WorkObservationFixture()
        let gate = WorkObservationGate<UDFInspectionResult?>()
        let store = OpticalWorkspaceStore(load: { _, _ in try await gate.request() })
        let start = WorkObservationChanges()
        #expect(!observe({ store.hasActiveWork }, changes: start))
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        #expect(start.count == 1)
        await gate.waitForRequest()
        let task = try #require(store.activeTask)
        let drain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: drain))
        await gate.succeed(nil)
        await task.value
        #expect(drain.count == 1)
        #expect(!store.hasActiveWork)
        #expect(store.canInspect)
    }

    @Test("Filesystem document ownership notifies on explicit start and canceled shutdown drain")
    func documentOwnership() async throws {
        let fixture = WorkObservationFixture()
        let gate = WorkObservationGate<FilesystemDocumentPreview>()
        let store = FilesystemDocumentPreviewStore(engineHelperURL: fixture.helper,
            load: { _, _, _ in try await gate.request() })
        store.configure(evidence: fixture.evidence, result: fixture.filesystem, file: fixture.file)
        let start = WorkObservationChanges()
        #expect(!observe({ store.hasActiveWork }, changes: start))
        store.load()
        #expect(start.count == 1)
        await gate.waitForRequest()
        let drain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: drain))
        let shutdown = try #require(store.beginShutdown())
        #expect(store.hasActiveWork)
        await gate.succeed(fixture.document)
        await shutdown.value
        #expect(drain.count == 1)
        #expect(!store.hasActiveWork)
        #expect(store.analysis == nil)
    }

    @Test("Filesystem batch ownership notifies parent controls after the published receipt's final drain")
    func batchOwnership() async throws {
        let fixture = WorkObservationFixture()
        let gate = WorkObservationGate<FilesystemBatchExportResult>()
        let store = FilesystemBatchExportStore(engineHelperURL: fixture.helper,
            export: { _, _, _, _, _ in try await gate.request() })
        let destination = URL(fileURLWithPath: "/synthetic/observed-batch")
        let start = WorkObservationChanges()
        #expect(!observe({ store.hasActiveWork }, changes: start))
        store.start(analysis: fixture.filesystem, files: [fixture.file], destination: destination,
            caseURL: fixture.forensicCase.bundleURL)
        #expect(start.count == 1)
        await gate.waitForRequest()
        let task = try #require(store.exportTask)
        let drain = WorkObservationChanges()
        #expect(observe({ store.hasActiveWork }, changes: drain))
        await gate.succeed(fixture.batch(destination))
        await task.value
        #expect(drain.count == 1)
        #expect(!store.hasActiveWork)
        #expect(store.result?.successfulCount == 1)
    }

    private func observe(_ value: () -> Bool, changes: WorkObservationChanges) -> Bool {
        withObservationTracking { value() } onChange: { changes.record() }
    }
}

private final class WorkObservationChanges: @unchecked Sendable {
    private let lock = NSLock()
    private var notifications = 0
    var count: Int { lock.withLock { notifications } }
    func record() { lock.withLock { notifications += 1 } }
}

/// Requests intentionally ignore cancellation until their owner is released,
/// allowing a deterministic Observation check at the retained cleanup boundary.
private actor WorkObservationGate<Value: Sendable> {
    private var response: CheckedContinuation<Value, Error>?
    private var waiter: CheckedContinuation<Void, Never>?
    func request() async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            response = continuation
            waiter?.resume()
            waiter = nil
        }
    }
    func waitForRequest() async {
        if response != nil { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func succeed(_ value: Value) { response?.resume(returning: value); response = nil }
}

private struct WorkObservationFixture: Sendable {
    let helper = URL(fileURLWithPath: "/usr/bin/true")
    let evidence: EvidenceRecord
    let forensicCase: ForensicCase
    let file: FilesystemEntry
    let filesystem: EnumerationResult
    let carving: CarvingResult
    let document: FilesystemDocumentPreview
    init() {
        let source = "/synthetic/observation.raw", sourceHash = String(repeating: "a", count: 64)
        let payloadHash = String(repeating: "b", count: 64)
        evidence = EvidenceRecord(sourcePath: source, byteCount: 4096, sha256: sourceHash, container: .raw, filesystemHint: nil)
        forensicCase = ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/Observation.nativecase"),
            manifest: CaseManifest(name: "Synthetic Work Observation", evidence: [evidence]))
        file = FilesystemEntry(id: "document", path: "/document.txt", name: "document.txt", fsOffsetBytes: 0,
            metaAddress: 2, size: 12, isDirectory: false, isDeleted: false)
        filesystem = EnumerationResult(engineVersion: "synthetic", patchDigest: "synthetic", sourcePaths: [source],
            sourceFileHashes: [source: sourceHash], options: EngineOptions(),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 4096, sectorSize: 512), volumes: [], files: [file], warnings: [], status: .completed)
        carving = CarvingResult(caseID: forensicCase.manifest.id, sourceEvidenceID: evidence.id, sourceSHA256: sourceHash,
            sourceByteCount: evidence.byteCount, status: .completed, artifacts: [], warnings: [],
            photoRecVersion: "synthetic", executableSHA256: String(repeating: "c", count: 64), options: RecoveryOptions())
        let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id, byteCount: file.size,
            sha256: payloadHash, verifiedAt: Date(), orderedContainerSHA256: [sourceHash])
        document = FilesystemDocumentPreview(file: file, receipt: receipt,
            analysis: DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
                sourceSHA256: payloadHash, sourceByteCount: file.size, textPages: [DocumentTextPage(pageNumber: 1, text: "fixture text")]))
    }
    func batch(_ destination: URL) -> FilesystemBatchExportResult {
        FilesystemBatchExportResult(destinationPath: destination.path,
            manifestPath: destination.appendingPathComponent("manifest.json").path,
            status: .completed, entries: [FilesystemBatchExportEntry(sourceFile: file, outputFilename: "document.txt",
                byteCount: file.size, sha256: document.receipt.sha256, errorMessage: nil)],
            sourcePaths: filesystem.sourcePaths, sourceFileHashes: filesystem.sourceFileHashes)
    }
}
