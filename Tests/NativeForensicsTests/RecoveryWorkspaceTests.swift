import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("RecoveryWorkspaceTests")
@MainActor
struct RecoveryWorkspaceTests {
    @Test("Unsupported filesystems can recover a RAW source and saved candidates stay separate from deletion claims")
    func rawWithoutFilesystem() async throws {
        let fixture = RecoveryUIFixture()
        let store = store(load: { _, _ in fixture.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        #expect(store.canRecover)
        #expect(store.result?.artifacts.count == 2)
        #expect(store.rows.allSatisfy { $0.deletionStatus == "unknown" })
        #expect(store.rows[0].formatHintScope == "PhotoRec recovery filename extension")
        #expect(store.analysis == nil)
        #expect(!store.hasActiveWork)
        let ewf = EvidenceRecord(sourcePath: "/synthetic/source.E01", byteCount: 10,
            sha256: fixture.evidence.sha256, container: .ewf, filesystemHint: nil)
        store.configure(evidence: ewf, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        #expect(!store.canRecover)
        #expect(store.recoveryUnavailableReason == RecoveryError.unsupportedSource.localizedDescription)
    }

    @Test("A foreign evidence receipt is rejected before recovered candidates populate the table")
    func scopeMismatch() async throws {
        let fixture = RecoveryUIFixture()
        let foreign = RecoveryUIFixture()
        let store = store(load: { _, _ in foreign.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        #expect(store.result == nil)
        #expect(store.rows.isEmpty)
        #expect(store.errorMessage == RecoveryError.scopeMismatch.localizedDescription)
    }

    @Test("Changing evidence retains and drains the old owner; stale receipts cannot publish over the new source")
    func sourceReplacement() async throws {
        let first = RecoveryUIFixture()
        let second = RecoveryUIFixture()
        let gate = RecoveryResultGate()
        let store = store(load: { evidence, _ in try await gate.load(evidence.id) })
        store.configure(evidence: first.evidence, in: first.forensicCase)
        let firstTask = try #require(store.activeTask)
        let firstRequest = await gate.nextRequest()
        store.configure(evidence: second.evidence, in: second.forensicCase)
        let secondTask = try #require(store.activeTask)
        #expect(store.hasActiveWork)
        #expect(store.result == nil)
        #expect(await gate.callCount == 1)
        await gate.succeed(firstRequest, first.result)
        await firstTask.value
        let secondRequest = await gate.nextRequest()
        #expect(secondRequest.evidenceID == second.evidence.id)
        await gate.succeed(secondRequest, second.result)
        await secondTask.value
        await store.examination.waitForPendingWork()
        #expect(store.result == second.result)
        #expect(store.rows == second.result.artifacts)
        #expect(!store.hasActiveWork)
    }

    @Test("Literal filename/hash filters search all candidates and superseded queries clear invisible selection")
    func filterGeneration() async throws {
        let fixture = RecoveryUIFixture()
        let store = store(load: { _, _ in fixture.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        store.selectedArtifactID = fixture.result.artifacts[0].id
        store.searchText = "image"
        let first = try #require(store.filterTask)
        store.searchText = "หลักฐาน"
        store.formatFilter = "pdf"
        let latest = try #require(store.filterTask)
        await first.value
        await latest.value
        #expect(store.rows == [fixture.result.artifacts[1]])
        #expect(store.selectedArtifactID == nil)
        #expect(store.analysis == nil)
        #expect(!store.hasActiveWork)
    }

    @Test("Decoder responses must match selected recovered bytes; a suffix never establishes decoded content")
    func decoderIntegrity() async throws {
        let fixture = RecoveryUIFixture()
        let store = store(load: { _, _ in fixture.result }, analyze: { artifact, _, _, _ in
            DocumentAnalysis(contentKind: .image, mimeType: "image/jpeg", status: .decoded,
                sourceSHA256: String(repeating: "f", count: 64), sourceByteCount: artifact.byteCount,
                pixelWidth: 10, pixelHeight: 10)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        store.selectedArtifactID = fixture.result.artifacts[0].id
        #expect(store.canPreview)
        store.previewSelected()
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        #expect(store.analysis == nil)
        #expect(store.errorMessage == DocumentAnalysisError.integrityMismatch.localizedDescription)
        #expect(store.selectedArtifact?.deletionStatus == "unknown")
    }

    @Test("Preview selection and shutdown drain canceled decoder owners and discard their delayed answer")
    func previewShutdown() async throws {
        let fixture = RecoveryUIFixture()
        let gate = RecoveryAnalysisGate()
        let store = store(load: { _, _ in fixture.result }, analyze: { artifact, _, _, _ in
            try await gate.load(artifact.id)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        let artifact = fixture.result.artifacts[0]
        store.selectedArtifactID = artifact.id
        store.previewSelected()
        let request = await gate.nextRequest()
        store.selectedArtifactID = fixture.result.artifacts[1].id
        #expect(store.analysis == nil)
        #expect(store.hasActiveWork)
        let drain = try #require(store.beginShutdown())
        #expect(!store.canPreview)
        await gate.succeed(request, DocumentAnalysis(contentKind: .image, mimeType: "image/jpeg", status: .unsupported,
            sourceSHA256: artifact.sha256, sourceByteCount: artifact.byteCount))
        await drain.value
        #expect(!store.hasActiveWork)
        #expect(store.analysis == nil)
    }

    @Test("Canceling recovery preserves the previous receipt and waits for the process owner before close")
    func canceledRecovery() async throws {
        let fixture = RecoveryUIFixture()
        let gate = RecoveryResultGate()
        let store = store(load: { _, _ in fixture.result }, recover: { evidence, _, _, _ in
            try await gate.load(evidence.id)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        store.beginRecovery()
        let request = await gate.nextRequest()
        #expect(store.isRecovering)
        store.cancel()
        #expect(store.hasActiveWork)
        #expect(store.result == fixture.result)
        let drain = try #require(store.beginShutdown())
        await gate.succeed(request, fixture.result)
        await drain.value
        #expect(!store.hasActiveWork)
        #expect(store.result == fixture.result)
    }

    @Test("Recovered-file navigation respects oversized note drafts")
    func notesGuard() async throws {
        let fixture = RecoveryUIFixture()
        let store = store(load: { _, _ in fixture.result })
        let workspace = WorkspaceStore(recovery: store)
        workspace.currentCase = fixture.forensicCase
        workspace.selectedEvidenceID = fixture.evidence.id
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        workspace.showRecoveredFiles()
        #expect(workspace.section == .recovery)
        #expect(workspace.navigationSelection == .recovery)
        workspace.section = .evidence
        let file = FilesystemEntry(id: "oversized-note", path: "/notes.txt", name: "notes.txt", fsOffsetBytes: 0,
            metaAddress: 1, size: 4, isDirectory: false, isDeleted: false)
        let filesystem = EnumerationResult(engineVersion: "synthetic", patchDigest: "synthetic", sourcePaths: [fixture.evidence.sourcePath],
            sourceFileHashes: [fixture.evidence.sourcePath: fixture.evidence.sha256], options: EngineOptions(),
            image: EngineImageMetadata(imageType: "raw", logicalSize: fixture.evidence.byteCount, sectorSize: 512),
            volumes: [], files: [file], warnings: [], status: .completed)
        workspace.caseWork.configure(forensicCase: fixture.forensicCase, evidence: fixture.evidence, result: filesystem, file: file)
        if let pending = workspace.caseWork.loadTask { await pending.value }
        workspace.caseWork.draft.note = String(repeating: "x", count: CaseWorkWorkspaceStore.maximumDraftBytes + 1)
        #expect(!workspace.caseWork.canChangeSelection)
        workspace.showRecoveredFiles()
        #expect(workspace.section == .evidence)
        #expect(!workspace.canRecoverFiles)
        #expect(workspace.caseWork.draft.note.utf8.count == CaseWorkWorkspaceStore.maximumDraftBytes + 1)
        await workspace.shutdown()
        #expect(!workspace.hasActiveWork)
    }

    @Test("Recovery notes retain per-file drafts and reject oversized selection changes without losing text")
    func recoveryNotesGuard() async throws {
        let fixture = RecoveryUIFixture()
        let store = store(load: { _, _ in fixture.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        let first = fixture.result.artifacts[0], second = fixture.result.artifacts[1]
        store.selectedArtifactID = first.id
        store.examination.note = "ผู้ตรวจอ่านไฟล์แล้ว"
        store.examination.assessment = .accessible
        store.selectedArtifactID = second.id
        #expect(store.examination.note.isEmpty)
        #expect(store.retainedDraftCount == 1)
        store.selectedArtifactID = first.id
        #expect(store.examination.note == "ผู้ตรวจอ่านไฟล์แล้ว")
        #expect(store.examination.assessment == .accessible)
        let oversized = String(repeating: "x", count: 8_193)
        store.examination.note = oversized
        store.selectedArtifactID = second.id
        #expect(store.selectedArtifactID == first.id)
        #expect(store.examination.note == oversized)
        #expect(!store.canChangeSelection)
        #expect(!store.canRecover)
        store.discardAllDrafts()
        #expect(store.retainedDraftCount == 0)
        #expect(store.canChangeSelection)
        #expect(store.examination.assessment == .notReviewed)
    }

    @Test("Explicit examiner assessment save survives a new workspace without implying decoded content")
    func examinerSaveReopen() async throws {
        let fixture = RecoveryUIFixture()
        let persistence = RecoveryNotesPersistence()
        func examination() -> RecoveryExaminationStore {
            RecoveryExaminationStore(loadAnnotations: { result, _ in await persistence.load(result.jobID) },
                saveAnnotation: { value, result, _ in await persistence.save(value, jobID: result.jobID) })
        }
        let store = RecoveryWorkspaceStore(photoRecURL: URL(fileURLWithPath: "/usr/bin/true"),
            documentHelperURL: URL(fileURLWithPath: "/usr/bin/true"), load: { _, _ in fixture.result }, examination: examination())
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        await store.examination.waitForPendingWork()
        let artifact = fixture.result.artifacts[0]
        store.selectedArtifactID = artifact.id
        store.examination.note = "Opened externally and checked image dimensions."
        store.examination.assessment = .accessible
        #expect(store.examination.canSaveAnnotation)
        store.examination.saveAnnotation()
        await store.examination.waitForPendingWork()
        #expect(store.retainedDraftCount == 0)
        #expect(store.analysis == nil)
        let reopened = RecoveryWorkspaceStore(photoRecURL: URL(fileURLWithPath: "/usr/bin/true"),
            documentHelperURL: URL(fileURLWithPath: "/usr/bin/true"), load: { _, _ in fixture.result }, examination: examination())
        reopened.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(reopened.activeTask)).value
        await reopened.examination.waitForPendingWork()
        reopened.selectedArtifactID = artifact.id
        #expect(reopened.examination.assessment == .accessible)
        #expect(reopened.examination.note == "Opened externally and checked image dimensions.")
        #expect(!reopened.examination.hasUnsavedChanges)
        #expect(reopened.analysis == nil)
        #expect(reopened.selectedArtifact?.deletionStatus == "unknown")
    }

    private func store(load: @escaping RecoveryWorkspaceStore.Load,
                       recover: RecoveryWorkspaceStore.Recover? = nil,
                       analyze: RecoveryWorkspaceStore.Analyze? = nil) -> RecoveryWorkspaceStore {
        RecoveryWorkspaceStore(photoRecURL: URL(fileURLWithPath: "/usr/bin/true"),
            documentHelperURL: URL(fileURLWithPath: "/usr/bin/true"), load: load, recover: recover, analyze: analyze,
            examination: RecoveryExaminationStore(loadAnnotations: { _, _ in [:] }))
    }
}

private struct RecoveryUIFixture: Sendable {
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let result: CarvingResult
    init() {
        let caseID = UUID()
        evidence = EvidenceRecord(sourcePath: "/synthetic/whole.raw", byteCount: 4096,
            sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
        forensicCase = ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/\(caseID).nativecase"),
            manifest: CaseManifest(id: caseID, name: "Synthetic Recovery", evidence: [evidence]))
        let imageID = UUID(), documentID = UUID()
        let image = CarvedArtifact(id: imageID, filename: "image.jpg", relativePath: "files/\(imageID.uuidString.lowercased())",
            formatHint: "jpg", byteCount: 100, sha256: String(repeating: "b", count: 64),
            reportedByteRuns: [], verifiedByteRuns: [], validationStatus: .unverified)
        let document = CarvedArtifact(id: documentID, filename: "หลักฐาน.pdf", relativePath: "files/\(documentID.uuidString.lowercased())",
            formatHint: "pdf", byteCount: 100, sha256: String(repeating: "c", count: 64),
            reportedByteRuns: [RecoveryByteRun(outputOffset: 0, sourceOffset: 1024, length: 100)],
            verifiedByteRuns: [RecoveryByteRun(outputOffset: 0, sourceOffset: 1024, length: 100)], validationStatus: .sourceBytesVerified)
        result = CarvingResult(caseID: caseID, sourceEvidenceID: evidence.id, sourceSHA256: evidence.sha256,
            sourceByteCount: evidence.byteCount, status: .completed, artifacts: [image, document], warnings: [],
            photoRecVersion: "synthetic-test", executableSHA256: String(repeating: "d", count: 64), options: RecoveryOptions())
    }
}

private actor RecoveryResultGate {
    struct Request: Sendable { let id: UUID; let evidenceID: UUID }
    private var queued: [Request] = []
    private var waiting: [CheckedContinuation<Request, Never>] = []
    private var responses: [UUID: CheckedContinuation<CarvingResult, Error>] = [:]
    private(set) var callCount = 0
    func load(_ evidenceID: UUID) async throws -> CarvingResult {
        callCount += 1
        let request = Request(id: UUID(), evidenceID: evidenceID)
        return try await withCheckedThrowingContinuation { continuation in
            responses[request.id] = continuation
            if waiting.isEmpty { queued.append(request) } else { waiting.removeFirst().resume(returning: request) }
        }
    }
    func nextRequest() async -> Request {
        if !queued.isEmpty { return queued.removeFirst() }
        return await withCheckedContinuation { waiting.append($0) }
    }
    func succeed(_ request: Request, _ value: CarvingResult) { responses.removeValue(forKey: request.id)?.resume(returning: value) }
}

private actor RecoveryAnalysisGate {
    struct Request: Sendable { let id: UUID; let artifactID: UUID }
    private var queued: [Request] = []
    private var waiting: [CheckedContinuation<Request, Never>] = []
    private var responses: [UUID: CheckedContinuation<DocumentAnalysis, Error>] = [:]
    func load(_ artifactID: UUID) async throws -> DocumentAnalysis {
        let request = Request(id: UUID(), artifactID: artifactID)
        return try await withCheckedThrowingContinuation { continuation in
            responses[request.id] = continuation
            if waiting.isEmpty { queued.append(request) } else { waiting.removeFirst().resume(returning: request) }
        }
    }
    func nextRequest() async -> Request {
        if !queued.isEmpty { return queued.removeFirst() }
        return await withCheckedContinuation { waiting.append($0) }
    }
    func succeed(_ request: Request, _ value: DocumentAnalysis) { responses.removeValue(forKey: request.id)?.resume(returning: value) }
}

private actor RecoveryNotesPersistence {
    private var values: [UUID: [UUID: RecoveryAnnotation]] = [:]
    func load(_ jobID: UUID) -> [UUID: RecoveryAnnotation] { values[jobID] ?? [:] }
    func save(_ value: RecoveryAnnotation, jobID: UUID) { values[jobID, default: [:]][value.artifactID] = value }
}
