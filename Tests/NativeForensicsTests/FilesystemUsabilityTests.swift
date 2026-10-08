import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("Filesystem assignment usability")
@MainActor
struct FilesystemUsabilityTests {
    @Test("Document preview remains explicit and accepts a detected type different from its filename")
    func explicitDocumentPreview() async throws {
        let fixture = UsabilityFixture(name: "misleading.jpg")
        let gate = UsabilityGate<FilesystemDocumentPreview>()
        let store = FilesystemDocumentPreviewStore(engineHelperURL: fixture.helper,
            load: { _, _, _ in try await gate.request() }, scheduler: ForensicWorkScheduler())
        store.configure(evidence: fixture.evidence, result: fixture.analysis, file: fixture.file)
        #expect(await gate.calls == 0)
        #expect(store.canLoad && store.preview == nil)
        store.load()
        let task = try #require(store.loadTask)
        await gate.next()
        await gate.succeed(fixture.preview())
        await task.value
        #expect(store.preview?.file.name == "misleading.jpg")
        #expect(store.analysis?.mimeType == "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        #expect(store.errorMessage == nil && !store.hasActiveWork)
    }

    @Test("Selection replacement waits for old preview ownership and rejects its stale result")
    func stalePreviewDrains() async throws {
        let first = UsabilityFixture(id: "first"), second = UsabilityFixture(id: "second")
        let gate = UsabilityGate<FilesystemDocumentPreview>()
        let store = FilesystemDocumentPreviewStore(engineHelperURL: first.helper,
            load: { _, _, _ in try await gate.request() }, scheduler: ForensicWorkScheduler())
        store.configure(evidence: first.evidence, result: first.analysis, file: first.file)
        store.load()
        let oldTask = try #require(store.loadTask)
        await gate.next()
        store.configure(evidence: second.evidence, result: second.analysis, file: second.file)
        store.load()
        let nextTask = try #require(store.loadTask)
        #expect(store.preview == nil && store.hasActiveWork)
        #expect(await gate.calls == 1)
        await gate.succeed(first.preview())
        await oldTask.value
        await gate.next()
        #expect(await gate.calls == 2)
        #expect(store.preview == nil)
        await gate.succeed(second.preview())
        await nextTask.value
        #expect(store.preview?.file.id == "second")
        #expect(!store.hasActiveWork)
    }

    @Test("Wrong document identity and shutdown results cannot populate the selected inspector")
    func mismatchedAndShutdownPreviews() async throws {
        let fixture = UsabilityFixture(), foreign = UsabilityFixture(id: "foreign")
        let gate = UsabilityGate<FilesystemDocumentPreview>()
        let store = FilesystemDocumentPreviewStore(engineHelperURL: fixture.helper,
            load: { _, _, _ in try await gate.request() }, scheduler: ForensicWorkScheduler())
        store.configure(evidence: fixture.evidence, result: fixture.analysis, file: fixture.file)
        store.load(); let task = try #require(store.loadTask)
        await gate.next(); await gate.succeed(foreign.preview()); await task.value
        #expect(store.preview == nil)
        #expect(store.errorMessage == VerifiedContentError.extractedContentMismatch.localizedDescription)
        store.load(); await gate.next()
        let drain = try #require(store.beginShutdown())
        #expect(store.hasActiveWork && !store.canLoad)
        await gate.succeed(fixture.preview()); await drain.value
        #expect(store.preview == nil && !store.hasActiveWork)
    }

    @Test("Document preview can exceed byte-preview size while its own 128 MiB bound remains explicit")
    func separatePreviewLimit() {
        let small = UsabilityFixture(size: 2 * 1_024 * 1_024)
        let store = FilesystemDocumentPreviewStore(engineHelperURL: small.helper,
            load: { _, _, _ in throw CancellationError() }, scheduler: ForensicWorkScheduler())
        store.configure(evidence: small.evidence, result: small.analysis, file: small.file)
        #expect(store.canLoad)
        let tooLarge = UsabilityFixture(size: DocumentLimits.maximumInputBytes + 1)
        store.configure(evidence: tooLarge.evidence, result: tooLarge.analysis, file: tooLarge.file)
        #expect(!store.canLoad)
        #expect(store.unavailableReason?.contains("128 MiB") == true)
    }

    @Test("Batch eligibility excludes engine rows while preserving real dollar filenames and deleted aliases")
    func eligibleFiles() {
        func file(_ path: String, directory: Bool = false) -> FilesystemEntry {
            FilesystemEntry(id: path, path: path, name: String(path.split(separator: "/").last ?? ""),
                fsOffsetBytes: 0, metaAddress: 1, size: 0, isDirectory: directory, isDeleted: true)
        }
        let legitimate = [file("/$Budget.txt"), file("/notes/$MBR"), file("/deleted/original.jpg")]
        let excluded = [file("/$MBR"), file("/$FAT1"), file("/$FAT2"), file("/directory", directory: true),
                        file("/LABEL (Volume Label Entry)")]
        #expect(FilesystemBatchExportStore.eligibleFiles(in: legitimate + excluded) == legitimate)
    }

    @Test("Batch count uses every filtered match rather than the visible 100-row table page")
    func allMatchedCount() {
        let fixture = UsabilityFixture()
        let workspace = WorkspaceStore(helperURL: fixture.helper, scheduler: ForensicWorkScheduler())
        workspace.currentCase = ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/case.nfcase"),
            manifest: CaseManifest(name: "Synthetic export count", evidence: [fixture.evidence]))
        workspace.filesystemResults[fixture.evidence.id] = fixture.analysis
        workspace.selectedEvidenceID = fixture.evidence.id
        let files = (0..<1_001).map { index in
            FilesystemEntry(id: String(index), path: "/\(index).bin", name: "\(index).bin",
                fsOffsetBytes: 0, metaAddress: UInt64(index + 1), size: 1, isDirectory: false, isDeleted: true)
        }
        workspace.filesystemRows = files
        #expect(workspace.matchingExportableFiles.count == 1_001)
        #expect(!workspace.canExtractAllMatched)
        workspace.filesystemRows = Array(files.prefix(999))
        #expect(workspace.matchingExportableFiles.count == 999)
        #expect(workspace.canExtractAllMatched)
    }

    @Test("Canceling an unpublished replacement batch keeps the previous published receipt")
    func batchCancellationPreservesReceipt() async throws {
        let fixture = UsabilityFixture()
        let gate = UsabilityGate<FilesystemBatchExportResult>()
        let store = FilesystemBatchExportStore(engineHelperURL: fixture.helper,
            export: { _, _, _, _, _ in try await gate.request() }, scheduler: ForensicWorkScheduler())
        let firstDestination = URL(fileURLWithPath: "/synthetic/export-one")
        store.start(analysis: fixture.analysis, files: [fixture.file], destination: firstDestination,
                    caseURL: URL(fileURLWithPath: "/synthetic/case.nfcase"))
        let task = try #require(store.exportTask)
        await gate.next(); await gate.succeed(fixture.batch(at: firstDestination)); await task.value
        let previous = try #require(store.result)
        store.start(analysis: fixture.analysis, files: [fixture.file], destination: URL(fileURLWithPath: "/synthetic/export-two"),
                    caseURL: URL(fileURLWithPath: "/synthetic/case.nfcase"))
        let cancelled = try #require(store.exportTask)
        await gate.next(); store.cancel()
        #expect(store.hasActiveWork)
        await gate.fail(CancellationError()); await cancelled.value
        #expect(store.result == previous)
        #expect(!store.hasActiveWork)
        #expect(store.statusMessage.contains("prior exports were preserved"))
    }

    @Test("Batch response from another selection is rejected and close drains the owner")
    func batchMismatchAndShutdown() async throws {
        let fixture = UsabilityFixture(), foreign = UsabilityFixture(id: "foreign")
        let gate = UsabilityGate<FilesystemBatchExportResult>()
        let store = FilesystemBatchExportStore(engineHelperURL: fixture.helper,
            export: { _, _, _, _, _ in try await gate.request() }, scheduler: ForensicWorkScheduler())
        let destination = URL(fileURLWithPath: "/synthetic/export")
        store.start(analysis: fixture.analysis, files: [fixture.file], destination: destination,
                    caseURL: URL(fileURLWithPath: "/synthetic/case.nfcase"))
        let task = try #require(store.exportTask)
        await gate.next(); await gate.succeed(foreign.batch(at: destination)); await task.value
        #expect(store.result == nil && store.errorMessage != nil)
        store.start(analysis: fixture.analysis, files: [fixture.file], destination: destination,
                    caseURL: URL(fileURLWithPath: "/synthetic/case.nfcase"))
        await gate.next()
        let drain = try #require(store.beginShutdown())
        #expect(store.hasActiveWork)
        await gate.fail(CancellationError()); await drain.value
        #expect(!store.hasActiveWork && store.result == nil)
    }
}

private actor UsabilityGate<Value: Sendable> {
    private(set) var calls = 0
    private var continuation: CheckedContinuation<Value, Error>?
    private var waiter: CheckedContinuation<Void, Never>?
    private var ready = false
    func request() async throws -> Value {
        calls += 1
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            if let waiter { self.waiter = nil; waiter.resume() } else { ready = true }
        }
    }
    func next() async {
        if ready { ready = false; return }
        await withCheckedContinuation { waiter = $0 }
    }
    func succeed(_ value: Value) { let response = continuation; continuation = nil; response?.resume(returning: value) }
    func fail(_ error: any Error) { let response = continuation; continuation = nil; response?.resume(throwing: error) }
}

private struct UsabilityFixture {
    let evidence: EvidenceRecord
    let file: FilesystemEntry
    let analysis: EnumerationResult
    let helper = URL(fileURLWithPath: "/synthetic/helper")
    private let payloadHash = String(repeating: "a", count: 64)

    init(id: String = "document", name: String = "document.docx", size: Int64 = 17) {
        let source = "/synthetic/image.dd", hash = String(repeating: "b", count: 64)
        evidence = EvidenceRecord(sourcePath: source, byteCount: 5, sha256: hash, container: .raw, filesystemHint: nil)
        file = FilesystemEntry(id: id, path: "/\(name)", name: name, fsOffsetBytes: 0,
            metaAddress: 1, size: size, isDirectory: false, isDeleted: true)
        analysis = EnumerationResult(engineVersion: "fixture", patchDigest: "synthetic-only", sourcePaths: [source],
            sourceFileHashes: [source: hash], options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 5, sectorSize: 512),
            volumes: [], files: [file], warnings: [], status: .completed)
    }

    func preview() -> FilesystemDocumentPreview {
        FilesystemDocumentPreview(file: file, receipt: VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id,
            byteCount: file.size, sha256: payloadHash, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]),
            analysis: DocumentAnalysis(contentKind: .office,
                mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", status: .decoded,
                sourceSHA256: payloadHash, sourceByteCount: file.size, officeFormat: .docx, contentUnitCount: 1,
                structuralValidation: .validated, textPages: [DocumentTextPage(pageNumber: 1, text: "Readable document",
                    referenceLabel: "Document body", referenceKind: .document)]))
    }

    func batch(at destination: URL) -> FilesystemBatchExportResult {
        FilesystemBatchExportResult(destinationPath: destination.path,
            manifestPath: destination.appendingPathComponent("manifest.json").path, status: .completed,
            entries: [.init(sourceFile: file, outputFilename: "0001-\(file.name)", byteCount: file.size,
                            sha256: payloadHash, errorMessage: nil)])
    }
}
