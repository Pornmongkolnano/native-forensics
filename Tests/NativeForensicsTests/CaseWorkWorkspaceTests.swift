import CryptoKit
import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("CaseWorkWorkspaceTests")
@MainActor
struct CaseWorkWorkspaceTests {
    @Test("Explicit note save survives reopen and appends review-safe revisions without source writes")
    func noteSaveReopen() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let binding = try #require(store.binding)
        #expect(try CaseWorkStore.latestFinding(binding: binding, in: fixture.forensicCase.bundleURL) == nil)
        store.draft.note = "บันทึกผู้ตรวจ · **literal**"
        store.draft.bookmarked = true
        store.draft.tagsText = "Thai, review, Thai"
        store.draft.reviewStatus = .verified
        #expect(!store.canSave)
        store.draft.reviewReason = "Compared the recorded fields locally."
        #expect(store.canSave)
        store.saveFinding()
        await (try #require(store.saveTask)).value
        let first = try #require(store.latestFinding)
        #expect(first.revision == 1)
        #expect(first.tags == ["Thai", "review"])
        #expect(!store.hasUnsavedChanges)
        #expect(first.reviewStatus == .verified)

        let reopened = CaseWorkWorkspaceStore()
        try await configure(reopened, fixture, file: fixture.files[0])
        #expect(reopened.draft.note == first.note)
        #expect(reopened.draft.bookmarked)
        #expect(reopened.draft.reviewStatus == .verified)
        reopened.draft.note = "Second revision"
        reopened.draft.reviewStatus = .unreviewed
        reopened.draft.reviewReason = ""
        reopened.saveFinding()
        await (try #require(reopened.saveTask)).value
        let second = try #require(reopened.latestFinding)
        #expect(second.revision == 2)
        #expect(second.previousRevisionID == first.id)
        #expect(try CaseWorkStore.loadFinding(id: first.id, in: fixture.forensicCase.bundleURL) == first)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: fixture.forensicCase.bundleURL.appendingPathComponent("manifest.json")) == fixture.manifestBytes)
    }

    @Test("Switching files retains unsaved drafts and saves only the captured file")
    func draftsStayWithTheirFiles() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let firstBinding = try #require(store.binding)
        store.draft.note = "First unsaved note"
        try await configure(store, fixture, file: fixture.files[1])
        #expect(store.draft.note.isEmpty)
        store.draft.note = "Second saved note"
        store.saveFinding()
        await (try #require(store.saveTask)).value
        let secondBinding = try #require(store.binding)
        #expect(try CaseWorkStore.latestFinding(binding: firstBinding, in: fixture.forensicCase.bundleURL) == nil)
        #expect(try CaseWorkStore.latestFinding(binding: secondBinding, in: fixture.forensicCase.bundleURL)?.note == "Second saved note")
        try await configure(store, fixture, file: fixture.files[0])
        #expect(store.draft.note == "First unsaved note")
        #expect(store.hasUnsavedChanges)
        store.saveFinding()
        await (try #require(store.saveTask)).value
        #expect(store.latestFinding?.binding.refersToSameFile(as: firstBinding) == true)
        #expect(store.latestFinding?.note == "First unsaved note")
        #expect(store.retainedDraftCount == 0)
    }

    @Test("Late background selection preparation cannot replace a newer file or its editor")
    func stalePreparationDiscarded() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let gate = CaseWorkBindingGate()
        var services = CaseWorkWorkspaceServices()
        let realPrepare = services.prepare
        services.prepare = { forensicCase, evidence, result, file in
            let binding = try await realPrepare(forensicCase, evidence, result, file)
            if file.id == fixture.files[0].id { return await gate.hold(binding) }
            return binding
        }
        let store = CaseWorkWorkspaceStore(services: services)
        store.configure(forensicCase: fixture.forensicCase, evidence: fixture.evidence,
            result: fixture.enumeration, file: fixture.files[0])
        let oldTask = try #require(store.loadTask)
        await gate.waitUntilHeld()
        try await configure(store, fixture, file: fixture.files[1])
        store.draft.note = "New selection draft"
        await gate.release()
        await oldTask.value
        #expect(store.selectedFilePath == fixture.files[1].path)
        #expect(store.binding?.selectedEntry.id == fixture.files[1].id)
        #expect(store.draft.note == "New selection draft")
        #expect(!store.isLoading)
    }

    @Test("A delayed saved-analysis detail cannot populate another selection")
    func staleDetailDiscarded() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let analysis = try fixture.analysis(file: fixture.files[0])
        try CaseWorkStore.saveAnalysis(analysis, in: fixture.forensicCase.bundleURL)
        let gate = CaseWorkAnalysisGate()
        var services = CaseWorkWorkspaceServices()
        services.loadAnalysis = { _, _ in await gate.hold(analysis) }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        let summary = try #require(store.analysisPage?.items.first)
        store.open(summary)
        let oldTask = try #require(store.loadTask)
        await gate.waitUntilHeld()
        try await configure(store, fixture, file: fixture.files[1])
        await gate.release()
        await oldTask.value
        #expect(store.selectedAnalysis == nil)
        #expect(store.analysisPage?.items.isEmpty == true)
        #expect(!store.isLoadingRecord)
    }

    @Test("Close drains an already-committed save, rejects new actions, and keeps the committed revision")
    func committedSaveDrainsOnShutdown() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let gate = CaseWorkPublicationGate()
        var services = CaseWorkWorkspaceServices()
        services.saveFinding = { record, expected, url in
            try await gate.saveAndHold(record: record, expected: expected, url: url)
        }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        store.draft.note = "Publication completed before close"
        store.saveFinding()
        let record = await gate.waitUntilPublished()
        #expect(store.hasActivePublication)
        let shutdown = try #require(store.beginShutdown())
        #expect(!store.canEdit)
        #expect(!store.configure(forensicCase: fixture.forensicCase, evidence: fixture.evidence,
            result: fixture.enumeration, file: fixture.files[1]))
        store.saveFinding()
        #expect(store.hasActiveWork)
        await gate.release()
        await shutdown.value
        #expect(!store.hasActiveWork)
        #expect(!store.hasActivePublication)
        #expect(store.latestFinding?.id == record.id)
        #expect(!store.hasUnsavedChanges)
        #expect(try CaseWorkStore.loadFinding(id: record.id, in: fixture.forensicCase.bundleURL) == record)
    }

    @Test("Returning to a file before its committed save finishes reconciles its own revision")
    func saveReentryDoesNotConflictWithItself() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let gate = CaseWorkPublicationGate()
        var services = CaseWorkWorkspaceServices()
        services.saveFinding = { record, expected, url in
            try await gate.saveAndHold(record: record, expected: expected, url: url)
        }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        store.draft.note = "Owned save before reentry"
        store.saveFinding()
        let pending = try #require(store.saveTask)
        let saved = await gate.waitUntilPublished()
        try await configure(store, fixture, file: fixture.files[1])
        try await configure(store, fixture, file: fixture.files[0])
        #expect(store.revisionConflict)
        await gate.release()
        await pending.value
        #expect(store.latestFinding?.id == saved.id)
        #expect(store.draft.note == saved.note)
        #expect(!store.hasUnsavedChanges)
        #expect(!store.revisionConflict)
        #expect(store.errorMessage == nil)
        #expect(store.canEdit)
        #expect(!store.hasActivePublication)
    }

    @Test("Save reconciliation loads an externally newer revision rather than replacing it with its own receipt")
    func saveReentryPreservesNewerExternalRevision() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let gate = CaseWorkPublicationGate()
        var services = CaseWorkWorkspaceServices()
        services.saveFinding = { record, expected, url in
            try await gate.saveAndHold(record: record, expected: expected, url: url)
        }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        store.draft.note = "Owned save"
        store.saveFinding()
        let pending = try #require(store.saveTask)
        let saved = await gate.waitUntilPublished()
        let newer = try saved.revised(note: "Newer external revision", bookmarked: false, tags: [],
            reviewStatus: .unreviewed, reviewReason: "")
        try CaseWorkStore.saveFinding(newer, expectedLatestRevisionID: saved.id, in: fixture.forensicCase.bundleURL)
        try await configure(store, fixture, file: fixture.files[1])
        try await configure(store, fixture, file: fixture.files[0])
        await gate.release()
        await pending.value
        #expect(store.latestFinding?.id == newer.id)
        #expect(store.draft.note == newer.note)
        #expect(!store.revisionConflict)
        #expect(store.canEdit)
        #expect(try CaseWorkStore.loadFinding(id: saved.id, in: fixture.forensicCase.bundleURL) == saved)
    }

    @Test("An old precommit reload cannot restore an empty baseline after save reconciliation")
    func stalePrecommitBaselineCannotOverwriteSavedNote() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let publicationGate = CaseWorkBeforePublicationGate()
        let historyGate = CaseWorkHistoryGate()
        var services = CaseWorkWorkspaceServices()
        let realHistory = services.history
        services.history = { binding, kind, cursor, url in
            let page = try await realHistory(binding, kind, cursor, url)
            if binding.selectedEntry.id == fixture.files[0].id, kind == .analysis {
                await historyGate.holdOnceIfArmed()
            }
            return page
        }
        services.saveFinding = { record, expected, url in
            await publicationGate.hold()
            try CaseWorkStore.saveFinding(record, expectedLatestRevisionID: expected, in: url)
        }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        store.draft.note = "Do not revert the committed baseline"
        store.saveFinding()
        let publication = try #require(store.saveTask)
        await publicationGate.waitUntilHeld()
        try await configure(store, fixture, file: fixture.files[1])
        await historyGate.arm()
        #expect(store.configure(forensicCase: fixture.forensicCase, evidence: fixture.evidence,
            result: fixture.enumeration, file: fixture.files[0]))
        let oldReload = try #require(store.loadTask)
        await historyGate.waitUntilHeld()
        await publicationGate.release()
        await publication.value
        #expect(store.canEdit)
        #expect(!store.hasUnsavedChanges)
        let savedID = try #require(store.latestFinding?.id)
        await historyGate.release()
        await oldReload.value
        #expect(store.latestFinding?.id == savedID)
        #expect(store.draft.note == "Do not revert the committed baseline")
        #expect(!store.hasUnsavedChanges)
        #expect(!store.revisionConflict)
        #expect(store.canEdit)
    }

    @Test("Global Cancel drains precommit work without closing or discarding the note draft")
    func globalCancelBeforePublication() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let gate = CaseWorkBeforePublicationGate()
        var services = CaseWorkWorkspaceServices()
        services.saveFinding = { record, expected, url in
            await gate.hold()
            try Task.checkCancellation()
            try CaseWorkStore.saveFinding(record, expectedLatestRevisionID: expected, in: url)
        }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        let binding = try #require(store.binding)
        store.draft.note = "Retain the cancelled draft"
        store.saveFinding()
        let pending = try #require(store.saveTask)
        await gate.waitUntilHeld()
        store.cancelPendingWork()
        #expect(!store.isClosing)
        #expect(store.hasActivePublication)
        await gate.release()
        await pending.value
        #expect(!store.hasActiveWork)
        #expect(store.canEdit)
        #expect(store.canSave)
        #expect(store.draft.note == "Retain the cancelled draft")
        #expect(store.statusMessage.contains("cancelled"))
        #expect(!store.statusMessage.contains("Saved"))
        #expect(try CaseWorkStore.latestFinding(binding: binding, in: fixture.forensicCase.bundleURL) == nil)
    }

    @Test("Global Cancel after atomic publication retains the revision and reports the successful save")
    func globalCancelAfterPublication() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let gate = CaseWorkPublicationGate()
        var services = CaseWorkWorkspaceServices()
        services.saveFinding = { record, expected, url in
            try await gate.saveAndHold(record: record, expected: expected, url: url)
        }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        store.draft.note = "Committed before global cancel"
        store.saveFinding()
        let pending = try #require(store.saveTask)
        let saved = await gate.waitUntilPublished()
        store.cancelPendingWork()
        #expect(!store.isClosing)
        #expect(store.hasActiveWork)
        await gate.release()
        await pending.value
        #expect(!store.hasActiveWork)
        #expect(store.latestFinding?.id == saved.id)
        #expect(!store.hasUnsavedChanges)
        #expect(store.canEdit)
        #expect(store.statusMessage.contains("Saved examiner note"))
    }

    @Test("A failed publication preserves the draft for explicit retry")
    func saveFailureRetainsDraft() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        var services = CaseWorkWorkspaceServices()
        services.saveFinding = { _, _, _ in throw CaseWorkError.sizeLimit }
        let store = CaseWorkWorkspaceStore(services: services)
        try await configure(store, fixture, file: fixture.files[0])
        let binding = try #require(store.binding)
        store.draft.note = "Do not lose this draft"
        store.saveFinding()
        await (try #require(store.saveTask)).value
        #expect(store.hasUnsavedChanges)
        #expect(store.draft.note == "Do not lose this draft")
        #expect(store.errorMessage == CaseWorkError.sizeLimit.localizedDescription)
        #expect(store.latestFinding == nil)
        #expect(try CaseWorkStore.latestFinding(binding: binding, in: fixture.forensicCase.bundleURL) == nil)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Concurrent note changes require explicit discard and reload before another revision")
    func staleRevisionRequiresReload() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let binding = try #require(store.binding)
        store.draft.note = "My retained draft"
        let elsewhere = try FindingRecord.create(binding: binding, note: "Another window saved this")
        try CaseWorkStore.saveFinding(elsewhere, expectedLatestRevisionID: nil, in: fixture.forensicCase.bundleURL)
        store.saveFinding()
        await (try #require(store.saveTask)).value
        #expect(store.revisionConflict)
        #expect(!store.canSave)
        #expect(store.draft.note == "My retained draft")
        store.refresh()
        await (try #require(store.loadTask)).value
        #expect(store.revisionConflict)
        #expect(store.draft.note == "My retained draft")
        store.discardDraftAndReload()
        await (try #require(store.loadTask)).value
        #expect(!store.revisionConflict)
        #expect(store.draft.note == elsewhere.note)
        #expect(store.latestFinding?.id == elsewhere.id)
        #expect(!store.hasUnsavedChanges)
    }

    @Test("Draft storage cap rejects navigation until an explicit discard, without evicting other drafts")
    func draftStorageBounded() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make(fileCount: 34)
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        for index in 0..<33 {
            try await configure(store, fixture, file: fixture.files[index])
            store.draft.note = "Retained draft \(index)"
        }
        #expect(!store.canChangeSelection)
        #expect(store.retainedDraftCount == 33)
        #expect(!store.configure(forensicCase: fixture.forensicCase, evidence: fixture.evidence,
            result: fixture.enumeration, file: fixture.files[33]))
        #expect(store.selectedFilePath == fixture.files[32].path)
        #expect(store.draft.note == "Retained draft 32")
        store.discardDraftAndReload()
        await (try #require(store.loadTask)).value
        #expect(store.canChangeSelection)
        try await configure(store, fixture, file: fixture.files[0])
        #expect(store.draft.note == "Retained draft 0")
    }

    @Test("An extraction receipt is saved for its captured selection without retaining a host output path")
    func extractionHistoryBinding() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let originalBinding = try #require(store.binding)
        let outputPath = fixture.directory.appendingPathComponent("not-retained.txt").path
        try await configure(store, fixture, file: fixture.files[1])
        store.recordExtraction(receipt: ExtractionResult(outputPath: outputPath, byteCount: 3,
            sha256: CaseWorkWorkspaceFixture.hash(fixture.sourceBytes)), forensicCase: fixture.forensicCase,
            evidence: fixture.evidence, result: fixture.enumeration, file: fixture.files[0])
        let publication = try #require(store.saveTask)
        await publication.value
        let page = try CaseWorkStore.history(binding: originalBinding, kind: .extraction, in: fixture.forensicCase.bundleURL)
        let summary = try #require(page.items.first)
        let receipt = try #require(try CaseWorkStore.loadExtraction(id: summary.id, in: fixture.forensicCase.bundleURL))
        #expect(receipt.binding.refersToSameFile(as: originalBinding))
        #expect(receipt.outputHash.scope == "extracted-file-bytes")
        let data = try Data(contentsOf: fixture.forensicCase.bundleURL.appendingPathComponent("extractions/\(receipt.id.uuidString.lowercased()).json"))
        #expect(!String(decoding: data, as: UTF8.self).contains(outputPath))
        #expect(store.selectedFilePath == fixture.files[1].path)
        #expect(store.selectedExtraction == nil)
    }

    @Test("History replaces bounded 50-record pages instead of accumulating every case record")
    func historyPagingBounded() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        for _ in 0..<53 {
            try CaseWorkStore.saveAnalysis(fixture.analysis(file: fixture.files[0]), in: fixture.forensicCase.bundleURL)
        }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let newest = try #require(store.analysisPage)
        #expect(newest.items.count == 50)
        #expect(newest.nextCursor != nil)
        store.loadOlder(kind: .analysis)
        await (try #require(store.loadTask)).value
        let older = try #require(store.analysisPage)
        #expect(older.items.count == 3)
        #expect(older.nextCursor == nil)
        #expect(Set(newest.items.map(\.id)).isDisjoint(with: Set(older.items.map(\.id))))
        store.loadNewest(kind: .analysis)
        await (try #require(store.loadTask)).value
        #expect(store.analysisPage?.items.map(\.id) == newest.items.map(\.id))
    }

    @Test("Corrupt note history blocks revisions but preserves analysis browsing and explicit diagnostics")
    func corruptNoteHistoryDoesNotHideAnalysis() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let analysis = try fixture.analysis(file: fixture.files[0])
        try CaseWorkStore.saveAnalysis(analysis, in: fixture.forensicCase.bundleURL)
        let findingDirectory = fixture.forensicCase.bundleURL.appendingPathComponent("findings")
        try FileManager.default.createDirectory(at: findingDirectory, withIntermediateDirectories: false)
        let corrupt = findingDirectory.appendingPathComponent("\(UUID().uuidString.lowercased()).json")
        let corruptBytes = Data("{not a supported record}".utf8)
        try corruptBytes.write(to: corrupt)
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        #expect(!store.canEdit)
        #expect(store.revisionConflict)
        #expect(store.errorMessage == CaseWorkError.historyUnavailable.localizedDescription)
        #expect(store.findingPage?.totalDiagnosticCount == 1)
        #expect(store.analysisPage?.items.map(\.id) == [analysis.id])
        store.open(try #require(store.analysisPage?.items.first))
        await (try #require(store.loadTask)).value
        #expect(store.selectedAnalysis?.id == analysis.id)
        #expect(try Data(contentsOf: corrupt) == corruptBytes)
    }

    @Test("Oversized editable fields remain intact with a validation error and cannot publish")
    func oversizedDraftValidation() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let binding = try #require(store.binding)
        let oversized = String(repeating: "x", count: 65_537)
        store.draft.note = oversized
        #expect(!store.canSave)
        #expect(store.draftValidationMessage?.contains("64 KiB") == true)
        store.saveFinding()
        #expect(store.saveTask == nil)
        #expect(store.draft.note == oversized)
        store.draft.note = "Corrected note"
        store.draft.reviewReason = String(repeating: "x", count: 8_193)
        #expect(!store.canSave)
        #expect(store.draftValidationMessage?.contains("8 KiB") == true)
        store.draft.reviewReason = ""
        store.draft.tagsText = (0..<33).map { "tag\($0)" }.joined(separator: ",")
        #expect(!store.canSave)
        #expect(store.draftValidationMessage?.contains("32") == true)
        store.draft.tagsText = String(repeating: "x", count: 129)
        #expect(!store.canSave)
        #expect(store.draftValidationMessage?.contains("128") == true)
        #expect(store.draft.tagsText.utf8.count == 129)
        store.draft.tagsText = "valid"
        #expect(store.canSave)
        #expect(try CaseWorkStore.latestFinding(binding: binding, in: fixture.forensicCase.bundleURL) == nil)
    }

    @Test("Explicit discard-all clears retained window drafts without writing case records")
    func explicitDiscardAllDrafts() async throws {
        let fixture = try await CaseWorkWorkspaceFixture.make()
        defer { fixture.remove() }
        let store = CaseWorkWorkspaceStore()
        try await configure(store, fixture, file: fixture.files[0])
        let firstBinding = try #require(store.binding)
        store.draft.note = "First draft"
        try await configure(store, fixture, file: fixture.files[1])
        store.draft.note = "Second draft"
        #expect(store.hasUnsavedDrafts)
        #expect(store.retainedDraftCount == 2)
        store.discardAllDrafts()
        #expect(!store.hasUnsavedDrafts)
        #expect(!store.hasUnsavedChanges)
        #expect(store.draft.note.isEmpty)
        #expect(store.saveTask == nil)
        #expect(try CaseWorkStore.latestFinding(binding: firstBinding, in: fixture.forensicCase.bundleURL) == nil)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    private func configure(_ store: CaseWorkWorkspaceStore, _ fixture: CaseWorkWorkspaceFixture, file: FilesystemEntry) async throws {
        #expect(store.configure(forensicCase: fixture.forensicCase, evidence: fixture.evidence, result: fixture.enumeration, file: file))
        await (try #require(store.loadTask)).value
        _ = try #require(store.binding)
        #expect(!store.isLoading)
    }
}

private struct CaseWorkWorkspaceFixture: Sendable {
    let directory: URL
    let source: URL
    let sourceBytes: Data
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let files: [FilesystemEntry]
    let enumeration: EnumerationResult
    let manifestBytes: Data

    static func make(fileCount: Int = 2) async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("CaseWorkWorkspace-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let source = directory.appendingPathComponent("synthetic.raw")
        let bytes = Data("abc".utf8)
        try bytes.write(to: source)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspected, to: CaseStore.create(name: "Synthetic", in: directory))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let files = (0..<fileCount).map { index in
            FilesystemEntry(id: "synthetic-\(index)", path: "/NOTE\(index).txt", name: "NOTE\(index).txt",
                fsOffsetBytes: 0, metaAddress: UInt64(10 + index), size: 3, isDirectory: false, isDeleted: false)
        }
        let enumeration = EnumerationResult(engineVersion: "synthetic-case-work-test", patchDigest: "synthetic-case-work-test",
            sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512, imagePaths: [source.path]),
            volumes: [], files: files, warnings: [], status: .completed, savedAt: Date(timeIntervalSince1970: 1_700_000_000))
        return Self(directory: directory, source: source, sourceBytes: bytes, forensicCase: forensicCase,
            evidence: evidence, files: files, enumeration: enumeration,
            manifestBytes: try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json")))
    }

    func analysis(file: FilesystemEntry) throws -> AnalysisRecord {
        let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: enumeration, file: file)
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: enumeration, file: file)
        let question = "Synthetic history question"
        let prompt = try AssistantPrompt.make(context: context, question: question)
        let response = CodexAnalysisResponse(summary: "Literal **text**", observations: ["Recorded metadata"],
            hypotheses: [], limitations: ["Metadata only"], nextSteps: ["Inspect locally"])
        let result = CodexAnalysisResult(response: response, requestSHA256: Self.hash(Data(prompt.utf8)), completedAt: Date())
        return try AnalysisRecord.make(binding: binding, context: context, prompt: prompt, question: question,
            result: result, retention: .digestOnly)
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}

private actor CaseWorkBindingGate {
    private var continuation: CheckedContinuation<CaseWorkBinding, Never>?
    private var binding: CaseWorkBinding?
    private var waiter: CheckedContinuation<Void, Never>?
    func hold(_ binding: CaseWorkBinding) async -> CaseWorkBinding {
        self.binding = binding
        return await withCheckedContinuation { continuation in
            self.continuation = continuation; waiter?.resume(); waiter = nil
        }
    }
    func waitUntilHeld() async { if continuation == nil { await withCheckedContinuation { waiter = $0 } } }
    func release() { if let binding { continuation?.resume(returning: binding); continuation = nil } }
}

private actor CaseWorkAnalysisGate {
    private var continuation: CheckedContinuation<AnalysisRecord?, Never>?
    private var record: AnalysisRecord?
    private var waiter: CheckedContinuation<Void, Never>?
    func hold(_ record: AnalysisRecord) async -> AnalysisRecord? {
        self.record = record
        return await withCheckedContinuation { continuation in
            self.continuation = continuation; waiter?.resume(); waiter = nil
        }
    }
    func waitUntilHeld() async { if continuation == nil { await withCheckedContinuation { waiter = $0 } } }
    func release() { continuation?.resume(returning: record); continuation = nil }
}

private actor CaseWorkPublicationGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var record: FindingRecord?
    private var waiter: CheckedContinuation<FindingRecord, Never>?
    func saveAndHold(record: FindingRecord, expected: UUID?, url: URL) async throws {
        try CaseWorkStore.saveFinding(record, expectedLatestRevisionID: expected, in: url)
        self.record = record
        await withCheckedContinuation { continuation in
            self.continuation = continuation; waiter?.resume(returning: record); waiter = nil
        }
    }
    func waitUntilPublished() async -> FindingRecord {
        if let record { return record }
        return await withCheckedContinuation { waiter = $0 }
    }
    func release() { continuation?.resume(); continuation = nil }
}

private actor CaseWorkBeforePublicationGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var waiter: CheckedContinuation<Void, Never>?
    func hold() async {
        await withCheckedContinuation { continuation in
            self.continuation = continuation; waiter?.resume(); waiter = nil
        }
    }
    func waitUntilHeld() async { if continuation == nil { await withCheckedContinuation { waiter = $0 } } }
    func release() { continuation?.resume(); continuation = nil }
}

private actor CaseWorkHistoryGate {
    private var armed = false
    private var continuation: CheckedContinuation<Void, Never>?
    private var waiter: CheckedContinuation<Void, Never>?
    func arm() { armed = true }
    func holdOnceIfArmed() async {
        guard armed else { return }
        armed = false
        await withCheckedContinuation { continuation in
            self.continuation = continuation; waiter?.resume(); waiter = nil
        }
    }
    func waitUntilHeld() async { if continuation == nil { await withCheckedContinuation { waiter = $0 } } }
    func release() { continuation?.resume(); continuation = nil }
}
