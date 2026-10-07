import Foundation
import ForensicsCore
import Observation

struct CaseFindingDraft: Equatable, Sendable {
    var note = ""
    var bookmarked = false
    var tagsText = ""
    var reviewStatus: FindingReviewStatus = .unreviewed
    var reviewReason = ""

    init() {}
    init(record: FindingRecord) {
        note = record.note; bookmarked = record.bookmarked
        tagsText = record.tags.joined(separator: ", ")
        reviewStatus = record.reviewStatus; reviewReason = record.reviewReason
    }

    var tags: [String] {
        Array(Set(tagsText.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty })).sorted()
    }
    var byteCount: Int { note.utf8.count + tagsText.utf8.count + reviewReason.utf8.count }
}

/// Injectable asynchronous boundaries keep tests independent of wall-clock
/// timing. Production filesystem reads and publications run off MainActor.
struct CaseWorkWorkspaceServices: Sendable {
    var prepare: @Sendable (ForensicCase, EvidenceRecord, EnumerationResult, FilesystemEntry) async throws -> CaseWorkBinding = { forensicCase, evidence, result, file in
        try await worker { try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: file) }
    }
    var latestFinding: @Sendable (CaseWorkBinding, URL) async throws -> FindingRecord? = { binding, url in
        try await worker { try ForensicsCore.CaseWorkStore.latestFinding(binding: binding, in: url) }
    }
    var history: @Sendable (CaseWorkBinding, CaseWorkKind, CaseWorkCursor?, URL) async throws -> CaseWorkHistoryPage = { binding, kind, cursor, url in
        try await worker { try ForensicsCore.CaseWorkStore.history(binding: binding, kind: kind, cursor: cursor, limit: 50, in: url) }
    }
    var loadAnalysis: @Sendable (UUID, URL) async throws -> AnalysisRecord? = { id, url in
        try await worker { try ForensicsCore.CaseWorkStore.loadAnalysis(id: id, in: url) }
    }
    var loadFinding: @Sendable (UUID, URL) async throws -> FindingRecord? = { id, url in
        try await worker { try ForensicsCore.CaseWorkStore.loadFinding(id: id, in: url) }
    }
    var loadExtraction: @Sendable (UUID, URL) async throws -> ExtractionRecord? = { id, url in
        try await worker { try ForensicsCore.CaseWorkStore.loadExtraction(id: id, in: url) }
    }
    var saveFinding: @Sendable (FindingRecord, UUID?, URL) async throws -> Void = { record, expected, url in
        try await worker { try ForensicsCore.CaseWorkStore.saveFinding(record, expectedLatestRevisionID: expected, in: url) }
    }
    var saveExtraction: @Sendable (ExtractionRecord, URL) async throws -> Void = { record, url in
        try await worker { try ForensicsCore.CaseWorkStore.saveExtraction(record, in: url) }
    }

    private static func worker<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
        let task = Task.detached(priority: .userInitiated, operation: operation)
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
}

/// Selection-owned drafts and historical sidecars. Saving is explicit; a
/// pending immutable publication outlives selection changes and window close.
@MainActor
@Observable
final class CaseWorkWorkspaceStore {
    static let maximumUnsavedDrafts = 32
    static let maximumDraftBytes = 1_048_576

    var draft = CaseFindingDraft()
    private(set) var binding: CaseWorkBinding?
    private(set) var latestFinding: FindingRecord?
    private(set) var analysisPage: CaseWorkHistoryPage?
    private(set) var findingPage: CaseWorkHistoryPage?
    private(set) var extractionPage: CaseWorkHistoryPage?
    var selectedAnalysis: AnalysisRecord?
    var selectedFinding: FindingRecord?
    var selectedExtraction: ExtractionRecord?
    private(set) var isLoading = false
    private(set) var isLoadingHistory = false
    private(set) var isLoadingRecord = false
    private(set) var isSavingFinding = false
    private(set) var isClosing = false
    private(set) var activeOperationCount = 0
    private(set) var publicationCount = 0
    var errorMessage: String?
    private(set) var statusMessage = "Select a file to view notes and saved history."
    private(set) var revisionConflict = false

    private var selection: Selection?
    @ObservationIgnored private var generation = UUID()
    @ObservationIgnored private var drafts: [SelectionKey: SavedDraft] = [:]
    @ObservationIgnored private var baseline = CaseFindingDraft()
    @ObservationIgnored private var readTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var publicationTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private let services: CaseWorkWorkspaceServices
    @ObservationIgnored private(set) var loadTask: Task<Void, Never>?
    @ObservationIgnored private(set) var saveTask: Task<Void, Never>?

    init(services: CaseWorkWorkspaceServices = CaseWorkWorkspaceServices()) { self.services = services }

    var selectedFilePath: String { selection?.file.path ?? "" }
    var hasSelection: Bool { selection != nil }
    var hasUnsavedChanges: Bool { hasSelection && draft != baseline }
    var isWorking: Bool { activeOperationCount > 0 }
    var hasActiveWork: Bool { isWorking }
    var hasActivePublication: Bool { publicationCount > 0 }
    var canEdit: Bool { binding != nil && !isLoading && !isSavingFinding && !isClosing && !revisionConflict }
    var draftValidationMessage: String? {
        if draft.note.utf8.count > 65_536 { return "The note exceeds 64 KiB. Your draft is retained; shorten it before saving." }
        if draft.reviewReason.utf8.count > 8_192 { return "The review reason exceeds 8 KiB. Your draft is retained; shorten it before saving." }
        if draft.tags.count > 32 { return "Use at most 32 distinct tags. Your draft is retained." }
        if draft.tags.contains(where: { $0.utf8.count > 128 }) { return "Each tag supports at most 128 UTF-8 bytes. Your draft is retained." }
        return nil
    }
    var canSave: Bool { canEdit && hasUnsavedChanges && draftValidationMessage == nil && (draft.reviewStatus == .unreviewed || !draft.reviewReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) }
    var canChangeSelection: Bool {
        guard hasUnsavedChanges, let selection else { return !isClosing }
        let others = drafts.filter { $0.key != selection.key }
        return !isClosing && others.count < Self.maximumUnsavedDrafts
            && others.values.reduce(draft.byteCount, { $0 + $1.draft.byteCount }) <= Self.maximumDraftBytes
    }
    var retainedDraftCount: Int { drafts.count + (hasUnsavedChanges && selection.map { drafts[$0.key] == nil } == true ? 1 : 0) }
    var hasUnsavedDrafts: Bool { retainedDraftCount > 0 }

    /// Returns false when an oversized draft cannot be retained. The caller
    /// can restore its selection instead of silently abandoning that draft.
    @discardableResult
    func configure(forensicCase: ForensicCase, evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) -> Bool {
        guard !isClosing else { return false }
        let next = Selection(forensicCase: forensicCase, evidence: evidence, result: result, file: file)
        if selection?.key == next.key, selection?.result == next.result { return true }
        guard retainDraft() else { return false }
        invalidateReads()
        selection = next
        clearPresentation()
        if let retained = drafts[next.key] {
            draft = retained.draft; baseline = retained.baseline; latestFinding = retained.latest
        } else { draft = CaseFindingDraft(); baseline = draft; latestFinding = nil }
        refresh()
        return true
    }

    @discardableResult
    func reset() -> Bool {
        guard !isClosing, retainDraft() else { return false }
        invalidateReads(); selection = nil; clearPresentation()
        draft = CaseFindingDraft(); baseline = draft; latestFinding = nil
        statusMessage = "Select a file to view notes and saved history."
        return true
    }

    func refresh() {
        guard !isClosing, let selection else { return }
        invalidateReads()
        let token = generation
        isLoading = true; revisionConflict = false; errorMessage = nil
        let initialDraft = draft
        let initialBaseline = baseline
        let retainedRevision = latestFinding?.id
        let hadDraft = hasUnsavedChanges
        let services = services
        let jobID = UUID()
        startRead(jobID) { [weak self] in
            guard let self else { return }
            defer { self.finishRead(jobID) }
            do {
                let binding = try await services.prepare(selection.forensicCase, selection.evidence, selection.result, selection.file)
                let finding: FindingRecord?
                let findingError: String?
                do { finding = try await services.latestFinding(binding, selection.url); findingError = nil }
                catch is CancellationError { throw CancellationError() }
                catch { finding = nil; findingError = error.localizedDescription }
                async let analyses = services.history(binding, .analysis, nil, selection.url)
                async let findings = services.history(binding, .finding, nil, selection.url)
                async let extractions = services.history(binding, .extraction, nil, selection.url)
                let loaded = try await (analyses, findings, extractions)
                try Task.checkCancellation()
                guard self.generation == token, !self.isClosing else { return }
                self.binding = binding
                self.analysisPage = loaded.0; self.findingPage = loaded.1; self.extractionPage = loaded.2
                if let findingError {
                    self.revisionConflict = true
                    self.errorMessage = findingError
                } else if hadDraft || self.draft != initialDraft {
                    self.baseline = initialBaseline
                    self.revisionConflict = retainedRevision != finding?.id
                    if self.revisionConflict {
                        self.errorMessage = "This note changed in another window. Your draft is retained; discard and reload before saving."
                    }
                } else {
                    self.latestFinding = finding
                    self.draft = finding.map(CaseFindingDraft.init(record:)) ?? CaseFindingDraft()
                    self.baseline = self.draft
                    self.drafts[selection.key] = nil
                }
                self.isLoading = false
                self.statusMessage = "Historical case records · opening them does not reverify source bytes."
            } catch is CancellationError {
                if self.generation == token { self.isLoading = false }
            } catch {
                guard self.generation == token, !self.isClosing else { return }
                self.isLoading = false; self.binding = nil
                self.errorMessage = error.localizedDescription
            }
        }
    }

    func discardDraftAndReload() {
        guard !isClosing, !isSavingFinding, let selection else { return }
        drafts[selection.key] = nil
        draft = baseline
        refresh()
    }

    /// An explicit window/Quit discard decision clears ephemeral drafts only.
    /// It never saves notes, modifies case records or contacts a provider.
    func discardAllDrafts() {
        drafts.removeAll()
        draft = baseline
    }

    func saveFinding() {
        guard canSave, let selection, let binding else { return }
        let capturedDraft = draft
        let previous = latestFinding
        let token = generation
        do {
            let record = try previous.map {
                try $0.revised(note: capturedDraft.note, bookmarked: capturedDraft.bookmarked, tags: capturedDraft.tags,
                    reviewStatus: capturedDraft.reviewStatus, reviewReason: capturedDraft.reviewReason, binding: binding)
            } ?? FindingRecord.create(binding: binding, note: capturedDraft.note, bookmarked: capturedDraft.bookmarked,
                tags: capturedDraft.tags, reviewStatus: capturedDraft.reviewStatus, reviewReason: capturedDraft.reviewReason)
            isSavingFinding = true; errorMessage = nil
            let services = services
            let jobID = UUID()
            startPublication(jobID) { [weak self] in
                guard let self else { return }
                defer { self.isSavingFinding = false; self.finishPublication(jobID) }
                do {
                    try await services.saveFinding(record, previous?.id, selection.url)
                    let savedBaseline = CaseFindingDraft(record: record)
                    // A selection change must not move the completed revision
                    // into another file's editor or discard that file's draft.
                    self.drafts[selection.key] = nil
                    if self.selection?.key == selection.key {
                        self.latestFinding = record; self.baseline = savedBaseline
                        if self.draft == capturedDraft { self.draft = savedBaseline }
                    }
                    guard self.selection?.key == selection.key, !self.isClosing else { return }
                    // Navigation away and back can observe this job's commit
                    // before its owner finishes. Reload the actual latest
                    // revision instead of treating our own receipt as a
                    // conflict or replacing a newer external revision.
                    self.refresh()
                    if let pending = self.loadTask { await pending.value }
                    if self.selection?.key == selection.key, !self.isClosing, self.errorMessage == nil {
                        self.statusMessage = "Saved examiner note revision \(record.revision). AI answers remain advisory."
                    }
                } catch is CancellationError {
                    guard self.generation == token, !self.isClosing else { return }
                    self.statusMessage = "Note save cancelled before completion. Your draft is retained; reload history before retrying."
                } catch {
                    guard self.generation == token, !self.isClosing else { return }
                    self.errorMessage = error.localizedDescription
                    self.revisionConflict = (error as? CaseWorkError) == .staleRevision
                }
            }
        } catch { errorMessage = error.localizedDescription }
    }

    /// Called only after independently verified output publication. Capture
    /// the selection before any subsequent navigation or delayed work.
    func recordExtraction(receipt: ExtractionResult) {
        guard let selection else { return }
        recordExtraction(receipt: receipt, forensicCase: selection.forensicCase, evidence: selection.evidence,
            result: selection.result, file: selection.file)
    }

    /// Explicit captured inputs are required when the export began before a
    /// later selection change. Accepted work owns its original selection.
    func recordExtraction(receipt: ExtractionResult, forensicCase: ForensicCase,
        evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) {
        guard !isClosing else { return }
        let selection = Selection(forensicCase: forensicCase, evidence: evidence, result: result, file: file)
        let services = services
        let jobID = UUID()
        startPublication(jobID) { [weak self] in
            guard let self else { return }
            defer { self.finishPublication(jobID) }
            do {
                let binding = try await services.prepare(selection.forensicCase, selection.evidence, selection.result, selection.file)
                let record = try ExtractionRecord.make(binding: binding, receipt: receipt)
                try await services.saveExtraction(record, selection.url)
                guard self.selection?.key == selection.key, !self.isClosing else { return }
                self.statusMessage = "Recorded extraction history. The output path is not retained."
                self.loadHistory(kind: .extraction, cursor: nil)
            } catch {
                guard self.selection?.key == selection.key, !self.isClosing else { return }
                self.errorMessage = "The export succeeded, but recording its history did not complete: \(error.localizedDescription)"
            }
        }
    }

    func loadOlder(kind: CaseWorkKind) {
        guard let cursor = page(for: kind)?.nextCursor else { return }
        loadHistory(kind: kind, cursor: cursor)
    }

    func loadNewest(kind: CaseWorkKind) { loadHistory(kind: kind, cursor: nil) }

    func open(_ summary: CaseWorkSummary) {
        guard !isClosing, !isLoadingRecord, let selection, let binding else { return }
        let token = generation
        let services = services
        isLoadingRecord = true; errorMessage = nil
        let jobID = UUID()
        startRead(jobID) { [weak self] in
            guard let self else { return }
            defer { self.finishRead(jobID) }
            do {
                switch summary.kind {
                case .analysis:
                    let record = try await services.loadAnalysis(summary.id, selection.url)
                    try Task.checkCancellation()
                    guard self.generation == token, !self.isClosing else { return }
                    guard let record, binding.refersToSameFile(as: record.binding) else { throw CaseWorkError.scopeMismatch }
                    self.selectedAnalysis = record
                case .finding:
                    let record = try await services.loadFinding(summary.id, selection.url)
                    try Task.checkCancellation()
                    guard self.generation == token, !self.isClosing else { return }
                    guard let record, binding.refersToSameFile(as: record.binding) else { throw CaseWorkError.scopeMismatch }
                    self.selectedFinding = record
                case .extraction:
                    let record = try await services.loadExtraction(summary.id, selection.url)
                    try Task.checkCancellation()
                    guard self.generation == token, !self.isClosing else { return }
                    guard let record, binding.refersToSameFile(as: record.binding) else { throw CaseWorkError.scopeMismatch }
                    self.selectedExtraction = record
                }
                self.isLoadingRecord = false
            } catch is CancellationError {
                if self.generation == token { self.isLoadingRecord = false }
            } catch {
                guard self.generation == token, !self.isClosing else { return }
                self.isLoadingRecord = false; self.errorMessage = error.localizedDescription
            }
        }
    }

    /// Cancel lock waits and pre-publication work, then drain every owner. A
    /// save that already committed remains saved even if close arrives later.
    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        cancelPendingWork()
        let pending = Array(readTasks.values) + Array(publicationTasks.values)
        guard !pending.isEmpty else { return nil }
        return Task { for task in pending { await task.value } }
    }

    /// Global Cancel remains nonclosing. Ownership lasts through cleanup; a
    /// successful already-committed save can still reconcile and report saved.
    func cancelPendingWork() {
        readTasks.values.forEach { $0.cancel() }
        publicationTasks.values.forEach { $0.cancel() }
    }

    private func page(for kind: CaseWorkKind) -> CaseWorkHistoryPage? {
        switch kind { case .analysis: analysisPage; case .finding: findingPage; case .extraction: extractionPage }
    }

    private func loadHistory(kind: CaseWorkKind, cursor: CaseWorkCursor?) {
        guard !isClosing, !isLoadingHistory, let selection, let binding else { return }
        let token = generation
        let services = services
        isLoadingHistory = true
        let jobID = UUID()
        startRead(jobID) { [weak self] in
            guard let self else { return }
            defer { self.finishRead(jobID) }
            do {
                let page = try await services.history(binding, kind, cursor, selection.url)
                try Task.checkCancellation()
                guard self.generation == token, !self.isClosing else { return }
                switch kind { case .analysis: self.analysisPage = page; case .finding: self.findingPage = page; case .extraction: self.extractionPage = page }
                self.isLoadingHistory = false
            } catch is CancellationError {
                if self.generation == token { self.isLoadingHistory = false }
            } catch {
                guard self.generation == token, !self.isClosing else { return }
                self.isLoadingHistory = false; self.errorMessage = error.localizedDescription
            }
        }
    }

    private func retainDraft() -> Bool {
        guard let selection else { return true }
        guard hasUnsavedChanges else { drafts[selection.key] = nil; return true }
        guard canChangeSelection else {
            errorMessage = "Unsaved draft storage is full (32 files / 1 MiB). Save or explicitly discard this draft before leaving it."
            return false
        }
        drafts[selection.key] = SavedDraft(draft: draft, baseline: baseline, latest: latestFinding)
        return true
    }

    private func clearPresentation() {
        binding = nil; analysisPage = nil; findingPage = nil; extractionPage = nil
        selectedAnalysis = nil; selectedFinding = nil; selectedExtraction = nil
        isLoading = false; isLoadingHistory = false; isLoadingRecord = false
        errorMessage = nil; revisionConflict = false
    }

    private func invalidateReads() {
        generation = UUID()
        readTasks.values.forEach { $0.cancel() }
        isLoading = false; isLoadingHistory = false; isLoadingRecord = false
    }

    private func startRead(_ id: UUID, operation: @escaping @MainActor () async -> Void) {
        activeOperationCount += 1
        let task = Task(operation: operation)
        readTasks[id] = task; loadTask = task
    }
    private func finishRead(_ id: UUID) { if readTasks.removeValue(forKey: id) != nil { activeOperationCount -= 1 } }
    private func startPublication(_ id: UUID, operation: @escaping @MainActor () async -> Void) {
        activeOperationCount += 1
        publicationCount += 1
        let task = Task(operation: operation)
        publicationTasks[id] = task; saveTask = task
    }
    private func finishPublication(_ id: UUID) {
        if publicationTasks.removeValue(forKey: id) != nil { activeOperationCount -= 1; publicationCount -= 1 }
    }

    private struct SavedDraft { let draft: CaseFindingDraft; let baseline: CaseFindingDraft; let latest: FindingRecord? }
    private struct Selection: Sendable {
        let forensicCase: ForensicCase; let evidence: EvidenceRecord
        let result: EnumerationResult; let file: FilesystemEntry
        var url: URL { forensicCase.bundleURL }
        var key: SelectionKey { SelectionKey(caseID: forensicCase.manifest.id, evidenceID: evidence.id,
            id: file.id, path: file.path, offset: file.fsOffsetBytes, address: file.metaAddress,
            attributeType: file.attributeType, attributeID: file.attributeID) }
    }
    private struct SelectionKey: Hashable {
        let caseID: UUID; let evidenceID: UUID; let id: String; let path: String
        let offset: Int64; let address: UInt64; let attributeType: Int32?; let attributeID: Int32?
    }
}
