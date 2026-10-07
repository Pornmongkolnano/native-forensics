import Foundation
import ForensicsCore
import Observation

/// Raw image ranges and examiner assessments are explicitly separate from
/// recovered file decoding. Notes never rewrite recovery or evidence receipts.
@MainActor
@Observable
final class RecoveryExaminationStore {
    typealias LoadAnnotations = @Sendable (CarvingResult, URL) async throws -> [UUID: RecoveryAnnotation]
    typealias SaveAnnotation = @Sendable (RecoveryAnnotation, CarvingResult, URL) async throws -> Void
    var rawOffsetText = "0"
    private(set) var rawSnapshot: RawEvidenceHexSnapshot?
    private(set) var isReadingRaw = false
    private(set) var isLoading = false
    private(set) var isSaving = false
    private(set) var isExportingReport = false
    var errorMessage: String?
    private(set) var statusMessage = "Inspect RAW ranges or record an examiner assessment."
    var assessment: RecoveryAssessment = .notReviewed
    var note = ""
    private(set) var annotations: [UUID: RecoveryAnnotation] = [:]
    private(set) var analyses: [UUID: DocumentAnalysis] = [:]
    private(set) var reportURL: URL?

    @ObservationIgnored private let loadAnnotations: LoadAnnotations
    @ObservationIgnored private let saveAnnotationRequest: SaveAnnotation
    @ObservationIgnored private var analysisOrder: [UUID] = []

    init(loadAnnotations: LoadAnnotations? = nil, saveAnnotation: SaveAnnotation? = nil) {
        self.loadAnnotations = loadAnnotations ?? { result, caseURL in try RecoveryAnnotationStore.latest(result: result, in: caseURL) }
        self.saveAnnotationRequest = saveAnnotation ?? { value, result, caseURL in
            _ = try RecoveryAnnotationStore.save(annotation: value, result: result, in: caseURL)
        }
    }

    @ObservationIgnored private var evidence: EvidenceRecord?
    @ObservationIgnored private var forensicCase: ForensicCase?
    @ObservationIgnored private var result: CarvingResult?
    @ObservationIgnored private var artifactID: UUID?
    @ObservationIgnored private var generation = UUID()
    @ObservationIgnored private var baseline: RecoveryAnnotation?
    @ObservationIgnored private var drafts: [DraftKey: RecoveryAnnotation] = [:]
    // hasActiveWork is rendered by parent views. Observe owner insertion and
    // final drain, including canceled owners retained for cleanup.
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var isClosing = false

    var hasActiveWork: Bool { !jobs.isEmpty }
    var hasUnsavedChanges: Bool {
        guard let artifactID else { return false }
        let saved = baseline ?? RecoveryAnnotation(artifactID: artifactID)
        return assessment != saved.assessment || note != saved.note
    }
    var retainedDraftCount: Int { drafts.count + (hasUnsavedChanges && currentDraftKey.map { drafts[$0] == nil } == true ? 1 : 0) }
    var canChangeSelection: Bool {
        let otherCount = drafts.count - (currentDraftKey.map { drafts[$0] != nil } == true ? 1 : 0)
        return !isClosing && (!hasUnsavedChanges || (note.utf8.count <= 8_192 && otherCount < 64))
    }
    var noteValidationMessage: String? {
        note.utf8.count > 8_192 ? "The examiner note exceeds 8 KiB. Shorten or discard the draft before changing selection." :
            note.contains("\0") ? "Examiner notes cannot contain NUL bytes." : nil
    }
    var canSaveAnnotation: Bool {
        artifactID != nil && result != nil && forensicCase != nil && hasUnsavedChanges && noteValidationMessage == nil
            && !hasActiveWork && !isClosing
    }
    var canReadRaw: Bool { evidence?.container == .raw && !hasActiveWork && !isClosing && parsedOffset != nil }
    var canExportReport: Bool { result != nil && forensicCase != nil && !hasActiveWork && !isClosing }
    var parsedOffset: Int64? {
        let value = rawOffsetText.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("0x") || value.hasPrefix("0X") { return Int64(value.dropFirst(2), radix: 16).flatMap { $0 >= 0 ? $0 : nil } }
        guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
        return Int64(value)
    }

    func configure(evidence: EvidenceRecord?, in forensicCase: ForensicCase?) {
        guard !isClosing else { return }
        retainDraft()
        generation = UUID()
        for task in jobs.values { task.cancel() }
        self.evidence = evidence
        self.forensicCase = forensicCase
        result = nil
        artifactID = nil
        baseline = nil
        annotations = [:]
        analyses = [:]
        analysisOrder = []
        note = ""
        assessment = .notReviewed
        rawOffsetText = "0"
        rawSnapshot = nil
        reportURL = nil
        isReadingRaw = false
        isLoading = false
        isSaving = false
        isExportingReport = false
        errorMessage = nil
    }

    func configure(result: CarvingResult?) {
        guard !isClosing else { return }
        guard self.result?.jobID != result?.jobID else { return }
        retainDraft()
        generation = UUID()
        self.result = result
        annotations = [:]
        analyses = [:]
        analysisOrder = []
        artifactID = nil
        baseline = nil
        note = ""
        assessment = .notReviewed
        guard let result, let forensicCase else { return }
        let selectedGeneration = generation
        let id = UUID(), operation = loadAnnotations
        isLoading = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.generation == selectedGeneration { self.isLoading = false } }
            do {
                let values = try await Self.work { try await operation(result, forensicCase.bundleURL) }
                try Task.checkCancellation()
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.annotations = values
                self.loadDraft()
            } catch is CancellationError { /* The new selection owns publication. */ }
            catch {
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Saved examiner notes could not be loaded. Recovery candidates remain available."
            }
        }
        jobs[id] = task
    }

    @discardableResult func selectArtifact(_ id: UUID?) -> Bool {
        guard !isClosing else { return false }
        if artifactID == id { return true }
        guard canChangeSelection else { errorMessage = noteValidationMessage ?? "Save or discard the examiner draft before changing recovered files."; return false }
        retainDraft()
        artifactID = id
        loadDraft()
        return true
    }
    func recordAnalysis(_ value: DocumentAnalysis, artifact: CarvedArtifact) {
        guard value.sourceSHA256 == artifact.sha256, value.sourceByteCount == artifact.byteCount,
              result?.artifacts.contains(where: { $0.id == artifact.id }) == true else { return }
        analysisOrder.removeAll { $0 == artifact.id }
        analysisOrder.append(artifact.id)
        analyses[artifact.id] = value
        // Retain a bounded set of recent decoder results for report generation;
        // recovery receipts and saved examiner notes remain durable independently.
        while analyses.count > 64 || analyses.values.reduce(0, { $0 + Self.analysisBytes($1) }) > 16 * 1_024 * 1_024 {
            guard let oldest = analysisOrder.first else { break }
            analysisOrder.removeFirst()
            analyses[oldest] = nil
        }
    }
    func saveAnnotation() {
        guard canSaveAnnotation, let artifactID, let result, let forensicCase else { return }
        let value = RecoveryAnnotation(artifactID: artifactID, assessment: assessment, note: note)
        let selectedGeneration = generation, id = UUID()
        let operation = saveAnnotationRequest
        isSaving = true
        errorMessage = nil
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.generation == selectedGeneration { self.isSaving = false } }
            do {
                try await Self.work { try await operation(value, result, forensicCase.bundleURL) }
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.annotations[artifactID] = value
                self.drafts[DraftKey(caseID: forensicCase.manifest.id, jobID: result.jobID, artifactID: artifactID)] = nil
                if self.artifactID == artifactID {
                    self.baseline = value
                    if self.assessment != value.assessment || self.note != value.note { self.retainDraft() }
                }
                self.statusMessage = "Examiner assessment saved. This is independent from decoder and source-byte verification."
            } catch {
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Examiner note was not confirmed saved; the draft is retained."
            }
        }
        jobs[id] = task
    }
    func discardDraft() {
        if let currentDraftKey { drafts[currentDraftKey] = nil }
        let saved = artifactID.flatMap { annotations[$0] }
        baseline = saved
        note = saved?.note ?? ""
        assessment = saved?.assessment ?? .notReviewed
    }
    func discardAllDrafts() { drafts = [:]; discardDraft() }

    func readRawRange() {
        guard canReadRaw, let evidence, let offset = parsedOffset else { return }
        let selectedGeneration = generation, id = UUID()
        isReadingRaw = true
        errorMessage = nil
        rawSnapshot = nil
        statusMessage = "Verifying the complete source and reading a bounded RAW range…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.generation == selectedGeneration { self.isReadingRaw = false } }
            do {
                let value = try await Self.work { try await RawEvidenceHexReader.read(evidence: evidence, offset: offset) }
                try Task.checkCancellation()
                guard self.generation == selectedGeneration, self.evidence == evidence, !self.isClosing else { return }
                self.rawSnapshot = value
                self.statusMessage = "RAW range verified against the recorded selected-file SHA-256."
            } catch is CancellationError {
                guard self.generation == selectedGeneration else { return }
                self.statusMessage = "RAW range inspection canceled."
            } catch {
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "The RAW range could not be verified."
            }
        }
        jobs[id] = task
    }
    func showSourceOffset(_ offset: Int64) { rawOffsetText = String(offset); readRawRange() }
    func exportReport() {
        guard canExportReport, let result, let forensicCase else { return }
        let selectedGeneration = generation, id = UUID()
        let savedAnalyses = analyses, savedAnnotations = annotations
        isExportingReport = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.generation == selectedGeneration { self.isExportingReport = false } }
            guard let destination = await CasePanelService.newRecoveryReport(), !self.isClosing, !Task.isCancelled else { return }
            do {
                let url = try await Self.work {
                    try RecoveryReportBuilder.exportMarkdown(result: result, analyses: savedAnalyses,
                        annotations: savedAnnotations, in: forensicCase.bundleURL, to: destination)
                }
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.reportURL = url
                self.statusMessage = "Recovery report exported with saved assessments and verified analysis references. Unsaved drafts are excluded."
            } catch {
                guard self.generation == selectedGeneration, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Report export could not create a verified new file."
            }
        }
        jobs[id] = task
    }
    func waitForPendingWork() async {
        let pending = Array(jobs.values)
        for task in pending { await task.value }
    }
    func cancel() { for task in jobs.values { task.cancel() } }
    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        generation = UUID()
        cancel()
        let pending = Array(jobs.values)
        guard !pending.isEmpty else { return nil }
        return Task { for task in pending { await task.value } }
    }
    func reset() {
        isClosing = false
        configure(evidence: nil, in: nil)
    }
    private func retainDraft() {
        guard hasUnsavedChanges, let artifactID, let currentDraftKey else { return }
        drafts[currentDraftKey] = RecoveryAnnotation(artifactID: artifactID, assessment: assessment, note: note)
    }
    private func loadDraft() {
        baseline = artifactID.flatMap { annotations[$0] }
        let value = currentDraftKey.flatMap { drafts[$0] } ?? artifactID.flatMap { annotations[$0] }
        note = value?.note ?? ""
        assessment = value?.assessment ?? .notReviewed
    }
    private static func analysisBytes(_ value: DocumentAnalysis) -> Int {
        (value.thumbnailPNG?.count ?? 0) + value.textPages.reduce(0, { $0 + $1.text.utf8.count })
            + value.rawMetadata.reduce(0, { $0 + $1.name.utf8.count + $1.value.utf8.count })
            + value.warnings.reduce(0, { $0 + $1.utf8.count })
    }
    private var currentDraftKey: DraftKey? {
        guard let artifactID, let result, let forensicCase else { return nil }
        return DraftKey(caseID: forensicCase.manifest.id, jobID: result.jobID, artifactID: artifactID)
    }
    private struct DraftKey: Hashable { let caseID: UUID; let jobID: UUID; let artifactID: UUID }
    nonisolated private static func work<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        let worker = Task.detached(priority: .userInitiated) { try Task.checkCancellation(); return try await operation() }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }
}
