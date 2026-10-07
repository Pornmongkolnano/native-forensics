import AppKit
import Foundation
import ForensicsCore
import Observation

/// Signature recovery is separate from filesystem entries. Every preview and
/// export retains the recovery job, output hash and selected source binding.
@MainActor
@Observable
final class RecoveryWorkspaceStore {
    typealias Load = @Sendable (EvidenceRecord, ForensicCase) async throws -> CarvingResult?
    typealias Recover = @Sendable (EvidenceRecord, ForensicCase, RecoveryOptions, @escaping @Sendable (RecoveryProgress) -> Void) async throws -> CarvingResult
    typealias Analyze = @Sendable (CarvedArtifact, CarvingResult, ForensicCase, URL) async throws -> DocumentAnalysis
    typealias Export = @Sendable (CarvedArtifact, CarvingResult, ForensicCase, URL) async throws -> ExtractionResult

    private(set) var result: CarvingResult?
    private(set) var rows: [CarvedArtifact] = []
    var selectedArtifactID: UUID? {
        didSet {
            guard selectedArtifactID != oldValue else { return }
            guard examination.selectArtifact(selectedArtifactID) else {
                selectedArtifactID = oldValue
                errorMessage = examination.errorMessage
                return
            }
            resetPreview()
        }
    }
    var searchText = "" { didSet { if searchText != oldValue { refreshRows() } } }
    var formatFilter = "all" { didSet { if formatFilter != oldValue { refreshRows() } } }
    var contentQuery = "" { didSet { refreshContentSearch() } }
    private(set) var searchOutcome: DocumentSearchOutcome?
    private(set) var analysis: DocumentAnalysis?
    private(set) var isLoading = false
    private(set) var isRecovering = false
    private(set) var isPreviewing = false
    private(set) var isExporting = false
    private(set) var isFiltering = false
    private(set) var progress: RecoveryProgress?
    private(set) var statusMessage = "Select a recorded RAW image to recover file signatures."
    var errorMessage: String?
    private(set) var lastExport: ExtractionResult?
    var options = RecoveryOptions()
    let examination: RecoveryExaminationStore

    @ObservationIgnored private let photoRecURL: URL?
    @ObservationIgnored private let documentHelperURL: URL
    @ObservationIgnored private let loadRequest: Load
    @ObservationIgnored private let recoverRequest: Recover
    @ObservationIgnored private let analyzeRequest: Analyze
    @ObservationIgnored private let exportRequest: Export
    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var previewID: UUID?
    @ObservationIgnored private var filterID: UUID?
    // hasActiveWork is rendered by parent views. Observe owner insertion and
    // final drain, including canceled owners retained for cleanup.
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private(set) var filterTask: Task<Void, Never>?
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private(set) var activeTask: Task<Void, Never>?

    init(photoRecURL: URL? = nil, documentHelperURL: URL? = nil,
         load: Load? = nil, recover: Recover? = nil, analyze: Analyze? = nil, export: Export? = nil,
         examination: RecoveryExaminationStore? = nil) {
        self.examination = examination ?? RecoveryExaminationStore()
        self.photoRecURL = photoRecURL ?? Self.detectPhotoRec()
        self.documentHelperURL = documentHelperURL ?? Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder")
        loadRequest = load ?? { evidence, forensicCase in
            try RecoveryResultStore.latest(evidenceID: evidence.id, in: forensicCase.bundleURL)
        }
        recoverRequest = recover ?? { evidence, forensicCase, options, progress in
            guard let executable = photoRecURL ?? Self.detectPhotoRec() else { throw RecoveryError.unavailable }
            return try await PhotoRecRecoveryService(executableURL: executable)
                .recover(evidence: evidence, in: forensicCase, options: options, progress: progress)
        }
        analyzeRequest = analyze ?? { artifact, result, forensicCase, helper in
            let file = try RecoveryResultStore.artifactURL(artifact: artifact, result: result, in: forensicCase.bundleURL)
            return try await DocumentAnalysisClient(helperURL: helper).analyze(
                DocumentInput(fileURL: file, expectedSHA256: artifact.sha256, expectedByteCount: artifact.byteCount))
        }
        exportRequest = export ?? { artifact, result, forensicCase, destination in
            try RecoveryResultStore.export(artifact: artifact, result: result, in: forensicCase.bundleURL, to: destination)
        }
    }

    var hasSource: Bool { selection != nil }
    var selectedSourceFilename: String { selection.map { URL(fileURLWithPath: $0.evidence.sourcePath).lastPathComponent } ?? "No data source" }
    var selectedArtifact: CarvedArtifact? { result?.artifacts.first { $0.id == selectedArtifactID } }
    var formatHints: [String] { Array(Set((result?.artifacts ?? []).map { $0.formatHint.lowercased() })).sorted() }
    var hasActiveWork: Bool { !jobs.isEmpty || examination.hasActiveWork }
    var canChangeSelection: Bool { examination.canChangeSelection }
    var retainedDraftCount: Int { examination.retainedDraftCount }
    func discardAllDrafts() { examination.discardAllDrafts() }
    var canRecover: Bool {
        guard let selection else { return false }
        return selection.evidence.container == .raw && selection.evidence.byteCount <= options.maximumInputBytes
            && photoRecURL != nil && !hasActiveWork && !isClosing && examination.canChangeSelection && examination.retainedDraftCount == 0
    }
    var recoveryUnavailableReason: String? {
        guard let selection else { return "Select a recorded single RAW image first." }
        if selection.evidence.container != .raw { return RecoveryError.unsupportedSource.localizedDescription }
        if selection.evidence.byteCount > options.maximumInputBytes { return "This image exceeds the configured 32 GiB input limit." }
        if examination.retainedDraftCount > 0 { return "Save or discard your recovery assessment drafts before starting a new scan." }
        if photoRecURL == nil { return "PhotoRec is unavailable. Install the local TestDisk / PhotoRec tool, then reopen this workbench. It is not bundled with this app." }
        return nil
    }
    var documentUnavailableReason: String? {
        guard FileManager.default.isExecutableFile(atPath: documentHelperURL.path) else { return DocumentAnalysisError.unavailable.localizedDescription }
        if let artifact = selectedArtifact, artifact.byteCount > DocumentLimits.maximumInputBytes {
            return DocumentAnalysisError.invalidInput.localizedDescription
        }
        return nil
    }
    var canPreview: Bool { selectedArtifact != nil && documentUnavailableReason == nil && !hasActiveWork && !isClosing }
    var canExport: Bool { selectedArtifact != nil && !hasActiveWork && !isClosing }

    func configure(evidence: EvidenceRecord?, in forensicCase: ForensicCase?) {
        guard !isClosing, examination.canChangeSelection else { return }
        if let selection, selection.evidence == evidence, selection.forensicCase.bundleURL == forensicCase?.bundleURL,
           selection.forensicCase.manifest.id == forensicCase?.manifest.id { return }
        invalidate()
        selection = nil
        examination.configure(evidence: evidence, in: forensicCase)
        result = nil
        rows = []
        selectedArtifactID = nil
        searchText = ""
        formatFilter = "all"
        lastExport = nil
        guard let evidence, let forensicCase else {
            statusMessage = "Select a recorded RAW image to recover file signatures."
            return
        }
        selection = Selection(evidence: evidence, forensicCase: forensicCase)
        refresh()
    }

    func refresh() {
        guard let selection, !isClosing, !isRecovering, !isExporting else { return }
        let pending = invalidate()
        let operation = loadRequest
        let id = UUID()
        generation = id
        isLoading = true
        errorMessage = nil
        statusMessage = "Loading saved recovery receipt…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for previous in pending { await previous.value }
            do {
                try Task.checkCancellation()
                let value = try await Self.runDetached { try await operation(selection.evidence, selection.forensicCase) }
                try Task.checkCancellation()
                guard self.matches(id, selection: selection) else { return }
                if let value { try Self.verifyBinding(value, selection: selection) }
                self.result = value
                self.examination.configure(result: value)
                self.refreshRows()
                self.statusMessage = value == nil ? "No recovery job is saved for this image. Recover Files scans the whole single RAW image."
                    : "Saved recovery receipt loaded. Recovered file bytes are checked again before preview or export."
            } catch is CancellationError {
                guard self.matches(id, selection: selection) else { return }
                self.statusMessage = "Recovery loading canceled. Saved results were preserved."
            } catch {
                guard self.matches(id, selection: selection) else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Saved recovery receipt could not be loaded."
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func beginRecovery() {
        guard canRecover, let selection else { return }
        let pending = invalidate()
        let operation = recoverRequest
        let selectedOptions = options
        let id = UUID()
        generation = id
        isRecovering = true
        statusMessage = "Verifying source bytes before signature recovery…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for previous in pending { await previous.value }
            do {
                try Task.checkCancellation()
                let value = try await Self.runDetached { [weak self] in
                    // The worker owns only its operation and frozen source;
                    // progress does not extend the workspace lifetime.
                    try await operation(selection.evidence, selection.forensicCase, selectedOptions) { [weak self] update in
                        Task { @MainActor [weak self] in
                            guard let self, self.matches(id, selection: selection), self.isRecovering else { return }
                            self.progress = update
                        }
                    }
                }
                try Task.checkCancellation()
                guard self.matches(id, selection: selection) else { return }
                try Self.verifyBinding(value, selection: selection)
                self.result = value
                self.examination.configure(result: value)
                self.selectedArtifactID = nil
                self.refreshRows()
                self.statusMessage = "Recovery \(value.status.rawValue): \(value.artifacts.count.formatted()) candidates saved with recovered-byte hashes. Deletion status is unknown."
            } catch is CancellationError {
                guard self.matches(id, selection: selection) else { return }
                self.statusMessage = "Recovery canceled. Refresh to inspect the latest saved receipt."
            } catch {
                guard self.matches(id, selection: selection) else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Recovery did not complete. Previously saved results remain available."
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func previewSelected() {
        guard canPreview, let selection, let artifact = selectedArtifact, let result else { return }
        let operation = analyzeRequest
        let helper = documentHelperURL
        let id = UUID()
        previewID = id
        isPreviewing = true
        analysis = nil
        searchOutcome = nil
        errorMessage = nil
        statusMessage = "Checking recovered bytes and decoding in an isolated helper…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer {
                self.jobs[id] = nil
                if self.previewID == id { self.previewID = nil; self.isPreviewing = false; self.activeTask = nil }
            }
            do {
                let value = try await Self.runDetached { try await operation(artifact, result, selection.forensicCase, helper) }
                try Task.checkCancellation()
                guard self.previewID == id, self.selection == selection,
                      self.selectedArtifactID == artifact.id, self.result?.jobID == result.jobID, !self.isClosing else { return }
                guard value.sourceSHA256 == artifact.sha256, value.sourceByteCount == artifact.byteCount else {
                    throw DocumentAnalysisError.integrityMismatch
                }
                self.analysis = value
                self.examination.recordAnalysis(value, artifact: artifact)
                self.refreshContentSearch()
                self.statusMessage = "Document inspection: \(value.status.rawValue). A format hint alone does not establish readable content."
            } catch is CancellationError {
                guard self.previewID == id else { return }
                self.statusMessage = "Document inspection canceled."
            } catch {
                guard self.previewID == id, self.selection == selection, self.selectedArtifactID == artifact.id, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Document inspection failed. No decoded-content claim was recorded."
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func exportSelected() {
        guard canExport, let artifact = selectedArtifact else { return }
        isExporting = true
        let id = UUID()
        generation = id
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            guard let destination = await CasePanelService.newRecoveredFile(named: artifact.filename),
                  !self.isClosing, !Task.isCancelled else { return }
            await self.exportArtifact(to: destination, id: id)
        }
        jobs[id] = task
        activeTask = task
    }

    /// Kept separate from the panel so tests can exercise receipt and stale-job guards.
    func exportSelected(to destination: URL) {
        guard canExport else { return }
        let id = UUID()
        generation = id
        isExporting = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            await self.exportArtifact(to: destination, id: id)
        }
        jobs[id] = task
        activeTask = task
    }

    private func exportArtifact(to destination: URL, id: UUID) async {
        guard let selection, let artifact = selectedArtifact, let result else { return }
        let operation = exportRequest
        do {
            let receipt = try await Self.runDetached { try await operation(artifact, result, selection.forensicCase, destination) }
            guard matches(id, selection: selection), selectedArtifactID == artifact.id, self.result?.jobID == result.jobID else { return }
            lastExport = receipt
            statusMessage = "Recovered file exported to a new destination after its size/hash check."
        } catch is CancellationError {
            guard matches(id, selection: selection) else { return }
            statusMessage = "Export canceled. Confirm the output destination before retrying."
        } catch {
            guard matches(id, selection: selection) else { return }
            errorMessage = error.localizedDescription
            statusMessage = "Export could not verify or create the destination."
        }
    }

    func cancel() {
        for task in jobs.values { task.cancel() }
        filterTask?.cancel()
        examination.cancel()
        if isFiltering {
            searchText = ""
            formatFilter = "all"
            refreshRows()
        }
    }
    func reset() {
        _ = invalidate()
        examination.reset()
        selection = nil
        result = nil
        rows = []
        selectedArtifactID = nil
        isClosing = false
    }
    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        var pending = invalidate()
        if let examinationJob = examination.beginShutdown() { pending.append(examinationJob) }
        guard !pending.isEmpty else { return nil }
        return Task { for task in pending { await task.value } }
    }
    func copySelectedHash() {
        guard let hash = selectedArtifact?.sha256 else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(hash, forType: .string)
    }

    private func refreshRows() {
        filterTask?.cancel()
        filterTask = nil
        filterID = nil
        isFiltering = false
        let artifacts = result?.artifacts ?? []
        let query = searchText
        let format = formatFilter
        if query.isEmpty && format == "all" {
            rows = artifacts
            clearInvisibleSelection()
            return
        }
        let id = UUID(), selectedJobID = result?.jobID
        filterID = id
        isFiltering = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer {
                self.jobs[id] = nil
                if self.filterID == id { self.filterTask = nil; self.filterID = nil; self.isFiltering = false }
            }
            do {
                try await Task.sleep(for: .milliseconds(120))
                let matches = try await Self.runDetached {
                    var matches: [CarvedArtifact] = []
                    for (index, artifact) in artifacts.enumerated() {
                        if index.isMultiple(of: 128) { try Task.checkCancellation() }
                        if (format == "all" || artifact.formatHint.lowercased() == format),
                           query.isEmpty || artifact.filename.localizedCaseInsensitiveContains(query) || artifact.sha256.localizedCaseInsensitiveContains(query) {
                            matches.append(artifact)
                        }
                    }
                    return matches
                }
                try Task.checkCancellation()
                guard self.filterID == id, self.result?.jobID == selectedJobID,
                      self.searchText == query, self.formatFilter == format, !self.isClosing else { return }
                self.rows = matches
                self.clearInvisibleSelection()
            } catch { /* A newer query or selection owns publication. */ }
        }
        jobs[id] = task
        filterTask = task
    }
    private func clearInvisibleSelection() {
        if let selectedArtifactID, !rows.contains(where: { $0.id == selectedArtifactID }) { self.selectedArtifactID = nil }
    }
    private func refreshContentSearch() {
        guard let analysis, !contentQuery.isEmpty else { searchOutcome = nil; return }
        searchOutcome = DocumentContentSearch.search(contentQuery, in: analysis)
    }
    private func resetPreview() {
        if let previewID { jobs[previewID]?.cancel(); activeTask = nil }
        previewID = nil
        isPreviewing = false
        analysis = nil
        searchOutcome = nil
        contentQuery = ""
        lastExport = nil
    }
    @discardableResult private func invalidate() -> [Task<Void, Never>] {
        generation = nil
        resetPreview()
        for task in jobs.values { task.cancel() }
        let pending = Array(jobs.values)
        filterTask?.cancel()
        self.filterTask = nil
        filterID = nil
        isFiltering = false
        activeTask = nil
        isLoading = false
        isRecovering = false
        isExporting = false
        progress = nil
        errorMessage = nil
        return pending
    }
    private func finish(_ id: UUID) {
        jobs[id] = nil
        guard generation == id else { return }
        generation = nil
        activeTask = nil
        isLoading = false
        isRecovering = false
        isExporting = false
        progress = nil
    }
    private func matches(_ id: UUID, selection: Selection) -> Bool {
        generation == id && self.selection == selection && !isClosing
    }
    private static func verifyBinding(_ result: CarvingResult, selection: Selection) throws {
        guard result.caseID == selection.forensicCase.manifest.id,
              result.sourceEvidenceID == selection.evidence.id,
              result.sourceSHA256 == selection.evidence.sha256,
              result.sourceByteCount == selection.evidence.byteCount else { throw RecoveryError.scopeMismatch }
    }
    nonisolated private static func runDetached<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        let worker = Task.detached(priority: .userInitiated) { try Task.checkCancellation(); return try await operation() }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }
    nonisolated private static func detectPhotoRec() -> URL? {
        ["/opt/homebrew/bin/photorec", "/usr/local/bin/photorec"].map(URL.init(fileURLWithPath:))
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }
    private struct Selection: Sendable, Equatable {
        let evidence: EvidenceRecord
        let forensicCase: ForensicCase
        static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.evidence == rhs.evidence && lhs.forensicCase.manifest.id == rhs.forensicCase.manifest.id
                && lhs.forensicCase.bundleURL == rhs.forensicCase.bundleURL
        }
    }
}
