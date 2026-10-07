import AppKit
import Darwin
import Foundation
import ForensicsCore
import Observation

enum OpticalStateFilter: String, CaseIterable, Identifiable, Sendable {
    case all, current, history, deletedAncestor
    var id: Self { self }
    var title: String {
        switch self {
        case .all: "All States"
        case .current: "Current Namespace"
        case .history: "Historical Files"
        case .deletedAncestor: "Deleted Ancestor"
        }
    }
    func matches(_ entry: UDFFileEntry) -> Bool {
        switch self {
        case .all: true
        case .current: entry.state == .current
        case .history: entry.state != .current
        case .deletedAncestor: entry.state == .historicalDeletedAncestor
        }
    }
}

/// Optical namespace history is a UDF metadata result. It is never presented as
/// PhotoRec output or inferred as deleted from a recovered filename.
@MainActor
@Observable
final class OpticalWorkspaceStore {
    typealias Load = @Sendable (EvidenceRecord, ForensicCase) async throws -> UDFInspectionResult?
    typealias Inspect = @Sendable (EvidenceRecord, ForensicCase, UDFInspectionOptions, @escaping @Sendable (UDFInspectionProgress) -> Void) async throws -> UDFInspectionResult
    typealias Analyze = @Sendable (UDFFileEntry, UDFInspectionResult, ForensicCase, URL) async throws -> DocumentAnalysis
    typealias Export = @Sendable (UDFFileEntry, UDFInspectionResult, ForensicCase, URL) async throws -> UDFExportReceipt

    private(set) var result: UDFInspectionResult?
    private(set) var rows: [UDFFileEntry] = []
    var selectedEntryID: String? { didSet { if oldValue != selectedEntryID { resetPreview() } } }
    var searchText = "" { didSet { if searchText != oldValue { refreshRows() } } }
    var stateFilter: OpticalStateFilter = .all { didSet { if stateFilter != oldValue { refreshRows() } } }
    var contentQuery = "" { didSet { updateContentSearch() } }
    private(set) var analysis: DocumentAnalysis?
    private(set) var searchOutcome: DocumentSearchOutcome?
    private(set) var isLoading = false
    private(set) var isInspecting = false
    private(set) var isPreviewing = false
    private(set) var isExporting = false
    private(set) var isFiltering = false
    private(set) var progress: UDFInspectionProgress?
    private(set) var statusMessage = "Inspect the recorded UDF namespace and linked VAT history."
    var errorMessage: String?
    private(set) var lastExport: UDFExportReceipt?
    var options = UDFInspectionOptions()
    private(set) var analyses: [String: DocumentAnalysis] = [:]
    private(set) var reportURL: URL?
    private(set) var isExportingReport = false

    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var previewID: UUID?
    @ObservationIgnored private var filterID: UUID?
    // hasActiveWork is rendered by parent views. Observe owner insertion and
    // final drain, including canceled owners retained for cleanup.
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private var analysisOrder: [String] = []
    @ObservationIgnored private let documentHelperURL: URL
    @ObservationIgnored private let loadRequest: Load
    @ObservationIgnored private let inspectRequest: Inspect
    @ObservationIgnored private let analyzeRequest: Analyze
    @ObservationIgnored private let exportRequest: Export
    @ObservationIgnored private(set) var activeTask: Task<Void, Never>?
    @ObservationIgnored private(set) var filterTask: Task<Void, Never>?

    init(documentHelperURL: URL? = nil, load: Load? = nil, inspect: Inspect? = nil,
         analyze: Analyze? = nil, export: Export? = nil) {
        self.documentHelperURL = documentHelperURL ?? Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder")
        loadRequest = load ?? { evidence, forensicCase in
            try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id)
        }
        inspectRequest = inspect ?? { evidence, forensicCase, options, progress in
            try await UDFInspector.inspect(evidence: evidence, in: forensicCase, options: options, progress: progress)
        }
        analyzeRequest = analyze ?? { entry, result, forensicCase, helper in
            try await Self.decodeOwnedPreview(entry: entry, result: result, forensicCase: forensicCase, helper: helper)
        }
        exportRequest = export ?? { entry, result, forensicCase, destination in
            try await UDFInspector.export(entryID: entry.id, from: result, in: forensicCase, to: destination)
        }
    }

    var selectedSourceFilename: String { selection.map { URL(fileURLWithPath: $0.evidence.sourcePath).lastPathComponent } ?? "No data source" }
    var hasSource: Bool { selection != nil }
    var selectedEntry: UDFFileEntry? { result?.entries.first { $0.id == selectedEntryID } }
    var hasActiveWork: Bool { !jobs.isEmpty }
    var canInspect: Bool { selection?.evidence.container == .raw && (selection?.evidence.byteCount ?? Int64.max) <= options.maximumSourceBytes && !hasActiveWork && !isClosing }
    var inspectionUnavailableReason: String? {
        guard let evidence = selection?.evidence else { return "Select a recorded RAW optical image first." }
        if evidence.container != .raw { return "UDF history currently supports one recorded RAW optical image." }
        if evidence.byteCount > options.maximumSourceBytes { return "The selected RAW image exceeds the bounded UDF input size limit." }
        return nil
    }
    var documentUnavailableReason: String? {
        if !FileManager.default.isExecutableFile(atPath: documentHelperURL.path) { return DocumentAnalysisError.unavailable.localizedDescription }
        if let entry = selectedEntry, entry.byteCount > DocumentLimits.maximumInputBytes { return "Document preview is bounded to files up to 128 MiB. Export the verified file for external examination." }
        return nil
    }
    var canPreview: Bool { selectedEntry != nil && documentUnavailableReason == nil && !hasActiveWork && !isClosing }
    var canExport: Bool { selectedEntry != nil && !hasActiveWork && !isClosing }
    var canExportReport: Bool { result != nil && !hasActiveWork && !isClosing }

    func configure(evidence: EvidenceRecord?, in forensicCase: ForensicCase?) {
        guard !isClosing else { return }
        if let selection, selection.evidence == evidence, selection.forensicCase.manifest.id == forensicCase?.manifest.id,
           selection.forensicCase.bundleURL == forensicCase?.bundleURL { return }
        _ = invalidate()
        selection = nil
        result = nil
        rows = []
        selectedEntryID = nil
        searchText = ""
        stateFilter = .all
        analyses = [:]
        analysisOrder = []
        reportURL = nil
        guard let evidence, let forensicCase else { return }
        selection = Selection(evidence: evidence, forensicCase: forensicCase)
        refresh()
    }

    func refresh() {
        guard let selection, !isClosing, !isInspecting, !isExporting, !isExportingReport else { return }
        let previous = invalidate()
        let id = UUID(), operation = loadRequest
        generation = id
        isLoading = true
        statusMessage = "Loading the saved UDF inspection receipt…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for job in previous { await job.value }
            do {
                try Task.checkCancellation()
                let value = try await Self.work { try await operation(selection.evidence, selection.forensicCase) }
                try Task.checkCancellation()
                guard self.matches(id, selection: selection) else { return }
                if let value { try Self.verifyBinding(value, selection: selection) }
                self.result = value
                self.refreshRows()
                self.statusMessage = value == nil ? "No UDF history result is saved. Inspect the bounded UDF 2.01 physical / virtual partition profile."
                    : "Saved UDF history loaded. Current namespace and historical deleted-ancestor evidence remain separate."
            } catch is CancellationError { /* New selection or shutdown owns publication. */ }
            catch {
                guard self.matches(id, selection: selection) else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Saved UDF history could not be loaded."
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func inspect() {
        guard canInspect, let selection else { return }
        let previous = invalidate()
        let id = UUID(), operation = inspectRequest, selectedOptions = options
        generation = id
        isInspecting = true
        statusMessage = "Verifying source bytes and inspecting UDF history…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for job in previous { await job.value }
            do {
                let value = try await Self.work { [weak self] in
                    // The worker owns only its operation and frozen source;
                    // progress does not extend the workspace lifetime.
                    try await operation(selection.evidence, selection.forensicCase, selectedOptions) { [weak self] update in
                        Task { @MainActor [weak self] in
                            guard let self, self.matches(id, selection: selection), self.isInspecting else { return }
                            self.progress = update
                        }
                    }
                }
                guard self.matches(id, selection: selection) else { return }
                try Self.verifyBinding(value, selection: selection)
                self.result = value
                self.selectedEntryID = nil
                self.analyses = [:]
                self.analysisOrder = []
                self.refreshRows()
                self.statusMessage = Task.isCancelled
                    ? "The UDF receipt was saved before cancellation completed. \(value.entries.count.formatted()) recorded files remain available."
                    : "UDF inspection saved: \(value.entries.count.formatted()) files across \(value.snapshots.count.formatted()) linked VAT states."
            } catch is CancellationError {
                guard self.matches(id, selection: selection) else { return }
                self.statusMessage = "UDF inspection canceled. Reopen the saved receipt to confirm its latest generation."
            } catch {
                guard self.matches(id, selection: selection) else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "UDF inspection did not complete. Existing saved history was preserved."
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func previewSelected() {
        guard canPreview, let selection, let result, let entry = selectedEntry else { return }
        let id = UUID(), operation = analyzeRequest, helper = documentHelperURL
        previewID = id
        isPreviewing = true
        analysis = nil
        searchOutcome = nil
        errorMessage = nil
        statusMessage = "Verifying the UDF export and decoding bounded private preview bytes…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.previewID == id { self.previewID = nil; self.isPreviewing = false; self.activeTask = nil } }
            do {
                let value = try await Self.work { try await operation(entry, result, selection.forensicCase, helper) }
                try Task.checkCancellation()
                guard self.previewID == id, self.selection == selection, self.selectedEntryID == entry.id,
                      self.result?.jobID == result.jobID, !self.isClosing else { return }
                guard value.sourceSHA256 == entry.sha256, value.sourceByteCount == entry.byteCount else { throw DocumentAnalysisError.integrityMismatch }
                self.analysis = value
                self.retainAnalysis(value, entryID: entry.id)
                self.updateContentSearch()
                self.statusMessage = "UDF file content inspection: \(value.status.rawValue). Owned preview scratch was cleaned up."
            } catch is CancellationError {
                guard self.previewID == id else { return }
                self.statusMessage = "UDF file preview canceled."
            } catch {
                guard self.previewID == id, self.selection == selection, self.selectedEntryID == entry.id, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "UDF file preview could not be verified or decoded."
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func exportSelected() {
        guard canExport, let entry = selectedEntry else { return }
        let id = UUID()
        generation = id
        isExporting = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            guard let destination = await CasePanelService.newOpticalFile(named: entry.name), !self.isClosing, !Task.isCancelled else { return }
            await self.export(to: destination, id: id)
        }
        jobs[id] = task
        activeTask = task
    }
    func exportSelected(to destination: URL) {
        guard canExport else { return }
        let id = UUID()
        generation = id
        isExporting = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            await self.export(to: destination, id: id)
        }
        jobs[id] = task
        activeTask = task
    }
    private func export(to destination: URL, id: UUID) async {
        guard let selection, let result, let entry = selectedEntry else { return }
        let operation = exportRequest
        do {
            let receipt = try await Self.work { try await operation(entry, result, selection.forensicCase, destination) }
            guard matches(id, selection: selection), self.result?.jobID == result.jobID, selectedEntryID == entry.id else { return }
            try Self.verifyReceipt(receipt, entry: entry, result: result)
            lastExport = receipt
            statusMessage = "UDF file exported to a new path with its recorded content SHA-256 verified."
        } catch {
            guard matches(id, selection: selection) else { return }
            errorMessage = error.localizedDescription
            statusMessage = "UDF export could not be verified or created."
        }
    }

    func exportReport() {
        guard canExportReport, let result, let selection else { return }
        let id = UUID(), selectedAnalyses = analyses
        generation = id
        isExportingReport = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            guard let destination = await CasePanelService.newOpticalReport(), !self.isClosing, !Task.isCancelled else { return }
            do {
                let exported = try await Self.work {
                    try UDFReportBuilder.exportMarkdown(result: result, analyses: selectedAnalyses,
                        in: selection.forensicCase, to: destination)
                }
                guard self.matches(id, selection: selection) else { return }
                self.reportURL = exported
                self.statusMessage = "UDF inventory report exported with namespace states, recorded proof and retained decoder results."
            } catch {
                guard self.matches(id, selection: selection) else { return }
                self.errorMessage = error.localizedDescription
            }
        }
        jobs[id] = task
        activeTask = task
    }

    func cancel() {
        for task in jobs.values { task.cancel() }
        if isFiltering { searchText = ""; stateFilter = .all; refreshRows() }
    }
    func reset() { _ = invalidate(); selection = nil; result = nil; rows = []; analyses = [:]; analysisOrder = []; selectedEntryID = nil; isClosing = false }
    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        let pending = invalidate()
        guard !pending.isEmpty else { return nil }
        return Task { for task in pending { await task.value } }
    }
    func waitForPendingWork() async { let pending = Array(jobs.values); for task in pending { await task.value } }
    func copySelectedHash() {
        guard let entry = selectedEntry else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(entry.sha256, forType: .string)
    }
    private func refreshRows() {
        filterTask?.cancel()
        filterID = nil
        filterTask = nil
        isFiltering = false
        let entries = result?.entries ?? [], query = searchText, state = stateFilter
        if query.isEmpty && state == .all { rows = entries; clearInvisibleSelection(); return }
        let id = UUID(), selectedJob = result?.jobID
        filterID = id
        isFiltering = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.filterID == id { self.filterID = nil; self.filterTask = nil; self.isFiltering = false } }
            do {
                try await Task.sleep(for: .milliseconds(120))
                let matches = try await Self.work {
                    var values: [UDFFileEntry] = []
                    for (index, entry) in entries.enumerated() {
                        if index.isMultiple(of: 128) { try Task.checkCancellation() }
                        if state.matches(entry), query.isEmpty || entry.originalPath.localizedCaseInsensitiveContains(query)
                            || entry.sha256.localizedCaseInsensitiveContains(query) { values.append(entry) }
                    }
                    return values
                }
                try Task.checkCancellation()
                guard self.filterID == id, self.result?.jobID == selectedJob, self.searchText == query,
                      self.stateFilter == state, !self.isClosing else { return }
                self.rows = matches
                self.clearInvisibleSelection()
            } catch { /* The matching query generation owns the table. */ }
        }
        jobs[id] = task
        filterTask = task
    }
    private func clearInvisibleSelection() { if let selectedEntryID, !rows.contains(where: { $0.id == selectedEntryID }) { self.selectedEntryID = nil } }
    private func resetPreview() {
        if let previewID { jobs[previewID]?.cancel(); activeTask = nil }
        previewID = nil
        isPreviewing = false
        analysis = nil
        searchOutcome = nil
        contentQuery = ""
        lastExport = nil
    }
    private func updateContentSearch() { searchOutcome = analysis.flatMap { contentQuery.isEmpty ? nil : DocumentContentSearch.search(contentQuery, in: $0) } }
    private func retainAnalysis(_ value: DocumentAnalysis, entryID: String) {
        analyses[entryID] = value
        analysisOrder.removeAll { $0 == entryID }
        analysisOrder.append(entryID)
        while analyses.count > 64 || analyses.values.reduce(0, { $0 + Self.analysisBytes($1) }) > 16 * 1_024 * 1_024 {
            guard let oldest = analysisOrder.first else { break }
            analysisOrder.removeFirst()
            analyses[oldest] = nil
        }
    }
    private static func analysisBytes(_ value: DocumentAnalysis) -> Int {
        (value.thumbnailPNG?.count ?? 0) + value.textPages.reduce(0, { $0 + $1.text.utf8.count })
            + value.rawMetadata.reduce(0, { $0 + $1.name.utf8.count + $1.value.utf8.count })
    }
    @discardableResult private func invalidate() -> [Task<Void, Never>] {
        generation = nil
        resetPreview()
        filterID = nil
        for task in jobs.values { task.cancel() }
        filterTask = nil
        let pending = Array(jobs.values)
        activeTask = nil
        isLoading = false
        isInspecting = false
        isExporting = false
        isExportingReport = false
        isFiltering = false
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
        isInspecting = false
        isExporting = false
        isExportingReport = false
        progress = nil
    }
    private func matches(_ id: UUID, selection: Selection) -> Bool { generation == id && self.selection == selection && !isClosing }
    nonisolated private static func verifyBinding(_ result: UDFInspectionResult, selection: Selection) throws {
        guard result.caseID == selection.forensicCase.manifest.id, result.sourceEvidenceID == selection.evidence.id,
              result.sourceSHA256 == selection.evidence.sha256, result.sourceByteCount == selection.evidence.byteCount else { throw UDFError.invalidResult("The inspection belongs to another case or source.") }
    }
    nonisolated private static func verifyReceipt(_ receipt: UDFExportReceipt, entry: UDFFileEntry, result: UDFInspectionResult) throws {
        guard receipt.caseID == result.caseID, receipt.sourceEvidenceID == result.sourceEvidenceID,
              receipt.jobID == result.jobID, receipt.entryID == entry.id, receipt.byteCount == entry.byteCount,
              receipt.sha256 == entry.sha256, receipt.sourceSHA256 == result.sourceSHA256 else { throw UDFError.invalidResult("The exported bytes or generation did not match this file.") }
    }
    nonisolated private static func decodeOwnedPreview(entry: UDFFileEntry, result: UDFInspectionResult,
                                                      forensicCase: ForensicCase, helper: URL) async throws -> DocumentAnalysis {
        guard entry.byteCount <= DocumentLimits.maximumInputBytes else { throw DocumentAnalysisError.invalidInput }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-UDF-Preview-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var initial = stat()
        guard lstat(directory.path, &initial) == 0, (initial.st_mode & S_IFMT) == S_IFDIR else { throw DocumentAnalysisError.invalidInput }
        defer {
            var current = stat()
            if lstat(directory.path, &current) == 0, current.st_dev == initial.st_dev, current.st_ino == initial.st_ino {
                try? FileManager.default.removeItem(at: directory)
            }
        }
        let file = directory.appendingPathComponent("verified-payload")
        let receipt = try await UDFInspector.export(entryID: entry.id, from: result, in: forensicCase, to: file)
        try verifyReceipt(receipt, entry: entry, result: result)
        try Task.checkCancellation()
        let analysis = try await DocumentAnalysisClient(helperURL: helper).analyze(
            DocumentInput(fileURL: file, expectedSHA256: entry.sha256, expectedByteCount: entry.byteCount))
        var cleanupIdentity = stat()
        guard lstat(directory.path, &cleanupIdentity) == 0, cleanupIdentity.st_dev == initial.st_dev,
              cleanupIdentity.st_ino == initial.st_ino else { throw DocumentAnalysisError.sourceChanged }
        try FileManager.default.removeItem(at: directory)
        return analysis
    }
    nonisolated private static func work<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        let worker = Task.detached(priority: .userInitiated) { try Task.checkCancellation(); return try await operation() }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }
    private struct Selection: Sendable, Equatable {
        let evidence: EvidenceRecord
        let forensicCase: ForensicCase
        static func == (lhs: Self, rhs: Self) -> Bool { lhs.evidence == rhs.evidence && lhs.forensicCase.manifest.id == rhs.forensicCase.manifest.id && lhs.forensicCase.bundleURL == rhs.forensicCase.bundleURL }
    }
}
