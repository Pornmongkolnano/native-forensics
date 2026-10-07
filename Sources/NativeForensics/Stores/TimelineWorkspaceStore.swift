import AppKit
import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class TimelineWorkspaceStore {
    typealias FilesystemLoad = @Sendable (UUID, EvidenceRecord, EnumerationResult, Bool) async throws -> TimelineReport
    typealias BrowserLoad = @Sendable (UUID, EvidenceRecord, EnumerationResult, FilesystemEntry) async throws -> BrowserTimelineResult
    typealias Export = @Sendable (TimelineReport, URL, [URL]) async throws -> TimelineExportReceipt
    private(set) var report: TimelineReport?
    private(set) var rows: [TimelineEvent] = []
    private(set) var isLoading = false
    private(set) var isFiltering = false
    private(set) var isExporting = false
    private(set) var isPresentingPanel = false
    private(set) var errorMessage: String?
    private(set) var phase = "Choose recorded filesystem results to build a timeline."
    private(set) var exportReceipt: TimelineExportReceipt?
    private(set) var browserCandidates: [FilesystemEntry] = []
    var selectedBrowserID: String?
    var selectedEventID: String?
    var query = "" { didSet { filter() } }
    var useDateRange = false { didSet { filter() } }
    var from = Date(timeIntervalSince1970: 0) { didSet { filter() } }
    var through = Date() { didSet { filter() } }
    var includeUnresolved = true { didSet { filter() } }
    var examinerNotes = ""
    var hasActiveWork: Bool { !jobs.isEmpty || !filterJobs.isEmpty }
    var isWorking: Bool { isLoading || isExporting || isFiltering || isPresentingPanel || hasActiveWork }
    var statusMessage: String { phase }
    var binding: TimelineSourceBinding? { report?.binding }
    var canLoad: Bool { selection != nil && !isLoading && !isExporting && !isPresentingPanel && !closing }
    var canExport: Bool { report != nil && !isLoading && !isExporting && !isPresentingPanel && !closing }
    var canLoadBrowser: Bool { canLoad && selectedBrowserID != nil && selection?.result.status == .completed }
    var selectedEvent: TimelineEvent? { rows.first { $0.id == selectedEventID } }
    var hasSource: Bool { selection != nil }

    @ObservationIgnored private let filesystemLoad: FilesystemLoad
    @ObservationIgnored private let browserLoad: BrowserLoad
    @ObservationIgnored private let export: Export
    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var filterGeneration: UUID?
    @ObservationIgnored private var closing = false
    private var jobs: [UUID: Task<Void, Never>] = [:]
    private var filterJobs: [UUID: Task<Void, Never>] = [:]

    init(engineHelperURL: URL, filesystemLoad: FilesystemLoad? = nil, browserLoad: BrowserLoad? = nil, export: Export? = nil) {
        self.filesystemLoad = filesystemLoad ?? { caseID, evidence, result, historical in
            try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: result, historical: historical)
        }
        self.browserLoad = browserLoad ?? { caseID, evidence, result, file in
            try await FilesystemBrowserTimelineService(engine: EngineClient(helperURL: engineHelperURL)).parse(caseID: caseID, evidence: evidence, result: result, file: file)
        }
        self.export = export ?? { report, output, forbidden in try await TimelineReportExporter.export(report, to: output, forbiddenURLs: forbidden) }
    }

    func configure(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult, historical: Bool, caseURL: URL) {
        guard !closing else { return }
        let next = Selection(caseID: caseID, evidence: evidence, result: result, historical: historical, caseURL: caseURL)
        guard next != selection else { return }
        invalidate(); selection = next
        browserCandidates = Array(result.files.filter { !$0.isDirectory && !$0.isDeleted && $0.name == "History" }.prefix(100))
        selectedBrowserID = browserCandidates.first?.id
        phase = historical ? "Recorded historical filesystem snapshot. Build metadata timeline; browser import will freshly verify source bytes." : "Build recorded filesystem timeline or import an allocated Chromium History artifact."
    }

    func loadFilesystem() {
        guard canLoad, let selection else { return }
        let operation = filesystemLoad
        start(phase: "Building recorded filesystem timeline…") { [weak self] id in
            let worker = Task.detached(priority: .userInitiated) {
                let value = try await operation(selection.caseID, selection.evidence, selection.result, selection.historical)
                try TimelineReportExporter.validate(value)
                return value
            }
            let value = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
            try Task.checkCancellation()
            guard let self, self.generation == id, self.selection == selection else { return }
            guard value.binding.caseID == selection.caseID, value.binding.evidenceID == selection.evidence.id,
                  value.binding.orderedContainerSHA256 == selection.result.sourcePaths.map({ selection.result.sourceFileHashes[$0] ?? "" }) else { throw TimelineError.sourceChanged }
            self.report = value; self.exportReceipt = nil
            self.phase = "\(value.events.count.formatted()) recorded filesystem events. Metadata receipt is distinct from fresh source verification."
            self.filter()
        }
    }

    func loadSelectedBrowserHistory() {
        guard let id = selectedBrowserID, let file = selection?.result.files.first(where: { $0.id == id }) else { return }
        loadBrowserHistory(file: file)
    }

    func loadBrowserHistory(file: FilesystemEntry) {
        guard canLoad, let selection, selection.result.files.contains(file) else { return }
        let operation = browserLoad, filesystem = filesystemLoad
        start(phase: "Verifying source bytes and extracting explicit History/WAL/SHM artifacts…") { [weak self] id in
            let worker = Task.detached(priority: .userInitiated) {
                let base = try await filesystem(selection.caseID, selection.evidence, selection.result, selection.historical)
                let browser = try await operation(selection.caseID, selection.evidence, selection.result, file)
                guard browser.binding.caseID == base.binding.caseID, browser.binding.evidenceID == base.binding.evidenceID,
                      browser.binding.snapshotSHA256 == base.binding.snapshotSHA256,
                      browser.binding.orderedContainerSHA256 == base.binding.orderedContainerSHA256,
                      let database = browser.receipts.first(where: { $0.role == "database" }), database.fileID == file.id,
                      database.evidencePath == file.path, database.byteCount == file.size,
                      browser.events.allSatisfy({ $0.fileID == file.id && $0.artifactSHA256 == database.sha256 }) else { throw TimelineError.sourceChanged }
                let value = TimelineReport(binding: base.binding, events: FilesystemTimeline.sort(base.events + browser.events), artifactReceipts: browser.receipts,
                    warnings: base.warnings + ["Browser History bytes were freshly extracted and independently verified; visits/download records are parser observations, not proof that a person performed an action.",
                        "Only one selected History database and its explicit recorded sidecars are covered. SQLite deleted/free pages, other browsers and full browser profiles are outside coverage."],
                    coverage: base.coverage + " Chromium History: \(browser.events.count) visit/download events from \(file.path).")
                try TimelineReportExporter.validate(value)
                return (value, browser.events.count)
            }
            let (value, browserCount) = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
            try Task.checkCancellation()
            guard let self, self.generation == id, self.selection == selection else { return }
            self.report = value; self.exportReceipt = nil
            self.phase = "Verified Chromium artifact: \(browserCount.formatted()) parser events added to recorded filesystem timeline."
            self.filter()
        }
    }

    func chooseExport() {
        guard canExport else { return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.canCreateDirectories = true; panel.allowsMultipleSelection = false
        panel.message = "Choose a parent folder outside evidence/case bundles. A new timeline folder will be created."
        let selected = selection
        isPresentingPanel = true
        let response = panel.runModal()
        isPresentingPanel = false
        guard response == .OK, let parent = panel.url, selected == selection, !closing else { return }
        exportReport(to: parent.appendingPathComponent("Timeline-\(UUID().uuidString.lowercased())", isDirectory: true))
    }

    func exportReport(to output: URL) {
        guard canExport, let existing = report, let selection else { return }
        guard examinerNotes.utf8.count <= TimelineLimits.maximumNotesBytes else { errorMessage = "Examiner notes exceed 32 KiB."; return }
        let value = TimelineReport(binding: existing.binding, events: existing.events, artifactReceipts: existing.artifactReceipts,
            warnings: existing.warnings, coverage: existing.coverage, aiInterpretation: nil, examinerNotes: examinerNotes)
        let operation = export
        let forbidden = selection.result.sourcePaths.map { URL(fileURLWithPath: $0) } + [selection.caseURL]
        // Export contains the whole recorded timeline. Search/date filters only
        // change presentation and cannot silently discard report observations.
        start(phase: "Publishing complete timeline JSON/Markdown and hash receipt…", exporting: true) { [weak self] id in
            let receipt = try await operation(value, output, forbidden)
            guard let self, self.generation == id, self.selection == selection else { return }
            guard receipt.snapshotSHA256 == value.binding.snapshotSHA256, receipt.eventCount == value.events.count,
                  receipt.destinationPath == output.standardizedFileURL.path else { throw TimelineError.sourceChanged }
            self.exportReceipt = receipt
            self.phase = "Saved complete timeline: \(receipt.eventCount.formatted()) events, parser facts separate from examiner notes."
        }
    }

    func cancel() {
        for job in jobs.values { job.cancel() }
        for job in filterJobs.values { job.cancel() }
        if isFiltering {
            rows = []; selectedEventID = nil
            phase = "Timeline filtering canceled. Run a new query to show matching rows."
        }
    }
    func reset() { invalidate(); selection = nil; browserCandidates = []; selectedBrowserID = nil; phase = "Choose recorded filesystem results to build a timeline." }
    func beginShutdown() -> Task<Void, Never>? {
        closing = true; invalidate(); selection = nil
        let tasks = Array(jobs.values) + Array(filterJobs.values)
        guard !tasks.isEmpty else { return nil }
        return Task { for task in tasks { await task.value } }
    }

    private func start(phase: String, exporting: Bool = false, operation: @escaping @MainActor (UUID) async throws -> Void) {
        let prior = Array(jobs.values), id = UUID()
        generation = id; isLoading = !exporting; isExporting = exporting; errorMessage = nil; self.phase = phase
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.jobs[id] = nil; if self.generation == id { self.generation = nil; self.isLoading = false; self.isExporting = false } }
            for task in prior { await task.value }
            do { try Task.checkCancellation(); guard self.generation == id, !self.closing else { return }; try await operation(id) }
            catch is CancellationError { if self.generation == id, !self.closing { self.phase = "Timeline job canceled; owned scratch cleanup completed." } }
            catch { if self.generation == id, !self.closing { self.errorMessage = error.localizedDescription; self.phase = "Timeline operation failed; prior report remains available." } }
        }
        jobs[id] = task
    }

    private func invalidate() {
        generation = nil; filterGeneration = nil
        for task in jobs.values { task.cancel() }; for task in filterJobs.values { task.cancel() }
        report = nil; rows = []; isLoading = false; isExporting = false; isFiltering = false; errorMessage = nil
        exportReceipt = nil; examinerNotes = ""; selectedEventID = nil
    }

    private func filter() {
        for task in filterJobs.values { task.cancel() }
        guard let report, !closing else { rows = []; isFiltering = false; return }
        let id = UUID(), filter = TimelineFilter(query: query, from: useDateRange ? from : nil, through: useDateRange ? through : nil, includeUnresolved: includeUnresolved)
        filterGeneration = id; isFiltering = true; selectedEventID = nil
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.filterJobs[id] = nil; if self.filterGeneration == id { self.isFiltering = false } }
            do {
                let worker = Task.detached(priority: .userInitiated) { try filter.apply(to: report.events) }
                let rows = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard self.filterGeneration == id, self.report?.binding == report.binding, !self.closing else { return }
                self.rows = rows
            } catch is CancellationError { } catch { if self.filterGeneration == id { self.errorMessage = error.localizedDescription; self.rows = [] } }
        }
        filterJobs[id] = task
    }

    private struct Selection: Sendable, Equatable { let caseID: UUID; let evidence: EvidenceRecord; let result: EnumerationResult; let historical: Bool; let caseURL: URL }
}
