import Foundation
import ForensicsCore
import Observation

enum WorkspaceSection: String, CaseIterable, Identifiable {
    case evidence
    case filesystem
    case caseDetails

    var id: Self { self }
    var title: String {
        switch self {
        case .evidence: "Data Sources"
        case .filesystem: "File Views"
        case .caseDetails: "Case Details"
        }
    }
    var symbol: String {
        switch self {
        case .evidence: "externaldrive"
        case .filesystem: "list.bullet.rectangle"
        case .caseDetails: "folder"
        }
    }
}

struct EvidenceRow: Identifiable {
    let record: EvidenceRecord
    var id: UUID { record.id }
    var filename: String { URL(fileURLWithPath: record.sourcePath).lastPathComponent }
}

@MainActor
@Observable
final class WorkspaceStore {
    var currentCase: ForensicCase?
    var section: WorkspaceSection? = .evidence
    var selectedEvidenceID: UUID? {
        didSet { if oldValue != selectedEvidenceID { refreshFilesystemSelection() } }
    }
    var searchText = ""
    var showInspector = true
    var isPresentingPanel = false
    private(set) var isClosing = false
    var isInspecting = false
    var progress: InspectionProgress?
    var inspectionFilename: String?
    var statusMessage = "Create a case to inspect a disk image."
    var errorMessage: String?

    var filesystemResults: [UUID: EnumerationResult] = [:]
    var filesystemRows: [FilesystemEntry] = []
    var filesystemFilesByID: [String: FilesystemEntry] = [:]
    var selectedFileID: String?
    var filesystemSearchText = "" {
        didSet { if oldValue != filesystemSearchText { refreshFilesystemRows() } }
    }
    var filesystemCategory: FilesystemCategory = .all {
        didSet { if oldValue != filesystemCategory { refreshFilesystemRows() } }
    }
    var filesystemNavigationShowsCategory = true
    var isFilteringFilesystem = false
    var engineImageType = "auto"
    var engineSectorSize = 0
    var engineMaxFiles = 50_000
    var engineMaxFilesText = "50000" {
        didSet {
            if let value = validatedEngineMaxFiles {
                engineMaxFiles = value
            }
        }
    }
    var additionalImageSegments: [URL] = []
    var evidenceTimezone = "Asia/Bangkok"
    var timestampDisplayTimezone = "UTC"
    var isEngineRunning = false
    var isLoadingFilesystem = false
    var engineOperationLabel = ""
    var engineProgress: EngineProgress?
    var verificationProgress: InspectionProgress?
    var extractionReceipt: ExtractionResult?
    var extractionReceiptIsVerified = false

    @ObservationIgnored var engineTask: Task<Void, Never>?
    @ObservationIgnored var engineJobID: UUID?
    @ObservationIgnored var filesystemLoadTask: Task<Void, Never>?
    @ObservationIgnored var filesystemLoadID: UUID?
    @ObservationIgnored var filesystemSelectionID: UUID?
    @ObservationIgnored var filesystemSelectionCaseID: UUID?
    @ObservationIgnored var filesystemSearchIndex = FilesystemSearchIndex(files: [])
    @ObservationIgnored var filesystemSearchTask: Task<Void, Never>?
    @ObservationIgnored var filesystemSearchID: UUID?

    @ObservationIgnored private var inspectionTask: Task<Void, Never>?
    @ObservationIgnored private var inspectionID: UUID?
    @ObservationIgnored let engineHelperURL: URL
    let assistant = AssistantAnalysisStore()

    init(helperURL: URL? = nil) {
        engineHelperURL = helperURL ?? Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/NFTSKEngine")
    }

    var isBusy: Bool { isClosing || isPresentingPanel || isInspecting || isEngineRunning || assistant.isPresented || assistant.hasActiveWork }
    var hasActiveWork: Bool {
        inspectionTask != nil || engineTask != nil || filesystemLoadTask != nil || filesystemSearchTask != nil || assistant.hasActiveWork
    }
    var canInspectImage: Bool { currentCase != nil && !isBusy }

    var rows: [EvidenceRow] {
        let rows = (currentCase?.manifest.evidence ?? []).map(EvidenceRow.init(record:))
        guard !searchText.isEmpty else { return rows }
        return rows.filter {
            $0.filename.localizedCaseInsensitiveContains(searchText)
                || $0.record.sha256.localizedCaseInsensitiveContains(searchText)
        }
    }

    var selectedEvidence: EvidenceRecord? {
        currentCase?.manifest.evidence.first { $0.id == selectedEvidenceID }
    }

    func createCase() {
        guard !isBusy else { return }
        isPresentingPanel = true
        Task {
            defer { isPresentingPanel = false }
            guard !isClosing else { return }
            guard let destination = await CasePanelService.newCaseDestination(), !isClosing else { return }
            do {
                let name = destination.deletingPathExtension().lastPathComponent
                let created = try CaseStore.create(name: name, in: destination.deletingLastPathComponent())
                load(created)
                statusMessage = "Case created. Add a disk image to record its file size and SHA-256."
            } catch { present(error) }
        }
    }

    func chooseCase() {
        guard !isBusy else { return }
        isPresentingPanel = true
        Task {
            defer { isPresentingPanel = false }
            guard !isClosing else { return }
            guard let url = await CasePanelService.existingCase(), !isClosing else { return }
            isPresentingPanel = false
            openCase(at: url)
        }
    }

    func openCase(at url: URL) {
        guard !isBusy else {
            errorMessage = "Finish or cancel the current job or file dialog before opening a different case."
            return
        }
        do {
            load(try CaseStore.open(at: url))
            statusMessage = "Case opened. Evidence records describe the files at the time they were inspected."
        } catch { present(error) }
    }

    func chooseImage() {
        guard canInspectImage else { return }
        isPresentingPanel = true
        Task {
            defer { isPresentingPanel = false }
            guard !isClosing else { return }
            guard let source = await CasePanelService.imageSource(), !isClosing else { return }
            isPresentingPanel = false
            inspectImage(at: source)
        }
    }

    func inspectImage(at url: URL) {
        guard let forensicCase = currentCase, !isBusy else { return }
        let jobID = UUID()
        inspectionID = jobID
        inspectionFilename = url.lastPathComponent
        progress = nil
        isInspecting = true
        statusMessage = "Reading selected file bytes…"
        inspectionTask = Task { [weak self] in
            guard let self else { return }
            var recordWasSaved = false
            do {
                let image = try await ImageInspector.inspect(url: url) { [weak self] update in
                    Task { @MainActor [weak self] in
                        guard let self, self.inspectionID == jobID, self.isInspecting else { return }
                        self.progress = update
                    }
                }
                try Task.checkCancellation()
                // Waiting for the case lock and publishing the manifest must not
                // block the UI actor. Once started, this atomic commit is drained
                // during close/quit even if cancellation arrives meanwhile.
                let updated = try await Task.detached(priority: .utility) {
                    try CaseStore.adding(image: image, to: forensicCase)
                }.value
                recordWasSaved = true
                self.currentCase = updated
                self.section = .evidence
                self.selectedEvidenceID = updated.manifest.evidence.last?.id
                self.showInspector = true
                self.statusMessage = "Inspection complete. The selected file SHA-256 was saved to the case."
                try Task.checkCancellation()
            } catch is CancellationError {
                self.statusMessage = recordWasSaved
                    ? "The evidence record was saved before cancellation completed."
                    : "Inspection cancelled. No evidence record was added."
            } catch {
                self.present(error)
                self.statusMessage = "Inspection failed. Reopen the case to confirm its saved evidence records before retrying."
            }
            guard self.inspectionID == jobID else { return }
            self.isInspecting = false
            self.inspectionFilename = nil
            self.progress = nil
            self.inspectionTask = nil
            self.inspectionID = nil
        }
    }

    func cancelInspection() {
        guard isInspecting else { return }
        statusMessage = "Cancelling inspection…"
        inspectionTask?.cancel()
    }

    /// Immediately prevents a dismissed panel or a menu command from starting
    /// another operation while the window/app is closing.
    func prepareForClosing() {
        isClosing = true
        assistant.prepareForTermination()
    }

    /// Awaiting the owning tasks also drains their detached workers and native
    /// helper cleanup. Cancellation alone does not make an in-flight write stop.
    func beginShutdown() -> [Task<Void, Never>] {
        prepareForClosing()
        let pending = [inspectionTask, engineTask, filesystemLoadTask, filesystemSearchTask, assistant.beginShutdown()].compactMap { $0 }
        cancelCurrentJob()
        return pending
    }

    func shutdown() async {
        let pending = beginShutdown()
        for task in pending { await task.value }
    }

    private func load(_ forensicCase: ForensicCase) {
        errorMessage = nil
        cancelFilesystemSearch()
        filesystemSearchIndex = FilesystemSearchIndex(files: [])
        filesystemSelectionID = nil
        filesystemSelectionCaseID = nil
        filesystemResults = [:]
        filesystemRows = []
        filesystemFilesByID = [:]
        selectedFileID = nil
        filesystemSearchText = ""
        filesystemCategory = .all
        filesystemNavigationShowsCategory = true
        additionalImageSegments = []
        extractionReceipt = nil
        extractionReceiptIsVerified = false
        currentCase = forensicCase
        section = .evidence
        searchText = ""
        selectedEvidenceID = forensicCase.manifest.evidence.first?.id
        refreshFilesystemSelection()
    }

    private func present(_ error: Error) {
        errorMessage = error.localizedDescription
    }
}
