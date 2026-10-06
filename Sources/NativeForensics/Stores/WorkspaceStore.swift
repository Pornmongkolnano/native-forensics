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
        case .evidence: "Evidence"
        case .filesystem: "Filesystem"
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
    var selectedEvidenceID: UUID?
    var searchText = ""
    var showInspector = true
    var isPresentingPanel = false
    var isInspecting = false
    var progress: InspectionProgress?
    var inspectionFilename: String?
    var statusMessage = "Create a case to inspect a disk image."
    var errorMessage: String?

    var filesystemResults: [UUID: EnumerationResult] = [:]
    var filesystemRows: [FilesystemEntry] = []
    var filesystemFilesByID: [String: FilesystemEntry] = [:]
    var selectedFileID: String?
    var filesystemSearchText = ""
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

    @ObservationIgnored private var inspectionTask: Task<Void, Never>?
    @ObservationIgnored private var inspectionID: UUID?

    var isBusy: Bool { isPresentingPanel || isInspecting || isEngineRunning }
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
            guard let destination = await CasePanelService.newCaseDestination() else { return }
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
            guard let url = await CasePanelService.existingCase() else { return }
            openCase(at: url)
        }
    }

    func openCase(at url: URL) {
        guard !isInspecting && !isEngineRunning else {
            errorMessage = "Wait for the current job to finish, or cancel it before opening a different case."
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
            guard let source = await CasePanelService.imageSource() else { return }
            inspectImage(at: source)
        }
    }

    func inspectImage(at url: URL) {
        guard let forensicCase = currentCase, !isInspecting && !isEngineRunning else { return }
        let jobID = UUID()
        inspectionID = jobID
        inspectionFilename = url.lastPathComponent
        progress = nil
        isInspecting = true
        statusMessage = "Reading selected file bytes…"
        inspectionTask = Task { [weak self] in
            guard let self else { return }
            do {
                let image = try await ImageInspector.inspect(url: url) { [weak self] update in
                    Task { @MainActor [weak self] in
                        guard let self, self.inspectionID == jobID, self.isInspecting else { return }
                        self.progress = update
                    }
                }
                try Task.checkCancellation()
                let updated = try CaseStore.adding(image: image, to: forensicCase)
                self.currentCase = updated
                self.section = .evidence
                self.selectedEvidenceID = updated.manifest.evidence.last?.id
                self.showInspector = true
                self.statusMessage = "Inspection complete. The selected file SHA-256 was saved to the case."
            } catch is CancellationError {
                self.statusMessage = "Inspection cancelled. No evidence record was added."
            } catch {
                self.present(error)
                self.statusMessage = "Inspection failed. No evidence record was added."
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

    private func load(_ forensicCase: ForensicCase) {
        filesystemSelectionID = nil
        filesystemSelectionCaseID = nil
        filesystemResults = [:]
        filesystemRows = []
        filesystemFilesByID = [:]
        selectedFileID = nil
        filesystemSearchText = ""
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
