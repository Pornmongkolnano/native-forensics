import AppKit
import CryptoKit
import Foundation
import ForensicsCore
import Observation

enum APFSWorkspaceState: Equatable { case idle, loading, discovering, inspecting, previewing, exporting, cancelling }

struct APFSWorkspaceCache: Sendable {
    let result: APFSInspectionResult
    let receipt: APFSCacheReceipt
}

struct APFSWorkspaceSnapshotInventory: Sendable, Equatable {
    let evidenceID: UUID
    let containerSHA256: String
    let volumeUUID: UUID
    let containerEncryption: APFSContainerEncryption
    let volumeEncryption: APFSVolumeEncryption
    let entries: [APFSSnapshotInventoryEntry]
    let isAvailable: Bool
    let isHistorical: Bool
}

/// The system APFS view has its own source binding, persistence and lifetime.
/// It never enters the TSK EngineClient/listing cache. Credentials exist only
/// in each task's single-use arguments, not observable or serializable state.
@MainActor
@Observable
final class APFSWorkspaceStore {
    typealias Load = @Sendable (EvidenceRecord, ForensicCase) async throws -> APFSWorkspaceCache?
    typealias Discover = @Sendable (EvidenceRecord, APFSReadOptions, APFSPassphrase?) async throws -> APFSVolumeCatalogResult
    typealias Inspect = @Sendable (EvidenceRecord, APFSReadOptions, APFSPassphrase?, APFSPassphrase?) async throws -> APFSInspectionResult
    typealias Save = @Sendable (APFSInspectionResult, ForensicCase) async throws -> APFSCacheReceipt
    typealias Preview = @Sendable (EvidenceRecord, APFSInspectionResult, APFSFileEntry, APFSPassphrase?, APFSPassphrase?, URL) async throws -> DocumentAnalysis
    typealias Export = @Sendable (EvidenceRecord, APFSInspectionResult, APFSFileEntry, ForensicCase, URL, APFSPassphrase?, APFSPassphrase?) async throws -> APFSExportReceipt
    typealias RecordProvenance = @Sendable (APFSInspectionResult, APFSCacheReceipt, Date, ForensicCase) async throws -> ForensicCase?

    private(set) var result: APFSInspectionResult?
    private(set) var cacheReceipt: APFSCacheReceipt?
    private(set) var rows: [APFSFileEntry] = []
    private(set) var volumeCatalog: APFSVolumeCatalogResult?
    private(set) var snapshotInventory: APFSWorkspaceSnapshotInventory?
    var selectedVolumeUUID: UUID? { didSet { if oldValue != selectedVolumeUUID, !restoringVolumeSelection { changeVolumeSelection() } } }
    var selectedSnapshotUUID: UUID? { didSet { if oldValue != selectedSnapshotUUID, !restoringVolumeSelection { changeSnapshotSelection() } } }
    private(set) var jobBindingID = UUID()
    var selectedEntryPath: String? { didSet { if oldValue != selectedEntryPath { resetPreview() } } }
    var searchText = "" { didSet { if oldValue != searchText { refreshRows() } } }
    var maximumEntries = 50_000 { didSet { if oldValue != maximumEntries { jobBindingID = UUID() } } }
    private(set) var analysis: DocumentAnalysis?
    var contentQuery = "" { didSet { refreshContentSearch() } }
    private(set) var searchOutcome: DocumentSearchOutcome?
    private(set) var state: APFSWorkspaceState = .idle
    private(set) var isHistorical = false
    private(set) var isFiltering = false
    private(set) var statusMessage = "Select a recorded source to inspect its allocated APFS view."
    private(set) var errorMessage: String?
    private(set) var lastExport: APFSExportReceipt?
    private(set) var lastExportDestination: URL?
    /// Cleanup is a workspace lifetime fact, even if the job's source/entry
    /// was superseded or shutdown has already invalidated its publication.
    private(set) var cleanupUncertain = false
    private(set) var previewCleanupBlocked = false
    @ObservationIgnored var caseDidUpdate: (@MainActor @Sendable (ForensicCase, ForensicCase) -> Bool)?

    @ObservationIgnored private let documentHelperURL: URL
    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    @ObservationIgnored private let hasInjectedPreview: Bool
    @ObservationIgnored private let hasInjectedInspection: Bool
    @ObservationIgnored private let hasInjectedExport: Bool
    @ObservationIgnored private let hasInjectedDiscovery: Bool
    @ObservationIgnored private let loadRequest: Load
    @ObservationIgnored private let discoverRequest: Discover
    @ObservationIgnored private let inspectRequest: Inspect
    @ObservationIgnored private let saveRequest: Save
    @ObservationIgnored private let previewRequest: Preview
    @ObservationIgnored private let exportRequest: Export
    @ObservationIgnored private let recordRequest: RecordProvenance
    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var previewID: UUID?
    @ObservationIgnored private var previewCancellationID: UUID?
    @ObservationIgnored private var filterID: UUID?
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private var restoringVolumeSelection = false
    @ObservationIgnored private(set) var activeTask: Task<Void, Never>?
    private var jobs: [UUID: Task<Void, Never>] = [:]

    init(documentHelperURL: URL? = nil, scheduler: ForensicWorkScheduler = .shared,
         load: Load? = nil, discover: Discover? = nil, inspect: Inspect? = nil, save: Save? = nil,
         preview: Preview? = nil, export: Export? = nil, recordProvenance: RecordProvenance? = nil) {
        self.documentHelperURL = documentHelperURL ?? Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder")
        self.scheduler = scheduler
        hasInjectedPreview = preview != nil
        hasInjectedInspection = inspect != nil; hasInjectedExport = export != nil; hasInjectedDiscovery = discover != nil
        loadRequest = load ?? { evidence, forensicCase in
            guard let value = try APFSResultStore.loadLatestRecord(in: forensicCase, evidenceID: evidence.id) else { return nil }
            return APFSWorkspaceCache(result: value.result, receipt: value.receipt)
        }
        discoverRequest = discover ?? { evidence, options, passphrase in
            try await APFSMountedImageAdapter().discoverVolumes(evidence: evidence, passphrase: passphrase, options: options)
        }
        inspectRequest = inspect ?? { evidence, options, passphrase, volumePassphrase in
            try await APFSMountedImageAdapter().inspect(evidence: evidence, passphrase: passphrase,
                volumePassphrase: volumePassphrase, options: options)
        }
        saveRequest = save ?? { result, forensicCase in try APFSResultStore.save(result, in: forensicCase) }
        previewRequest = preview ?? { evidence, result, entry, passphrase, volumePassphrase, helper in
            try await APFSPreviewService.preview(evidence: evidence, inspection: result, entry: entry,
                passphrase: passphrase, volumePassphrase: volumePassphrase, documentHelperURL: helper)
        }
        exportRequest = export ?? { evidence, result, entry, forensicCase, destination, passphrase, volumePassphrase in
            try await APFSExportService.export(evidence: evidence, inspection: result, entry: entry,
                in: forensicCase, to: destination, passphrase: passphrase, volumePassphrase: volumePassphrase)
        }
        recordRequest = recordProvenance ?? { result, receipt, startedAt, forensicCase in
            guard forensicCase.manifest.schemaVersion == 2 else { return nil }
            let job = try APFSResultStore.jobProvenance(result: result, receipt: receipt, startedAt: startedAt)
            return try CaseStore.recording(job: job, in: forensicCase)
        }
    }

    var selectedSourceFilename: String { selection.map { URL(fileURLWithPath: $0.evidence.sourcePath).lastPathComponent } ?? "No data source" }
    var selectedEvidenceID: UUID? { selection?.evidence.id }
    var selectedCaseID: UUID? { selection?.forensicCase.manifest.id }
    var selectedEntry: APFSFileEntry? { result?.entries.first { $0.relativePath == selectedEntryPath } }
    var hasSource: Bool { selection != nil }
    var hasActiveWork: Bool { !jobs.isEmpty }
    var canDiscoverVolumes: Bool { sourceUnavailableReason == nil && !hasActiveWork && !isClosing }
    func acquireImmediateAdmission() async throws -> ForensicWorkPermit {
        guard !isClosing else { throw ForensicSchedulingError.closed }
        guard !hasActiveWork else { throw ForensicSchedulingError.busy }
        guard !cleanupUncertain else { throw APFSReadError.cleanupIncomplete }
        return try await scheduler.acquireImmediately(.apfsRead)
    }
    var cleanupWarning: String? {
        if cleanupUncertain {
            return "APFS image cleanup could not be confirmed. The owned private backing copy was retained for quarantine. Fresh APFS inspection, preview and export are blocked in this workspace. Reload Saved Result to review historical metadata. Reopening the case does not confirm cleanup; the retained owned quarantine requires review before another live read."
        }
        if previewCleanupBlocked { return APFSPreviewError.cleanupIncomplete.localizedDescription }
        return nil
    }
    var canInspect: Bool { selection != nil && inspectionUnavailableReason == nil && !hasActiveWork && !isClosing }
    var inspectionUnavailableReason: String? {
        if let reason = sourceUnavailableReason { return reason }
        if let catalog = volumeCatalog {
            if let selectedVolumeUUID, !catalog.volumes.contains(where: { $0.volumeUUID == selectedVolumeUUID }) {
                return "The selected APFS volume UUID is absent from the verified catalog. Find volumes again or choose a recorded UUID."
            }
            if catalog.volumes.count > 1, selectedVolumeUUID == nil {
                return "Choose an APFS volume UUID before inspecting this image's allocated view."
            }
        }
        return snapshotSelectionUnavailableReason
    }
    var snapshotSelectionUnavailableReason: String? {
        guard let selectedSnapshotUUID else { return nil }
        guard let inventory = snapshotInventory, inventory.isAvailable else {
            return "Snapshot content selection is unavailable without a verified inventory for this volume. Inspect Current Volume first."
        }
        guard inventory.evidenceID == selection?.evidence.id,
              inventory.containerSHA256 == selection?.evidence.sha256,
              selectedVolumeUUID == nil || inventory.volumeUUID == selectedVolumeUUID else {
            return "The snapshot inventory belongs to a different source or volume. Inspect Current Volume again."
        }
        guard inventory.volumeEncryption == .none else {
            return "Snapshot content requires an unencrypted APFS volume. Snapshots from encrypted APFS volumes remain unverified; Current Volume is still selectable."
        }
        guard inventory.entries.contains(where: { $0.uuid == selectedSnapshotUUID }) else {
            return "The selected snapshot UUID is absent from this recorded inventory. Choose a recorded snapshot or Current Volume."
        }
        return nil
    }
    private var requestedSnapshot: APFSSnapshotInventoryEntry? {
        guard snapshotSelectionUnavailableReason == nil, let selectedSnapshotUUID else { return nil }
        return snapshotInventory?.entries.first { $0.uuid == selectedSnapshotUUID }
    }
    private var hasBoundResultView: Bool {
        guard let result else { return false }
        return (selectedVolumeUUID == nil || selectedVolumeUUID == result.volumeUUID)
            && result.options.selectedSnapshotUUID == selectedSnapshotUUID
            && result.selectedSnapshot == requestedSnapshot
    }
    private var sourceUnavailableReason: String? {
        if cleanupUncertain { return "Fresh APFS reads are blocked because owned image cleanup remains unconfirmed." }
        guard let evidence = selection?.evidence else { return "Select a recorded disk-image source first." }
        if evidence.container == .ewf { return "This separate APFS view supports one disk-image file, rather than an EWF segment set." }
        if evidence.hashScope != FileHashScope.selectedFileBytes || evidence.byteCount <= 0 || evidence.byteCount > APFSReadOptions().maximumContainerBytes {
            return "The source requires a complete selected-file SHA-256 receipt within the APFS input limit."
        }
        if !(1...50_000).contains(maximumEntries) { return "The APFS entry limit must be between 1 and 50,000." }
        return nil
    }
    var documentUnavailableReason: String? {
        if cleanupUncertain { return "Fresh APFS reads are blocked because owned image cleanup remains unconfirmed." }
        if previewCleanupBlocked { return APFSPreviewError.cleanupIncomplete.localizedDescription }
        if result != nil, !hasBoundResultView { return "Inspect the selected APFS volume and snapshot before reading file bytes." }
        guard let entry = selectedEntry, entry.kind == .regular, entry.sha256 != nil else {
            return "Select a completely verified regular file to preview its content."
        }
        if entry.byteCount > DocumentLimits.maximumInputBytes { return "Document preview supports complete files up to 128 MiB." }
        if !hasInjectedPreview && !DocumentAnalysisClient(helperURL: documentHelperURL).isAvailable { return DocumentAnalysisError.unavailable.localizedDescription }
        return nil
    }
    var canPreview: Bool { result != nil && documentUnavailableReason == nil && !hasActiveWork && !isClosing }
    var canExport: Bool { !cleanupUncertain && hasBoundResultView && selectedEntry?.kind == .regular && selectedEntry?.sha256 != nil && !hasActiveWork && !isClosing }

    func configure(evidence: EvidenceRecord?, in forensicCase: ForensicCase?) {
        guard !isClosing else { return }
        if let selection, selection.evidence == evidence, selection.forensicCase.manifest.id == forensicCase?.manifest.id,
           selection.forensicCase.bundleURL == forensicCase?.bundleURL {
            if let forensicCase {
                if forensicCase.manifest != selection.forensicCase.manifest { jobBindingID = UUID() }
                self.selection = Selection(evidence: selection.evidence, forensicCase: forensicCase)
            }
            return
        }
        _ = invalidate()
        selection = nil; volumeCatalog = nil; snapshotInventory = nil
        restoreViewSelection(volume: nil, snapshot: nil)
        result = nil; cacheReceipt = nil; rows = []; selectedEntryPath = nil
        searchText = ""; isHistorical = false; lastExport = nil; lastExportDestination = nil
        statusMessage = cleanupWarning ?? (jobs.isEmpty ? "Select a recorded source to inspect its allocated APFS view."
            : "Waiting for previous APFS work to release its owned storage…")
        guard let evidence, let forensicCase else { return }
        selection = Selection(evidence: evidence, forensicCase: forensicCase)
        refresh()
    }

    func refresh() {
        guard let selection, !isClosing else { return }
        let previous = invalidate(), id = UUID(), operation = loadRequest
        generation = id; state = .loading; statusMessage = "Loading the saved APFS inspection…"
        let task = Task { [weak self] in
            guard let self else { return }; defer { self.finish(id) }
            for job in previous { await job.value }
            do {
                let cached = try await self.scheduler.run(.historyRead) { _ in
                    let value = try await operation(selection.evidence, selection.forensicCase)
                    if let value { try Self.verify(value, selection) }
                    return value
                }
                try Task.checkCancellation()
                guard self.matches(id, selection) else { return }
                self.restoreViewSelection(volume: cached?.result.options.selectedVolumeUUID, snapshot: cached?.result.options.selectedSnapshotUUID)
                self.result = cached?.result; self.cacheReceipt = cached?.receipt
                self.snapshotInventory = cached.map { Self.inventory($0.result, historical: true) }
                self.isHistorical = cached != nil; self.refreshRows()
                self.statusMessage = cached == nil
                    ? (self.cleanupUncertain ? "No saved APFS inspection is available. Live reads remain blocked pending cleanup review."
                        : "No APFS inspection is saved. Inspect the selected supported disk image.")
                    : (self.cleanupUncertain ? "Historical APFS metadata loaded. Live reads remain blocked pending cleanup review."
                        : "Historical APFS result loaded. Preview and export verify the source again.")
            } catch is CancellationError {
                if self.matches(id, selection) { self.statusMessage = "Loading the saved APFS result canceled." }
            } catch { self.fail(error, id: id, selection: selection, message: "Saved APFS inspection could not be loaded.") }
        }
        jobs[id] = task; activeTask = task
    }

    @discardableResult
    func discoverVolumes(passphrase: APFSPassphrase? = nil, permit: ForensicWorkPermit? = nil) -> Bool {
        guard canDiscoverVolumes, let selection, accepts(permit, injected: hasInjectedDiscovery) else { return false }
        let id = UUID(), binding = jobBindingID, operation = discoverRequest
        let options = APFSReadOptions(maximumEntries: maximumEntries)
        generation = id; state = .discovering; errorMessage = nil
        statusMessage = "Verifying the source and finding bounded APFS volume metadata…"
        startOwnedTask(id: id, permit: permit) { [self] in
            do {
                let catalog = try await Self.work(permit: permit) { try await operation(selection.evidence, options, passphrase) }
                try Task.checkCancellation(); try catalog.validate(evidence: selection.evidence)
                guard self.matches(id, selection), self.jobBindingID == binding else { return }
                guard catalog.options == options else { throw APFSReadError.invalidResult }
                self.volumeCatalog = catalog
                if let chosen = self.selectedVolumeUUID, !catalog.volumes.contains(where: { $0.volumeUUID == chosen }) {
                    self.restoreViewSelection(volume: nil, snapshot: nil); self.snapshotInventory = nil
                    self.result = nil; self.cacheReceipt = nil; self.rows = []; self.selectedEntryPath = nil
                    self.isHistorical = false; self.lastExport = nil; self.lastExportDestination = nil
                }
                self.statusMessage = "APFS volume metadata verified: \(catalog.volumes.count.formatted()) volumes. No file content was read."
            } catch is CancellationError {
                if self.matches(id, selection) { self.statusMessage = "APFS volume discovery canceled after owned image cleanup." }
            } catch { self.fail(error, id: id, selection: selection, message: "APFS volume discovery did not complete. Previous saved results were preserved.") }
        }
        return true
    }

    @discardableResult
    func inspect(passphrase: APFSPassphrase? = nil, volumePassphrase: APFSPassphrase? = nil, permit: ForensicWorkPermit? = nil) -> Bool {
        guard canInspect, let selection, accepts(permit, injected: hasInjectedInspection) else { return false }
        let id = UUID(), operation = inspectRequest, save = saveRequest, record = recordRequest
        let options = APFSReadOptions(maximumEntries: maximumEntries, selectedVolumeUUID: selectedVolumeUUID,
                                      selectedSnapshotUUID: selectedSnapshotUUID), startedAt = Date()
        let requestedSnapshot = self.requestedSnapshot
        let snapshotVolumeUUID = requestedSnapshot == nil ? nil : snapshotInventory?.volumeUUID
        generation = id; state = .inspecting; errorMessage = nil; resetPreview()
        statusMessage = "Verifying the recorded source and inspecting its read-only APFS view…"
        startOwnedTask(id: id, permit: permit) { [self] in
            do {
                let value = try await Self.work(permit: permit) {
                    let value = try await operation(selection.evidence, options, passphrase, volumePassphrase)
                    try Task.checkCancellation(); try APFSMountedImageAdapter.validate(value, evidence: selection.evidence)
                    guard value.options == options else { throw APFSReadError.invalidResult }
                    guard value.selectedSnapshot == requestedSnapshot,
                          snapshotVolumeUUID == nil || value.volumeUUID == snapshotVolumeUUID else { throw APFSReadError.invalidResult }
                    return value
                }
                try Task.checkCancellation()
                let receipt = try await Self.work(permit: permit, atomic: true) {
                    let receipt = try await save(value, selection.forensicCase)
                    try Self.verify(APFSWorkspaceCache(result: value, receipt: receipt), selection)
                    return receipt
                }
                // Save's successful receipt is past atomic publication. A late
                // cancel cannot erase it or invent an uncommitted failure.
                guard self.matches(id, selection) else { return }
                self.result = value; self.cacheReceipt = receipt; self.isHistorical = false
                self.snapshotInventory = Self.inventory(value, historical: false)
                self.selectedEntryPath = nil; self.lastExport = nil; self.lastExportDestination = nil
                self.refreshRows()
                self.statusMessage = Task.isCancelled ? "APFS inspection was saved before cancellation finished."
                    : "APFS inspection saved: \(value.entries.count.formatted()) allocated entries."
                if !Task.isCancelled {
                    do {
                        let publicationCase = self.selection?.forensicCase ?? selection.forensicCase
                        let updated = try await Self.work(permit: permit, atomic: true) { try await record(value, receipt, startedAt, publicationCase) }
                        guard self.matches(id, selection) else { return }
                        guard self.selection?.forensicCase.manifest == publicationCase.manifest else {
                            self.statusMessage = "APFS inspection saved. A newer case revision is selected; reload the case to review its latest job provenance."
                            return
                        }
                        if let updated {
                            guard updated.manifest.id == selection.forensicCase.manifest.id,
                                  updated.bundleURL == selection.forensicCase.bundleURL,
                                  updated.manifest.evidence.contains(selection.evidence) else { throw APFSReadError.invalidResult }
                            guard self.caseDidUpdate?(publicationCase, updated) ?? true else {
                                self.statusMessage = "APFS inspection saved. The workspace has a newer case revision; its manifest was preserved."
                                return
                            }
                            self.selection = Selection(evidence: selection.evidence, forensicCase: updated)
                        }
                    } catch {
                        self.recordCleanupFailure(error)
                        guard self.matches(id, selection) else { return }
                        self.errorMessage = "The APFS inspection was saved, but the case job provenance update could not be confirmed. Reload the case before retrying."
                    }
                }
            } catch let error as CasePublicationError {
                guard self.matches(id, selection) else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "APFS inspection was published, but durable completion could not be confirmed. Reload the saved result before inspecting again."
            } catch is CancellationError {
                if self.matches(id, selection) { self.statusMessage = "APFS inspection canceled after owned image cleanup. Previous saved results remain available." }
            } catch { self.fail(error, id: id, selection: selection, message: "APFS inspection did not complete. Previous saved results were preserved.") }
        }
        return true
    }

    @discardableResult
    func previewSelected(passphrase: APFSPassphrase? = nil, volumePassphrase: APFSPassphrase? = nil, permit: ForensicWorkPermit? = nil) -> Bool {
        guard canPreview, let selection, let result, let entry = selectedEntry,
              accepts(permit, injected: hasInjectedPreview) else { return false }
        guard credentialsAvailable(result, passphrase, volumePassphrase) else { rejectCredentialCapture(); return false }
        let id = UUID(), operation = previewRequest, helper = documentHelperURL
        generation = id; previewID = id; state = .previewing; analysis = nil; errorMessage = nil
        contentQuery = ""; searchOutcome = nil; statusMessage = "Verifying fresh APFS file bytes and decoding supported content locally…"
        startOwnedTask(id: id, permit: permit) { [self] in
            do {
                let value = try await Self.work(permit: permit) { try await operation(selection.evidence, result, entry, passphrase, volumePassphrase, helper) }
                try Task.checkCancellation()
                guard self.matches(id, selection), self.selectedEntryPath == entry.relativePath, self.result == result else { return }
                guard value.sourceSHA256 == entry.sha256, value.sourceByteCount == entry.byteCount else { throw DocumentAnalysisError.integrityMismatch }
                self.analysis = value
                self.statusMessage = value.status == .decoded ? "Fresh APFS file bytes verified; supported content decoded locally."
                    : "Fresh APFS bytes verified; content requires further examination."
            } catch is CancellationError {
                if self.matches(id, selection), self.selectedEntryPath == entry.relativePath, self.result == result {
                    self.statusMessage = "APFS preview canceled after owned temporary storage cleanup."
                }
            } catch {
                self.recordCleanupFailure(error)
                guard self.selectedEntryPath == entry.relativePath, self.result == result else { return }
                self.fail(error, id: id, selection: selection, message: "APFS preview could not be verified.")
            }
        }
        return true
    }

    @discardableResult
    func exportSelected(to destination: URL, passphrase: APFSPassphrase? = nil, volumePassphrase: APFSPassphrase? = nil, permit: ForensicWorkPermit? = nil) -> Bool {
        guard canExport, let selection, let result, let entry = selectedEntry,
              accepts(permit, injected: hasInjectedExport) else { return false }
        guard credentialsAvailable(result, passphrase, volumePassphrase) else { rejectCredentialCapture(); return false }
        let id = UUID(), operation = exportRequest
        generation = id; state = .exporting; errorMessage = nil; lastExport = nil; lastExportDestination = nil
        statusMessage = "Verifying fresh APFS bytes and exporting a new file…"
        startOwnedTask(id: id, permit: permit) { [self] in
            do {
                let receipt = try await Self.work(permit: permit) { try await operation(selection.evidence, result, entry,
                    selection.forensicCase, destination, passphrase, volumePassphrase) }
                guard self.matches(id, selection), self.result == result else { return }
                try Self.verifyExport(receipt, caseID: selection.forensicCase.manifest.id,
                    resultSHA256: self.cacheReceipt?.resultSHA256, evidence: selection.evidence, result: result, entry: entry)
                self.lastExport = receipt; self.lastExportDestination = destination
                self.statusMessage = Task.isCancelled ? "The verified APFS export completed before cancellation finished."
                    : "APFS export complete; current file bytes independently verified."
            } catch is CancellationError {
                if self.matches(id, selection) { self.statusMessage = "APFS export canceled. No incomplete file was published." }
            } catch { self.fail(error, id: id, selection: selection, message: "APFS export could not be confirmed. Existing files were preserved.") }
        }
        return true
    }

    func rejectCredentialCapture() {
        errorMessage = "Enter a valid credential for each encrypted layer. Credentials are used only for this job and must be entered again for another read."
    }
    func cancel() {
        jobBindingID = UUID()
        for task in jobs.values { task.cancel() }
        if isFiltering { searchText = "" }
        if hasActiveWork { state = .cancelling; statusMessage = "Canceling APFS work and waiting for owned image cleanup…" }
    }
    func reset(reopen: Bool = false) {
        _ = invalidate(); selection = nil; volumeCatalog = nil; snapshotInventory = nil
        restoreViewSelection(volume: nil, snapshot: nil)
        result = nil; cacheReceipt = nil; rows = []; selectedEntryPath = nil
        searchText = ""; isHistorical = false; lastExport = nil; lastExportDestination = nil
        statusMessage = cleanupWarning ?? "Select a recorded source to inspect its allocated APFS view."
        if reopen { isClosing = false }
    }
    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true; let pending = invalidate(); selection = nil; result = nil; rows = []
        statusMessage = cleanupWarning ?? (pending.isEmpty ? "APFS workspace closed." : "Waiting for APFS work to release its owned storage…")
        guard !pending.isEmpty else { return nil }
        return Task { for job in pending { await job.value } }
    }
    func waitForPendingWork() async { let pending = Array(jobs.values); for job in pending { await job.value } }
    func copySelectedHash() {
        guard let hash = selectedEntry?.sha256 else { return }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(hash, forType: .string)
    }

    private func refreshRows() {
        if let filterID { jobs[filterID]?.cancel() }; filterID = nil; isFiltering = false
        let entries = result?.entries ?? [], query = searchText
        if query.isEmpty { rows = entries; clearInvisibleSelection(); return }
        let id = UUID(), selectedResult = result
        filterID = id; isFiltering = true
        let task = Task { [weak self] in
            guard let self else { return }
            defer {
                self.jobs[id] = nil
                if self.filterID == id { self.filterID = nil; self.isFiltering = false }
                if self.jobs.isEmpty, self.state == .cancelling {
                    self.state = .idle; self.statusMessage = "APFS path filtering canceled."
                }
            }
            do {
                try await Task.sleep(for: .milliseconds(120))
                let filtered = try await Self.work {
                    var matches: [APFSFileEntry] = []
                    for (index, entry) in entries.enumerated() {
                        if index.isMultiple(of: 128) { try Task.checkCancellation() }
                        if entry.relativePath.localizedStandardContains(query) || (entry.sha256?.localizedStandardContains(query) ?? false) { matches.append(entry) }
                    }
                    return matches
                }
                guard self.filterID == id, self.result == selectedResult, !self.isClosing else { return }
                self.rows = filtered; self.clearInvisibleSelection()
            } catch { /* A superseding query or source owns publication. */ }
        }
        jobs[id] = task
    }
    private func clearInvisibleSelection() { if let selectedEntryPath, !rows.contains(where: { $0.relativePath == selectedEntryPath }) { self.selectedEntryPath = nil } }
    private func resetPreview() {
        if let previewID {
            jobs[previewID]?.cancel()
            if generation == previewID {
                previewCancellationID = previewID
                state = .cancelling
                statusMessage = "The APFS entry changed; stopping the previous preview and cleaning its owned storage…"
            }
        }
        previewID = nil; analysis = nil; contentQuery = ""; searchOutcome = nil
    }
    private func refreshContentSearch() { searchOutcome = analysis.flatMap { contentQuery.isEmpty ? nil : DocumentContentSearch.search(contentQuery, in: $0) } }
    @discardableResult private func invalidate() -> [Task<Void, Never>] {
        jobBindingID = UUID()
        generation = nil; resetPreview(); filterID = nil
        previewCancellationID = nil
        for task in jobs.values { task.cancel() }
        let previous = Array(jobs.values)
        activeTask = nil; state = .idle; isFiltering = false; errorMessage = nil
        return previous
    }
    private func finish(_ id: UUID) {
        jobs[id] = nil
        if jobs.isEmpty, selection == nil {
            statusMessage = cleanupWarning ?? (isClosing ? "APFS workspace closed." : "Select a recorded source to inspect its allocated APFS view.")
        }
        if previewID == id { previewID = nil }
        if previewCancellationID == id {
            previewCancellationID = nil
            statusMessage = cleanupWarning ?? "Previous APFS preview stopped after the entry changed."
        }
        guard generation == id else { return }
        generation = nil; activeTask = nil; state = .idle
    }
    private func matches(_ id: UUID, _ selection: Selection) -> Bool { generation == id && self.selection == selection && !isClosing }
    private func fail(_ error: Error, id: UUID, selection: Selection, message: String) {
        recordCleanupFailure(error)
        guard matches(id, selection) else { return }
        errorMessage = Self.safeError(error); statusMessage = message
    }
    private func recordCleanupFailure(_ error: Error) {
        if error as? APFSReadError == .cleanupIncomplete { cleanupUncertain = true }
        if error as? APFSPreviewError == .cleanupIncomplete { previewCleanupBlocked = true }
    }
    nonisolated private static func safeError(_ error: Error) -> String {
        if let error = error as? APFSReadError {
            if case .unsupported = error { return "The selected APFS image combination is not supported by this allocated view." }
            return error.localizedDescription
        }
        if let error = error as? DocumentAnalysisError { return error.localizedDescription }
        if let error = error as? APFSPreviewError { return error.localizedDescription }
        return "The APFS operation could not be verified. Reload the recorded case and source before retrying."
    }
    private func credentialsAvailable(_ result: APFSInspectionResult, _ container: APFSPassphrase?, _ volume: APFSPassphrase?) -> Bool {
        (result.containerEncryption == .none || container != nil) && (result.volumeEncryption == .none || volume != nil)
    }
    nonisolated private static func verify(_ cached: APFSWorkspaceCache, _ selection: Selection) throws {
        try APFSMountedImageAdapter.validate(cached.result, evidence: selection.evidence)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let serialized = try encoder.encode(cached.result)
        let digest = SHA256.hash(data: serialized).map { String(format: "%02x", $0) }.joined()
        guard cached.receipt.schemaVersion == 1, cached.receipt.caseID == selection.forensicCase.manifest.id,
              cached.receipt.evidenceID == selection.evidence.id, cached.receipt.coverage == cached.result.coverage,
              cached.receipt.serializedByteCount > 0, cached.receipt.serializedByteCount <= APFSResultStore.maximumResultBytes,
              cached.receipt.serializedByteCount == serialized.count, cached.receipt.resultSHA256 == digest,
              cached.receipt.relativePath == "apfs/\(selection.evidence.id.uuidString.lowercased())/generations/\(cached.receipt.generationID.uuidString.lowercased())/result.json" else {
            throw APFSReadError.invalidResult
        }
    }
    nonisolated private static func verifyExport(_ receipt: APFSExportReceipt, caseID: UUID, resultSHA256: String?, evidence: EvidenceRecord, result: APFSInspectionResult, entry: APFSFileEntry) throws {
        guard receipt.caseID == caseID, receipt.resultSHA256 == resultSHA256,
              receipt.containerHashScope == FileHashScope.selectedFileBytes, receipt.outputHashScope == "logical-APFS-file-bytes",
              receipt.evidenceID == evidence.id, receipt.containerSHA256 == evidence.sha256,
              receipt.volumeUUID == result.volumeUUID, receipt.relativePath == entry.relativePath,
              receipt.selectedSnapshot == result.selectedSnapshot,
              receipt.byteCount == entry.byteCount, receipt.sha256 == entry.sha256 else { throw APFSReadError.invalidResult }
    }
    nonisolated private static func work<T: Sendable>(permit: ForensicWorkPermit? = nil, atomic: Bool = false,
                                                     _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        if let permit {
            if atomic { return try await permit.runToCompletion(operation) }
            return try await permit.run(operation)
        }
        try Task.checkCancellation()
        let worker = Task.detached(priority: .userInitiated) { try Task.checkCancellation(); return try await operation() }
        if atomic { return try await worker.value }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }
    private func accepts(_ permit: ForensicWorkPermit?, injected: Bool) -> Bool {
        if let permit { return permit.admission.kind == .apfsRead }
        guard injected else {
            errorMessage = "APFS read admission is required before credentials are captured. Start the job from its workspace control."
            return false
        }
        return true
    }
    private func startOwnedTask(id: UUID, permit: ForensicWorkPermit?, operation: @escaping @MainActor () async -> Void) {
        let task = Task { [self] in
            await operation()
            if let permit { _ = await permit.release() }
            finish(id)
        }
        jobs[id] = task; activeTask = task
    }
    private func changeVolumeSelection() {
        snapshotInventory = nil
        restoringVolumeSelection = true; selectedSnapshotUUID = nil; restoringVolumeSelection = false
        _ = invalidate(); result = nil; cacheReceipt = nil; rows = []; selectedEntryPath = nil
        isHistorical = false; lastExport = nil; lastExportDestination = nil
        statusMessage = cleanupWarning ?? "Volume selection changed. Inspect the selected UUID to record its allocated view."
    }
    private func changeSnapshotSelection() {
        _ = invalidate(); result = nil; cacheReceipt = nil; rows = []; selectedEntryPath = nil
        isHistorical = false; lastExport = nil; lastExportDestination = nil
        statusMessage = cleanupWarning ?? "APFS view selection changed. Inspect the selected current volume or snapshot to verify its file bytes."
    }
    private func restoreViewSelection(volume: UUID?, snapshot: UUID?) {
        restoringVolumeSelection = true; selectedVolumeUUID = volume; selectedSnapshotUUID = snapshot; restoringVolumeSelection = false
        jobBindingID = UUID()
    }
    nonisolated private static func inventory(_ result: APFSInspectionResult, historical: Bool) -> APFSWorkspaceSnapshotInventory {
        APFSWorkspaceSnapshotInventory(evidenceID: result.evidenceID, containerSHA256: result.containerSHA256,
            volumeUUID: result.volumeUUID, containerEncryption: result.containerEncryption, volumeEncryption: result.volumeEncryption,
            entries: result.snapshots, isAvailable: result.snapshotInventoryAvailable, isHistorical: historical)
    }
    private struct Selection: Sendable, Equatable {
        let evidence: EvidenceRecord
        let forensicCase: ForensicCase
        static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.evidence == rhs.evidence && lhs.forensicCase.manifest.id == rhs.forensicCase.manifest.id && lhs.forensicCase.bundleURL == rhs.forensicCase.bundleURL
        }
    }
}
