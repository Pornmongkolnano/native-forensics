import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class FilesystemDocumentPreviewStore {
    typealias Load = @Sendable (EvidenceRecord, EnumerationResult, FilesystemEntry) async throws -> FilesystemDocumentPreview

    private(set) var preview: FilesystemDocumentPreview?
    private(set) var isLoading = false
    private(set) var errorMessage: String?
    private(set) var phase = "Select a filesystem file to inspect its recovered content."
    var contentQuery = "" { didSet { refreshSearch() } }
    private(set) var searchOutcome: DocumentSearchOutcome?
    var analysis: DocumentAnalysis? { preview?.analysis }
    var hasActiveWork: Bool { !jobs.isEmpty }
    var selectedFilename: String { selection?.file.name ?? "" }
    var canLoad: Bool { selection != nil && unavailableReason == nil && !isLoading && !isClosing }
    var unavailableReason: String? {
        guard let selection else { return "Select a filesystem file first." }
        if selection.file.isDirectory { return "Select a regular file to preview its content." }
        if selection.file.size > DocumentLimits.maximumInputBytes { return "Document preview supports complete recovered files up to 128 MiB." }
        if !hasInjectedLoad && !FileManager.default.isExecutableFile(atPath: documentHelperURL.path) {
            return DocumentAnalysisError.unavailable.localizedDescription
        }
        return nil
    }

    @ObservationIgnored private let documentHelperURL: URL
    @ObservationIgnored private let hasInjectedLoad: Bool
    @ObservationIgnored private let loadRequest: Load
    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    // hasActiveWork is rendered by parent views. Observe owner insertion and
    // final drain, including canceled owners retained for cleanup.
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private(set) var loadTask: Task<Void, Never>?
    @ObservationIgnored private var isClosing = false

    init(engineHelperURL: URL,
         documentHelperURL: URL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder"),
         load: Load? = nil) {
        self.documentHelperURL = documentHelperURL
        self.hasInjectedLoad = load != nil
        loadRequest = load ?? { evidence, result, file in
            try await FilesystemDocumentPreviewService(engine: EngineClient(helperURL: engineHelperURL),
                documents: DocumentAnalysisClient(helperURL: documentHelperURL))
                .preview(evidence: evidence, result: result, file: file)
        }
    }

    func configure(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) {
        guard !isClosing else { return }
        let next = Selection(evidence: evidence, result: result, file: file)
        guard selection != next else { return }
        invalidate()
        selection = next
        phase = "Verify recovered bytes and inspect content locally."
    }

    func load() {
        guard canLoad, let selection else { return }
        let previous = Array(jobs.values), operation = loadRequest, id = UUID()
        generation = id
        preview = nil; errorMessage = nil; isLoading = true
        contentQuery = ""; searchOutcome = nil
        phase = previous.isEmpty ? "Verifying sources and recovering selected document…" : "Waiting for previous preview cleanup…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for job in previous { await job.value }
            do {
                try Task.checkCancellation()
                guard self.generation == id, !self.isClosing else { return }
                self.phase = "Verifying sources, recovered bytes and supported document content…"
                let worker = Task.detached(priority: .userInitiated) {
                    try await operation(selection.evidence, selection.result, selection.file)
                }
                let value = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard self.generation == id, !self.isClosing else { return }
                guard value.file == selection.file, value.receipt.evidenceID == selection.evidence.id,
                      value.receipt.fileID == selection.file.id, value.receipt.byteCount == selection.file.size,
                      value.analysis.sourceSHA256 == value.receipt.sha256,
                      value.analysis.sourceByteCount == value.receipt.byteCount,
                      value.receipt.orderedContainerSHA256 == selection.result.sourcePaths.map({ selection.result.sourceFileHashes[$0] ?? "" }) else {
                    throw VerifiedContentError.extractedContentMismatch
                }
                self.preview = value
                self.phase = value.analysis.status == .decoded
                    ? "Verified recovered bytes · supported content decoded locally"
                    : "Verified recovered bytes · content requires further examination"
            } catch is CancellationError {
                guard self.generation == id, !self.isClosing else { return }
                self.phase = "Preview canceled. Temporary storage cleanup finished."
            } catch {
                guard self.generation == id, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.phase = "Preview could not be verified."
            }
        }
        jobs[id] = task; loadTask = task
    }

    func cancel() { loadTask?.cancel() }

    func reset() {
        invalidate(); selection = nil; isClosing = false
        phase = "Select a filesystem file to inspect its recovered content."
    }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true; invalidate(); selection = nil
        let pending = Array(jobs.values)
        guard !pending.isEmpty else { return nil }
        return Task { for job in pending { await job.value } }
    }

    private func invalidate() {
        generation = nil
        for job in jobs.values { job.cancel() }
        loadTask = nil; preview = nil; errorMessage = nil; isLoading = false
        contentQuery = ""; searchOutcome = nil
    }

    private func finish(_ id: UUID) {
        jobs[id] = nil
        guard generation == id else { return }
        generation = nil; isLoading = false; loadTask = nil
    }

    private func refreshSearch() {
        searchOutcome = analysis.map { DocumentContentSearch.search(contentQuery, in: $0) }
    }

    private struct Selection: Sendable, Equatable {
        let evidence: EvidenceRecord
        let result: EnumerationResult
        let file: FilesystemEntry
    }
}
