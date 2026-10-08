import AppKit
import Foundation
import ForensicsCore
import Observation

enum ContentPreviewDisplayMode: String, CaseIterable {
    case text = "Text"
    case hex = "Hex"
}

@MainActor
@Observable
final class ContentPreviewStore {
    typealias Load = @Sendable (EvidenceRecord, EnumerationResult, FilesystemEntry, URL) async throws -> LocalContentPreview
    static let rowsPerPage = 50

    var preview: LocalContentPreview?
    var isLoading = false
    var errorMessage: String?
    var phase = "Load a verified local preview. No data is sent to Codex."
    var mode: ContentPreviewDisplayMode = .text { didSet { if oldValue != mode { page = 0 } } }
    var page = 0
    var selectedFilePath: String { selection?.file.path ?? "" }
    var hasSelection: Bool { selection != nil }
    var hasActiveWork: Bool { !jobs.isEmpty }
    var canLoad: Bool {
        guard let selection else { return false }
        return !selection.file.isDirectory && selection.file.size <= VerifiedContentService.maximumFileBytes
            && !isLoading && !isClosing
    }
    var pageCount: Int {
        let count = mode == .text ? preview?.textFragments.count ?? 0 : preview?.hexRows.count ?? 0
        return max(1, (count + Self.rowsPerPage - 1) / Self.rowsPerPage)
    }
    var visibleTextFragments: ArraySlice<ContentTextFragment> {
        guard let rows = preview?.textFragments else { return [] }
        return rows[visibleRange(count: rows.count)]
    }
    var visibleHexRows: ArraySlice<ContentHexRow> {
        guard let rows = preview?.hexRows else { return [] }
        return rows[visibleRange(count: rows.count)]
    }

    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private let loadRequest: Load
    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    @ObservationIgnored private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private(set) var loadTask: Task<Void, Never>?

    init(load: Load? = nil, scheduler: ForensicWorkScheduler = .shared) {
        self.scheduler = scheduler
        loadRequest = load ?? { evidence, result, file, helper in
            try await ContentPreviewBuilder.load(evidence: evidence, result: result, file: file,
                engine: EngineClient(helperURL: helper))
        }
    }

    /// Selection changes clear the UI immediately without silently hashing the
    /// source again. Retain all canceled owning jobs until cleanup has drained.
    func configure(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry, helperURL: URL) {
        guard !isClosing else { return }
        invalidate()
        selection = Selection(evidence: evidence, result: result, file: file, helperURL: helperURL)
        phase = "Load a verified local preview. No data is sent to Codex."
        if file.isDirectory { errorMessage = VerifiedContentError.directoryContent.localizedDescription }
        else if file.size > VerifiedContentService.maximumFileBytes { errorMessage = VerifiedContentError.contentTooLarge.localizedDescription }
    }

    func load() {
        guard canLoad, let selection else { return }
        guard !selection.file.isDirectory else { errorMessage = VerifiedContentError.directoryContent.localizedDescription; return }
        guard selection.file.size <= VerifiedContentService.maximumFileBytes else {
            errorMessage = VerifiedContentError.contentTooLarge.localizedDescription
            return
        }
        let previous = Array(jobs.values)
        let operation = loadRequest
        let id = UUID()
        generation = id
        preview = nil
        errorMessage = nil
        isLoading = true
        page = 0
        phase = previous.isEmpty ? "Waiting for the application work slot to verify selected bytes…" : "Waiting for previous preview cleanup…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            // Rapid selection changes must never accumulate extraction helpers
            // or private scratch: a replacement waits for all older owners.
            for pending in previous { await pending.value }
            do {
                try Task.checkCancellation()
                guard self.generation == id, !self.isClosing else { return }
                let value = try await self.scheduler.run(.documentPreview) { _ in
                    try await operation(selection.evidence, selection.result, selection.file, selection.helperURL)
                }
                try Task.checkCancellation()
                guard self.generation == id, !self.isClosing else { return }
                guard value.receipt.evidenceID == selection.evidence.id, value.receipt.fileID == selection.file.id,
                      value.receipt.byteCount == selection.file.size else { throw VerifiedContentError.extractedContentMismatch }
                self.preview = value
                self.mode = value.supportsText ? .text : .hex
                self.phase = "Verified extracted bytes · local preview only"
            } catch is CancellationError {
                guard self.generation == id, !self.isClosing else { return }
                self.phase = "Preview canceled. Owned temporary bytes were cleaned up."
            } catch {
                guard self.generation == id, !self.isClosing else { return }
                self.errorMessage = Self.safeMessage(error)
                self.phase = "Preview could not be verified. The evidence and case were preserved."
            }
        }
        jobs[id] = task
        loadTask = task
    }

    func cancel() { loadTask?.cancel() }

    func reset() {
        invalidate()
        selection = nil
        isClosing = false
        phase = "Select a file to load its verified local preview."
    }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        invalidate()
        let pending = Array(jobs.values)
        guard !pending.isEmpty else { return nil }
        return Task { for job in pending { await job.value } }
    }

    func copyVisiblePage() {
        let value: String
        if mode == .text {
            value = visibleTextFragments.map { "\($0.lineNumber).\($0.fragmentNumber)  \($0.text)" }.joined(separator: "\n")
        } else {
            value = visibleHexRows.map { String(format: "%08X  %@  %@", $0.byteOffset, $0.hexadecimal, $0.ascii) }.joined(separator: "\n")
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private func invalidate() {
        generation = nil
        for job in jobs.values { job.cancel() }
        loadTask = nil
        preview = nil
        errorMessage = nil
        isLoading = false
        page = 0
    }

    private func finish(_ id: UUID) {
        jobs[id] = nil
        guard generation == id else { return }
        isLoading = false
        loadTask = nil
        generation = nil
    }

    private func visibleRange(count: Int) -> Range<Int> {
        let start = min(max(0, page), pageCount - 1) * Self.rowsPerPage
        return min(start, count)..<min(start + Self.rowsPerPage, count)
    }

    private static func safeMessage(_ error: Error) -> String {
        if let error = error as? ForensicSchedulingError { return error.localizedDescription }
        if let error = error as? VerifiedContentError { return error.localizedDescription }
        if let error = error as? AssistantContextError { return error.localizedDescription }
        if let error = error as? EngineError, error == .sourceChanged { return error.localizedDescription }
        return "The native engine could not verify a bounded preview. Review the recorded analysis and source availability before retrying."
    }

    private struct Selection: Sendable {
        let evidence: EvidenceRecord
        let result: EnumerationResult
        let file: FilesystemEntry
        let helperURL: URL
    }
}
