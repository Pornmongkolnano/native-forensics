import Foundation
import ForensicsCore
import Observation

/// Bounded presentation for choosing two entries from the same saved listing.
/// The search works off MainActor and never extracts or discloses content.
@MainActor
@Observable
final class ComparisonSelectionStore {
    var query = "" { didSet { if oldValue != query { search() } } }
    var selectedCandidateID: String?
    private(set) var firstFile: FilesystemEntry?
    private(set) var secondFile: FilesystemEntry?
    private(set) var rows: [FilesystemEntry] = []
    private(set) var matchCount = 0
    private(set) var isSearching = false
    private(set) var errorMessage: String?
    @ObservationIgnored private var snapshot: EnumerationResult?
    @ObservationIgnored private var index = FilesystemSearchIndex(files: [])
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var isClosing = false

    var canCompare: Bool { firstFile != nil && secondFile != nil && firstFile?.id != secondFile?.id }
    var hasActiveWork: Bool { task != nil }

    func waitForSearch() async { await task?.value }

    func configure(result: EnumerationResult?) {
        guard !isClosing, snapshot != result else { return }
        cancel()
        snapshot = result
        index = FilesystemSearchIndex(files: result?.files ?? [])
        firstFile = nil; secondFile = nil; selectedCandidateID = nil
        query = ""
        search()
    }

    func useSelected(asFirst: Bool) {
        guard !isClosing, let file = rows.first(where: { $0.id == selectedCandidateID }) else { return }
        if asFirst {
            firstFile = file
            if secondFile?.id == file.id { secondFile = nil }
        } else {
            secondFile = file
            if firstFile?.id == file.id { firstFile = nil }
        }
    }

    func cancel() {
        generation = nil
        task?.cancel()
        // A superseded immutable search has no publication or process ownership.
        task = nil; isSearching = false
    }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        let pending = task
        cancel()
        return pending
    }

    func prepareForClosing() { isClosing = true; task?.cancel() }

    private func search() {
        cancel()
        guard !isClosing else { return }
        guard query.utf8.count <= 4_096 else {
            rows = []; matchCount = 0
            errorMessage = "Search is limited to 4,096 UTF-8 bytes."
            return
        }
        errorMessage = nil
        let index = index, query = query, id = UUID()
        generation = id; isSearching = true
        task = Task { [weak self] in
            defer {
                if self?.generation == id {
                    self?.isSearching = false; self?.generation = nil; self?.task = nil
                }
            }
            do {
                let worker = Task.detached(priority: .userInitiated) {
                    var visible: [FilesystemEntry] = [], count = 0
                    for (offset, file) in try index.rows(matching: query).enumerated() {
                        if offset.isMultiple(of: 128) { try Task.checkCancellation() }
                        guard !file.isDirectory, (0...1_048_576).contains(file.size) else { continue }
                        count += 1
                        if visible.count < 100 { visible.append(file) }
                    }
                    try Task.checkCancellation()
                    return (visible, count)
                }
                let outcome = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard let self, self.generation == id, !self.isClosing else { return }
                self.rows = outcome.0; self.matchCount = outcome.1
                if !self.rows.contains(where: { $0.id == self.selectedCandidateID }) { self.selectedCandidateID = nil }
            } catch is CancellationError {
            } catch {
                guard let self, self.generation == id else { return }
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
