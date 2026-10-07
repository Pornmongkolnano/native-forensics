import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class ContentIndexWorkspaceStore {
    typealias Rebuild = @Sendable (UUID, [ContentIndexInput], @escaping @Sendable (ContentIndexProgress) -> Void) async throws -> CaseContentIndexSnapshot
    typealias Load = @Sendable (URL) throws -> CaseContentIndexSnapshot?
    typealias Save = @Sendable (CaseContentIndexSnapshot, UUID?, URL) throws -> Void
    typealias LoadListing = @Sendable (UUID, URL) throws -> EnumerationResult?

    private(set) var snapshot: CaseContentIndexSnapshot?
    private(set) var isLoading = false
    private(set) var isRebuilding = false
    private(set) var isSearching = false
    private(set) var isHistorical = false
    private(set) var isStale = false
    private(set) var needsReload = false
    private(set) var progress: ContentIndexProgress?
    private(set) var phase = "Open a case and analyze its filesystems before rebuilding the content index."
    private(set) var errorMessage: String?
    private(set) var searchOutcome: CaseContentSearchOutcome?
    var query = "" { didSet { refreshSearch() } }
    var caseSensitive = false { didSet { refreshSearch() } }
    var hasActiveWork: Bool { !jobs.isEmpty || searchTask != nil }
    var isWorking: Bool { isLoading || isRebuilding || isSearching }
    var canRebuild: Bool { scope != nil && !(scope?.inputs.isEmpty ?? true)
        && (scope?.inputs.count ?? 0) <= ContentIndexLimits.maximumSources && !needsReload && !isLoading && !isRebuilding && !isClosing }
    var queryIsTooLong: Bool { query.utf8.count > ContentIndexLimits.maximumQueryBytes }
    var missingListingCount: Int { scope?.inputs.filter { $0.result == nil }.count ?? 0 }

    @ObservationIgnored private let rebuildRequest: Rebuild
    @ObservationIgnored private let loadRequest: Load
    @ObservationIgnored private let saveRequest: Save
    @ObservationIgnored private let listingRequest: LoadListing
    @ObservationIgnored private var scope: Scope?
    @ObservationIgnored private var requestedScope: Scope?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var searchGeneration: UUID?
    @ObservationIgnored private var isClosing = false
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private(set) var operationTask: Task<Void, Never>?
    @ObservationIgnored private(set) var searchTask: Task<Void, Never>?

    init(engineHelperURL: URL,
         documentHelperURL: URL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder"),
         rebuild: Rebuild? = nil, load: @escaping Load = { try CaseContentIndexStore.load(in: $0) },
         save: @escaping Save = { try CaseContentIndexStore.save($0, expectedSnapshotID: $1, in: $2) },
         loadListing: @escaping LoadListing = { try EngineResultStore.load(evidenceID: $0, in: $1) }) {
        let service = CaseContentIndexService(engineHelperURL: engineHelperURL, documentHelperURL: documentHelperURL)
        self.rebuildRequest = rebuild ?? { try await service.rebuild(caseID: $0, inputs: $1, progress: $2) }
        self.loadRequest = load; self.saveRequest = save; self.listingRequest = loadListing
    }

    /// Call on case/listing changes, not every row render. All recorded evidence
    /// participates; absent listings are explicit uncovered sources.
    func configure(forensicCase: ForensicCase, results: [UUID: EnumerationResult]) {
        guard !isClosing else { return }
        let next = Scope(caseID: forensicCase.manifest.id, caseURL: forensicCase.bundleURL,
            manifest: forensicCase.manifest,
            inputs: forensicCase.manifest.evidence.map { ContentIndexInput(evidence: $0, result: results[$0.id]) })
        guard requestedScope != next else { return }
        let previous = Array(jobs.values)
        invalidate(); scope = next; requestedScope = next; isLoading = true
        guard next.inputs.count <= ContentIndexLimits.maximumSources else {
            isLoading = false
            errorMessage = "Case content indexing supports at most 128 evidence sources. This case remains unchanged."
            phase = "The case exceeds the bounded content-index source budget."
            return
        }
        let id = UUID(), load = loadRequest, listing = listingRequest
        generation = id; phase = "Reading historical derived index…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for job in previous { await job.value }
            do {
                try Task.checkCancellation()
                let worker = Task.detached(priority: .utility) {
                    let value = try load(next.caseURL)
                    try value?.validate()
                    var resolved: [ContentIndexInput] = []
                    var unreadable = 0
                    var budget = ContentIndexListingBudget()
                    for input in next.inputs {
                        try Task.checkCancellation()
                        do {
                            let result = try input.result ?? listing(input.evidence.id, next.caseURL)
                            if let result, try budget.admit(result) {
                                resolved.append(ContentIndexInput(evidence: input.evidence, result: result))
                            } else {
                                if result != nil { unreadable += 1 }
                                resolved.append(ContentIndexInput(evidence: input.evidence, result: nil))
                            }
                        } catch {
                            try Task.checkCancellation(); unreadable += 1; resolved.append(input)
                        }
                    }
                    return (value, resolved, unreadable)
                }
                let (value, inputs, unreadable) = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard self.generation == id, self.requestedScope == next, !self.isClosing else { return }
                let resolvedScope = Scope(caseID: next.caseID, caseURL: next.caseURL, manifest: next.manifest, inputs: inputs)
                self.scope = resolvedScope
                if let value {
                    guard value.caseID == next.caseID else { throw ContentIndexError.invalidSnapshot }
                    self.snapshot = value; self.isHistorical = true
                    // Equality of saved hashes/listings is a scope comparison,
                    // not a fresh read of source bytes.
                    let check = Task.detached(priority: .utility) {
                        try inputs.map(ContentIndexSource.make)
                    }
                    let sources = try await withTaskCancellationHandler { try await check.value } onCancel: { check.cancel() }
                    try Task.checkCancellation()
                    guard self.generation == id, self.scope == resolvedScope, !self.isClosing else { return }
                    self.isStale = sources != value.sources
                    self.phase = self.isStale ? "Stale historical index · source/listing bindings changed. Rebuild to search current recorded inputs."
                        : "Historical index · source bytes have not been verified in this session."
                } else {
                    self.phase = "Rebuild local content text across all analyzed sources in this case."
                }
                if unreadable > 0 { self.errorMessage = "\(unreadable) listing(s) could not be read or exceed the aggregate listing budget and remain uncovered. A negative result is not an absence proof." }
                self.refreshSearch()
            } catch is CancellationError { }
            catch {
                guard self.generation == id, !self.isClosing else { return }
                if self.snapshot != nil { self.isStale = true }
                self.errorMessage = error.localizedDescription; self.phase = "The saved derived index was preserved; current source/listing bindings could not be accepted."
            }
        }
        jobs[id] = task; operationTask = task
    }

    func rebuild() {
        guard canRebuild, let scope else { return }
        let previous = Array(jobs.values), build = rebuildRequest, save = saveRequest
        let expectedID = snapshot?.id, id = UUID()
        generation = id; isRebuilding = true; progress = nil; errorMessage = nil
        phase = "Verifying recorded sources and decoding local content…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            for job in previous { await job.value }
            do {
                try Task.checkCancellation()
                let update: @Sendable (ContentIndexProgress) -> Void = { [weak self] value in
                    Task { @MainActor [weak self] in
                        guard let self, self.generation == id, self.isRebuilding, !self.isClosing else { return }
                        self.progress = value
                    }
                }
                let worker = Task.detached(priority: .userInitiated) { try await build(scope.caseID, scope.inputs, update) }
                let value = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard self.generation == id, self.scope == scope, !self.isClosing else { return }
                guard value.caseID == scope.caseID else { throw ContentIndexError.invalidSnapshot }
                self.phase = "Saving a source-bound derived index…"
                let writer = Task.detached(priority: .utility) {
                    try value.validate()
                    try CaseContentIndexStore.validateScope(value, manifest: scope.manifest)
                    try save(value, expectedID, scope.caseURL)
                }
                try await withTaskCancellationHandler { try await writer.value } onCancel: { writer.cancel() }
                // An atomic save may have completed just before cancel. Present
                // its receipt for this same scope instead of implying no write.
                guard self.generation == id, self.scope == scope, !self.isClosing else { return }
                self.snapshot = value; self.isHistorical = false; self.isStale = false
                self.phase = value.isPartial ? "Derived index saved with partial coverage. No match does not prove absence."
                    : "Derived index saved · bytes verified at build time."
                self.refreshSearch()
            } catch is CancellationError {
                guard self.generation == id, !self.isClosing else { return }
                self.phase = "Rebuild canceled after cleanup. The previous index was preserved."
            } catch {
                guard self.generation == id, !self.isClosing else { return }
                if error as? ContentIndexError == .sourceChanged || error as? ForensicsError == .sourceChanged { self.isStale = true }
                if self.snapshot != nil { self.isHistorical = true }
                self.errorMessage = error.localizedDescription
                if error as? ContentIndexError == .publicationUncertain {
                    self.needsReload = true; self.isStale = true
                    self.phase = "Publication may have committed. Reload Index to inspect the saved generation."
                } else if error as? ContentIndexError == .staleGeneration {
                    self.needsReload = true; self.isStale = true
                    self.phase = "A different generation was saved. Reload Index before rebuilding."
                } else { self.phase = "Rebuild failed before publication. The previous index was preserved." }
            }
        }
        jobs[id] = task; operationTask = task
    }

    func cancel() { operationTask?.cancel(); searchTask?.cancel() }

    func reload() {
        guard let scope, !isWorking, !isClosing else { return }
        requestedScope = nil
        configure(forensicCase: ForensicCase(bundleURL: scope.caseURL, manifest: scope.manifest),
            results: Dictionary(uniqueKeysWithValues: scope.inputs.compactMap { input in
                input.result.map { (input.evidence.id, $0) }
            }))
    }

    func reset() {
        invalidate(); scope = nil; requestedScope = nil; isClosing = false
        phase = "Open a case and analyze its filesystems before rebuilding the content index."
    }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        let tasks = Array(jobs.values), search = searchTask
        invalidate(); scope = nil; requestedScope = nil
        guard !tasks.isEmpty || search != nil else { return nil }
        return Task { for task in tasks { await task.value }; await search?.value }
    }

    private func refreshSearch() {
        searchTask?.cancel(); searchTask = nil; searchGeneration = nil; isSearching = false; searchOutcome = nil
        guard !isClosing, let snapshot, !query.isEmpty, !queryIsTooLong else { return }
        let text = query, sensitive = caseSensitive, id = UUID()
        searchGeneration = id; isSearching = true
        let task = Task { [weak self] in
            defer {
                self?.jobs[id] = nil
                if let self, self.searchGeneration == id { self.searchTask = nil; self.searchGeneration = nil; self.isSearching = false }
            }
            do {
                try await Task.sleep(for: .milliseconds(120)); try Task.checkCancellation()
                let worker = Task.detached(priority: .userInitiated) { try CaseContentIndexSearch.search(text, in: snapshot, caseSensitive: sensitive) }
                let value = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard let self, self.searchGeneration == id, self.snapshot?.id == snapshot.id,
                      self.query == text, self.caseSensitive == sensitive, !self.isClosing else { return }
                self.searchOutcome = value
            } catch { }
        }
        jobs[id] = task; searchTask = task
    }

    private func finish(_ id: UUID) {
        jobs[id] = nil
        guard generation == id else { return }
        generation = nil; operationTask = nil; isLoading = false; isRebuilding = false
    }

    private func invalidate() {
        generation = nil
        for job in jobs.values { job.cancel() }
        searchTask?.cancel(); searchTask = nil; searchGeneration = nil; isSearching = false
        operationTask = nil; snapshot = nil; searchOutcome = nil; errorMessage = nil; progress = nil
        isLoading = false; isRebuilding = false; isHistorical = false; isStale = false
        needsReload = false
        query = ""
    }

    private struct Scope: Sendable, Equatable {
        let caseID: UUID; let caseURL: URL; let manifest: CaseManifest; let inputs: [ContentIndexInput]
    }
}
