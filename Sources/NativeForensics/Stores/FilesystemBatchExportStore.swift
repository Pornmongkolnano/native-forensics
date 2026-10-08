import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class FilesystemBatchExportStore {
    typealias Export = @Sendable (EnumerationResult, [FilesystemEntry], URL, URL, @escaping @Sendable (FilesystemBatchExportProgress) -> Void) async throws -> FilesystemBatchExportResult

    private(set) var result: FilesystemBatchExportResult?
    private(set) var isExporting = false
    private(set) var progress: FilesystemBatchExportProgress?
    private(set) var errorMessage: String?
    private(set) var statusMessage = "Export matching regular files to a new folder with a size/hash manifest."
    var hasActiveWork: Bool { !jobs.isEmpty }

    @ObservationIgnored private let exportRequest: Export
    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    @ObservationIgnored private var generation: UUID?
    // hasActiveWork is rendered by parent views. Observe owner insertion and
    // final drain, including canceled owners retained for cleanup.
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private(set) var exportTask: Task<Void, Never>?
    @ObservationIgnored private var isClosing = false

    init(engineHelperURL: URL, export: Export? = nil, scheduler: ForensicWorkScheduler = .shared) {
        self.scheduler = scheduler
        exportRequest = export ?? { analysis, files, destination, caseURL, progress in
            try await FilesystemBatchExportService(engine: EngineClient(helperURL: engineHelperURL))
                .export(analysis: analysis, files: files, to: destination, caseURL: caseURL, progress: progress)
        }
    }

    static func eligibleFiles(in files: [FilesystemEntry]) -> [FilesystemEntry] {
        let virtualNames: Set<String> = ["$MBR", "$FAT1", "$FAT2", "$Unalloc", "$Unallocated"]
        return files.filter { file in
            !file.isDirectory && !file.name.isEmpty && file.name != "." && file.name != ".."
                && !(virtualNames.contains(file.name) && file.path == "/" + file.name)
                && !file.name.hasSuffix(" (Volume Label Entry)")
        }
    }

    func start(analysis: EnumerationResult, files: [FilesystemEntry], destination: URL, caseURL: URL) {
        guard !hasActiveWork, !isClosing else { return }
        guard !files.isEmpty, files.count <= FilesystemBatchExportService.maximumFiles else {
            errorMessage = "Choose between 1 and 1,000 matching regular files for one batch export."
            return
        }
        let id = UUID(), operation = exportRequest
        generation = id; errorMessage = nil; isExporting = true
        progress = nil
        statusMessage = "Waiting for the application work slot to export \(files.count.formatted()) matching files…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(id) }
            do {
                let update: @Sendable (FilesystemBatchExportProgress) -> Void = { [weak self] value in
                    Task { @MainActor [weak self] in
                        guard let self, self.generation == id, !self.isClosing else { return }
                        self.progress = value
                        self.statusMessage = "Exporting \(value.completedFiles.formatted()) / \(value.totalFiles.formatted()) files"
                    }
                }
                let value = try await self.scheduler.run(.batchExport) { _ in
                    try await operation(analysis, files, destination, caseURL, update)
                }
                // A successful return is past the atomic directory publication
                // boundary. Do not hide a committed export if cancel arrived
                // just after its rename; show its receipt instead.
                guard self.generation == id, !self.isClosing else { return }
                guard value.entries.map(\.sourceFile) == files,
                      value.destinationPath == destination.deletingLastPathComponent().standardizedFileURL
                        .resolvingSymlinksInPath().appendingPathComponent(destination.lastPathComponent).path,
                      value.manifestPath == URL(fileURLWithPath: value.destinationPath).appendingPathComponent("manifest.json").path,
                      value.requestedCount == files.count,
                      value.successfulCount + value.failedCount == files.count,
                      (value.status == .completed && value.failedCount == 0)
                        || (value.status == .partial && value.failedCount > 0) else {
                    throw EngineError.protocolViolation("The export receipt does not describe the requested file selection.")
                }
                self.result = value
                self.statusMessage = value.status == .completed
                    ? "Exported \(value.successfulCount.formatted()) files with verified size/hash receipts."
                    : "Partial export: \(value.successfulCount.formatted()) succeeded, \(value.failedCount.formatted()) failed. Review the manifest."
            } catch is CancellationError {
                guard self.generation == id, !self.isClosing else { return }
                self.statusMessage = "Batch export canceled. Temporary export cleanup finished; prior exports were preserved."
            } catch {
                guard self.generation == id, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Batch export could not be verified. Review the error before retrying."
            }
        }
        jobs[id] = task; exportTask = task
    }

    func cancel() { exportTask?.cancel() }

    func reset() {
        invalidate(); result = nil; isClosing = false
        statusMessage = "Export matching regular files to a new folder with a size/hash manifest."
    }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true; invalidate()
        let pending = Array(jobs.values)
        guard !pending.isEmpty else { return nil }
        return Task { for job in pending { await job.value } }
    }

    private func invalidate() {
        generation = nil
        for job in jobs.values { job.cancel() }
        exportTask = nil; errorMessage = nil; progress = nil; isExporting = false
    }

    private func finish(_ id: UUID) {
        jobs[id] = nil
        guard generation == id else { return }
        generation = nil; isExporting = false; exportTask = nil
    }
}
