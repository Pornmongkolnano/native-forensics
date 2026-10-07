import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class CaseIntegrityWorkspaceStore {
    typealias Audit = @Sendable (ForensicCase, CaseIntegrityAuditOptions, @escaping @Sendable (CaseIntegrityProgress) -> Void) async throws -> CaseIntegrityReport
    typealias ChooseDestination = @MainActor @Sendable (CaseIntegrityReportFormat) async -> URL?
    typealias Export = @Sendable (CaseIntegrityReport, ForensicCase, CaseIntegrityReportFormat, URL, Bool) async throws -> URL

    var freshEvidenceRehash = false
    var includePrivatePaths = false
    private(set) var report: CaseIntegrityReport?
    private(set) var progress: CaseIntegrityProgress?
    private(set) var statusMessage = "Open a case to audit its recorded metadata."
    private(set) var errorMessage: String?
    private(set) var reportURL: URL?
    private(set) var isAuditing = false
    private(set) var isExporting = false
    private(set) var isClosing = false
    private var jobs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var forensicCase: ForensicCase?
    @ObservationIgnored private var generation = UUID()
    @ObservationIgnored private let auditRequest: Audit
    @ObservationIgnored private let chooseDestination: ChooseDestination
    @ObservationIgnored private let exportRequest: Export
    @ObservationIgnored private(set) var activeTask: Task<Void, Never>?

    init(audit: Audit? = nil, chooseDestination: ChooseDestination? = nil, export: Export? = nil) {
        auditRequest = audit ?? { forensicCase, options, progress in
            try await CaseIntegrityAuditor.audit(forensicCase: forensicCase, options: options, progress: progress)
        }
        self.chooseDestination = chooseDestination ?? { format in await CaseIntegrityPanelService.chooseDestination(format: format) }
        exportRequest = export ?? { report, forensicCase, format, outputURL, privatePaths in
            try await CaseIntegrityReportExporter.export(report: report, forensicCase: forensicCase,
                format: format, to: outputURL, includePrivatePaths: privatePaths)
        }
    }

    var isWorking: Bool { !jobs.isEmpty }
    var hasActiveWork: Bool { isWorking }
    var canAudit: Bool { forensicCase != nil && !isWorking && !isClosing }
    var canExport: Bool { forensicCase != nil && report != nil && !isWorking && !isClosing }

    func configure(forensicCase: ForensicCase?) {
        guard !isClosing else { return }
        if self.forensicCase?.bundleURL == forensicCase?.bundleURL,
           self.forensicCase?.manifest == forensicCase?.manifest { return }
        generation = UUID(); cancelPendingWork()
        self.forensicCase = forensicCase; report = nil; progress = nil; reportURL = nil
        errorMessage = nil; isAuditing = false; isExporting = false
        statusMessage = forensicCase == nil ? "Open a case to audit its recorded metadata."
            : "Ready for a read-only audit. Source bytes remain unopened unless fresh rehash is selected."
    }

    func runAudit() {
        guard canAudit, let forensicCase else { return }
        let token = generation, owner = UUID(), request = auditRequest
        let options = CaseIntegrityAuditOptions(freshEvidenceRehash: freshEvidenceRehash)
        isAuditing = true; progress = nil; errorMessage = nil; reportURL = nil
        statusMessage = options.freshEvidenceRehash ? "Auditing metadata and freshly rehashing recorded source files…" : "Auditing historical case metadata; source bytes are not opened…"
        let task = Task { [weak self] in
            guard let self else { return }
            defer {
                self.jobs[owner] = nil
                if self.generation == token { self.isAuditing = false; self.progress = nil }
            }
            do {
                let result = try await request(forensicCase, options) { [weak self] progress in
                    Task { @MainActor in
                        guard let self, self.generation == token, !self.isClosing, self.jobs[owner] != nil else { return }
                        self.progress = progress
                    }
                }
                try Task.checkCancellation()
                guard self.generation == token, !self.isClosing else { return }
                guard result.caseID == forensicCase.manifest.id, result.casePath == forensicCase.bundleURL.path,
                      result.sourceRehashed == options.freshEvidenceRehash else {
                    throw ForensicsError.invalidCase("The integrity report does not match the requested case or rehash mode.")
                }
                self.report = result
                let scope = result.sourceRehashed ? "\(result.verifiedSourceCount) sources freshly verified" : "Historical metadata only"
                self.statusMessage = "\(result.checks.count) checks · \(scope) · \(result.hasFailures ? "Issues found" : result.isPartial ? "Partial coverage" : "Audit complete within scope")"
            } catch is CancellationError {
                guard self.generation == token, !self.isClosing else { return }
                self.statusMessage = "Audit cancelled. Existing case files and any earlier report were preserved."
            } catch {
                guard self.generation == token, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
            }
        }
        jobs[owner] = task; activeTask = task
    }

    func exportReport(format: CaseIntegrityReportFormat) {
        guard canExport, let forensicCase, let report else { return }
        let token = generation, owner = UUID(), chooser = chooseDestination, request = exportRequest
        let privatePaths = includePrivatePaths
        isExporting = true; errorMessage = nil
        let task = Task { [weak self] in
            guard let self else { return }
            defer {
                self.jobs[owner] = nil
                if self.generation == token { self.isExporting = false }
            }
            do {
                guard let destination = await chooser(format) else { return }
                try Task.checkCancellation()
                guard self.generation == token, !self.isClosing else { return }
                let output = try await request(report, forensicCase, format, destination, privatePaths)
                // A completed atomic export remains on disk after late cancel.
                guard self.generation == token, !self.isClosing else { return }
                self.reportURL = output
                self.statusMessage = "Exported \(format == .json ? "JSON" : "Markdown") audit report\(privatePaths ? " with private host paths" : " with host paths omitted")."
            } catch is CancellationError {
                guard self.generation == token, !self.isClosing else { return }
                self.statusMessage = "Report export cancelled before completion. Existing files were preserved."
            } catch {
                guard self.generation == token, !self.isClosing else { return }
                self.errorMessage = error.localizedDescription
            }
        }
        jobs[owner] = task; activeTask = task
    }

    func cancelPendingWork() { jobs.values.forEach { $0.cancel() } }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true; generation = UUID(); cancelPendingWork()
        let pending = Array(jobs.values)
        guard !pending.isEmpty else { return nil }
        return Task { for task in pending { await task.value } }
    }
}
