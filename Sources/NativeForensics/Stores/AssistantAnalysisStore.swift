import AppKit
import CryptoKit
import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class AssistantAnalysisStore {
    typealias Analyze = @Sendable (String, URL) async throws -> CodexAnalysisResult
    typealias Save = @Sendable (AnalysisRecord, URL) async throws -> Void
    var isPresented = false
    var question = "สรุปข้อมูลที่ไฟล์นี้แสดง แยกสิ่งที่สังเกตได้จากข้อสันนิษฐาน และระบุข้อมูลที่ยังขาด" {
        didSet { if oldValue != question { invalidateAnswer() } }
    }
    var includeText = false {
        didSet { if oldValue != includeText { invalidateAnswer() } }
    }
    var context: EvidenceAnalysisContext?
    var isWorking = false
    var phase = "Prepare the selected context locally before sending."
    var errorMessage: String?
    var result: CodexAnalysisResult?
    private(set) var savedAnalysisID: UUID?
    private(set) var isSaving = false
    var cliPath: String
    var selectedFilePath: String { selection?.file.path ?? "" }
    var connectionStatus: String {
        CodexCLIAvailability.issue(for: cliPath) == nil
            ? "CLI found · saved ChatGPT sign-in required"
            : "Set up Codex CLI in Settings"
    }
    var contextNeedsPreparation: Bool { context == nil || preparedIncludesText != includeText }
    var outboundPrompt: String {
        guard let context, !contextNeedsPreparation else { return "" }
        return (try? AssistantPrompt.make(context: context, question: question)) ?? ""
    }
    var canAnalyze: Bool {
        isPresented && !isWorking && !isClosing && !contextNeedsPreparation
            && !outboundPrompt.isEmpty && CodexCLIAvailability.issue(for: cliPath) == nil
    }
    var hasActiveWork: Bool { jobTask != nil }
    var canSaveAnalysis: Bool {
        !isWorking && !isClosing && isPresented && savedAnalysisID == nil
            && completedAnalysis?.selection.forensicCase != nil
            && completedAnalysis?.result == result
            && completedAnalysis?.prompt == outboundPrompt
    }

    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var preparedIncludesText = false
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private let analyzeRequest: Analyze
    @ObservationIgnored private let saveRecord: Save
    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    @ObservationIgnored private var completedAnalysis: CompletedAnalysis?
    @ObservationIgnored var onAnalysisSaved: (@MainActor (UUID) -> Void)?
    @ObservationIgnored private(set) var jobTask: Task<Void, Never>?

    init(executableURL: URL? = nil, save: Save? = nil, analyze: Analyze? = nil,
         scheduler: ForensicWorkScheduler = .shared) {
        self.scheduler = scheduler
        cliPath = executableURL?.path ?? CodexCLIAvailability.configuredPath
        saveRecord = save ?? { record, caseURL in
            try CaseWorkStore.saveAnalysis(record, in: caseURL)
        }
        analyzeRequest = analyze ?? { prompt, executable in
            try await CodexAnalysisClient(executableURL: executable, timeout: 180).analyze(prompt: prompt)
        }
    }

    func configure(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry, helperURL: URL,
                   forensicCase: ForensicCase? = nil) {
        guard !isWorking && !isClosing else { return }
        selection = Selection(evidence: evidence, result: result, file: file, helperURL: helperURL, forensicCase: forensicCase)
        context = nil
        invalidateAnswer()
        errorMessage = nil
        includeText = false
        isPresented = true
        prepareContext()
    }

    func prepareContext() {
        guard isPresented, !isWorking, !isClosing, let selection else { return }
        let wantsText = includeText
        let jobID = UUID()
        generation = jobID
        isWorking = true
        context = nil
        invalidateAnswer()
        errorMessage = nil
        phase = wantsText ? "Verifying sources and preparing UTF-8 text locally…" : "Preparing historical metadata locally…"
        jobTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(jobID) }
            do {
                let prepared = try await self.scheduler.run(.documentPreview) { _ in
                    try await AssistantContextBuilder.build(evidence: selection.evidence, result: selection.result,
                        file: selection.file, includeText: wantsText,
                        engine: EngineClient(helperURL: selection.helperURL))
                }
                try Task.checkCancellation()
                guard self.generation == jobID, !self.isClosing else { return }
                self.context = prepared
                self.preparedIncludesText = wantsText
                self.phase = "Context prepared locally. Review the exact question and context before sending."
            } catch is CancellationError {
                self.phase = "Preparation cancelled. No request was sent."
            } catch {
                self.errorMessage = error.localizedDescription
                self.phase = "Preparation failed. No request was sent."
            }
        }
    }

    /// The exact reviewed prompt is checked again at the transmission boundary.
    func analyze(confirmedPrompt: String) {
        guard canAnalyze, !confirmedPrompt.isEmpty, confirmedPrompt == outboundPrompt,
              let selection, let context else {
            errorMessage = "Prepare and review the current question and context before sending."
            return
        }
        let jobID = UUID()
        let prompt = confirmedPrompt
        let executable = URL(fileURLWithPath: cliPath).standardizedFileURL.resolvingSymlinksInPath()
        let operation = analyzeRequest
        let reviewedQuestion = question
        generation = jobID
        isWorking = true
        invalidateAnswer()
        errorMessage = nil
        phase = "Codex is analyzing the reviewed context…"
        jobTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(jobID) }
            do {
                let response = try await operation(prompt, executable)
                try Task.checkCancellation()
                guard self.generation == jobID, !self.isClosing,
                      self.outboundPrompt == prompt else { return }
                let expectedHash = SHA256.hash(data: Data(prompt.utf8)).map { String(format: "%02x", $0) }.joined()
                guard response.requestSHA256 == expectedHash else { throw CodexAnalysisError.invalidProtocol }
                self.result = response
                self.completedAnalysis = CompletedAnalysis(selection: selection, context: context,
                    prompt: prompt, question: reviewedQuestion, result: response)
                self.phase = "AI interpretation received. Verify it against the evidence."
            } catch is CancellationError {
                self.phase = "Analysis cancelled. A request already sent may still count toward account usage."
            } catch {
                self.errorMessage = error.localizedDescription
                self.phase = "Codex analysis failed. The evidence and case were preserved."
            }
        }
    }

    func cancel() { jobTask?.cancel() }

    /// Saving is a separate local action. Freeze the completed transaction,
    /// never reconstruct its prompt from a later question/template/selection.
    func saveAnalysis(retention: AnalysisRetention) {
        guard canSaveAnalysis, let completed = completedAnalysis,
              let forensicCase = completed.selection.forensicCase else { return }
        let jobID = UUID()
        let save = saveRecord
        generation = jobID
        isWorking = true
        isSaving = true
        errorMessage = nil
        phase = "Saving the analysis receipt locally…"
        jobTask = Task { [weak self] in
            guard let self else { return }
            defer { self.isSaving = false; self.finish(jobID) }
            do {
                // Publication owns its detached worker until it finishes. Quit
                // drains this task even if cancellation arrives after commit.
                let worker = Task.detached(priority: .utility) {
                    let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id,
                        evidence: completed.selection.evidence, result: completed.selection.result,
                        file: completed.selection.file)
                    let record = try AnalysisRecord.make(binding: binding, context: completed.context,
                        prompt: completed.prompt, question: completed.question, result: completed.result,
                        retention: retention, cliVersion: nil, promptTemplateVersion: AssistantPrompt.templateVersion)
                    try await save(record, forensicCase.bundleURL)
                    return record
                }
                let saved = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: { worker.cancel() }
                guard self.generation == jobID else { return }
                self.savedAnalysisID = saved.id
                self.phase = "Analysis saved to this case. It remains an AI interpretation of historical evidence."
                self.onAnalysisSaved?(saved.id)
            } catch is CancellationError {
                self.phase = "Saving cancelled before publication completed. Reload history before retrying."
            } catch {
                self.errorMessage = error.localizedDescription
                self.phase = "Saving did not complete normally. Reload case history before retrying."
            }
        }
    }

    func close() {
        let pending = beginShutdown()
        Task {
            if let pending { await pending.value }
            isPresented = false
            context = nil
            invalidateAnswer()
            selection = nil
            // Reopening the sheet is allowed; window shutdown also retains
            // isPresented until its owning task has completed cleanup.
            isClosing = false
        }
    }

    func beginShutdown() -> Task<Void, Never>? {
        isClosing = true
        let pending = jobTask
        pending?.cancel()
        return pending
    }

    /// AppKit can refuse a termination request while a modal review sheet is
    /// attached. Dismiss its UI while retaining and draining the owning job.
    func prepareForTermination() {
        isClosing = true
        isPresented = false
        jobTask?.cancel()
    }

    func copyContextPrompt() {
        guard !outboundPrompt.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(outboundPrompt, forType: .string)
    }

    func copyResponse() {
        guard let result else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(result) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(String(decoding: data, as: UTF8.self), forType: .string)
    }

    private func finish(_ jobID: UUID) {
        guard generation == jobID else { return }
        isWorking = false
        jobTask = nil
        generation = nil
    }

    private func invalidateAnswer() {
        result = nil
        completedAnalysis = nil
        savedAnalysisID = nil
    }

    private struct Selection: Sendable {
        let evidence: EvidenceRecord
        let result: EnumerationResult
        let file: FilesystemEntry
        let helperURL: URL
        let forensicCase: ForensicCase?
    }

    private struct CompletedAnalysis: Sendable {
        let selection: Selection
        let context: EvidenceAnalysisContext
        let prompt: String
        let question: String
        let result: CodexAnalysisResult
    }
}
