import AppKit
import CryptoKit
import Foundation
import ForensicsCore
import Observation

@MainActor
@Observable
final class AssistantAnalysisStore {
    typealias Analyze = @Sendable (String, URL) async throws -> CodexAnalysisResult
    var isPresented = false
    var question = "สรุปข้อมูลที่ไฟล์นี้แสดง แยกสิ่งที่สังเกตได้จากข้อสันนิษฐาน และระบุข้อมูลที่ยังขาด" {
        didSet { if oldValue != question { result = nil } }
    }
    var includeText = false {
        didSet { if oldValue != includeText { result = nil } }
    }
    var context: EvidenceAnalysisContext?
    var isWorking = false
    var phase = "Prepare the selected context locally before sending."
    var errorMessage: String?
    var result: CodexAnalysisResult?
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

    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var preparedIncludesText = false
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private let analyzeRequest: Analyze
    @ObservationIgnored private(set) var jobTask: Task<Void, Never>?

    init(executableURL: URL? = nil, analyze: Analyze? = nil) {
        cliPath = executableURL?.path ?? CodexCLIAvailability.configuredPath
        analyzeRequest = analyze ?? { prompt, executable in
            try await CodexAnalysisClient(executableURL: executable, timeout: 180).analyze(prompt: prompt)
        }
    }

    func configure(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry, helperURL: URL) {
        guard !isWorking && !isClosing else { return }
        selection = Selection(evidence: evidence, result: result, file: file, helperURL: helperURL)
        context = nil
        self.result = nil
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
        result = nil
        errorMessage = nil
        phase = wantsText ? "Verifying sources and preparing UTF-8 text locally…" : "Preparing historical metadata locally…"
        jobTask = Task { [weak self] in
            guard let self else { return }
            defer { self.finish(jobID) }
            do {
                let worker = Task.detached(priority: .userInitiated) {
                    try await AssistantContextBuilder.build(evidence: selection.evidence, result: selection.result,
                        file: selection.file, includeText: wantsText,
                        engine: EngineClient(helperURL: selection.helperURL))
                }
                let prepared = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: { worker.cancel() }
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
        guard canAnalyze, !confirmedPrompt.isEmpty, confirmedPrompt == outboundPrompt else {
            errorMessage = "Prepare and review the current question and context before sending."
            return
        }
        let jobID = UUID()
        let prompt = confirmedPrompt
        let executable = URL(fileURLWithPath: cliPath).standardizedFileURL.resolvingSymlinksInPath()
        let operation = analyzeRequest
        generation = jobID
        isWorking = true
        result = nil
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

    func close() {
        let pending = beginShutdown()
        Task {
            if let pending { await pending.value }
            isPresented = false
            context = nil
            result = nil
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

    private struct Selection: Sendable {
        let evidence: EvidenceRecord
        let result: EnumerationResult
        let file: FilesystemEntry
        let helperURL: URL
    }
}
