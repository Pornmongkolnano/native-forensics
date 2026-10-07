import AppKit
import CryptoKit
import Foundation
import ForensicsCore
import Observation

@MainActor @Observable
final class MultiEvidenceAnalysisStore {
    typealias Prepare = @Sendable (UUID, EvidenceRecord, EnumerationResult, [FilesystemEntry], URL) async throws -> [MultiEvidenceVerifiedFile]
    typealias Verify = @Sendable (EvidenceRecord, EnumerationResult) async throws -> Void
    typealias Analyze = AssistantAnalysisStore.Analyze
    typealias Save = @Sendable (MultiEvidenceAnalysisRecord, URL) async throws -> Void
    var isPresented = false
    var question = "เปรียบเทียบข้อมูลในสองไฟล์ แยกสิ่งที่สังเกตได้จากข้อสันนิษฐานและอ้างช่วงข้อความที่เปิดเผย" { didSet { if oldValue != question { invalidateAnswer() } } }
    var firstRanges = "" { didSet { if oldValue != firstRanges { invalidateDisclosure() } } }
    var firstRedactions = "" { didSet { if oldValue != firstRedactions { invalidateDisclosure() } } }
    var secondRanges = "" { didSet { if oldValue != secondRanges { invalidateDisclosure() } } }
    var secondRedactions = "" { didSet { if oldValue != secondRedactions { invalidateDisclosure() } } }
    var cliPath: String
    private(set) var verifiedFiles: [MultiEvidenceVerifiedFile] = []
    private(set) var context: MultiEvidenceContext?
    private(set) var result: CodexAnalysisResult?
    private(set) var references: [MultiEvidenceReference] = []
    private(set) var parentRecord: MultiEvidenceAnalysisRecord?
    private(set) var savedRecord: MultiEvidenceAnalysisRecord?
    private(set) var history: [MultiEvidenceRecordSummary] = []
    private(set) var historyCursor: MultiEvidenceRecordSummary?
    private(set) var historyShowsOlderPage = false
    var canLoadOlderHistory: Bool { !isWorking && historyCursor != nil }
    private(set) var isWorking = false
    private(set) var phase = "Prepare two files locally. No request is sent until exact review."
    var errorMessage: String?
    private(set) var openedReferenceText: String?
    private(set) var openedReferenceLabel: String?
    @ObservationIgnored private(set) var jobTask: Task<Void, Never>?
    @ObservationIgnored private var selection: Selection?
    @ObservationIgnored private var generation: UUID?
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private var settingDefaults = false
    @ObservationIgnored private var completed: Completed?
    @ObservationIgnored private let prepare: Prepare
    @ObservationIgnored private let verify: Verify
    @ObservationIgnored private let analyzeRequest: Analyze
    @ObservationIgnored private let save: Save
    var hasActiveWork: Bool { jobTask != nil }
    var outboundPrompt: String { guard let context else { return "" }; return (try? MultiEvidencePrompt.make(context: context, question: question, parent: parentRecord)) ?? "" }
    var canAnalyze: Bool { isPresented && !isWorking && !isClosing && !outboundPrompt.isEmpty && CodexCLIAvailability.issue(for: cliPath) == nil }
    var canSaveAnalysis: Bool { !isWorking && !isClosing && completed != nil && savedRecord == nil && selection?.forensicCase != nil }
    var filePaths: [String] { selection?.files.map(\.path) ?? [] }
    var connectionStatus: String { CodexCLIAvailability.issue(for: cliPath) == nil ? "Codex CLI found · ChatGPT sign-in required" : "Set up Codex CLI in Settings" }

    init(executableURL: URL? = nil, prepare: Prepare? = nil, verify: Verify? = nil, save: Save? = nil, analyze: Analyze? = nil) {
        cliPath = executableURL?.path ?? CodexCLIAvailability.configuredPath
        self.prepare = prepare ?? { caseID, evidence, result, files, helper in
            try await MultiEvidenceContextBuilder.prepare(caseID: caseID, evidence: evidence, result: result,
                files: files, engine: EngineClient(helperURL: helper))
        }
        self.verify = verify ?? { evidence, result in
            guard result.sourcePaths.first == evidence.sourcePath, result.sourceFileHashes[evidence.sourcePath] == evidence.sha256 else {
                throw VerifiedContentError.staleEvidence
            }
            for path in result.sourcePaths {
                let inspected = try await ImageInspector.inspect(url: URL(fileURLWithPath: path), progress: { _ in })
                guard inspected.sha256 == result.sourceFileHashes[path],
                      path != evidence.sourcePath || inspected.byteCount == evidence.byteCount else { throw VerifiedContentError.staleEvidence }
            }
        }
        self.save = save ?? { record, caseURL in try await MultiEvidenceRecordStore.saveAsync(record, in: caseURL) }
        analyzeRequest = analyze ?? { prompt, executable in try await CodexAnalysisClient(executableURL: executable, timeout: 180).analyze(prompt: prompt) }
    }

    func configure(evidence: EvidenceRecord, result: EnumerationResult, files: [FilesystemEntry], helperURL: URL, forensicCase: ForensicCase? = nil) {
        guard !isWorking && !isClosing else { return }
        guard files.count == 2, files[0].id != files[1].id, files.allSatisfy({ !$0.isDirectory && $0.size <= VerifiedContentService.maximumFileBytes }) else {
            errorMessage = MultiEvidenceError.invalidSelection.localizedDescription; return
        }
        selection = Selection(caseID: forensicCase?.manifest.id ?? UUID(), evidence: evidence, result: result,
            files: files, helperURL: helperURL, forensicCase: forensicCase)
        parentRecord = nil; context = nil; verifiedFiles = []; history = []; historyCursor = nil; historyShowsOlderPage = false; invalidateAnswer()
        isPresented = true; prepareContext()
    }

    func prepareContext() {
        guard isPresented, !isWorking, !isClosing, let selection else { return }
        let id = start("Verifying and extracting both complete UTF-8 files locally…")
        context = nil; invalidateAnswer()
        let operation = prepare
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                let files = try await operation(selection.caseID, selection.evidence, selection.result, selection.files, selection.helperURL)
                try Task.checkCancellation(); guard generation == id, !isClosing else { return }
                guard files.count == 2, files.map({ $0.binding.selectedEntry }) == selection.files,
                      files.allSatisfy({ $0.binding.caseID == selection.caseID && $0.binding.evidenceID == selection.evidence.id }) else { throw MultiEvidenceError.invalidSelection }
                verifiedFiles = files
                settingDefaults = true
                firstRanges = format(files[0].defaultSelection.ranges); secondRanges = format(files[1].defaultSelection.ranges)
                firstRedactions = ""; secondRedactions = ""; settingDefaults = false
                parentRecord = nil
                try buildDisclosure()
                phase = "Verified locally. Select ranges/redactions and review the exact aggregate payload before Send."
                if let forensicCase = selection.forensicCase {
                    let worker = Task.detached(priority: .utility) { try MultiEvidenceRecordStore.history(in: forensicCase.bundleURL) }
                    let items = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                    if generation == id, !isClosing { updateHistory(items, older: false) }
                }
            } catch is CancellationError { phase = "Preparation cancelled. No request was sent." }
            catch { errorMessage = error.localizedDescription; phase = "Preparation failed. No request was sent." }
        }
    }

    func rebuildDisclosure() {
        guard !isWorking, !isClosing else { return }
        do { try buildDisclosure(); errorMessage = nil; phase = "Disclosure rebuilt locally. Review the exact payload again." }
        catch { context = nil; errorMessage = error.localizedDescription }
    }
    private func buildDisclosure() throws {
        context = try MultiEvidenceContext.make(files: verifiedFiles, selections: [
            .init(ranges: parse(firstRanges), redactions: parse(firstRedactions)),
            .init(ranges: parse(secondRanges), redactions: parse(secondRedactions))])
        _ = try MultiEvidencePrompt.make(context: context!, question: question, parent: parentRecord)
    }

    func analyze(confirmedPrompt: String) {
        guard canAnalyze, confirmedPrompt == outboundPrompt, let context, let selection else {
            errorMessage = MultiEvidenceError.requestMismatch.localizedDescription; return
        }
        let question = question, parent = parentRecord, operation = analyzeRequest, verify = verify
        let executable = URL(fileURLWithPath: cliPath).standardizedFileURL.resolvingSymlinksInPath()
        let id = start("Rechecking source hashes before sending the exact reviewed request…")
        invalidateAnswer()
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                try await verify(selection.evidence, selection.result)
                try Task.checkCancellation()
                guard generation == id, !isClosing, outboundPrompt == confirmedPrompt else { throw MultiEvidenceError.requestMismatch }
                phase = "Codex is comparing the reviewed disclosure…"
                let response = try await operation(confirmedPrompt, executable)
                try Task.checkCancellation()
                guard generation == id, !isClosing, outboundPrompt == confirmedPrompt else { return }
                // This constructor validates response limits and the exact
                // question/context/parent binding before any save is offered.
                _ = try MultiEvidenceAnalysisRecord.make(context: context, question: question, prompt: confirmedPrompt,
                    result: response, retention: .digestOnly, parent: parent)
                result = response; references = MultiEvidenceReferences.validate(response: response.response, context: context)
                completed = Completed(context: context, question: question, prompt: confirmedPrompt, result: response, parent: parent)
                phase = "AI interpretation received. Resolved citations confirm disclosed ranges only."
            } catch is CancellationError { phase = "Comparison cancelled; an already sent request may use account quota." }
            catch { errorMessage = error.localizedDescription; phase = "Comparison failed; no answer was published." }
        }
    }

    func saveAnalysis(retention: AnalysisRetention) {
        guard canSaveAnalysis, let completed, let forensicCase = selection?.forensicCase else { return }
        let id = start("Saving an immutable comparison receipt locally…"), save = save
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                let worker = Task.detached(priority: .utility) {
                    let record = try MultiEvidenceAnalysisRecord.make(context: completed.context, question: completed.question,
                        prompt: completed.prompt, result: completed.result, retention: retention, parent: completed.parent)
                    try await save(record, forensicCase.bundleURL)
                    return record
                }
                let record = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                guard generation == id else { return }
                savedRecord = record; phase = "Comparison saved as historical AI interpretation."
                let loader = Task.detached(priority: .utility) { try MultiEvidenceRecordStore.history(in: forensicCase.bundleURL) }
                let items = try await withTaskCancellationHandler { try await loader.value } onCancel: { loader.cancel() }
                updateHistory(items, older: false)
            } catch is CancellationError { phase = "Save cancelled; reload case history before retrying." }
            catch { errorMessage = error.localizedDescription; phase = "Save failed; existing records remain unchanged." }
        }
    }

    func loadHistory(older: Bool = false) {
        guard !isWorking, !isClosing, let forensicCase = selection?.forensicCase else { return }
        let before = older ? historyCursor : nil
        if older && before == nil { return }
        let id = start("Reading a bounded historical comparison page locally…")
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                let worker = Task.detached(priority: .utility) { try MultiEvidenceRecordStore.history(in: forensicCase.bundleURL, before: before) }
                let items = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation(); guard generation == id, !isClosing else { return }
                updateHistory(items, older: older)
            } catch is CancellationError { phase = "History page cancelled." }
            catch { errorMessage = error.localizedDescription }
        }
    }
    private func updateHistory(_ items: [MultiEvidenceRecordSummary], older: Bool) {
        history = items; historyShowsOlderPage = older
        historyCursor = items.count == MultiEvidenceRecordStore.maximumPageSize ? items.last : nil
    }

    func loadRecord(id recordID: UUID) {
        guard !isWorking, !isClosing, let forensicCase = selection?.forensicCase else { return }
        let id = start("Opening historical comparison; source bytes are not reverified by this read…")
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                let worker = Task.detached(priority: .utility) { try MultiEvidenceRecordStore.load(id: recordID, in: forensicCase.bundleURL) }
                let record = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation(); guard generation == id, !isClosing, let record else { return }
                completed = nil; savedRecord = record; result = record.result; references = record.references
                phase = "Historical comparison opened. Digest-only records do not retain disclosed text."
            } catch is CancellationError { phase = "Opening history cancelled." }
            catch { errorMessage = error.localizedDescription }
        }
    }

    func beginFollowUp() {
        guard !isWorking, !isClosing, let savedRecord, let context,
              savedRecord.context.files.map(\.binding) == context.files.map(\.binding),
              savedRecord.context.files.map(\.contentSHA256) == context.files.map(\.contentSHA256) else {
            errorMessage = MultiEvidenceError.parentMismatch.localizedDescription; return
        }
        parentRecord = savedRecord; invalidateAnswer()
        phase = "Follow-up uses a saved parent. Prior AI interpretation is untrusted; review this new request before Send."
    }
    func clearParent() { guard !isWorking else { return }; parentRecord = nil; invalidateAnswer() }

    func openReference(_ reference: MultiEvidenceReference) {
        guard !isWorking, !isClosing, references.contains(reference), reference.state == .disclosed, let selection,
              let context = completed?.context ?? savedRecord?.context ?? context else { return }
        let id = start("Reextracting files before opening the cited bytes…"), operation = prepare
        openedReferenceText = nil; openedReferenceLabel = nil
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                let fresh = try await operation(selection.caseID, selection.evidence, selection.result, context.files.map { $0.binding.selectedEntry }, selection.helperURL)
                let text = try MultiEvidenceReferences.open(reference, context: context, current: fresh)
                try Task.checkCancellation(); guard generation == id, !isClosing else { return }
                openedReferenceText = text; openedReferenceLabel = reference.marker
                phase = "Cited bytes freshly verified; interpretation remains unverified."
            } catch is CancellationError { phase = "Opening cited bytes cancelled." }
            catch { errorMessage = MultiEvidenceError.staleReference.localizedDescription; phase = "Citation unresolved against the current source." }
        }
    }
    func cancel() { jobTask?.cancel() }
    func close() {
        let pending = beginShutdown()
        Task { if let pending { await pending.value }; isPresented = false; verifiedFiles = []; context = nil; selection = nil; parentRecord = nil; invalidateAnswer(); isClosing = false }
    }
    func beginShutdown() -> Task<Void, Never>? { isClosing = true; jobTask?.cancel(); return jobTask }
    func prepareForTermination() { isClosing = true; isPresented = false; jobTask?.cancel() }
    func copyContextPrompt() { guard !outboundPrompt.isEmpty else { return }; NSPasteboard.general.clearContents(); NSPasteboard.general.setString(outboundPrompt, forType: .string) }
    private func start(_ phase: String) -> UUID { let id = UUID(); generation = id; isWorking = true; errorMessage = nil; self.phase = phase; return id }
    private func finish(_ id: UUID) { guard generation == id else { return }; generation = nil; isWorking = false; jobTask = nil }
    private func invalidateDisclosure() {
        guard !settingDefaults else { return }
        context = nil; parentRecord = nil; invalidateAnswer()
        phase = "Disclosure changed; follow-up parent cleared to avoid resending a prior answer that may quote newly redacted text."
    }
    private func invalidateAnswer() { result = nil; references = []; completed = nil; savedRecord = nil; openedReferenceText = nil; openedReferenceLabel = nil }
    private func format(_ ranges: [MultiEvidenceRange]) -> String { ranges.map { "\($0.start):\($0.end)" }.joined(separator: ",") }
    private func parse(_ text: String) throws -> [MultiEvidenceRange] {
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return [] }
        guard text.utf8.count <= 1_024 else { throw MultiEvidenceError.budgetExceeded }
        return try text.split(separator: ",", omittingEmptySubsequences: false).map { component in
            let parts = component.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2, let start = Int(parts[0].trimmingCharacters(in: .whitespaces)),
                  let end = Int(parts[1].trimmingCharacters(in: .whitespaces)) else { throw MultiEvidenceError.invalidRange }
            return .init(start: start, end: end)
        }
    }
    private struct Selection: Sendable { let caseID: UUID; let evidence: EvidenceRecord; let result: EnumerationResult; let files: [FilesystemEntry]; let helperURL: URL; let forensicCase: ForensicCase? }
    private struct Completed: Sendable { let context: MultiEvidenceContext; let question: String; let prompt: String; let result: CodexAnalysisResult; let parent: MultiEvidenceAnalysisRecord? }
}
