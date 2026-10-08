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
    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    var hasActiveWork: Bool { jobTask != nil }
    var outboundPrompt: String { guard let context else { return "" }; return (try? MultiEvidencePrompt.make(context: context, question: question, parent: parentRecord)) ?? "" }
    var canAnalyze: Bool { isPresented && !isWorking && !isClosing && !outboundPrompt.isEmpty && CodexCLIAvailability.issue(for: cliPath) == nil }
    var canSaveAnalysis: Bool { !isWorking && !isClosing && completed != nil && savedRecord == nil && selection?.forensicCase != nil }
    var filePaths: [String] { selection?.files.map(\.path) ?? [] }
    var connectionStatus: String { CodexCLIAvailability.issue(for: cliPath) == nil ? "Codex CLI found · ChatGPT sign-in required" : "Set up Codex CLI in Settings" }

    init(executableURL: URL? = nil, prepare: Prepare? = nil, verify: Verify? = nil, save: Save? = nil, analyze: Analyze? = nil, scheduler: ForensicWorkScheduler = .shared) {
        self.scheduler = scheduler
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
        guard files.count == 2, files[0].id != files[1].id,
              files.allSatisfy({ !$0.isDirectory && (0...DocumentLimits.maximumInputBytes).contains($0.size) }) else {
            errorMessage = MultiEvidenceError.invalidSelection.localizedDescription; return
        }
        selection = Selection(caseID: forensicCase?.manifest.id ?? UUID(), evidence: evidence, result: result,
            files: files, helperURL: helperURL, forensicCase: forensicCase)
        parentRecord = nil; context = nil; verifiedFiles = []; history = []; historyCursor = nil; historyShowsOlderPage = false; invalidateAnswer()
        isPresented = true; prepareContext()
    }

    func prepareContext() {
        guard isPresented, !isWorking, !isClosing, let selection else { return }
        let id = start("Verifying complete files and decoding PDF text locally…")
        context = nil; invalidateAnswer()
        let operation = prepare
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                try await withHeavyWork(.documentPreview) { permit in
                    let files = try await permit.run {
                        try await operation(selection.caseID, selection.evidence, selection.result, selection.files, selection.helperURL)
                    }
                    try Task.checkCancellation(); guard generation == id, !isClosing else { return }
                    guard files.count == 2, files.map({ $0.binding.selectedEntry }) == selection.files,
                          files.allSatisfy({ $0.binding.caseID == selection.caseID && $0.binding.evidenceID == selection.evidence.id }) else { throw MultiEvidenceError.invalidSelection }
                    verifiedFiles = files
                    settingDefaults = true
                    firstRanges = format(files[0].defaultSelection); secondRanges = format(files[1].defaultSelection)
                    firstRedactions = ""; secondRedactions = ""; settingDefaults = false
                    parentRecord = nil
                    try buildDisclosure()
                    phase = "Verified locally. Select ranges/redactions and review the exact aggregate payload before Send."
                    if let forensicCase = selection.forensicCase {
                        let items = try await permit.run { try MultiEvidenceRecordStore.history(in: forensicCase.bundleURL) }
                        if generation == id, !isClosing { updateHistory(items, older: false) }
                    }
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
        let built = try MultiEvidenceContext.make(files: verifiedFiles, selections: disclosureSelections())
        _ = try MultiEvidencePrompt.make(context: built, question: question, parent: parentRecord)
        context = built
    }

    func analyze(confirmedPrompt: String) {
        guard canAnalyze, confirmedPrompt == outboundPrompt, let context, let selection else {
            errorMessage = MultiEvidenceError.requestMismatch.localizedDescription; return
        }
        let question = question, parent = parentRecord, operation = analyzeRequest, verify = verify
        let prepare = prepare
        let selections: [MultiEvidenceSelection]
        do { selections = try disclosureSelections() }
        catch { errorMessage = error.localizedDescription; return }
        let executable = URL(fileURLWithPath: cliPath).standardizedFileURL.resolvingSymlinksInPath()
        let id = start("Rechecking source hashes before sending the exact reviewed request…")
        invalidateAnswer()
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                if context.files.contains(where: { $0.pdf != nil }) {
                    phase = "Reextracting and checking the reviewed PDF decoder/text provenance before Send…"
                }
                // Local source rechecks and PDF materialization own the shared
                // slot. The already bounded reviewed request releases it before
                // waiting for the external provider.
                try await withHeavyWork(.documentPreview) { permit in
                    try await permit.run {
                        try await verify(selection.evidence, selection.result)
                        if context.files.contains(where: { $0.pdf != nil }) {
                            let fresh = try await prepare(selection.caseID, selection.evidence, selection.result, selection.files, selection.helperURL)
                            let freshContext = try MultiEvidenceContext.make(files: fresh, selections: selections)
                            guard context.hasSameDisclosure(as: freshContext) else { throw MultiEvidenceError.requestMismatch }
                        }
                    }
                }
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
            var didSave = false
            do {
                try await withHeavyWork(.historyRead) { permit in
                    let record = try await permit.runToCompletion {
                        let record = try MultiEvidenceAnalysisRecord.make(context: completed.context, question: completed.question,
                            prompt: completed.prompt, result: completed.result, retention: retention, parent: completed.parent)
                        try await save(record, forensicCase.bundleURL)
                        return record
                    }
                    didSave = true
                    guard generation == id else { return }
                    savedRecord = record; phase = "Comparison saved as historical AI interpretation."
                    let items = try await permit.run { try MultiEvidenceRecordStore.history(in: forensicCase.bundleURL) }
                    updateHistory(items, older: false)
                }
            } catch is CancellationError {
                phase = didSave ? "Comparison saved. History refresh cancelled; reload case history." : "Save cancelled; reload case history before retrying."
            }
            catch {
                errorMessage = error.localizedDescription
                phase = didSave ? "Comparison saved. History refresh failed; reload case history." : "Save failed; reload case history before retrying."
            }
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
                parentRecord = nil; openedReferenceText = nil; openedReferenceLabel = nil
                completed = nil; savedRecord = record; result = record.result; references = record.references
                phase = "Historical comparison opened. Digest-only records do not retain disclosed text."
            } catch is CancellationError { phase = "Opening history cancelled." }
            catch { errorMessage = error.localizedDescription }
        }
    }

    func beginFollowUp() {
        guard !isWorking, !isClosing, let savedRecord, let context,
              savedRecord.context.hasSameDisclosure(as: context) else {
            errorMessage = MultiEvidenceError.parentMismatch.localizedDescription; return
        }
        parentRecord = savedRecord; invalidateAnswer()
        phase = "Follow-up uses a saved parent. Prior AI interpretation is untrusted; review this new request before Send."
    }
    func clearParent() { guard !isWorking else { return }; parentRecord = nil; invalidateAnswer() }

    func openReference(_ reference: MultiEvidenceReference) {
        guard !isWorking, !isClosing, references.contains(reference), reference.state == .disclosed, let selection,
              let context = completed?.context ?? savedRecord?.context ?? context else { return }
        let id = start("Reextracting and verifying the cited source/derived span…"), operation = prepare
        openedReferenceText = nil; openedReferenceLabel = nil
        jobTask = Task { [weak self] in
            guard let self else { return }; defer { finish(id) }
            do {
                let text = try await withHeavyWork(.documentPreview) { permit in
                    try await permit.run {
                        let fresh = try await operation(selection.caseID, selection.evidence, selection.result, context.files.map { $0.binding.selectedEntry }, selection.helperURL)
                        return try MultiEvidenceReferences.open(reference, context: context, current: fresh)
                    }
                }
                try Task.checkCancellation(); guard generation == id, !isClosing else { return }
                openedReferenceText = text
                if let span = reference.pdfRange {
                    openedReferenceLabel = "\(reference.marker) · PDF page \(span.pageNumber), raw derived UTF-16 \(span.range.start):\(span.range.end)"
                } else { openedReferenceLabel = reference.marker }
                phase = "Cited span freshly verified; interpretation remains unverified."
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
    /// Keep admission through owned decoder/helper cleanup and subsequent case
    /// publication. Await release before the UI owner marks its task finished.
    private func withHeavyWork<Value: Sendable>(_ kind: ForensicWorkKind,
        operation: @MainActor (ForensicWorkPermit) async throws -> Value) async throws -> Value {
        let permit = try await scheduler.acquire(kind)
        do {
            let value = try await operation(permit)
            await permit.release()
            return value
        } catch {
            await permit.release()
            throw error
        }
    }
    private func invalidateDisclosure() {
        guard !settingDefaults else { return }
        context = nil; parentRecord = nil; invalidateAnswer()
        phase = "Disclosure changed; follow-up parent cleared to avoid resending a prior answer that may quote newly redacted text."
    }
    private func invalidateAnswer() { result = nil; references = []; completed = nil; savedRecord = nil; openedReferenceText = nil; openedReferenceLabel = nil }
    private func format(_ selection: MultiEvidenceSelection) -> String {
        if !selection.pdfRanges.isEmpty {
            return selection.pdfRanges.map { "\($0.pageNumber):\($0.range.start):\($0.range.end)" }.joined(separator: ",")
        }
        return selection.ranges.map { "\($0.start):\($0.end)" }.joined(separator: ",")
    }
    private func disclosureSelections() throws -> [MultiEvidenceSelection] {
        guard verifiedFiles.count == 2 else { throw MultiEvidenceError.invalidSelection }
        return try verifiedFiles.enumerated().map { index, file in
            let ranges = index == 0 ? firstRanges : secondRanges
            let redactions = index == 0 ? firstRedactions : secondRedactions
            if file.isPDF { return try .init(pdfRanges: parsePDF(ranges), pdfRedactions: parsePDF(redactions)) }
            return try .init(ranges: parse(ranges), redactions: parse(redactions))
        }
    }
    private func parsePDF(_ text: String) throws -> [MultiEvidencePDFRange] {
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return [] }
        guard text.utf8.count <= 1_024 else { throw MultiEvidenceError.budgetExceeded }
        return try text.split(separator: ",", omittingEmptySubsequences: false).map { component in
            let parts = component.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 3, let page = Int(parts[0].trimmingCharacters(in: .whitespaces)),
                  let start = Int(parts[1].trimmingCharacters(in: .whitespaces)),
                  let end = Int(parts[2].trimmingCharacters(in: .whitespaces)) else { throw MultiEvidenceError.invalidRange }
            return .init(pageNumber: page, start: start, end: end)
        }
    }
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
