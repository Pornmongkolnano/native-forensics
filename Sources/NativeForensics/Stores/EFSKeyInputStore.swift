import Foundation
import ForensicsCore
import Observation

/// Small, exact selection binding. Credential file URLs/bytes are deliberately
/// excluded, and this transient UI value is not a persisted credential record.
struct EFSKeySelectionContext: Sendable, Equatable {
    let caseID: UUID
    let evidence: EvidenceRecord
    let listingGenerationID: UUID
    let listingSavedAt: Date
    let engineVersion: String
    let patchDigest: String
    let options: EngineOptions
    let sourcePaths: [String]
    let sourceHashes: [String: String]
    let filesystem: String
    let file: FilesystemEntry

    init(caseID: UUID, evidence: EvidenceRecord, listingGenerationID: UUID,
         result: EnumerationResult, file: FilesystemEntry) throws {
        guard [.completed, .partial].contains(result.status), result.files.first(where: { $0.id == file.id }) == file,
              let volume = result.volumes.first(where: { $0.offsetBytes == file.fsOffsetBytes }),
              result.sourcePaths.contains(evidence.sourcePath),
              result.sourceFileHashes[evidence.sourcePath] == evidence.sha256 else {
            throw EFSKeyInputStoreError.selectionChanged
        }
        self.caseID = caseID; self.evidence = evidence; self.listingGenerationID = listingGenerationID
        listingSavedAt = result.savedAt; engineVersion = result.engineVersion; patchDigest = result.patchDigest
        options = result.options; sourcePaths = result.sourcePaths; sourceHashes = result.sourceFileHashes
        filesystem = volume.filesystem; self.file = file
        guard unavailableReason == nil else { throw EFSKeyInputStoreError.ineligibleFile }
    }

    var unavailableReason: String? {
        guard filesystem.lowercased() == "ntfs", !file.isDirectory, !file.isDeleted,
              file.attributeType == 128, file.attributeID != nil, file.attributeName == "", file.size >= 0,
              file.encryptionStatus == .ntfsEFSEncrypted else {
            return "Select a known EFS-encrypted, allocated regular NTFS file with a recorded unnamed DATA stream."
        }
        guard evidence.hashScope == FileHashScope.selectedFileBytes, evidence.byteCount > 0,
              !sourcePaths.isEmpty, sourcePaths.count <= 1_024,
              Set(sourcePaths).count == sourcePaths.count, Set(sourcePaths) == Set(sourceHashes.keys),
              sourceHashes[evidence.sourcePath] == evidence.sha256,
              sourceHashes.values.allSatisfy({ $0.count == 64 && $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) else {
            return "The selected listing requires complete recorded source-file SHA-256 bindings."
        }
        return nil
    }
}

enum EFSKeyInputStoreError: Error, LocalizedError, Sendable, Equatable {
    case ineligibleFile, selectionChanged, invalidReceipt
    var errorDescription: String? {
        switch self {
        case .ineligibleFile: "This selected stream does not have a verified supported EFS profile."
        case .selectionChanged: "The case, source or file selection changed. Select the encrypted file again."
        case .invalidReceipt: "The extraction did not return a valid decrypted-content receipt for the selected file."
        }
    }
}

enum EFSKeyInputState: Equatable {
    case idle, selectingCredential, selectingDestination, admitting, reading, extracting, cancelling, closed
}

struct EFSKeyPublication: Sendable {
    let id: UUID
    let context: EFSKeySelectionContext
    let receipt: ExtractionResult
    init(context: EFSKeySelectionContext, receipt: ExtractionResult, id: UUID = UUID()) {
        self.id = id; self.context = context; self.receipt = receipt
    }
}

/// The sheet stores only explicit file choices while idle. No credential bytes
/// are read until immediate scheduler admission; no secret waits in its queue.
/// The task retains admission through key reader, extraction and cleanup drain.
@MainActor
@Observable
final class EFSKeyInputStore {
    typealias Read = @Sendable (URL, URL) async throws -> EFSKeyMaterial
    typealias Operation = @Sendable (EFSKeySelectionContext, EFSKeyMaterial, URL) async throws -> ExtractionResult
    typealias RecordPublication = @Sendable (EFSKeyPublication) async -> ExtractionHistoryPublicationOutcome
    typealias Validate = @MainActor @Sendable (EFSKeySelectionContext) -> Bool
    typealias Pick = @MainActor @Sendable (EFSKeyFileRole) async -> URL?
    typealias PickOutput = @MainActor @Sendable (String) async -> URL?

    private(set) var context: EFSKeySelectionContext?
    private(set) var state: EFSKeyInputState = .idle
    private(set) var privateKeyFilename: String?
    private(set) var certificateFilename: String?
    private(set) var errorMessage: String?
    private(set) var statusMessage = "Choose the RSA private DER and certificate DER for this one extraction."
    private(set) var lastPublication: EFSKeyPublication?
    private(set) var historyOutcome: ExtractionHistoryPublicationOutcome?

    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    @ObservationIgnored private let read: Read
    @ObservationIgnored private let operation: Operation
    @ObservationIgnored private let validateSelection: Validate
    @ObservationIgnored private let pick: Pick
    @ObservationIgnored private let pickOutput: PickOutput
    @ObservationIgnored private let onPublished: (@MainActor @Sendable (EFSKeyPublication) -> Void)?
    @ObservationIgnored private let recordPublication: RecordPublication?
    @ObservationIgnored private var privateKeyURL: URL?
    @ObservationIgnored private var certificateURL: URL?
    @ObservationIgnored private var generation = UUID()
    @ObservationIgnored private var isClosing = false
    @ObservationIgnored private(set) var activeTask: Task<Void, Never>?

    init(scheduler: ForensicWorkScheduler = .shared, validateSelection: @escaping Validate,
         operation: @escaping Operation, read: @escaping Read = { try await EFSKeyMaterial.read(privateKeyURL: $0, certificateURL: $1) },
         pick: @escaping Pick = { await EFSKeyFilePanelService.choose($0) },
         pickOutput: @escaping PickOutput = { await CasePanelService.newExtractedFile(named: $0) },
         onPublished: (@MainActor @Sendable (EFSKeyPublication) -> Void)? = nil,
         recordPublication: RecordPublication? = nil) {
        self.scheduler = scheduler; self.validateSelection = validateSelection; self.operation = operation
        self.read = read; self.pick = pick; self.pickOutput = pickOutput; self.onPublished = onPublished
        self.recordPublication = recordPublication
    }

    var hasActiveWork: Bool { activeTask != nil }
    var canSelectCredentials: Bool { !isClosing && !hasActiveWork && context != nil && selectionIsCurrent }
    var canBegin: Bool { canSelectCredentials && privateKeyURL != nil && certificateURL != nil }
    var selectionIsCurrent: Bool { context.map { $0.unavailableReason == nil && validateSelection($0) } ?? false }
    var publicationIsCurrent: Bool { lastPublication.map { $0.context == context && validateSelection($0.context) } ?? false }

    func configure(context: EFSKeySelectionContext?) {
        guard !isClosing, self.context != context else { return }
        generation = UUID(); activeTask?.cancel(); clearChoices()
        self.context = context; lastPublication = nil; historyOutcome = nil; errorMessage = nil
        state = hasActiveWork ? .cancelling : .idle
        statusMessage = hasActiveWork ? "Waiting for previous credential work to release its owned resources…"
            : "Choose credentials for the selected EFS-encrypted file."
    }

    func choose(_ role: EFSKeyFileRole) {
        guard canSelectCredentials, let context else { return }
        let id = generation, picker = pick
        state = .selectingCredential; errorMessage = nil
        activeTask = Task { [weak self] in
            guard let self else { return }; defer { self.finish() }
            let url = await picker(role)
            guard !Task.isCancelled, self.matches(id, context), let url else { return }
            self.setChoice(url, for: role)
        }
    }

    /// Internal injection seam and panel result. Storing a URL never reads its
    /// bytes; metadata and read validation occur only inside the admitted job.
    func setChoice(_ url: URL, for role: EFSKeyFileRole) {
        guard !isClosing, context != nil, selectionIsCurrent else { return }
        if role == .privateKey { privateKeyURL = url; privateKeyFilename = url.lastPathComponent }
        else { certificateURL = url; certificateFilename = url.lastPathComponent }
        errorMessage = nil
    }

    func beginChoosingDestination() {
        guard canBegin, let context else { return }
        let id = generation, picker = pickOutput
        state = .selectingDestination; errorMessage = nil
        activeTask = Task { [weak self] in
            guard let self else { return }
            let destination = await picker(context.file.name)
            guard !Task.isCancelled, self.matches(id, context), let destination else { self.finish(); return }
            await self.perform(context: context, destination: destination, generation: id)
            self.finish()
        }
    }

    func begin(to destination: URL) {
        guard canBegin, let context else { return }
        let id = generation
        state = .admitting; errorMessage = nil
        activeTask = Task { [weak self] in
            guard let self else { return }
            await self.perform(context: context, destination: destination, generation: id)
            self.finish()
        }
    }

    func cancel() {
        guard hasActiveWork else { clearChoices(); return }
        state = .cancelling; clearChoices(); activeTask?.cancel()
        statusMessage = "Cancelling and waiting for credential reading and extraction cleanup…"
    }

    func waitForPendingWork() async { if let activeTask { await activeTask.value } }

    func close() async {
        guard !isClosing else { await waitForPendingWork(); return }
        isClosing = true; generation = UUID(); clearChoices()
        if hasActiveWork { state = .cancelling; activeTask?.cancel() }
        await waitForPendingWork()
        context = nil; state = .closed
    }

    private func perform(context: EFSKeySelectionContext, destination: URL, generation id: UUID) async {
        var permit: ForensicWorkPermit?
        var material: EFSKeyMaterial?
        var publishedThisJob = false
        do {
            try Task.checkCancellation()
            guard matches(id, context), let key = privateKeyURL, let certificate = certificateURL else {
                throw EFSKeyInputStoreError.selectionChanged
            }
            state = .admitting; statusMessage = "Checking the available forensic workflow slot…"
            let admitted = try await scheduler.acquireImmediately(.extraction)
            permit = admitted
            try Task.checkCancellation()
            guard matches(id, context) else { throw EFSKeyInputStoreError.selectionChanged }
            clearChoices()
            state = .reading; statusMessage = "Reading bounded local credential files for this one operation…"
            let reader = read
            let captured = try await admitted.run { try await reader(key, certificate) }
            material = captured
            try Task.checkCancellation()
            guard matches(id, context) else { throw EFSKeyInputStoreError.selectionChanged }
            state = .extracting; statusMessage = "Verifying source bytes and extracting the selected EFS stream…"
            let execute = operation
            let receipt = try await admitted.run { try await execute(context, captured, destination) }
            // A successfully published output remains a fact after late cancel
            // or selection replacement; it stays bound to the original context.
            guard receipt.byteCount == context.file.size, receipt.contentStatus == "decrypted-content" else {
                throw EFSKeyInputStoreError.invalidReceipt
            }
            let publication = EFSKeyPublication(context: context, receipt: receipt)
            lastPublication = publication; historyOutcome = nil; publishedThisJob = true
            captured.discard(); material = nil
            if let record = recordPublication {
                statusMessage = "Decrypted output was published. Waiting for its original-case history writer…"
                // Publication already occurred. An owned, uncancelled worker
                // establishes the same permit's completion boundary even if
                // Quit/cancel was requested before this actor resumed. It is
                // awaited; it does not acquire another scheduler admission.
                let history = Task.detached(priority: admitted.admission.policy.priority.taskPriority) {
                    do {
                        return try await admitted.runToCompletion { await record(publication) }
                    } catch {
                        return ExtractionHistoryPublicationOutcome.failed(recordID: publication.id, reason: .storageFailure)
                    }
                }
                let outcome = await history.value
                lastPublication = publication
                historyOutcome = outcome
                statusMessage = outcome.message + " EFS CBC content remains unauthenticated."
            } else {
                statusMessage = matches(id, context) ? "Decrypted bytes were published to a new output file. EFS CBC content is unauthenticated."
                    : "An output was published for the earlier selection. Its receipt remains bound to that file."
            }
            // Presentation can now refresh history without racing the writer.
            // The output itself was visible before history began; this callback
            // remains exactly once and never owns a fire-and-forget save.
            onPublished?(publication)
        } catch is CancellationError {
            if !publishedThisJob { statusMessage = "Credential reading and extraction cancelled after owned cleanup." }
        } catch {
            errorMessage = Self.safeMessage(error)
            statusMessage = "No decrypted-content receipt was accepted for this operation."
        }
        material?.discard(); material = nil
        if let permit { await permit.release() }
    }

    private func matches(_ id: UUID, _ context: EFSKeySelectionContext) -> Bool {
        !isClosing && generation == id && self.context == context && validateSelection(context)
    }
    private func clearChoices() { privateKeyURL = nil; certificateURL = nil; privateKeyFilename = nil; certificateFilename = nil }
    private func finish() { activeTask = nil; state = isClosing ? .closed : .idle }
    private static func safeMessage(_ error: Error) -> String {
        if let known = error as? EFSKeyInputError { return known.localizedDescription }
        if let known = error as? EFSKeyInputStoreError { return known.localizedDescription }
        if let known = error as? ForensicSchedulingError { return known.localizedDescription }
        return "The selected EFS stream could not be decrypted with these credentials. The source, key match or supported encryption profile could not be confirmed. Select the files again to retry."
    }
}
