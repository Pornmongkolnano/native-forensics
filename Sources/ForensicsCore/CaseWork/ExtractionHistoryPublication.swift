import Foundation

/// Sanitized history failures carry no helper diagnostics, host paths, source
/// filenames or credentials. None changes the already-published output fact.
public enum ExtractionHistoryPublicationFailure: String, Sendable, Equatable {
    case invalidRecord, unavailableCase, unsafePath, scopeMismatch
    case changedDuringPublication, recordAlreadyExists, recordTooLarge, storageFailure

    public var message: String {
        switch self {
        case .invalidRecord: "The extraction history receipt or its recorded selection could not be validated."
        case .unavailableCase: "The captured case was unavailable for recording extraction history."
        case .unsafePath: "The captured case-work location could not be verified as safe."
        case .scopeMismatch: "The extraction receipt did not match the captured case and evidence binding."
        case .changedDuringPublication: "The case changed while recording extraction history. Reopen it before retrying."
        case .recordAlreadyExists: "This immutable extraction record already exists. Reload it before retrying."
        case .recordTooLarge: "The extraction history record exceeded the existing record-size limit."
        case .storageFailure: "The extraction history record could not be saved. The published output was preserved."
        }
    }
}

/// Every outcome is subsequent to a caller-accepted output publication. A
/// historical record identifies those recorded bytes; it is not a fresh source
/// verification, plaintext authentication, or a new output commit.
public enum ExtractionHistoryPublicationOutcome: Sendable, Equatable {
    case recorded(ExtractionRecord)
    case publishedButDurabilityUnconfirmed(ExtractionRecord)
    case failed(recordID: UUID, reason: ExtractionHistoryPublicationFailure)

    public var recordID: UUID {
        switch self {
        case .recorded(let record), .publishedButDurabilityUnconfirmed(let record): record.id
        case .failed(let recordID, _): recordID
        }
    }
    public var record: ExtractionRecord? {
        switch self {
        case .recorded(let record), .publishedButDurabilityUnconfirmed(let record): record
        case .failed: nil
        }
    }
    public var historyIsConfirmed: Bool {
        if case .recorded = self { true } else { false }
    }
    public var message: String {
        switch self {
        case .recorded:
            "Extraction history was recorded. The output path and credentials were not retained."
        case .publishedButDurabilityUnconfirmed:
            "The output and immutable extraction history were published, but history durability could not be confirmed. Reload its record before retrying."
        case .failed(_, let reason):
            "The output was published, but extraction history was not confirmed. \(reason.message)"
        }
    }
}

/// Await this after a verified EngineClient output has been accepted, under the
/// same owned workflow permit. The caller establishes its run-to-completion
/// boundary before entry and retains admission until this writer drains. No
/// scheduler is acquired here and no user source or output is opened.
public enum ExtractionHistoryPublication {
    public static func publish(receipt: ExtractionResult, caseID: UUID,
        evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry,
        in caseURL: URL, id: UUID = UUID(), verifiedAt: Date = Date()) async -> ExtractionHistoryPublicationOutcome {
        await run(id: id) {
            perform(receipt: receipt, id: id, verifiedAt: verifiedAt,
                prepare: { try CaseWorkBinding.make(caseID: caseID, evidence: evidence, result: result, file: file) },
                save: { try CaseWorkStore.saveExtraction($0, in: caseURL) })
        }
    }

    /// A previously prepared immutable binding is useful when admission began
    /// before navigation changed. It receives the same validation and writer.
    public static func publish(receipt: ExtractionResult, binding: CaseWorkBinding,
        in caseURL: URL, id: UUID = UUID(), verifiedAt: Date = Date()) async -> ExtractionHistoryPublicationOutcome {
        await run(id: id) {
            perform(receipt: receipt, id: id, verifiedAt: verifiedAt, prepare: { binding },
                save: { try CaseWorkStore.saveExtraction($0, in: caseURL) })
        }
    }

    static func publishForTesting(receipt: ExtractionResult, binding: CaseWorkBinding,
        in caseURL: URL, id: UUID = UUID(), verifiedAt: Date = Date(),
        persistenceCheckpoint: @escaping @Sendable (CasePersistenceCheckpoint, Int) throws -> Void
    ) async -> ExtractionHistoryPublicationOutcome {
        await run(id: id) {
            perform(receipt: receipt, id: id, verifiedAt: verifiedAt, prepare: { binding },
                save: { try CaseWorkStore.saveExtractionForTesting($0, in: caseURL,
                    persistenceCheckpoint: persistenceCheckpoint) })
        }
    }

    private static func run(id: UUID,
        operation: @escaping @Sendable () -> ExtractionHistoryPublicationOutcome
    ) async -> ExtractionHistoryPublicationOutcome {
        do { return try await BlockingWork.run(operation) }
        catch { return .failed(recordID: id, reason: .storageFailure) }
    }

    private static func perform(receipt: ExtractionResult, id: UUID, verifiedAt: Date,
        prepare: () throws -> CaseWorkBinding, save: (ExtractionRecord) throws -> Void
    ) -> ExtractionHistoryPublicationOutcome {
        let record: ExtractionRecord
        do {
            record = try ExtractionRecord.make(binding: prepare(), receipt: receipt,
                verifiedAt: verifiedAt, id: id)
        } catch {
            return .failed(recordID: id, reason: failure(error))
        }
        do {
            // Exactly one immutable save attempt. A post-rename failure must
            // not trigger a second UUID, overwrite, or remove the first record.
            try save(record)
            return .recorded(record)
        } catch CasePublicationError.publishedButDurabilityUnconfirmed(let publishedID) where publishedID == id {
            return .publishedButDurabilityUnconfirmed(record)
        } catch {
            return .failed(recordID: id, reason: failure(error))
        }
    }

    private static func failure(_ error: Error) -> ExtractionHistoryPublicationFailure {
        guard let error = error as? CaseWorkError else {
            if error is EngineError || error is AssistantContextError { return .invalidRecord }
            return .storageFailure
        }
        switch error {
        case .invalidRecord, .unsupportedVersion, .requestMismatch: return .invalidRecord
        case .invalidCase, .historyUnavailable: return .unavailableCase
        case .scopeMismatch: return .scopeMismatch
        case .unsafePath: return .unsafePath
        case .changedDuringOperation, .staleRevision: return .changedDuringPublication
        case .alreadyExists: return .recordAlreadyExists
        case .sizeLimit: return .recordTooLarge
        }
    }
}
