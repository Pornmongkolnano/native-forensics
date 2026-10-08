import Foundation

/// Internal deterministic seams at the real staging and commit boundaries.
/// Passing a fault here models a failed syscall or interrupted process; it is
/// not evidence that a power failure was physically exercised.
enum CasePersistenceCheckpoint: String, CaseIterable, Sendable {
    case beforeWrite, afterWriteChunk, beforeFileFlush, afterFileFlush
    case beforeRename, afterRename, beforeDirectoryFlush, afterDirectoryFlush
}

public enum CasePublicationError: Error, LocalizedError, Sendable, Equatable {
    case publishedButDurabilityUnconfirmed(recordID: UUID)
    public var errorDescription: String? {
        switch self {
        case .publishedButDurabilityUnconfirmed(let id):
            "Record \(id.uuidString.lowercased()) was published, but its durable completion could not be confirmed. Reload that record before retrying; the existing record was preserved."
        }
    }
}

public enum CaseManifestPublicationError: Error, LocalizedError, Sendable, Equatable {
    case publishedButDurabilityUnconfirmed(caseID: UUID)
    public var errorDescription: String? {
        "The case manifest was published, but durable completion could not be confirmed. Reopen the case before retrying; no prior evidence or immutable work record was removed."
    }
}
