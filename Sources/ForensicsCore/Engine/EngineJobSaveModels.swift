import Foundation

public enum EngineJobCommitState: String, Codable, Sendable, Equatable {
    case notCommitted, confirmed, uncertain
}

public struct EngineJobSaveReceipt: Sendable {
    public let forensicCase: ForensicCase
    public let job: CaseJobProvenance
    public let artifactRelativePath: String
    public let artifactSHA256: String
    public let artifactByteCount: Int
    /// True only when this exact immutable manifest job was already recorded.
    public let wasAlreadyRecorded: Bool
    /// Historical retries do not replace a newer job's convenience cache.
    public let latestCacheUpdated: Bool
}

public enum EngineJobSaveError: Error, LocalizedError, Sendable, Equatable {
    case jobConflict, artifactUnavailable
    case publishedButIncomplete(jobID: UUID, artifactSHA256: String,
        artifactState: EngineJobCommitState, manifestState: EngineJobCommitState,
        latestCacheState: EngineJobCommitState)
    public var errorDescription: String? {
        switch self {
        case .jobConflict:
            "This job identifier already refers to different listing bytes or provenance. Its original records were preserved."
        case .artifactUnavailable:
            "This recorded job's immutable artifact is missing or unsafe. It was not automatically repaired."
        case .publishedButIncomplete:
            "A job artifact or manifest was published, but the complete durable save could not be confirmed. Reopen the case and inspect this job before retrying; existing artifacts and records were preserved."
        }
    }
}

enum EngineJobSaveCheckpoint: String, CaseIterable, Sendable {
    case beforeArtifactWrite, afterArtifactWriteChunk, beforeArtifactFileFlush, afterArtifactFileFlush
    case beforeArtifactRename, afterArtifactRename, beforeArtifactDirectoryFlush, afterArtifactDirectoryFlush
    case beforeManifestRecord, afterManifestRecord
    case beforeLatestWrite, afterLatestWriteChunk, beforeLatestFileFlush, afterLatestFileFlush
    case beforeLatestRename, afterLatestRename, beforeLatestDirectoryFlush, afterLatestDirectoryFlush
    case complete
}
