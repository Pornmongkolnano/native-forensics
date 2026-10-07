import Foundation

public enum CaseIntegrityStatus: String, Codable, Sendable, CaseIterable {
    case pass, fail, historical, offline, unavailable
}

public struct CaseIntegrityCheck: Codable, Sendable, Equatable, Identifiable {
    public let id: UUID
    public let status: CaseIntegrityStatus
    public let code: String
    public let relativePath: String?
    public let evidenceID: UUID?
    public let privatePath: String?
    public let byteCount: Int64?
    public let sha256: String?
    public let recordedByteCount: Int64?
    public let recordedSHA256: String?
    public let message: String

    public init(id: UUID = UUID(), status: CaseIntegrityStatus, code: String, relativePath: String? = nil,
                evidenceID: UUID? = nil, privatePath: String? = nil, byteCount: Int64? = nil,
                sha256: String? = nil, recordedByteCount: Int64? = nil, recordedSHA256: String? = nil, message: String) {
        self.id = id; self.status = status; self.code = code; self.relativePath = relativePath
        self.evidenceID = evidenceID; self.privatePath = privatePath; self.byteCount = byteCount
        self.sha256 = sha256; self.message = message
        self.recordedByteCount = recordedByteCount; self.recordedSHA256 = recordedSHA256
    }
}

public struct CaseIntegrityReport: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let id: UUID
    public let caseID: UUID
    public let casePath: String
    public let manifestSHA256: String?
    public let startedAt: Date
    public let completedAt: Date
    /// Explicit requested mode, not a claim that every source was online or verified.
    public let sourceRehashed: Bool
    public let isPartial: Bool
    public let checks: [CaseIntegrityCheck]
    public var hasFailures: Bool { checks.contains { $0.status == .fail } }
    public var verifiedSourceCount: Int { checks.filter { $0.code == "source.verified" && $0.status == .pass }.count }

    public init(schemaVersion: Int = 1, id: UUID = UUID(), caseID: UUID, casePath: String,
                manifestSHA256: String?, startedAt: Date = Date(), completedAt: Date = Date(),
                sourceRehashed: Bool, isPartial: Bool, checks: [CaseIntegrityCheck]) {
        self.schemaVersion = schemaVersion; self.id = id; self.caseID = caseID; self.casePath = casePath
        self.manifestSHA256 = manifestSHA256; self.startedAt = startedAt; self.completedAt = completedAt
        self.sourceRehashed = sourceRehashed; self.isPartial = isPartial; self.checks = checks
    }
}

public struct CaseIntegrityAuditOptions: Sendable, Equatable {
    public let freshEvidenceRehash: Bool
    public let maximumFiles: Int
    public let maximumMetadataBytes: Int64
    public let maximumPayloadBytes: Int64
    public let maximumSourceBytes: Int64
    public let timeoutSeconds: TimeInterval
    public init(freshEvidenceRehash: Bool = false, maximumFiles: Int = 10_000,
                maximumMetadataBytes: Int64 = 268_435_456, maximumPayloadBytes: Int64 = 2_147_483_648,
                maximumSourceBytes: Int64 = 34_359_738_368, timeoutSeconds: TimeInterval = 120) {
        self.freshEvidenceRehash = freshEvidenceRehash; self.maximumFiles = maximumFiles
        self.maximumMetadataBytes = maximumMetadataBytes; self.maximumPayloadBytes = maximumPayloadBytes
        self.maximumSourceBytes = maximumSourceBytes; self.timeoutSeconds = timeoutSeconds
    }
}

public struct CaseIntegrityProgress: Sendable, Equatable {
    public let stage: String
    public let checkedFiles: Int
    public let bytesRead: Int64
    public init(stage: String, checkedFiles: Int, bytesRead: Int64) {
        self.stage = stage; self.checkedFiles = checkedFiles; self.bytesRead = bytesRead
    }
}

public enum CaseIntegrityReportFormat: String, Sendable, CaseIterable { case json, markdown }

enum CaseIntegrityAuditError: Error {
    case limit, unsafe, changed, invalid, unsupported
}
