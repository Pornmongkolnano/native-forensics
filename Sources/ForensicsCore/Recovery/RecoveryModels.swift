import Foundation

/// Source extents and output offsets are byte offsets, never filesystem addresses.
public struct RecoveryByteRun: Codable, Sendable, Equatable {
    public let outputOffset: Int64
    public let sourceOffset: Int64
    public let length: Int64
    public init(outputOffset: Int64, sourceOffset: Int64, length: Int64) {
        self.outputOffset = outputOffset; self.sourceOffset = sourceOffset; self.length = length
    }
}

public enum RecoveryValidationStatus: String, Codable, Sendable { case sourceBytesVerified, unverified }

/// A signature recovery candidate. A verified byte mapping does not prove that
/// a decoder can open the file, establish its original name, or show deletion.
public struct CarvedArtifact: Codable, Sendable, Equatable, Identifiable {
    public let id: UUID
    public let filename: String
    public let relativePath: String
    public let formatHint: String
    public let byteCount: Int64
    public let sha256: String
    public let reportedByteRuns: [RecoveryByteRun]
    public let verifiedByteRuns: [RecoveryByteRun]
    public let validationStatus: RecoveryValidationStatus
    public let warnings: [String]
    public var deletionStatus: String { "unknown" }
    public var hashScope: String { "recovered-file-bytes" }
    public var formatHintScope: String { "PhotoRec recovery filename extension" }

    public init(id: UUID = UUID(), filename: String, relativePath: String, formatHint: String,
                byteCount: Int64, sha256: String, reportedByteRuns: [RecoveryByteRun],
                verifiedByteRuns: [RecoveryByteRun], validationStatus: RecoveryValidationStatus,
                warnings: [String] = []) {
        self.id = id; self.filename = filename; self.relativePath = relativePath; self.formatHint = formatHint
        self.byteCount = byteCount; self.sha256 = sha256; self.reportedByteRuns = reportedByteRuns
        self.verifiedByteRuns = verifiedByteRuns; self.validationStatus = validationStatus; self.warnings = warnings
    }
}

public struct RecoveryOptions: Codable, Sendable, Equatable {
    public var maximumFiles: Int
    public var maximumOutputBytes: Int64
    public var maximumArtifactBytes: Int64
    public var maximumInputBytes: Int64
    public var timeout: TimeInterval
    /// Record the exact fixed command with each job. Legacy schema-1 results
    /// omitted it and used auto-detected partition selection via `search`.
    public let photoRecCommand: String
    public init(maximumFiles: Int = 5_000, maximumOutputBytes: Int64 = 2_147_483_648,
                maximumArtifactBytes: Int64 = 536_870_912, maximumInputBytes: Int64 = 34_359_738_368,
                timeout: TimeInterval = 600) {
        self.maximumFiles = maximumFiles; self.maximumOutputBytes = maximumOutputBytes
        self.maximumArtifactBytes = maximumArtifactBytes; self.maximumInputBytes = maximumInputBytes
        self.timeout = timeout
        self.photoRecCommand = "partition_none,wholespace,search"
    }
    public var scanScope: String {
        photoRecCommand == "search" ? "auto-detected-selected-partition" : "whole-single-RAW-image"
    }

    private enum CodingKeys: String, CodingKey {
        case maximumFiles, maximumOutputBytes, maximumArtifactBytes, maximumInputBytes, timeout, photoRecCommand
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        maximumFiles = try values.decode(Int.self, forKey: .maximumFiles)
        maximumOutputBytes = try values.decode(Int64.self, forKey: .maximumOutputBytes)
        maximumArtifactBytes = try values.decode(Int64.self, forKey: .maximumArtifactBytes)
        maximumInputBytes = try values.decode(Int64.self, forKey: .maximumInputBytes)
        timeout = try values.decode(TimeInterval.self, forKey: .timeout)
        photoRecCommand = values.contains(.photoRecCommand)
            ? try values.decode(String.self, forKey: .photoRecCommand) : "search"
        try validate()
    }
    func validate() throws {
        guard (1...5_000).contains(maximumFiles), (1...2_147_483_648).contains(maximumOutputBytes),
              (1...maximumOutputBytes).contains(maximumArtifactBytes),
              (1...34_359_738_368).contains(maximumInputBytes), timeout.isFinite,
              (1...3_600).contains(timeout),
              ["search", "partition_none,wholespace,search"].contains(photoRecCommand) else { throw RecoveryError.invalidOptions }
    }
}

public struct RecoveryProgress: Sendable, Equatable {
    public let stage: String
    public let completed: Int64
    public let total: Int64?
    public let unit: String
    public init(stage: String, completed: Int64 = 0, total: Int64? = nil, unit: String = "bytes") {
        self.stage = stage; self.completed = completed; self.total = total; self.unit = unit
    }
}

public struct CarvingResult: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let caseID: UUID
    public let sourceEvidenceID: UUID
    public let sourceSHA256: String
    public let sourceByteCount: Int64
    public let jobID: UUID
    public let status: EngineTerminalStatus
    public let artifacts: [CarvedArtifact]
    public let warnings: [String]
    public let photoRecVersion: String
    public let executableSHA256: String
    public let options: RecoveryOptions
    public let savedAt: Date
    public var sourceHashScope: String { FileHashScope.selectedFileBytes }
    public var sourceOffsetScope: String { "selected-single-RAW-file-bytes" }

    public init(schemaVersion: Int = 1, caseID: UUID, sourceEvidenceID: UUID, sourceSHA256: String,
                sourceByteCount: Int64, jobID: UUID = UUID(), status: EngineTerminalStatus,
                artifacts: [CarvedArtifact], warnings: [String], photoRecVersion: String,
                executableSHA256: String, options: RecoveryOptions, savedAt: Date = Date()) {
        self.schemaVersion = schemaVersion; self.caseID = caseID; self.sourceEvidenceID = sourceEvidenceID
        self.sourceSHA256 = sourceSHA256; self.sourceByteCount = sourceByteCount; self.jobID = jobID
        self.status = status; self.artifacts = artifacts; self.warnings = warnings
        self.photoRecVersion = photoRecVersion; self.executableSHA256 = executableSHA256
        self.options = options; self.savedAt = savedAt
    }

    func validate() throws {
        try options.validate()
        guard schemaVersion == 1, [.completed, .partial].contains(status),
              EngineValidation.validHash(sourceSHA256), EngineValidation.validHash(executableSHA256),
              sourceByteCount >= 0, sourceByteCount <= options.maximumInputBytes,
              savedAt.timeIntervalSince1970.isFinite, EngineValidation.text(photoRecVersion, maximum: 4_096),
              artifacts.count <= options.maximumFiles, Set(artifacts.map(\.id)).count == artifacts.count,
              Set(artifacts.map(\.relativePath)).count == artifacts.count,
              warnings.count <= 64, warnings.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) else {
            throw RecoveryError.invalidResult
        }
        var total: Int64 = 0
        for artifact in artifacts {
            try artifact.validate(sourceSize: sourceByteCount, options: options)
            guard artifact.byteCount <= options.maximumOutputBytes - total else { throw RecoveryError.outputLimit }
            total += artifact.byteCount
        }
    }
}

extension CarvedArtifact {
    func validate(sourceSize: Int64, options: RecoveryOptions) throws {
        guard EngineValidation.text(filename, maximum: 1_024), filename != ".", filename != "..",
              !filename.contains("/"), !filename.contains("\\"),
              relativePath == "files/\(id.uuidString.lowercased())",
              EngineValidation.text(formatHint, maximum: 64, allowEmpty: true),
              byteCount >= 0, byteCount <= options.maximumArtifactBytes,
              EngineValidation.validHash(sha256), reportedByteRuns.count <= 8_192,
              verifiedByteRuns.count <= 8_192, warnings.count <= 32,
              warnings.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) else { throw RecoveryError.invalidResult }
        for run in reportedByteRuns + verifiedByteRuns {
            guard run.outputOffset >= 0, run.sourceOffset >= 0, run.length > 0,
                  run.sourceOffset <= sourceSize, run.length <= sourceSize - run.sourceOffset,
                  run.outputOffset <= Int64.max - run.length else { throw RecoveryError.invalidResult }
        }
        if validationStatus == .sourceBytesVerified {
            var covered: Int64 = 0
            var expectedRuns: [RecoveryByteRun] = []
            for run in reportedByteRuns {
                if covered == byteCount { break }
                guard run.outputOffset == covered else { throw RecoveryError.invalidResult }
                let clipped = min(run.length, byteCount - covered)
                if clipped > 0 { expectedRuns.append(RecoveryByteRun(outputOffset: covered, sourceOffset: run.sourceOffset, length: clipped)) }
                covered += clipped
            }
            guard covered == byteCount, expectedRuns == verifiedByteRuns else { throw RecoveryError.invalidResult }
            covered = 0
            for run in verifiedByteRuns {
                guard run.outputOffset == covered, run.length <= byteCount - covered else { throw RecoveryError.invalidResult }
                covered += run.length
            }
            guard covered == byteCount else { throw RecoveryError.invalidResult }
        } else if !verifiedByteRuns.isEmpty { throw RecoveryError.invalidResult }
    }
}

public enum RecoveryError: Error, LocalizedError, Sendable, Equatable {
    case invalidOptions, unsupportedSource, sourceChanged, unavailable, launchFailed, timeout, outputLimit
    case invalidReport, invalidResult, invalidCase, scopeMismatch, storageChanged, artifactChanged, destinationExists
    case toolFailed(Int32)
    public var errorDescription: String? {
        switch self {
        case .invalidOptions: "Recovery limits or timeout are invalid."
        case .unsupportedSource: "Recovery currently supports one regular RAW image. EWF, split images, directories and devices are unsupported."
        case .sourceChanged: "The evidence bytes or source identity changed. No recovery result was published."
        case .unavailable: "A verified local PhotoRec executable is unavailable."
        case .launchFailed: "The owned PhotoRec process could not be started."
        case .timeout: "PhotoRec exceeded the recovery deadline. No previous results were changed."
        case .outputLimit: "Recovery exceeded its bounded file, byte or diagnostic limit. No previous results were changed."
        case .invalidReport: "The PhotoRec report is malformed, incomplete or contains unsafe file references."
        case .invalidResult: "The recovery result did not pass validation."
        case .invalidCase: "The recovery case is unavailable or invalid."
        case .scopeMismatch: "Recovery provenance does not match this case and evidence record."
        case .storageChanged: "Recovery storage changed during the operation."
        case .artifactChanged: "The historical recovered bytes failed their size or hash check."
        case .destinationExists: "Choose a new export destination; existing files are never overwritten."
        case .toolFailed(let status): "PhotoRec did not complete successfully (status \(status))."
        }
    }
}
