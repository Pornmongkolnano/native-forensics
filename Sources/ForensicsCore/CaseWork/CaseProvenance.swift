import CryptoKit
import Foundation

/// A reproducible local component identity. An absent executable digest is
/// explicit unknown information; a version label alone is not a binary receipt.
public struct CaseComponentProvenance: Codable, Sendable, Equatable {
    public let identifier: String
    public let version: String
    public let buildDigest: String
    public let executableSHA256: String?
    public init(identifier: String, version: String, buildDigest: String, executableSHA256: String? = nil) {
        self.identifier = identifier; self.version = version; self.buildDigest = buildDigest
        self.executableSHA256 = executableSHA256
    }
    func validate() throws {
        guard EngineValidation.text(identifier, maximum: 256), EngineValidation.text(version, maximum: 256),
              EngineValidation.text(buildDigest, maximum: 256),
              executableSHA256.map(EngineValidation.validHash) ?? true else { throw CaseProvenanceError.invalid }
    }
}

public struct CaseJobSourceHash: Codable, Sendable, Equatable {
    public let ordinal: Int
    public let scope: String
    public let sha256: String
    public let byteCount: Int64?
    public init(ordinal: Int, scope: String = FileHashScope.selectedFileBytes, sha256: String, byteCount: Int64?) {
        self.ordinal = ordinal; self.scope = scope; self.sha256 = sha256; self.byteCount = byteCount
    }
}

/// Reconstructible options and ordered source hashes, rather than a digest of
/// unavailable parameters. No source pathname is copied into a job receipt.
public struct CaseJobProvenance: Codable, Sendable, Equatable, Identifiable {
    public let id: UUID
    public let evidenceID: UUID
    public let kind: String
    public let startedAt: Date
    public let completedAt: Date
    public let status: EngineTerminalStatus
    public let component: CaseComponentProvenance
    public let optionsJSON: String
    public let optionsSHA256: String
    public let sourceHashes: [CaseJobSourceHash]
    public let selectedSourceOrdinal: Int
    public let warnings: [String]
    public let artifactRelativePath: String?
    public let artifactSHA256: String?
    /// Exact serialized artifact size when observed by its producer. Older
    /// schema 2 receipts may omit this field; unknown is never inferred.
    public let artifactByteCount: Int?
    public var isPartial: Bool { status != .completed }

    private enum CodingKeys: String, CodingKey {
        case id, evidenceID, kind, startedAt, completedAt, status, component, optionsJSON, optionsSHA256
        case sourceHashes, selectedSourceOrdinal, warnings, artifactRelativePath, artifactSHA256, artifactByteCount
    }
    private init(id: UUID, evidenceID: UUID, kind: String, startedAt: Date, completedAt: Date,
        status: EngineTerminalStatus, component: CaseComponentProvenance, optionsJSON: String,
        optionsSHA256: String, sourceHashes: [CaseJobSourceHash], selectedSourceOrdinal: Int, warnings: [String],
        artifactRelativePath: String?, artifactSHA256: String?, artifactByteCount: Int?) {
        self.id = id; self.evidenceID = evidenceID; self.kind = kind
        self.startedAt = startedAt; self.completedAt = completedAt; self.status = status; self.component = component
        self.optionsJSON = optionsJSON; self.optionsSHA256 = optionsSHA256; self.sourceHashes = sourceHashes
        self.selectedSourceOrdinal = selectedSourceOrdinal
        self.warnings = warnings; self.artifactRelativePath = artifactRelativePath; self.artifactSHA256 = artifactSHA256
        self.artifactByteCount = artifactByteCount
    }
    public init(from decoder: Decoder) throws {
        let value = try decoder.container(keyedBy: CodingKeys.self)
        id = try value.decode(UUID.self, forKey: .id); evidenceID = try value.decode(UUID.self, forKey: .evidenceID)
        kind = try value.decode(String.self, forKey: .kind)
        // Reference-date Doubles preserve exact subsecond instants independently
        // of the outer historical manifest's ISO8601 date strategy.
        startedAt = Date(timeIntervalSinceReferenceDate: try value.decode(Double.self, forKey: .startedAt))
        completedAt = Date(timeIntervalSinceReferenceDate: try value.decode(Double.self, forKey: .completedAt))
        status = try value.decode(EngineTerminalStatus.self, forKey: .status)
        component = try value.decode(CaseComponentProvenance.self, forKey: .component)
        optionsJSON = try value.decode(String.self, forKey: .optionsJSON)
        optionsSHA256 = try value.decode(String.self, forKey: .optionsSHA256)
        sourceHashes = try value.decode([CaseJobSourceHash].self, forKey: .sourceHashes)
        selectedSourceOrdinal = try value.decode(Int.self, forKey: .selectedSourceOrdinal)
        warnings = try value.decode([String].self, forKey: .warnings)
        artifactRelativePath = try value.decodeIfPresent(String.self, forKey: .artifactRelativePath)
        artifactSHA256 = try value.decodeIfPresent(String.self, forKey: .artifactSHA256)
        artifactByteCount = try value.decodeIfPresent(Int.self, forKey: .artifactByteCount)
    }
    public func encode(to encoder: Encoder) throws {
        var value = encoder.container(keyedBy: CodingKeys.self)
        try value.encode(id, forKey: .id); try value.encode(evidenceID, forKey: .evidenceID)
        try value.encode(kind, forKey: .kind)
        try value.encode(startedAt.timeIntervalSinceReferenceDate, forKey: .startedAt)
        try value.encode(completedAt.timeIntervalSinceReferenceDate, forKey: .completedAt)
        try value.encode(status, forKey: .status); try value.encode(component, forKey: .component)
        try value.encode(optionsJSON, forKey: .optionsJSON); try value.encode(optionsSHA256, forKey: .optionsSHA256)
        try value.encode(sourceHashes, forKey: .sourceHashes)
        try value.encode(selectedSourceOrdinal, forKey: .selectedSourceOrdinal); try value.encode(warnings, forKey: .warnings)
        try value.encodeIfPresent(artifactRelativePath, forKey: .artifactRelativePath)
        try value.encodeIfPresent(artifactSHA256, forKey: .artifactSHA256)
        try value.encodeIfPresent(artifactByteCount, forKey: .artifactByteCount)
    }

    public static func make<Options: Encodable>(id: UUID = UUID(), evidenceID: UUID, kind: String,
        startedAt: Date, completedAt: Date, status: EngineTerminalStatus, component: CaseComponentProvenance,
        options: Options, sourceHashes: [CaseJobSourceHash], selectedSourceOrdinal: Int = 0, warnings: [String],
        artifactRelativePath: String? = nil, artifactSHA256: String? = nil, artifactByteCount: Int? = nil) throws -> Self {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let optionsData = try encoder.encode(options)
        let canonical = try canonicalOptions(optionsData)
        let value = Self(id: id, evidenceID: evidenceID, kind: kind, startedAt: startedAt,
            completedAt: completedAt, status: status, component: component,
            optionsJSON: String(decoding: canonical, as: UTF8.self), optionsSHA256: digest(canonical),
            sourceHashes: sourceHashes, selectedSourceOrdinal: selectedSourceOrdinal, warnings: warnings, artifactRelativePath: artifactRelativePath,
            artifactSHA256: artifactSHA256, artifactByteCount: artifactByteCount)
        try value.validate(); return value
    }

    public static func enumeration(id: UUID = UUID(), evidence: EvidenceRecord, result: EnumerationResult,
        startedAt: Date, executableSHA256: String? = nil,
        artifactRelativePath: String? = nil, artifactSHA256: String? = nil, artifactByteCount: Int? = nil) throws -> Self {
        try EngineValidation.result(result)
        guard let selectedOrdinal = result.sourcePaths.firstIndex(of: evidence.sourcePath),
              result.sourceFileHashes[evidence.sourcePath] == evidence.sha256 else { throw CaseProvenanceError.scopeMismatch }
        let hashes = try result.sourcePaths.enumerated().map { ordinal, path in
            guard let sha = result.sourceFileHashes[path] else { throw CaseProvenanceError.scopeMismatch }
            let size = ordinal == selectedOrdinal ? evidence.byteCount : result.sourceIdentities.first { $0.path == path }?.size
            return CaseJobSourceHash(ordinal: ordinal, sha256: sha, byteCount: size)
        }
        // Diagnostics can contain host paths. Retain all warning text after
        // replacing each exact known source path; no warning is silently dropped.
        let warnings = result.warnings.map { warning in
            result.sourcePaths.enumerated().reduce(warning) { text, source in
                text.replacingOccurrences(of: source.element, with: "[selected-source-\(source.offset)]")
            }
        }
        return try make(id: id, evidenceID: evidence.id, kind: "filesystem.enumeration", startedAt: startedAt,
            completedAt: result.savedAt, status: result.status,
            component: .init(identifier: "NFTSKEngine", version: result.engineVersion,
                buildDigest: result.patchDigest, executableSHA256: executableSHA256),
            options: result.options, sourceHashes: hashes, selectedSourceOrdinal: selectedOrdinal, warnings: warnings,
            artifactRelativePath: artifactRelativePath, artifactSHA256: artifactSHA256, artifactByteCount: artifactByteCount)
    }

    /// Used only to compare an older receipt that explicitly has no size field
    /// with a reconstructed current producer receipt. It does not persist or
    /// infer a new size for that historical record.
    func preservingUnknownArtifactSize() -> Self {
        Self(id: id, evidenceID: evidenceID, kind: kind, startedAt: startedAt, completedAt: completedAt,
            status: status, component: component, optionsJSON: optionsJSON, optionsSHA256: optionsSHA256,
            sourceHashes: sourceHashes, selectedSourceOrdinal: selectedSourceOrdinal, warnings: warnings,
            artifactRelativePath: artifactRelativePath, artifactSHA256: artifactSHA256, artifactByteCount: nil)
    }

    func validate() throws {
        try component.validate()
        guard EngineValidation.text(kind, maximum: 256), startedAt.timeIntervalSince1970.isFinite,
              completedAt.timeIntervalSince1970.isFinite, completedAt >= startedAt,
              !sourceHashes.isEmpty, sourceHashes.count <= 1_024, sourceHashes.indices.contains(selectedSourceOrdinal),
              sourceHashes.enumerated().allSatisfy({ $0.offset == $0.element.ordinal &&
                  $0.element.scope == FileHashScope.selectedFileBytes && EngineValidation.validHash($0.element.sha256) &&
                  ($0.element.byteCount.map { $0 >= 0 } ?? true) }),
              warnings.count <= 1_024, warnings.allSatisfy({ EngineValidation.text($0, maximum: 65_536) }),
              warnings.reduce(0, { $0 + $1.utf8.count }) <= 8 * 1_048_576,
              optionsJSON.utf8.count <= 65_536,
              EngineValidation.validHash(optionsSHA256),
              try Self.canonicalOptions(Data(optionsJSON.utf8)) == Data(optionsJSON.utf8),
              Self.digest(Data(optionsJSON.utf8)) == optionsSHA256,
              (artifactRelativePath == nil) == (artifactSHA256 == nil),
              artifactByteCount.map({ $0 >= 0 && artifactRelativePath != nil && artifactSHA256 != nil }) ?? true,
              artifactSHA256.map(EngineValidation.validHash) ?? true else { throw CaseProvenanceError.invalid }
        if let path = artifactRelativePath {
            let parts = path.split(separator: "/", omittingEmptySubsequences: false)
            guard !path.hasPrefix("/"), path.utf8.count <= 4_096, !path.utf8.contains(0),
                  !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\\") }) else {
                throw CaseProvenanceError.invalid
            }
        }
    }

    private static func canonicalOptions(_ bytes: Data) throws -> Data {
        guard bytes.count <= 65_536,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { throw CaseProvenanceError.invalid }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

public struct CaseMigrationReceipt: Codable, Sendable, Equatable {
    public let id: UUID
    public let procedureVersion: String
    public let sourceSchemaVersion: Int
    public let targetSchemaVersion: Int
    public let performedAt: Date
    public let originalManifestSHA256: String
    public let originalManifestByteCount: Int
    public var backupFilename: String { id.uuidString.lowercased() + ".json" }
    func validate() throws {
        guard procedureVersion == "case-manifest.v1-to-v2.1", sourceSchemaVersion == 1, targetSchemaVersion == 2,
              performedAt.timeIntervalSince1970.isFinite, EngineValidation.validHash(originalManifestSHA256),
              (1...16 * 1_048_576).contains(originalManifestByteCount) else { throw CaseProvenanceError.invalid }
    }
}

public struct CaseManifestProvenance: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let migration: CaseMigrationReceipt
    public let jobs: [CaseJobProvenance]
    public init(migration: CaseMigrationReceipt, jobs: [CaseJobProvenance] = []) {
        self.schemaVersion = 1; self.migration = migration; self.jobs = jobs
    }
    func validate(evidence: [EvidenceRecord]) throws {
        guard schemaVersion == 1, jobs.count <= 10_000 else { throw CaseProvenanceError.invalid }
        try migration.validate()
        var ids = Set<UUID>()
        for job in jobs {
            try job.validate()
            guard ids.insert(job.id).inserted,
                  let source = evidence.first(where: { $0.id == job.evidenceID }),
                  job.sourceHashes[job.selectedSourceOrdinal].sha256 == source.sha256,
                  job.sourceHashes[job.selectedSourceOrdinal].byteCount == source.byteCount else { throw CaseProvenanceError.scopeMismatch }
        }
    }
}

public enum CaseProvenanceError: Error, LocalizedError, Equatable, Sendable {
    case invalid, scopeMismatch, migrationRequired, rollbackWouldDiscardChanges
    public var errorDescription: String? {
        switch self {
        case .invalid: "Case provenance or migration data is invalid; original records were preserved."
        case .scopeMismatch: "Job provenance does not match this case's recorded source hash and byte count."
        case .migrationRequired: "This operation requires an explicitly migrated schema 2 case. Opening a schema 1 case never migrates it automatically."
        case .rollbackWouldDiscardChanges: "Rollback would discard newer evidence or job provenance. Export that work before choosing a different case migration."
        }
    }
}
