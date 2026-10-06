import Foundation

public struct EngineOptions: Codable, Sendable, Equatable {
    public var imageType: String
    public var sectorSize: Int
    public var timezone: String
    public var maxFiles: Int
    public var hashLogicalImage: Bool

    public init(imageType: String = "auto", sectorSize: Int = 0, timezone: String = "Asia/Bangkok", maxFiles: Int = 50_000, hashLogicalImage: Bool = true) {
        self.imageType = imageType
        self.sectorSize = sectorSize
        self.timezone = timezone
        self.maxFiles = maxFiles
        self.hashLogicalImage = hashLogicalImage
    }

    func validate() throws {
        guard ["auto", "raw", "ewf"].contains(imageType), [0, 512, 4096].contains(sectorSize),
              (1...50_000).contains(maxFiles), !timezone.isEmpty, timezone.utf8.count <= 256,
              TimeZone(identifier: timezone) != nil else {
            throw EngineError.invalidRequest("Unsupported image type, sector size, timezone or file limit.")
        }
    }
}

public enum EngineTerminalStatus: String, Codable, Sendable, Equatable {
    case completed, partial, failed, cancelled
}

public struct EngineImageMetadata: Codable, Sendable, Equatable {
    public let imageType: String
    public let logicalSize: Int64
    public let sectorSize: Int
    public let logicalSha256: String?
    public let imagePaths: [String]?
    public var hashScope: String { "logical-image-bytes" }

    public init(imageType: String, logicalSize: Int64, sectorSize: Int, logicalSha256: String? = nil, imagePaths: [String]? = nil) {
        self.imageType = imageType
        self.logicalSize = logicalSize
        self.sectorSize = sectorSize
        self.logicalSha256 = logicalSha256
        self.imagePaths = imagePaths
    }
}

public struct EngineVolume: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let offsetBytes: Int64
    public let filesystem: String
    public let blockSize: Int64
    public let blockCount: Int64

    public init(id: String, offsetBytes: Int64, filesystem: String, blockSize: Int64, blockCount: Int64) {
        self.id = id
        self.offsetBytes = offsetBytes
        self.filesystem = filesystem
        self.blockSize = blockSize
        self.blockCount = blockCount
    }
}

public struct FilesystemEntry: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let path: String
    public let name: String
    public let fsOffsetBytes: Int64
    public let metaAddress: UInt64
    public let attributeType: Int32?
    public let attributeID: Int32?
    public let size: Int64
    public let isDirectory: Bool
    public let isDeleted: Bool
    public let createdEpoch: Int64?
    public let modifiedEpoch: Int64?
    public let accessedEpoch: Int64?
    public let changedEpoch: Int64?
    public let createdNanoseconds: Int32
    public let modifiedNanoseconds: Int32
    public let accessedNanoseconds: Int32
    public let changedNanoseconds: Int32

    public init(id: String, path: String, name: String, fsOffsetBytes: Int64, metaAddress: UInt64, attributeType: Int32? = nil, attributeID: Int32? = nil, size: Int64, isDirectory: Bool, isDeleted: Bool, createdEpoch: Int64? = nil, modifiedEpoch: Int64? = nil, accessedEpoch: Int64? = nil, changedEpoch: Int64? = nil, createdNanoseconds: Int32 = 0, modifiedNanoseconds: Int32 = 0, accessedNanoseconds: Int32 = 0, changedNanoseconds: Int32 = 0) {
        self.id = id; self.path = path; self.name = name
        self.fsOffsetBytes = fsOffsetBytes; self.metaAddress = metaAddress
        self.attributeType = attributeType; self.attributeID = attributeID
        self.size = size; self.isDirectory = isDirectory; self.isDeleted = isDeleted
        self.createdEpoch = createdEpoch; self.modifiedEpoch = modifiedEpoch
        self.accessedEpoch = accessedEpoch; self.changedEpoch = changedEpoch
        self.createdNanoseconds = createdNanoseconds; self.modifiedNanoseconds = modifiedNanoseconds
        self.accessedNanoseconds = accessedNanoseconds; self.changedNanoseconds = changedNanoseconds
    }

    private enum CodingKeys: String, CodingKey {
        case id, path, name, fsOffsetBytes, metaAddress, attributeType, attributeID, size, isDirectory, isDeleted
        case createdEpoch, modifiedEpoch, accessedEpoch, changedEpoch
        case createdNanoseconds, modifiedNanoseconds, accessedNanoseconds, changedNanoseconds
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        path = try values.decode(String.self, forKey: .path)
        name = try values.decode(String.self, forKey: .name)
        fsOffsetBytes = try values.decode(Int64.self, forKey: .fsOffsetBytes)
        metaAddress = try values.decode(UInt64.self, forKey: .metaAddress)
        attributeType = try values.decodeIfPresent(Int32.self, forKey: .attributeType)
        attributeID = try values.decodeIfPresent(Int32.self, forKey: .attributeID)
        size = try values.decode(Int64.self, forKey: .size)
        isDirectory = try values.decode(Bool.self, forKey: .isDirectory)
        isDeleted = try values.decode(Bool.self, forKey: .isDeleted)
        createdEpoch = try values.decodeIfPresent(Int64.self, forKey: .createdEpoch)
        modifiedEpoch = try values.decodeIfPresent(Int64.self, forKey: .modifiedEpoch)
        accessedEpoch = try values.decodeIfPresent(Int64.self, forKey: .accessedEpoch)
        changedEpoch = try values.decodeIfPresent(Int64.self, forKey: .changedEpoch)
        createdNanoseconds = try values.decodeIfPresent(Int32.self, forKey: .createdNanoseconds) ?? 0
        modifiedNanoseconds = try values.decodeIfPresent(Int32.self, forKey: .modifiedNanoseconds) ?? 0
        accessedNanoseconds = try values.decodeIfPresent(Int32.self, forKey: .accessedNanoseconds) ?? 0
        changedNanoseconds = try values.decodeIfPresent(Int32.self, forKey: .changedNanoseconds) ?? 0
    }
}

public struct EngineProgress: Codable, Sendable, Equatable {
    public let stage: String
    public let completed: Int64
    public let total: Int64?
    public let unit: String
    public var fraction: Double? {
        guard let total, total > 0 else { return nil }
        return min(1, max(0, Double(completed) / Double(total)))
    }

    public init(stage: String, completed: Int64, total: Int64? = nil, unit: String) {
        self.stage = stage; self.completed = completed; self.total = total; self.unit = unit
    }
}

/// Each path describes exactly one input file, in the helper's read order.
/// Identity snapshots are for detecting replacement/editing, not content hashes.
public struct EngineSourceIdentity: Codable, Sendable, Equatable {
    public let path: String
    public let device: Int64
    public let inode: UInt64
    public let size: Int64
    public let modifiedSeconds: Int64
    public let modifiedNanoseconds: Int64
    public let changedSeconds: Int64
    public let changedNanoseconds: Int64

    init(path: String, identity: SourceIdentity) {
        self.path = path; device = Int64(identity.device); inode = UInt64(identity.inode); size = identity.size
        modifiedSeconds = Int64(identity.modifiedSeconds); modifiedNanoseconds = Int64(identity.modifiedNanoseconds)
        changedSeconds = Int64(identity.changedSeconds); changedNanoseconds = Int64(identity.changedNanoseconds)
    }

    func matches(_ identity: SourceIdentity) -> Bool {
        self == EngineSourceIdentity(path: path, identity: identity)
    }
}

public struct EnumerationResult: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let engineVersion: String
    public let patchDigest: String
    public let sourcePaths: [String]
    public let sourceIdentities: [EngineSourceIdentity]
    public let sourceFileHashes: [String: String]
    public let options: EngineOptions
    public let image: EngineImageMetadata
    public let volumes: [EngineVolume]
    public let files: [FilesystemEntry]
    public let warnings: [String]
    public let status: EngineTerminalStatus
    public let savedAt: Date

    public init(schemaVersion: Int = 1, engineVersion: String, patchDigest: String, sourcePaths: [String], sourceIdentities: [EngineSourceIdentity] = [], sourceFileHashes: [String: String] = [:], options: EngineOptions, image: EngineImageMetadata, volumes: [EngineVolume], files: [FilesystemEntry], warnings: [String], status: EngineTerminalStatus, savedAt: Date = Date()) {
        self.schemaVersion = schemaVersion; self.engineVersion = engineVersion; self.patchDigest = patchDigest
        self.sourcePaths = sourcePaths; self.sourceIdentities = sourceIdentities; self.sourceFileHashes = sourceFileHashes; self.options = options; self.image = image
        self.volumes = volumes; self.files = files; self.warnings = warnings; self.status = status; self.savedAt = savedAt
    }
}

public struct ExtractionResult: Codable, Sendable, Equatable {
    public let outputPath: String
    public let byteCount: Int64
    public let sha256: String
    public var hashScope: String { "extracted-file-bytes" }

    public init(outputPath: String, byteCount: Int64, sha256: String) {
        self.outputPath = outputPath; self.byteCount = byteCount; self.sha256 = sha256
    }
}

public struct EngineTimeouts: Sendable, Equatable {
    public let startup: TimeInterval
    public let inactivity: TimeInterval
    public let cancellationGrace: TimeInterval
    public let terminationGrace: TimeInterval

    public init(startup: TimeInterval = 120, inactivity: TimeInterval = 120, cancellationGrace: TimeInterval = 1, terminationGrace: TimeInterval = 1) {
        self.startup = startup; self.inactivity = inactivity
        self.cancellationGrace = cancellationGrace; self.terminationGrace = terminationGrace
    }
}

public enum EngineError: Error, LocalizedError, Sendable, Equatable {
    case invalidRequest(String)
    case protocolViolation(String)
    case limitExceeded(String)
    case helperFailed(String)
    case timeout(String)
    case invalidCache(String)
    case sourceChanged

    public var errorDescription: String? {
        switch self {
        case .invalidRequest(let detail), .protocolViolation(let detail), .limitExceeded(let detail),
             .helperFailed(let detail), .timeout(let detail), .invalidCache(let detail): detail
        case .sourceChanged: "The evidence source changed during the engine job. The result was rejected."
        }
    }
}

enum EngineValidation {
    static let frameLimit = 1_048_576
    static let resultLimit = 64 * 1_048_576
    static let stderrLimit = 65_536

    static func validHash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    static func text(_ value: String, maximum: Int = 32_768, allowEmpty: Bool = false) -> Bool {
        (allowEmpty || !value.isEmpty) && value.utf8.count <= maximum && !value.utf8.contains(0)
    }

    static func image(_ image: EngineImageMetadata) throws {
        guard text(image.imageType, maximum: 64), image.logicalSize >= 0, image.sectorSize > 0,
              image.sectorSize <= 65_536,
              image.logicalSha256.map(validHash) ?? true else {
            throw EngineError.protocolViolation("Invalid image metadata.")
        }
    }

    static func file(_ file: FilesystemEntry) throws {
        guard text(file.id, maximum: 1024), text(file.path), text(file.name, allowEmpty: true),
              file.fsOffsetBytes >= 0, file.size >= 0,
              (file.attributeType == nil) == (file.attributeID == nil),
              file.attributeType.map({ $0 >= 0 }) ?? true,
              file.attributeID.map({ $0 >= 0 }) ?? true,
              [file.createdNanoseconds, file.modifiedNanoseconds, file.accessedNanoseconds, file.changedNanoseconds].allSatisfy({ (0..<1_000_000_000).contains($0) }) else {
            throw EngineError.protocolViolation("Invalid filesystem entry.")
        }
    }

    static func result(_ result: EnumerationResult) throws {
        guard result.schemaVersion == 1, [.completed, .partial].contains(result.status),
              text(result.engineVersion, maximum: 256), text(result.patchDigest, maximum: 256),
              !result.sourcePaths.isEmpty, result.sourcePaths.count <= 1024,
              result.sourcePaths.allSatisfy({ $0.hasPrefix("/") && text($0) }),
              Set(result.sourcePaths).count == result.sourcePaths.count,
              result.files.count <= result.options.maxFiles,
              result.warnings.count <= 1024, result.warnings.allSatisfy({ text($0, maximum: 65_536) }),
              Set(result.files.map(\.id)).count == result.files.count,
              Set(result.volumes.map(\.id)).count == result.volumes.count else {
            throw EngineError.invalidCache("The filesystem result has an unsupported version or invalid records.")
        }
        try result.options.validate()
        try image(result.image)
        for volume in result.volumes { try self.volume(volume) }
        for file in result.files { try self.file(file) }
        if !result.sourceIdentities.isEmpty {
            guard result.sourceIdentities.map(\.path) == result.sourcePaths,
                  result.sourceIdentities.allSatisfy({ $0.size >= 0 }) else {
                throw EngineError.invalidCache("Source identity scope does not match the ordered inputs.")
            }
        }
        guard Set(result.sourceFileHashes.keys) == Set(result.sourcePaths),
              result.sourceFileHashes.values.allSatisfy(validHash) else {
            throw EngineError.invalidCache("Container-file SHA-256 scope does not match the ordered image inputs.")
        }
        if let imagePaths = result.image.imagePaths, imagePaths != result.sourcePaths {
            throw EngineError.invalidCache("Engine image paths do not match the verified input scope.")
        }
    }

    static func volume(_ volume: EngineVolume) throws {
        guard text(volume.id, maximum: 1024), text(volume.filesystem, maximum: 128), volume.offsetBytes >= 0,
              volume.blockSize > 0, volume.blockCount >= 0 else {
            throw EngineError.protocolViolation("Invalid filesystem volume metadata.")
        }
    }
}
