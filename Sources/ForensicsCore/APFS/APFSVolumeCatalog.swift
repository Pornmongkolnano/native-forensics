import Foundation

/// Source-bound inventory. An encrypted declaration is metadata, not proof that
/// a credential, crypto user, boot acquisition or plaintext read is supported.
public struct APFSVolumeDescriptor: Codable, Sendable, Equatable, Identifiable {
    public let volumeUUID: UUID
    public let containerUUID: UUID
    public let name: String
    public let roles: [String]
    public let volumeGroupUUID: UUID?
    public let encrypted: Bool
    public let locked: Bool
    public var id: UUID { volumeUUID }

    public init(volumeUUID: UUID, containerUUID: UUID, name: String, roles: [String],
                volumeGroupUUID: UUID? = nil, encrypted: Bool, locked: Bool) {
        self.volumeUUID = volumeUUID; self.containerUUID = containerUUID; self.name = name
        self.roles = roles; self.volumeGroupUUID = volumeGroupUUID
        self.encrypted = encrypted; self.locked = locked
    }
}

public struct APFSVolumeCatalogResult: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let evidenceID: UUID
    public let containerSHA256: String
    public let containerByteCount: Int64
    public let hashScope: String
    public let driver: String
    public let driverVersion: String
    public let options: APFSReadOptions
    public let containerEncryption: APFSContainerEncryption
    public let volumes: [APFSVolumeDescriptor]
    public let volumeGroupInventoryAvailable: Bool
    public let warnings: [String]

    public init(schemaVersion: Int = 1, evidenceID: UUID, containerSHA256: String,
                containerByteCount: Int64, hashScope: String = FileHashScope.selectedFileBytes,
                driver: String = "apple-system-readonly-apfs-v1", driverVersion: String,
                options: APFSReadOptions = .init(), containerEncryption: APFSContainerEncryption,
                volumes: [APFSVolumeDescriptor], volumeGroupInventoryAvailable: Bool = false, warnings: [String] = []) {
        self.schemaVersion = schemaVersion; self.evidenceID = evidenceID
        self.containerSHA256 = containerSHA256; self.containerByteCount = containerByteCount
        self.hashScope = hashScope; self.driver = driver; self.driverVersion = driverVersion
        self.options = options; self.containerEncryption = containerEncryption
        self.volumes = volumes; self.warnings = warnings
        self.volumeGroupInventoryAvailable = volumeGroupInventoryAvailable
    }

    public func validate(evidence: EvidenceRecord) throws {
        try options.validate()
        guard schemaVersion == 1, evidenceID == evidence.id,
              evidence.hashScope == FileHashScope.selectedFileBytes,
              containerSHA256 == evidence.sha256, containerByteCount == evidence.byteCount,
              containerByteCount > 0, containerByteCount <= options.maximumContainerBytes,
              containerSHA256.utf8.count == 64,
              containerSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              hashScope == FileHashScope.selectedFileBytes, driver == "apple-system-readonly-apfs-v1",
              !driverVersion.isEmpty, driverVersion.utf8.count <= 256,
              (1...64).contains(volumes.count), Set(volumes.map(\.volumeUUID)).count == volumes.count,
              warnings.count <= 32, warnings.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 }) else {
            throw APFSReadError.invalidResult
        }
        var chargedBytes = 0
        for volume in volumes {
            try APFSVolumeCatalogMetadata.validate(volume)
            let charge = volume.name.utf8.count + volume.roles.reduce(512) { $0 + $1.utf8.count + 64 }
            guard charge <= options.maximumMetadataBytes - chargedBytes else { throw APFSReadError.invalidResult }
            chargedBytes += charge
        }
    }
}

enum APFSVolumeCatalogMetadata {
    static func descriptor(info: [String: Any], volume: [String: Any], containerUUID: UUID,
                           volumeGroupUUID: UUID? = nil) throws -> APFSVolumeDescriptor {
        guard info["FilesystemType"] as? String == "apfs",
              let infoUUID = (info["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)),
              (volume["APFSVolumeUUID"] as? String).flatMap(UUID.init(uuidString:)) == infoUUID,
              let name = volume["Name"] as? String, let roles = volume["Roles"] as? [String],
              let encrypted = (info["Encryption"] as? Bool) ?? (info["Encrypted"] as? Bool),
              info["FileVault"] as? Bool == encrypted,
              volume["Encryption"] as? Bool == encrypted,
              let locked = info["Locked"] as? Bool, volume["Locked"] as? Bool == locked else {
            throw APFSReadError.invalidResult
        }
        if let declared = volume["FileVault"] {
            guard declared as? Bool == encrypted else { throw APFSReadError.invalidResult }
        }
        let result = APFSVolumeDescriptor(volumeUUID: infoUUID, containerUUID: containerUUID,
            name: name, roles: roles.sorted(), volumeGroupUUID: volumeGroupUUID, encrypted: encrypted, locked: locked)
        try validate(result)
        return result
    }

    static func validate(_ volume: APFSVolumeDescriptor) throws {
        guard boundedText(volume.name, maximumBytes: 1_024), volume.roles.count <= 16,
              Set(volume.roles).count == volume.roles.count,
              volume.roles.allSatisfy({ boundedText($0, maximumBytes: 64) }),
              volume.encrypted || !volume.locked else { throw APFSReadError.invalidResult }
    }

    private static func boundedText(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes &&
            !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
    }
}

/// A separately queried, scoped group inventory. Missing/unknown keys never
/// become a claim that a volume has no group or that it is a boot acquisition.
enum APFSVolumeGroupMetadata {
    static func mapping(_ listing: [String: Any], containerUUID: UUID) throws -> [UUID: UUID] {
        guard let containers = listing["Containers"] as? [[String: Any]], containers.count <= 64 else {
            throw APFSReadError.invalidResult
        }
        let matching = containers.filter {
            ($0["APFSContainerUUID"] as? String).flatMap(UUID.init(uuidString:)) == containerUUID
        }
        guard matching.count == 1, let groups = matching[0]["VolumeGroups"] as? [[String: Any]], groups.count <= 64 else {
            throw APFSReadError.invalidResult
        }
        var mapping: [UUID: UUID] = [:], groupIDs: Set<UUID> = []
        for group in groups {
            guard let groupUUID = (group["APFSVolumeGroupUUID"] as? String).flatMap(UUID.init(uuidString:)),
                  groupIDs.insert(groupUUID).inserted,
                  let volumes = group["Volumes"] as? [[String: Any]], (1...64).contains(volumes.count) else {
                throw APFSReadError.invalidResult
            }
            for volume in volumes {
                guard let uuid = (volume["APFSVolumeUUID"] as? String).flatMap(UUID.init(uuidString:)),
                      mapping.updateValue(groupUUID, forKey: uuid) == nil else { throw APFSReadError.invalidResult }
            }
        }
        return mapping
    }
}
