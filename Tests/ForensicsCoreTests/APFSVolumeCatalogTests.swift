import Foundation
import Testing
@testable import ForensicsCore

@Suite("Bounded APFS volume inventory metadata")
struct APFSVolumeCatalogTests {
    @Test("Legacy read options decode with no selected UUID and explicit selection roundtrips")
    func legacyOptions() throws {
        let original = APFSReadOptions(), encoded = try JSONEncoder().encode(original)
        var object = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object.removeValue(forKey: "selectedVolumeUUID")
        let legacy = try JSONDecoder().decode(APFSReadOptions.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(legacy == original && legacy.selectedVolumeUUID == nil)
        let selected = APFSReadOptions(selectedVolumeUUID: UUID())
        #expect(try JSONDecoder().decode(APFSReadOptions.self, from: JSONEncoder().encode(selected)) == selected)
    }

    @Test("Observed empty group inventory is distinct from a missing or ambiguous schema")
    func groupInventorySchema() throws {
        let container = UUID()
        let observed: [String: Any] = ["Containers": [["APFSContainerUUID": container.uuidString,
            "ContainerReference": "disk77", "VolumeGroups": [] as [[String: Any]]]]]
        #expect(try APFSVolumeGroupMetadata.mapping(observed, containerUUID: container).isEmpty)
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSVolumeGroupMetadata.mapping(["Containers": [["APFSContainerUUID": container.uuidString]]], containerUUID: container)
        }
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSVolumeGroupMetadata.mapping(observed, containerUUID: UUID())
        }
        let volume = UUID(), first = UUID(), second = UUID()
        let duplicate: [String: Any] = ["Containers": [["APFSContainerUUID": container.uuidString,
            "VolumeGroups": [["APFSVolumeGroupUUID": first.uuidString, "Volumes": [["APFSVolumeUUID": volume.uuidString]]],
                ["APFSVolumeGroupUUID": second.uuidString, "Volumes": [["APFSVolumeUUID": volume.uuidString]]]]]]]
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSVolumeGroupMetadata.mapping(duplicate, containerUUID: container)
        }
    }
    @Test("Observed info/list UUID and explicit encryption declarations bind a metadata descriptor")
    func descriptorBinding() throws {
        let uuid = UUID(), container = UUID(), group = UUID()
        let info: [String: Any] = ["FilesystemType": "apfs", "VolumeUUID": uuid.uuidString,
            "Encryption": true, "FileVault": true, "Locked": true, "DeviceIdentifier": "disk99s1",
            "MountPoint": "/synthetic/private/mount"]
        let row: [String: Any] = ["APFSVolumeUUID": uuid.uuidString, "Name": "Synthetic Data",
            "Roles": ["Data"], "Encryption": true, "FileVault": true, "Locked": true]
        let descriptor = try APFSVolumeCatalogMetadata.descriptor(info: info, volume: row,
            containerUUID: container, volumeGroupUUID: group)
        #expect(descriptor.volumeUUID == uuid && descriptor.containerUUID == container)
        #expect(descriptor.volumeGroupUUID == group && descriptor.roles == ["Data"])
        #expect(descriptor.encrypted && descriptor.locked)
        let encoded = String(decoding: try JSONEncoder().encode(descriptor), as: UTF8.self)
        #expect(!encoded.contains("disk99") && !encoded.contains("/synthetic/private"))
        var unrelated = row; unrelated["APFSVolumeUUID"] = UUID().uuidString
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSVolumeCatalogMetadata.descriptor(info: info, volume: unrelated, containerUUID: container)
        }
        for key in ["Encryption", "Locked", "FileVault"] {
            var contradictory = info; contradictory[key] = false
            #expect(throws: APFSReadError.invalidResult) {
                _ = try APFSVolumeCatalogMetadata.descriptor(info: contradictory, volume: row, containerUUID: container)
            }
        }
        var unknown = info; unknown.removeValue(forKey: "Encryption")
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSVolumeCatalogMetadata.descriptor(info: unknown, volume: row, containerUUID: container)
        }
    }

    @Test("Catalog source binding, unique UUIDs and metadata budget reject ambiguity")
    func catalogBounds() throws {
        let evidence = EvidenceRecord(sourcePath: "/synthetic/source.img", byteCount: 128,
            sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
        let descriptor = APFSVolumeDescriptor(volumeUUID: UUID(), containerUUID: UUID(), name: "Synthetic",
                                              roles: [], encrypted: false, locked: false)
        let catalog = make(evidence, volumes: [descriptor])
        try catalog.validate(evidence: evidence)
        #expect(throws: APFSReadError.invalidResult) {
            try make(evidence, volumes: [descriptor, descriptor]).validate(evidence: evidence)
        }
        let wrongEvidence = EvidenceRecord(sourcePath: evidence.sourcePath, byteCount: evidence.byteCount,
            sha256: evidence.sha256, container: .raw, filesystemHint: nil)
        #expect(throws: APFSReadError.invalidResult) { try catalog.validate(evidence: wrongEvidence) }
        #expect(throws: APFSReadError.invalidResult) {
            try make(evidence, volumes: [], options: .init()).validate(evidence: evidence)
        }
        #expect(throws: APFSReadError.invalidResult) {
            try make(evidence, volumes: [descriptor], options: .init(maximumMetadataBytes: 512)).validate(evidence: evidence)
        }
        let encoded = String(decoding: try JSONEncoder().encode(catalog), as: UTF8.self)
        #expect(!encoded.contains(evidence.sourcePath))
    }

    @Test("Control names, excessive roles, duplicate roles and impossible plain-locked state are refused")
    func invalidLabels() {
        let uuid = UUID(), container = UUID()
        for descriptor in [
            APFSVolumeDescriptor(volumeUUID: uuid, containerUUID: container, name: "control\nname", roles: [], encrypted: false, locked: false),
            APFSVolumeDescriptor(volumeUUID: uuid, containerUUID: container, name: "Data", roles: ["Data", "Data"], encrypted: false, locked: false),
            APFSVolumeDescriptor(volumeUUID: uuid, containerUUID: container, name: "Data", roles: (0..<17).map { "Role\($0)" }, encrypted: false, locked: false),
            APFSVolumeDescriptor(volumeUUID: uuid, containerUUID: container, name: "Data", roles: [], encrypted: false, locked: true)
        ] {
            #expect(throws: APFSReadError.invalidResult) { try APFSVolumeCatalogMetadata.validate(descriptor) }
        }
    }

    private func make(_ evidence: EvidenceRecord, volumes: [APFSVolumeDescriptor],
                      options: APFSReadOptions = .init()) -> APFSVolumeCatalogResult {
        .init(evidenceID: evidence.id, containerSHA256: evidence.sha256, containerByteCount: evidence.byteCount,
              driverVersion: "independent-synthetic-metadata-contract", options: options,
              containerEncryption: .none, volumes: volumes)
    }
}
