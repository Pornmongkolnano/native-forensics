import Foundation
import Testing
@testable import ForensicsCore

@Suite("APFS current and snapshot model binding")
struct APFSSnapshotBindingTests {
    private let volumeUUID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
    private let snapshotUUID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
    private let evidenceID = UUID(uuidString: "33333333-3333-4333-8333-333333333333")!

    @Test("Legacy options missing selection keys still mean the current view with unchanged caps")
    func legacyOptions() throws {
        let legacy = Data("""
        {"maximumEntries":50000,"maximumFileBytes":134217728,"maximumContainerBytes":68719476736,
         "commandTimeoutSeconds":60,"maximumDepth":128,"maximumMetadataBytes":67108864,
         "maximumAggregateFileBytes":4294967296,"jobTimeoutSeconds":600}
        """.utf8)
        let decoded = try JSONDecoder().decode(APFSReadOptions.self, from: legacy)
        #expect(decoded == APFSReadOptions())
        #expect(decoded.selectedVolumeUUID == nil && decoded.selectedSnapshotUUID == nil)
        try decoded.validate()

        var object = try #require(try JSONSerialization.jsonObject(with: legacy) as? [String: Any])
        object["selectedSnapshotUUID"] = NSNull()
        let explicitNull = try JSONDecoder().decode(APFSReadOptions.self,
            from: JSONSerialization.data(withJSONObject: object))
        #expect(explicitNull == decoded)
    }

    @Test("A stored legacy result omitting snapshot selection retains its base volume and current view")
    func legacyResult() throws {
        let legacy = Data("""
        {"schemaVersion":1,"evidenceID":"33333333-3333-4333-8333-333333333333",
         "containerSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "containerByteCount":268435456,"hashScope":"selected-file-bytes",
         "driver":"apple-system-readonly-apfs-v1","driverVersion":"synthetic-model-contract",
         "options":{"maximumEntries":50000,"maximumFileBytes":134217728,
           "maximumContainerBytes":68719476736,"commandTimeoutSeconds":60,"maximumDepth":128,
           "maximumMetadataBytes":67108864,"maximumAggregateFileBytes":4294967296,
           "jobTimeoutSeconds":600,"selectedVolumeUUID":"11111111-1111-4111-8111-111111111111"},
         "volumeUUID":"11111111-1111-4111-8111-111111111111","containerEncryption":"none",
         "volumeEncryption":"none","entries":[],"snapshots":[],"snapshotInventoryAvailable":true,
         "coverage":"completeAllocatedView","warnings":[]}
        """.utf8)
        let decoded = try JSONDecoder().decode(APFSInspectionResult.self, from: legacy)
        let current = make(options: .init(selectedVolumeUUID: volumeUUID), snapshots: [])
        #expect(decoded == current)
        #expect(decoded.selectedSnapshot == nil && decoded.options.selectedSnapshotUUID == nil)
        #expect(decoded.volumeUUID == volumeUUID && decoded.options.selectedVolumeUUID == volumeUUID)

        var object = try #require(try JSONSerialization.jsonObject(with: legacy) as? [String: Any])
        object["selectedSnapshot"] = NSNull()
        #expect(try JSONDecoder().decode(APFSInspectionResult.self,
            from: JSONSerialization.data(withJSONObject: object)) == decoded)
    }

    @Test("Requested snapshot UUID is independent of base-volume selection and participates in equality")
    func requestedSelection() throws {
        let current = APFSReadOptions(selectedVolumeUUID: volumeUUID)
        let selected = APFSReadOptions(selectedVolumeUUID: volumeUUID, selectedSnapshotUUID: snapshotUUID)
        #expect(current.selectedSnapshotUUID == nil && selected.selectedSnapshotUUID == snapshotUUID)
        #expect(current != selected && selected.selectedVolumeUUID == volumeUUID)
        #expect(selected.maximumEntries == current.maximumEntries)
        #expect(selected.maximumFileBytes == current.maximumFileBytes)
        #expect(selected.maximumContainerBytes == current.maximumContainerBytes)
        #expect(selected.maximumMetadataBytes == current.maximumMetadataBytes)
        #expect(selected.maximumAggregateFileBytes == current.maximumAggregateFileBytes)
        #expect(selected.maximumDepth == current.maximumDepth)
        #expect(selected.commandTimeoutSeconds == current.commandTimeoutSeconds)
        #expect(selected.jobTimeoutSeconds == current.jobTimeoutSeconds)
        try selected.validate()
        #expect(try JSONDecoder().decode(APFSReadOptions.self, from: JSONEncoder().encode(selected)) == selected)
    }

    @Test("A result keeps the exact selected tuple and base UUID across serialization")
    func selectedResult() throws {
        let snapshot = APFSSnapshotInventoryEntry(uuid: snapshotUUID, name: "nf-before", transactionID: 42)
        let options = APFSReadOptions(selectedVolumeUUID: volumeUUID, selectedSnapshotUUID: snapshotUUID)
        let selected = make(options: options, snapshots: [snapshot], selectedSnapshot: snapshot)
        #expect(selected.volumeUUID == volumeUUID && selected.selectedSnapshot == snapshot)
        #expect(try JSONDecoder().decode(APFSInspectionResult.self, from: JSONEncoder().encode(selected)) == selected)

        let current = make(options: .init(selectedVolumeUUID: volumeUUID), snapshots: [snapshot])
        #expect(current.selectedSnapshot == nil && current != selected)
        let changedTransaction = APFSSnapshotInventoryEntry(uuid: snapshotUUID, name: "nf-before", transactionID: 43)
        let changedName = APFSSnapshotInventoryEntry(uuid: snapshotUUID, name: "nf-after", transactionID: 42)
        #expect(selected != make(options: options, snapshots: [snapshot], selectedSnapshot: changedTransaction))
        #expect(selected != make(options: options, snapshots: [snapshot], selectedSnapshot: changedName))
    }

    @Test("Snapshot encoding is an exact UUID-name-UInt64 tuple without mount or host paths")
    func snapshotTupleEncoding() throws {
        let snapshot = APFSSnapshotInventoryEntry(uuid: snapshotUUID, name: "nf-before", transactionID: UInt64.max)
        let encoded = try JSONEncoder().encode(snapshot)
        let object = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(Set(object.keys) == Set(["uuid", "name", "transactionID"]))
        #expect(object["uuid"] as? String == snapshotUUID.uuidString)
        #expect(object["name"] as? String == "nf-before")
        #expect(String(decoding: encoded, as: UTF8.self).contains("18446744073709551615"))
        #expect(try JSONDecoder().decode(APFSSnapshotInventoryEntry.self, from: encoded) == snapshot)

        let selected = make(options: .init(selectedVolumeUUID: volumeUUID, selectedSnapshotUUID: snapshotUUID),
                            snapshots: [snapshot], selectedSnapshot: snapshot)
        let text = String(decoding: try JSONEncoder().encode(selected), as: UTF8.self)
        #expect(!text.contains("/Users/") && !text.contains("/Volumes/") && !text.contains("/dev/disk"))
        let invalidTransaction = Data("""
        {"uuid":"22222222-2222-4222-8222-222222222222","name":"nf-before","transactionID":"42"}
        """.utf8)
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(APFSSnapshotInventoryEntry.self, from: invalidTransaction)
        }
    }

    @Test("Verified-file initializer preserves prior arguments and defaults to the current view")
    func verifiedFileSelection() {
        let bytes = Data("synthetic logical bytes".utf8)
        let current = APFSVerifiedFile(data: bytes, sha256: String(repeating: "b", count: 64),
            containerSHA256: String(repeating: "a", count: 64), volumeUUID: volumeUUID, relativePath: "history.bin")
        let snapshot = APFSSnapshotInventoryEntry(uuid: snapshotUUID, name: "nf-before", transactionID: 42)
        let selected = APFSVerifiedFile(data: bytes, sha256: current.sha256, containerSHA256: current.containerSHA256,
            volumeUUID: volumeUUID, relativePath: current.relativePath, selectedSnapshot: snapshot)
        #expect(current.selectedSnapshot == nil && selected.selectedSnapshot == snapshot)
        #expect(selected.volumeUUID == current.volumeUUID && selected.data == current.data)
        #expect(selected.sha256 == current.sha256 && selected.containerSHA256 == current.containerSHA256)
        #expect(selected.relativePath == current.relativePath)
    }

    private func make(options: APFSReadOptions, snapshots: [APFSSnapshotInventoryEntry],
                      selectedSnapshot: APFSSnapshotInventoryEntry? = nil) -> APFSInspectionResult {
        .init(evidenceID: evidenceID, containerSHA256: String(repeating: "a", count: 64), containerByteCount: 268_435_456,
              driverVersion: "synthetic-model-contract", options: options, volumeUUID: volumeUUID,
              containerEncryption: .none, volumeEncryption: .none, entries: [], snapshots: snapshots,
              snapshotInventoryAvailable: true, coverage: .completeAllocatedView, warnings: [], selectedSnapshot: selectedSnapshot)
    }
}
