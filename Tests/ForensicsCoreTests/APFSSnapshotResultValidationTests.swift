import Foundation
import Testing
@testable import ForensicsCore

@Suite("APFS snapshot result and pre-launch command contracts")
struct APFSSnapshotResultValidationTests {
    private let baseVolume = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
    private let snapshot = APFSSnapshotInventoryEntry(
        uuid: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!, name: "nf-before", transactionID: 42)
    private let otherSnapshot = APFSSnapshotInventoryEntry(
        uuid: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!, name: "nf-other", transactionID: 43)

    @Test("Plain current and exact requested snapshot results retain the same base-volume binding")
    func acceptedViews() throws {
        let evidence = fakeEvidence()
        let current = make(evidence, inventory: [snapshot, otherSnapshot])
        let historical = make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [snapshot, otherSnapshot])
        try APFSMountedImageAdapter.validate(current, evidence: evidence)
        try APFSMountedImageAdapter.validate(historical, evidence: evidence)
        #expect(current.volumeUUID == baseVolume && historical.volumeUUID == current.volumeUUID)
        #expect(current.selectedSnapshot == nil && historical.selectedSnapshot == snapshot)
        #expect(throws: APFSReadError.invalidResult) {
            try APFSMountedImageAdapter.validate(make(evidence, requested: snapshot.uuid, selected: snapshot,
                inventory: [snapshot], resultVolume: otherSnapshot.uuid), evidence: evidence)
        }
    }

    @Test("A current request cannot acquire a selected snapshot and explicit requests cannot substitute or omit UUIDs")
    func requestBinding() {
        let evidence = fakeEvidence()
        let invalid = [
            make(evidence, selected: snapshot, inventory: [snapshot]),
            make(evidence, requested: snapshot.uuid, inventory: [snapshot]),
            make(evidence, requested: otherSnapshot.uuid, selected: snapshot, inventory: [snapshot]),
            make(evidence, requested: otherSnapshot.uuid, selected: otherSnapshot, inventory: [snapshot])
        ]
        for result in invalid {
            #expect(throws: APFSReadError.invalidResult) {
                try APFSMountedImageAdapter.validate(result, evidence: evidence)
            }
        }
    }

    @Test("Matching UUID alone does not permit selected-name or transaction drift")
    func exactTupleBinding() {
        let evidence = fakeEvidence()
        for changed in [
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: "nf-renamed", transactionID: snapshot.transactionID),
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: snapshot.name, transactionID: snapshot.transactionID + 1)
        ] {
            #expect(throws: APFSReadError.invalidResult) {
                try APFSMountedImageAdapter.validate(make(evidence, requested: snapshot.uuid, selected: changed,
                    inventory: [snapshot]), evidence: evidence)
            }
            #expect(throws: APFSReadError.invalidResult) {
                try APFSMountedImageAdapter.validate(make(evidence, requested: snapshot.uuid, selected: snapshot,
                    inventory: [changed]), evidence: evidence)
            }
        }
    }

    @Test("Selected snapshots require an available inventory containing the exact observed tuple")
    func unavailableInventory() {
        let evidence = fakeEvidence()
        for result in [
            make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [], inventoryAvailable: false),
            make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [], inventoryAvailable: true),
            make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [snapshot], inventoryAvailable: false),
            make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [otherSnapshot], inventoryAvailable: true)
        ] {
            #expect(throws: APFSReadError.invalidResult) {
                try APFSMountedImageAdapter.validate(result, evidence: evidence)
            }
        }
    }

    @Test("Duplicate inventory UUIDs, names or transaction IDs are ambiguous for both view types")
    func duplicateInventoryKeys() {
        let evidence = fakeEvidence()
        for duplicate in [
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: otherSnapshot.name, transactionID: otherSnapshot.transactionID),
            APFSSnapshotInventoryEntry(uuid: otherSnapshot.uuid, name: snapshot.name, transactionID: otherSnapshot.transactionID),
            APFSSnapshotInventoryEntry(uuid: otherSnapshot.uuid, name: otherSnapshot.name, transactionID: snapshot.transactionID)
        ] {
            let inventory = [snapshot, duplicate]
            for result in [make(evidence, inventory: inventory),
                make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: inventory)] {
                #expect(throws: APFSReadError.invalidResult) {
                    try APFSMountedImageAdapter.validate(result, evidence: evidence)
                }
            }
        }
    }

    @Test("Plain APFS snapshot contexts admit wrapper encryption while Disk-user volume snapshots remain unavailable")
    func encryptionScope() throws {
        let evidence = fakeEvidence()
        for container in [APFSContainerEncryption.none, .encryptedDiskImage] {
            let historical = make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [snapshot],
                                  containerEncryption: container, volumeEncryption: .none)
            try APFSMountedImageAdapter.validate(historical, evidence: evidence)
        }
        let combinations: [(APFSContainerEncryption, APFSVolumeEncryption)] = [
            (.encryptedDiskImage, .none), (.none, .diskUserAPFS), (.encryptedDiskImage, .diskUserAPFS)
        ]
        for (container, volume) in combinations {
            if volume != .none {
                let historical = make(evidence, requested: snapshot.uuid, selected: snapshot, inventory: [snapshot],
                                      containerEncryption: container, volumeEncryption: volume)
                #expect(throws: APFSReadError.invalidResult) {
                    try APFSMountedImageAdapter.validate(historical, evidence: evidence)
                }
            }
            let current = make(evidence, inventory: [], inventoryAvailable: false,
                               containerEncryption: container, volumeEncryption: volume)
            try APFSMountedImageAdapter.validate(current, evidence: evidence)
            #expect(current.options.selectedSnapshotUUID == nil && current.selectedSnapshot == nil)
        }
    }

    @Test("Snapshot labels, transaction IDs and aggregate metadata are bounded before results are trusted")
    func snapshotMetadataBounds() {
        let evidence = fakeEvidence()
        for invalid in [
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: snapshot.name, transactionID: 0),
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: "", transactionID: 42),
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: "nf\ncontrol", transactionID: 42),
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: "nf\u{7f}control", transactionID: 42),
            APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: String(repeating: "x", count: 1_025), transactionID: 42)
        ] {
            #expect(throws: APFSReadError.invalidResult) {
                try APFSMountedImageAdapter.validate(make(evidence, inventory: [invalid]), evidence: evidence)
            }
        }
        #expect(throws: APFSReadError.invalidResult) {
            try APFSMountedImageAdapter.validate(make(evidence, inventory: [snapshot], maximumMetadataBytes: 128),
                evidence: evidence)
        }
    }

    @Test("Malformed snapshot mount shapes and synthetic secret input are rejected before spawning")
    func mountShapeBeforeLaunch() {
        let shape = ["-o", "rdonly,nobrowse,noexec,nosuid,nodev,nofollow", "-s", "nf-before",
                     "/synthetic-apfs-command/base", "/synthetic-apfs-command/view"]
        var invalid = [[String](), Array(shape.dropLast()), shape + ["extra"]]
        for (index, replacement) in [
            (0, "--options"), (1, "rw,nobrowse,noexec,nosuid,nodev,nofollow"),
            (1, "rdonly,nobrowse,noexec,nosuid,nodev"), (1, "rdonly"), (2, "--snapshot"),
            (3, ""), (3, String(repeating: "x", count: 1_025)),
            (3, "nf\0before"), (3, "nf\nbefore"), (3, "nf\rbefore"), (3, "nf\tbefore"), (3, "nf\u{7f}before"),
            (4, "relative-base"), (5, "relative-view"), (4, "/synthetic-apfs-command/base\0suffix"),
            (5, "/synthetic-apfs-command/view\0suffix")
        ] {
            var arguments = shape
            arguments[index] = replacement
            invalid.append(arguments)
        }
        for arguments in invalid {
            expectPreLaunchRejection(tool: "/sbin/mount_apfs", arguments: arguments)
        }
        expectPreLaunchRejection(tool: "/sbin/mount_apfs", arguments: shape,
                                 input: Data("synthetic-secret-input".utf8))
    }

    @Test("Unmount rejects options, multiple targets, relative paths, NUL and input before spawning")
    func unmountShapeBeforeLaunch() {
        for arguments in [[], ["relative-view"], ["-f"], ["-f", "/synthetic-apfs-command/view"],
                          ["/synthetic-apfs-command/first", "/synthetic-apfs-command/second"],
                          ["/synthetic-apfs-command/view\0suffix"]] {
            expectPreLaunchRejection(tool: "/sbin/umount", arguments: arguments)
        }
        expectPreLaunchRejection(tool: "/sbin/umount", arguments: ["/synthetic-apfs-command/view"],
                                 input: Data("synthetic-secret-input".utf8))
    }

    @Test("Volume discovery refuses snapshot selection before opening a nonexistent source or creating scratch")
    func discoverySelectionBeforeIO() async throws {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("NativeForensics-snapshot-no-scratch-\(UUID().uuidString)")
        #expect(!FileManager.default.fileExists(atPath: scratch.path))
        let adapter = APFSMountedImageAdapter(scratchRoot: scratch)
        await #expect(throws: APFSReadError.invalidOptions) {
            _ = try await adapter.discoverVolumes(evidence: fakeEvidence(),
                options: APFSReadOptions(selectedVolumeUUID: baseVolume, selectedSnapshotUUID: snapshot.uuid))
        }
        #expect(!FileManager.default.fileExists(atPath: scratch.path))
    }

    private func expectPreLaunchRejection(tool: String, arguments: [String], input: Data = Data()) {
        // Cancellation is a second safety barrier: a regressed argument guard
        // fails this test with CancellationError instead of invoking a tool.
        let cancellation = APFSCancellation()
        cancellation.cancel()
        var started = false
        #expect(throws: APFSReadError.invalidOptions) {
            _ = try APFSSystemCommand.run(tool, arguments, input: input, timeout: 1,
                cancellation: cancellation, started: { _ in started = true })
        }
        #expect(!started)
    }

    private func fakeEvidence() -> EvidenceRecord {
        .init(sourcePath: "/synthetic-apfs-static-validation/nonexistent.raw", byteCount: 268_435_456,
              sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
    }

    private func make(_ evidence: EvidenceRecord, requested: UUID? = nil,
                      selected: APFSSnapshotInventoryEntry? = nil, inventory: [APFSSnapshotInventoryEntry],
                      inventoryAvailable: Bool = true, containerEncryption: APFSContainerEncryption = .none,
                      volumeEncryption: APFSVolumeEncryption = .none, resultVolume: UUID? = nil,
                      maximumMetadataBytes: Int = 64 * 1_024 * 1_024) -> APFSInspectionResult {
        .init(evidenceID: evidence.id, containerSHA256: evidence.sha256, containerByteCount: evidence.byteCount,
              driverVersion: "synthetic-snapshot-validation-contract",
              options: .init(maximumMetadataBytes: maximumMetadataBytes, selectedVolumeUUID: baseVolume,
                             selectedSnapshotUUID: requested), volumeUUID: resultVolume ?? baseVolume,
              containerEncryption: containerEncryption, volumeEncryption: volumeEncryption,
              entries: [], snapshots: inventory, snapshotInventoryAvailable: inventoryAvailable,
              coverage: .completeAllocatedView, warnings: [], selectedSnapshot: selected)
    }
}
