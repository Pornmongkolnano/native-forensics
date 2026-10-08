import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Kernel APFS snapshot identity metadata")
struct APFSSnapshotMountMetadataTests {
    private static let requiredFlags = UInt32(MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID | MNT_NODEV | MNT_SNAPSHOT)
    private static let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(uuid:
        (0x32, 0x22, 0x23, 0x4b, 0xee, 0x3f, 0x46, 0x7b, 0x9d, 0x1e, 0xd1, 0xe4, 0x30, 0xdf, 0x8f, 0x5b)),
        name: "nf-before", transactionID: 1)

    @Test("The selected snapshot requires every readonly and snapshot flag, with ordinary extra flags allowed")
    func kernelFlags() {
        #expect(validates())
        #expect(validates(flags: Self.requiredFlags | UInt32(MNT_LOCAL)))
        for missing in [MNT_RDONLY, MNT_NOEXEC, MNT_NOSUID, MNT_NODEV, MNT_SNAPSHOT] {
            #expect(!validates(flags: Self.requiredFlags & ~UInt32(missing)))
        }
        #expect(!validates(flags: 0))
        #expect(!validates(filesystemType: "hfs"))
        #expect(!validates(filesystemType: "APFS"))
    }

    @Test("The kernel source is the exact snapshot name at the exact owned APFS volume device")
    func selectedSourceAndDevice() {
        for source in ["nf-after@/dev/disk99s1", "nf-before@/dev/disk98s1", "/dev/disk99s1",
                       Self.snapshot.uuid.uuidString + "@/dev/disk99s1", "nf-before@/dev/disk99s1extra"] {
            #expect(!validates(source: source))
        }
        for device in ["/dev/disk99", "/dev/disk99s", "/dev/disk99s1s1", "/dev/disk99s-1",
                       "/dev/disk９９s1", "/dev/rdisk99s1", "/dev/disk99s1extra", "/dev/disk99s1\0",
                       "/dev/disk" + String(repeating: "9", count: 65) + "s1"] {
            #expect(!validates(volumeDevice: device))
        }
        #expect(validates(volumeDevice: "/dev/disk123s456"))
    }

    @Test("The filesystem UUID must be the selected snapshot UUID and the eight-byte FSID must differ from base")
    func distinctSnapshotIdentity() {
        #expect(!validates(filesystemUUID: UUID()))
        #expect(!validates(snapshotFSID: [8, 7, 6, 5, 4, 3, 2, 1]))
        for malformed in [[], [UInt8](repeating: 1, count: 7), [UInt8](repeating: 1, count: 9),
                          [UInt8](repeating: 0, count: 8)] {
            #expect(!validates(snapshotFSID: malformed))
            #expect(!validates(baseFSID: malformed))
        }
    }

    @Test("Snapshot names are bounded UTF8 metadata and reject control characters")
    func snapshotNames() {
        let accepted = APFSSnapshotInventoryEntry(uuid: Self.snapshot.uuid,
            name: String(repeating: "ก", count: 336) + "a", transactionID: 1)
        #expect(accepted.name.utf8.count == 1_009)
        #expect(validates(snapshot: accepted))
        for name in ["", String(repeating: "ก", count: 336) + "aa",
                     String(repeating: "ก", count: 341) + "aa", "nf\0before", "nf\nbefore", "nf\u{7f}before"] {
            let malformed = APFSSnapshotInventoryEntry(uuid: Self.snapshot.uuid, name: name, transactionID: 1)
            #expect(!validates(snapshot: malformed))
        }
        let zeroTransaction = APFSSnapshotInventoryEntry(uuid: Self.snapshot.uuid, name: "nf-before", transactionID: 0)
        #expect(!validates(snapshot: zeroTransaction))
    }

    @Test("The public getter rejects an invalid descriptor with unsafeMount")
    func invalidDescriptor() {
        #expect(throws: APFSReadError.unsafeMount) { _ = try APFSSnapshotMountMetadata.filesystemUUID(of: -1) }
    }

    @Test("On an APFS host, two readonly descriptors of the existing temporary directory report the same filesystem UUID")
    func existingAPFSDirectoryGetter() throws {
        let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        let first = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try #require(first >= 0)
        defer { Darwin.close(first) }
        var filesystem = statfs()
        try #require(Darwin.fstatfs(first, &filesystem) == 0)
        let type = withUnsafePointer(to: &filesystem.f_fstypename) {
            $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
        }
        guard type == "apfs" else { return }
        let second = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try #require(second >= 0)
        defer { Darwin.close(second) }
        var left = stat(), right = stat()
        try #require(Darwin.fstat(first, &left) == 0 && Darwin.fstat(second, &right) == 0)
        try #require(left.st_dev == right.st_dev && left.st_ino == right.st_ino)
        let firstUUID = try APFSSnapshotMountMetadata.filesystemUUID(of: first)
        let secondUUID = try APFSSnapshotMountMetadata.filesystemUUID(of: second)
        #expect(firstUUID == secondUUID)
        #expect(Darwin.fcntl(first, F_GETFL) & O_ACCMODE == O_RDONLY)
        #expect(Darwin.fcntl(second, F_GETFL) & O_ACCMODE == O_RDONLY)
    }

    private func validates(flags: UInt32 = APFSSnapshotMountMetadataTests.requiredFlags, filesystemType: String = "apfs", source: String? = nil,
        snapshot: APFSSnapshotInventoryEntry = APFSSnapshotMountMetadataTests.snapshot, volumeDevice: String = "/dev/disk99s1",
        snapshotFSID: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8], baseFSID: [UInt8] = [8, 7, 6, 5, 4, 3, 2, 1],
        filesystemUUID: UUID? = nil) -> Bool {
        APFSSnapshotMountMetadata.validatesReadOnlySnapshot(flags: flags, filesystemType: filesystemType,
            source: source ?? snapshot.name + "@" + volumeDevice, snapshot: snapshot, volumeDevice: volumeDevice,
            snapshotFSID: snapshotFSID, baseFSID: baseFSID, filesystemUUID: filesystemUUID ?? snapshot.uuid)
    }
}
