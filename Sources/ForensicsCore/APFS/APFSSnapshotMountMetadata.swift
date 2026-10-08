import Darwin
import Foundation

/// Kernel-derived snapshot metadata complements the adapter's held-descriptor,
/// owned-image, mount-path and source-byte validation; it never replaces them.
enum APFSSnapshotMountMetadata {
    static func filesystemUUID(of fd: Int32) throws -> UUID {
        guard fd >= 0 else { throw APFSReadError.unsafeMount }
        var attributes = attrlist(bitmapcount: UInt16(ATTR_BIT_MAP_COUNT), reserved: 0,
            commonattr: 0, volattr: UInt32(ATTR_VOL_INFO) | UInt32(ATTR_VOL_UUID),
            dirattr: 0, fileattr: 0, forkattr: 0)
        var response = [UInt8](repeating: 0, count: 20)
        let status = response.withUnsafeMutableBytes { bytes in
            Darwin.fgetattrlist(fd, &attributes, bytes.baseAddress!, bytes.count, 0)
        }
        guard status == 0 else { throw APFSReadError.unsafeMount }
        // With only ATTR_VOL_UUID requested, the public packed response is a
        // 32-bit little-endian total length followed by the 16 UUID bytes.
        let length = UInt32(response[0]) | UInt32(response[1]) << 8 |
            UInt32(response[2]) << 16 | UInt32(response[3]) << 24
        guard length == 20 else { throw APFSReadError.unsafeMount }
        return UUID(uuid: (response[4], response[5], response[6], response[7],
            response[8], response[9], response[10], response[11],
            response[12], response[13], response[14], response[15],
            response[16], response[17], response[18], response[19]))
    }

    static func validatesReadOnlySnapshot(flags: UInt32, filesystemType: String, source: String,
        snapshot: APFSSnapshotInventoryEntry, volumeDevice: String, snapshotFSID: [UInt8],
        baseFSID: [UInt8], filesystemUUID: UUID) -> Bool {
        let requiredFlags = UInt32(MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID | MNT_NODEV | MNT_SNAPSHOT)
        guard flags & requiredFlags == requiredFlags, filesystemType == "apfs",
              validVolumeDevice(volumeDevice), !snapshot.name.isEmpty, snapshot.name.utf8.count <= 1_024,
              !snapshot.name.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              snapshot.transactionID > 0, source == snapshot.name + "@" + volumeDevice,
              source.utf8.count <= 1_023,
              filesystemUUID == snapshot.uuid,
              snapshotFSID.count == 8, baseFSID.count == 8,
              snapshotFSID.contains(where: { $0 != 0 }), baseFSID.contains(where: { $0 != 0 }),
              snapshotFSID != baseFSID else { return false }
        return true
    }

    private static func validVolumeDevice(_ device: String) -> Bool {
        guard device.hasPrefix("/dev/disk"), device.utf8.count <= 64 else { return false }
        let components = device.dropFirst(9).split(separator: "s", omittingEmptySubsequences: false)
        return components.count == 2 && components.allSatisfy { component in
            !component.isEmpty && component.utf8.allSatisfy { (48...57).contains($0) }
        }
    }
}
