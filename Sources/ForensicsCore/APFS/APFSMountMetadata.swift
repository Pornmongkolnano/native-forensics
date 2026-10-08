import Foundation

/// Decodes observed diskutil mount metadata. Actual descriptor/kernel mount
/// validation is still mandatory; this is never a filesystem safety boundary
/// by itself. The current plist schema does not define a Mounted boolean.
enum APFSMountMetadata {
    static func declaresReadOnlyAPFS(_ info: [String: Any], volumeUUID: String,
                                     matchesOwnedMount: (String?) -> Bool) -> Bool {
        guard info["FilesystemType"] as? String == "apfs", info["VolumeUUID"] as? String == volumeUUID,
              let mountPoint = info["MountPoint"] as? String, !mountPoint.isEmpty,
              info["WritableVolume"] as? Bool != true, info["ReadOnlyVolume"] as? Bool != false,
              (info["ReadOnlyVolume"] as? Bool == true || info["WritableVolume"] as? Bool == false) else { return false }
        return matchesOwnedMount(mountPoint)
    }
}
