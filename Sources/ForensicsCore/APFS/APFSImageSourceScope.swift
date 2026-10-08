import Darwin

/// A selected-file SHA-256 covers the data fork. A legacy DiskImages resource
/// fork must not become additional parser input outside that recorded scope.
enum APFSImageSourceScope {
    static let resourceForkReason = "legacy disk images with a nonempty resource fork are outside the selected-file-byte hash scope"
    static func requireMainForkOnly(_ descriptor: Int32) throws {
        let count = Darwin.fgetxattr(descriptor, "com.apple.ResourceFork", nil, 0, 0, 0)
        if count < 0 {
            guard errno == ENOATTR else {
                throw APFSReadError.unsupported("the disk-image resource-fork state could not be verified")
            }
        } else if count > 0 { throw APFSReadError.unsupported(resourceForkReason) }
    }
}
