import Darwin
import Foundation

/// Returns the kernel's raw POSIX path for a held directory. Foundation URL
/// conversion must not rewrite /private/tmp to its /tmp symlink before a
/// nofollow mount. Existing adapter ownership checks remain mandatory.
enum APFSCanonicalDirectoryPath {
    static func path(for descriptor: Int32) throws -> String {
        var before = stat(), beforeFS = statfs()
        guard descriptor >= 0, Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFDIR,
              Darwin.fstatfs(descriptor, &beforeFS) == 0 else { throw APFSReadError.unsafeMount }
        let path = try kernelPath(for: descriptor)
        let canonical = try openCanonicalDirectory(path)
        defer { Darwin.close(canonical) }
        var named = stat(), namedFS = statfs(), after = stat(), afterFS = statfs()
        guard Darwin.fstat(canonical, &named) == 0, sameIdentity(before, named),
              Darwin.fstatfs(canonical, &namedFS) == 0, filesystemID(beforeFS) == filesystemID(namedFS),
              Darwin.fstat(descriptor, &after) == 0, sameIdentity(before, after),
              Darwin.fstatfs(descriptor, &afterFS) == 0, filesystemID(beforeFS) == filesystemID(afterFS),
              try kernelPath(for: descriptor) == path else { throw APFSReadError.unsafeMount }
        return path
    }

    private static func kernelPath(for descriptor: Int32) throws -> String {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let status = buffer.withUnsafeMutableBufferPointer { storage in
            Darwin.fcntl(descriptor, F_GETPATH, storage.baseAddress!)
        }
        guard status == 0, let end = buffer.firstIndex(of: 0), end > 0, end < Int(MAXPATHLEN),
              let path = String(bytes: buffer.prefix(end).map { UInt8(bitPattern: $0) }, encoding: .utf8),
              path.hasPrefix("/"), path.utf8.count == end else { throw APFSReadError.unsafeMount }
        return path
    }

    private static func openCanonicalDirectory(_ path: String) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count < Int(MAXPATHLEN) else {
            throw APFSReadError.unsafeMount
        }
        let components = path == "/" ? [] : Array(path.split(separator: "/", omittingEmptySubsequences: false).dropFirst())
        guard components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw APFSReadError.unsafeMount }
        let flags = O_SEARCH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        var current = Darwin.open("/", flags)
        guard current >= 0 else { throw APFSReadError.unsafeMount }
        do {
            for component in components {
                let name = String(component)
                var before = stat()
                guard Darwin.fstatat(current, name, &before, AT_SYMLINK_NOFOLLOW) == 0,
                      before.st_mode & S_IFMT == S_IFDIR else { throw APFSReadError.unsafeMount }
                let next = Darwin.openat(current, name, flags)
                guard next >= 0 else { throw APFSReadError.unsafeMount }
                var held = stat(), named = stat()
                guard Darwin.fstat(next, &held) == 0, sameIdentity(before, held),
                      Darwin.fstatat(current, name, &named, AT_SYMLINK_NOFOLLOW) == 0, sameIdentity(held, named) else {
                    Darwin.close(next); throw APFSReadError.unsafeMount
                }
                Darwin.close(current); current = next
            }
            return current
        } catch { Darwin.close(current); throw error }
    }

    private static func sameIdentity(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode &&
            lhs.st_uid == rhs.st_uid && lhs.st_gid == rhs.st_gid && lhs.st_flags == rhs.st_flags &&
            rhs.st_mode & S_IFMT == S_IFDIR
    }
    private static func filesystemID(_ metadata: statfs) -> [UInt8] {
        withUnsafeBytes(of: metadata.f_fsid) { Array($0) }
    }
}
