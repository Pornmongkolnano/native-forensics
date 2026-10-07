import CryptoKit
import Darwin
import Foundation

/// One newly created, descriptor-pinned workspace. Cleanup removes only leaf
/// inodes observed in this owned workspace, never replacement paths or targets.
final class RecoveryScratch {
    let url: URL
    let descriptor: Int32
    private let parentDescriptor: Int32
    private let name: String
    private var known: [String: (device: dev_t, inode: ino_t, directory: Bool)] = [:]
    private var cleaned = false

    init() throws {
        let parent = try FileAccess.localURL(FileManager.default.temporaryDirectory)
        let parentFD = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw RecoveryError.storageChanged }
        let leaf = ".native-recovery-\(UUID().uuidString.lowercased())"
        guard Darwin.mkdirat(parentFD, leaf, 0o700) == 0 else { Darwin.close(parentFD); throw RecoveryError.storageChanged }
        let root = Darwin.openat(parentFD, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { Darwin.close(parentFD); throw RecoveryError.storageChanged }
        parentDescriptor = parentFD; descriptor = root; name = leaf; url = parent.appendingPathComponent(leaf)
        try validate()
    }

    func validate() throws {
        var held = stat(), named = stat(), requested = stat()
        guard Darwin.fstat(descriptor, &held) == 0,
              Darwin.fstatat(parentDescriptor, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              Darwin.lstat(url.path, &requested) == 0,
              [named, requested].allSatisfy({ $0.st_mode & S_IFMT == S_IFDIR && $0.st_dev == held.st_dev && $0.st_ino == held.st_ino })
        else { throw RecoveryError.storageChanged }
    }

    func copy(source: Int32, named leaf: String, maximumBytes: Int64, mode: mode_t,
              progress: (Int64) -> Void = { _ in }) throws -> (sha256: String, byteCount: Int64) {
        try validate()
        let before = try FileAccess.identity(of: source)
        guard before.size <= maximumBytes else { throw RecoveryError.outputLimit }
        let target = Darwin.openat(descriptor, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard target >= 0 else { throw RecoveryError.storageChanged }
        defer { Darwin.close(target) }
        try claim(leaf, parent: descriptor)
        var digest = SHA256(), offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while offset < before.size {
            try Task.checkCancellation()
            let count = try buffer.withUnsafeMutableBytes {
                try RecoveryIO.readAt(source, offset: offset, into: $0, count: Int(min(Int64($0.count), before.size - offset)))
            }
            guard count > 0 else { throw RecoveryError.sourceChanged }
            let bytes = Data(buffer.prefix(count)); digest.update(data: bytes)
            try bytes.withUnsafeBytes { pointer in
                var written = 0
                while written < count {
                    let amount = Darwin.write(target, pointer.baseAddress!.advanced(by: written), count - written)
                    if amount < 0, errno == EINTR { continue }
                    guard amount > 0 else { throw RecoveryError.storageChanged }
                    written += amount
                }
            }
            offset += Int64(count); progress(offset)
        }
        guard try FileAccess.identity(of: source) == before,
              Darwin.fsync(target) == 0, Darwin.fchmod(target, mode) == 0 else { throw RecoveryError.sourceChanged }
        try validate()
        return (RecoveryIO.hex(digest.finalize()), offset)
    }

    /// Every recovered leaf is bounded and non-symlink. The monitor is advisory
    /// during the child run; acceptance repeats the inventory after child exit.
    func inventory(options: RecoveryOptions) throws -> [String: SourceIdentity] {
        try validate()
        var files: [String: SourceIdentity] = [:]
        var count = 0, total: Int64 = 0
        var reportCount = 0, reportBytes: Int64 = 0, diagnosticBytes: Int64 = 0
        for entry in try names(in: descriptor) {
            var info = stat()
            if Darwin.fstatat(descriptor, entry, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                if errno == ENOENT { continue }; throw RecoveryError.storageChanged
            }
            if info.st_mode & S_IFMT == S_IFDIR {
                guard entry.hasPrefix("recovered."), !entry.dropFirst("recovered.".count).isEmpty,
                      entry.dropFirst("recovered.".count).utf8.allSatisfy({ (48...57).contains($0) }) else { throw RecoveryError.invalidReport }
                try claim(entry, parent: descriptor)
                let child = Darwin.openat(descriptor, entry, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw RecoveryError.storageChanged }
                defer { Darwin.close(child) }
                var opened = stat()
                guard Darwin.fstat(child, &opened) == 0,
                      opened.st_dev == info.st_dev, opened.st_ino == info.st_ino else { throw RecoveryError.storageChanged }
                for leaf in try names(in: child) {
                    var metadata = stat()
                    if Darwin.fstatat(child, leaf, &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
                        if errno == ENOENT { continue }; throw RecoveryError.storageChanged
                    }
                    guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_nlink == 1, metadata.st_size >= 0 else { throw RecoveryError.invalidReport }
                    let path = entry + "/" + leaf
                    try remember(path, metadata: metadata)
                    if leaf == "report.xml" {
                        reportCount += 1
                        guard reportCount <= 10, metadata.st_size <= Int64(RecoveryReportParser.maximumReportBytes) - reportBytes else { throw RecoveryError.outputLimit }
                        reportBytes += metadata.st_size
                    } else {
                        guard metadata.st_size <= options.maximumArtifactBytes,
                              metadata.st_size <= options.maximumOutputBytes - total else { throw RecoveryError.outputLimit }
                        total += metadata.st_size; count += 1
                        guard count <= options.maximumFiles else { throw RecoveryError.outputLimit }
                    }
                    files[path] = SourceIdentity(metadata)
                }
            } else {
                guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1, info.st_size >= 0 else { throw RecoveryError.invalidReport }
                let allowed = ["input.raw", "photorec", "photorec.ses", "photorec.log", "photorec.cfg", ".photorec.cfg", ".photorec.sig", ".photorec.ses"]
                guard allowed.contains(entry) else { throw RecoveryError.invalidReport }
                let maximum: Int64 = entry == "input.raw" ? options.maximumInputBytes : entry == "photorec" ? 64 * 1_048_576 : 1_048_576
                guard info.st_size <= maximum else { throw RecoveryError.outputLimit }
                if entry != "input.raw", entry != "photorec" {
                    guard info.st_size <= 2 * 1_048_576 - diagnosticBytes else { throw RecoveryError.outputLimit }
                    diagnosticBytes += info.st_size
                }
                try claim(entry, parent: descriptor)
            }
        }
        try validate(); return files
    }

    func open(_ path: String) throws -> Int32 {
        try validate()
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, parts.count <= 2, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\\") && !$0.utf8.contains(0) }) else { throw RecoveryError.invalidReport }
        if parts.count == 1 { return try FileAccess.openReadOnly(parts[0], in: descriptor) }
        let parent = Darwin.openat(descriptor, parts[0], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw RecoveryError.storageChanged }
        defer { Darwin.close(parent) }
        return try FileAccess.openReadOnly(parts[1], in: parent)
    }

    @discardableResult
    func cleanup() -> Bool {
        guard !cleaned else { return true }; cleaned = true
        // Acceptance stops immediately at a quota/error. After child reaping,
        // collect bounded remaining regular leaves for cleanup independently of
        // those quotas; never replace an earlier ownership token.
        claimRemainingForCleanup()
        let directories = known.filter { $0.value.directory }.map(\.key)
        for directory in directories {
            guard matches(directory, parent: descriptor) else { continue }
            let child = Darwin.openat(descriptor, directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { continue }
            var opened = stat()
            guard Darwin.fstat(child, &opened) == 0, let expected = known[directory],
                  opened.st_dev == expected.device, opened.st_ino == expected.inode else { Darwin.close(child); continue }
            for path in known.keys where path.hasPrefix(directory + "/") {
                let leaf = String(path.dropFirst(directory.count + 1))
                if matches(path, parent: child, leaf: leaf) { _ = Darwin.unlinkat(child, leaf, 0) }
            }
            Darwin.close(child)
            if matches(directory, parent: descriptor) { _ = Darwin.unlinkat(descriptor, directory, AT_REMOVEDIR) }
        }
        for path in known.keys where !path.contains("/") && known[path]?.directory == false {
            if matches(path, parent: descriptor) { _ = Darwin.unlinkat(descriptor, path, 0) }
        }
        var removed = false
        do { try validate(); removed = Darwin.unlinkat(parentDescriptor, name, AT_REMOVEDIR) == 0 } catch { }
        Darwin.close(descriptor); Darwin.close(parentDescriptor)
        return removed
    }
    deinit { cleanup() }

    private func claimRemainingForCleanup() {
        guard (try? validate()) != nil else { return }
        for entry in cleanupNames(in: descriptor) {
            var info = stat()
            guard Darwin.fstatat(descriptor, entry, &info, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
            if info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1 {
                try? remember(entry, metadata: info)
            } else if info.st_mode & S_IFMT == S_IFDIR, entry.hasPrefix("recovered."),
                      (try? remember(entry, metadata: info)) != nil {
                let child = Darwin.openat(descriptor, entry, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { continue }
                var held = stat()
                if Darwin.fstat(child, &held) == 0, held.st_dev == info.st_dev, held.st_ino == info.st_ino {
                    for leaf in cleanupNames(in: child) {
                        var value = stat()
                        if Darwin.fstatat(child, leaf, &value, AT_SYMLINK_NOFOLLOW) == 0,
                           value.st_mode & S_IFMT == S_IFREG, value.st_nlink == 1 {
                            try? remember(entry + "/" + leaf, metadata: value)
                        }
                    }
                }
                Darwin.close(child)
            }
        }
    }

    private func cleanupNames(in descriptor: Int32) -> [String] {
        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0 else { return [] }
        _ = Darwin.fcntl(duplicate, F_SETFD, FD_CLOEXEC)
        guard let directory = Darwin.fdopendir(duplicate) else { Darwin.close(duplicate); return [] }
        defer { Darwin.closedir(directory) }
        Darwin.rewinddir(directory)
        var values: [String] = []
        while values.count < 20_000, let entry = Darwin.readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." { values.append(name) }
        }
        return values
    }

    private func claim(_ path: String, parent: Int32) throws {
        var value = stat()
        guard Darwin.fstatat(parent, path, &value, AT_SYMLINK_NOFOLLOW) == 0 else { throw RecoveryError.storageChanged }
        try remember(path, metadata: value)
    }
    private func remember(_ path: String, metadata: stat) throws {
        let value = (metadata.st_dev, metadata.st_ino, metadata.st_mode & S_IFMT == S_IFDIR)
        if let original = known[path] {
            guard original.device == value.0, original.inode == value.1, original.directory == value.2 else {
                throw RecoveryError.storageChanged
            }
        } else { known[path] = value }
    }
    private func matches(_ path: String, parent: Int32, leaf: String? = nil) -> Bool {
        guard let expected = known[path] else { return false }
        var current = stat()
        return Darwin.fstatat(parent, leaf ?? path, &current, AT_SYMLINK_NOFOLLOW) == 0
            && current.st_dev == expected.device && current.st_ino == expected.inode
            && current.st_mode & S_IFMT == (expected.directory ? S_IFDIR : S_IFREG)
    }
    private func names(in descriptor: Int32) throws -> [String] {
        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0, let directory = Darwin.fdopendir(duplicate) else {
            if duplicate >= 0 { Darwin.close(duplicate) }; throw RecoveryError.storageChanged
        }
        defer { Darwin.closedir(directory) }
        // dup shares the open directory description: reset its enumeration
        // position so every watchdog pass observes the current whole directory.
        Darwin.rewinddir(directory)
        var values: [String] = []
        while let entry = Darwin.readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." { values.append(name) }
            guard values.count <= 5_020 else { throw RecoveryError.outputLimit }
        }
        return values.sorted()
    }
}

enum RecoveryIO {
    static func hex(_ digest: SHA256.Digest) -> String { digest.map { String(format: "%02x", $0) }.joined() }
    static func readAt(_ descriptor: Int32, offset: Int64, into buffer: UnsafeMutableRawBufferPointer, count: Int) throws -> Int {
        while true {
            let amount = Darwin.pread(descriptor, buffer.baseAddress, count, off_t(offset))
            if amount >= 0 { return amount }
            if errno == EINTR { continue }; throw RecoveryError.storageChanged
        }
    }
    static func digest(_ descriptor: Int32, maximumBytes: Int64) throws -> (hash: String, size: Int64) {
        let before = try FileAccess.identity(of: descriptor)
        guard before.size <= maximumBytes else { throw RecoveryError.outputLimit }
        var hasher = SHA256(), offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while offset < before.size {
            try Task.checkCancellation()
            let read = try buffer.withUnsafeMutableBytes {
                try readAt(descriptor, offset: offset, into: $0, count: Int(min(Int64($0.count), before.size - offset)))
            }
            guard read > 0 else { throw RecoveryError.sourceChanged }
            hasher.update(data: Data(buffer.prefix(read))); offset += Int64(read)
        }
        guard try FileAccess.identity(of: descriptor) == before else { throw RecoveryError.sourceChanged }
        return (hex(hasher.finalize()), before.size)
    }
    static func data(_ descriptor: Int32, maximumBytes: Int) throws -> Data {
        let before = try FileAccess.identity(of: descriptor)
        guard before.size <= maximumBytes else { throw RecoveryError.outputLimit }
        var bytes = Data(), offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while offset < before.size {
            try Task.checkCancellation()
            let count = try buffer.withUnsafeMutableBytes {
                try readAt(descriptor, offset: offset, into: $0, count: Int(min(Int64($0.count), before.size - offset)))
            }
            guard count > 0 else { throw RecoveryError.storageChanged }
            bytes.append(contentsOf: buffer.prefix(count)); offset += Int64(count)
        }
        guard try FileAccess.identity(of: descriptor) == before else { throw RecoveryError.storageChanged }
        return bytes
    }
}
