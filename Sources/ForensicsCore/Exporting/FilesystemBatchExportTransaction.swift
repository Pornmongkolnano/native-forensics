import Darwin
import Foundation

/// Descriptor-relative publication never traverses a mutable staging path for
/// deletion. Cleanup removes only the exact regular files claimed by this job;
/// an injected or replaced entry is preserved and prevents directory removal.
final class FilesystemBatchExportTransaction {
    let stagedURL: URL
    private let destination: URL
    private let stagingName: String
    private let parent: Int32
    private let stage: Int32
    private var claimed: [String: SourceIdentity] = [:]
    private var published = false
    private var committed = false
    private var cleaned = false

    init(destination: URL) throws {
        self.destination = destination
        stagingName = ".native-batch-export-" + UUID().uuidString
        stagedURL = destination.deletingLastPathComponent().appendingPathComponent(stagingName, isDirectory: true)
        parent = try EvidenceViewFiles.openDirectory(destination.deletingLastPathComponent())
        guard Darwin.mkdirat(parent, stagingName, mode_t(0o700)) == 0 else {
            let error = FileAccess.posixError("Cannot create private batch export directory")
            Darwin.close(parent)
            throw error
        }
        let opened = Darwin.openat(parent, stagingName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard opened >= 0 else {
            let error = FileAccess.posixError("Cannot open private batch export directory")
            // Without an opened directory identity, never remove a potentially
            // replaced path, even if it leaves an empty owned stage behind.
            Darwin.close(parent)
            throw error
        }
        stage = opened
        do {
            try validate()
            var metadata = stat()
            guard Darwin.fstat(stage, &metadata) == 0, metadata.st_mode & 0o777 == 0o700 else {
                throw EngineError.invalidRequest("The batch export staging directory is not private.")
            }
        } catch {
            cleanup()
            throw error
        }
    }

    func validate() throws {
        try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        guard directoryMatches(published ? destination.lastPathComponent : stagingName) else {
            throw EngineError.invalidRequest("The batch export directory changed during the job.")
        }
    }

    func hasChild(_ filename: String) -> Bool {
        var metadata = stat()
        return Darwin.fstatat(stage, filename, &metadata, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT
    }

    func claim(_ filename: String, identity: SourceIdentity) throws {
        try validate()
        guard claimed[filename] == nil, try currentIdentity(filename) == identity else {
            throw EngineError.protocolViolation("A batch export output was replaced or modified before verification.")
        }
        claimed[filename] = identity
    }

    func writeManifest(_ data: Data) throws {
        try validate()
        guard data.count <= 96 * 1_024 * 1_024 else {
            throw EngineError.limitExceeded("The batch export manifest exceeds its bounded size limit.")
        }
        let filename = "manifest.json"
        let descriptor = Darwin.openat(stage, filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot create batch export manifest") }
        defer { Darwin.close(descriptor) }
        // This file is ours from O_EXCL creation. Refresh the identity only
        // after our own writes, and verify the pathname still names that inode.
        claimed[filename] = try FileAccess.identity(of: descriptor)
        var written = 0
        while written < data.count {
            try Task.checkCancellation()
            let amount = data.withUnsafeBytes { bytes in
                Darwin.write(descriptor, bytes.baseAddress!.advanced(by: written), min(65_536, bytes.count - written))
            }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw FileAccess.posixError("Cannot write batch export manifest") }
            written += amount
            let identity = try FileAccess.identity(of: descriptor)
            guard try currentIdentity(filename) == identity else {
                throw EngineError.protocolViolation("The batch export manifest changed during its write.")
            }
            claimed[filename] = identity
        }
        guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush batch export manifest") }
        guard try currentIdentity(filename) == claimed[filename] else {
            throw EngineError.protocolViolation("The batch export manifest changed before publication.")
        }
    }

    func publish() throws {
        try validate()
        guard Set(try names()) == Set(claimed.keys), claimed["manifest.json"] != nil else {
            throw EngineError.protocolViolation("The batch export directory contains an unclaimed output.")
        }
        for (filename, identity) in claimed {
            try Task.checkCancellation()
            let descriptor = try FileAccess.openReadOnly(filename, in: stage)
            defer { Darwin.close(descriptor) }
            var metadata = stat()
            guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1,
                  try FileAccess.identity(of: descriptor) == identity,
                  try currentIdentity(filename) == identity else {
                throw EngineError.protocolViolation("A verified batch export output changed before publication.")
            }
            guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush batch export output") }
        }
        guard Darwin.fsync(stage) == 0 else { throw FileAccess.posixError("Cannot flush batch export directory") }
        try Task.checkCancellation()
        try validate()
        guard Darwin.renameatx_np(parent, stagingName, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw EngineError.invalidRequest("The batch export destination already exists.") }
            throw FileAccess.posixError("Cannot publish batch export directory")
        }
        published = true
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush published batch export directory") }
        try validate()
        // Cancellation before the commit removes only this owned publication.
        // After commit, do not return cancellation for a visible valid export.
        try Task.checkCancellation()
        committed = true
    }

    func cleanup() {
        guard !cleaned else { return }
        cleaned = true
        defer { Darwin.close(stage); Darwin.close(parent) }
        guard !committed else { return }
        // A failure between rename and commit may still have a visible owned
        // directory. Move that exact directory back to its private name first;
        // RENAME_EXCL preserves any raced replacement at the original stage.
        if published, directoryMatches(destination.lastPathComponent),
           Darwin.renameatx_np(parent, destination.lastPathComponent, parent, stagingName, UInt32(RENAME_EXCL)) == 0 {
            published = false
        }
        for (filename, identity) in claimed {
            guard (try? currentIdentity(filename)) == identity else { continue }
            _ = Darwin.unlinkat(stage, filename, 0)
        }
        // AT_REMOVEDIR fails on unknown content; no recursive removal and no
        // adoption of a replacement directory at either pathname.
        let name = published ? destination.lastPathComponent : stagingName
        if directoryMatches(name) { _ = Darwin.unlinkat(parent, name, AT_REMOVEDIR) }
    }

    private func currentIdentity(_ filename: String) throws -> SourceIdentity {
        let descriptor = try FileAccess.openReadOnly(filename, in: stage)
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1 else {
            throw EngineError.protocolViolation("Batch export files must be regular files with one directory entry.")
        }
        let identity = try FileAccess.identity(of: descriptor)
        guard (try? FileAccess.identity(at: filename, in: stage)) == identity else {
            throw EngineError.protocolViolation("A batch export output pathname changed during verification.")
        }
        return identity
    }

    private func directoryMatches(_ name: String) -> Bool {
        var requested = stat(), opened = stat()
        return Darwin.fstatat(parent, name, &requested, AT_SYMLINK_NOFOLLOW) == 0
            && Darwin.fstat(stage, &opened) == 0 && requested.st_mode & S_IFMT == S_IFDIR
            && opened.st_mode & S_IFMT == S_IFDIR && requested.st_dev == opened.st_dev && requested.st_ino == opened.st_ino
    }

    private func names() throws -> [String] {
        let duplicate = Darwin.dup(stage)
        guard duplicate >= 0 else { throw FileAccess.posixError("Cannot inspect batch export entries") }
        _ = Darwin.fcntl(duplicate, F_SETFD, FD_CLOEXEC)
        guard let directory = Darwin.fdopendir(duplicate) else {
            Darwin.close(duplicate); throw FileAccess.posixError("Cannot inspect batch export entries")
        }
        defer { Darwin.closedir(directory) }
        Darwin.rewinddir(directory)
        var values: [String] = []
        while let entry = Darwin.readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != ".", name != ".." { values.append(name) }
            guard values.count <= FilesystemBatchExportService.maxFiles + 1 else {
                throw EngineError.limitExceeded("The batch export directory exceeds its file limit.")
            }
        }
        return values
    }
}
