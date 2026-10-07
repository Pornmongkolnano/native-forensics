import Darwin
import Foundation

@_silgen_name("flock")
private func contentIndexFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// One replaceable derived generation; bounded reads and atomic compare/save.
/// Historical reads never open or verify evidence. The manifest is unchanged.
public enum CaseContentIndexStore {
    public static let filename = "derived-content-index.json"

    public static func load(in caseURL: URL) throws -> CaseContentIndexSnapshot? {
        let forensicCase = try CaseStore.open(at: caseURL)
        let root = try openRoot(forensicCase.bundleURL)
        defer { Darwin.close(root) }
        let value = try read(root: root)?.snapshot
        // Adding/reanalyzing evidence must not erase a readable older derived
        // generation. Its source bindings are compared by the workspace, and
        // reopening never turns historical text into freshly verified bytes.
        if let value, value.caseID != forensicCase.manifest.id { throw ContentIndexError.invalidSnapshot }
        try validateRoot(forensicCase.bundleURL, descriptor: root)
        return value
    }

    public static func save(_ snapshot: CaseContentIndexSnapshot, expectedSnapshotID: UUID?, in caseURL: URL) throws {
        try save(snapshot, expectedSnapshotID: expectedSnapshotID, in: caseURL, beforePublish: {})
    }

    static func save(_ snapshot: CaseContentIndexSnapshot, expectedSnapshotID: UUID?, in caseURL: URL,
                     beforePublish: () throws -> Void, afterPublish: () throws -> Void = {}) throws {
        try snapshot.validate(); try Task.checkCancellation()
        let bytes = try CaseWorkCoding.encode(snapshot)
        guard bytes.count <= ContentIndexLimits.maximumSerializedBytes else { throw ContentIndexError.storageLimit }
        let forensicCase = try CaseStore.open(at: caseURL)
        try validateScope(snapshot, manifest: forensicCase.manifest)
        let root = try openRoot(forensicCase.bundleURL)
        defer { Darwin.close(root) }
        let lock = Darwin.openat(root, ".case.lock", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard lock >= 0 else { throw ContentIndexError.unsafeStore }
        defer { Darwin.close(lock) }
        let lockIdentity = try FileAccess.identity(of: lock)
        let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(3))
        while contentIndexFlock(lock, LOCK_EX | LOCK_NB) != 0 {
            try Task.checkCancellation()
            guard errno == EWOULDBLOCK || errno == EINTR, clock.now < deadline else { throw ContentIndexError.unsafeStore }
            usleep(10_000)
        }
        defer { _ = contentIndexFlock(lock, LOCK_UN) }
        try validateRoot(forensicCase.bundleURL, descriptor: root)
        guard (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity,
              try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest else { throw ContentIndexError.unsafeStore }
        let previous = try read(root: root)
        guard previous?.snapshot.id == expectedSnapshotID else { throw ContentIndexError.staleGeneration }
        let stage = ".content-index-\(UUID().uuidString.lowercased()).tmp"
        let fd = Darwin.openat(root, stage, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw FileAccess.posixError("Cannot stage content index") }
        defer {
            if matches(stage, in: root, descriptor: fd, kind: S_IFREG) { _ = Darwin.unlinkat(root, stage, 0) }
            Darwin.close(fd)
        }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(fd, buffer.baseAddress?.advanced(by: offset), min(buffer.count - offset, 65_536))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write content index") }
                offset += count
            }
        }
        guard Darwin.fsync(fd) == 0 else { throw FileAccess.posixError("Cannot flush content index") }
        try beforePublish(); try Task.checkCancellation()
        try validateRoot(forensicCase.bundleURL, descriptor: root)
        guard matches(stage, in: root, descriptor: fd, kind: S_IFREG),
              (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity,
              try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest else { throw ContentIndexError.unsafeStore }
        let current = try read(root: root)
        guard current?.snapshot.id == expectedSnapshotID, current?.identity == previous?.identity else { throw ContentIndexError.staleGeneration }
        guard Darwin.renameat(root, stage, root, filename) == 0 else { throw FileAccess.posixError("Cannot publish content index") }
        do {
            try afterPublish()
            guard Darwin.fsync(root) == 0 else { throw FileAccess.posixError("Cannot flush content index directory") }
            try validateRoot(forensicCase.bundleURL, descriptor: root)
        } catch { throw ContentIndexError.publicationUncertain }
    }

    public static func validateScope(_ snapshot: CaseContentIndexSnapshot, manifest: CaseManifest) throws {
        guard snapshot.caseID == manifest.id, snapshot.sources.count == manifest.evidence.count,
              snapshot.sources.enumerated().allSatisfy({ pair in
                  let evidence = manifest.evidence[pair.offset], source = pair.element
                  return source.evidenceID == evidence.id && source.selectedContainerSHA256 == evidence.sha256
                      && source.selectedContainerByteCount == evidence.byteCount
              }) else { throw ContentIndexError.sourceChanged }
    }

    private struct Read { let snapshot: CaseContentIndexSnapshot; let identity: SourceIdentity }

    private static func read(root: Int32) throws -> Read? {
        let fd = Darwin.openat(root, filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw ContentIndexError.unsafeStore
        }
        defer { Darwin.close(fd) }
        let identity = try FileAccess.identity(of: fd)
        guard identity.size <= ContentIndexLimits.maximumSerializedBytes else { throw ContentIndexError.storageLimit }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < identity.size {
            try Task.checkCancellation()
            let requested = Int(min(Int64(buffer.count), identity.size - Int64(bytes.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(fd, into: $0, count: requested) }
            guard count > 0 else { throw ContentIndexError.unsafeStore }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        guard try FileAccess.identity(of: fd) == identity,
              (try? FileAccess.identity(at: filename, in: root)) == identity else { throw ContentIndexError.unsafeStore }
        let snapshot: CaseContentIndexSnapshot
        do { snapshot = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, bytes) }
        catch { throw ContentIndexError.invalidSnapshot }
        try snapshot.validate()
        return Read(snapshot: snapshot, identity: identity)
    }

    private static func openRoot(_ url: URL) throws -> Int32 {
        let root = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw ContentIndexError.unsafeStore }
        do { try validateRoot(url, descriptor: root) } catch { Darwin.close(root); throw error }
        return root
    }

    private static func validateRoot(_ url: URL, descriptor: Int32) throws {
        var held = stat(), current = stat()
        guard Darwin.fstat(descriptor, &held) == 0, Darwin.lstat(url.path, &current) == 0,
              current.st_mode & S_IFMT == S_IFDIR, held.st_dev == current.st_dev, held.st_ino == current.st_ino else {
            throw ContentIndexError.unsafeStore
        }
    }

    private static func matches(_ name: String, in root: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var held = stat(), current = stat()
        return Darwin.fstat(descriptor, &held) == 0 && Darwin.fstatat(root, name, &current, AT_SYMLINK_NOFOLLOW) == 0
            && current.st_mode & S_IFMT == kind && held.st_dev == current.st_dev && held.st_ino == current.st_ino
    }
}
