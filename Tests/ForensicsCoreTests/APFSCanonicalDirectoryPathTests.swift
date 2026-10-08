import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Raw kernel canonical APFS mount directory paths")
struct APFSCanonicalDirectoryPathTests {
    @Test("A descriptor opened through /tmp returns raw /private/tmp with matching directory identity and filesystem ID")
    func systemTemporaryAlias() throws {
        // Intentionally follow Apple's input alias once. The helper must return
        // the canonical raw string; converting it to URL.path would regress it.
        let original = Darwin.open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        try #require(original >= 0)
        defer { Darwin.close(original) }
        let path = try APFSCanonicalDirectoryPath.path(for: original)
        #expect(path == "/private/tmp")
        let reopened = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try #require(reopened >= 0)
        defer { Darwin.close(reopened) }
        var lhs = stat(), rhs = stat(), leftFS = statfs(), rightFS = statfs()
        try #require(Darwin.fstat(original, &lhs) == 0 && Darwin.fstat(reopened, &rhs) == 0)
        try #require(Darwin.fstatfs(original, &leftFS) == 0 && Darwin.fstatfs(reopened, &rightFS) == 0)
        #expect(lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode)
        #expect(lhs.st_uid == rhs.st_uid && lhs.st_gid == rhs.st_gid && lhs.st_flags == rhs.st_flags)
        let leftID = withUnsafeBytes(of: leftFS.f_fsid) { Array($0) }
        let rightID = withUnsafeBytes(of: rightFS.f_fsid) { Array($0) }
        #expect(leftID.count == 8 && leftID == rightID)
    }

    @Test("Invalid and owned regular-file descriptors cannot become directory mount paths")
    func invalidDescriptors() throws {
        #expect(throws: APFSReadError.unsafeMount) { _ = try APFSCanonicalDirectoryPath.path(for: -1) }
        let fixture = try APFSCanonicalPathTestDirectory()
        defer { fixture.cleanupKnownLeaves() }
        let regular = Darwin.openat(fixture.descriptor, "regular", O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try #require(regular >= 0)
        defer { Darwin.close(regular) }
        try fixture.record("regular", descriptor: regular)
        #expect(throws: APFSReadError.unsafeMount) { _ = try APFSCanonicalDirectoryPath.path(for: regular) }
    }

    @Test("Replacing an unlinked held directory at the same named leaf cannot validate the old descriptor")
    func replacedNamedDirectory() throws {
        let fixture = try APFSCanonicalPathTestDirectory()
        defer { fixture.cleanupKnownLeaves() }
        try #require(Darwin.mkdirat(fixture.descriptor, "selected", 0o700) == 0)
        let old = Darwin.openat(fixture.descriptor, "selected", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try #require(old >= 0)
        defer { Darwin.close(old) }
        try fixture.record("selected", descriptor: old)
        #expect(try APFSCanonicalDirectoryPath.path(for: old) == fixture.path + "/selected")
        try #require(Darwin.unlinkat(fixture.descriptor, "selected", AT_REMOVEDIR) == 0)
        try #require(Darwin.mkdirat(fixture.descriptor, "selected", 0o700) == 0)
        let replacement = Darwin.openat(fixture.descriptor, "selected", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try #require(replacement >= 0)
        defer { Darwin.close(replacement) }
        try fixture.record("selected", descriptor: replacement)
        var previous = stat(), current = stat()
        try #require(Darwin.fstat(old, &previous) == 0 && Darwin.fstat(replacement, &current) == 0)
        #expect(previous.st_dev != current.st_dev || previous.st_ino != current.st_ino)
        #expect(throws: APFSReadError.unsafeMount) { _ = try APFSCanonicalDirectoryPath.path(for: old) }
        #expect(try APFSCanonicalDirectoryPath.path(for: replacement) == fixture.path + "/selected")
    }

    @Test("Raw owned directory paths preserve Unicode and spaces without URL normalization")
    func unicodeDirectory() throws {
        let fixture = try APFSCanonicalPathTestDirectory()
        defer { fixture.cleanupKnownLeaves() }
        let name = "Thai test ทดสอบ e\u{301}"
        try #require(Darwin.mkdirat(fixture.descriptor, name, 0o700) == 0)
        let directory = Darwin.openat(fixture.descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try #require(directory >= 0)
        defer { Darwin.close(directory) }
        try fixture.record(name, descriptor: directory)
        #expect(try APFSCanonicalDirectoryPath.path(for: directory) == fixture.path + "/" + name)
    }
}

/// Only newly created known leaves are removed. An unknown/replaced leaf or
/// nonempty directory is retained rather than recursively traversed/deleted.
private final class APFSCanonicalPathTestDirectory {
    let path: String
    let descriptor: Int32
    private let parent: Int32
    private let name: String
    private let identity: (dev_t, ino_t)
    private var leaves: [String: (dev_t, ino_t, mode_t)] = [:]

    init() throws {
        parent = Darwin.open("/private/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw APFSReadError.unsafeMount }
        var template = Array("/private/tmp/NF-APFS-canonical-XXXXXX".utf8CString)
        let created = template.withUnsafeMutableBufferPointer { storage -> String? in
            guard let value = Darwin.mkdtemp(storage.baseAddress!) else { return nil }
            return String(cString: value)
        }
        guard let created else { Darwin.close(parent); throw APFSReadError.unsafeMount }
        path = created; name = String(created.split(separator: "/").last!)
        descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { Darwin.close(parent); throw APFSReadError.unsafeMount }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0 else {
            Darwin.close(descriptor); Darwin.close(parent); throw APFSReadError.unsafeMount
        }
        identity = (metadata.st_dev, metadata.st_ino)
    }
    deinit { Darwin.close(descriptor); Darwin.close(parent) }
    func record(_ name: String, descriptor: Int32) throws {
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0 else { throw APFSReadError.unsafeMount }
        leaves[name] = (metadata.st_dev, metadata.st_ino, metadata.st_mode & S_IFMT)
    }
    func cleanupKnownLeaves() {
        for (leaf, expected) in leaves {
            var metadata = stat()
            guard Darwin.fstatat(descriptor, leaf, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
                  metadata.st_dev == expected.0, metadata.st_ino == expected.1,
                  metadata.st_mode & S_IFMT == expected.2 else { return }
            guard Darwin.unlinkat(descriptor, leaf, expected.2 == S_IFDIR ? AT_REMOVEDIR : 0) == 0 else { return }
        }
        var metadata = stat()
        guard Darwin.fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
              metadata.st_dev == identity.0, metadata.st_ino == identity.1,
              metadata.st_mode & S_IFMT == S_IFDIR else { return }
        _ = Darwin.unlinkat(parent, name, AT_REMOVEDIR)
    }
}
