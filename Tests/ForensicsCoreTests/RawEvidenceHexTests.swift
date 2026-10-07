import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

// Matches the read-directory primitive used by Apple's O_SEARCH VFS test.
// Test-only: the production reader never enumerates the source directory.
@_silgen_name("__getdirentries64")
private func rawHexDirectoryEntries(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer,
                                   _ count: Int, _ offset: UnsafeMutablePointer<off_t>) -> Int

struct RawEvidenceHexTests {
    @Test("Search-only parent handles open a known source but cannot enumerate its directory")
    func sourceDirectorySearchOnly() throws {
        let fixture = try HexFixture(bytes: Data("selected evidence bytes".utf8))
        defer { fixture.remove() }
        let parent = try EvidenceViewFiles.openDirectory(fixture.root, searchOnly: true)
        defer { Darwin.close(parent) }
        #expect(Darwin.fcntl(parent, F_GETFD) & FD_CLOEXEC != 0)
        var buffer = [UInt8](repeating: 0, count: 4_096), offset: off_t = 0
        errno = 0
        let enumerated = buffer.withUnsafeMutableBytes {
            rawHexDirectoryEntries(parent, $0.baseAddress!, $0.count, &offset)
        }
        let enumerationError = errno
        #expect(enumerated == -1)
        #expect(enumerationError == EBADF)
        let source = try FileAccess.openReadOnly(fixture.source.lastPathComponent, in: parent)
        defer { Darwin.close(source) }
        let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(source, into: $0, count: $0.count) }
        #expect(Data(buffer.prefix(count)) == Data("selected evidence bytes".utf8))
        try EvidenceViewFiles.validateDirectory(fixture.root, descriptor: parent, searchOnly: true)

        // The default remains a readable directory, needed by report/storage
        // callers for directory enumeration and durability operations.
        let readable = try EvidenceViewFiles.openDirectory(fixture.root)
        defer { Darwin.close(readable) }
        offset = 0
        let defaultRead = buffer.withUnsafeMutableBytes {
            rawHexDirectoryEntries(readable, $0.baseAddress!, $0.count, &offset)
        }
        #expect(defaultRead > 0)
        #expect(Darwin.fsync(readable) == 0)
        try EvidenceViewFiles.validateDirectory(fixture.root, descriptor: readable)
    }

    @Test("A raw byte window preserves absolute offsets without filesystem metadata")
    func exactWindow() async throws {
        let fixture = try HexFixture(bytes: Data((0...255).map(UInt8.init)))
        defer { fixture.remove() }
        let identity = try FileAccess.identity(at: fixture.source)
        let value = try await RawEvidenceHexReader.read(evidence: fixture.evidence, offset: 31, length: 18)
        #expect(value.offset == 31)
        #expect(value.byteCount == 256)
        #expect(value.bytes == Data((31...48).map(UInt8.init)))
        #expect(value.sourceSHA256 == fixture.evidence.sha256)
        #expect(value.hashScope == FileHashScope.selectedFileBytes)
        #expect(value.hexText.hasPrefix("000000000000001f  1f 20 21"))
        #expect(value.hexText.contains("000000000000002f  2f 30"))
        #expect(try FileAccess.identity(at: fixture.source) == identity)
    }

    @Test("EOF windows are clipped, including an empty selected file")
    func endOfFile() async throws {
        for bytes in [Data(), Data("boot-sector damaged".utf8)] {
            let fixture = try HexFixture(bytes: bytes)
            defer { fixture.remove() }
            let end = try await RawEvidenceHexReader.read(evidence: fixture.evidence, offset: Int64(bytes.count))
            #expect(end.bytes.isEmpty)
            #expect(end.hexText.isEmpty)
            if bytes.count > 0 {
                let last = try await RawEvidenceHexReader.read(evidence: fixture.evidence,
                    offset: Int64(bytes.count - 1), length: 32_768)
                #expect(last.bytes == bytes.suffix(1))
            }
        }
    }

    @Test("Invalid offsets and oversized windows are rejected before reading", arguments: [(-1, 16), (20, 16), (0, 0), (0, 32_769)])
    func rangeLimits(_ range: (Int, Int)) async throws {
        let fixture = try HexFixture(bytes: Data("header".utf8))
        defer { fixture.remove() }
        await #expect(throws: ForensicsError.self) {
            try await RawEvidenceHexReader.read(evidence: fixture.evidence,
                offset: Int64(range.0), length: range.1)
        }
    }

    @Test("Full-source integrity catches a changed byte outside the visible window")
    func changedSource() async throws {
        let fixture = try HexFixture(bytes: Data(repeating: 0x44, count: 2_097_155))
        defer { fixture.remove() }
        let handle = try FileHandle(forWritingTo: fixture.source)
        try handle.seek(toOffset: 2_097_150)
        try handle.write(contentsOf: Data([0x45])); try handle.close()
        await #expect(throws: ForensicsError.sourceChanged) {
            try await RawEvidenceHexReader.read(evidence: fixture.evidence, offset: 0, length: 16)
        }
    }

    @Test("Held descriptors detect same-byte pathname replacement after the window read")
    func replacedSource() throws {
        let fixture = try HexFixture(bytes: Data("abcdef".utf8))
        defer { fixture.remove() }
        #expect(throws: ForensicsError.sourceChanged) {
            try RawEvidenceHexReader.readForTesting(evidence: fixture.evidence, offset: 0, length: 4) {
                let replacement = fixture.root.appendingPathComponent("replacement")
                try Data("abcdef".utf8).write(to: replacement)
                guard Darwin.rename(replacement.path, fixture.source.path) == 0 else {
                    throw FileAccess.posixError("Fixture rename failed")
                }
            }
        }
    }

    @Test("Leaf and intermediate symlinks cannot redirect raw evidence reads", arguments: [false, true])
    func symlinkSource(_ intermediate: Bool) async throws {
        let fixture = try HexFixture(bytes: Data("abcdef".utf8))
        defer { fixture.remove() }
        let alias = fixture.root.appendingPathComponent(intermediate ? "directory-link" : "file-link")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: intermediate ? fixture.root : fixture.source)
        let path = intermediate ? alias.appendingPathComponent(fixture.source.lastPathComponent).path : alias.path
        let record = EvidenceRecord(sourcePath: path, byteCount: fixture.evidence.byteCount,
            sha256: fixture.evidence.sha256, container: .raw, filesystemHint: nil)
        await #expect(throws: ForensicsError.self) {
            try await RawEvidenceHexReader.read(evidence: record, offset: 0)
        }
        #expect(try Data(contentsOf: fixture.source) == Data("abcdef".utf8))
    }

    @Test("Cancellation propagates to the raw byte reader")
    func cancellation() async throws {
        let fixture = try HexFixture(bytes: Data(repeating: 0x41, count: 4_096))
        defer { fixture.remove() }
        let task = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await RawEvidenceHexReader.read(evidence: fixture.evidence, offset: 0)
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        let duringRead = Task.detached {
            try RawEvidenceHexReader.readForTesting(evidence: fixture.evidence, offset: 0, length: 16) {
                withUnsafeCurrentTask { $0?.cancel() }
            }
        }
        await #expect(throws: CancellationError.self) { try await duringRead.value }
    }
}

private struct HexFixture: Sendable {
    let root: URL
    let source: URL
    let evidence: EvidenceRecord
    init(bytes: Data) throws {
        root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("RawEvidenceHexTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        source = root.appendingPathComponent("damaged.dd")
        try bytes.write(to: source, options: .withoutOverwriting)
        evidence = EvidenceRecord(sourcePath: source.path, byteCount: Int64(bytes.count),
            sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
            container: .raw, filesystemHint: nil)
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
