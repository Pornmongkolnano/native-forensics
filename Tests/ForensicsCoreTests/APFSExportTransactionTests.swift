import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("APFS exclusive export publication")
struct APFSExportTransactionTests {
    @Test("Owned APFS rename adopts only its ctime transition and verifies the exact committed bytes")
    func renamedOutputIdentity() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("exported.txt"), bytes = Data("independent synthetic export bytes\n".utf8)
        let token = APFSCancellation(), transaction = try APFSExportTransaction(destination: destination)
        defer { transaction.cleanup() }
        try transaction.write(bytes, cancellation: token)
        let before = try transaction.verify(size: Int64(bytes.count), hash: hash(bytes), cancellation: token)
        try transaction.publish(identity: before, expectedSHA256: hash(bytes), cancellation: token, validate: {})
        let after = try FileAccess.identity(at: destination)
        #expect(after.device == before.device && after.inode == before.inode && after.size == before.size)
        #expect(after.modifiedSeconds == before.modifiedSeconds && after.modifiedNanoseconds == before.modifiedNanoseconds)
        #expect(after.changedSeconds != before.changedSeconds || after.changedNanoseconds != before.changedNanoseconds)
        #expect(try Data(contentsOf: destination) == bytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["exported.txt"])
    }

    @Test("Post-rename byte mutation preserving size and mtime is uncertain and its committed bytes remain visible")
    func mutationAfterRename() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("exported.txt"), bytes = Data("independent synthetic export bytes\n".utf8)
        let token = APFSCancellation(), transaction = try APFSExportTransaction(destination: destination)
        try transaction.write(bytes, cancellation: token)
        let before = try transaction.verify(size: Int64(bytes.count), hash: hash(bytes), cancellation: token)
        #expect(throws: APFSExportPublicationError.self) {
            try transaction.publish(identity: before, expectedSHA256: hash(bytes), cancellation: token, validate: {},
                afterRename: { try replaceFirstBytePreservingMtime(destination) })
        }
        transaction.cleanup()
        let after = try FileAccess.identity(at: destination), changed = try Data(contentsOf: destination)
        #expect(after.size == before.size)
        #expect(after.modifiedSeconds == before.modifiedSeconds && after.modifiedNanoseconds == before.modifiedNanoseconds)
        #expect(changed != bytes && changed.count == bytes.count)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["exported.txt"])
    }

    @Test("A failed parent flush stays published-but-unconfirmed and preserves the output")
    func parentFlushFailure() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("exported.txt"), bytes = Data("synthetic durable bytes\n".utf8)
        let token = APFSCancellation(), transaction = try APFSExportTransaction(destination: destination)
        try transaction.write(bytes, cancellation: token)
        let before = try transaction.verify(size: Int64(bytes.count), hash: hash(bytes), cancellation: token)
        #expect(throws: APFSExportPublicationError.self) {
            try transaction.publish(identity: before, expectedSHA256: hash(bytes), cancellation: token,
                                    validate: {}, flushDirectory: { _ in -1 })
        }
        transaction.cleanup()
        #expect(try Data(contentsOf: destination) == bytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["exported.txt"])
    }

    @Test("A destination created during staging is never replaced")
    func destinationCollision() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("exported.txt"), bytes = Data("synthetic staged bytes\n".utf8)
        let existing = Data("independent existing bytes\n".utf8)
        let token = APFSCancellation(), transaction = try APFSExportTransaction(destination: destination)
        try transaction.write(bytes, cancellation: token)
        let before = try transaction.verify(size: Int64(bytes.count), hash: hash(bytes), cancellation: token)
        try existing.write(to: destination, options: .withoutOverwriting)
        #expect(throws: (any Error).self) {
            try transaction.publish(identity: before, expectedSHA256: hash(bytes), cancellation: token, validate: {})
        }
        transaction.cleanup()
        #expect(try Data(contentsOf: destination) == existing)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["exported.txt"])
    }

    @Test("Cancellation during the final source validation stops before the publication commit")
    func cancellationBeforeRename() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("exported.txt"), bytes = Data("synthetic staged bytes\n".utf8)
        let token = APFSCancellation(), transaction = try APFSExportTransaction(destination: destination)
        try transaction.write(bytes, cancellation: token)
        let before = try transaction.verify(size: Int64(bytes.count), hash: hash(bytes), cancellation: token)
        #expect(throws: CancellationError.self) {
            try transaction.publish(identity: before, expectedSHA256: hash(bytes), cancellation: token,
                                    validate: { token.cancel() })
        }
        transaction.cleanup()
        #expect(!FileManager.default.fileExists(atPath: destination.path))
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }

    @Test("Replacing the parent after output verification stays uncertain and preserves committed bytes")
    func parentReplacedAfterVerification() throws {
        let root = try fixture(); defer { try? FileManager.default.removeItem(at: root) }
        let parent = root.appendingPathComponent("chosen-parent"), movedParent = root.appendingPathComponent("moved-parent")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        let destination = parent.appendingPathComponent("exported.txt"), bytes = Data("synthetic committed bytes\n".utf8)
        let token = APFSCancellation(), transaction = try APFSExportTransaction(destination: destination)
        try transaction.write(bytes, cancellation: token)
        let before = try transaction.verify(size: Int64(bytes.count), hash: hash(bytes), cancellation: token)
        #expect(throws: APFSExportPublicationError.self) {
            try transaction.publish(identity: before, expectedSHA256: hash(bytes), cancellation: token, validate: {},
                afterVerification: {
                    try FileManager.default.moveItem(at: parent, to: movedParent)
                    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
                })
        }
        transaction.cleanup()
        #expect(!FileManager.default.fileExists(atPath: destination.path))
        #expect(try Data(contentsOf: movedParent.appendingPathComponent("exported.txt")) == bytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
    }

    private func fixture() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-APFS-export-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        return root
    }
    private func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    private func replaceFirstBytePreservingMtime(_ destination: URL) throws {
        let descriptor = Darwin.open(destination.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw APFSReadError.invalidResult }
        defer { Darwin.close(descriptor) }
        var metadata = stat(), replacement: UInt8 = 0x58
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Darwin.pwrite(descriptor, &replacement, 1, 0) == 1 else { throw APFSReadError.invalidResult }
        var timestamps = [metadata.st_atimespec, metadata.st_mtimespec]
        guard timestamps.withUnsafeMutableBufferPointer({ Darwin.futimens(descriptor, $0.baseAddress) }) == 0,
              Darwin.fsync(descriptor) == 0 else { throw APFSReadError.invalidResult }
    }
}
