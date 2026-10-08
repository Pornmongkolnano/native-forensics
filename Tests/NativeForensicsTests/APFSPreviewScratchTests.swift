import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("APFS owned preview bytes", .serialized)
struct APFSPreviewScratchTests {
    @Test("A complete independently hashed payload is written and cleanup removes only owned leaves")
    func verifiedScratch() throws {
        let parent = try makeParent(); defer { try? FileManager.default.removeItem(at: parent) }
        let preserved = parent.appendingPathComponent("preserved.txt")
        try Data("preserve".utf8).write(to: preserved, options: .withoutOverwriting)
        let data = Data("APFS preview ภาษาไทย\n".utf8), scratch = try APFSPreviewScratch(parentURL: parent)
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        try scratch.writeVerified(data, sha256: hash)
        #expect(try Data(contentsOf: scratch.fileURL) == data)
        try scratch.validate(); try scratch.cleanupChecked()
        #expect(!FileManager.default.fileExists(atPath: scratch.directoryURL.path))
        #expect(try Data(contentsOf: preserved) == Data("preserve".utf8))
    }

    @Test("A replaced leaf is rejected and cleanup never follows its symlink")
    func replacedLeaf() throws {
        let parent = try makeParent(); defer { try? FileManager.default.removeItem(at: parent) }
        let target = parent.appendingPathComponent("target.txt")
        try Data("never modify".utf8).write(to: target, options: .withoutOverwriting)
        let scratch = try APFSPreviewScratch(parentURL: parent)
        try FileManager.default.removeItem(at: scratch.fileURL)
        try FileManager.default.createSymbolicLink(at: scratch.fileURL, withDestinationURL: target)
        #expect(throws: DocumentAnalysisError.sourceChanged) { try scratch.validate() }
        scratch.cleanup()
        #expect(try Data(contentsOf: target) == Data("never modify".utf8))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: scratch.fileURL.path) == target.path)
    }

    @Test("Invalid digest cannot prepare document bytes")
    func invalidDigest() throws {
        let parent = try makeParent(); defer { try? FileManager.default.removeItem(at: parent) }
        let scratch = try APFSPreviewScratch(parentURL: parent)
        #expect(throws: DocumentAnalysisError.integrityMismatch) {
            try scratch.writeVerified(Data("known".utf8), sha256: String(repeating: "0", count: 64))
        }
        #expect(try Data(contentsOf: scratch.fileURL).isEmpty)
        scratch.cleanup(); #expect(!FileManager.default.fileExists(atPath: scratch.directoryURL.path))
    }

    @Test("An injected sibling survives nonrecursive cleanup")
    func preservesUnknownSibling() throws {
        let parent = try makeParent(); defer { try? FileManager.default.removeItem(at: parent) }
        let scratch = try APFSPreviewScratch(parentURL: parent)
        let sibling = scratch.directoryURL.appendingPathComponent("unowned.txt")
        try Data("preserve unowned leaf".utf8).write(to: sibling, options: .withoutOverwriting)
        #expect(throws: APFSPreviewError.cleanupIncomplete) { try scratch.cleanupChecked() }
        #expect(try Data(contentsOf: sibling) == Data("preserve unowned leaf".utf8))
        #expect(!FileManager.default.fileExists(atPath: scratch.fileURL.path))
    }

    @Test("Correct file bytes from a different snapshot tuple cannot enter local preview")
    func snapshotBinding() throws {
        let data = Data("same independently known file bytes\n".utf8)
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let evidence = EvidenceRecord(sourcePath: "/synthetic/snapshots.dmg", byteCount: 128,
            sha256: String(repeating: "a", count: 64), container: .unknown, filesystemHint: nil)
        let volume = UUID(), snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let entry = APFSFileEntry(relativePath: "known.txt", kind: .regular, inode: 12, byteCount: Int64(data.count),
            sha256: hash, modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 0)
        let inspection = APFSInspectionResult(evidenceID: evidence.id, containerSHA256: evidence.sha256,
            containerByteCount: evidence.byteCount, driverVersion: "synthetic-preview-binding",
            options: APFSReadOptions(selectedVolumeUUID: volume, selectedSnapshotUUID: snapshot.uuid), volumeUUID: volume,
            containerEncryption: .none, volumeEncryption: .none, entries: [entry], snapshots: [snapshot],
            snapshotInventoryAvailable: true, coverage: .completeAllocatedView, warnings: [], selectedSnapshot: snapshot)
        let valid = APFSVerifiedFile(data: data, sha256: hash, containerSHA256: evidence.sha256,
            volumeUUID: volume, relativePath: entry.relativePath, selectedSnapshot: snapshot)
        try APFSPreviewService.validateVerifiedFile(valid, evidence: evidence, inspection: inspection, entry: entry)
        for wrong in [APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: snapshot.name, transactionID: 42),
                      APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: "other-name", transactionID: snapshot.transactionID)] {
            let substituted = APFSVerifiedFile(data: data, sha256: hash, containerSHA256: evidence.sha256,
                volumeUUID: volume, relativePath: entry.relativePath, selectedSnapshot: wrong)
            #expect(throws: DocumentAnalysisError.integrityMismatch) {
                try APFSPreviewService.validateVerifiedFile(substituted, evidence: evidence, inspection: inspection, entry: entry)
            }
        }
        let current = APFSVerifiedFile(data: data, sha256: hash, containerSHA256: evidence.sha256,
            volumeUUID: volume, relativePath: entry.relativePath)
        #expect(throws: DocumentAnalysisError.integrityMismatch) {
            try APFSPreviewService.validateVerifiedFile(current, evidence: evidence, inspection: inspection, entry: entry)
        }
    }

    private func makeParent() throws -> URL {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("NF-APFS-preview-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return root
    }
}
