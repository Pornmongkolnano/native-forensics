import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("APFS read contracts")
struct APFSAdapterTests {
    @Test("Observed diskutil plist has no Mounted key and still requires readonly metadata plus the exact owned directory")
    func actualMountPlistSchema() {
        let uuid = UUID().uuidString
        let observed: [String: Any] = ["FilesystemType": "apfs", "VolumeUUID": uuid,
                                       "MountPoint": "/synthetic/owned-view", "WritableVolume": false]
        #expect(observed["Mounted"] == nil)
        #expect(APFSMountMetadata.declaresReadOnlyAPFS(observed, volumeUUID: uuid) { $0 == "/synthetic/owned-view" })
        #expect(!APFSMountMetadata.declaresReadOnlyAPFS(observed, volumeUUID: UUID().uuidString) { _ in true })
        #expect(!APFSMountMetadata.declaresReadOnlyAPFS(observed, volumeUUID: uuid) { _ in false })
        for (key, value) in [("FilesystemType", "hfs" as Any), ("WritableVolume", true as Any),
                             ("WritableVolume", "false" as Any), ("MountPoint", "" as Any)] {
            var malformed = observed; malformed[key] = value
            #expect(!APFSMountMetadata.declaresReadOnlyAPFS(malformed, volumeUUID: uuid) { _ in true })
        }
        var fabricated = observed; fabricated["Mounted"] = true; fabricated["WritableVolume"] = true
        #expect(!APFSMountMetadata.declaresReadOnlyAPFS(fabricated, volumeUUID: uuid) { _ in true })
    }
    @Test("Credentials reject transport delimiters and are consumed exactly once")
    func credentialContract() throws {
        for invalid in [Data(), Data([0]), Data("a\nb".utf8), Data("a\rb".utf8), Data([0xff]), Data(repeating: 65, count: 1_025)] {
            #expect(throws: APFSReadError.invalidCredential) { _ = try APFSPassphrase(invalid) }
        }
        let container = try APFSPassphrase(Data("synthetic passphrase".utf8))
        #expect(try container.consume() == Data("synthetic passphrase\0".utf8))
        #expect(throws: APFSReadError.credentialConsumed) { _ = try container.consume() }
        let volume = try APFSPassphrase(Data("volume secret".utf8))
        #expect(try volume.consume(terminator: 10) == Data("volume secret\n".utf8))
        #expect(throws: APFSReadError.credentialConsumed) { _ = try volume.consume() }
    }

    @Test("An empty instantaneous daemon inventory does not clear a running attach's quarantine requirement")
    func lateAttachModel() throws {
        let lifecycle = APFSAttachmentLifecycle()
        #expect(lifecycle.state == .notStarted && !lifecycle.requiresQuarantine)
        lifecycle.clientStarted()
        var simulatedDaemonInventory: Set<String> = []
        #expect(simulatedDaemonInventory.isEmpty && lifecycle.requiresQuarantine)
        // The independent daemon completes after the client was killed/reaped;
        // the backing must still exist even though the first inventory was empty.
        simulatedDaemonInventory.insert("owned-private-image")
        #expect(lifecycle.requiresQuarantine)
        #expect(simulatedDaemonInventory == ["owned-private-image"])
        // Only an actually observed natural command termination authorizes
        // inventory/detach cleanup; the inventory itself never changes state.
        lifecycle.commandReachedTerminal()
        #expect(lifecycle.state == .confirmedTerminal && !lifecycle.requiresQuarantine)
    }

    @Test("Invalid/expanded limits fail before any image operation")
    func limits() throws {
        try APFSReadOptions().validate()
        for invalid in [APFSReadOptions(maximumEntries: 50_001), APFSReadOptions(maximumFileBytes: 128 * 1_024 * 1_024 + 1),
                        APFSReadOptions(commandTimeoutSeconds: .infinity), APFSReadOptions(maximumDepth: 129),
                        APFSReadOptions(maximumMetadataBytes: 0), APFSReadOptions(maximumAggregateFileBytes: 0),
                        APFSReadOptions(jobTimeoutSeconds: .nan)] {
            #expect(throws: APFSReadError.invalidOptions) { try invalid.validate() }
        }
    }

    @Test("Stored results cannot substitute another source, unsupported contract or escaping locator")
    func resultBinding() throws {
        let source = EvidenceRecord(sourcePath: "/synthetic/image.dmg", byteCount: 128, sha256: String(repeating: "a", count: 64),
                                    container: .unknown, filesystemHint: nil)
        let entry = APFSFileEntry(relativePath: "nested/file.txt", kind: .regular, inode: 4, byteCount: 5,
                                 sha256: String(repeating: "b", count: 64), modifiedSeconds: 1, modifiedNanoseconds: 2)
        let result = makeResult(source, entries: [entry])
        try APFSMountedImageAdapter.validate(result, evidence: source)
        let other = EvidenceRecord(sourcePath: source.sourcePath, byteCount: source.byteCount, sha256: source.sha256,
                                   container: source.container, filesystemHint: nil)
        #expect(throws: APFSReadError.invalidResult) { try APFSMountedImageAdapter.validate(result, evidence: other) }
        #expect(throws: APFSReadError.invalidResult) {
            try APFSMountedImageAdapter.validate(makeResult(source, entries: [entry, entry]), evidence: source)
        }
        for path in ["../escape", "/absolute", "a//b", "a/../b", "a/./b", "a\0b", "tail/"] {
            let bad = APFSFileEntry(relativePath: path, kind: .regular, inode: 4, byteCount: 5,
                                   sha256: entry.sha256, modifiedSeconds: 1, modifiedNanoseconds: 2)
            #expect(throws: APFSReadError.invalidResult) {
                try APFSMountedImageAdapter.validate(makeResult(source, entries: [bad]), evidence: source)
            }
        }
        let linked = APFSFileEntry(relativePath: "link", kind: .symbolicLink, inode: 7, byteCount: 9,
                                  sha256: entry.sha256, modifiedSeconds: 1, modifiedNanoseconds: 2)
        #expect(throws: APFSReadError.invalidResult) {
            try APFSMountedImageAdapter.validate(makeResult(source, entries: [linked]), evidence: source)
        }
    }

    @Test("Cancellation before launch creates no owned scratch directory")
    func preCancelled() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-APFS-cancel-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = EvidenceRecord(sourcePath: "/synthetic/image.dmg", byteCount: 128, sha256: String(repeating: "a", count: 64),
                                    container: .unknown, filesystemHint: nil)
        let task = Task { try Task.checkCancellation(); return try await APFSMountedImageAdapter(scratchRoot: root).inspect(evidence: source) }
        task.cancel()
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }

    @Test("A mismatched complete selected-file hash fails and cleans only its private image")
    func wrongSourceHash() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-APFS-hash-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let image = root.appendingPathComponent("input.img"), scratch = root.appendingPathComponent("scratch")
        let bytes = Data("independently known invalid image".utf8)
        try bytes.write(to: image, options: .withoutOverwriting)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: false)
        let source = EvidenceRecord(sourcePath: image.path, byteCount: Int64(bytes.count), sha256: String(repeating: "a", count: 64),
                                    container: .raw, filesystemHint: nil)
        await #expect(throws: APFSReadError.sourceChanged) { _ = try await APFSMountedImageAdapter(scratchRoot: scratch).inspect(evidence: source) }
        #expect(try Data(contentsOf: image) == bytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: scratch.path).isEmpty)
    }

    @Test("A legacy source resource fork is rejected before private-copy/attach with original bytes and metadata intact")
    func resourceForkScope() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-APFS-fork-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let image = root.appendingPathComponent("legacy.img"), scratch = root.appendingPathComponent("scratch")
        let bytes = Data("known main-fork bytes".utf8), fork = Data("synthetic out-of-hash resource fork".utf8)
        try bytes.write(to: image, options: .withoutOverwriting)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: false)
        let fd = Darwin.open(image.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        try #require(fd >= 0)
        defer { Darwin.close(fd) }
        try fork.withUnsafeBytes { buffer in
            try #require(Darwin.fsetxattr(fd, "com.apple.ResourceFork", buffer.baseAddress, buffer.count, 0, 0) == 0)
        }
        let before = try FileAccess.identity(of: fd)
        let sha = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let evidence = EvidenceRecord(sourcePath: image.path, byteCount: Int64(bytes.count), sha256: sha, container: .raw, filesystemHint: nil)
        await #expect(throws: APFSReadError.unsupported(APFSImageSourceScope.resourceForkReason)) {
            _ = try await APFSMountedImageAdapter(scratchRoot: scratch).inspect(evidence: evidence)
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: scratch.path).isEmpty)
        #expect(try Data(contentsOf: image) == bytes)
        #expect(try FileAccess.identity(of: fd) == before)
        #expect(Darwin.fgetxattr(fd, "com.apple.ResourceFork", nil, 0, 0, 0) == fork.count)
        var actualFork = Data(count: fork.count)
        let count = actualFork.withUnsafeMutableBytes { Darwin.fgetxattr(fd, "com.apple.ResourceFork", $0.baseAddress, $0.count, 0, 0) }
        #expect(count == fork.count && actualFork == fork)
    }

    private func makeResult(_ source: EvidenceRecord, entries: [APFSFileEntry]) -> APFSInspectionResult {
        .init(schemaVersion: 1, evidenceID: source.id, containerSHA256: source.sha256, containerByteCount: source.byteCount,
              hashScope: FileHashScope.selectedFileBytes, driver: "apple-system-readonly-apfs-v1", driverVersion: "synthetic",
              options: .init(), volumeUUID: UUID(), containerEncryption: .none, volumeEncryption: .none,
              entries: entries, snapshots: [], snapshotInventoryAvailable: true, coverage: .completeAllocatedView, warnings: [])
    }
}
