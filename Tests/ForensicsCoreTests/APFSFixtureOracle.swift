import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// The operating system creates these APFS containers from independently known
/// bytes. The production adapter never produces its own expected output. Image
/// IDs and container hashes are measured per run because APFS creation is not a
/// deterministic disk-image serializer.
@Suite("Independent APFS mounted-image combinations", .serialized)
struct APFSFixtureOracle {
    private static let enabled = ProcessInfo.processInfo.environment["NF_APFS_INTEGRATION"] == "1"

    @Test("Cooperative attach cancellation drains the read-only operation and cleans owned images before reporting cancellation",
          .enabled(if: APFSFixtureOracle.enabled))
    func cooperativeAttachCancellation() async throws {
        let fixture = try APFSOracleImageFixture()
        defer { fixture.bestEffortCleanup() }
        let image = try fixture.createPlainImage()
        let inspected = try await ImageInspector.inspect(url: image, progress: { _ in })
        let evidence = fixture.evidence(from: inspected), control = APFSFixtureCancellation()
        let adapter = APFSMountedImageAdapter(scratchRoot: fixture.adapterScratch) { event in
            if case .attachClientStarted = event { control.requestCancellation() }
        }
        let task = Task { try await adapter.inspect(evidence: evidence) }
        control.install(task)
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        #expect(control.wasRequested)
        try fixture.requireEmptyAdapterScratch()
        let after = try await ImageInspector.inspect(url: image, progress: { _ in })
        #expect(after.sha256 == inspected.sha256 && after.sourceIdentity == inspected.sourceIdentity)
        try fixture.cleanup()
    }

    @Test("A killed actual attach client retains a reviewable backing image for a simulated late daemon attach",
          .enabled(if: APFSFixtureOracle.enabled))
    func cancelledAttachQuarantine() async throws {
        let fixture = try APFSOracleImageFixture()
        // This test intentionally keeps its synthetic quarantine: an empty
        // current inventory is not a positive original-daemon drain receipt.
        var preserveQuarantine = false
        defer { if !preserveQuarantine { fixture.bestEffortCleanup() } }
        let image = try fixture.createPlainImage()
        let inspected = try await ImageInspector.inspect(url: image, progress: { _ in })
        let evidence = fixture.evidence(from: inspected), control = APFSFixtureCancellation()
        let adapter = APFSMountedImageAdapter(scratchRoot: fixture.adapterScratch) { event in
            if case .attachClientStarted(let pid) = event {
                // The callback receives the just-spawned, unreaped OWNED child;
                // its identity cannot be reused before this startup hook ends.
                Darwin.kill(pid, SIGKILL)
                control.requestCancellation()
            }
        }
        let task = Task { try await adapter.inspect(evidence: evidence) }
        control.install(task)
        await #expect(throws: APFSReadError.cleanupIncomplete) { _ = try await task.value }
        #expect(control.wasRequested)
        preserveQuarantine = true
        try fixture.verifyRetainedBackingAndLateAttach(expectedSHA256: inspected.sha256)
        let after = try await ImageInspector.inspect(url: image, progress: { _ in })
        #expect(after.sha256 == inspected.sha256 && after.sourceIdentity == inspected.sourceIdentity)
    }

    @Test("Plain APFS verified files match an independent read-only mount and preserve the source",
          .enabled(if: APFSFixtureOracle.enabled))
    func plainAPFS() async throws {
        let fixture = try APFSOracleImageFixture()
        defer { fixture.bestEffortCleanup() }
        let image = try fixture.createPlainImage()
        let before = try await ImageInspector.inspect(url: image, progress: { _ in })
        let independentContainerSHA256 = try fixture.independentContainerHash(image)
        #expect(before.sha256 == independentContainerSHA256)
        let independentVolumeUUID = try fixture.verifyIndependentReadOnlyMount(image: image)
        let created = try CaseStore.create(name: "Plain APFS Oracle", in: fixture.root)
        let forensicCase = try CaseStore.adding(image: before, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let adapter = fixture.productionAdapter()
        let inspection = try await adapter.inspect(evidence: evidence)
        #expect(inspection.evidenceID == evidence.id)
        #expect(inspection.containerSHA256 == before.sha256)
        #expect(inspection.containerByteCount == before.byteCount)
        #expect(inspection.volumeUUID == independentVolumeUUID)
        #expect(inspection.containerEncryption == .none)
        #expect(inspection.volumeEncryption == .none)
        #expect(inspection.hashScope == FileHashScope.selectedFileBytes)
        #expect(inspection.coverage == .completeAllocatedView)
        let cache = try APFSResultStore.save(inspection, in: forensicCase)
        #expect(try APFSResultStore.loadLatest(in: forensicCase, evidenceID: evidence.id) == inspection)
        try fixture.verifyCompleteEnumeration(inspection)
        for (path, expectedBytes) in fixture.expected.sorted(by: { $0.key < $1.key }) {
            let entry = try #require(inspection.entries.first { $0.relativePath == path })
            #expect(entry.byteCount == Int64(expectedBytes.count))
            #expect(entry.sha256 == APFSOracleImageFixture.hash(expectedBytes))
            let verified = try await adapter.readVerifiedFile(evidence: evidence, inspection: inspection, entry: entry)
            #expect(verified.data == expectedBytes)
            #expect(verified.sha256 == APFSOracleImageFixture.hash(expectedBytes))
            #expect(verified.containerSHA256 == before.sha256)
            #expect(verified.volumeUUID == inspection.volumeUUID)
            #expect(verified.relativePath == path)
            try fixture.requireEmptyAdapterScratch()
        }
        let escape = try #require(inspection.entries.first(where: { $0.relativePath == "escape-link" }))
        #expect(escape.kind == .symbolicLink && escape.sha256 == nil)
        await #expect(throws: APFSReadError.fileUnavailable) {
            _ = try await adapter.readVerifiedFile(evidence: evidence, inspection: inspection, entry: escape)
        }
        try fixture.requireEmptyAdapterScratch()
        let exportedEntry = try #require(inspection.entries.first { $0.relativePath == "alpha.txt" })
        let destination = fixture.root.appendingPathComponent("exported-alpha.txt")
        let export = try await APFSExportService.export(evidence: evidence, inspection: inspection, entry: exportedEntry,
                                                       in: forensicCase, to: destination)
        #expect(try Data(contentsOf: destination) == fixture.expected["alpha.txt"])
        #expect(export.sha256 == exportedEntry.sha256)
        #expect(export.containerSHA256 == evidence.sha256)
        #expect(export.resultSHA256 == cache.resultSHA256)
        #expect(export.outputHashScope == "logical-APFS-file-bytes")
        #expect(export.caseID == forensicCase.manifest.id && export.evidenceID == evidence.id)
        #expect(!String(decoding: try JSONEncoder().encode(export), as: UTF8.self).contains(fixture.root.path))
        let beforeExisting = try Data(contentsOf: destination)
        await #expect(throws: APFSReadError.invalidResult) {
            _ = try await APFSExportService.export(evidence: evidence, inspection: inspection, entry: exportedEntry,
                                                   in: forensicCase, to: destination)
        }
        #expect(try Data(contentsOf: destination) == beforeExisting)
        let after = try await ImageInspector.inspect(url: image, progress: { _ in })
        #expect(after.sha256 == before.sha256)
        #expect(try fixture.independentContainerHash(image) == independentContainerSHA256)
        #expect(after.byteCount == before.byteCount)
        #expect(after.sourceIdentity == before.sourceIdentity)
        try fixture.cleanup()
    }

    @Test("AES-256 UDIF wrapping plain APFS requires the correct stdin credential and retains plaintext oracles",
          .enabled(if: APFSFixtureOracle.enabled))
    func encryptedUDIF() async throws {
        let fixture = try APFSOracleImageFixture()
        defer { fixture.bestEffortCleanup() }
        let plain = try fixture.createPlainImage()
        let secret = Data(UUID().uuidString.utf8)
        let encrypted = try fixture.createEncryptedUDIF(from: plain, passphrase: secret)
        let before = try await ImageInspector.inspect(url: encrypted, progress: { _ in })
        let independentContainerSHA256 = try fixture.independentContainerHash(encrypted)
        #expect(before.sha256 == independentContainerSHA256)
        let independentVolumeUUID = try fixture.verifyIndependentReadOnlyMount(image: encrypted, passphrase: secret)
        let evidence = fixture.evidence(from: before)
        let adapter = fixture.productionAdapter()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence)
        }
        try fixture.requireEmptyAdapterScratch()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence, passphrase: try APFSPassphrase(Data("wrong synthetic credential".utf8)))
        }
        try fixture.requireEmptyAdapterScratch()
        let inspection = try await adapter.inspect(evidence: evidence, passphrase: try APFSPassphrase(secret))
        #expect(inspection.containerSHA256 == before.sha256)
        #expect(inspection.containerByteCount == before.byteCount)
        #expect(inspection.volumeUUID == independentVolumeUUID)
        #expect(inspection.containerEncryption == .encryptedDiskImage)
        #expect(inspection.volumeEncryption == .none)
        #expect(inspection.hashScope == FileHashScope.selectedFileBytes)
        #expect(inspection.coverage == .completeAllocatedView)
        try fixture.verifyCompleteEnumeration(inspection)
        for (path, expectedBytes) in fixture.expected.sorted(by: { $0.key < $1.key }) {
            let entry = try #require(inspection.entries.first { $0.relativePath == path })
            let verified = try await adapter.readVerifiedFile(
                evidence: evidence, inspection: inspection, entry: entry, passphrase: try APFSPassphrase(secret))
            #expect(verified.data == expectedBytes)
            #expect(verified.sha256 == APFSOracleImageFixture.hash(expectedBytes))
            #expect(verified.containerSHA256 == before.sha256)
            #expect(verified.volumeUUID == inspection.volumeUUID)
            #expect(verified.relativePath == path)
            try fixture.requireEmptyAdapterScratch()
        }
        let after = try await ImageInspector.inspect(url: encrypted, progress: { _ in })
        #expect(after.sha256 == before.sha256)
        #expect(try fixture.independentContainerHash(encrypted) == independentContainerSHA256)
        #expect(after.byteCount == before.byteCount)
        #expect(after.sourceIdentity == before.sourceIdentity)
        try fixture.cleanup()
    }

    @Test("Disk-user APFS volume encryption in a plain UDIF requires a separate volume credential",
          .enabled(if: APFSFixtureOracle.enabled))
    func encryptedAPFSVolume() async throws {
        let fixture = try APFSOracleImageFixture()
        defer { fixture.bestEffortCleanup() }
        let plain = try fixture.createPlainImage()
        let volumeSecret = Data(UUID().uuidString.utf8)
        let encrypted = try fixture.createAPFSVolumeEncryptedImage(from: plain, passphrase: volumeSecret)
        let before = try await ImageInspector.inspect(url: encrypted, progress: { _ in })
        let independentContainerSHA256 = try fixture.independentContainerHash(encrypted)
        #expect(before.sha256 == independentContainerSHA256)
        let independentVolumeUUID = try fixture.verifyIndependentReadOnlyMount(image: encrypted, volumePassphrase: volumeSecret)
        let evidence = fixture.evidence(from: before)
        let adapter = fixture.productionAdapter()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence)
        }
        try fixture.requireEmptyAdapterScratch()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence,
                volumePassphrase: try APFSPassphrase(Data("wrong synthetic volume credential".utf8)))
        }
        try fixture.requireEmptyAdapterScratch()
        let inspection = try await adapter.inspect(evidence: evidence, volumePassphrase: try APFSPassphrase(volumeSecret))
        #expect(inspection.containerSHA256 == before.sha256)
        #expect(inspection.containerByteCount == before.byteCount)
        #expect(inspection.volumeUUID == independentVolumeUUID)
        #expect(inspection.containerEncryption == .none)
        #expect(inspection.volumeEncryption == .diskUserAPFS)
        #expect(inspection.hashScope == FileHashScope.selectedFileBytes)
        #expect(inspection.coverage == .completeAllocatedView)
        try fixture.verifyCompleteEnumeration(inspection)
        for (path, expectedBytes) in fixture.expected.sorted(by: { $0.key < $1.key }) {
            let entry = try #require(inspection.entries.first { $0.relativePath == path })
            let verified = try await adapter.readVerifiedFile(
                evidence: evidence, inspection: inspection, entry: entry, volumePassphrase: try APFSPassphrase(volumeSecret))
            #expect(verified.data == expectedBytes)
            #expect(verified.sha256 == APFSOracleImageFixture.hash(expectedBytes))
            #expect(verified.containerSHA256 == before.sha256)
            #expect(verified.volumeUUID == inspection.volumeUUID)
            #expect(verified.relativePath == path)
            try fixture.requireEmptyAdapterScratch()
        }
        let after = try await ImageInspector.inspect(url: encrypted, progress: { _ in })
        #expect(after.sha256 == before.sha256)
        #expect(try fixture.independentContainerHash(encrypted) == independentContainerSHA256)
        #expect(after.byteCount == before.byteCount)
        #expect(after.sourceIdentity == before.sourceIdentity)
        try fixture.cleanup()
    }

    @Test("Two independently encrypted layers require distinct container and Disk-user volume credentials",
          .enabled(if: APFSFixtureOracle.enabled))
    func combinedEncryptedContainerAndVolume() async throws {
        let fixture = try APFSOracleImageFixture()
        defer { fixture.bestEffortCleanup() }
        let plain = try fixture.createPlainImage()
        let volumeSecret = Data("ทดสอบ volume e\u{301} with spaces \(UUID().uuidString)".utf8)
        let containerSecret = Data("container secret \(UUID().uuidString)".utf8)
        #expect(containerSecret != volumeSecret)
        let volumeEncrypted = try fixture.createAPFSVolumeEncryptedImage(from: plain, passphrase: volumeSecret)
        let combined = try fixture.createEncryptedUDIF(from: volumeEncrypted, passphrase: containerSecret)
        let before = try await ImageInspector.inspect(url: combined, progress: { _ in })
        let independentContainerSHA256 = try fixture.independentContainerHash(combined)
        #expect(before.sha256 == independentContainerSHA256)
        let independentVolumeUUID = try fixture.verifyIndependentReadOnlyMount(
            image: combined, passphrase: containerSecret, volumePassphrase: volumeSecret)
        let evidence = fixture.evidence(from: before)
        let adapter = fixture.productionAdapter()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence,
                passphrase: try APFSPassphrase(Data("wrong synthetic container credential".utf8)),
                volumePassphrase: try APFSPassphrase(volumeSecret))
        }
        try fixture.requireEmptyAdapterScratch()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence,
                passphrase: try APFSPassphrase(containerSecret),
                volumePassphrase: try APFSPassphrase(Data("wrong synthetic volume credential".utf8)))
        }
        try fixture.requireEmptyAdapterScratch()
        await #expect(throws: (any Error).self) {
            _ = try await adapter.inspect(evidence: evidence, passphrase: try APFSPassphrase(containerSecret))
        }
        try fixture.requireEmptyAdapterScratch()
        let inspection = try await adapter.inspect(evidence: evidence,
            passphrase: try APFSPassphrase(containerSecret), volumePassphrase: try APFSPassphrase(volumeSecret))
        #expect(inspection.containerSHA256 == before.sha256)
        #expect(inspection.containerByteCount == before.byteCount)
        #expect(inspection.volumeUUID == independentVolumeUUID)
        #expect(inspection.containerEncryption == .encryptedDiskImage)
        #expect(inspection.volumeEncryption == .diskUserAPFS)
        #expect(inspection.hashScope == FileHashScope.selectedFileBytes)
        #expect(inspection.coverage == .completeAllocatedView)
        try fixture.verifyCompleteEnumeration(inspection)
        for (path, expectedBytes) in fixture.expected.sorted(by: { $0.key < $1.key }) {
            let entry = try #require(inspection.entries.first { $0.relativePath == path })
            let verified = try await adapter.readVerifiedFile(
                evidence: evidence, inspection: inspection, entry: entry,
                passphrase: try APFSPassphrase(containerSecret), volumePassphrase: try APFSPassphrase(volumeSecret))
            #expect(verified.data == expectedBytes)
            #expect(verified.sha256 == APFSOracleImageFixture.hash(expectedBytes))
            #expect(verified.containerSHA256 == before.sha256)
            #expect(verified.volumeUUID == inspection.volumeUUID)
            #expect(verified.relativePath == path)
            try fixture.requireEmptyAdapterScratch()
        }
        let after = try await ImageInspector.inspect(url: combined, progress: { _ in })
        #expect(after.sha256 == before.sha256)
        #expect(try fixture.independentContainerHash(combined) == independentContainerSHA256)
        #expect(after.byteCount == before.byteCount)
        #expect(after.sourceIdentity == before.sourceIdentity)
        try fixture.cleanup()
    }

    @Test("RAW GPT/APFS logical device bytes have independent CRC, geometry, readonly and plaintext oracles",
          .enabled(if: APFSFixtureOracle.enabled))
    func rawGPTAPFS() async throws {
        let fixture = try APFSOracleImageFixture()
        defer { fixture.bestEffortCleanup() }
        let plain = try fixture.createPlainImage()
        let raw = try fixture.createRawGPTImage(from: plain)
        let before = try await ImageInspector.inspect(url: raw, progress: { _ in })
        let independentContainerSHA256 = try fixture.independentContainerHash(raw)
        #expect(before.sha256 == independentContainerSHA256)
        #expect(before.container == .raw)
        let independentVolumeUUID = try fixture.verifyIndependentReadOnlyMount(image: raw, rawLogicalDevice: true)
        let evidence = fixture.evidence(from: before)
        let adapter = fixture.productionAdapter()
        let inspection = try await adapter.inspect(evidence: evidence)
        #expect(inspection.evidenceID == evidence.id)
        #expect(inspection.containerSHA256 == before.sha256)
        #expect(inspection.containerByteCount == before.byteCount)
        #expect(inspection.volumeUUID == independentVolumeUUID)
        #expect(inspection.containerEncryption == .none && inspection.volumeEncryption == .none)
        #expect(inspection.coverage == .completeAllocatedView)
        try fixture.verifyCompleteEnumeration(inspection)
        for (path, expectedBytes) in fixture.expected.sorted(by: { $0.key < $1.key }) {
            let entry = try #require(inspection.entries.first { $0.relativePath == path })
            let verified = try await adapter.readVerifiedFile(evidence: evidence, inspection: inspection, entry: entry)
            #expect(verified.data == expectedBytes)
            #expect(verified.sha256 == APFSOracleImageFixture.hash(expectedBytes))
            #expect(verified.containerSHA256 == before.sha256 && verified.volumeUUID == independentVolumeUUID)
            #expect(verified.relativePath == path)
            try fixture.requireEmptyAdapterScratch()
        }
        let after = try await ImageInspector.inspect(url: raw, progress: { _ in })
        #expect(after.sha256 == before.sha256)
        #expect(try fixture.independentContainerHash(raw) == independentContainerSHA256)
        #expect(after.byteCount == before.byteCount && after.sourceIdentity == before.sourceIdentity)
        try fixture.cleanup()
    }
}

private final class APFSFixtureCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<APFSInspectionResult, any Error>?
    private var requested = false
    var wasRequested: Bool { lock.lock(); defer { lock.unlock() }; return requested }
    func install(_ value: Task<APFSInspectionResult, any Error>) {
        lock.lock(); task = value; let shouldCancel = requested; lock.unlock()
        if shouldCancel { value.cancel() }
    }
    func requestCancellation() {
        lock.lock(); requested = true; let current = task; lock.unlock()
        current?.cancel()
    }
}

private final class APFSOracleImageFixture {
    let root: URL
    let seed: URL
    let adapterScratch: URL
    let expected: [String: Data] = [
        "alpha.txt": Data("APFS independent oracle\nThai: ทดสอบข้อมูล\nCombining: e\u{301}\nshared marker\n".utf8),
        "nested/file with spaces.txt": Data("Second independent file\n0123456789\n".utf8),
        "binary.bin": Data((0..<8_193).map { UInt8(($0 * 31 + 7) % 256) })
    ]
    private var attachedDevices: Set<String> = []
    private var knownImagePaths: Set<String> = []
    private var independentEntryKinds: [String: APFSFileKind]?

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-APFS-oracle-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        seed = root.appendingPathComponent("seed", isDirectory: true)
        adapterScratch = root.appendingPathComponent("adapter-scratch", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            try FileManager.default.createDirectory(at: seed, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(at: adapterScratch, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for (path, bytes) in expected {
                let destination = seed.appendingPathComponent(path)
                try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
                try bytes.write(to: destination, options: .withoutOverwriting)
                try #require(try Data(contentsOf: destination) == bytes)
            }
            try Data("Synthetic outside marker; never disclose through a mounted-image symlink.\n".utf8)
                .write(to: root.appendingPathComponent("outside-marker.txt"), options: .withoutOverwriting)
            // A real, owned absolute target remains present when the adapter
            // mounts at a different scratch depth. A relative link would be
            // dangling there and could miss a traversal-leak regression.
            try FileManager.default.createSymbolicLink(atPath: seed.appendingPathComponent("escape-link").path,
                withDestinationPath: root.appendingPathComponent("outside-marker.txt").path)
        } catch {
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func createPlainImage() throws -> URL {
        let image = root.appendingPathComponent("plain-apfs.dmg")
        knownImagePaths.insert(image.path)
        _ = try run("/usr/bin/hdiutil", ["create", "-size", "128m", "-fs", "APFS", "-srcfolder", seed.path,
            "-format", "UDRW", "-nospotlight", "-volname", "NativeForensicsOracle", image.path])
        try #require(FileManager.default.fileExists(atPath: image.path))
        return image
    }

    func createEncryptedUDIF(from plain: URL, passphrase: Data) throws -> URL {
        let image = root.appendingPathComponent("encrypted-udif-apfs.dmg")
        knownImagePaths.insert(image.path)
        _ = try run("/usr/bin/hdiutil", ["convert", plain.path, "-format", "UDRO", "-encryption", "AES-256",
            "-stdinpass", "-o", image.path], passphrase: passphrase)
        let receipt = try run("/usr/bin/hdiutil", ["isencrypted", "-plist", image.path])
        let dictionary = try #require(try PropertyListSerialization.propertyList(from: receipt, format: nil) as? [String: Any])
        try #require(dictionary["encrypted"] as? Bool == true)
        return image
    }

    /// Encryption is a fixture-construction operation on a fresh owned copy.
    /// Production analysis is never permitted to invoke encryptVolume.
    func createAPFSVolumeEncryptedImage(from plain: URL, passphrase: Data) throws -> URL {
        let image = root.appendingPathComponent("encrypted-apfs-volume.dmg")
        knownImagePaths.insert(image.path)
        try FileManager.default.copyItem(at: plain, to: image)
        let mount = root.appendingPathComponent("crypto-construction-mount", isDirectory: true)
        try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let receipt = try run("/usr/bin/hdiutil", ["attach", image.path, "-readwrite", "-nobrowse", "-noautoopen",
            "-noautofsck", "-noverify", "-mountpoint", mount.path, "-plist"])
        let dictionary = try #require(try PropertyListSerialization.propertyList(from: receipt, format: nil) as? [String: Any])
        let entities = try #require(dictionary["system-entities"] as? [[String: Any]])
        let wholeDevice = try #require(entities.compactMap { $0["dev-entry"] as? String }.first { $0.range(of: "^/dev/disk[0-9]+$", options: .regularExpression) != nil })
        attachedDevices.insert(wholeDevice)
        do {
            let volumeDevice = try #require(entities.first { sameMountedDirectory($0["mount-point"] as? String, mount) }?["dev-entry"] as? String)
            let initialInfoBytes = try run("/usr/sbin/diskutil", ["info", "-plist", volumeDevice])
            let initialInfo = try #require(try PropertyListSerialization.propertyList(from: initialInfoBytes, format: nil) as? [String: Any])
            try #require(initialInfo["FilesystemType"] as? String == "apfs")
            try #require(initialInfo["Encryption"] as? Bool == false)
            let container = try #require(initialInfo["APFSContainerReference"] as? String)
            _ = try run("/usr/sbin/diskutil", ["apfs", "encryptVolume", volumeDevice, "-user", "disk", "-stdinpassphrase"],
                passphrase: passphrase, credentialTerminator: 10)
            let clock = ContinuousClock()
            let deadline = clock.now + .seconds(60)
            while true {
                let stateBytes = try run("/usr/sbin/diskutil", ["apfs", "list", container, "-plist"])
                let state = try #require(try PropertyListSerialization.propertyList(from: stateBytes, format: nil) as? [String: Any])
                let containers = try #require(state["Containers"] as? [[String: Any]])
                let volumes = containers.flatMap { ($0["Volumes"] as? [[String: Any]]) ?? [] }
                let identifier = URL(fileURLWithPath: volumeDevice).lastPathComponent
                let volume = try #require(volumes.first { ($0["DeviceIdentifier"] as? String) == identifier })
                if volume["CryptoMigrationOn"] as? Bool == false {
                    try #require(volume["Encryption"] as? Bool == true)
                    break
                }
                try #require(clock.now < deadline)
                usleep(500_000)
            }
            try detachOwnedDevice(wholeDevice)
            return image
        } catch {
            try? detachOwnedDevice(wholeDevice)
            throw error
        }
    }

    /// UDTO is a construction route. CRC-checked logical structures and exact
    /// device geometry, rather than the suffix or a format label, certify this
    /// corpus file as raw GPT/APFS device bytes.
    func createRawGPTImage(from plain: URL) throws -> URL {
        let image = root.appendingPathComponent("raw-apfs.cdr")
        knownImagePaths.insert(image.path)
        _ = try run("/usr/bin/hdiutil", ["convert", plain.path, "-format", "UDTO", "-o", root.appendingPathComponent("raw-apfs").path])
        let infoBytes = try run("/usr/bin/hdiutil", ["imageinfo", "-plist", image.path])
        let info = try #require(try PropertyListSerialization.propertyList(from: infoBytes, format: nil) as? [String: Any])
        try #require(info["Format"] as? String == "UDTO")
        let size = try FileAccess.identity(at: image).size
        try #require(size > 1_024 && size % 512 == 0)
        let stream = try FileHandle(forReadingFrom: image)
        defer { try? stream.close() }
        let mbr = try #require(try stream.read(upToCount: 512))
        try #require(mbr.count == 512 && mbr.suffix(2) == Data([0x55, 0xaa]) && mbr[450] == 0xee)
        let header = try #require(try stream.read(upToCount: 512))
        try #require(header.count == 512 && header.prefix(8) == Data("EFI PART".utf8))
        let headerLength = Int(Self.le32(header, 12))
        try #require((92...512).contains(headerLength))
        var headerCRCBytes = Data(header.prefix(headerLength))
        headerCRCBytes.replaceSubrange(16..<20, with: [UInt8](repeating: 0, count: 4))
        try #require(Self.crc32(headerCRCBytes) == Self.le32(header, 16))
        try #require(Self.le64(header, 24) == 1 && Self.le64(header, 32) == UInt64(size / 512 - 1))
        let firstUsable = Self.le64(header, 40), lastUsable = Self.le64(header, 48)
        let entriesLBA = Self.le64(header, 72), entryCount = Int(Self.le32(header, 80)), entrySize = Int(Self.le32(header, 84))
        try #require((1...4_096).contains(entryCount) && entrySize >= 128 && entrySize <= 4_096 && entryCount * entrySize <= 1_048_576)
        try #require(entriesLBA <= UInt64(size / 512) && UInt64(entryCount * entrySize) <= UInt64(size) - entriesLBA * 512)
        try stream.seek(toOffset: entriesLBA * 512)
        let entries = try #require(try stream.read(upToCount: entryCount * entrySize))
        try #require(entries.count == entryCount * entrySize && Self.crc32(entries) == Self.le32(header, 88))
        let apfsType = Data([0xef, 0x57, 0x34, 0x7c, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac])
        var apfsRange: (UInt64, UInt64)?
        for index in 0..<entryCount {
            let entry = entries.subdata(in: index * entrySize..<(index + 1) * entrySize)
            if entry.prefix(16) == apfsType {
                let first = Self.le64(entry, 32), last = Self.le64(entry, 40)
                try #require(first >= firstUsable && first <= last && last <= lastUsable)
                try #require(last < UInt64(size / 512))
                try #require(apfsRange == nil)
                apfsRange = (first, last)
            }
        }
        let range = try #require(apfsRange)
        try stream.seek(toOffset: range.0 * 512)
        let superblock = try #require(try stream.read(upToCount: 4_096))
        try #require(superblock.count == 4_096 && superblock.subdata(in: 32..<36) == Data("NXSB".utf8))
        let blockSize = UInt64(Self.le32(superblock, 36)), blockCount = Self.le64(superblock, 40)
        try #require(blockSize == 4_096 && blockCount > 0 && blockCount <= (range.1 - range.0 + 1) * 512 / blockSize)
        try stream.seek(toOffset: UInt64(size - 512))
        let finalSector = try #require(try stream.read(upToCount: 512))
        try #require(finalSector.count == 512 && finalSector.prefix(8) == Data("EFI PART".utf8))
        try #require(finalSector.prefix(4) != Data("koly".utf8))
        return image
    }

    func evidence(from inspection: InspectedImage) -> EvidenceRecord {
        EvidenceRecord(sourcePath: inspection.sourceURL.path, byteCount: inspection.byteCount,
            sha256: inspection.sha256, container: inspection.container, filesystemHint: inspection.filesystemHint)
    }

    func productionAdapter() -> APFSMountedImageAdapter {
        APFSMountedImageAdapter(scratchRoot: adapterScratch) { event in
            if case .safetyFailure(let stage, let flags) = event {
                print("APFS safety rejection stage=\(stage) kernelFlags=\(flags.map(String.init) ?? "unavailable")")
            }
        }
    }

    func independentContainerHash(_ image: URL) throws -> String {
        let receipt = try run("/usr/bin/shasum", ["-a", "256", image.path])
        let output = try #require(String(data: receipt, encoding: .utf8))
        let digest = try #require(output.split(whereSeparator: \.isWhitespace).first.map(String.init))
        try #require(digest.count == 64 && digest.allSatisfy { $0.isHexDigit })
        return digest
    }

    /// This mount is an independent OS observation; the application adapter
    /// uses its own fresh private clone and mount rather than this mounted path.
    func verifyIndependentReadOnlyMount(image: URL, passphrase: Data? = nil, volumePassphrase: Data? = nil,
                                        rawLogicalDevice: Bool = false) throws -> UUID {
        // DiskImages can cache UDIF checksum xattrs despite a read-only mounted
        // device. Its separate private copy prevents that metadata change from
        // touching the source whose full identity the adapter must preserve.
        let originalIdentity = try FileAccess.identity(at: image)
        let originalSHA256 = try independentContainerHash(image)
        let privateImage = root.appendingPathComponent("oracle-copy-\(UUID().uuidString).dmg")
        try FileManager.default.copyItem(at: image, to: privateImage)
        knownImagePaths.insert(privateImage.path)
        try #require(try independentContainerHash(privateImage) == originalSHA256)
        let privateIdentity = try FileAccess.identity(at: privateImage)
        let mount = root.appendingPathComponent("oracle-mount-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var arguments = ["attach", privateImage.path, "-readonly", "-nobrowse", "-noautoopen", "-noautofsck", "-noverify", "-plist"]
        arguments.append(contentsOf: volumePassphrase == nil ? ["-mountpoint", mount.path] : ["-nomount"])
        if passphrase != nil { arguments.append("-stdinpass") }
        let receipt = try run("/usr/bin/hdiutil", arguments, passphrase: passphrase)
        let dictionary = try #require(try PropertyListSerialization.propertyList(from: receipt, format: nil) as? [String: Any])
        let entities = try #require(dictionary["system-entities"] as? [[String: Any]])
        let wholeDevice = try #require(entities.compactMap { $0["dev-entry"] as? String }.first { $0.range(of: "^/dev/disk[0-9]+$", options: .regularExpression) != nil })
        attachedDevices.insert(wholeDevice)
        do {
            if let volumePassphrase {
                let volumeEntity = try #require(entities.first { ($0["volume-kind"] as? String) == "apfs" })
                let volumeDevice = try #require(volumeEntity["dev-entry"] as? String)
                let lockedInfoBytes = try run("/usr/sbin/diskutil", ["info", "-plist", volumeDevice])
                let lockedInfo = try #require(try PropertyListSerialization.propertyList(from: lockedInfoBytes, format: nil) as? [String: Any])
                try #require(lockedInfo["Encryption"] as? Bool == true && lockedInfo["Locked"] as? Bool == true)
                let unlockBytes = try run("/usr/sbin/diskutil", ["apfs", "unlockVolume", volumeDevice, "-user", "disk", "-stdinpassphrase", "-nomount", "-plist"],
                    passphrase: volumePassphrase, credentialTerminator: 10)
                let unlock = try #require(try PropertyListSerialization.propertyList(from: unlockBytes, format: nil) as? [String: Any])
                try #require(unlock["Success"] as? Bool == true && unlock["DiskManagementErrorCode"] as? Int == 0)
                _ = try run("/usr/sbin/diskutil", ["mount", "readOnly", "nobrowse", "-mountOptions", "noexec,nosuid,nodev", "-mountPoint", mount.path, volumeDevice])
            } else {
                let mounted = try #require(entities.first { sameMountedDirectory($0["mount-point"] as? String, mount) })
                try #require(mounted["dev-entry"] as? String != nil)
            }
            var status = statfs()
            let mountedDescriptor = Darwin.open(mount.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            try #require(mountedDescriptor >= 0)
            let filesystemStatus = Darwin.fstatfs(mountedDescriptor, &status)
            Darwin.close(mountedDescriptor)
            try #require(filesystemStatus == 0)
            try #require((status.f_flags & UInt32(MNT_RDONLY)) != 0)
            let type = withUnsafeBytes(of: status.f_fstypename) { bytes in
                String(cString: bytes.bindMemory(to: CChar.self).baseAddress!)
            }
            try #require(type == "apfs")
            try #require(try FileManager.default.destinationOfSymbolicLink(atPath: mount.appendingPathComponent("escape-link").path)
                == root.appendingPathComponent("outside-marker.txt").path)
            try #require(FileManager.default.fileExists(atPath: root.appendingPathComponent("outside-marker.txt").path))
            let volumeInfoBytes = try run("/usr/sbin/diskutil", ["info", "-plist", mount.path])
            let volumeInfo = try #require(try PropertyListSerialization.propertyList(from: volumeInfoBytes, format: nil) as? [String: Any])
            let volumeUUID = try #require((volumeInfo["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)))
            try #require(volumeInfo["FilesystemType"] as? String == "apfs")
            try #require(volumeInfo["WritableVolume"] as? Bool == false)
            if rawLogicalDevice {
                let deviceInfoBytes = try run("/usr/sbin/diskutil", ["info", "-plist", wholeDevice])
                let deviceInfo = try #require(try PropertyListSerialization.propertyList(from: deviceInfoBytes, format: nil) as? [String: Any])
                try #require((deviceInfo["TotalSize"] as? NSNumber)?.int64Value == originalIdentity.size)
                try #require((deviceInfo["DeviceBlockSize"] as? NSNumber)?.intValue == 512)
            }
            for (path, bytes) in expected {
                let actual = try Data(contentsOf: mount.appendingPathComponent(path))
                try #require(actual == bytes)
                try #require(Self.hash(actual) == Self.hash(bytes))
            }
            independentEntryKinds = try collectIndependentEntryKinds(at: mount)
            let writePath = mount.appendingPathComponent("must-not-exist-write-probe").path
            errno = 0
            let writeDescriptor = Darwin.open(writePath, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
            let writeError = errno
            if writeDescriptor >= 0 { Darwin.close(writeDescriptor) }
            try #require(writeDescriptor == -1 && writeError == EROFS)
            try #require(!FileManager.default.fileExists(atPath: writePath))
            try detachOwnedDevice(wholeDevice)
            try #require(try independentContainerHash(privateImage) == originalSHA256)
            try #require(try FileAccess.identity(at: privateImage) == privateIdentity)
            try #require(try independentContainerHash(image) == originalSHA256)
            try #require(try FileAccess.identity(at: image) == originalIdentity)
            return volumeUUID
        } catch {
            try? detachOwnedDevice(wholeDevice)
            throw error
        }
    }

    func requireEmptyAdapterScratch() throws {
        try #require(try FileManager.default.contentsOfDirectory(atPath: adapterScratch.path).isEmpty)
    }

    func verifyCompleteEnumeration(_ inspection: APFSInspectionResult) throws {
        let expectedKinds = try #require(independentEntryKinds)
        try #require(inspection.entries.count == Set(inspection.entries.map(\.relativePath)).count)
        let actualKinds = Dictionary(uniqueKeysWithValues: inspection.entries.map { ($0.relativePath, $0.kind) })
        try #require(actualKinds == expectedKinds)
    }

    private func collectIndependentEntryKinds(at mountedRoot: URL) throws -> [String: APFSFileKind] {
        var kinds: [String: APFSFileKind] = [:]
        func walk(_ directory: URL, prefix: String) throws {
            let children = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            for child in children {
                let relative = prefix.isEmpty ? child.lastPathComponent : prefix + "/" + child.lastPathComponent
                var metadata = stat()
                try #require(Darwin.lstat(child.path, &metadata) == 0)
                let kind: APFSFileKind
                switch metadata.st_mode & S_IFMT {
                case S_IFREG: kind = .regular
                case S_IFDIR: kind = .directory
                case S_IFLNK: kind = .symbolicLink
                default: kind = .other
                }
                kinds[relative] = kind
                if kind == .directory { try walk(child, prefix: relative) }
            }
        }
        try walk(mountedRoot, prefix: "")
        return kinds
    }

    func cleanup() throws {
        try discoverOwnedAttachments()
        for device in attachedDevices.sorted() {
            try detachOwnedDevice(device)
        }
        try discoverOwnedAttachments()
        try #require(attachedDevices.isEmpty)
        // An adapter cleanup failure deliberately retains its backing image.
        // Do not remove or recurse into that image or its still-live mount.
        if FileManager.default.fileExists(atPath: adapterScratch.path) { try requireEmptyAdapterScratch() }
        if FileManager.default.fileExists(atPath: root.path) { try FileManager.default.removeItem(at: root) }
    }

    func bestEffortCleanup() { try? cleanup() }

    /// A failed attach can leave a device before its plist is returned. Discover
    /// only images whose exact paths this fixture created; never detach a host
    /// disk, a different test's image, or a device guessed from numeric IDs.
    private func discoverOwnedAttachments() throws {
        guard FileManager.default.fileExists(atPath: root.path) else { attachedDevices = []; return }
        let receipt = try run("/usr/bin/hdiutil", ["info", "-plist"])
        let info = try #require(try PropertyListSerialization.propertyList(from: receipt, format: nil) as? [String: Any])
        let images = try #require(info["images"] as? [[String: Any]])
        var currentOwnedDevices: Set<String> = []
        for image in images {
            guard let path = image["image-path"] as? String, isKnownImagePath(path) else { continue }
            let entities = try #require(image["system-entities"] as? [[String: Any]])
            var found = false
            for entity in entities {
                guard let device = entity["dev-entry"] as? String,
                      device.range(of: "^/dev/disk[0-9]+$", options: .regularExpression) != nil else { continue }
                currentOwnedDevices.insert(device)
                found = true
                break
            }
            try #require(found)
        }
        // Replace the cached set; retaining a detached/reused disk number could
        // otherwise cause a later cleanup to target a different image or disk.
        attachedDevices = currentOwnedDevices
    }

    private func detachOwnedDevice(_ device: String) throws {
        try discoverOwnedAttachments()
        guard attachedDevices.contains(device) else { return }
        _ = try run("/usr/bin/hdiutil", ["detach", device])
        try discoverOwnedAttachments()
        try #require(!attachedDevices.contains(device))
    }

    static func hash(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// Foundation/tool spelling of Apple's /var alias may differ. Accept only
    /// canonical-equivalent paths that open the same actual directory and
    /// filesystem through independent held descriptors, never a string alone.
    private func sameMountedDirectory(_ reportedPath: String?, _ requested: URL) -> Bool {
        guard let reportedPath, reportedPath.hasPrefix("/"), !reportedPath.utf8.contains(0) else { return false }
        let reported = URL(fileURLWithPath: reportedPath).standardizedFileURL.resolvingSymlinksInPath()
        let expected = requested.standardizedFileURL.resolvingSymlinksInPath()
        guard reported == expected else { return false }
        let left = Darwin.open(reportedPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard left >= 0 else { return false }; defer { Darwin.close(left) }
        let right = Darwin.open(requested.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard right >= 0 else { return false }; defer { Darwin.close(right) }
        var lhs = stat(), rhs = stat(), leftFS = statfs(), rightFS = statfs()
        guard Darwin.fstat(left, &lhs) == 0, Darwin.fstat(right, &rhs) == 0,
              lhs.st_dev == rhs.st_dev, lhs.st_ino == rhs.st_ino,
              Darwin.fstatfs(left, &leftFS) == 0, Darwin.fstatfs(right, &rightFS) == 0 else { return false }
        return withUnsafeBytes(of: leftFS.f_fsid) { Array($0) } == withUnsafeBytes(of: rightFS.f_fsid) { Array($0) }
    }

    private func isKnownImagePath(_ reported: String) -> Bool {
        guard reported.hasPrefix("/"), !reported.utf8.contains(0) else { return false }
        let requested = URL(fileURLWithPath: reported).standardizedFileURL.resolvingSymlinksInPath()
        return knownImagePaths.contains { path in
            let known = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
            guard known == requested, let lhs = try? FileAccess.identity(at: URL(fileURLWithPath: reported)),
                  let rhs = try? FileAccess.identity(at: URL(fileURLWithPath: path)) else { return false }
            return lhs == rhs
        }
    }

    func verifyRetainedBackingAndLateAttach(expectedSHA256: String) throws {
        defer {
            try? discoverOwnedAttachments()
            for device in attachedDevices.sorted() { try? detachOwnedDevice(device) }
        }
        let owned = try FileManager.default.contentsOfDirectory(at: adapterScratch, includingPropertiesForKeys: nil)
        try #require(owned.count == 1 && owned[0].lastPathComponent.hasPrefix(".native-apfs-"))
        let image = owned[0].appendingPathComponent("image.dmg")
        let marker = try JSONSerialization.jsonObject(with: Data(contentsOf: owned[0].appendingPathComponent("quarantine.json"))) as? [String: Any]
        try #require(marker?["state"] as? String == "cleanupUncertain" && marker?["backingImageRetained"] as? Bool == true)
        knownImagePaths.insert(image.path)
        try #require(try independentContainerHash(image) == expectedSHA256)
        let identity = try FileAccess.identity(at: image)
        // If the real daemon already attached during cancellation, clean only
        // that currently confirmed owned device before simulating another late
        // attach. The producer backing remains quarantined throughout.
        try discoverOwnedAttachments()
        for device in attachedDevices.sorted() { try detachOwnedDevice(device) }
        let bytes = try run("/usr/bin/hdiutil", ["attach", image.path, "-readonly", "-nomount", "-noverify", "-noautofsck", "-nobrowse", "-noautoopen", "-plist"])
        let plist = try #require(try PropertyListSerialization.propertyList(from: bytes, format: nil) as? [String: Any])
        let entities = try #require(plist["system-entities"] as? [[String: Any]])
        let whole = try #require(entities.compactMap { $0["dev-entry"] as? String }.first { $0.range(of: "^/dev/disk[0-9]+$", options: .regularExpression) != nil })
        try #require(try FileAccess.identity(at: image) == identity)
        try #require(try independentContainerHash(image) == expectedSHA256)
        try detachOwnedDevice(whole)
        try discoverOwnedAttachments(); try #require(attachedDevices.isEmpty)
        try #require(try FileAccess.identity(at: image) == identity)
        try #require(try independentContainerHash(image) == expectedSHA256)
        // Do not recursively remove this private backing or its mount directory.
        // Original killed-client daemon completion was never claimed proven.
    }

    private static func le32(_ bytes: Data, _ offset: Int) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << ($1 * 8) }
    }
    private static func le64(_ bytes: Data, _ offset: Int) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << ($1 * 8) }
    }
    private static func crc32(_ bytes: Data) -> UInt32 {
        var crc = UInt32.max
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb8_8320 : crc >> 1 }
        }
        return ~crc
    }

    /// Command arguments are credential-free. hdiutil consumes a NUL-terminated
    /// passphrase on a private pipe; output goes to bounded owned temporary
    /// files, so the process cannot deadlock on unread stdout/stderr pipes.
    private func run(_ executable: String, _ arguments: [String], passphrase: Data? = nil, credentialTerminator: UInt8 = 0) throws -> Data {
        let outputURL = root.appendingPathComponent("stdout-\(UUID().uuidString)")
        let errorURL = root.appendingPathComponent("stderr-\(UUID().uuidString)")
        try #require(FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600]))
        try #require(FileManager.default.createFile(atPath: errorURL.path, contents: nil, attributes: [.posixPermissions: 0o600]))
        let output = try FileHandle(forWritingTo: outputURL)
        let errors = try FileHandle(forWritingTo: errorURL)
        defer {
            try? output.close(); try? errors.close()
            try? FileManager.default.removeItem(at: outputURL)
            try? FileManager.default.removeItem(at: errorURL)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardOutput = output
        process.standardError = errors
        let input = Pipe()
        process.standardInput = input
        try process.run()
        defer {
            if process.isRunning {
                process.terminate()
                let cleanupClock = ContinuousClock()
                let cleanupDeadline = cleanupClock.now + .seconds(2)
                while process.isRunning && cleanupClock.now < cleanupDeadline { usleep(20_000) }
                if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
                process.waitUntilExit()
            }
        }
        if var bytes = passphrase {
            bytes.append(credentialTerminator)
            try input.fileHandleForWriting.write(contentsOf: bytes)
            bytes.resetBytes(in: 0..<bytes.count)
        }
        try input.fileHandleForWriting.close()
        let clock = ContinuousClock()
        let deadline = clock.now + .seconds(90)
        while process.isRunning && clock.now < deadline { usleep(20_000) }
        if process.isRunning {
            process.terminate()
            let killDeadline = clock.now + .seconds(2)
            while process.isRunning && clock.now < killDeadline { usleep(20_000) }
            if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw ForensicsError.io("Synthetic APFS fixture command exceeded its deadline.")
        }
        process.waitUntilExit()
        try output.synchronize(); try errors.synchronize()
        let attributes = try FileManager.default.attributesOfItem(atPath: outputURL.path)
        try #require(((attributes[.size] as? NSNumber)?.int64Value ?? Int64.max) <= 1_048_576)
        let bytes = try Data(contentsOf: outputURL)
        guard process.terminationStatus == 0 else {
            // Error output intentionally is not returned or logged: a failed
            // credential operation must not make secrets part of test output.
            throw ForensicsError.io("Synthetic APFS fixture command failed with status \(process.terminationStatus).")
        }
        return bytes
    }
}
