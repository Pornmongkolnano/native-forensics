import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// Uses an externally produced, frozen UDIF whose native OS historical-byte
/// oracle predates this test. No fixture builder or source-image mount runs here.
@Suite("Independent APFS snapshot content", .serialized)
struct APFSSnapshotFixtureOracle {
    private static let enabled = ProcessInfo.processInfo.environment["NF_APFS_SNAPSHOT_INTEGRATION"] == "1"

    @Test("Current and exact snapshot contexts survive verified reads, case reopen and historical export",
          .enabled(if: APFSSnapshotFixtureOracle.enabled))
    func immutableHistoricalFixture() async throws {
        let fixture = try APFSSnapshotOracleContext()
        defer { fixture.finishBestEffort() }
        let before = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        try #require(before.sha256 == APFSSnapshotOracleContext.imageSHA256 && before.byteCount == 392_537)
        #expect(before.sourceIdentity == fixture.sourceIdentity)
        let created = try CaseStore.create(name: "Owned snapshot integration", in: fixture.root)
        let forensicCase = try CaseStore.adding(image: before, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let adapter = APFSMountedImageAdapter(scratchRoot: fixture.scratch,
            snapshotMountDiagnostic: { fixture.observeSnapshotCommand($0) }) { event in
            fixture.observeLifecycle(event)
            if case .mounted = event { fixture.observeMounted() }
        }
        let earlier = APFSSnapshotOracleContext.earlier, later = APFSSnapshotOracleContext.later
        try #require(earlier.count == 16_384 && later.count == 16_384 && earlier != later)
        try #require(APFSSnapshotOracleContext.hash(earlier) == APFSSnapshotOracleContext.earlierSHA256)
        try #require(APFSSnapshotOracleContext.hash(later) == APFSSnapshotOracleContext.laterSHA256)

        fixture.expectSnapshot(false)
        fixture.beginOperation("current-inspect")
        let current = try await adapter.inspect(evidence: evidence, options: Self.options())
        try fixture.requireAudits(1); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()
        #expect(current.options.selectedSnapshotUUID == nil && current.selectedSnapshot == nil)
        #expect(current.volumeUUID == APFSSnapshotOracleContext.volumeUUID)
        #expect(current.snapshotInventoryAvailable && current.snapshots == [APFSSnapshotOracleContext.snapshot])
        #expect(current.containerEncryption == .none && current.volumeEncryption == .none)
        #expect(current.coverage == .completeAllocatedView)
        let currentEntry = try #require(current.entries.first { $0.relativePath == "history.bin" })
        #expect(currentEntry.kind == .regular && currentEntry.byteCount == Int64(later.count))
        #expect(currentEntry.sha256 == APFSSnapshotOracleContext.laterSHA256)
        fixture.expectSnapshot(false)
        fixture.beginOperation("current-read")
        let currentRead = try await adapter.readVerifiedFile(evidence: evidence, inspection: current, entry: currentEntry)
        #expect(currentRead.data == later && currentRead.sha256 == APFSSnapshotOracleContext.laterSHA256)
        #expect(currentRead.selectedSnapshot == nil && currentRead.volumeUUID == current.volumeUUID)
        #expect(currentRead.containerSHA256 == APFSSnapshotOracleContext.imageSHA256)
        try fixture.requireAudits(2); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()
        fixture.beginOperation("current-cache-reopen")
        let currentCache = try APFSResultStore.save(current, in: forensicCase)
        let currentCase = try CaseStore.open(at: forensicCase.bundleURL)
        let reopenedCurrent = try #require(try APFSResultStore.loadLatest(in: currentCase, evidenceID: evidence.id))
        #expect(reopenedCurrent == current && reopenedCurrent.selectedSnapshot == nil)
        let originalCurrentBytes = try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent(currentCache.relativePath))
        #expect(APFSSnapshotOracleContext.hash(originalCurrentBytes) == currentCache.resultSHA256)

        fixture.expectSnapshot(true)
        fixture.beginOperation("historical-inspect")
        let historical = try await adapter.inspect(evidence: evidence,
            options: Self.options(snapshot: APFSSnapshotOracleContext.snapshot.uuid))
        try fixture.requireAudits(3); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()
        #expect(historical.options.selectedSnapshotUUID == APFSSnapshotOracleContext.snapshot.uuid)
        #expect(historical.selectedSnapshot == APFSSnapshotOracleContext.snapshot)
        #expect(historical.volumeUUID == current.volumeUUID && historical.coverage == .completeAllocatedView)
        #expect(historical.containerSHA256 == before.sha256 && historical.containerByteCount == before.byteCount)
        #expect(historical.snapshotInventoryAvailable && historical.snapshots == [APFSSnapshotOracleContext.snapshot])
        let historicalEntry = try #require(historical.entries.first { $0.relativePath == "history.bin" })
        #expect(historicalEntry.kind == .regular && historicalEntry.byteCount == Int64(earlier.count))
        #expect(historicalEntry.sha256 == APFSSnapshotOracleContext.earlierSHA256 && historicalEntry.sha256 != currentEntry.sha256)
        fixture.expectSnapshot(true)
        fixture.beginOperation("historical-read")
        let historicalRead = try await adapter.readVerifiedFile(evidence: evidence, inspection: historical, entry: historicalEntry)
        #expect(historicalRead.data == earlier && historicalRead.data != currentRead.data)
        #expect(historicalRead.sha256 == APFSSnapshotOracleContext.earlierSHA256)
        #expect(historicalRead.selectedSnapshot == APFSSnapshotOracleContext.snapshot)
        #expect(historicalRead.volumeUUID == APFSSnapshotOracleContext.volumeUUID && historicalRead.relativePath == "history.bin")
        #expect(historicalRead.containerSHA256 == APFSSnapshotOracleContext.imageSHA256)
        try fixture.requireAudits(4); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()

        // Unknown selection must clean its own newly attached private image.
        let unknown = UUID(uuidString: "00000000-0000-4000-8000-000000000000")!
        fixture.beginOperation("unknown-snapshot-reject")
        do {
            _ = try await adapter.inspect(evidence: evidence, options: Self.options(snapshot: unknown))
            Issue.record("Unknown APFS snapshot UUID was accepted.")
        } catch let error as APFSReadError {
            if case .unsupported = error {} else { throw error }
        }
        try fixture.requireAudits(4); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()

        let forgedTuple = APFSSnapshotInventoryEntry(uuid: APFSSnapshotOracleContext.snapshot.uuid,
            name: "nf-forged", transactionID: 2)
        let forgedSelected = Self.replacingContext(historical, selected: forgedTuple, snapshots: historical.snapshots)
        fixture.beginOperation("forged-selected-reject")
        #expect(throws: APFSReadError.invalidResult) { try APFSMountedImageAdapter.validate(forgedSelected, evidence: evidence) }
        await #expect(throws: APFSReadError.invalidResult) {
            _ = try await adapter.readVerifiedFile(evidence: evidence, inspection: forgedSelected, entry: historicalEntry)
        }
        try fixture.requireAudits(4); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()
        // A self-consistent forged inventory can pass static shape validation;
        // a fresh actual mount must still reject its invented observed tuple.
        let forgedInventory = Self.replacingContext(historical, selected: forgedTuple, snapshots: [forgedTuple])
        try APFSMountedImageAdapter.validate(forgedInventory, evidence: evidence)
        fixture.expectSnapshot(true)
        fixture.beginOperation("forged-inventory-read")
        await #expect(throws: APFSReadError.invalidResult) {
            _ = try await adapter.readVerifiedFile(evidence: evidence, inspection: forgedInventory, entry: historicalEntry)
        }
        try fixture.requireAudits(5); try fixture.requireEmptyScratch(); try fixture.requireSourcePreserved()

        fixture.beginOperation("historical-cache-reopen")
        let historicalCache = try APFSResultStore.save(historical, in: currentCase)
        let reopenedCase = try CaseStore.open(at: forensicCase.bundleURL)
        let reopenedHistorical = try #require(try APFSResultStore.loadLatest(in: reopenedCase, evidenceID: evidence.id))
        #expect(reopenedHistorical == historical && reopenedHistorical.selectedSnapshot == APFSSnapshotOracleContext.snapshot)
        #expect(historicalCache.generationID != currentCache.generationID)
        #expect(try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent(currentCache.relativePath)) == originalCurrentBytes)
        let persistedCurrent = try JSONDecoder().decode(APFSInspectionResult.self, from: originalCurrentBytes)
        #expect(persistedCurrent == current && persistedCurrent.selectedSnapshot == nil)
        let destination = fixture.root.appendingPathComponent("verified-historical.bin")
        // The public export service owns its default private scratch; its mount
        // has no injectable observer. Bytes, receipt context and source fences
        // are checked here, and any incomplete export leaves this test root.
        fixture.retainRootOnFailure()
        fixture.beginOperation("historical-export")
        let export = try await APFSExportService.export(evidence: evidence, inspection: reopenedHistorical,
            entry: historicalEntry, in: reopenedCase, to: destination)
        #expect(try Data(contentsOf: destination) == earlier)
        #expect(export.sha256 == APFSSnapshotOracleContext.earlierSHA256 && export.byteCount == 16_384)
        #expect(export.selectedSnapshot == APFSSnapshotOracleContext.snapshot && export.volumeUUID == historical.volumeUUID)
        #expect(export.resultSHA256 == historicalCache.resultSHA256 && export.containerSHA256 == before.sha256)
        #expect(export.caseID == reopenedCase.manifest.id && export.evidenceID == evidence.id)
        let encodedExport = try JSONEncoder().encode(export)
        #expect(try JSONDecoder().decode(APFSExportReceipt.self, from: encodedExport) == export)
        #expect(!String(decoding: encodedExport, as: UTF8.self).contains(fixture.root.path))
        try fixture.requireSourcePreserved(); try fixture.requireEmptyScratch(); try fixture.requireAudits(5)
        fixture.beginOperation("final-source-fence")
        let after = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        #expect(after.sha256 == before.sha256 && after.byteCount == before.byteCount && after.sourceIdentity == before.sourceIdentity)
        fixture.releaseFailureRetention()
        try fixture.finish()
    }

    private static func options(snapshot: UUID? = nil) -> APFSReadOptions {
        .init(maximumEntries: 128, maximumFileBytes: 32_768, maximumContainerBytes: 1_048_576,
              commandTimeoutSeconds: 30, maximumDepth: 8, maximumMetadataBytes: 65_536,
              maximumAggregateFileBytes: 65_536, jobTimeoutSeconds: 180,
              selectedVolumeUUID: APFSSnapshotOracleContext.volumeUUID, selectedSnapshotUUID: snapshot)
    }
    private static func replacingContext(_ result: APFSInspectionResult, selected: APFSSnapshotInventoryEntry,
                                          snapshots: [APFSSnapshotInventoryEntry]) -> APFSInspectionResult {
        .init(schemaVersion: result.schemaVersion, evidenceID: result.evidenceID, containerSHA256: result.containerSHA256,
              containerByteCount: result.containerByteCount, hashScope: result.hashScope, driver: result.driver,
              driverVersion: result.driverVersion, options: result.options, volumeUUID: result.volumeUUID,
              containerEncryption: result.containerEncryption, volumeEncryption: result.volumeEncryption,
              entries: result.entries, snapshots: snapshots, snapshotInventoryAvailable: result.snapshotInventoryAvailable,
              coverage: result.coverage, warnings: result.warnings, selectedSnapshot: selected)
    }
}

private final class APFSSnapshotOracleContext: @unchecked Sendable {
    static let imageSHA256 = "11ddb1a8aa08625a21ba923efdf3cc8c1c11928db0d936d3d009a14651c502b6"
    static let earlierSHA256 = "712f13ec2ad0f05759975b7b798ec8cdd1166b7f3d51d28ff279c46e487277fd"
    static let laterSHA256 = "f4f68d721a9e07f438bb76269b78769416256ae43cd250fd0dad9d30e8e9c2df"
    static let volumeUUID = UUID(uuidString: "3322234B-EE3F-467B-9D1E-D1E430DF8F5B")!
    static let containerUUID = UUID(uuidString: "98CF6C75-0405-4B89-B29C-14817D758C7F")!
    static let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(uuidString: "3222234B-EE3F-467B-9D1E-D1E430DF8F5B")!,
                                                      name: "nf-before", transactionID: 1)
    static let earlier = payload("NATIVE FORENSICS BEFORE SNAPSHOT\n", "earlier-known-block;0123456789abcdef\n")
    static let later = payload("NATIVE FORENSICS AFTER SNAPSHOT\n", "later-known-block!!;fedcba9876543210\n")
    let image: URL
    let root: URL
    let scratch: URL
    let sourceIdentity: SourceIdentity
    private let sourceParent: Int32
    private let source: Int32
    private let sourceState: [Int64]
    private let parentIdentity: (dev_t, ino_t)
    private let rootIdentity: (dev_t, ino_t)
    private let scratchIdentity: (dev_t, ino_t)
    private let lock = NSLock()
    private var expectedSnapshot = false
    private var audits = 0
    private var failures: [String] = []
    private var retainRoot = false
    private var finished = false
    private var operation = "source-admission"
    private var lifecycle: [String] = []
    private var lifecycleCounts: [String: Int] = [:]
    private var omittedLifecycleEvents = 0

    init() throws {
        let path = try #require(ProcessInfo.processInfo.environment["NF_APFS_SNAPSHOT_FIXTURE_PATH"])
        try #require(path.hasPrefix("/") && !path.utf8.contains(0) && !path.split(separator: "/").contains(".."))
        image = URL(fileURLWithPath: path).standardizedFileURL
        sourceParent = try Self.openDirectory(image.deletingLastPathComponent())
        var parentStatus = stat()
        guard Darwin.fstat(sourceParent, &parentStatus) == 0 else { Darwin.close(sourceParent); throw ForensicsError.io("Snapshot source parent unavailable.") }
        parentIdentity = (parentStatus.st_dev, parentStatus.st_ino)
        source = Darwin.openat(sourceParent, image.lastPathComponent, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0 else { Darwin.close(sourceParent); throw ForensicsError.io("Snapshot source unavailable.") }
        var metadata = stat()
        guard Darwin.fstat(source, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(), metadata.st_nlink == 1, metadata.st_size == 392_537,
              metadata.st_mode & 0o7777 == 0o400 else {
            Darwin.close(source); Darwin.close(sourceParent); throw ForensicsError.invalidSource("The immutable snapshot fixture does not match its scope.")
        }
        sourceIdentity = SourceIdentity(metadata); sourceState = Self.fullState(metadata)
        do {
            try #require(try Self.descriptorHash(source, size: 392_537) == Self.imageSHA256)
            var template = Array("/private/tmp/NF-APFS-snapshot-XXXXXX".utf8CString)
            let created = template.withUnsafeMutableBufferPointer { buffer -> String? in
                guard let value = mkdtemp(buffer.baseAddress!) else { return nil }
                return String(cString: value)
            }
            root = URL(fileURLWithPath: try #require(created), isDirectory: true)
            scratch = root.appendingPathComponent("adapter-scratch", isDirectory: true)
            try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(at: root.appendingPathComponent("commands"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            var rootStatus = stat()
            try #require(Darwin.lstat(root.path, &rootStatus) == 0 && rootStatus.st_uid == geteuid() && rootStatus.st_mode & 0o7777 == 0o700)
            rootIdentity = (rootStatus.st_dev, rootStatus.st_ino)
            var scratchStatus = stat()
            try #require(Darwin.lstat(scratch.path, &scratchStatus) == 0 && scratchStatus.st_uid == geteuid() &&
                         scratchStatus.st_mode & S_IFMT == S_IFDIR && scratchStatus.st_mode & 0o7777 == 0o700)
            scratchIdentity = (scratchStatus.st_dev, scratchStatus.st_ino)
        } catch { Darwin.close(source); Darwin.close(sourceParent); throw error }
    }
    deinit { Darwin.close(source); Darwin.close(sourceParent) }

    func beginOperation(_ label: String) {
        precondition(Self.operationLabels.contains(label))
        lock.lock()
        operation = label; lifecycle.removeAll(keepingCapacity: true)
        lifecycleCounts.removeAll(keepingCapacity: true); omittedLifecycleEvents = 0
        lock.unlock()
    }
    func observeLifecycle(_ event: APFSReadLifecycleStage) {
        let label: String
        switch event {
        case .attachClientStarted: label = "attach-client-started"
        case .attachCommandTerminal: label = "attach-command-terminal"
        case .baseMountClientStarted: label = "base-mount-client-started"
        case .baseMountCommandTerminal: label = "base-mount-command-terminal"
        case .snapshotMountClientStarted: label = "snapshot-mount-client-started"
        case .snapshotMountCommandTerminal: label = "snapshot-mount-command-terminal"
        case .mounted: label = "mounted-audit"
        case .detached: label = "detached"
        case .safetyFailure: label = "safety-failure"
        }
        lock.lock()
        lifecycleCounts[label] = min(1_024, (lifecycleCounts[label] ?? 0) + 1)
        if lifecycle.count < 64 { lifecycle.append(label) }
        else { omittedLifecycleEvents = min(1_024, omittedLifecycleEvents + 1) }
        lock.unlock()
    }
    func observeSnapshotCommand(_ diagnostic: APFSSnapshotMountDiagnostic) {
        do {
            let arguments = diagnostic.arguments
            guard diagnostic.standardError.count <= 128 * 1_024, arguments.count == 6,
                  arguments[0] == "-o", arguments[1] == "rdonly,nobrowse,noexec,nosuid,nodev,nofollow",
                  arguments[2] == "-s", arguments[3] == Self.snapshot.name,
                  arguments.allSatisfy({ $0.utf8.count <= 2_048 && !$0.utf8.contains(0) }) else {
                throw ForensicsError.io("Snapshot diagnostic was outside the immutable plaintext fixture scope.")
            }
            let base = URL(fileURLWithPath: arguments[4]).standardizedFileURL
            let target = URL(fileURLWithPath: arguments[5]).standardizedFileURL
            let privateJob = base.deletingLastPathComponent()
            let prefix = ".native-apfs-", name = privateJob.lastPathComponent
            guard base.lastPathComponent == "view", target.lastPathComponent == "snapshot-view",
                  target.deletingLastPathComponent().path == privateJob.path,
                  privateJob.deletingLastPathComponent().path == scratch.standardizedFileURL.path,
                  name.hasPrefix(prefix), UUID(uuidString: String(name.dropFirst(prefix.count))) != nil else {
                throw ForensicsError.io("Snapshot diagnostic did not refer to this fixture's private mount targets.")
            }
            try requireSourcePreserved()
            let directory = try Self.openDirectory(root)
            defer { Darwin.close(directory) }
            var held = stat()
            guard Darwin.fstat(directory, &held) == 0, held.st_dev == rootIdentity.0,
                  held.st_ino == rootIdentity.1, held.st_uid == geteuid(), held.st_mode & 0o7777 == 0o700 else {
                throw ForensicsError.io("The owned snapshot diagnostic anchor changed.")
            }
            lock.lock(); let label = operation; lock.unlock()
            let stem = "snapshot-command-" + UUID().uuidString
            let record = SnapshotCommandDiagnosticRecord(schemaVersion: 1, operation: label, arguments: arguments,
                naturalRawWaitStatus: diagnostic.naturalRawWaitStatus, standardErrorByteCount: diagnostic.standardError.count,
                standardErrorSHA256: Self.hash(diagnostic.standardError), standardErrorRelativePath: stem + ".stderr")
            let metadata = try JSONEncoder().encode(record)
            func writeExclusive(_ leaf: String, bytes: Data, limit: Int) throws {
                guard bytes.count <= limit else { throw ForensicsError.io("Snapshot diagnostic bound exceeded.") }
                let fd = Darwin.openat(directory, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                guard fd >= 0 else { throw ForensicsError.io("Cannot create an owned snapshot command diagnostic.") }
                defer { Darwin.close(fd) }
                try bytes.withUnsafeBytes { buffer in
                    var offset = 0
                    while offset < buffer.count {
                        let amount = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                        if amount < 0 && errno == EINTR { continue }
                        guard amount > 0 else { throw ForensicsError.io("Cannot write snapshot command diagnostic.") }
                        offset += amount
                    }
                }
                guard Darwin.fsync(fd) == 0 else { throw ForensicsError.io("Cannot synchronize snapshot command diagnostic.") }
            }
            try writeExclusive(stem + ".stderr", bytes: diagnostic.standardError, limit: 128 * 1_024)
            try writeExclusive(stem + ".json", bytes: metadata, limit: 8_192)
            guard Darwin.fsync(directory) == 0 else { throw ForensicsError.io("Cannot synchronize snapshot command diagnostic parent.") }
            // The fixture URL path is normalized by Foundation back to /tmp.
            // The actual nofollow command must instead retain raw /private/tmp
            // strings, bound again to the existing source/target descriptors.
            guard arguments[4].hasPrefix("/private/tmp/"), arguments[5].hasPrefix("/private/tmp/") else {
                throw ForensicsError.io("The snapshot command reintroduced a symbolic temporary-directory alias.")
            }
            let baseFD = Darwin.open(arguments[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard baseFD >= 0 else { throw ForensicsError.io("Cannot bind the snapshot command's canonical base descriptor.") }
            defer { Darwin.close(baseFD) }
            let targetFD = Darwin.open(arguments[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard targetFD >= 0 else { throw ForensicsError.io("Cannot bind the snapshot command's canonical target descriptor.") }
            defer { Darwin.close(targetFD) }
            guard try APFSCanonicalDirectoryPath.path(for: baseFD) == arguments[4],
                  try APFSCanonicalDirectoryPath.path(for: targetFD) == arguments[5],
                  try APFSSnapshotMountMetadata.filesystemUUID(of: baseFD) == Self.volumeUUID else {
                throw ForensicsError.io("The snapshot command's canonical directory arguments lost their FD binding.")
            }
            if diagnostic.naturalRawWaitStatus == 0 {
                guard try APFSSnapshotMountMetadata.filesystemUUID(of: targetFD) == Self.snapshot.uuid else {
                    throw ForensicsError.io("The snapshot command's target FD did not identify the exact historical snapshot.")
                }
            }
            try requireSourcePreserved()
        } catch {
            lock.lock(); retainRoot = true; lock.unlock()
            Issue.record("The bounded owned snapshot command diagnostic could not be published.")
        }
    }
    private struct SnapshotCommandDiagnosticRecord: Encodable {
        let schemaVersion: Int
        let operation: String
        let arguments: [String]
        let naturalRawWaitStatus: Int32
        let standardErrorByteCount: Int
        let standardErrorSHA256: String
        let standardErrorRelativePath: String
    }
    private static let operationLabels: Set<String> = ["source-admission", "current-inspect", "current-read",
        "current-cache-reopen", "historical-inspect", "historical-read", "unknown-snapshot-reject",
        "forged-selected-reject", "forged-inventory-read", "historical-cache-reopen", "historical-export", "final-source-fence"]
    func expectSnapshot(_ value: Bool) { lock.lock(); expectedSnapshot = value; lock.unlock() }
    func observeMounted() {
        lock.lock(); let selected = expectedSnapshot; lock.unlock()
        var stage = "observer-process"
        do {
            let output = try runAudit(snapshot: selected)
            stage = "observer-result"
            let result = try JSONDecoder().decode(AuditResult.self, from: output)
            guard Self.auditStages.contains(result.stage) else { throw ForensicsError.io("Unknown independent snapshot audit stage.") }
            stage = result.stage
            try #require(result.ok && result.mode == (selected ? "snapshot" : "current"))
            try #require(result.privateSHA256 == Self.imageSHA256 && result.baseUUID == Self.volumeUUID)
            try #require(result.currentSHA256 == Self.laterSHA256)
            try #require(result.snapshotUUID == (selected ? Self.snapshot.uuid : nil))
            try #require(result.transactionID == (selected ? Self.snapshot.transactionID : nil))
            try #require(result.historySHA256 == (selected ? Self.earlierSHA256 : nil))
            lock.lock(); audits += 1; lock.unlock()
        } catch {
            lock.lock(); if failures.count < 8 { failures.append(stage) }; retainRoot = true; lock.unlock()
            Issue.record("Independent APFS snapshot mounted audit failed at \(stage).")
        }
    }
    func requireAudits(_ expected: Int) throws {
        lock.lock(); let count = audits, failed = failures; lock.unlock()
        try #require(failed.isEmpty && count == expected,
            "Independent APFS mounted audits completed \(count) of \(expected); stages \(failed.joined(separator: ",")).")
    }
    func requireEmptyScratch() throws { try #require(try FileManager.default.contentsOfDirectory(atPath: scratch.path).isEmpty) }
    func requireSourcePreserved() throws {
        let reopened = try Self.openDirectory(image.deletingLastPathComponent())
        defer { Darwin.close(reopened) }
        var heldParent = stat(), currentParent = stat(), held = stat(), named = stat()
        try #require(Darwin.fstat(sourceParent, &heldParent) == 0 && Darwin.fstat(reopened, &currentParent) == 0)
        try #require(heldParent.st_dev == parentIdentity.0 && heldParent.st_ino == parentIdentity.1 &&
                     currentParent.st_dev == parentIdentity.0 && currentParent.st_ino == parentIdentity.1)
        try #require(Darwin.fstat(source, &held) == 0 && Darwin.fstatat(sourceParent, image.lastPathComponent, &named, AT_SYMLINK_NOFOLLOW) == 0)
        try #require(Self.fullState(held) == sourceState && Self.fullState(named) == sourceState && SourceIdentity(held) == sourceIdentity)
        try #require(try Self.descriptorHash(source, size: 392_537) == Self.imageSHA256)
        try #require(Darwin.fstat(source, &held) == 0 && Darwin.fstatat(sourceParent, image.lastPathComponent, &named, AT_SYMLINK_NOFOLLOW) == 0)
        try #require(Self.fullState(held) == sourceState && Self.fullState(named) == sourceState)
    }
    func retainRootOnFailure() { lock.lock(); retainRoot = true; lock.unlock() }
    func releaseFailureRetention() { lock.lock(); retainRoot = false; lock.unlock() }
    func finish() throws {
        if finished { return }
        try requireSourcePreserved(); try requireEmptyScratch()
        var original = stat()
        try #require(Darwin.lstat(root.path, &original) == 0 && original.st_dev == rootIdentity.0 && original.st_ino == rootIdentity.1 &&
                     original.st_uid == geteuid() && original.st_mode & 0o7777 == 0o700)
        func removeOwnedTree(_ directory: URL) throws {
            for child in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
                var value = stat()
                try #require(Darwin.lstat(child.path, &value) == 0 && value.st_uid == geteuid() && value.st_dev == rootIdentity.0)
                if value.st_mode & S_IFMT == S_IFDIR {
                    let descriptor = try #require({ () -> Int32? in
                        let opened = Darwin.open(child.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                        return opened >= 0 ? opened : nil
                    }())
                    defer { Darwin.close(descriptor) }
                    var held = stat()
                    try #require(Darwin.fstat(descriptor, &held) == 0 && held.st_dev == value.st_dev && held.st_ino == value.st_ino)
                    var filesystem = statfs()
                    try #require(Darwin.fstatfs(descriptor, &filesystem) == 0)
                    let mountedAt = withUnsafeBytes(of: filesystem.f_mntonname) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
                    try #require(mountedAt != child.path)
                    try removeOwnedTree(child); try #require(Darwin.rmdir(child.path) == 0)
                } else {
                    try #require(value.st_mode & S_IFMT == S_IFREG && value.st_nlink == 1)
                    try #require(Darwin.unlink(child.path) == 0)
                }
            }
        }
        try removeOwnedTree(root); try #require(Darwin.rmdir(root.path) == 0); finished = true
    }
    func finishBestEffort() {
        if finished { return }
        // A thrown production error has no stderr or command label by design.
        // Preserve this fixture's bounded stage/counters and existing raw audit
        // output instead of deleting evidence of the failed positive oracle.
        lock.lock()
        retainRoot = true
        let label = operation, sequence = lifecycle, counters = lifecycleCounts
        let omitted = omittedLifecycleEvents, completedAudits = audits, failedAudits = failures
        lock.unlock()
        print("APFS snapshot fixture retained operation=\(label); lifecycle=\(sequence.joined(separator: ",")); completedAudits=\(completedAudits)")
        do {
            try requireSourcePreserved()
            let directory = try Self.openDirectory(root)
            defer { Darwin.close(directory) }
            var held = stat()
            guard Darwin.fstat(directory, &held) == 0, held.st_dev == rootIdentity.0,
                  held.st_ino == rootIdentity.1, held.st_uid == geteuid(), held.st_mode & 0o7777 == 0o700 else {
                throw ForensicsError.io("The owned snapshot diagnostic anchor changed.")
            }
            let payload = FailureDiagnostic(schemaVersion: 1, operation: label, lifecycle: sequence,
                lifecycleCounts: counters, omittedLifecycleEvents: omitted, completedMountedAudits: completedAudits,
                failedAuditStages: failedAudits, originalSourcePreserved: true)
            let body = try JSONEncoder().encode(payload)
            guard body.count <= 8_192 else { throw ForensicsError.io("Snapshot diagnostic bound exceeded.") }
            let fd = Darwin.openat(directory, "failure-stage.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw ForensicsError.io("Cannot create an owned snapshot failure diagnostic.") }
            defer { Darwin.close(fd) }
            try body.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { throw ForensicsError.io("Cannot write snapshot failure diagnostic.") }
                    offset += written
                }
            }
            guard Darwin.fsync(fd) == 0, Darwin.fsync(directory) == 0 else {
                throw ForensicsError.io("Cannot synchronize snapshot failure diagnostic.")
            }
        } catch {
            print("APFS snapshot fixture retained its owned root; bounded failure diagnostic publication was unconfirmed.")
        }
    }

    private struct FailureDiagnostic: Encodable {
        let schemaVersion: Int
        let operation: String
        let lifecycle: [String]
        let lifecycleCounts: [String: Int]
        let omittedLifecycleEvents: Int
        let completedMountedAudits: Int
        let failedAuditStages: [String]
        let originalSourcePreserved: Bool
    }

    private struct AuditResult: Decodable {
        let ok: Bool
        let stage: String
        let mode: String?
        let privateSHA256: String?
        let baseUUID: UUID?
        let currentSHA256: String?
        let snapshotUUID: UUID?
        let transactionID: UInt64?
        let historySHA256: String?
    }
    private static let auditStages: Set<String> = ["arguments", "sdk-abi", "scratch", "scratch-path", "scratch-anchor",
        "scratch-owner", "scratch-permissions", "directory-component", "private-job", "image", "base",
        "inventory", "inventory-command-start", "inventory-command-job-deadline", "inventory-command-deadline",
        "inventory-command-output-limit", "inventory-command-exit", "inventory-command-plist",
        "inventory-envelope", "inventory-row-type", "inventory-candidate-path", "inventory-owned-missing",
        "inventory-owned-ambiguous", "image-alias", "devices", "physical", "container", "volume", "base-kernel", "base-uuid",
        "base-bytes", "snapshot-inventory", "snapshot-kernel", "snapshot-uuid", "snapshot-bytes", "current-only", "identities", "complete"]

    private func runAudit(snapshot: Bool) throws -> Data {
        let directory = root.appendingPathComponent("commands", isDirectory: true)
        let name = UUID().uuidString
        let outputURL = directory.appendingPathComponent(name + ".stdout"), errorURL = directory.appendingPathComponent(name + ".stderr")
        let parent = try Self.openDirectory(directory)
        defer { Darwin.close(parent) }
        let outputFD = Darwin.openat(parent, outputURL.lastPathComponent, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard outputFD >= 0 else { throw ForensicsError.io("Cannot create owned snapshot audit output.") }
        let errorFD = Darwin.openat(parent, errorURL.lastPathComponent, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard errorFD >= 0 else { Darwin.close(outputFD); throw ForensicsError.io("Cannot create owned snapshot audit diagnostics.") }
        let output = FileHandle(fileDescriptor: outputFD, closeOnDealloc: true), errors = FileHandle(fileDescriptor: errorFD, closeOnDealloc: true)
        defer { try? output.close(); try? errors.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-c", Self.pythonMountedAudit, scratch.path, snapshot ? "snapshot" : "current", root.path,
            String(rootIdentity.0), String(rootIdentity.1), String(scratchIdentity.0), String(scratchIdentity.1)]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C", "TMPDIR": directory.path]
        process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = errors
        try process.run()
        let clock = ContinuousClock(), deadline = ContinuousClock().now + .seconds(90)
        var withinBounds = true
        while process.isRunning && clock.now < deadline {
            var out = stat(), err = stat()
            if Darwin.fstat(outputFD, &out) != 0 || Darwin.fstat(errorFD, &err) != 0 || out.st_size > 65_536 || err.st_size > 8_192 {
                withinBounds = false; break
            }
            usleep(20_000)
        }
        let timedOut = process.isRunning
        if timedOut {
            process.terminate()
            let until = clock.now + .seconds(1)
            while process.isRunning && clock.now < until { usleep(20_000) }
            if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
        }
        process.waitUntilExit(); try output.synchronize(); try errors.synchronize()
        try #require(!timedOut && withinBounds && process.terminationStatus == 0)
        var final = stat()
        try #require(Darwin.fstat(outputFD, &final) == 0 && final.st_size <= 65_536)
        return try Data(contentsOf: outputURL)
    }
    private static func openDirectory(_ url: URL) throws -> Int32 {
        let components = url.path.split(separator: "/").map(String.init)
        guard url.isFileURL, url.path.hasPrefix("/"), !components.isEmpty,
              !components.contains("."), !components.contains("..") else { throw ForensicsError.invalidFileURL }
        var held = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard held >= 0 else { throw ForensicsError.io("Cannot open directory anchor.") }
        do {
            for component in components {
                let next = Darwin.openat(held, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw ForensicsError.io("Unsafe directory component.") }
                Darwin.close(held); held = next
            }
            return held
        } catch { Darwin.close(held); throw error }
    }
    private static func fullState(_ value: stat) -> [Int64] {
        [Int64(value.st_dev), Int64(value.st_ino), Int64(value.st_mode), value.st_size, Int64(value.st_uid),
         Int64(value.st_gid), Int64(value.st_nlink), Int64(value.st_flags), Int64(value.st_mtimespec.tv_sec),
         Int64(value.st_mtimespec.tv_nsec), Int64(value.st_ctimespec.tv_sec), Int64(value.st_ctimespec.tv_nsec)]
    }
    private static func descriptorHash(_ descriptor: Int32, size: Int64) throws -> String {
        var hasher = SHA256(), offset: Int64 = 0, buffer = [UInt8](repeating: 0, count: 65_536)
        while offset < size {
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress!, min($0.count, Int(size - offset)), off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw ForensicsError.io("Short immutable snapshot fixture read.") }
            hasher.update(data: Data(buffer.prefix(count))); offset += Int64(count)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    private static func payload(_ prefix: String, _ pattern: String) -> Data {
        Data((prefix + String(repeating: pattern, count: 16_384 / pattern.utf8.count + 2)).utf8).prefix(16_384)
    }

    // Independent standard-library observer. Only read-only metadata commands
    // and fd reads run; there is no import/call of ForensicsCore or lab scripts.
    private static let pythonMountedAudit = #"""
import ctypes,hashlib,json,os,plistlib,re,selectors,signal,stat,struct,subprocess,sys,time,uuid
from pathlib import Path
stage='arguments'
opened=[]
deadline=time.monotonic()+75
image_hash='11ddb1a8aa08625a21ba923efdf3cc8c1c11928db0d936d3d009a14651c502b6'
base_uuid='3322234B-EE3F-467B-9D1E-D1E430DF8F5B'
container_uuid='98CF6C75-0405-4B89-B29C-14817D758C7F'
snapshot_uuid='3222234B-EE3F-467B-9D1E-D1E430DF8F5B'
snapshot_name='nf-before'
last_command=None
last_inventory=None

def check(condition,label):
 global stage
 stage=label
 if not condition: raise RuntimeError(label)

def fd_open(name,flags,parent=None):
 descriptor=os.open(name,flags|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
 opened.append(descriptor)
 return descriptor

def directory_path(path):
 path=Path(path)
 check(path.is_absolute() and not any(p in ('.','..') for p in path.parts[1:]),'scratch-path')
 # Parent aliases such as /tmp -> /private/tmp are legitimate. Resolve only
 # the parent, then open the controlled leaf with O_NOFOLLOW and bind its
 # descriptor to the independent Swift-held creation identity below.
 parent=path.parent.resolve(strict=True)
 descriptor=fd_open('/',os.O_RDONLY|os.O_DIRECTORY)
 for component in parent.parts[1:]:
  check(True,'directory-component')
  descriptor=fd_open(component,os.O_RDONLY|os.O_DIRECTORY,descriptor)
 check(True,'directory-component')
 return fd_open(path.name,os.O_RDONLY|os.O_DIRECTORY,descriptor)

def stable_stat(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_uid,value.st_gid,
         value.st_nlink,value.st_flags,value.st_mtime_ns,value.st_ctime_ns)

def held_state(descriptor): return stable_stat(os.fstat(descriptor))

def named_same(name,parent,descriptor):
 check(stable_stat(os.stat(name,dir_fd=parent,follow_symlinks=False))==held_state(descriptor),'identities')

def parse_command(tool,args):
 global last_command
 check(time.monotonic()<deadline,'inventory-command-job-deadline')
 last_command={'tool':tool,'arguments':args,'startedMonotonic':time.monotonic(),
               'exit':None,'naturalTerminal':False,'stdoutBytes':0,'stderrBytes':0}
 check(True,'inventory-command-start')
 process=subprocess.Popen([tool,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  start_new_session=True,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'})
 selector=selectors.DefaultSelector(); buffers=[bytearray(),bytearray()]
 for index,pipe in enumerate((process.stdout,process.stderr)):
  os.set_blocking(pipe.fileno(),False); selector.register(pipe,selectors.EVENT_READ,index)
 until=min(deadline,time.monotonic()+15)
 try:
  while selector.get_map() or process.poll() is None:
   check(time.monotonic()<until,'inventory-command-deadline')
   for key,_ in selector.select(0.05):
    try: body=os.read(key.fileobj.fileno(),65536)
    except BlockingIOError: continue
    if not body: selector.unregister(key.fileobj); continue
    buffers[key.data].extend(body)
    check(len(buffers[key.data])<=(2*1024**2 if key.data==0 else 65536),'inventory-command-output-limit')
  result=process.wait()
  last_command.update({'exit':result,'naturalTerminal':result>=0})
  check(result==0,'inventory-command-exit')
  check(True,'inventory-command-plist')
  return plistlib.loads(bytes(buffers[0]))
 finally:
  last_command.update({'elapsedSeconds':time.monotonic()-last_command['startedMonotonic'],
   'stdoutBytes':len(buffers[0]),'stderrBytes':len(buffers[1]),
   'stdoutSHA256':hashlib.sha256(buffers[0]).hexdigest(),'stderrSHA256':hashlib.sha256(buffers[1]).hexdigest()})
  if process.poll() is None:
   try: os.killpg(process.pid,signal.SIGTERM)
   except ProcessLookupError: pass
   try: process.wait(timeout=0.5)
   except subprocess.TimeoutExpired:
    try: os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait(timeout=1)
  selector.close(); process.stdout.close(); process.stderr.close()

class KernelFS(ctypes.Structure):
 _fields_=[('block_size',ctypes.c_uint32),('io_size',ctypes.c_int32),('blocks',ctypes.c_uint64),
  ('free',ctypes.c_uint64),('available',ctypes.c_uint64),('files',ctypes.c_uint64),('free_files',ctypes.c_uint64),
  ('identifier',ctypes.c_int32*2),('owner',ctypes.c_uint32),('type',ctypes.c_uint32),('flags',ctypes.c_uint32),
  ('subtype',ctypes.c_uint32),('type_name',ctypes.c_char*16),('mount_path',ctypes.c_char*1024),
  ('source_name',ctypes.c_char*1024),('extended_flags',ctypes.c_uint32),('reserved',ctypes.c_uint32*7)]

class Attributes(ctypes.Structure):
 _fields_=[('groups',ctypes.c_uint16),('reserved',ctypes.c_uint16),('common',ctypes.c_uint32),
  ('volume',ctypes.c_uint32),('directory',ctypes.c_uint32),('file',ctypes.c_uint32),('fork',ctypes.c_uint32)]

def kernel(descriptor):
 value=KernelFS()
 check(library.fstatfs(descriptor,ctypes.byref(value))==0,'base-kernel')
 independent=os.fstatvfs(descriptor)
 check(value.block_size==independent.f_frsize and value.blocks==independent.f_blocks,'sdk-abi')
 return {'fsid':tuple(value.identifier),'flags':value.flags,'type':bytes(value.type_name).decode(),
         'mount':bytes(value.mount_path).decode(),'source':bytes(value.source_name).decode()}

def native_uuid(descriptor,label):
 request=Attributes(5,0,0,0x80040000,0,0,0)
 result=ctypes.create_string_buffer(20)
 check(library.fgetattrlist(descriptor,ctypes.byref(request),result,len(result),0)==0,label)
 check(struct.unpack_from('<I',result.raw,0)[0]==20,label)
 return str(uuid.UUID(bytes=result.raw[4:20])).upper()

def literal(prefix,pattern): return (prefix+pattern*((16384//len(pattern))+2))[:16384].encode('ascii')

def file_bytes(parent,name,expected,label):
 descriptor=fd_open(name,os.O_RDONLY,parent); before=held_state(descriptor)
 check(stat.S_ISREG(before[2]) and before[3]==len(expected) and before[0]==os.fstat(parent).st_dev,label)
 check(kernel(descriptor)['fsid']==kernel(parent)['fsid'],label)
 data=os.pread(descriptor,len(expected)+1,0)
 check(data==expected,label)
 check(held_state(descriptor)==before,label); named_same(name,parent,descriptor)
 return hashlib.sha256(data).hexdigest()

def exact_alias(reported,expected,descriptor,parent,is_directory):
 check(isinstance(reported,str) and reported.startswith('/') and '\x00' not in reported,'image-alias')
 reported_path=Path(reported)
 check(reported_path.resolve(strict=True)==expected,'image-alias')
 reported_parent=directory_path(reported_path.parent)
 check(held_state(reported_parent)==held_state(parent),'image-alias')
 alias=fd_open(reported_path.name,os.O_RDONLY|(os.O_DIRECTORY if is_directory else 0),reported_parent)
 check(held_state(alias)==held_state(descriptor),'image-alias')
 named_same(reported_path.name,reported_parent,alias)

def owned_image(required=()):
 global last_inventory
 body=parse_command('/usr/bin/hdiutil',['info','-plist'])
 check(isinstance(body,dict) and isinstance(body.get('images'),list),'inventory-envelope')
 images=body['images']
 last_inventory={'imageCount':len(images),'candidateCount':0,'ownedMatchCount':0,
                 'unrelatedCount':len(images),'ownedRows':[]}
 matches=[]
 for row in images:
  check(isinstance(row,dict),'inventory-row-type')
  path=row.get('image-path')
  # Unrelated host/user image paths are neither resolved nor opened.
  if isinstance(path,str) and Path(path).name=='image.dmg' and Path(path).parent.name==job_name:
   last_inventory['candidateCount']+=1
   last_inventory['unrelatedCount']-=1
   check(True,'inventory-candidate-path')
   if Path(path).resolve(strict=True)==image_path:
    matches.append(row); last_inventory['ownedMatchCount']=len(matches)
 check(len(matches)>0,'inventory-owned-missing')
 check(len(matches)==1,'inventory-owned-ambiguous')
 exact_alias(matches[0]['image-path'],image_path,image_fd,job_fd,False)
 entries=matches[0]['system-entities']
 check(isinstance(entries,list) and 0<len(entries)<=64,'devices')
 # Only an exact pathname plus independently checked held/named full identity
 # reaches this record. Unrelated rows contribute counts, never host paths,
 # resolved files, content or mount locations.
 last_inventory['ownedRows']=[{'privateImageIdentity':list(held_state(image_fd)),
  'expectedPrivateSHA256':image_hash,'entityCount':len(entries),
  'entities':[{'device':e.get('dev-entry') if isinstance(e.get('dev-entry'),str) and len(e['dev-entry'])<=64 else None,
               'contentHint':e.get('content-hint') if isinstance(e.get('content-hint'),str) and len(e['content-hint'].encode())<=128 else None,
               'hasMountPoint':'mount-point' in e} for e in entries if isinstance(e,dict)]}]
 mapped={entry.get('dev-entry') for entry in entries}
 check(all(isinstance(d,str) and re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*',d) for d in mapped),'devices')
 check(all(device in mapped for device in required),'devices')
 return entries,mapped

def native_snapshot(device):
 owned_image([device])
 rows=parse_command('/usr/sbin/diskutil',['apfs','listSnapshots','-plist',device])['Snapshots']
 check(isinstance(rows,list) and len(rows)==1,'snapshot-inventory')
 value=rows[0]
 check(value.get('SnapshotName')==snapshot_name and str(uuid.UUID(value['SnapshotUUID'])).upper()==snapshot_uuid
       and type(value.get('SnapshotXID')) is int and value['SnapshotXID']==1,'snapshot-inventory')
 return (value['SnapshotName'],str(uuid.UUID(value['SnapshotUUID'])).upper(),value['SnapshotXID'])

try:
 check(len(sys.argv)==8 and sys.argv[2] in ('current','snapshot'),'arguments')
 mode=sys.argv[2]; scratch=Path(sys.argv[1])
 check(os.uname().machine=='arm64' and ctypes.sizeof(KernelFS)==2168 and ctypes.sizeof(Attributes)==24,'sdk-abi')
 library=ctypes.CDLL(None,use_errno=True)
 library.fstatfs.argtypes=[ctypes.c_int,ctypes.POINTER(KernelFS)]; library.fstatfs.restype=ctypes.c_int
 library.fgetattrlist.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_ulong]
 library.fgetattrlist.restype=ctypes.c_int
 root_path=Path(sys.argv[3]); root_fd=directory_path(root_path)
 root_state=os.fstat(root_fd)
 check((root_state.st_dev,root_state.st_ino)==(int(sys.argv[4]),int(sys.argv[5]))
       and root_state.st_uid==os.getuid() and stat.S_IMODE(root_state.st_mode)==0o700,'scratch-anchor')
 check(scratch.name=='adapter-scratch' and scratch.parent.resolve(strict=True)==root_path.resolve(strict=True),'scratch-path')
 scratch_fd=fd_open('adapter-scratch',os.O_RDONLY|os.O_DIRECTORY,root_fd); scratch=scratch.resolve(strict=True)
 check((os.fstat(scratch_fd).st_dev,os.fstat(scratch_fd).st_ino)==(int(sys.argv[6]),int(sys.argv[7])),'scratch-anchor')
 scratch_before=held_state(scratch_fd)
 check(os.fstat(scratch_fd).st_uid==os.getuid(),'scratch-owner')
 check(stat.S_IMODE(os.fstat(scratch_fd).st_mode)==0o700,'scratch-permissions')
 names=os.listdir(scratch_fd)
 check(len(names)==1 and re.fullmatch(r'\.native-apfs-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',names[0]),'private-job')
 job_name=names[0]; job_fd=fd_open(job_name,os.O_RDONLY|os.O_DIRECTORY,scratch_fd)
 job_before=held_state(job_fd)
 check(os.fstat(job_fd).st_uid==os.getuid() and stat.S_IMODE(os.fstat(job_fd).st_mode)==0o700,'private-job')
 job_path=scratch/job_name; image_path=job_path/'image.dmg'
 image_fd=fd_open('image.dmg',os.O_RDONLY,job_fd); image_before=held_state(image_fd)
 check(stat.S_ISREG(image_before[2]) and image_before[3]==392537 and image_before[4]==os.getuid()
       and image_before[6]==1 and stat.S_IMODE(image_before[2])==0o400,'image')
 data=os.pread(image_fd,392538,0)
 private_hash=hashlib.sha256(data).hexdigest()
 check(len(data)==392537 and private_hash==image_hash and data[-512:-508]==b'koly','image')
 base_fd=fd_open('view',os.O_RDONLY|os.O_DIRECTORY,job_fd); base_before=held_state(base_fd)
 base_path=job_path/'view'
 entries,mapped=owned_image()
 physicals=[e['dev-entry'] for e in entries if e.get('content-hint') in ('Apple_APFS','7C3457EF-0000-11AA-AA11-00306543ECAC')]
 if not physicals:
  physicals=[e['dev-entry'] for e in entries if e.get('content-hint')=='' and re.fullmatch(r'/dev/disk[0-9]+',e['dev-entry'])]
 check(len(physicals)==1,'physical'); physical=physicals[0]
 owned_image([physical])
 physical_info=parse_command('/usr/sbin/diskutil',['info','-plist',physical])
 check(physical_info['DeviceNode']==physical,'physical')
 reference=physical_info['APFSContainerReference']
 check(re.fullmatch(r'disk[0-9]+',reference) and '/dev/'+reference in mapped,'container')
 owned_image([physical,'/dev/'+reference])
 containers=parse_command('/usr/sbin/diskutil',['apfs','list','/dev/'+reference,'-plist'])['Containers']
 check(len(containers)==1,'container'); container=containers[0]
 check(container['ContainerReference']==reference and container['APFSContainerUUID'].upper()==container_uuid
       and {p['DeviceIdentifier'] for p in container['PhysicalStores']}=={physical[5:]},'container')
 volumes=container['Volumes']
 check(len(volumes)==1 and volumes[0]['APFSVolumeUUID'].upper()==base_uuid,'volume')
 volume_device='/dev/'+volumes[0]['DeviceIdentifier']
 owned_image([physical,'/dev/'+reference,volume_device])
 volume=parse_command('/usr/sbin/diskutil',['info','-plist',volume_device])
 check(volume['DeviceNode']==volume_device and volume['VolumeUUID'].upper()==base_uuid
       and volume['APFSContainerReference']==reference and volume['ParentWholeDisk']==reference
       and {p['APFSPhysicalStore'] for p in volume['APFSPhysicalStores']}=={physical[5:]},'volume')
 check(volume['FilesystemType']=='apfs' and volume['WritableMedia'] is False and volume['WritableVolume'] is False,'base-kernel')
 exact_alias(volume['MountPoint'],base_path,base_fd,job_fd,True)
 base_kernel=kernel(base_fd)
 check(base_kernel['type']=='apfs' and base_kernel['source']==volume_device and base_kernel['mount']==str(base_path)
       and base_kernel['flags']&0x1d==0x1d and base_kernel['flags']&0x40000000==0,'base-kernel')
 check(native_uuid(base_fd,'base-uuid')==base_uuid,'base-uuid')
 earlier=literal('NATIVE FORENSICS BEFORE SNAPSHOT\n','earlier-known-block;0123456789abcdef\n')
 later=literal('NATIVE FORENSICS AFTER SNAPSHOT\n','later-known-block!!;fedcba9876543210\n')
 current_hash=file_bytes(base_fd,'history.bin',later,'base-bytes')
 tuple_before=native_snapshot(volume_device)
 history_hash=None; chosen_uuid=None; chosen_xid=None; snapshot_fd=None
 if mode=='snapshot':
  snapshot_fd=fd_open('snapshot-view',os.O_RDONLY|os.O_DIRECTORY,job_fd)
  snapshot_before=held_state(snapshot_fd); snapshot_path=job_path/'snapshot-view'
  snapshot_kernel=kernel(snapshot_fd)
  check(snapshot_kernel['type']=='apfs' and snapshot_kernel['mount']==str(snapshot_path)
        and snapshot_kernel['source']==snapshot_name+'@'+volume_device
        and snapshot_kernel['flags']&0x4000001d==0x4000001d
        and snapshot_kernel['fsid']!=base_kernel['fsid'],'snapshot-kernel')
  check(native_uuid(snapshot_fd,'snapshot-uuid')==snapshot_uuid,'snapshot-uuid')
  history_hash=file_bytes(snapshot_fd,'history.bin',earlier,'snapshot-bytes')
  check(held_state(snapshot_fd)==snapshot_before and kernel(snapshot_fd)==snapshot_kernel,'identities')
  named_same('snapshot-view',job_fd,snapshot_fd)
  chosen_uuid=snapshot_uuid; chosen_xid=1
 else:
  check('snapshot-view' not in os.listdir(job_fd),'current-only')
 check(native_snapshot(volume_device)==tuple_before,'snapshot-inventory')
 owned_image([physical,'/dev/'+reference,volume_device])
 check(held_state(scratch_fd)==scratch_before and held_state(job_fd)==job_before
       and held_state(image_fd)==image_before and held_state(base_fd)==base_before,'identities')
 named_same(job_name,scratch_fd,job_fd); named_same('image.dmg',job_fd,image_fd); named_same('view',job_fd,base_fd)
 check(kernel(base_fd)==base_kernel and native_uuid(base_fd,'base-uuid')==base_uuid,'identities')
 check(hashlib.sha256(os.pread(image_fd,392538,0)).hexdigest()==image_hash and held_state(image_fd)==image_before,'identities')
 print(json.dumps({'ok':True,'stage':'complete','mode':mode,'privateSHA256':private_hash,'baseUUID':base_uuid,
                   'currentSHA256':current_hash,'snapshotUUID':chosen_uuid,'transactionID':chosen_xid,'historySHA256':history_hash}))
except BaseException:
 print(json.dumps({'ok':False,'stage':stage,'lastCommand':last_command,'lastOwnedInventory':last_inventory}))
finally:
 for descriptor in reversed(opened): os.close(descriptor)
"""#
}
