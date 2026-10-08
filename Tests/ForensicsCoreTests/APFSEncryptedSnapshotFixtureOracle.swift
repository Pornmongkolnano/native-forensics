import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

/// Staged outside SwiftPM. Each workflow constructs a fresh encrypted wrapper
/// around the independently pinned synthetic plaintext snapshot image. Its key
/// exists only in the support object's memory and fresh single-use credentials.
@Suite("Fresh AES-256 APFS snapshot API", .serialized)
struct APFSEncryptedSnapshotFixtureOracle {
    private static let enabled = ProcessInfo.processInfo.environment["NF_APFS_ENCRYPTED_SNAPSHOT_INTEGRATION"] == "1"

    @Test("Fresh encrypted current and historical views preserve credentials, cache generations and verified exports",
          .enabled(if: APFSEncryptedSnapshotFixtureOracle.enabled))
    func currentAndHistoricalAPI() async throws {
        let fixture = try AESnapshotFixture()
        defer { fixture.finishBestEffort() }
        let cipher = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        try Self.requireCipher(cipher, fixture: fixture)
        try fixture.requireSourcesPreserved()
        try fixture.requireEmptyScratch()
        let created = try CaseStore.create(name: "Fresh encrypted snapshot integration", in: fixture.root)
        let forensicCase = try CaseStore.adding(image: cipher, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let originalManifest = try Data(contentsOf: manifestURL)
        try fixture.requireMetadataExcludesKey([originalManifest])
        var metadataBodies = [originalManifest]
        let adapter = fixture.adapter()

        // The two selectors have identical credential admission. Missing and
        // consumed credentials must fail before attaching any private image;
        // a wrong fresh key must naturally terminate its actual attach client.
        let views: [UUID?] = [nil, AESnapshotFixture.snapshot.uuid]
        for view in views {
            let options = fixture.options(snapshot: view)
            fixture.begin(snapshot: view)
            await #expect(throws: APFSReadError.invalidCredential) {
                _ = try await adapter.inspect(evidence: evidence, options: options)
            }
            try fixture.requireNoAttach()
            try Self.requireQuiescent(fixture)
            try Self.requireManifestUnchanged(manifestURL, original: originalManifest, fixture: fixture)

            fixture.begin(snapshot: view, wrongAttach: true)
            let wrong = try fixture.wrongCredential()
            var refusedWrongKey = false
            do {
                _ = try await adapter.inspect(evidence: evidence, passphrase: wrong, options: options)
            } catch let error as APFSReadError {
                guard case .commandFailed(let status) = error, status > 0 else { throw error }
                refusedWrongKey = true
            }
            try #require(refusedWrongKey)
            try fixture.requireWrongAttachTerminal()
            try Self.requireQuiescent(fixture)
            try Self.requireManifestUnchanged(manifestURL, original: originalManifest, fixture: fixture)

            fixture.begin(snapshot: view)
            await #expect(throws: APFSReadError.credentialConsumed) {
                _ = try await adapter.inspect(evidence: evidence, passphrase: wrong, options: options)
            }
            try fixture.requireNoAttach()
            try Self.requireQuiescent(fixture)
            try Self.requireManifestUnchanged(manifestURL, original: originalManifest, fixture: fixture)
        }

        fixture.begin()
        let currentCredential = try fixture.credential()
        let current = try await adapter.inspect(evidence: evidence, passphrase: currentCredential,
                                                options: fixture.options())
        let currentEncoded = try Self.checkedMetadata(current, fixture: fixture)
        metadataBodies.append(currentEncoded)
        try Self.requireInspection(current, evidence: evidence, fixture: fixture, snapshot: nil)
        try fixture.requireMountedAudit()
        try Self.requireQuiescent(fixture)
        let currentEntry = try Self.historyEntry(current, expected: AESnapshotFixture.later,
                                                 sha256: AESnapshotFixture.laterSHA)

        // The credential consumed by inspect cannot be reused by a file read.
        fixture.begin()
        await #expect(throws: APFSReadError.credentialConsumed) {
            _ = try await adapter.readVerifiedFile(evidence: evidence, inspection: current,
                                                   entry: currentEntry, passphrase: currentCredential)
        }
        try fixture.requireNoAttach()
        try Self.requireQuiescent(fixture)
        try Self.requireManifestUnchanged(manifestURL, original: originalManifest, fixture: fixture)
        fixture.begin()
        let currentRead = try await adapter.readVerifiedFile(evidence: evidence, inspection: current,
                                                            entry: currentEntry, passphrase: fixture.credential())
        Self.expectRead(currentRead, evidence: evidence, snapshot: nil,
                        bytes: AESnapshotFixture.later, sha256: AESnapshotFixture.laterSHA)
        try fixture.requireMountedAudit()
        try Self.requireQuiescent(fixture)

        let currentCache = try APFSResultStore.save(current, in: forensicCase)
        let currentCase = try CaseStore.open(at: forensicCase.bundleURL)
        let loadedCurrent = try APFSResultStore.loadLatest(in: currentCase, evidenceID: evidence.id)
        let reopenedCurrent = try #require(loadedCurrent)
        metadataBodies.append(try Self.checkedMetadata(reopenedCurrent, fixture: fixture))
        #expect(reopenedCurrent == current && reopenedCurrent.selectedSnapshot == nil)
        let currentResultURL = forensicCase.bundleURL.appendingPathComponent(currentCache.relativePath)
        let originalCurrentBytes = try Data(contentsOf: currentResultURL)
        let currentChecksumURL = currentResultURL.deletingLastPathComponent().appendingPathComponent("checksum.json")
        let originalCurrentChecksum = try Data(contentsOf: currentChecksumURL)
        let latestURL = forensicCase.bundleURL.appendingPathComponent("apfs", isDirectory: true)
            .appendingPathComponent(evidence.id.uuidString.lowercased(), isDirectory: true)
            .appendingPathComponent("latest.json")
        let currentPointer = try Data(contentsOf: latestURL)
        try fixture.requireMetadataExcludesKey([originalCurrentBytes, originalCurrentChecksum, currentPointer])
        metadataBodies += [originalCurrentBytes, originalCurrentChecksum, currentPointer,
                           try Self.checkedMetadata(currentCache, fixture: fixture)]
        #expect(Self.hash(originalCurrentBytes) == currentCache.resultSHA256)
        #expect(originalCurrentBytes.count == currentCache.serializedByteCount)
        let decodedCurrentChecksum = try JSONDecoder().decode(APFSCacheReceipt.self, from: originalCurrentChecksum)
        let decodedCurrentPointer = try JSONDecoder().decode(APFSCacheReceipt.self, from: currentPointer)
        #expect(decodedCurrentChecksum == currentCache && decodedCurrentPointer == currentCache)

        // Export while the current generation is still latest. The export
        // service uses its own default adapter, so its mounts are not counted
        // by our injected observer; exact output bytes and receipt are checked.
        fixture.begin()
        let currentOutput = fixture.root.appendingPathComponent("current-verified.bin")
        let currentExportFence = try fixture.beginDefaultExportFence()
        let currentExport = try await APFSExportService.export(evidence: evidence, inspection: reopenedCurrent,
            entry: currentEntry, in: currentCase, to: currentOutput, passphrase: fixture.credential())
        try fixture.requireDefaultExportFence(currentExportFence)
        metadataBodies.append(try Self.checkedMetadata(currentExport, fixture: fixture))
        let currentBytes = try Data(contentsOf: currentOutput)
        #expect(currentBytes == AESnapshotFixture.later)
        Self.expectExport(currentExport, cache: currentCache, evidence: evidence, caseID: currentCase.manifest.id,
                          snapshot: nil, bytes: currentBytes, sha256: AESnapshotFixture.laterSHA)
        try Self.requireQuiescent(fixture)

        fixture.begin(snapshot: AESnapshotFixture.snapshot.uuid)
        let historical = try await adapter.inspect(evidence: evidence, passphrase: fixture.credential(),
            options: fixture.options(snapshot: AESnapshotFixture.snapshot.uuid))
        metadataBodies.append(try Self.checkedMetadata(historical, fixture: fixture))
        try Self.requireInspection(historical, evidence: evidence, fixture: fixture, snapshot: AESnapshotFixture.snapshot)
        try fixture.requireMountedAudit()
        try Self.requireQuiescent(fixture)
        let historicalEntry = try Self.historyEntry(historical, expected: AESnapshotFixture.earlier,
                                                    sha256: AESnapshotFixture.earlierSHA)
        #expect(historicalEntry.sha256 != currentEntry.sha256)
        fixture.begin(snapshot: AESnapshotFixture.snapshot.uuid)
        let historicalRead = try await adapter.readVerifiedFile(evidence: evidence, inspection: historical,
                                                               entry: historicalEntry, passphrase: fixture.credential())
        Self.expectRead(historicalRead, evidence: evidence, snapshot: AESnapshotFixture.snapshot,
                        bytes: AESnapshotFixture.earlier, sha256: AESnapshotFixture.earlierSHA)
        #expect(historicalRead.data != currentRead.data)
        try fixture.requireMountedAudit()
        try Self.requireQuiescent(fixture)

        let historicalCache = try APFSResultStore.save(historical, in: currentCase)
        let reopenedCase = try CaseStore.open(at: forensicCase.bundleURL)
        let loadedHistorical = try APFSResultStore.loadLatest(in: reopenedCase, evidenceID: evidence.id)
        let reopenedHistorical = try #require(loadedHistorical)
        metadataBodies.append(try Self.checkedMetadata(reopenedHistorical, fixture: fixture))
        #expect(reopenedHistorical == historical && reopenedHistorical.selectedSnapshot == AESnapshotFixture.snapshot)
        #expect(historicalCache.generationID != currentCache.generationID)
        let retainedCurrentBytes = try Data(contentsOf: currentResultURL)
        let retainedCurrentChecksum = try Data(contentsOf: currentChecksumURL)
        let historicalResultURL = reopenedCase.bundleURL.appendingPathComponent(historicalCache.relativePath)
        let historicalBytes = try Data(contentsOf: historicalResultURL)
        let historicalChecksum = try Data(contentsOf: historicalResultURL.deletingLastPathComponent()
            .appendingPathComponent("checksum.json"))
        let historicalPointer = try Data(contentsOf: latestURL)
        try fixture.requireMetadataExcludesKey([retainedCurrentBytes, retainedCurrentChecksum,
                                               historicalBytes, historicalChecksum, historicalPointer])
        metadataBodies += [retainedCurrentBytes, retainedCurrentChecksum, historicalBytes, historicalChecksum,
                           historicalPointer, try Self.checkedMetadata(historicalCache, fixture: fixture)]
        #expect(retainedCurrentBytes == originalCurrentBytes && retainedCurrentChecksum == originalCurrentChecksum)
        #expect(Self.hash(historicalBytes) == historicalCache.resultSHA256)
        #expect(historicalBytes.count == historicalCache.serializedByteCount)
        let decodedPriorCurrent = try JSONDecoder().decode(APFSInspectionResult.self, from: retainedCurrentBytes)
        let decodedHistoricalChecksum = try JSONDecoder().decode(APFSCacheReceipt.self, from: historicalChecksum)
        let decodedHistoricalPointer = try JSONDecoder().decode(APFSCacheReceipt.self, from: historicalPointer)
        #expect(decodedPriorCurrent == current && decodedPriorCurrent.selectedSnapshot == nil)
        #expect(decodedHistoricalChecksum == historicalCache && decodedHistoricalPointer == historicalCache)

        // Persisted metadata never supplies a reusable key to a fresh read.
        fixture.begin(snapshot: AESnapshotFixture.snapshot.uuid)
        await #expect(throws: APFSReadError.invalidCredential) {
            _ = try await adapter.readVerifiedFile(evidence: evidence, inspection: reopenedHistorical,
                                                   entry: historicalEntry)
        }
        try fixture.requireNoAttach()
        try Self.requireQuiescent(fixture)
        try Self.requireManifestUnchanged(manifestURL, original: originalManifest, fixture: fixture)
        fixture.begin(snapshot: AESnapshotFixture.snapshot.uuid)
        let reopenedRead = try await adapter.readVerifiedFile(evidence: evidence, inspection: reopenedHistorical,
                                                             entry: historicalEntry, passphrase: fixture.credential())
        Self.expectRead(reopenedRead, evidence: evidence, snapshot: AESnapshotFixture.snapshot,
                        bytes: AESnapshotFixture.earlier, sha256: AESnapshotFixture.earlierSHA)
        try fixture.requireMountedAudit()
        try Self.requireQuiescent(fixture)

        fixture.begin(snapshot: AESnapshotFixture.snapshot.uuid)
        let historicalOutput = fixture.root.appendingPathComponent("historical-verified.bin")
        let historicalExportFence = try fixture.beginDefaultExportFence()
        let historicalExport = try await APFSExportService.export(evidence: evidence, inspection: reopenedHistorical,
            entry: historicalEntry, in: reopenedCase, to: historicalOutput, passphrase: fixture.credential())
        try fixture.requireDefaultExportFence(historicalExportFence)
        let encodedHistoricalExport = try Self.checkedMetadata(historicalExport, fixture: fixture)
        metadataBodies.append(encodedHistoricalExport)
        let historicalOutputBytes = try Data(contentsOf: historicalOutput)
        #expect(historicalOutputBytes == AESnapshotFixture.earlier && historicalOutputBytes != currentBytes)
        Self.expectExport(historicalExport, cache: historicalCache, evidence: evidence, caseID: reopenedCase.manifest.id,
                          snapshot: AESnapshotFixture.snapshot, bytes: historicalOutputBytes, sha256: AESnapshotFixture.earlierSHA)
        let decodedExport = try JSONDecoder().decode(APFSExportReceipt.self, from: encodedHistoricalExport)
        #expect(decodedExport == historicalExport)
        try fixture.requireMetadataExcludesKey(metadataBodies)
        try Self.requireManifestUnchanged(manifestURL, original: originalManifest, fixture: fixture)
        try Self.requireQuiescent(fixture)
        let after = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        #expect(after.sha256 == cipher.sha256 && after.byteCount == cipher.byteCount)
        #expect(after.sourceIdentity == cipher.sourceIdentity)
        try fixture.requireSourcesPreserved()
        try fixture.finish()
    }

    @Test("Encrypted historical client cancellation proves actual successful snapshot mount before owned cleanup",
          .enabled(if: APFSEncryptedSnapshotFixtureOracle.enabled))
    func cooperativeHistoricalCancellation() async throws {
        let fixture = try AESnapshotFixture()
        defer { fixture.finishBestEffort() }
        let cipher = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        try Self.requireCipher(cipher, fixture: fixture)
        try Self.requireQuiescent(fixture)
        let evidence = EvidenceRecord(sourcePath: fixture.image.path, byteCount: cipher.byteCount,
            sha256: cipher.sha256, container: cipher.container, filesystemHint: cipher.filesystemHint)
        let control = AESnapshotCancellationControl()
        fixture.begin(snapshot: AESnapshotFixture.snapshot.uuid)
        let adapter = fixture.adapter(additionalLifecycle: { event in control.observe(event) }, proveSnapshotTerminal: true)
        let credential = try fixture.credential()
        let options = fixture.options(snapshot: AESnapshotFixture.snapshot.uuid)
        let task = Task {
            await control.waitUntilInstalled()
            return try await adapter.inspect(evidence: evidence, passphrase: credential, options: options)
        }
        control.install(task)
        defer { control.releaseTask() }
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        let observation = control.observation()
        #expect(observation.requested && observation.started == 1 && observation.terminal == 1)
        #expect(observation.detached == 1 && observation.mounted == 0 && observation.validOrder)
        // Natural terminal and CancellationError alone can also describe a
        // failed native mount. The internal diagnostic must observe raw exit 0
        // and independent exact UUID/flags/device/fsid metadata before cleanup.
        try fixture.requireSuccessfulSnapshotTerminalProof()
        try Self.requireQuiescent(fixture)
        let after = try await ImageInspector.inspect(url: fixture.image, progress: { _ in })
        #expect(after.sha256 == cipher.sha256 && after.byteCount == cipher.byteCount)
        #expect(after.sourceIdentity == cipher.sourceIdentity)
        try fixture.requireSourcesPreserved()
        // No cache, export, extraction or file walker publication is invoked.
        try fixture.finish()
    }

    private static func requireCipher(_ image: InspectedImage, fixture: AESnapshotFixture) throws {
        try #require((1...Int64(512 * 1_024 * 1_024)).contains(fixture.cipherBytes))
        #expect(image.container == .unknown && image.sha256 == fixture.cipherSHA)
        #expect(image.byteCount == fixture.cipherBytes && image.sourceIdentity == fixture.inspectedSourceIdentity)
        let hint = try #require(image.filesystemHint)
        #expect(hint.contains("Encrypted UDIF wrapper signature (version 2)"))
        #expect(image.hashScope == FileHashScope.selectedFileBytes)
        try #require(AESnapshotFixture.earlier.count == 16_384 && AESnapshotFixture.later.count == 16_384)
        try #require(AESnapshotFixture.earlier != AESnapshotFixture.later)
        #expect(hash(AESnapshotFixture.earlier) == AESnapshotFixture.earlierSHA)
        #expect(hash(AESnapshotFixture.later) == AESnapshotFixture.laterSHA)
    }

    private static func requireInspection(_ result: APFSInspectionResult, evidence: EvidenceRecord,
                                           fixture: AESnapshotFixture, snapshot: APFSSnapshotInventoryEntry?) throws {
        try APFSMountedImageAdapter.validate(result, evidence: evidence)
        #expect(result.evidenceID == evidence.id && result.containerSHA256 == fixture.cipherSHA)
        #expect(result.containerByteCount == fixture.cipherBytes && result.hashScope == FileHashScope.selectedFileBytes)
        #expect(result.options == fixture.options(snapshot: snapshot?.uuid))
        #expect(result.volumeUUID == AESnapshotFixture.baseUUID)
        #expect(result.containerEncryption == .encryptedDiskImage && result.volumeEncryption == .none)
        #expect(result.selectedSnapshot == snapshot && result.options.selectedSnapshotUUID == snapshot?.uuid)
        #expect(result.snapshotInventoryAvailable && result.snapshots == [AESnapshotFixture.snapshot])
        #expect(result.coverage == .completeAllocatedView)
    }

    private static func historyEntry(_ result: APFSInspectionResult, expected: Data, sha256: String) throws -> APFSFileEntry {
        let entry = try #require(result.entries.first { $0.relativePath == "history.bin" })
        #expect(entry.kind == .regular && entry.byteCount == Int64(expected.count) && entry.sha256 == sha256)
        return entry
    }

    private static func expectRead(_ read: APFSVerifiedFile, evidence: EvidenceRecord, snapshot: APFSSnapshotInventoryEntry?,
                                    bytes: Data, sha256: String) {
        #expect(read.data == bytes && read.sha256 == sha256)
        #expect(read.containerSHA256 == evidence.sha256 && read.volumeUUID == AESnapshotFixture.baseUUID)
        #expect(read.relativePath == "history.bin" && read.selectedSnapshot == snapshot)
    }

    private static func expectExport(_ receipt: APFSExportReceipt, cache: APFSCacheReceipt, evidence: EvidenceRecord,
                                      caseID: UUID, snapshot: APFSSnapshotInventoryEntry?, bytes: Data, sha256: String) {
        #expect(receipt.caseID == caseID && receipt.evidenceID == evidence.id)
        #expect(receipt.volumeUUID == AESnapshotFixture.baseUUID && receipt.relativePath == "history.bin")
        #expect(receipt.resultSHA256 == cache.resultSHA256 && receipt.containerSHA256 == evidence.sha256)
        #expect(receipt.byteCount == Int64(bytes.count) && receipt.sha256 == sha256 && hash(bytes) == sha256)
        #expect(receipt.selectedSnapshot == snapshot && receipt.containerHashScope == FileHashScope.selectedFileBytes)
        #expect(receipt.outputHashScope == "logical-APFS-file-bytes")
    }

    private static func checkedMetadata<Value: Encodable>(_ value: Value, fixture: AESnapshotFixture) throws -> Data {
        let bytes = try JSONEncoder().encode(value)
        try fixture.requireMetadataExcludesKey([bytes])
        return bytes
    }

    private static func requireManifestUnchanged(_ url: URL, original: Data, fixture: AESnapshotFixture) throws {
        let bytes = try Data(contentsOf: url)
        try fixture.requireMetadataExcludesKey([bytes])
        #expect(bytes == original)
    }

    private static func requireQuiescent(_ fixture: AESnapshotFixture) throws {
        try fixture.requireEmptyScratch()
        try fixture.requireSourcesPreserved()
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private final class AESnapshotCancellationControl: @unchecked Sendable {
    struct Observation: Sendable {
        let requested: Bool
        let started: Int
        let terminal: Int
        let detached: Int
        let mounted: Int
        let validOrder: Bool
    }
    private let lock = NSLock()
    private var task: Task<APFSInspectionResult, any Error>?
    private var installationWaiter: CheckedContinuation<Void, Never>?
    private var requested = false
    private var started = 0, terminal = 0, detached = 0, mounted = 0
    private var validOrder = true

    func waitUntilInstalled() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if task != nil { lock.unlock(); continuation.resume() }
            else { installationWaiter = continuation; lock.unlock() }
        }
    }

    func install(_ value: Task<APFSInspectionResult, any Error>) {
        lock.lock()
        task = value
        let pendingCancellation = requested, waiter = installationWaiter
        installationWaiter = nil
        lock.unlock()
        if pendingCancellation { value.cancel() }
        waiter?.resume()
    }

    func observe(_ event: APFSReadLifecycleStage) {
        lock.lock()
        var target: Task<APFSInspectionResult, any Error>?
        switch event {
        case .snapshotMountClientStarted(let pid):
            started += 1
            validOrder = validOrder && pid > 0 && started == 1 && terminal == 0 && detached == 0
            requested = true
            target = task
        case .snapshotMountCommandTerminal:
            terminal += 1
            validOrder = validOrder && started == 1 && terminal == 1 && detached == 0
        case .mounted:
            mounted += 1
        case .detached:
            detached += 1
            validOrder = validOrder && started == 1 && terminal == 1 && detached == 1
        default:
            break
        }
        lock.unlock()
        target?.cancel()
    }

    func observation() -> Observation {
        lock.lock(); defer { lock.unlock() }
        return .init(requested: requested, started: started, terminal: terminal,
                     detached: detached, mounted: mounted, validOrder: validOrder)
    }

    func releaseTask() { lock.lock(); task = nil; lock.unlock() }
}
