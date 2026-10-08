import Darwin
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("EFS credential admission and ownership", .serialized)
@MainActor
struct EFSKeyInputStoreTests {
    @Test("Only known encrypted allocated unnamed NTFS streams can create an input context")
    func eligibility() throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        _ = try fixture.context()
        for file in [fixture.file(encryption: nil), fixture.file(attributeName: nil), fixture.file(attributeID: nil), fixture.file(attributeName: "alternate"),
                     fixture.file(deleted: true), fixture.file(directory: true)] {
            #expect(throws: EFSKeyInputStoreError.ineligibleFile) { try fixture.context(file: file) }
        }
        #expect(throws: EFSKeyInputStoreError.ineligibleFile) { try fixture.context(filesystem: "fat32") }
        var hashes = fixture.listing().sourceFileHashes; hashes[fixture.evidence.sourcePath] = String(repeating: "c", count: 64)
        #expect(throws: EFSKeyInputStoreError.selectionChanged) { try fixture.context(hashes: hashes) }
    }

    @Test("A fixture promising a logical-image hash without that receipt is rejected by history binding")
    func promisedLogicalHashIsRequired() throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        #expect(throws: EngineError.invalidCache("The requested logical-image SHA-256 is missing from the filesystem cache.")) {
            try CaseWorkBinding.make(caseID: fixture.caseID, evidence: fixture.evidence,
                result: fixture.listing(hashLogicalImage: true), file: fixture.file())
        }
        let record = try fixture.historyRecord(id: UUID())
        #expect(record.binding.options.hashLogicalImage == false && record.binding.logicalImageHash == nil)
        #expect(record.decryption?.authenticatedPlaintext == false)
    }

    @Test("A busy immediate scheduler refuses before reading any credential bytes or queueing a secret")
    func immediateAdmission() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler(), observations = EFSUIObservations()
        let occupying = try await scheduler.acquireImmediately(.filesystemAnalysis)
        let store = makeStore(context: context, scheduler: scheduler, read: { key, certificate in
            await observations.readStarted(); return try await EFSKeyMaterial.read(privateKeyURL: key, certificateURL: certificate)
        })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        await store.waitForPendingWork()
        #expect(await observations.reads == 0)
        #expect(!store.hasActiveWork && store.errorMessage == ForensicSchedulingError.busy.localizedDescription)
        let state = await scheduler.state()
        #expect(state.active?.id == occupying.admission.id && state.queuedKinds.isEmpty)
        #expect(store.privateKeyFilename == fixture.key.lastPathComponent)
        await occupying.release()
        await store.close()
    }

    @Test("A stale exact selection refuses before admission and reads")
    func staleBeforeRead() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), validation = EFSUIValidation(context), observations = EFSUIObservations()
        let store = EFSKeyInputStore(scheduler: ForensicWorkScheduler(), validateSelection: { validation.current == $0 },
            operation: { _, _, _ in throw EFSKeyInputStoreError.invalidReceipt }, read: { key, certificate in
                await observations.readStarted(); return try await EFSKeyMaterial.read(privateKeyURL: key, certificateURL: certificate)
            })
        store.configure(context: context); select(store, fixture: fixture)
        validation.current = nil
        store.begin(to: fixture.output)
        #expect(!store.canBegin && !store.hasActiveWork)
        #expect(await observations.reads == 0)
        await store.close()
    }

    @Test("Early reader failure cannot strand a test gate or retain an admitted workflow")
    func failedReadGateIsBounded() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler(), gate = EFSUIReadGate()
        let store = makeStore(context: context, scheduler: scheduler, read: { _, _ in throw EFSKeyInputError.invalidSelection })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        do {
            try await withCleanup(store, gates: [gate]) { try await gate.waitEntered(maximumSeconds: 0.1) }
            Issue.record("The deliberately unentered gate unexpectedly opened.")
        } catch { #expect(error as? EFSUITestFailure == .gateDeadline) }
        #expect(store.state == .closed && !store.hasActiveWork)
        #expect(await scheduler.state().active == nil)
    }

    @Test("Source/listing supersession while reading discards material before helper transfer")
    func supersededRead() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler(), gate = EFSUIReadGate(), observations = EFSUIObservations()
        let material = try await EFSKeyMaterial.read(privateKeyURL: fixture.key, certificateURL: fixture.certificate)
        let store = makeStore(context: context, scheduler: scheduler, operation: { _, _, _ in
            await observations.operationStarted(); return fixture.receipt()
        }, read: { _, _ in await gate.read(material) })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        try await withCleanup(store, gates: [gate]) {
            try await gate.waitEntered()
            #expect(store.privateKeyFilename == nil && store.certificateFilename == nil)
            #expect(await scheduler.state().active != nil)
            store.configure(context: nil)
            #expect(store.hasActiveWork && store.state == .cancelling)
            await gate.release(); await store.waitForPendingWork()
            let transfers = await observations.operations
            #expect(material.isConsumed && transfers == 0)
            #expect(await scheduler.state().active == nil)
            #expect(store.lastPublication == nil && store.context == nil)
        }
    }

    @Test("Close waits for the actual admitted key reader and only then releases the workflow slot")
    func closeDrains() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler(), gate = EFSUIReadGate()
        let material = try await EFSKeyMaterial.read(privateKeyURL: fixture.key, certificateURL: fixture.certificate)
        let store = makeStore(context: context, scheduler: scheduler, read: { _, _ in await gate.read(material) })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        try await withCleanup(store, gates: [gate]) {
            try await gate.waitEntered()
            let completion = EFSUICloseCompletion()
            let close = Task { await store.close(); completion.finished = true }
            try await Task.sleep(nanoseconds: 30_000_000)
            let heldState = await scheduler.state()
            #expect(!completion.finished && store.hasActiveWork && heldState.active != nil)
            await gate.release(); await close.value
            #expect(completion.finished && material.isConsumed && !store.hasActiveWork && store.state == .closed)
            #expect(store.context == nil && store.privateKeyFilename == nil && store.certificateFilename == nil)
            #expect(await scheduler.state().active == nil)
        }
    }

    @Test("A finalized publisher's late receipt remains bound to the original context after cancel")
    func latePublication() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler(), gate = EFSUIOperationGate()
        let callback = EFSUIPublications()
        let store = makeStore(context: context, scheduler: scheduler, operation: { context, material, destination in
            _ = try material.consume { key, certificate in
                #expect(key.count == 5 && certificate.count == 5)
            }
            return await gate.finalizedPublisher(fixture.receipt(output: destination))
        }, onPublished: { callback.values.append($0) })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        try await withCleanup(store, gates: [gate]) {
            try await gate.waitEntered(); store.cancel()
            let heldState = await scheduler.state()
            #expect(store.hasActiveWork && store.state == .cancelling && heldState.active != nil)
            await gate.release(); await store.waitForPendingWork()
            #expect(store.lastPublication?.context == context && store.lastPublication?.receipt == fixture.receipt())
            #expect(callback.values.count == 1 && callback.values.first?.context == context)
            #expect(await scheduler.state().active == nil)
        }
    }

    @Test("Credential and arbitrary operation failures suppress private paths and bytes")
    func privateDiagnostics() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), material = try await EFSKeyMaterial.read(privateKeyURL: fixture.key, certificateURL: fixture.certificate)
        let store = makeStore(context: context, operation: { _, _, _ in
            throw NSError(domain: "synthetic", code: 1,
                userInfo: [NSLocalizedDescriptionKey: fixture.key.path + " raw-private-key-value"])
        }, read: { _, _ in material })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        await store.waitForPendingWork()
        #expect(material.isConsumed && store.lastPublication == nil)
        #expect(store.errorMessage != nil && store.errorMessage?.contains("raw-private-key-value") == false)
        #expect(store.errorMessage?.contains(fixture.key.path) == false)
        #expect(store.privateKeyFilename == nil && store.certificateFilename == nil)
        await store.close()
    }

    @Test("Unknown or nondecrypted receipt cannot become an accepted publication")
    func invalidReceipt() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context()
        let store = makeStore(context: context, operation: { _, _, destination in
            ExtractionResult(outputPath: destination.path, byteCount: 7, sha256: String(repeating: "b", count: 64), contentStatus: "logical-content")
        })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        await store.waitForPendingWork()
        #expect(store.lastPublication == nil && store.errorMessage == EFSKeyInputStoreError.invalidReceipt.localizedDescription)
        await store.close()
    }

    @Test("Already-requested cancellation cannot skip history for a finalized output")
    func lateCancelHistory() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler()
        _ = try fixture.historyRecord(id: UUID()) // Fail before any worker/gate if the fixture contract is invalid.
        let outputGate = EFSUIOperationGate(), historyGate = EFSUIHistoryGate()
        let presentation = EFSUIPublications()
        let store = makeStore(context: context, scheduler: scheduler, operation: { _, material, destination in
            material.discard(); return await outputGate.finalizedPublisher(fixture.receipt(output: destination))
        }, onPublished: { presentation.values.append($0) }, recordPublication: { publication in
            do {
                let record = try fixture.historyRecord(id: publication.id)
                return await historyGate.publish(.recorded(record), parentWasCancelled: Task.isCancelled)
            } catch {
                Issue.record(error, "An independently prevalidated synthetic history fixture failed during publication.")
                return .failed(recordID: publication.id, reason: .invalidRecord)
            }
        })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        try await withCleanup(store, gates: [outputGate, historyGate]) {
            try await outputGate.waitEntered(); let firstAdmission = await scheduler.state().active?.id
            store.cancel(); await outputGate.release(); try await historyGate.waitEntered()
            let heldAdmission = await scheduler.state().active?.id
            let writerCancelled = await historyGate.parentWasCancelled
            #expect(store.hasActiveWork && store.lastPublication?.receipt == fixture.receipt())
            #expect(store.historyOutcome == nil && firstAdmission != nil && firstAdmission == heldAdmission)
            #expect(presentation.values.isEmpty)
            #expect(!writerCancelled)
            await historyGate.release(); await store.waitForPendingWork()
            #expect(store.historyOutcome?.historyIsConfirmed == true)
            #expect(store.historyOutcome?.recordID == store.lastPublication?.id)
            #expect(presentation.values.count == 1 && presentation.values.first?.id == store.historyOutcome?.recordID)
            let completed = await scheduler.state()
            #expect(store.errorMessage == nil && completed.active == nil)
        }
    }

    @Test("Quit waits for original-case history publication and keeps the same workflow permit")
    func closeDrainsHistory() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), scheduler = ForensicWorkScheduler(), historyGate = EFSUIHistoryGate()
        _ = try fixture.historyRecord(id: UUID())
        let material = try await EFSKeyMaterial.read(privateKeyURL: fixture.key, certificateURL: fixture.certificate)
        let store = makeStore(context: context, scheduler: scheduler, read: { _, _ in material },
            recordPublication: { publication in
                do {
                    let record = try fixture.historyRecord(id: publication.id)
                    return await historyGate.publish(.recorded(record), parentWasCancelled: Task.isCancelled)
                } catch {
                    Issue.record(error, "An independently prevalidated synthetic history fixture failed during publication.")
                    return .failed(recordID: publication.id, reason: .invalidRecord)
                }
            })
        select(store, fixture: fixture); store.begin(to: fixture.output)
        try await withCleanup(store, gates: [historyGate]) {
            try await historyGate.waitEntered(); let admission = await scheduler.state().active?.id
            #expect(material.isConsumed && store.lastPublication != nil && store.historyOutcome == nil)
            let completion = EFSUICloseCompletion()
            let close = Task { await store.close(); completion.finished = true }
            try await Task.sleep(nanoseconds: 30_000_000)
            let held = await scheduler.state()
            #expect(!completion.finished && store.hasActiveWork && held.active?.id == admission && admission != nil)
            await historyGate.release(); await close.value
            #expect(completion.finished && store.state == .closed && !store.hasActiveWork)
            #expect(store.lastPublication?.context == context && store.historyOutcome?.historyIsConfirmed == true)
            #expect(store.historyOutcome?.recordID == store.lastPublication?.id)
            #expect(await scheduler.state().active == nil)
        }
    }

    @Test("History failure preserves an accepted output and does not fabricate extraction failure")
    func failedHistoryKeepsOutput() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), observations = EFSUIObservations()
        _ = try fixture.historyRecord(id: UUID())
        let store = makeStore(context: context, recordPublication: { publication in
            await observations.operationStarted()
            return .failed(recordID: publication.id, reason: .storageFailure)
        })
        select(store, fixture: fixture); store.begin(to: fixture.output); await store.waitForPendingWork()
        #expect(store.lastPublication?.receipt == fixture.receipt())
        #expect(store.historyOutcome?.historyIsConfirmed == false && store.historyOutcome?.record == nil)
        #expect(store.historyOutcome?.recordID == store.lastPublication?.id && store.errorMessage == nil)
        #expect(store.statusMessage.contains("output was published") && !store.statusMessage.contains("No decrypted-content"))
        #expect(await observations.operations == 1)
        await store.close()
    }

    @Test("Unconfirmed history durability retains the single immutable record and output")
    func uncertainHistoryKeepsOutput() async throws {
        let fixture = try EFSUIFixture(); defer { fixture.remove() }
        let context = try fixture.context(), observations = EFSUIObservations()
        _ = try fixture.historyRecord(id: UUID())
        let store = makeStore(context: context, recordPublication: { publication in
            await observations.operationStarted()
            do {
                let record = try fixture.historyRecord(id: publication.id)
                return .publishedButDurabilityUnconfirmed(record)
            } catch {
                Issue.record(error, "An independently prevalidated synthetic history fixture failed during publication.")
                return .failed(recordID: publication.id, reason: .invalidRecord)
            }
        })
        select(store, fixture: fixture); store.begin(to: fixture.output); await store.waitForPendingWork()
        #expect(store.lastPublication?.receipt == fixture.receipt() && store.historyOutcome?.historyIsConfirmed == false)
        #expect(store.historyOutcome?.record != nil && store.historyOutcome?.recordID == store.lastPublication?.id)
        #expect(store.errorMessage == nil && store.statusMessage.contains("durability could not be confirmed"))
        #expect(await observations.operations == 1)
        await store.close()
    }

    private func makeStore(context: EFSKeySelectionContext, scheduler: ForensicWorkScheduler = ForensicWorkScheduler(),
                           operation: EFSKeyInputStore.Operation? = nil, read: EFSKeyInputStore.Read? = nil,
                           onPublished: (@MainActor @Sendable (EFSKeyPublication) -> Void)? = nil,
                           recordPublication: EFSKeyInputStore.RecordPublication? = nil) -> EFSKeyInputStore {
        let store = EFSKeyInputStore(scheduler: scheduler, validateSelection: { $0 == context },
            operation: operation ?? { _, material, destination in
                try material.consume { _, _ in EFSUIFixture.decryptedReceipt(output: destination) }
            }, read: read ?? { try await EFSKeyMaterial.read(privateKeyURL: $0, certificateURL: $1) },
            onPublished: onPublished, recordPublication: recordPublication)
        store.configure(context: context); return store
    }
    private func select(_ store: EFSKeyInputStore, fixture: EFSUIFixture) {
        store.setChoice(fixture.key, for: .privateKey); store.setChoice(fixture.certificate, for: .certificate)
    }
    private func withCleanup(_ store: EFSKeyInputStore, gates: [any EFSUITestGate],
                             operation: @MainActor () async throws -> Void) async throws {
        do {
            try await operation()
            for gate in gates { await gate.release() }
            await store.close()
        } catch {
            for gate in gates { await gate.release() }
            await store.close()
            throw error
        }
    }
}

private struct EFSUIFixture: Sendable {
    let directory: URL, key: URL, certificate: URL, output: URL
    let caseID = UUID(), generationID = UUID(), savedAt = Date(timeIntervalSince1970: 1_700_000_000)
    let evidence = EvidenceRecord(sourcePath: "/synthetic/efs-volume.raw", byteCount: 1_048_576,
        sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: "ntfs")
    init() throws {
        directory = try Self.newOwnedDirectory()
        key = directory.appendingPathComponent("private-fixture.der"); certificate = directory.appendingPathComponent("certificate-fixture.der")
        output = directory.appendingPathComponent("new-output.bin")
        // Admission/state fixtures only; strict ASN.1/cryptography belongs to
        // independent native key pipeline tests, not these fake operations.
        try Data([0x30, 0x03, 0x02, 0x01, 0x00]).write(to: key)
        try Data([0x30, 0x03, 0x02, 0x01, 0x01]).write(to: certificate)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    private static func newOwnedDirectory() throws -> URL {
        // macOS 27 Foundation preserves /var after "resolution". Preserve the
        // strict producer gate and create only a fresh ignored repo child.
        let local = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("local", isDirectory: true)
        guard Darwin.mkdir(local.path, 0o700) == 0 || errno == EEXIST else { throw EFSUITestFailure.fixtureDirectory }
        let parent = try openDirectory(local.path); defer { Darwin.close(parent) }
        var base = stat()
        guard Darwin.fstat(parent, &base) == 0, base.st_uid == geteuid() else { throw EFSUITestFailure.fixtureDirectory }
        let leaf = "efs-ui-\(UUID().uuidString)"
        guard Darwin.mkdirat(parent, leaf, 0o700) == 0 else { throw EFSUITestFailure.fixtureDirectory }
        let url = local.appendingPathComponent(leaf, isDirectory: true)
        let descriptor = Darwin.openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw EFSUITestFailure.fixtureDirectory }
        defer { Darwin.close(descriptor) }
        var held = stat(), named = stat()
        guard Darwin.fstat(descriptor, &held) == 0, Darwin.lstat(url.path, &named) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_uid == geteuid(),
              held.st_mode & S_IFMT == S_IFDIR, held.st_mode & 0o7777 == 0o700 else { throw EFSUITestFailure.fixtureDirectory }
        return url
    }
    private static func openDirectory(_ path: String) throws -> Int32 {
        var parent = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw EFSUITestFailure.fixtureDirectory }
        for name in path.split(separator: "/") {
            let next = Darwin.openat(parent, String(name), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            Darwin.close(parent)
            guard next >= 0 else { throw EFSUITestFailure.fixtureDirectory }
            parent = next
        }
        return parent
    }
    func file(encryption: FilesystemEncryptionStatus? = .ntfsEFSEncrypted, attributeName: String? = "",
              attributeID: Int32? = 3, deleted: Bool = false, directory: Bool = false) -> FilesystemEntry {
        FilesystemEntry(id: "efs-known", path: "/Encrypted/sample.txt", name: "sample.txt", fsOffsetBytes: 0,
            metaAddress: 42, attributeType: 128, attributeID: attributeID, size: 7, isDirectory: directory, isDeleted: deleted,
            encryptionStatus: encryption, attributeName: attributeName)
    }
    func listing(file: FilesystemEntry? = nil, filesystem: String = "ntfs", hashes: [String: String]? = nil,
                 hashLogicalImage: Bool = false) -> EnumerationResult {
        EnumerationResult(engineVersion: "synthetic-engine", patchDigest: String(repeating: "d", count: 64),
            sourcePaths: [evidence.sourcePath], sourceFileHashes: hashes ?? [evidence.sourcePath: evidence.sha256],
            // This UI state fixture has no logical source bytes to hash.
            // Explicitly omit that optional operation rather than promise a
            // logical-image receipt it never generated.
            options: .init(hashLogicalImage: hashLogicalImage), image: .init(imageType: "raw", logicalSize: evidence.byteCount, sectorSize: 512),
            volumes: [.init(id: "ntfs0", offsetBytes: 0, filesystem: filesystem, blockSize: 512, blockCount: 2_048)],
            files: [file ?? self.file()], warnings: [], status: .completed, savedAt: savedAt)
    }
    func context(file: FilesystemEntry? = nil, filesystem: String = "ntfs", hashes: [String: String]? = nil) throws -> EFSKeySelectionContext {
        try EFSKeySelectionContext(caseID: caseID, evidence: evidence, listingGenerationID: generationID,
            result: listing(file: file, filesystem: filesystem, hashes: hashes), file: file ?? self.file())
    }
    func receipt(output: URL? = nil) -> ExtractionResult {
        Self.decryptedReceipt(output: output ?? self.output)
    }
    static func decryptedReceipt(output: URL) -> ExtractionResult {
        ExtractionResult(outputPath: output.path, byteCount: 7, sha256: String(repeating: "b", count: 64),
            contentStatus: "decrypted-content", warnings: [ExtractionDecryptionReceipt.unauthenticatedPlaintextWarning],
            decryption: ExtractionDecryptionReceipt(profile: "ntfs-efs-rsa-pkcs1-aes256-der", recipientRole: .ddf,
                metadataSHA256: String(repeating: "c", count: 64), certificateSHA1: String(repeating: "d", count: 40),
                ciphertextSHA256: String(repeating: "e", count: 64), ciphertextBytes: 512, unitBytes: 512, authenticatedPlaintext: false))
    }
    func historyRecord(id: UUID) throws -> ExtractionRecord {
        try ExtractionRecord.make(binding: CaseWorkBinding.make(caseID: caseID, evidence: evidence,
            result: listing(), file: file()), receipt: receipt(), id: id)
    }
}

@MainActor private final class EFSUIValidation { var current: EFSKeySelectionContext?; init(_ value: EFSKeySelectionContext) { current = value } }
@MainActor private final class EFSUICloseCompletion { var finished = false }
@MainActor private final class EFSUIPublications { var values: [EFSKeyPublication] = [] }
private actor EFSUIObservations {
    private(set) var reads = 0, operations = 0
    func readStarted() { reads += 1 }
    func operationStarted() { operations += 1 }
}
private protocol EFSUITestGate: Actor { func release() }
private enum EFSUITestFailure: Error, Equatable { case fixtureDirectory, gateDeadline }
private actor EFSUIReadGate: EFSUITestGate {
    private var entered = false
    private var released = false
    private var resume: CheckedContinuation<EFSKeyMaterial, Never>?
    private var material: EFSKeyMaterial?
    func read(_ value: EFSKeyMaterial) async -> EFSKeyMaterial {
        entered = true; if released { return value }; material = value
        return await withCheckedContinuation { resume = $0 }
    }
    func waitEntered(maximumSeconds: TimeInterval = 5) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + maximumSeconds
        while !entered {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw EFSUITestFailure.gateDeadline }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }
    func release() { released = true; if let material { resume?.resume(returning: material) }; resume = nil; material = nil }
}
private actor EFSUIOperationGate: EFSUITestGate {
    private var entered = false
    private var released = false
    private var resume: CheckedContinuation<ExtractionResult, Never>?
    private var receipt: ExtractionResult?
    func finalizedPublisher(_ value: ExtractionResult) async -> ExtractionResult {
        entered = true; if released { return value }; receipt = value
        return await withCheckedContinuation { resume = $0 }
    }
    func waitEntered() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        while !entered {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw EFSUITestFailure.gateDeadline }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }
    func release() { released = true; if let receipt { resume?.resume(returning: receipt) }; resume = nil; receipt = nil }
}
private actor EFSUIHistoryGate: EFSUITestGate {
    private var entered = false
    private var released = false
    private var resume: CheckedContinuation<ExtractionHistoryPublicationOutcome, Never>?
    private var outcome: ExtractionHistoryPublicationOutcome?
    private(set) var parentWasCancelled = false
    func publish(_ value: ExtractionHistoryPublicationOutcome, parentWasCancelled: Bool) async -> ExtractionHistoryPublicationOutcome {
        self.parentWasCancelled = parentWasCancelled; entered = true; if released { return value }; outcome = value
        return await withCheckedContinuation { resume = $0 }
    }
    func waitEntered() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        while !entered {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw EFSUITestFailure.gateDeadline }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }
    func release() { released = true; if let outcome { resume?.resume(returning: outcome) }; resume = nil; outcome = nil }
}
