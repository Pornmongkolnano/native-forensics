import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("APFS workspace ownership", .serialized)
@MainActor
struct APFSWorkspaceStoreTests {
    @Test("Reopened cache is historical and bound to its exact case/source/result digest")
    func historicalBinding() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await store.waitForPendingWork()
        #expect(store.isHistorical && store.result == fixture.result())
        #expect(store.rows.count == 2)
        #expect(store.selectedEvidenceID == fixture.evidence.id && store.selectedCaseID == fixture.forensicCase.manifest.id)
        store.selectedEntryPath = fixture.entry.relativePath
        #expect(store.canPreview && store.canExport)
        let wrong = APFSUIFixture(sourceHash: String(repeating: "e", count: 64))
        store.configure(evidence: wrong.evidence, in: wrong.forensicCase)
        await store.waitForPendingWork()
        #expect(store.result == nil && store.errorMessage != nil)
        #expect(!store.hasActiveWork)
    }

    @Test("Malformed cached checksum cannot be displayed as a source-bound result")
    func checksumBinding() async throws {
        let fixture = APFSUIFixture(), valid = try fixture.cache()
        let forged = APFSCacheReceipt(caseID: valid.receipt.caseID, evidenceID: valid.receipt.evidenceID,
            generationID: valid.receipt.generationID, resultSHA256: String(repeating: "0", count: 64),
            relativePath: valid.receipt.relativePath, serializedByteCount: valid.receipt.serializedByteCount,
            coverage: valid.receipt.coverage)
        let store = makeStore(load: { _, _ in APFSWorkspaceCache(result: valid.result, receipt: forged) })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.result == nil && store.errorMessage != nil)
    }

    @Test("Two layer credentials are cleared by capture and consumed only by their single inspection job")
    func credentialsAndSave() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIInspectionGate()
        let store = makeStore(inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        }, save: { result, _ in try fixture.cache(result: result).receipt })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.maximumEntries = 17
        var container = "synthetic-container-secret", volume = "synthetic-volume-secret"
        let captured = try APFSViewCredentialCapture.capture(container: &container, volume: &volume)
        #expect(container.isEmpty && volume.isEmpty)
        store.inspect(passphrase: captured.container, volumePassphrase: captured.volume)
        let task = try #require(store.activeTask); try await gate.waitStarted()
        #expect(store.state == .inspecting && store.hasActiveWork)
        #expect(await gate.credentialsMatched)
        #expect(await gate.maximumEntries == 17)
        let encrypted = fixture.result(options: APFSReadOptions(maximumEntries: 17), container: .encryptedDiskImage, volume: .diskUserAPFS)
        await gate.succeed(encrypted); await task.value
        #expect(store.result == encrypted && !store.isHistorical && !store.hasActiveWork)
        #expect(store.cacheReceipt != nil && store.errorMessage == nil)
        #expect(throws: APFSReadError.credentialConsumed) { _ = try captured.container?.consume() }
        #expect(throws: APFSReadError.credentialConsumed) { _ = try captured.volume?.consume(terminator: 10) }
        let saved = try JSONEncoder().encode(try #require(store.result))
        let text = try #require(String(data: saved, encoding: .utf8))
        #expect(!text.contains("synthetic-container-secret") && !text.contains("synthetic-volume-secret"))
    }

    @Test("Invalid capture clears both fields without embedding a credential in the error")
    func captureFailure() throws {
        var container = "valid-synthetic-secret", volume = "invalid\nsynthetic-secret"
        #expect(throws: APFSReadError.invalidCredential) {
            _ = try APFSViewCredentialCapture.capture(container: &container, volume: &volume)
        }
        #expect(container.isEmpty && volume.isEmpty)
        let store = makeStore(); store.rejectCredentialCapture()
        #expect(store.errorMessage?.contains("synthetic-secret") == false)
    }

    @Test("Disabled encrypted-layer controls never capture a stale hidden credential")
    func disabledCredentials() throws {
        var container = "hidden\nsynthetic-secret", volume = "hidden-volume-secret"
        let captured = try APFSViewCredentialCapture.capture(container: &container, volume: &volume,
            containerEnabled: false, volumeEnabled: false)
        #expect(captured.container == nil && captured.volume == nil)
        #expect(container.isEmpty && volume.isEmpty)
    }

    @Test("Volume discovery captures only the container key and clears an invalid unused volume field")
    func catalogCredentialCapture() throws {
        var container = "synthetic-wrapper-only", volume = "invalid-unused\nvolume-key"
        let key = try #require(APFSViewCredentialCapture.captureContainer(container: &container, volume: &volume, containerEnabled: true))
        #expect(container.isEmpty && volume.isEmpty)
        #expect(try key.consume() == Data("synthetic-wrapper-only\0".utf8))
        #expect(throws: APFSReadError.credentialConsumed) { _ = try key.consume() }
    }

    @Test("Failed refresh/inspection preserves the prior saved result and suppresses arbitrary diagnostics")
    func failurePreservesResult() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() }, inspect: { _, _, _, _ in
            throw NSError(domain: "fixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "/private/tmp/credential-value"])
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        let old = store.result; store.inspect(); await store.waitForPendingWork()
        #expect(store.result == old && store.isHistorical)
        #expect(store.errorMessage != nil && store.errorMessage?.contains("credential-value") == false)
        #expect(store.errorMessage?.contains("/private/") == false)
    }

    @Test("An inspection is not published in the UI when its cache save fails")
    func saveFailure() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() }, inspect: { _, _, _, _ in fixture.result(volumeUUID: UUID()) },
            save: { _, _ in throw APFSReadError.outputLimit })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        let old = store.result; store.inspect(); await store.waitForPendingWork()
        #expect(store.result == old && store.errorMessage != nil && !store.hasActiveWork)
    }

    @Test("Cancel keeps the resource owner until cleanup and never publishes a late uncommitted result")
    func cancelDrain() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIInspectionGate()
        let store = makeStore(inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); let task = try #require(store.activeTask); try await gate.waitStarted()
        store.cancel()
        #expect(store.state == .cancelling && store.hasActiveWork && !store.canInspect)
        await gate.succeed(fixture.result()); await task.value
        #expect(store.result == nil && !store.hasActiveWork && store.state == .idle)
    }

    @Test("Source replacement prevents a late old read from replacing the new historical cache")
    func sourceReplacement() async throws {
        let first = APFSUIFixture(), second = APFSUIFixture(), gate = APFSUIInspectionGate()
        let store = makeStore(load: { evidence, _ in
            if evidence.id == second.evidence.id { return try second.cache() }; return nil
        }, inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        })
        store.configure(evidence: first.evidence, in: first.forensicCase); await store.waitForPendingWork()
        store.inspect(); let oldTask = try #require(store.activeTask); try await gate.waitStarted()
        store.configure(evidence: second.evidence, in: second.forensicCase)
        let newTask = try #require(store.activeTask)
        #expect(store.result == nil && store.selectedEvidenceID == second.evidence.id && store.hasActiveWork)
        await gate.succeed(first.result()); await oldTask.value; await newTask.value
        #expect(store.result == second.result() && store.isHistorical && !store.hasActiveWork)
    }

    @Test("Preview bytes and export receipts cannot substitute another result or source")
    func previewAndExportBinding() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() }, preview: { _, _, _, _, _, _ in
            fixture.analysis(hash: String(repeating: "f", count: 64))
        }, export: { _, result, entry, forensicCase, _, _, _ in
            APFSExportReceipt(caseID: forensicCase.manifest.id, evidenceID: UUID(), volumeUUID: result.volumeUUID,
                relativePath: entry.relativePath, resultSHA256: try fixture.cache().receipt.resultSHA256,
                containerSHA256: fixture.evidence.sha256, byteCount: entry.byteCount, sha256: try #require(entry.sha256))
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath
        store.previewSelected(); await store.waitForPendingWork()
        #expect(store.analysis == nil && store.errorMessage != nil)
        store.exportSelected(to: URL(fileURLWithPath: "/synthetic/new-output.txt")); await store.waitForPendingWork()
        #expect(store.lastExport == nil && store.lastExportDestination == nil && store.errorMessage != nil)
    }

    @Test("Encrypted historical reads require new keys; plaintext previews and exports carry exact receipts")
    func verifiedActions() async throws {
        let fixture = APFSUIFixture()
        let encrypted = fixture.result(container: .encryptedDiskImage, volume: .diskUserAPFS)
        let store = makeStore(load: { _, _ in try fixture.cache(result: encrypted) }, preview: { _, _, _, _, _, _ in fixture.analysis() },
            export: { _, result, entry, forensicCase, _, _, _ in
                APFSExportReceipt(caseID: forensicCase.manifest.id, evidenceID: fixture.evidence.id,
                    volumeUUID: result.volumeUUID, relativePath: entry.relativePath,
                    resultSHA256: try fixture.cache(result: result).receipt.resultSHA256,
                    containerSHA256: fixture.evidence.sha256, byteCount: entry.byteCount, sha256: try #require(entry.sha256))
            })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath
        store.previewSelected(); #expect(!store.hasActiveWork && store.analysis == nil && store.errorMessage != nil)
        store.previewSelected(passphrase: try APFSPassphrase(Data("new-container".utf8)), volumePassphrase: try APFSPassphrase(Data("new-volume".utf8)))
        await store.waitForPendingWork(); #expect(store.analysis?.sourceSHA256 == fixture.entry.sha256)
        let destination = URL(fileURLWithPath: "/synthetic/new-output.txt")
        store.exportSelected(to: destination, passphrase: try APFSPassphrase(Data("another-container".utf8)), volumePassphrase: try APFSPassphrase(Data("another-volume".utf8)))
        await store.waitForPendingWork()
        #expect(store.lastExport?.sha256 == fixture.entry.sha256 && store.lastExportDestination == destination)
        #expect(!store.hasActiveWork && store.errorMessage == nil)
    }

    @Test("Shutdown drains the owner and reopening is explicit after a case change")
    func shutdown() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIInspectionGate()
        let store = makeStore(inspect: { evidence, options, container, volume in try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume) })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); try await gate.waitStarted()
        let drain = try #require(store.beginShutdown()); #expect(store.hasActiveWork && !store.canInspect)
        await gate.succeed(fixture.result()); await drain.value
        store.reset(); store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        #expect(!store.hasSource && !store.hasActiveWork)
        store.reset(reopen: true); store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await store.waitForPendingWork(); #expect(store.canInspect)
    }

    @Test("Filtering searches the whole inventory and clears an invisible selection")
    func filtering() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath; store.searchText = "folder"
        await store.waitForPendingWork()
        #expect(store.rows.count == 1 && store.rows.first?.kind == .directory && store.selectedEntryPath == nil)
    }

    @Test("UTC display preserves nanoseconds without rounding them into another second")
    func exactTimestampDisplay() {
        let entry = APFSFileEntry(relativePath: "known.txt", kind: .regular, inode: 12, byteCount: 0,
            sha256: nil, modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 999_999_999)
        #expect(APFSViewFormatting.modified(entry) == "2023-11-14T22:13:20.999999999Z")
    }

    @Test("Cache publication survives a separate job-provenance failure")
    func provenanceFailure() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(inspect: { _, _, _, _ in fixture.result() },
            save: { result, _ in try fixture.cache(result: result).receipt },
            recordProvenance: { _, _, _, _ in throw ForensicsError.staleCase })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); await store.waitForPendingWork()
        #expect(store.result == fixture.result() && store.cacheReceipt != nil && !store.isHistorical)
        #expect(store.errorMessage?.contains("inspection was saved") == true)
    }

    @Test("An explicitly migrated case receives the APFS job and callback; schema1 is not automatically migrated")
    func explicitProvenance() async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("NF-APFS-native-case-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("injected-UI-contract.img")
        try Data("Synthetic selected bytes for an injected workspace reader".utf8).write(to: source, options: .withoutOverwriting)
        let initial = try CaseStore.create(name: "APFS native provenance", in: root)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let version1 = try CaseStore.adding(image: inspected, to: initial)
        let evidence = try #require(version1.manifest.evidence.first)
        let fixture = APFSUIFixture(evidence: evidence, forensicCase: version1)
        let first = APFSWorkspaceStore(documentHelperURL: URL(fileURLWithPath: "/unused-decoder"), scheduler: ForensicWorkScheduler(),
            inspect: { _, _, _, _ in fixture.result() })
        first.configure(evidence: evidence, in: version1); await first.waitForPendingWork()
        first.inspect(); await first.waitForPendingWork()
        #expect(first.errorMessage == nil && first.cacheReceipt != nil)
        #expect(try CaseStore.open(at: version1.bundleURL).manifest.schemaVersion == 1)
        let migrated = try CaseStore.migrateToSchema2(version1)
        let callback = APFSUIUpdatedCase()
        let second = APFSWorkspaceStore(documentHelperURL: URL(fileURLWithPath: "/unused-decoder"), scheduler: ForensicWorkScheduler(),
            inspect: { _, _, _, _ in fixture.result() })
        second.caseDidUpdate = { _, value in callback.value = value; return true }
        second.configure(evidence: evidence, in: migrated); await second.waitForPendingWork()
        second.inspect(); await second.waitForPendingWork()
        let updated = try #require(callback.value)
        #expect(second.errorMessage == nil && updated.manifest.id == migrated.manifest.id)
        let jobs = try #require(updated.manifest.provenance).jobs
        #expect(jobs.count == 1 && jobs[0].kind == "apfs.allocated-inspection")
        #expect(jobs[0].artifactSHA256 == second.cacheReceipt?.resultSHA256)
        #expect(jobs[0].sourceHashes.first?.sha256 == evidence.sha256)
        #expect(!jobs[0].optionsJSON.contains(source.path))
        #expect(try CaseStore.open(at: updated.bundleURL).manifest == updated.manifest)
    }

    @Test("A late same-case provenance callback cannot replace a newer manifest revision")
    func lateCaseRevision() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIRecordGate(), callback = APFSUIUpdatedCase()
        let store = makeStore(inspect: { _, _, _, _ in fixture.result() },
            save: { result, _ in try fixture.cache(result: result).receipt },
            recordProvenance: { _, _, _, _ in try await gate.record() })
        store.caseDidUpdate = { _, value in callback.value = value; return true }
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); let task = try #require(store.activeTask); try await gate.waitStarted()
        let newer = fixture.caseRevision(name: "Newer case metadata")
        store.configure(evidence: fixture.evidence, in: newer)
        await gate.succeed(fixture.caseRevision(name: "Older queued publication")); await task.value
        #expect(callback.value == nil && store.result == fixture.result() && store.cacheReceipt != nil)
        #expect(store.statusMessage.contains("newer case revision"))
        #expect(!store.hasActiveWork)
    }

    @Test("A cancellation after cache commit retains the successful receipt")
    func postCommitCancel() async throws {
        let fixture = APFSUIFixture(), gate = APFSUISaveGate()
        let store = makeStore(inspect: { _, _, _, _ in fixture.result() }, save: { _, _ in try await gate.save() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); let task = try #require(store.activeTask); try await gate.waitStarted()
        store.cancel(); #expect(store.hasActiveWork && store.state == .cancelling)
        await gate.succeed(try fixture.cache().receipt); await task.value
        #expect(store.result == fixture.result() && store.cacheReceipt != nil && store.errorMessage == nil)
        #expect(store.statusMessage.contains("saved before cancellation") && store.state == .idle)
    }

    @Test("Published-but-unconfirmed cache is reported distinctly and can be reloaded")
    func durabilityUnconfirmed() async throws {
        let fixture = APFSUIFixture(), generation = UUID()
        let store = makeStore(inspect: { _, _, _, _ in fixture.result() }, save: { _, _ in
            throw CasePublicationError.publishedButDurabilityUnconfirmed(recordID: generation)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); await store.waitForPendingWork()
        #expect(store.result == nil && store.errorMessage?.contains(generation.uuidString.lowercased()) == true)
        #expect(store.statusMessage.contains("published") && store.statusMessage.contains("Reload"))
    }

    @Test("Filter cancellation returns to idle after its owner drains")
    func filterCancel() async throws {
        let fixture = APFSUIFixture(), store = makeStore(load: { _, _ in try fixture.cache() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.searchText = "folder"; store.cancel(); await store.waitForPendingWork()
        #expect(!store.hasActiveWork && !store.isFiltering && store.state == .idle && store.searchText.isEmpty)
        #expect(store.rows.count == fixture.result().entries.count)
    }

    @Test("A failure from the previous preview cannot label a newly selected entry")
    func replacedPreviewFailure() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIPreviewGate()
        let store = makeStore(load: { _, _ in try fixture.cache() }, preview: { _, _, _, _, _, _ in try await gate.preview() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath; store.previewSelected()
        let task = try #require(store.activeTask); try await gate.waitStarted()
        store.selectedEntryPath = "folder"
        await gate.fail(APFSReadError.sourceChanged); await task.value
        #expect(store.analysis == nil && store.errorMessage == nil && store.selectedEntryPath == "folder")
        #expect(!store.hasActiveWork && store.state == .idle)
        #expect(store.statusMessage.contains("entry changed"))
    }

    @Test("Unconfirmed preview cleanup prevents another preview in the same window")
    func cleanupQuarantine() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() }, preview: { _, _, _, _, _, _ in throw APFSPreviewError.cleanupIncomplete })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath; store.previewSelected(); await store.waitForPendingWork()
        #expect(!store.canPreview && store.analysis == nil)
        #expect(store.documentUnavailableReason == APFSPreviewError.cleanupIncomplete.localizedDescription)
        #expect(store.errorMessage == APFSPreviewError.cleanupIncomplete.localizedDescription)
    }

    @Test("A canceled superseded inspection retains its global quarantine notice while historical reload remains available")
    func supersededImageCleanupQuarantine() async throws {
        let first = APFSUIFixture(), second = APFSUIFixture(), gate = APFSUIInspectionGate()
        let store = makeStore(load: { evidence, _ in
            if evidence.id == second.evidence.id { return try second.cache() }
            return nil
        }, inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        })
        store.configure(evidence: first.evidence, in: first.forensicCase); await store.waitForPendingWork()
        store.inspect(); let oldTask = try #require(store.activeTask); try await gate.waitStarted()
        store.configure(evidence: second.evidence, in: second.forensicCase)
        let newTask = try #require(store.activeTask)
        await gate.fail(.cleanupIncomplete); await oldTask.value; await newTask.value
        #expect(store.cleanupUncertain && store.cleanupWarning?.contains("quarantine") == true)
        #expect(store.selectedEvidenceID == second.evidence.id && store.result == second.result() && store.isHistorical)
        #expect(store.errorMessage == nil && !store.hasActiveWork && store.state == .idle)
        store.selectedEntryPath = second.entry.relativePath
        #expect(!store.canInspect && !store.canPreview && !store.canExport)
        #expect(store.statusMessage.contains("Historical") && store.statusMessage.contains("blocked"))
        store.refresh(); await store.waitForPendingWork()
        #expect(store.result == second.result() && store.cleanupUncertain && !store.hasActiveWork)
        #expect(store.cleanupWarning?.contains("Reload Saved Result") == true)
        store.inspect(); store.previewSelected(); store.exportSelected(to: URL(fileURLWithPath: "/synthetic/blocked.txt"))
        #expect(!store.hasActiveWork && store.lastExport == nil && store.analysis == nil)
    }

    @Test("Shutdown drain records late image quarantine and reopening a case does not imply cleanup")
    func shutdownImageCleanupQuarantine() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIInspectionGate()
        let store = makeStore(load: { _, _ in try fixture.cache() }, inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.inspect(); try await gate.waitStarted()
        let drain = try #require(store.beginShutdown())
        #expect(store.hasActiveWork && !store.hasSource)
        await gate.fail(.cleanupIncomplete); await drain.value
        #expect(store.cleanupUncertain && store.cleanupWarning != nil && !store.hasActiveWork)
        #expect(store.result == nil && store.errorMessage == nil)
        #expect(!store.statusMessage.contains("canceled after owned image cleanup"))
        store.reset(reopen: true); store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath
        #expect(store.isHistorical && store.result == fixture.result() && store.cleanupUncertain)
        #expect(!store.canInspect && !store.canPreview && !store.canExport && !store.hasActiveWork)
        #expect(store.cleanupWarning?.contains("Reopening the case does not confirm cleanup") == true)
    }

    @Test("A late previous-entry image cleanup failure cannot be described as a clean stopped preview")
    func replacedPreviewImageCleanupQuarantine() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIPreviewGate()
        let store = makeStore(load: { _, _ in try fixture.cache() }, preview: { _, _, _, _, _, _ in try await gate.preview() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath; store.previewSelected()
        let task = try #require(store.activeTask); try await gate.waitStarted()
        store.selectedEntryPath = "folder"
        await gate.fail(.cleanupIncomplete); await task.value
        #expect(store.cleanupUncertain && !store.previewCleanupBlocked)
        #expect(store.analysis == nil && store.errorMessage == nil && store.selectedEntryPath == "folder")
        #expect(!store.hasActiveWork && store.state == .idle && !store.canInspect)
        #expect(store.statusMessage == (store.cleanupWarning ?? "") && !store.statusMessage.contains("preview stopped"))
    }

    @Test("Export image cleanup uncertainty blocks every further fresh APFS job")
    func exportImageCleanupQuarantine() async throws {
        let fixture = APFSUIFixture()
        let store = makeStore(load: { _, _ in try fixture.cache() }, export: { _, _, _, _, _, _, _ in throw APFSReadError.cleanupIncomplete })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedEntryPath = fixture.entry.relativePath
        store.exportSelected(to: URL(fileURLWithPath: "/synthetic/not-published.txt")); await store.waitForPendingWork()
        #expect(store.cleanupUncertain && !store.canInspect && !store.canPreview && !store.canExport)
        #expect(store.lastExport == nil && store.lastExportDestination == nil && !store.hasActiveWork)
        #expect(store.errorMessage == APFSReadError.cleanupIncomplete.localizedDescription)
    }

    @Test("Global workspace Cancel reaches the APFS owner, keeps busy until drain, and preserves late quarantine")
    func globalWorkspaceCancelDrainsAPFS() async throws {
        let fixture = APFSUIFixture(), gate = APFSUIInspectionGate()
        let scheduler = ForensicWorkScheduler()
        let apfs = makeStore(scheduler: scheduler, load: { _, _ in try fixture.cache() }, inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        })
        let workspace = WorkspaceStore(helperURL: URL(fileURLWithPath: "/unused-engine"), apfs: apfs, scheduler: scheduler)
        workspace.currentCase = fixture.forensicCase
        apfs.configure(evidence: fixture.evidence, in: fixture.forensicCase); await apfs.waitForPendingWork()
        let saved = apfs.result
        apfs.inspect(); let owner = try #require(apfs.activeTask); try await gate.waitStarted()
        #expect(workspace.isBusy && workspace.hasActiveWork && apfs.state == .inspecting)
        workspace.cancelCurrentJob()
        #expect(workspace.isBusy && workspace.hasActiveWork && apfs.hasActiveWork)
        #expect(apfs.state == .cancelling && !apfs.canInspect && !workspace.canInspectImage)
        #expect(apfs.result == saved && !apfs.cleanupUncertain)
        await gate.fail(.cleanupIncomplete); await owner.value
        #expect(await gate.cancellationObserved)
        #expect(!workspace.isBusy && !workspace.hasActiveWork && !apfs.hasActiveWork && apfs.state == .idle)
        #expect(apfs.result == saved && apfs.cleanupUncertain && apfs.cleanupWarning?.contains("quarantine") == true)
        #expect(apfs.errorMessage == APFSReadError.cleanupIncomplete.localizedDescription && !apfs.canInspect)
        #expect(!apfs.statusMessage.contains("canceled after owned image cleanup"))
    }

    @Test("Immediate APFS admission rejects a busy slot before credential capture without queueing a job")
    func immediateAdmissionBusy() async throws {
        let scheduler = ForensicWorkScheduler(), fixture = APFSUIFixture()
        let store = makeStore(scheduler: scheduler)
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        let blocker = try await scheduler.acquireImmediately(.filesystemAnalysis)
        var container = "uncaptured-container", volume = "uncaptured-volume"
        do {
            let permit = try await store.acquireImmediateAdmission()
            _ = try APFSViewCredentialCapture.capture(container: &container, volume: &volume)
            _ = await permit.release()
            Issue.record("A busy scheduler admitted credential capture")
        } catch { #expect(error as? ForensicSchedulingError == .busy) }
        #expect(container == "uncaptured-container" && volume == "uncaptured-volume")
        #expect(!store.hasActiveWork && store.state == .idle && store.errorMessage == nil)
        #expect(await scheduler.state().queuedKinds.isEmpty)
        _ = await blocker.release()
    }

    @Test("An admitted APFS owner retains its slot and policy through canceled cleanup and quarantine")
    func admittedOwnerDrain() async throws {
        let scheduler = ForensicWorkScheduler(), fixture = APFSUIFixture(), gate = APFSUIInspectionGate()
        await scheduler.updatePolicy(mode: .conserveEnergy, context: .init(powerSource: .battery))
        let store = makeStore(scheduler: scheduler, inspect: { evidence, options, container, volume in
            try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        let permit = try await store.acquireImmediateAdmission()
        #expect(store.inspect(permit: permit)); let owner = try #require(store.activeTask); try await gate.waitStarted()
        #expect(await gate.requestedPriority == .utility)
        store.cancel()
        #expect(await scheduler.state().active?.id == permit.admission.id)
        #expect(store.hasActiveWork && store.state == .cancelling)
        await gate.fail(.cleanupIncomplete); await owner.value
        #expect(store.cleanupUncertain && !store.hasActiveWork)
        #expect(await scheduler.state().active == nil)
        #expect(await permit.release() == false)
    }

    @Test("Admitted atomic cache publication retains its permit and committed truth after late cancellation")
    func admittedAtomicSave() async throws {
        let scheduler = ForensicWorkScheduler(), fixture = APFSUIFixture(), gate = APFSUISaveGate()
        let store = makeStore(scheduler: scheduler, inspect: { _, _, _, _ in fixture.result() }, save: { _, _ in try await gate.save() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        let permit = try await store.acquireImmediateAdmission()
        #expect(store.inspect(permit: permit)); let owner = try #require(store.activeTask); try await gate.waitStarted()
        store.cancel()
        #expect(await scheduler.state().active?.id == permit.admission.id)
        #expect(store.hasActiveWork && store.state == .cancelling)
        await gate.succeed(try fixture.cache().receipt); await owner.value
        #expect(await gate.cancellationObserved == false)
        #expect(store.result == fixture.result() && store.cacheReceipt != nil && store.errorMessage == nil)
        #expect(store.statusMessage.contains("saved before cancellation") && !store.hasActiveWork)
        #expect(await scheduler.state().active == nil)
    }

    @Test("A bounded two-volume catalog requires an explicit UUID and resets prior file actions on selection")
    func explicitVolumeSelection() async throws {
        let fixture = APFSUIFixture(), first = UUID(), second = UUID()
        let catalog = fixture.catalog(volumeUUIDs: [first, second])
        let store = makeStore(load: { _, _ in try fixture.cache() }, discover: { _, _, _ in catalog },
            inspect: { _, options, _, _ in fixture.result(options: options, volumeUUID: options.selectedVolumeUUID) },
            save: { value, _ in try fixture.cache(result: value).receipt })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.discoverVolumes()); await store.waitForPendingWork()
        #expect(store.volumeCatalog == catalog && !store.canInspect && store.canDiscoverVolumes)
        store.selectedVolumeUUID = second
        #expect(store.result == nil && store.cacheReceipt == nil && store.analysis == nil && store.canInspect)
        #expect(store.inspect()); await store.waitForPendingWork()
        #expect(store.result?.volumeUUID == second && store.result?.options.selectedVolumeUUID == second)
        store.selectedEntryPath = fixture.entry.relativePath
        #expect(store.canPreview && store.canExport)
        store.selectedVolumeUUID = first
        #expect(store.volumeCatalog == catalog && store.result == nil && !store.canPreview && !store.canExport)
        store.selectedVolumeUUID = UUID()
        #expect(!store.canInspect && store.canDiscoverVolumes)
    }

    @Test("A catalog from another source cannot become selectable volume metadata")
    func catalogSourceBinding() async throws {
        let fixture = APFSUIFixture(), wrong = APFSUIFixture()
        let store = makeStore(discover: { _, _, _ in wrong.catalog(volumeUUIDs: [UUID()]) })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.discoverVolumes()); await store.waitForPendingWork()
        #expect(store.volumeCatalog == nil && store.errorMessage == APFSReadError.invalidResult.localizedDescription)
    }

    @Test("Changing the chosen volume fences a late old allocated view without publishing it")
    func supersededVolumeInspection() async throws {
        let fixture = APFSUIFixture(), first = UUID(), second = UUID(), gate = APFSUIInspectionGate()
        let store = makeStore(discover: { _, _, _ in fixture.catalog(volumeUUIDs: [first, second]) },
            inspect: { evidence, options, container, volume in try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume) })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.discoverVolumes()); await store.waitForPendingWork(); store.selectedVolumeUUID = first
        #expect(store.inspect()); let old = try #require(store.activeTask); try await gate.waitStarted()
        store.selectedVolumeUUID = second
        await gate.succeed(fixture.result(options: APFSReadOptions(selectedVolumeUUID: first), volumeUUID: first)); await old.value
        #expect(store.selectedVolumeUUID == second && store.result == nil && store.errorMessage == nil && !store.hasActiveWork)
        #expect(await gate.selectedVolumeUUID == first)
    }

    @Test("A source-valid inspection of another requested UUID is rejected before its cache writer")
    func requestedVolumeBinding() async throws {
        let fixture = APFSUIFixture(), first = UUID(), second = UUID()
        let returned = fixture.result(options: APFSReadOptions(selectedVolumeUUID: first), volumeUUID: first)
        let writes = APFSUIWriteCounter()
        let store = makeStore(discover: { _, _, _ in fixture.catalog(volumeUUIDs: [first, second]) },
            inspect: { _, _, _, _ in returned }, save: { value, _ in
                await writes.record(); return try fixture.cache(result: value).receipt
            })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.discoverVolumes()); await store.waitForPendingWork(); store.selectedVolumeUUID = second
        #expect(store.inspect()); await store.waitForPendingWork()
        #expect(store.selectedVolumeUUID == second && store.result == nil && store.cacheReceipt == nil)
        #expect(store.errorMessage == APFSReadError.invalidResult.localizedDescription && !store.canPreview && !store.canExport)
        #expect(await writes.count == 0)
    }

    @Test("Snapshot choices retain historical inventory while a fresh admitted read records the exact selected tuple")
    func selectedSnapshotInspectionAndExport() async throws {
        let fixture = APFSUIFixture(), snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let current = fixture.result(snapshots: [snapshot])
        let store = makeStore(load: { _, _ in try fixture.cache(result: current) },
            inspect: { _, options, _, _ in fixture.result(options: options, snapshots: [snapshot], selectedSnapshot: snapshot) },
            save: { value, _ in try fixture.cache(result: value).receipt }, preview: { _, _, _, _, _, _ in fixture.analysis() },
            export: { _, value, entry, forensicCase, _, _, _ in
                APFSExportReceipt(caseID: forensicCase.manifest.id, evidenceID: fixture.evidence.id, volumeUUID: value.volumeUUID,
                    relativePath: entry.relativePath, resultSHA256: try fixture.cache(result: value).receipt.resultSHA256,
                    containerSHA256: fixture.evidence.sha256, byteCount: entry.byteCount, sha256: try #require(entry.sha256),
                    selectedSnapshot: value.selectedSnapshot)
            })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.snapshotInventory?.entries == [snapshot] && store.snapshotInventory?.isHistorical == true)
        #expect(store.selectedSnapshotUUID == nil && store.result?.selectedSnapshot == nil)
        store.selectedSnapshotUUID = snapshot.uuid
        #expect(store.result == nil && store.cacheReceipt == nil && !store.canPreview && !store.canExport)
        #expect(store.snapshotInventory?.entries == [snapshot] && store.canInspect)
        let inspectPermit = try await store.acquireImmediateAdmission()
        #expect(store.inspect(permit: inspectPermit)); await store.waitForPendingWork()
        #expect(store.result?.selectedSnapshot == snapshot && store.result?.options.selectedSnapshotUUID == snapshot.uuid)
        #expect(store.result?.volumeUUID == fixture.volumeUUID && store.snapshotInventory?.isHistorical == false)
        store.selectedEntryPath = fixture.entry.relativePath
        let previewPermit = try await store.acquireImmediateAdmission()
        #expect(store.previewSelected(permit: previewPermit)); await store.waitForPendingWork()
        #expect(store.analysis?.sourceSHA256 == fixture.entry.sha256)
        let exportPermit = try await store.acquireImmediateAdmission()
        #expect(store.exportSelected(to: URL(fileURLWithPath: "/synthetic/snapshot-output.txt"), permit: exportPermit))
        await store.waitForPendingWork()
        #expect(store.lastExport?.selectedSnapshot == snapshot && !store.hasActiveWork)
        store.selectedSnapshotUUID = nil
        #expect(store.result == nil && store.analysis == nil && store.lastExport == nil && store.snapshotInventory?.entries == [snapshot])
    }

    @Test("Unavailable snapshot inventory stays distinct from empty inventory and both Disk-user snapshot combinations remain bounded")
    func snapshotInventoryAvailabilityAndProfile() async throws {
        let fixture = APFSUIFixture(), snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        for available in [false, true] {
            let value = fixture.result(snapshotInventoryAvailable: available)
            let store = makeStore(load: { _, _ in try fixture.cache(result: value) })
            store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
            #expect(store.snapshotInventory?.isAvailable == available && store.snapshotInventory?.entries.isEmpty == true)
            #expect(store.canInspect && store.selectedSnapshotUUID == nil)
            store.selectedSnapshotUUID = snapshot.uuid
            #expect(!store.canInspect && store.snapshotSelectionUnavailableReason != nil)
        }
        for value in [fixture.result(volume: .diskUserAPFS, snapshots: [snapshot]),
                      fixture.result(container: .encryptedDiskImage, volume: .diskUserAPFS, snapshots: [snapshot])] {
            let store = makeStore(load: { _, _ in try fixture.cache(result: value) })
            store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
            store.selectedSnapshotUUID = snapshot.uuid
            #expect(!store.canInspect && store.snapshotSelectionUnavailableReason?.contains("unencrypted APFS volume") == true)
            store.selectedSnapshotUUID = nil; #expect(store.canInspect)
        }
    }

    @Test("An encrypted wrapper with a plain APFS snapshot forwards fresh single-use keys and resets current file actions")
    func encryptedWrapperSnapshotActions() async throws {
        let fixture = APFSUIFixture(), calls = APFSUIWrapperCredentialCalls(), scheduler = ForensicWorkScheduler()
        let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let current = fixture.result(options: APFSReadOptions(selectedVolumeUUID: fixture.volumeUUID),
                                     container: .encryptedDiskImage, snapshots: [snapshot])
        let store = makeStore(scheduler: scheduler, load: { _, _ in try fixture.cache(result: current) },
            inspect: { evidence, options, container, volume in
                try await calls.record("inspect", evidence: evidence, volumeUUID: options.selectedVolumeUUID,
                    snapshotUUID: options.selectedSnapshotUUID, snapshot: snapshot, container: container, volume: volume)
                return fixture.result(options: options, container: .encryptedDiskImage,
                                      snapshots: [snapshot], selectedSnapshot: snapshot)
            }, save: { value, _ in try fixture.cache(result: value).receipt },
            preview: { evidence, value, entry, container, volume, _ in
                try await calls.record("preview", evidence: evidence, volumeUUID: value.volumeUUID,
                    snapshotUUID: value.options.selectedSnapshotUUID, snapshot: value.selectedSnapshot,
                    entryPath: entry.relativePath, container: container, volume: volume)
                return fixture.analysis()
            }, export: { evidence, value, entry, forensicCase, _, container, volume in
                try await calls.record("export", evidence: evidence, volumeUUID: value.volumeUUID,
                    snapshotUUID: value.options.selectedSnapshotUUID, snapshot: value.selectedSnapshot,
                    entryPath: entry.relativePath, container: container, volume: volume)
                return APFSExportReceipt(caseID: forensicCase.manifest.id, evidenceID: evidence.id,
                    volumeUUID: value.volumeUUID, relativePath: entry.relativePath,
                    resultSHA256: try fixture.cache(result: value).receipt.resultSHA256,
                    containerSHA256: evidence.sha256, byteCount: entry.byteCount,
                    sha256: try #require(entry.sha256), selectedSnapshot: value.selectedSnapshot)
            })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        #expect(store.result == current && store.isHistorical && store.rows.count == 2)
        #expect(store.snapshotInventory?.containerEncryption == .encryptedDiskImage)
        #expect(store.snapshotInventory?.volumeEncryption == APFSVolumeEncryption.none)
        #expect(store.snapshotInventory?.evidenceID == fixture.evidence.id)
        #expect(store.snapshotInventory?.containerSHA256 == fixture.evidence.sha256)
        store.selectedSnapshotUUID = snapshot.uuid
        #expect(store.canInspect && store.snapshotSelectionUnavailableReason == nil)
        #expect(store.result == nil && store.rows.isEmpty && !store.canPreview && !store.canExport)
        let inspectKey = try APFSPassphrase(Data("synthetic-wrapper-secret".utf8))
        let inspectPermit = try await store.acquireImmediateAdmission()
        #expect(store.inspect(passphrase: inspectKey, permit: inspectPermit)); await store.waitForPendingWork()
        #expect(throws: APFSReadError.credentialConsumed) { _ = try inspectKey.consume() }
        #expect(store.result?.containerEncryption == .encryptedDiskImage && store.result?.volumeEncryption == APFSVolumeEncryption.none)
        #expect(store.result?.volumeUUID == fixture.volumeUUID && store.result?.selectedSnapshot == snapshot)
        #expect(store.result?.options.selectedVolumeUUID == fixture.volumeUUID)
        #expect(store.result?.options.selectedSnapshotUUID == snapshot.uuid && !store.isHistorical)
        #expect(store.snapshotInventory?.isHistorical == false && store.rows.count == 2)
        store.selectedEntryPath = fixture.entry.relativePath
        #expect(store.canPreview && store.canExport)
        #expect(!store.previewSelected() && !store.hasActiveWork && store.analysis == nil)
        #expect(await calls.observations.count == 1)
        let previewKey = try APFSPassphrase(Data("synthetic-wrapper-secret".utf8))
        let previewPermit = try await store.acquireImmediateAdmission()
        #expect(store.previewSelected(passphrase: previewKey, permit: previewPermit)); await store.waitForPendingWork()
        #expect(throws: APFSReadError.credentialConsumed) { _ = try previewKey.consume() }
        #expect(store.analysis?.sourceSHA256 == fixture.entry.sha256 && store.errorMessage == nil)
        let destination = URL(fileURLWithPath: "/synthetic/encrypted-snapshot-output.txt")
        #expect(!store.exportSelected(to: destination) && !store.hasActiveWork && store.lastExport == nil)
        #expect(await calls.observations.count == 2)
        let exportKey = try APFSPassphrase(Data("synthetic-wrapper-secret".utf8))
        let exportPermit = try await store.acquireImmediateAdmission()
        #expect(store.exportSelected(to: destination, passphrase: exportKey, permit: exportPermit))
        await store.waitForPendingWork()
        #expect(throws: APFSReadError.credentialConsumed) { _ = try exportKey.consume() }
        #expect(store.lastExport?.selectedSnapshot == snapshot && store.lastExportDestination == destination)
        #expect(store.lastExport?.evidenceID == fixture.evidence.id && store.lastExport?.volumeUUID == fixture.volumeUUID)
        #expect(store.lastExport?.containerSHA256 == fixture.evidence.sha256)
        #expect(store.lastExport?.resultSHA256 == store.cacheReceipt?.resultSHA256 && store.errorMessage == nil)
        let observed = await calls.observations
        #expect(observed.map(\.operation) == ["inspect", "preview", "export"])
        #expect(observed.allSatisfy { $0.evidenceID == fixture.evidence.id && $0.sourceSHA256 == fixture.evidence.sha256
            && $0.volumeUUID == fixture.volumeUUID && $0.snapshotUUID == snapshot.uuid && $0.snapshot == snapshot })
        #expect(observed.dropFirst().allSatisfy { $0.entryPath == fixture.entry.relativePath })
        let persisted = try JSONEncoder().encode(try #require(store.result))
        #expect(!String(decoding: persisted, as: UTF8.self).contains("synthetic-wrapper-secret"))
        store.selectedSnapshotUUID = nil
        #expect(store.result == nil && store.cacheReceipt == nil && store.rows.isEmpty && store.selectedEntryPath == nil)
        #expect(store.analysis == nil && store.lastExport == nil && store.lastExportDestination == nil)
        #expect(!store.canPreview && !store.canExport && store.canInspect && store.selectedVolumeUUID == fixture.volumeUUID)
        #expect(store.snapshotInventory?.entries == [snapshot] && store.snapshotInventory?.volumeUUID == fixture.volumeUUID)
        #expect(await scheduler.state().active == nil)
    }

    @Test("Encrypted snapshot cancellation drains the admitted owner and preserves prior or replacement source binding")
    func encryptedSnapshotCancellationBinding() async throws {
        for replaceSource in [false, true] {
            let first = APFSUIFixture(), second = APFSUIFixture(sourceHash: String(repeating: "b", count: 64))
            let gate = APFSUIInspectionGate(), calls = APFSUIWrapperCredentialCalls(), writes = APFSUIWriteCounter()
            let scheduler = ForensicWorkScheduler()
            let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
            let firstOptions = APFSReadOptions(selectedVolumeUUID: first.volumeUUID, selectedSnapshotUUID: snapshot.uuid)
            let prior = first.result(options: firstOptions, container: .encryptedDiskImage,
                                     snapshots: [snapshot], selectedSnapshot: snapshot)
            let replacement = second.result(options: APFSReadOptions(selectedVolumeUUID: second.volumeUUID),
                                            container: .encryptedDiskImage)
            let store = makeStore(scheduler: scheduler, load: { evidence, _ in
                if evidence.id == first.evidence.id { return try first.cache(result: prior) }
                if evidence.id == second.evidence.id { return try second.cache(result: replacement) }
                return nil
            }, inspect: { evidence, options, container, volume in
                try await calls.record("inspect", evidence: evidence, volumeUUID: options.selectedVolumeUUID,
                    snapshotUUID: options.selectedSnapshotUUID, snapshot: snapshot, container: container, volume: volume)
                return try await gate.inspect(evidence: evidence, options: options, container: nil, volume: nil)
            }, save: { value, _ in await writes.record(); return try first.cache(result: value).receipt })
            store.configure(evidence: first.evidence, in: first.forensicCase); await store.waitForPendingWork()
            #expect(store.result == prior && store.selectedSnapshotUUID == snapshot.uuid && store.canInspect)
            let key = try APFSPassphrase(Data("synthetic-wrapper-secret".utf8))
            let permit = try await store.acquireImmediateAdmission()
            #expect(store.inspect(passphrase: key, permit: permit))
            let owner = try #require(store.activeTask); try await gate.waitStarted()
            #expect(throws: APFSReadError.credentialConsumed) { _ = try key.consume() }
            store.cancel()
            #expect(store.hasActiveWork && store.state == .cancelling && !store.canInspect)
            #expect(await scheduler.state().active?.id == permit.admission.id)
            let replacementTask: Task<Void, Never>?
            if replaceSource {
                store.configure(evidence: second.evidence, in: second.forensicCase)
                replacementTask = try #require(store.activeTask)
                #expect(store.selectedEvidenceID == second.evidence.id && store.selectedCaseID == second.forensicCase.manifest.id)
                #expect(store.result == nil && store.rows.isEmpty && store.snapshotInventory == nil)
            } else {
                replacementTask = nil
                #expect(store.result == prior && store.isHistorical && store.selectedSnapshotUUID == snapshot.uuid)
            }
            #expect(store.hasActiveWork)
            #expect(await scheduler.state().active?.id == permit.admission.id)
            await gate.succeed(prior); await owner.value
            if let replacementTask { await replacementTask.value }
            #expect(await gate.cancellationObserved)
            #expect(await gate.selectedVolumeUUID == first.volumeUUID)
            #expect(await gate.selectedSnapshotUUID == snapshot.uuid)
            #expect(await writes.count == 0)
            #expect(await scheduler.state().active == nil)
            #expect(!store.hasActiveWork && !store.cleanupUncertain && store.errorMessage == nil && store.isHistorical)
            let expected = replaceSource ? replacement : prior
            let expectedFixture = replaceSource ? second : first
            #expect(store.result == expected && store.selectedEvidenceID == expectedFixture.evidence.id)
            #expect(store.selectedCaseID == expectedFixture.forensicCase.manifest.id && store.selectedVolumeUUID == expectedFixture.volumeUUID)
            #expect(store.snapshotInventory?.evidenceID == expectedFixture.evidence.id)
            #expect(store.snapshotInventory?.containerSHA256 == expectedFixture.evidence.sha256)
            #expect(store.selectedSnapshotUUID == expected.selectedSnapshot?.uuid && store.rows.count == 2)
            #expect(await calls.observations.count == 1)
            #expect(await permit.release() == false)
        }
    }

    @Test("Snapshot inventory and selection are cleared when their source or base volume changes")
    func snapshotSourceAndVolumeBinding() async throws {
        let fixture = APFSUIFixture(), other = APFSUIFixture(), snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let current = fixture.result(snapshots: [snapshot])
        let store = makeStore(load: { evidence, _ in
            if evidence.id == fixture.evidence.id { return try fixture.cache(result: current) }
            return nil
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedSnapshotUUID = snapshot.uuid; store.selectedVolumeUUID = UUID()
        #expect(store.snapshotInventory == nil && store.selectedSnapshotUUID == nil && store.result == nil)
        store.configure(evidence: other.evidence, in: other.forensicCase); await store.waitForPendingWork()
        #expect(store.snapshotInventory == nil && store.selectedSnapshotUUID == nil && store.selectedVolumeUUID == nil)
        store.selectedSnapshotUUID = snapshot.uuid
        #expect(!store.canInspect && store.snapshotSelectionUnavailableReason != nil)
    }

    @Test("An internally consistent but changed snapshot name or XID is rejected before atomic cache publication")
    func requestedSnapshotTupleBinding() async throws {
        let fixture = APFSUIFixture(), snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let current = fixture.result(snapshots: [snapshot])
        for wrong in [APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: "different-name", transactionID: 41),
                      APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: snapshot.name, transactionID: 42)] {
            let writes = APFSUIWriteCounter()
            let store = makeStore(load: { _, _ in try fixture.cache(result: current) },
                inspect: { _, options, _, _ in fixture.result(options: options, snapshots: [wrong], selectedSnapshot: wrong) },
                save: { value, _ in await writes.record(); return try fixture.cache(result: value).receipt })
            store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
            store.selectedSnapshotUUID = snapshot.uuid
            #expect(store.inspect()); await store.waitForPendingWork()
            #expect(store.result == nil && store.cacheReceipt == nil && store.errorMessage == APFSReadError.invalidResult.localizedDescription)
            #expect(await writes.count == 0)
        }
    }

    @Test("A snapshot export receipt cannot substitute current content or another name/XID with identical file hashes")
    func snapshotExportReceiptBinding() async throws {
        let fixture = APFSUIFixture(), snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let selected = fixture.result(options: APFSReadOptions(selectedSnapshotUUID: snapshot.uuid), snapshots: [snapshot], selectedSnapshot: snapshot)
        let wrong = APFSSnapshotInventoryEntry(uuid: snapshot.uuid, name: snapshot.name, transactionID: 42)
        for supplied in [APFSSnapshotInventoryEntry?.none, Optional(wrong)] {
            let store = makeStore(load: { _, _ in try fixture.cache(result: selected) }, export: { _, value, entry, forensicCase, _, _, _ in
                APFSExportReceipt(caseID: forensicCase.manifest.id, evidenceID: fixture.evidence.id, volumeUUID: value.volumeUUID,
                    relativePath: entry.relativePath, resultSHA256: try fixture.cache(result: value).receipt.resultSHA256,
                    containerSHA256: fixture.evidence.sha256, byteCount: entry.byteCount, sha256: try #require(entry.sha256), selectedSnapshot: supplied)
            })
            store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
            #expect(store.selectedSnapshotUUID == snapshot.uuid && store.isHistorical)
            store.selectedEntryPath = fixture.entry.relativePath
            #expect(store.exportSelected(to: URL(fileURLWithPath: "/synthetic/substituted.txt"))); await store.waitForPendingWork()
            #expect(store.lastExport == nil && store.lastExportDestination == nil && store.errorMessage == APFSReadError.invalidResult.localizedDescription)
        }
    }

    @Test("Changing a snapshot while an admitted read drains preserves late quarantine without adopting old content")
    func supersededSnapshotQuarantine() async throws {
        let fixture = APFSUIFixture(), scheduler = ForensicWorkScheduler(), gate = APFSUIInspectionGate()
        let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let current = fixture.result(snapshots: [snapshot])
        let store = makeStore(scheduler: scheduler, load: { _, _ in try fixture.cache(result: current) },
            inspect: { evidence, options, container, volume in try await gate.inspect(evidence: evidence, options: options, container: container, volume: volume) })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedSnapshotUUID = snapshot.uuid
        let permit = try await store.acquireImmediateAdmission()
        #expect(store.inspect(permit: permit)); let owner = try #require(store.activeTask); try await gate.waitStarted()
        store.selectedSnapshotUUID = nil
        #expect(store.hasActiveWork && !store.canInspect)
        #expect(await scheduler.state().active?.id == permit.admission.id)
        await gate.fail(.cleanupIncomplete); await owner.value
        #expect(store.result == nil && store.selectedSnapshotUUID == nil && store.errorMessage == nil)
        #expect(store.cleanupUncertain && store.cleanupWarning != nil && !store.hasActiveWork)
        #expect(await scheduler.state().active == nil)
        #expect(await gate.selectedSnapshotUUID == snapshot.uuid)
    }

    @Test("A snapshot cache receipt remains bound to its exact tuple after cancellation inside atomic publication")
    func snapshotAtomicPublicationAfterCancel() async throws {
        let fixture = APFSUIFixture(), scheduler = ForensicWorkScheduler(), gate = APFSUISaveGate()
        let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(), name: "known-before", transactionID: 41)
        let current = fixture.result(snapshots: [snapshot])
        let selected = fixture.result(options: APFSReadOptions(selectedSnapshotUUID: snapshot.uuid), snapshots: [snapshot], selectedSnapshot: snapshot)
        let store = makeStore(scheduler: scheduler, load: { _, _ in try fixture.cache(result: current) },
            inspect: { _, _, _, _ in selected }, save: { _, _ in try await gate.save() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase); await store.waitForPendingWork()
        store.selectedSnapshotUUID = snapshot.uuid
        let permit = try await store.acquireImmediateAdmission()
        #expect(store.inspect(permit: permit)); let owner = try #require(store.activeTask); try await gate.waitStarted()
        store.cancel(); #expect(store.hasActiveWork && store.state == .cancelling)
        #expect(await scheduler.state().active?.id == permit.admission.id)
        await gate.succeed(try fixture.cache(result: selected).receipt); await owner.value
        #expect(store.result == selected && store.cacheReceipt != nil && store.selectedSnapshotUUID == snapshot.uuid)
        #expect(store.statusMessage.contains("saved before cancellation") && store.errorMessage == nil && !store.hasActiveWork)
        #expect(await gate.cancellationObserved == false)
        #expect(await scheduler.state().active == nil)
    }

    private func makeStore(scheduler: ForensicWorkScheduler = ForensicWorkScheduler(),
                           load: APFSWorkspaceStore.Load? = nil, discover: APFSWorkspaceStore.Discover? = nil, inspect: APFSWorkspaceStore.Inspect? = nil,
                           save: APFSWorkspaceStore.Save? = nil, preview: APFSWorkspaceStore.Preview? = nil,
                           export: APFSWorkspaceStore.Export? = nil,
                           recordProvenance: APFSWorkspaceStore.RecordProvenance? = nil) -> APFSWorkspaceStore {
        APFSWorkspaceStore(documentHelperURL: URL(fileURLWithPath: "/unused-decoder"), scheduler: scheduler,
            load: load ?? { _, _ in nil }, discover: discover ?? { _, _, _ in throw APFSReadError.invalidResult },
            inspect: inspect ?? { _, _, _, _ in throw APFSReadError.unsupported("fixture") },
            save: save ?? { _, _ in throw APFSReadError.invalidResult },
            preview: preview ?? { _, _, _, _, _, _ in throw DocumentAnalysisError.unavailable },
            export: export ?? { _, _, _, _, _, _, _ in throw APFSReadError.fileUnavailable },
            recordProvenance: recordProvenance ?? { _, _, _, _ in nil })
    }
}

private struct APFSUIFixture: Sendable {
    let evidence: EvidenceRecord
    let forensicCase: ForensicCase
    let entry: APFSFileEntry
    let volumeUUID = UUID()
    init(sourceHash: String = String(repeating: "a", count: 64)) {
        let evidence = EvidenceRecord(sourcePath: "/synthetic/one.dmg", byteCount: 128, sha256: sourceHash, container: .unknown, filesystemHint: nil)
        self.init(evidence: evidence, forensicCase: ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/\(UUID().uuidString).nativecase"),
            manifest: CaseManifest(name: "Synthetic APFS", evidence: [evidence])))
    }
    init(evidence: EvidenceRecord, forensicCase: ForensicCase) {
        self.evidence = evidence; self.forensicCase = forensicCase
        let bytes = Data("Thai ภาษาไทย\n".utf8)
        entry = APFSFileEntry(relativePath: "known.txt", kind: .regular, inode: 12, byteCount: Int64(bytes.count),
            sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(), modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 2)
    }
    func result(options: APFSReadOptions = .init(), container: APFSContainerEncryption = .none,
                volume: APFSVolumeEncryption = .none, volumeUUID: UUID? = nil,
                snapshots: [APFSSnapshotInventoryEntry] = [], snapshotInventoryAvailable: Bool = true,
                selectedSnapshot: APFSSnapshotInventoryEntry? = nil) -> APFSInspectionResult {
        APFSInspectionResult(evidenceID: evidence.id, containerSHA256: evidence.sha256, containerByteCount: evidence.byteCount,
            driverVersion: "synthetic-native-workspace", options: options, volumeUUID: volumeUUID ?? self.volumeUUID,
            containerEncryption: container, volumeEncryption: volume, entries: [entry,
                APFSFileEntry(relativePath: "folder", kind: .directory, inode: 11, byteCount: 0, sha256: nil, modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 0)],
            snapshots: snapshots, snapshotInventoryAvailable: snapshotInventoryAvailable, coverage: .completeAllocatedView, warnings: [], selectedSnapshot: selectedSnapshot)
    }
    func cache(result: APFSInspectionResult? = nil) throws -> APFSWorkspaceCache {
        let result = result ?? self.result(), generation = UUID()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(result), hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let receipt = APFSCacheReceipt(caseID: forensicCase.manifest.id, evidenceID: evidence.id,
            generationID: generation, resultSHA256: hash,
            relativePath: "apfs/\(evidence.id.uuidString.lowercased())/generations/\(generation.uuidString.lowercased())/result.json",
            serializedByteCount: bytes.count, coverage: result.coverage)
        return APFSWorkspaceCache(result: result, receipt: receipt)
    }
    func catalog(volumeUUIDs: [UUID]) -> APFSVolumeCatalogResult {
        let container = UUID()
        return APFSVolumeCatalogResult(evidenceID: evidence.id, containerSHA256: evidence.sha256,
            containerByteCount: evidence.byteCount, driverVersion: "synthetic-native-workspace", containerEncryption: .none,
            volumes: volumeUUIDs.enumerated().map { index, id in
                APFSVolumeDescriptor(volumeUUID: id, containerUUID: container, name: "Synthetic \(index)", roles: [], encrypted: false, locked: false)
            })
    }
    func caseRevision(name: String) -> ForensicCase {
        let old = forensicCase.manifest
        return ForensicCase(bundleURL: forensicCase.bundleURL,
            manifest: CaseManifest(id: old.id, name: name, createdAt: old.createdAt, evidence: old.evidence,
                schemaVersion: old.schemaVersion, provenance: old.provenance))
    }
    func analysis(hash: String? = nil) -> DocumentAnalysis {
        DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded, sourceSHA256: hash ?? entry.sha256!,
            sourceByteCount: entry.byteCount, textPages: [.init(pageNumber: 1, text: "Thai ภาษาไทย\n")])
    }
}

@MainActor private final class APFSUIUpdatedCase { var value: ForensicCase? }

private actor APFSUIWriteCounter {
    private(set) var count = 0
    func record() { count += 1 }
}

/// Consumes only a known synthetic test credential and stores public operation
/// context, never the credential bytes. Native mount proof remains in Core's
/// independently measured opt-in integration oracles.
private actor APFSUIWrapperCredentialCalls {
    struct Observation: Sendable {
        let operation: String
        let evidenceID: UUID
        let sourceSHA256: String
        let volumeUUID: UUID?
        let snapshotUUID: UUID?
        let snapshot: APFSSnapshotInventoryEntry?
        let entryPath: String?
    }
    private(set) var observations: [Observation] = []
    func record(_ operation: String, evidence: EvidenceRecord, volumeUUID: UUID?, snapshotUUID: UUID?,
                snapshot: APFSSnapshotInventoryEntry?, entryPath: String? = nil,
                container: APFSPassphrase?, volume: APFSPassphrase?) throws {
        guard volume == nil, let container else { throw APFSReadError.invalidCredential }
        var bytes = try container.consume()
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard bytes == Data("synthetic-wrapper-secret\0".utf8) else { throw APFSReadError.invalidCredential }
        observations.append(Observation(operation: operation, evidenceID: evidence.id, sourceSHA256: evidence.sha256,
            volumeUUID: volumeUUID, snapshotUUID: snapshotUUID, snapshot: snapshot, entryPath: entryPath))
    }
}

private actor APFSUIInspectionGate {
    private var continuation: CheckedContinuation<APFSInspectionResult, Error>?
    private(set) var started = false
    private(set) var credentialsMatched = false
    private(set) var maximumEntries = 0
    private(set) var cancellationObserved = false
    private(set) var requestedPriority: ForensicWorkPriority?
    private(set) var selectedVolumeUUID: UUID?
    private(set) var selectedSnapshotUUID: UUID?
    func inspect(evidence: EvidenceRecord, options: APFSReadOptions, container: APFSPassphrase?, volume: APFSPassphrase?) async throws -> APFSInspectionResult {
        maximumEntries = options.maximumEntries
        requestedPriority = ForensicWorkExecutionContext.requestedPriority
        selectedVolumeUUID = options.selectedVolumeUUID
        selectedSnapshotUUID = options.selectedSnapshotUUID
        if let container, let volume {
            credentialsMatched = try container.consume() == Data("synthetic-container-secret\0".utf8)
                && volume.consume(terminator: 10) == Data("synthetic-volume-secret\n".utf8)
        }
        do {
            let value: APFSInspectionResult = try await withCheckedThrowingContinuation { continuation = $0; started = true }
            cancellationObserved = Task.isCancelled
            return value
        } catch {
            cancellationObserved = Task.isCancelled
            throw error
        }
    }
    func waitStarted() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !started {
            guard ContinuousClock.now < deadline else { throw APFSReadError.timeout }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    func succeed(_ value: APFSInspectionResult) { let held = continuation; continuation = nil; held?.resume(returning: value) }
    func fail(_ error: APFSReadError) { let held = continuation; continuation = nil; held?.resume(throwing: error) }
}

private actor APFSUIRecordGate {
    private var continuation: CheckedContinuation<ForensicCase?, Error>?
    private var started = false
    func record() async throws -> ForensicCase? { try await withCheckedThrowingContinuation { continuation = $0; started = true } }
    func waitStarted() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !started { guard ContinuousClock.now < deadline else { throw APFSReadError.timeout }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func succeed(_ value: ForensicCase) { let held = continuation; continuation = nil; held?.resume(returning: value) }
}
private actor APFSUISaveGate {
    private var continuation: CheckedContinuation<APFSCacheReceipt, Error>?
    private var started = false
    private(set) var cancellationObserved = false
    func save() async throws -> APFSCacheReceipt {
        let value: APFSCacheReceipt = try await withCheckedThrowingContinuation { continuation = $0; started = true }
        cancellationObserved = Task.isCancelled
        return value
    }
    func waitStarted() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !started { guard ContinuousClock.now < deadline else { throw APFSReadError.timeout }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func succeed(_ value: APFSCacheReceipt) { let held = continuation; continuation = nil; held?.resume(returning: value) }
}
private actor APFSUIPreviewGate {
    private var continuation: CheckedContinuation<DocumentAnalysis, Error>?
    private var started = false
    func preview() async throws -> DocumentAnalysis { try await withCheckedThrowingContinuation { continuation = $0; started = true } }
    func waitStarted() async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !started { guard ContinuousClock.now < deadline else { throw APFSReadError.timeout }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func fail(_ error: APFSReadError) { let held = continuation; continuation = nil; held?.resume(throwing: error) }
}
