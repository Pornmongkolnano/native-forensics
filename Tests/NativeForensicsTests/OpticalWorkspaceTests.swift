import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("OpticalWorkspaceTests")
@MainActor
struct OpticalWorkspaceTests {
    @Test("Current and deleted-ancestor records remain distinct without inventing a deleted child FID")
    func namespaceStates() async throws {
        let fixture = OpticalUIFixture()
        let store = makeStore(load: { _, _ in fixture.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        #expect(store.rows.count == 2)
        #expect(store.rows[0].state == .current)
        let old = store.rows[1]
        #expect(old.state == .historicalDeletedAncestor)
        #expect(old.fidCharacteristics == 0)
        #expect(old.deletedAncestorProof[0].fidCharacteristics == 0x06)
        #expect(old.deletedAncestorProof[0].nullICB)
        #expect(old.timestamps.creation == nil)
        #expect(old.timestamps.modification.timezoneMinutes == nil)
        #expect(old.timestamps.modification.utcDate == nil)
        #expect(store.canInspect)
        #expect(store.analysis == nil)
    }

    @Test("Late UDF receipt loads cannot populate another selected source or case")
    func sourceReplacement() async throws {
        let first = OpticalUIFixture(), second = OpticalUIFixture()
        let gate = OpticalResultGate()
        let store = makeStore(load: { evidence, _ in try await gate.load(evidence.id) })
        store.configure(evidence: first.evidence, in: first.forensicCase)
        let firstTask = try #require(store.activeTask)
        let old = await gate.nextRequest()
        store.configure(evidence: second.evidence, in: second.forensicCase)
        let secondTask = try #require(store.activeTask)
        #expect(store.hasActiveWork)
        await gate.succeed(old, first.result)
        await firstTask.value
        let latest = await gate.nextRequest()
        #expect(latest.evidenceID == second.evidence.id)
        await gate.succeed(latest, second.result)
        await secondTask.value
        #expect(store.result == second.result)
        #expect(!store.hasActiveWork)
    }

    @Test("A receipt from another source is rejected before showing original UDF paths")
    func wrongSourceReceipt() async throws {
        let fixture = OpticalUIFixture(), other = OpticalUIFixture()
        let store = makeStore(load: { _, _ in other.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        #expect(store.result == nil)
        #expect(store.rows.isEmpty)
        #expect(store.errorMessage != nil)
    }

    @Test("History filtering includes ancestor-deleted paths and removes stale selections")
    func historyFilter() async throws {
        let fixture = OpticalUIFixture()
        let store = makeStore(load: { _, _ in fixture.result })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.selectedEntryID = fixture.result.entries[0].id
        store.stateFilter = .current
        let first = try #require(store.filterTask)
        store.stateFilter = .deletedAncestor
        store.searchText = "หลักฐาน"
        let latest = try #require(store.filterTask)
        await first.value
        await latest.value
        #expect(store.rows == [fixture.result.entries[1]])
        #expect(store.selectedEntryID == nil)
        #expect(!store.hasActiveWork)
    }

    @Test("Late commit after a cancel request remains visible as a saved receipt")
    func canceledInspectionCommit() async throws {
        let fixture = OpticalUIFixture()
        let gate = OpticalResultGate()
        let store = makeStore(load: { _, _ in nil }, inspect: { evidence, _, _, _ in try await gate.load(evidence.id) })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.inspect()
        let task = try #require(store.activeTask)
        let request = await gate.nextRequest()
        store.cancel()
        #expect(store.hasActiveWork)
        await gate.succeed(request, fixture.result)
        await task.value
        #expect(store.result == fixture.result)
        #expect(store.statusMessage.contains("saved before cancellation"))
        #expect(!store.hasActiveWork)
    }

    @Test("A decoder response for a different UDF file fails its byte identity check")
    func previewMismatch() async throws {
        let fixture = OpticalUIFixture()
        let store = makeStore(load: { _, _ in fixture.result }, analyze: { entry, _, _, _ in
            DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
                sourceSHA256: String(repeating: "f", count: 64), sourceByteCount: entry.byteCount,
                textPages: [DocumentTextPage(pageNumber: 1, text: "foreign")])
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.selectedEntryID = fixture.result.entries[0].id
        store.previewSelected()
        await (try #require(store.activeTask)).value
        #expect(store.analysis == nil)
        #expect(store.analyses.isEmpty)
        #expect(store.errorMessage == DocumentAnalysisError.integrityMismatch.localizedDescription)
    }

    @Test("Closing drains the decoder owner and suppresses its delayed selected-file result")
    func previewShutdown() async throws {
        let fixture = OpticalUIFixture()
        let gate = OpticalAnalysisGate()
        let store = makeStore(load: { _, _ in fixture.result }, analyze: { _, _, _, _ in try await gate.load() })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        let entry = fixture.result.entries[0]
        store.selectedEntryID = entry.id
        store.previewSelected()
        await gate.waitUntilRequested()
        let shutdown = try #require(store.beginShutdown())
        #expect(store.hasActiveWork)
        #expect(!store.canPreview)
        await gate.succeed(DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: entry.sha256, sourceByteCount: entry.byteCount,
            textPages: [DocumentTextPage(pageNumber: 1, text: "delayed")]))
        await shutdown.value
        #expect(!store.hasActiveWork)
        #expect(store.analysis == nil)
    }

    @Test("Export confirmation rejects a valid hash attached to the wrong UDF generation")
    func exportReceiptMismatch() async throws {
        let fixture = OpticalUIFixture()
        let store = makeStore(load: { _, _ in fixture.result }, export: { entry, result, _, output in
            UDFExportReceipt(caseID: result.caseID, sourceEvidenceID: result.sourceEvidenceID, jobID: UUID(),
                entryID: entry.id, destinationPath: output.path, byteCount: entry.byteCount,
                sha256: entry.sha256, sourceSHA256: result.sourceSHA256)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.selectedEntryID = fixture.result.entries[0].id
        store.exportSelected(to: URL(fileURLWithPath: "/synthetic/new-export.txt"))
        await (try #require(store.activeTask)).value
        #expect(store.lastExport == nil)
        #expect(store.errorMessage != nil)
    }

    @Test("Autopsy export includes the full inventory despite a filtered table and selected row")
    func autopsyExportWholeInventory() async throws {
        let fixture = OpticalUIFixture(), destination = URL(fileURLWithPath: "/synthetic/new-udf-export")
        let gate = OpticalAutopsyExportGate()
        let store = makeStore(load: { _, _ in fixture.result }, exportForAutopsy: { evidence, result, forensicCase, output, progress in
            try await gate.export(evidence: evidence, result: result, forensicCase: forensicCase, output: output, progress: progress)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.stateFilter = .current
        await (try #require(store.filterTask)).value
        store.selectedEntryID = fixture.result.entries[0].id
        #expect(store.rows.count == 1)
        store.exportForAutopsy(to: destination)
        let owner = try #require(store.activeTask)
        let request = await gate.nextRequest()
        #expect(request.result == fixture.result)
        #expect(request.evidence == fixture.evidence)
        #expect(request.caseID == fixture.forensicCase.manifest.id)
        #expect(request.output == destination)
        #expect(store.isExportingAutopsy)
        #expect(!store.canInspect && !store.canExport && !store.canExportReport && !store.canPreview)
        await gate.succeed(request, try makeAutopsyReceipt(fixture.result, destination: destination))
        await owner.value
        #expect(store.lastAutopsyExport?.entries.count == 2)
        #expect(store.result == fixture.result)
        #expect(store.selectedEntryID == fixture.result.entries[0].id)
        #expect(store.errorMessage == nil)
        #expect(!store.hasActiveWork && !store.isExportingAutopsy)
        #expect(store.canExportForAutopsy)
    }

    @Test("A source change suppresses the old Autopsy export receipt and progress while draining its owner")
    func autopsyExportSourceReplacement() async throws {
        let first = OpticalUIFixture(), second = OpticalUIFixture()
        let destination = URL(fileURLWithPath: "/synthetic/source-one-export")
        let gate = OpticalAutopsyExportGate()
        let store = makeStore(load: { evidence, _ in evidence.id == first.evidence.id ? first.result : second.result },
            exportForAutopsy: { evidence, result, forensicCase, output, progress in
                try await gate.export(evidence: evidence, result: result, forensicCase: forensicCase, output: output, progress: progress)
            })
        store.configure(evidence: first.evidence, in: first.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy(to: destination)
        let oldOwner = try #require(store.activeTask)
        let old = await gate.nextRequest()
        store.configure(evidence: second.evidence, in: second.forensicCase)
        let newOwner = try #require(store.activeTask)
        #expect(store.hasActiveWork)
        await gate.report(old, .init(stage: "Foreign progress", completedBytes: 1, totalBytes: 2))
        await gate.succeed(old, try makeAutopsyReceipt(first.result, destination: destination))
        await oldOwner.value
        await newOwner.value
        #expect(store.result == second.result)
        #expect(store.lastAutopsyExport == nil && store.autopsyExportDestination == nil)
        #expect(store.progress == nil)
        #expect(store.errorMessage == nil)
        #expect(!store.hasActiveWork)
    }

    @Test("Autopsy export cancellation drains staging work and permits a new destination retry")
    func autopsyExportCancelAndRetry() async throws {
        let fixture = OpticalUIFixture(), gate = OpticalAutopsyExportGate()
        let store = makeStore(load: { _, _ in fixture.result }, exportForAutopsy: { evidence, result, forensicCase, output, progress in
            try await gate.export(evidence: evidence, result: result, forensicCase: forensicCase, output: output, progress: progress)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy(to: URL(fileURLWithPath: "/synthetic/canceled-output"))
        let firstOwner = try #require(store.activeTask), first = await gate.nextRequest()
        store.cancel()
        #expect(store.hasActiveWork && !store.canExportForAutopsy)
        await gate.fail(first, CancellationError())
        await firstOwner.value
        #expect(store.lastAutopsyExport == nil && store.errorMessage == nil)
        #expect(store.statusMessage.contains("canceled"))
        #expect(store.canExportForAutopsy)
        let retryDestination = URL(fileURLWithPath: "/synthetic/retry-output")
        store.exportForAutopsy(to: retryDestination)
        let retryOwner = try #require(store.activeTask), retry = await gate.nextRequest()
        await gate.succeed(retry, try makeAutopsyReceipt(fixture.result, destination: retryDestination))
        await retryOwner.value
        #expect(store.lastAutopsyExport?.destinationPath == retryDestination.path)
        #expect(store.errorMessage == nil)
    }

    @Test("A successful atomic export remains visible when cancellation arrives after publication")
    func autopsyExportLateCancelCommit() async throws {
        let fixture = OpticalUIFixture(), gate = OpticalAutopsyExportGate()
        let destination = URL(fileURLWithPath: "/synthetic/committed-output")
        let store = makeStore(load: { _, _ in fixture.result }, exportForAutopsy: { evidence, result, forensicCase, output, progress in
            try await gate.export(evidence: evidence, result: result, forensicCase: forensicCase, output: output, progress: progress)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy(to: destination)
        let owner = try #require(store.activeTask), request = await gate.nextRequest()
        store.cancel()
        await gate.succeed(request, try makeAutopsyReceipt(fixture.result, destination: destination))
        await owner.value
        #expect(store.lastAutopsyExport != nil)
        #expect(store.statusMessage.contains("completed before cancellation"))
        #expect(!store.hasActiveWork)
    }

    @Test("Shutdown waits for Autopsy export cleanup and suppresses its completed UI result")
    func autopsyExportShutdown() async throws {
        let fixture = OpticalUIFixture(), gate = OpticalAutopsyExportGate()
        let destination = URL(fileURLWithPath: "/synthetic/shutdown-output")
        let store = makeStore(load: { _, _ in fixture.result }, exportForAutopsy: { evidence, result, forensicCase, output, progress in
            try await gate.export(evidence: evidence, result: result, forensicCase: forensicCase, output: output, progress: progress)
        })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy(to: destination)
        let request = await gate.nextRequest()
        let shutdown = try #require(store.beginShutdown())
        #expect(store.hasActiveWork && !store.canExportForAutopsy)
        await gate.succeed(request, try makeAutopsyReceipt(fixture.result, destination: destination))
        await shutdown.value
        #expect(!store.hasActiveWork && store.lastAutopsyExport == nil)
    }

    @Test("Invalid source, payload, history and destination bindings cannot produce an Autopsy success receipt", arguments: AutopsyReceiptFault.allCases)
    fileprivate func autopsyExportRejectsReceipt(_ fault: AutopsyReceiptFault) async throws {
        let fixture = OpticalUIFixture(), destination = URL(fileURLWithPath: "/synthetic/bad-receipt-output")
        let receipt = try makeAutopsyReceipt(fixture.result, destination: destination, fault: fault)
        let store = makeStore(load: { _, _ in fixture.result }, exportForAutopsy: { _, _, _, _, _ in receipt })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy(to: destination)
        await (try #require(store.activeTask)).value
        #expect(store.lastAutopsyExport == nil)
        #expect(store.errorMessage != nil)
        #expect(store.result == fixture.result)
        #expect(store.canExportForAutopsy)
    }

    @Test("A late destination chooser cannot export after the source selection changes")
    func autopsyExportStaleChooser() async throws {
        let first = OpticalUIFixture(), second = OpticalUIFixture(), chooser = OpticalDestinationGate()
        let calls = OpticalExportCallCounter()
        let store = makeStore(load: { evidence, _ in evidence.id == first.evidence.id ? first.result : second.result },
            exportForAutopsy: { _, _, _, _, _ in await calls.record(); throw CancellationError() },
            chooseAutopsyDestination: { await chooser.choose() })
        store.configure(evidence: first.evidence, in: first.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy()
        await chooser.waitUntilRequested()
        let oldOwner = try #require(store.activeTask)
        store.configure(evidence: second.evidence, in: second.forensicCase)
        let newOwner = try #require(store.activeTask)
        await chooser.finish(URL(fileURLWithPath: "/synthetic/stale-chooser-output"))
        await oldOwner.value
        await newOwner.value
        #expect(await calls.count == 0)
        #expect(store.result == second.result)
        #expect(store.lastAutopsyExport == nil && store.errorMessage == nil)
    }

    @Test("Canceling the folder chooser never starts the source exporter")
    func autopsyExportChooserCancel() async throws {
        let fixture = OpticalUIFixture(), calls = OpticalExportCallCounter()
        let store = makeStore(load: { _, _ in fixture.result }, exportForAutopsy: { _, _, _, _, _ in
            await calls.record(); throw CancellationError()
        }, chooseAutopsyDestination: { nil })
        store.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(store.activeTask)).value
        store.exportForAutopsy()
        await (try #require(store.activeTask)).value
        #expect(await calls.count == 0)
        #expect(store.lastAutopsyExport == nil && store.errorMessage == nil)
        #expect(store.statusMessage.contains("No export was started"))
        #expect(store.canExportForAutopsy)
    }

    @Test("An existing file or forensic case path is never replaced by an Autopsy export")
    func autopsyExportProtectedDestination() throws {
        let fixture = OpticalUIFixture()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("Synthetic-UDF-UI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let existing = root.appendingPathComponent("existing-output")
        let marker = Data("existing synthetic export".utf8)
        try marker.write(to: existing)
        #expect(throws: (any Error).self) {
            try OpticalAutopsyExportService.validateDestination(existing, evidence: fixture.evidence, forensicCase: fixture.forensicCase)
        }
        #expect(try Data(contentsOf: existing) == marker)
        #expect(throws: (any Error).self) {
            try OpticalAutopsyExportService.validateDestination(fixture.forensicCase.bundleURL.appendingPathComponent("Output"),
                evidence: fixture.evidence, forensicCase: fixture.forensicCase)
        }
        #expect(throws: (any Error).self) {
            try OpticalAutopsyExportService.validateDestination(root.appendingPathComponent("Other.nativecase/Output"),
                evidence: fixture.evidence, forensicCase: fixture.forensicCase)
        }
    }

    @Test("Whole-source exports require a standard complete UDF receipt and respect workspace busy state")
    func autopsyExportEligibility() async throws {
        let fixture = OpticalUIFixture()
        let store = makeStore(load: { _, _ in fixture.result })
        #expect(!store.canExportForAutopsy)
        let workspace = WorkspaceStore(optical: store)
        workspace.currentCase = fixture.forensicCase
        workspace.selectedEvidenceID = fixture.evidence.id
        await (try #require(store.activeTask)).value
        #expect(workspace.canExportOpticalForAutopsy)
        workspace.isInspecting = true
        #expect(!workspace.canExportOpticalForAutopsy)
        workspace.isInspecting = false
        var fields = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(fixture.result)) as? [String: Any])
        var options = try #require(fields["options"] as? [String: Any])
        options["maximumFiles"] = 1
        fields["options"] = options
        let limited = try JSONDecoder().decode(UDFInspectionResult.self, from: JSONSerialization.data(withJSONObject: fields))
        let limitedStore = makeStore(load: { _, _ in limited })
        limitedStore.configure(evidence: fixture.evidence, in: fixture.forensicCase)
        await (try #require(limitedStore.activeTask)).value
        #expect(!limitedStore.canExportForAutopsy)
        #expect(limitedStore.autopsyExportUnavailableReason?.contains("custom bounded inventory") == true)
    }

    @Test("File-count progress does not present completed files as evidence bytes")
    func autopsyProgressUnits() {
        let description = OpticalViewFormatting.progressDescription(.init(stage: "Exporting verified file 2/20",
            completedBytes: 1, totalBytes: 20, files: 1))
        #expect(description.contains("1 / 20 files"))
        #expect(!description.contains("bytes") && !description.contains("B /"))
    }

    private func makeStore(load: @escaping OpticalWorkspaceStore.Load, inspect: OpticalWorkspaceStore.Inspect? = nil,
                           analyze: OpticalWorkspaceStore.Analyze? = nil, export: OpticalWorkspaceStore.Export? = nil,
                           exportForAutopsy: OpticalWorkspaceStore.ExportForAutopsy? = nil,
                           chooseAutopsyDestination: OpticalWorkspaceStore.ChooseAutopsyDestination? = nil) -> OpticalWorkspaceStore {
        OpticalWorkspaceStore(documentHelperURL: URL(fileURLWithPath: "/usr/bin/true"), load: load,
            inspect: inspect, analyze: analyze, export: export, exportForAutopsy: exportForAutopsy,
            chooseAutopsyDestination: chooseAutopsyDestination)
    }
}

private struct OpticalUIFixture: Sendable {
    let evidence: EvidenceRecord
    let forensicCase: ForensicCase
    let result: UDFInspectionResult
    init() {
        evidence = EvidenceRecord(sourcePath: "/synthetic/optical.dd", byteCount: 65536,
            sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
        let caseID = UUID()
        forensicCase = ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/\(caseID).nativecase"),
            manifest: CaseManifest(id: caseID, name: "Synthetic Optical", evidence: [evidence]))
        let unzoned = UDFTimestamp(rawHex: "000000000000000000000000", sourceOffset: 4096,
            type: 1, timezoneMinutes: nil, utcDate: nil, microsecond: 0)
        let proof = UDFDeletedAncestorProof(originalPath: "/removed", latestSnapshotID: "latest", fidSourceOffset: 8192,
            fidCharacteristics: 0x06, nullICB: true, rawNameHex: "0872656d6f766564")
        func entry(_ id: String, path: String, state: UDFEntryState, address: Int64) -> UDFFileEntry {
            UDFFileEntry(id: id, originalPath: path, state: state, fidCharacteristics: 0, fidSourceOffset: address,
                deletedAncestorProof: state == .historicalDeletedAncestor ? [proof] : [], byteCount: 12,
                sha256: String(repeating: id == "current" ? "b" : "c", count: 64),
                icb: UDFEntryAddress(logicalBlock: 2, partitionReference: 1, sourceOffset: address, tagIdentifier: 261),
                sourceExtents: [UDFSourceExtent(offset: address + 2048, byteCount: 12)],
                timestamps: UDFEntryTimestamps(access: unzoned, modification: unzoned, attribute: unzoned, creation: nil),
                snapshotIDs: [state == .current ? "latest" : "older"])
        }
        let entries = [entry("current", path: "/current.txt", state: .current, address: 16384),
                       entry("historical", path: "/removed/หลักฐาน.txt", state: .historicalDeletedAncestor, address: 24576)]
        let snapshots = [UDFSnapshot(id: "latest", vatICBSourceOffset: 32768, previousVATLogicalBlock: 2,
            mappedBlockCount: 10, namespaceFileCount: 1, modification: unzoned),
            UDFSnapshot(id: "older", vatICBSourceOffset: 34816, previousVATLogicalBlock: nil,
                mappedBlockCount: 10, namespaceFileCount: 2, modification: unzoned)]
        result = UDFInspectionResult(caseID: caseID, sourceEvidenceID: evidence.id, sourceSHA256: evidence.sha256,
            sourceByteCount: evidence.byteCount, volumeIdentifier: "Synthetic UDF", udfRevision: "2.01",
            latestSnapshotID: "latest", snapshots: snapshots, entries: entries, deletedAncestors: [proof],
            limitations: ["Synthetic UI receipt only"], options: UDFInspectionOptions())
    }
}

private actor OpticalResultGate {
    struct Request: Sendable { let id: UUID; let evidenceID: UUID }
    private var queued: [Request] = []
    private var waiting: [CheckedContinuation<Request, Never>] = []
    private var responses: [UUID: CheckedContinuation<UDFInspectionResult, Error>] = [:]
    func load(_ evidenceID: UUID) async throws -> UDFInspectionResult {
        let request = Request(id: UUID(), evidenceID: evidenceID)
        return try await withCheckedThrowingContinuation { continuation in
            responses[request.id] = continuation
            if waiting.isEmpty { queued.append(request) } else { waiting.removeFirst().resume(returning: request) }
        }
    }
    func nextRequest() async -> Request { if !queued.isEmpty { return queued.removeFirst() }; return await withCheckedContinuation { waiting.append($0) } }
    func succeed(_ request: Request, _ result: UDFInspectionResult) { responses.removeValue(forKey: request.id)?.resume(returning: result) }
}
private actor OpticalAnalysisGate {
    private var response: CheckedContinuation<DocumentAnalysis, Error>?
    private var waiter: CheckedContinuation<Void, Never>?
    func load() async throws -> DocumentAnalysis {
        try await withCheckedThrowingContinuation { response = $0; waiter?.resume(); waiter = nil }
    }
    func waitUntilRequested() async { if response != nil { return }; await withCheckedContinuation { waiter = $0 } }
    func succeed(_ result: DocumentAnalysis) { response?.resume(returning: result); response = nil }
}

private enum AutopsyReceiptFault: CaseIterable, Sendable {
    case sourceHash, sourceSize, missingFile, changedPayload, changedHistory, duplicateID, duplicatePath, escapedPath, destination
}

private func makeAutopsyReceipt(_ result: UDFInspectionResult, destination: URL,
    fault: AutopsyReceiptFault? = nil) throws -> UDFLogicalFilesExport {
    var entries: [[String: Any]] = result.entries.map { entry in
        ["entryID": entry.id, "originalPath": entry.originalPath,
         "outputRelativePath": "LogicalFiles/\(entry.state.rawValue)/\(entry.id)/payload",
         "pathMapping": "synthetic", "state": entry.state.rawValue,
         "snapshotIDs": entry.snapshotIDs, "byteCount": entry.byteCount, "sha256": entry.sha256]
    }
    switch fault {
    case .missingFile: entries.removeLast()
    case .changedPayload: entries[0]["sha256"] = String(repeating: "f", count: 64)
    case .changedHistory: entries[1]["state"] = UDFEntryState.current.rawValue
    case .duplicateID: entries[1]["entryID"] = entries[0]["entryID"]
    case .duplicatePath: entries[1]["outputRelativePath"] = entries[0]["outputRelativePath"]
    case .escapedPath: entries[0]["outputRelativePath"] = "LogicalFiles/../outside"
    default: break
    }
    let object: [String: Any] = [
        "schemaVersion": 1, "status": "completed",
        "destinationPath": fault == .destination ? "/synthetic/foreign-output" : destination.path,
        "sourceSHA256": fault == .sourceHash ? String(repeating: "f", count: 64) : result.sourceSHA256,
        "sourceByteCount": result.sourceByteCount + (fault == .sourceSize ? 1 : 0),
        "caseID": UUID().uuidString, "jobID": UUID().uuidString,
        "parserVersion": result.parserVersion, "profile": result.profile, "exportedAt": 0,
        "entries": entries, "historyReportSHA256": String(repeating: "d", count: 64),
        "historyJSONSHA256": String(repeating: "e", count: 64), "limitations": ["Synthetic adapter receipt"]
    ]
    return try JSONDecoder().decode(UDFLogicalFilesExport.self, from: JSONSerialization.data(withJSONObject: object))
}

private actor OpticalAutopsyExportGate {
    struct Request: Sendable {
        let id: UUID
        let evidence: EvidenceRecord
        let result: UDFInspectionResult
        let caseID: UUID
        let output: URL
    }
    private var queued: [Request] = []
    private var waiting: [CheckedContinuation<Request, Never>] = []
    private var responses: [UUID: CheckedContinuation<UDFLogicalFilesExport, Error>] = [:]
    private var progress: [UUID: @Sendable (UDFInspectionProgress) -> Void] = [:]
    func export(evidence: EvidenceRecord, result: UDFInspectionResult, forensicCase: ForensicCase, output: URL,
        progress: @escaping @Sendable (UDFInspectionProgress) -> Void) async throws -> UDFLogicalFilesExport {
        let request = Request(id: UUID(), evidence: evidence, result: result, caseID: forensicCase.manifest.id, output: output)
        self.progress[request.id] = progress
        return try await withCheckedThrowingContinuation { continuation in
            responses[request.id] = continuation
            if waiting.isEmpty { queued.append(request) } else { waiting.removeFirst().resume(returning: request) }
        }
    }
    func nextRequest() async -> Request {
        if !queued.isEmpty { return queued.removeFirst() }
        return await withCheckedContinuation { waiting.append($0) }
    }
    func report(_ request: Request, _ value: UDFInspectionProgress) { progress[request.id]?(value) }
    func succeed(_ request: Request, _ receipt: UDFLogicalFilesExport) {
        progress[request.id] = nil
        responses.removeValue(forKey: request.id)?.resume(returning: receipt)
    }
    func fail(_ request: Request, _ error: any Error) {
        progress[request.id] = nil
        responses.removeValue(forKey: request.id)?.resume(throwing: error)
    }
}

private actor OpticalDestinationGate {
    private var response: CheckedContinuation<URL?, Never>?
    private var waiter: CheckedContinuation<Void, Never>?
    func choose() async -> URL? {
        await withCheckedContinuation { response = $0; waiter?.resume(); waiter = nil }
    }
    func waitUntilRequested() async {
        if response != nil { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func finish(_ destination: URL?) { response?.resume(returning: destination); response = nil }
}

private actor OpticalExportCallCounter {
    private(set) var count = 0
    func record() { count += 1 }
}
