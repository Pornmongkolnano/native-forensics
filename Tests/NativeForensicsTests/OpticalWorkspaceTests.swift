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

    private func makeStore(load: @escaping OpticalWorkspaceStore.Load, inspect: OpticalWorkspaceStore.Inspect? = nil,
                           analyze: OpticalWorkspaceStore.Analyze? = nil, export: OpticalWorkspaceStore.Export? = nil) -> OpticalWorkspaceStore {
        OpticalWorkspaceStore(documentHelperURL: URL(fileURLWithPath: "/usr/bin/true"), load: load,
            inspect: inspect, analyze: analyze, export: export)
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
