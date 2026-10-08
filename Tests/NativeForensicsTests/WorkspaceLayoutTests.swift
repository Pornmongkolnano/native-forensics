import AppKit
import ForensicsCore
import SwiftUI
import Testing
@testable import NativeForensics

@Suite("WorkspaceLayoutTests", .serialized)
@MainActor
struct WorkspaceLayoutTests {
    @Test("A populated optical table retains three visible rows before and after export within its finite window", arguments: [
        CGSize(width: 1280, height: 780), CGSize(width: 1040, height: 660)
    ], [false, true])
    func opticalViewport(size: CGSize, hasCompletedExport: Bool) async throws {
        _ = NSApplication.shared
        let fixture = LayoutOpticalFixture()
        let scheduler = ForensicWorkScheduler()
        let optical = OpticalWorkspaceStore(documentHelperURL: URL(fileURLWithPath: "/usr/bin/true"),
            load: { _, _ in fixture.result }, exportForAutopsy: { _, result, _, destination, _ in
                try layoutAutopsyReceipt(result, destination: destination)
            }, scheduler: scheduler)
        let workspace = WorkspaceStore(helperURL: URL(fileURLWithPath: "/usr/bin/true"), optical: optical, scheduler: scheduler)
        workspace.currentCase = fixture.forensicCase
        workspace.selectedEvidenceID = fixture.evidence.id
        workspace.section = .optical
        await (try #require(optical.activeTask)).value
        optical.selectedEntryID = fixture.result.entries[0].id
        if hasCompletedExport {
            optical.exportForAutopsy(to: URL(fileURLWithPath: "/synthetic/layout-completed-export"))
            await (try #require(optical.activeTask)).value
            #expect(optical.lastAutopsyExport?.entries.count == fixture.result.entries.count)
        }

        let host = NSHostingView(rootView: ContentView(workspace: workspace))
        let window = NSWindow(contentRect: CGRect(origin: .zero, size: size),
            styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = host
        defer { window.close() }

        // AppKit creates SwiftUI's native table/split views on its next layout
        // turns. The hidden test window does not activate or touch the real app.
        for _ in 0..<10 {
            try await Task.sleep(for: .milliseconds(50))
            host.layoutSubtreeIfNeeded()
        }
        let views = descendants(of: host)
        let splits = views.compactMap { $0 as? NSSplitView }
        let scrolls = views.compactMap { $0 as? NSScrollView }
        #expect(!splits.isEmpty)
        #expect(scrolls.count >= 3, "Sidebar, file table, and inspector must retain independent scroll viewports")
        #expect(host.fittingSize.height <= host.bounds.height + 1,
                "Table content must not become the entire window's minimum height")
        for split in splits {
            let rect = split.convert(split.bounds, to: host)
            #expect(rect.height <= host.bounds.height + 1)
            #expect(rect.minY >= -1)
            #expect(rect.maxY <= host.bounds.maxY + 1)
        }
        for scroll in scrolls {
            let viewport = scroll.convert(scroll.bounds, to: host)
            #expect(viewport.height <= host.bounds.height + 1)
            #expect(viewport.intersects(host.bounds), "A scrollable column cannot be laid out entirely offscreen")
        }
        let tables = views.compactMap { $0 as? NSTableView }
        let fileTable = try #require(tables.first { $0.numberOfRows == fixture.result.entries.count })
        let tableViewport = try #require(fileTable.enclosingScrollView)
        let firstThreeRows = fileTable.rect(ofRow: 2).maxY - fileTable.rect(ofRow: 0).minY
        #expect(tableViewport.contentSize.height >= firstThreeRows,
                "The file table must show at least three complete rows at \(size) with completed export \(hasCompletedExport); viewport \(tableViewport.contentSize.height), required \(firstThreeRows)")
        #expect(fileTable.bounds.height > tableViewport.contentSize.height,
                "Overflow belongs to the file table's scrollable document, not the containing split view")
        await workspace.shutdown()
    }

    private func descendants(of view: NSView) -> [NSView] {
        view.subviews.flatMap { [$0] + descendants(of: $0) }
    }
}

private struct LayoutOpticalFixture: Sendable {
    let evidence: EvidenceRecord
    let forensicCase: ForensicCase
    let result: UDFInspectionResult

    init() {
        evidence = EvidenceRecord(sourcePath: "/synthetic/layout-optical.dd", byteCount: 65536,
            sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
        let caseID = UUID()
        forensicCase = ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/\(caseID).nativecase"),
            manifest: CaseManifest(id: caseID, name: "Synthetic Optical Layout", evidence: [evidence]))
        let stamp = UDFTimestamp(rawHex: "000000000000000000000000", sourceOffset: 4096,
            type: 1, timezoneMinutes: nil, utcDate: nil, microsecond: 0)
        let entries = (0..<20).map { index in
            UDFFileEntry(id: "layout-\(index)", originalPath: "/synthetic/recorded-file-\(index).txt",
                state: index < 3 ? .current : .historical, fidCharacteristics: 0, fidSourceOffset: 16384,
                deletedAncestorProof: [], byteCount: 12, sha256: String(repeating: "b", count: 64),
                icb: UDFEntryAddress(logicalBlock: 2, partitionReference: 1, sourceOffset: 16384, tagIdentifier: 261),
                sourceExtents: [UDFSourceExtent(offset: 18432, byteCount: 12)],
                timestamps: UDFEntryTimestamps(access: stamp, modification: stamp, attribute: stamp, creation: nil),
                snapshotIDs: ["latest"])
        }
        let snapshot = UDFSnapshot(id: "latest", vatICBSourceOffset: 32768, previousVATLogicalBlock: nil,
            mappedBlockCount: 10, namespaceFileCount: entries.count, modification: stamp)
        result = UDFInspectionResult(caseID: caseID, sourceEvidenceID: evidence.id,
            sourceSHA256: evidence.sha256, sourceByteCount: evidence.byteCount, volumeIdentifier: "Synthetic UDF",
            udfRevision: "2.01", latestSnapshotID: "latest", snapshots: [snapshot], entries: entries,
            deletedAncestors: [], limitations: ["Synthetic layout receipt only"], options: UDFInspectionOptions())
    }
}

private func layoutAutopsyReceipt(_ result: UDFInspectionResult, destination: URL) throws -> UDFLogicalFilesExport {
    let entries: [[String: Any]] = result.entries.map { entry in
        ["entryID": entry.id, "originalPath": entry.originalPath,
         "outputRelativePath": "LogicalFiles/\(entry.state.rawValue)/\(entry.id)/payload",
         "pathMapping": "synthetic", "state": entry.state.rawValue, "snapshotIDs": entry.snapshotIDs,
         "byteCount": entry.byteCount, "sha256": entry.sha256]
    }
    let object: [String: Any] = [
        "schemaVersion": 1, "status": "completed", "destinationPath": destination.path,
        "sourceSHA256": result.sourceSHA256, "sourceByteCount": result.sourceByteCount,
        "caseID": UUID().uuidString, "jobID": UUID().uuidString,
        "parserVersion": result.parserVersion, "profile": result.profile, "exportedAt": 0,
        "entries": entries, "historyReportSHA256": String(repeating: "d", count: 64),
        "historyJSONSHA256": String(repeating: "e", count: 64), "limitations": ["Synthetic layout receipt"]
    ]
    return try JSONDecoder().decode(UDFLogicalFilesExport.self, from: JSONSerialization.data(withJSONObject: object))
}
