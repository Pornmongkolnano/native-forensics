import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

struct UDFReportTests {
    @Test("UDF reports retain all VAT states and distinguish child FIDs from ancestor deletion")
    func namespaceProvenance() async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let report = UDFReportBuilder.renderMarkdown(result: fixture.result)
        for snapshot in fixture.result.snapshots { #expect(report.contains(snapshot.id)) }
        for entry in fixture.result.entries {
            #expect(report.contains(entry.id))
            #expect(report.contains(entry.sha256))
        }
        #expect(report.contains(fixture.result.sourceSHA256))
        #expect(report.contains("selected-file-bytes"))
        #expect(report.contains("native-udf-test"))
        #expect(report.contains("0x06"))
        #expect(report.contains("0x00"))
        #expect(report.contains("/archive"))
        #expect(report.contains("0010e7070b0e160d14000000"))
        #expect(!report.contains("PhotoRec"))
        #expect(!report.contains(fixture.source.path))
        #expect(!report.contains(fixture.forensicCase.bundleURL.path))
    }

    @Test("UDF report MIME and Office/ZIP references remain separate from original filenames")
    func decoderReferences() async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let entry = fixture.result.entries[1]
        let office = DocumentAnalysis(contentKind: .office,
            mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", status: .decoded,
            sourceSHA256: entry.sha256, sourceByteCount: entry.byteCount, officeFormat: .xlsx,
            contentUnitCount: 2, structuralValidation: .validated,
            textPages: [DocumentTextPage(pageNumber: 1, text: "A bounded worksheet excerpt", isTruncated: true,
                referenceLabel: "Sheet 1: Plan", referenceKind: .sheet)])
        let report = UDFReportBuilder.renderMarkdown(result: fixture.result, analyses: [entry.id: office])
        #expect(report.contains("hidden.jpg"))
        #expect(report.contains("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
        #expect(report.contains("Sheet 1: Plan"))
        #expect(report.lowercased().contains("partial"))
        #expect(!report.contains("Page 1: A bounded worksheet excerpt"))
    }

    @Test("Wrong entry, file hash and size receipts fail closed before report publication")
    func analysisMismatch() async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let entry = fixture.result.entries[0]
        let wrong = DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: String(repeating: "c", count: 64), sourceByteCount: entry.byteCount,
            textPages: [DocumentTextPage(pageNumber: 1, text: "FORGED DECODER FINDING")])
        let report = UDFReportBuilder.renderMarkdown(result: fixture.result, analyses: [entry.id: wrong])
        #expect(!report.contains("FORGED DECODER FINDING"))
        let destination = fixture.root.appendingPathComponent("rejected.md")
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try UDFReportBuilder.exportMarkdown(result: fixture.result, analyses: [entry.id: wrong],
                in: fixture.forensicCase, to: destination)
        }
        #expect(throws: RecoveryError.scopeMismatch) {
            try UDFReportBuilder.exportMarkdown(result: fixture.result, analyses: ["foreign-id": wrong],
                in: fixture.forensicCase, to: destination)
        }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test("UDF reports use persisted provenance with source offline and publish exclusively")
    func offlineAndProtectedDestinations() async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let destination = fixture.root.appendingPathComponent("udf.md")
        for output in [fixture.source, fixture.forensicCase.bundleURL.appendingPathComponent("bad.md")] {
            #expect(throws: RecoveryError.scopeMismatch) {
                try UDFReportBuilder.exportMarkdown(result: fixture.result, in: fixture.forensicCase, to: output)
            }
        }
        try FileManager.default.removeItem(at: fixture.source)
        #expect(try UDFReportBuilder.exportMarkdown(result: fixture.result, in: fixture.forensicCase,
                                                   to: destination) == destination)
        let saved = try Data(contentsOf: destination)
        #expect(throws: RecoveryError.destinationExists) {
            try UDFReportBuilder.exportMarkdown(result: fixture.result, in: fixture.forensicCase, to: destination)
        }
        #expect(try Data(contentsOf: destination) == saved)
    }

    @Test("Stale UDF jobs cannot be exported after the current pointer advances")
    func staleJob() async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let first = fixture.result
        let next = UDFInspectionResult(caseID: first.caseID, sourceEvidenceID: first.sourceEvidenceID,
            sourceSHA256: first.sourceSHA256, sourceByteCount: first.sourceByteCount,
            parserVersion: first.parserVersion, profile: first.profile, volumeIdentifier: first.volumeIdentifier,
            udfRevision: first.udfRevision, latestSnapshotID: first.latestSnapshotID, snapshots: first.snapshots,
            entries: first.entries, deletedAncestors: first.deletedAncestors,
            limitations: first.limitations, options: first.options)
        _ = try UDFResultStore.save(next, in: fixture.forensicCase)
        #expect(throws: UDFError.self) {
            try UDFReportBuilder.exportMarkdown(result: first, in: fixture.forensicCase,
                                                to: fixture.root.appendingPathComponent("stale.md"))
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("stale.md").path))
    }

    @Test("Report source/case aliases and corrupted optical metadata fail closed", arguments: ["destination-link", "directory-link", "corrupt-job"])
    func unsafeExport(_ mode: String) async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let destination = fixture.root.appendingPathComponent("rejected.md")
        var supplied = destination
        switch mode {
        case "destination-link": try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: fixture.source)
        case "directory-link":
            let alias = fixture.root.appendingPathComponent("output-alias")
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture.root)
            supplied = alias.appendingPathComponent("rejected.md")
        default:
            let resultURL = fixture.forensicCase.bundleURL.appendingPathComponent("optical")
                .appendingPathComponent(fixture.result.sourceEvidenceID.uuidString.lowercased())
                .appendingPathComponent("generations").appendingPathComponent(fixture.result.jobID.uuidString.lowercased())
                .appendingPathComponent("result.json")
            try Data("{".utf8).write(to: resultURL)
        }
        #expect(throws: (any Error).self) {
            try UDFReportBuilder.exportMarkdown(result: fixture.result, in: fixture.forensicCase, to: supplied)
        }
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Cancellation before report commit leaves no export; after commit returns its receipt")
    func cancellationBoundary() async throws {
        let fixture = try await UDFReportFixture.make()
        defer { fixture.remove() }
        let rejected = fixture.root.appendingPathComponent("before.md")
        let before = Task.detached {
            try UDFReportBuilder.exportForTesting(result: fixture.result, in: fixture.forensicCase,
                to: rejected, beforePublication: { withUnsafeCurrentTask { $0?.cancel() } })
        }
        await #expect(throws: CancellationError.self) { try await before.value }
        #expect(!FileManager.default.fileExists(atPath: rejected.path))
        let committed = fixture.root.appendingPathComponent("after.md")
        let after = Task.detached {
            try UDFReportBuilder.exportForTesting(result: fixture.result, in: fixture.forensicCase,
                to: committed, afterPublication: { withUnsafeCurrentTask { $0?.cancel() } })
        }
        #expect(try await after.value == committed)
        #expect(try !Data(contentsOf: committed).isEmpty)
    }
}

private struct UDFReportFixture: Sendable {
    let root: URL
    let source: URL
    let sourceBytes: Data
    let forensicCase: ForensicCase
    let result: UDFInspectionResult

    static func make() async throws -> UDFReportFixture {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("UDFReportTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            var bytes = Data(repeating: 0, count: 65_536)
            bytes.replaceSubrange(2048..<2051, with: Data("abc".utf8))
            bytes.replaceSubrange(4096..<4099, with: Data("XYZ".utf8))
            let source = root.appendingPathComponent("synthetic.dd")
            try bytes.write(to: source)
            let inspected = try await ImageInspector.inspect(url: source) { _ in }
            let created = try CaseStore.create(name: "Optical report", in: root)
            let forensicCase = try CaseStore.adding(image: inspected, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let stamp = UDFTimestamp(rawHex: "0010e7070b0e160d14000000", sourceOffset: 64,
                type: 1, timezoneMinutes: 0, utcDate: Date(timeIntervalSince1970: 1_700_000_000), microsecond: 0)
            let timestamps = UDFEntryTimestamps(access: stamp, modification: stamp, attribute: stamp, creation: nil)
            var snapshots: [UDFSnapshot] = []
            for index in 0..<9 {
                let offset = Int64(8192) + Int64(index) * 2048
                let previous: UInt32? = index == 8 ? nil : UInt32(101 + index)
                let files: Int = index == 0 ? 1 : 2
                snapshots.append(UDFSnapshot(id: "vat-\(index)", vatICBSourceOffset: offset,
                    previousVATLogicalBlock: previous, mappedBlockCount: 16,
                    namespaceFileCount: files, modification: stamp))
            }
            let proof = UDFDeletedAncestorProof(originalPath: "/archive", latestSnapshotID: "vat-0",
                fidSourceOffset: 512, fidCharacteristics: 0x06, nullICB: true, rawNameHex: "fe61726368697665")
            let current = UDFFileEntry(id: "current-file", originalPath: "/photos/current.jpg", state: .current,
                fidCharacteristics: 0, fidSourceOffset: 1024, deletedAncestorProof: [], byteCount: 3,
                sha256: hash(Data("abc".utf8)), icb: UDFEntryAddress(logicalBlock: 1, partitionReference: 1,
                    sourceOffset: 128, tagIdentifier: 261), sourceExtents: [UDFSourceExtent(offset: 2048, byteCount: 3)],
                timestamps: timestamps, snapshotIDs: snapshots.map(\.id))
            let historical = UDFFileEntry(id: "historical-file", originalPath: "/archive/hidden.jpg",
                state: .historicalDeletedAncestor, fidCharacteristics: 0, fidSourceOffset: 1280,
                deletedAncestorProof: [proof], byteCount: 3, sha256: hash(Data("XYZ".utf8)),
                icb: UDFEntryAddress(logicalBlock: 2, partitionReference: 1, sourceOffset: 256, tagIdentifier: 261),
                sourceExtents: [UDFSourceExtent(offset: 4096, byteCount: 3)], timestamps: timestamps,
                snapshotIDs: Array(snapshots.dropFirst().map(\.id)))
            let result = UDFInspectionResult(caseID: forensicCase.manifest.id, sourceEvidenceID: evidence.id,
                sourceSHA256: evidence.sha256, sourceByteCount: evidence.byteCount,
                parserVersion: "native-udf-test", volumeIdentifier: "SYNTHETIC", udfRevision: "2.01",
                latestSnapshotID: "vat-0", snapshots: snapshots, entries: [current, historical],
                deletedAncestors: [proof], limitations: ["Synthetic model receipt; no general UDF support claimed."],
                options: UDFInspectionOptions())
            _ = try UDFResultStore.save(result, in: forensicCase)
            return UDFReportFixture(root: root, source: source, sourceBytes: bytes,
                forensicCase: forensicCase, result: result)
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
