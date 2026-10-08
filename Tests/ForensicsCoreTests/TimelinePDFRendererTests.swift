import CoreGraphics
import CryptoKit
import Foundation
import PDFKit
import Testing
@testable import ForensicsCore

struct TimelinePDFRendererTests {
    @Test("Native PDF retains complete timestamp, engine, parser and source provenance")
    func completeProvenance() throws {
        let report = try fixture(fullProvenance: true)
        let data = try TimelinePDFRenderer.render(report)
        let document = try #require(PDFDocument(data: data))
        let text = try #require(document.string)
        let joined = joinedBodyText(text)
        #expect(data.count <= TimelineLimits.maximumReportBytes)
        #expect(document.pageCount > 1)
        for token in [report.binding.caseID.uuidString, report.binding.evidenceID.uuidString,
                      report.binding.snapshotSHA256, "engine-patch-fixture-v1", "raw-utf8.v1",
                      "raw-utf8-document", "1793511000", "1793514600", "year=2026",
                      "America/New_York", "ambiguous-local-time", "fractional-9", "123456789",
                      "Source UTF-8 byte offset: 42", "Source UTF-8 byte length: 128",
                      "Volume 0 ID: synthetic-volume", "block count: 2048",
                      "Parser parameter selectedYear: 2026", "Artifact file ID: artifact-file-fixture",
                      "\\tTAB-fixture", "\\u0007BEL-fixture",
                      "Native filesystem raw date: 23878", "Native filesystem raw time: 19238",
                      "Native filesystem raw increment: 123", "Native filesystem raw UTC offset: 156",
                      "Native filesystem civil value: 2026-10-06T09:25:13.230", "Native filesystem timestamp status: recorded-offset",
                      "Native filesystem UTC offset minutes: 420", "Native filesystem precision nanoseconds: 10000000",
                      "Examiner note fixture", "AI interpretation fixture"] {
            #expect(joined.contains(token.filter { !$0.isWhitespace }), "Missing PDF text: \(token)")
        }
        #expect(text.contains("UTC epoch seconds: unresolved"))
        #expect(joined.contains("Rawtimestamp:Nov101:30:00"))
        #expect(text.contains("1791253513"))
        #expect(text.contains("Timestamp precision: fractional-9"))
        let examiner = try #require(text.range(of: "Examiner notes"))
        let ai = try #require(text.range(of: "AI interpretation (unverified)"))
        #expect(examiner.upperBound < ai.lowerBound)
        try assertStatic(document: document, data: data)
    }

    @Test("Pagination preserves every event and endpoint across Thai, wide paths, whitespace and newlines")
    func losslessPagination() throws {
        let path = "/หลักฐาน/" + String(repeating: "WM", count: 600) + "/path-end-fixture.txt"
        let detail = "detail-start-fixture " + String(repeating: " ", count: 8_000)
            + "after-whitespace-fixture\n" + String(repeating: "หลักฐานภาษาไทย ", count: 90)
            + "\nfinal-detail-fixture"
        let events = (0..<24).map { index in
            TimelineEvent(id: digest("pagination-event-\(index)"), kind: .filesystemModified,
                timestamp: .unix(seconds: 1_791_253_513), fileID: "file-fixture-\(index)",
                evidencePath: path, title: "record-title-\(index)", detail: detail,
                parser: "filesystem.v1", recordID: "record-end-fixture-\(index)")
        }
        let report = TimelineReport(binding: binding(), events: events, warnings: ["Warning-end-fixture"],
            coverage: "Synthetic pagination coverage", examinerNotes: "final-examiner-fixture")
        let data = try TimelinePDFRenderer.render(report)
        let document = try #require(PDFDocument(data: data))
        let text = try #require(document.string)
        let joined = joinedBodyText(text)
        #expect(document.pageCount > 10)
        for event in events { #expect(text.contains(event.id)); #expect(text.contains(event.recordID)) }
        #expect(text.components(separatedBy: "final-detail-fixture").count - 1 == events.count)
        #expect(text.components(separatedBy: "after-whitespace-fixture").count - 1 == events.count)
        #expect(joined.components(separatedBy: "path-end-fixture.txt").count - 1 == events.count)
        #expect(joined.components(separatedBy: "หลักฐานภาษาไทย").count - 1 == 90 * events.count)
        #expect(text.contains("final-examiner-fixture"))
        #expect(text.contains("Readable engine provenance: Unavailable"))
        try assertStatic(document: document, data: data)
    }

    @Test("Byte and page bounds reject a complete report instead of publishing truncated PDF data")
    func outputBounds() throws {
        let report = try fixture(fullProvenance: true)
        #expect(throws: TimelineError.self) {
            try TimelinePDFRenderer.render(report, byteLimit: 128, pageLimit: TimelinePDFRenderer.maximumPages)
        }
        do {
            _ = try TimelinePDFRenderer.render(report, byteLimit: TimelineLimits.maximumReportBytes, pageLimit: 1)
            Issue.record("Oversized pagination unexpectedly succeeded.")
        } catch let error as TimelineError {
            guard case .limitExceeded = error else { Issue.record("Unexpected PDF page-limit failure: \(error)"); return }
        }
        let data = try TimelinePDFRenderer.render(TimelineReport(binding: binding(), events: [], warnings: [], coverage: "Empty synthetic report"))
        #expect(PDFDocument(data: data)?.pageCount ?? 0 >= 1)
    }

    @Test("Invalid and cancelled reports cannot produce PDF output")
    func invalidAndCancelled() async throws {
        let event = TimelineEvent(id: digest("duplicate"), kind: .filesystemModified, timestamp: .unix(seconds: 0),
            fileID: "fixture", evidencePath: "/fixture", title: "", detail: "", parser: "fixture.v1", recordID: "fixture")
        let invalid = TimelineReport(binding: binding(), events: [event, event], warnings: [], coverage: "Synthetic duplicate")
        #expect(throws: TimelineError.self) { try TimelinePDFRenderer.render(invalid) }
        let report = try fixture(fullProvenance: false)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try TimelinePDFRenderer.render(report)
        }
        do { _ = try await task.value; Issue.record("Cancelled PDF rendering unexpectedly succeeded.") }
        catch { #expect(error is CancellationError) }
    }

    private func fixture(fullProvenance: Bool) throws -> TimelineReport {
        let artifactHash = String(repeating: "d", count: 64)
        let textHash = String(repeating: "e", count: 64)
        let artifact = TimelineArtifactReceipt(file: VerifiedArtifactFile(url: URL(fileURLWithPath: "/synthetic-runtime-only"),
            fileID: "artifact-file-fixture", evidencePath: "/var/log/หลักฐาน.log", byteCount: 4096, sha256: artifactHash), role: "syslog")
        let parser = TimelineParserReceipt(parser: "syslog-record", version: "raw-utf8.v1",
            parameters: ["selectedYear": "2026", "timezone": "America/New_York"], sourceSHA256: artifactHash,
            derivedTextSHA256: textHash, unitCount: 1, lineCount: 32, eventCount: 1)
        let source = TimelineTextSourceReference(derivedTextSHA256: textHash, unit: 1, unitKind: "raw-utf8-document",
            line: 2, utf8Offset: 42, utf8Length: 128)
        let ambiguous = TimelineEvent(id: digest("ambiguous-fixture"), kind: .syslogRecord,
            timestamp: .syslog("Nov  1 01:30:00", year: 2026, timezone: "America/New_York"),
            fileID: artifact.fileID, evidencePath: artifact.evidencePath,
            title: "หลักฐานภาษาไทย https://example.invalid/fixture", detail: "Literal /JavaScript /OpenAction text <script>fixture</script>\tTAB-fixture\u{0007}BEL-fixture",
            parser: parser.parser, recordID: "syslog-line-2", artifactSHA256: artifactHash, sourceReference: source)
        let exact = TimelineEvent(id: digest("exact-fixture"), kind: .filesystemModified,
            timestamp: .rfc3339("2026-10-06T09:25:13.123456789+07:00"), fileID: "exact-file-fixture",
            evidencePath: "/exact-fixture", title: "Exact fixture", detail: "", parser: "filesystem.v1", recordID: "exact-record-fixture")
        let native = FilesystemCivilTimestamp(rawDate: 23878, rawTime: 19238, rawIncrement: 123, rawUTCOffset: 156,
            civil: "2026-10-06T09:25:13.230", status: .recordedOffset, utcOffsetMinutes: 420,
            candidateEpochs: [1_791_253_513], precisionNanoseconds: 10_000_000)
        let nativeEvent = TimelineEvent(id: digest("native-fixture"), kind: .filesystemCreated,
            timestamp: try .filesystem(native, epoch: 1_791_253_513, nanos: 230_000_000), fileID: "native-file-fixture",
            evidencePath: "/native-fixture", title: "Native offset fixture", detail: "", parser: "filesystem.v1",
            recordID: "native-record-fixture", filesystemTimestamp: native)
        var provenance: TimelineEngineProvenance?
        if fullProvenance {
            let encoded = """
            {"schemaVersion":1,"patchDigest":"engine-patch-fixture-v1","options":{"imageType":"raw","sectorSize":512,"timezone":"UTC","maxFiles":50000,"hashLogicalImage":true},"image":{"imageType":"raw","logicalSize":1048576,"sectorSize":512,"logicalSha256":"\(String(repeating: "f", count: 64))"},"orderedInputs":[{"ordinal":0,"byteCount":1048576,"sha256":"\(String(repeating: "c", count: 64))","hashScope":"selected-file-bytes"}],"volumes":[{"id":"synthetic-volume","offsetBytes":0,"filesystem":"fat16","blockSize":512,"blockCount":2048}]}
            """
            provenance = try JSONDecoder().decode(TimelineEngineProvenance.self, from: Data(encoded.utf8))
        }
        return TimelineReport(binding: binding(provenance: provenance), events: [ambiguous, exact, nativeEvent], artifactReceipts: [artifact],
            warnings: ["Synthetic warning fixture"], coverage: "Synthetic parser coverage", aiInterpretation: "AI interpretation fixture",
            examinerNotes: "Examiner note fixture", parserReceipts: [parser])
    }

    private func binding(provenance: TimelineEngineProvenance? = nil) -> TimelineSourceBinding {
        TimelineSourceBinding(caseID: UUID(), evidenceID: UUID(), snapshotSHA256: String(repeating: "b", count: 64),
            orderedContainerSHA256: [String(repeating: "c", count: 64)], logicalImageSHA256: String(repeating: "f", count: 64),
            engineVersion: "synthetic-engine-v1", engineTimezone: "UTC", snapshotSavedAt: Date(timeIntervalSince1970: 1_791_253_513.125),
            listingStatus: .completed, historical: true, engineProvenance: provenance)
    }
    private func digest(_ text: String) -> String { SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined() }

    // Extraction inserts layout line breaks, and page chrome may occur inside
    // a wrapped value. Compare source tokens after removing only that chrome
    // and whitespace, rather than requiring an unwrapped field to fit a page.
    private func joinedBodyText(_ text: String) -> String {
        text.replacingOccurrences(of: "NativeForensics timeline\n", with: "")
            .replacingOccurrences(of: "Recorded evidence report - page [0-9]+\\n", with: "", options: .regularExpression)
            .filter { !$0.isWhitespace }
    }

    private func assertStatic(document: PDFDocument, data: Data) throws {
        for index in 0..<document.pageCount { #expect(try #require(document.page(at: index)).annotations.isEmpty) }
        let provider = try #require(CGDataProvider(data: data as CFData))
        let native = try #require(CGPDFDocument(provider))
        let catalog = try #require(native.catalog)
        var object: CGPDFObjectRef?
        #expect(!CGPDFDictionaryGetObject(catalog, "OpenAction", &object))
        #expect(!CGPDFDictionaryGetObject(catalog, "AA", &object))
        #expect(!CGPDFDictionaryGetObject(catalog, "Names", &object))
        for index in 1...native.numberOfPages {
            let page = try #require(native.page(at: index))
            let dictionary = try #require(page.dictionary)
            #expect(!CGPDFDictionaryGetObject(dictionary, "Annots", &object))
            #expect(!CGPDFDictionaryGetObject(dictionary, "AA", &object))
        }
    }
}
