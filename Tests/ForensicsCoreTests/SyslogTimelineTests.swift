import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

struct SyslogTimelineTests {
    private let payload = "Oct  6 09:25:13 host app: ภาษาไทย\n2026-10-06T02:25:13.123456789Z host app: raw fact\r\n<34>1 2026-10-06T02:25:14+00:00 host app - ID - encoded text\nunrecognized payload\n2026-02-29T00:00:00Z invalid-calendar\n2026-10-06T02:25:13.01-00:00 unresolved\n"

    @Test("Raw UTF-8 syslog facts use independent epoch, nanosecond, hash and exact source-line oracles")
    func fixedOracles() throws {
        let fixture = try SyslogFixture(bytes: Data(payload.utf8)); defer { fixture.remove() }
        let result = try fixture.parse(options: SyslogParserOptions(year: 2026, timezone: "Asia/Bangkok"))
        #expect(fixture.file.sha256 == "7711ff690bd953171ecf852e91872b514d3e48f8029bcd77b8d7bd0062e83034")
        #expect(result.events.count == 4)
        let classic = try #require(result.events.first { $0.recordID == "unit:1/line:1" })
        #expect(classic.timestamp.epochSeconds == 1_791_253_513)
        #expect(classic.timestamp.nanoseconds == 0)
        #expect(classic.timestamp.rawValue == "Oct  6 09:25:13")
        #expect(classic.timestamp.timezoneAssumption == "year=2026, zone=Asia/Bangkok")
        #expect(classic.detail == "Oct  6 09:25:13 host app: ภาษาไทย")
        #expect(classic.sourceReference?.utf8Offset == 0)
        #expect(classic.sourceReference?.utf8Length == 47)
        let rfc = try #require(result.events.first { $0.recordID == "unit:1/line:2" })
        #expect(rfc.timestamp.epochSeconds == 1_791_253_513)
        #expect(rfc.timestamp.nanoseconds == 123_456_789)
        #expect(rfc.timestamp.precision == "fractional-9")
        #expect(rfc.sourceReference?.line == 2)
        #expect(rfc.sourceReference?.utf8Offset == 48)
        #expect(rfc.sourceReference?.utf8Length == 50) // Includes the source CR, excludes LF.
        let sourceBytes = try Data(contentsOf: fixture.file.url)
        #expect(sourceBytes.subdata(in: 48..<98) == Data("2026-10-06T02:25:13.123456789Z host app: raw fact\r".utf8))
        #expect(sourceBytes[98] == 0x0a) // The delimiting LF is outside the recorded span.
        #expect(rfc.detail == "2026-10-06T02:25:13.123456789Z host app: raw fact")
        let structured = try #require(result.events.first { $0.recordID == "unit:1/line:3" })
        #expect(structured.timestamp.epochSeconds == 1_791_253_514)
        #expect(structured.sourceReference?.utf8Offset == 99)
        #expect(structured.sourceReference?.utf8Length == 60)
        let unknown = try #require(result.events.first { $0.recordID == "unit:1/line:6" })
        #expect(unknown.timestamp.epochSeconds == nil)
        #expect(unknown.timestamp.nanoseconds == 10_000_000)
        #expect(unknown.timestamp.interpretation == "unknown-offset")
        #expect(unknown.sourceReference?.utf8Offset == 219)
        #expect(result.parserReceipt.lineCount == 6)
        #expect(result.parserReceipt.parameters["unrecognizedNonemptyLines"] == "1")
        #expect(result.parserReceipt.parameters["invalidTimestampLines"] == "1")
        #expect(result.parserReceipt.derivedTextSHA256 == fixture.file.sha256)
        #expect(result.parserReceipt.sourceHashScope == "extracted-file-bytes")
        #expect(result.parserReceipt.derivedTextHashScope == "derived-utf8-text-bytes")
        #expect(result.receipts.first?.hashScope == "extracted-file-bytes")
        #expect(result.events.allSatisfy { $0.kind == .syslogRecord && $0.parser == "syslog-record.v1" && $0.artifactSHA256 == fixture.file.sha256 })
        #expect(result.events == (try fixture.parse(options: SyslogParserOptions(year: 2026, timezone: "Asia/Bangkok"))).events)
        let unchangedSource = try Data(contentsOf: fixture.file.url)
        #expect(unchangedSource == Data(payload.utf8))
        #expect(TimelineCoding.hex(SHA256.hash(data: unchangedSource)) == "7711ff690bd953171ecf852e91872b514d3e48f8029bcd77b8d7bd0062e83034")
        let report = fixture.report(result)
        try TimelineReportExporter.validate(report)
        #expect(report.aiInterpretation == nil)
        let markdown = String(decoding: try TimelineReportExporter.markdown(report), as: UTF8.self)
        #expect(markdown.contains("raw-utf8.v1")); #expect(markdown.contains("unit:1/line:2"))
        #expect(!markdown.contains(fixture.directory.path))
    }

    @Test("Explicit assumptions and DST policy do not choose a guessed instant")
    func explicitDSTPolicy() throws {
        let fixture = try SyslogFixture(bytes: Data("Nov  1 01:30:00 host overlap\nMar  8 02:30:00 host gap\n".utf8)); defer { fixture.remove() }
        let result = try fixture.parse(options: SyslogParserOptions(year: 2026, timezone: "America/New_York", localTimePolicy: .preserveUnresolved))
        let overlap = try #require(result.events.first { $0.recordID == "unit:1/line:1" })
        #expect(overlap.timestamp.epochSeconds == nil)
        #expect(overlap.timestamp.alternativeEpochSeconds == [1_793_511_000, 1_793_514_600])
        let gap = try #require(result.events.first { $0.recordID == "unit:1/line:2" })
        #expect(gap.timestamp.epochSeconds == nil); #expect(gap.timestamp.interpretation == "nonexistent-local-time")
        #expect(throws: TimelineError.self) { try fixture.parse(options: SyslogParserOptions(year: 2026, timezone: "America/New_York", localTimePolicy: .rejectAmbiguousOrNonexistent)) }
        #expect(throws: TimelineError.self) { try fixture.parse(options: SyslogParserOptions()) }
        #expect(throws: TimelineError.self) { try fixture.parse(options: SyslogParserOptions(year: 2026)) }
        #expect(throws: TimelineError.self) { try fixture.parse(options: SyslogParserOptions(year: 2026, timezone: "Invalid/Zone")) }
    }

    @Test("RFC3339 log import uses explicit offsets without requiring classic assumptions; invalid bounds are counted")
    func rfcOnlyAndBounds() throws {
        let fixture = try SyslogFixture(bytes: Data("1970-01-01T00:00:00Z earliest\n9999-12-31T23:59:59.999999999Z latest\n1969-12-31T23:59:59Z before\n9999-12-31T23:59:59-01:00 after\n2026-10-06T02:25:60Z leap\n".utf8)); defer { fixture.remove() }
        let result = try fixture.parse()
        #expect(result.events.map { $0.timestamp.epochSeconds } == [0, 253_402_300_799])
        #expect(result.events.last?.timestamp.nanoseconds == 999_999_999)
        #expect(result.parserReceipt.parameters["invalidTimestampLines"] == "3")
        #expect(result.parserReceipt.parameters["year"] == "not supplied; RFC3339 only")
    }

    @Test("Input, line and observation limits fail closed without partial complete results", arguments: ["input", "line", "events", "utf8", "binary"])
    func malformedAndLimits(_ mode: String) throws {
        let bytes: Data
        switch mode {
        case "input": bytes = Data(repeating: 0x61, count: TimelineLimits.maximumSyslogBytes + 1)
        case "line": bytes = Data(("2026-10-06T02:25:13Z " + String(repeating: "a", count: TimelineLimits.maximumSyslogLineBytes)).utf8)
        case "events": bytes = Data(String(repeating: "2026-10-06T02:25:13Z x\n", count: TimelineLimits.maximumSyslogEvents + 1).utf8)
        case "utf8": bytes = Data([0xc3])
        default: bytes = Data([0])
        }
        let fixture = try SyslogFixture(bytes: bytes); defer { fixture.remove() }
        #expect(throws: (any Error).self) { try fixture.parse() }
        #expect(try Data(contentsOf: fixture.file.url) == bytes)
    }

    @Test("Changed bytes and symlink replacements cannot satisfy a syslog content receipt", arguments: [false, true])
    func changedSource(symlink: Bool) throws {
        let bytes = Data("2026-10-06T02:25:13Z a\n".utf8)
        let fixture = try SyslogFixture(bytes: bytes); defer { fixture.remove() }
        if symlink {
            let other = fixture.directory.appendingPathComponent("other")
            try bytes.write(to: other); try FileManager.default.removeItem(at: fixture.file.url)
            try FileManager.default.createSymbolicLink(at: fixture.file.url, withDestinationURL: other)
        } else { try Data("2026-10-06T02:25:13Z b\n".utf8).write(to: fixture.file.url) }
        #expect(throws: (any Error).self) { try fixture.parse() }
    }

    @Test("Historical v1 JSON keeps unavailable extended provenance explicit and is never rewritten")
    func historicalJSON() throws {
        let fixture = try SyslogFixture(bytes: Data()); defer { fixture.remove() }
        let legacy = TimelineReport(binding: fixture.binding, events: [], warnings: [], coverage: "historical")
        let data = Data(String(decoding: try TimelineCoding.encode(legacy), as: UTF8.self).replacingOccurrences(of: "timeline.v2", with: "timeline.v1").utf8)
        #expect(!String(decoding: data, as: UTF8.self).contains("engineProvenance"))
        #expect(!String(decoding: data, as: UTF8.self).contains("parserReceipts"))
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let reopened = try decoder.decode(TimelineReport.self, from: data)
        #expect(reopened.parserVersion == "timeline.v1"); #expect(reopened.binding == legacy.binding); #expect(reopened.binding.engineProvenance == nil)
        #expect(reopened.binding.hashScopes == nil)
        let oldReceipt = Data("{\"schemaVersion\":1,\"destinationPath\":\"/synthetic/report\",\"snapshotSHA256\":\"\(fixture.binding.snapshotSHA256)\",\"eventCount\":0,\"jsonSHA256\":\"\(String(repeating: "a", count: 64))\",\"markdownSHA256\":\"\(String(repeating: "b", count: 64))\",\"artifactReceipts\":[]}".utf8)
        #expect(try decoder.decode(TimelineExportReceipt.self, from: oldReceipt).pdfSHA256 == nil)
        #expect(String(decoding: try TimelineReportExporter.markdown(reopened), as: UTF8.self).contains("cannot reconstruct"))
    }

    @Test("Report provenance rejects an out-of-source syslog byte pointer")
    func outOfSourcePointer() throws {
        let fixture = try SyslogFixture(bytes: Data("2026-10-06T02:25:13Z a\n".utf8)); defer { fixture.remove() }
        let parsed = try fixture.parse(), original = try #require(parsed.events.first)
        let fake = TimelineEvent(id: original.id, kind: original.kind, timestamp: original.timestamp, fileID: original.fileID,
            evidencePath: original.evidencePath, title: original.title, detail: original.detail, parser: original.parser,
            recordID: original.recordID, artifactSHA256: original.artifactSHA256,
            sourceReference: TimelineTextSourceReference(derivedTextSHA256: fixture.file.sha256, unit: 1, unitKind: "raw-utf8-document", line: 1, utf8Offset: 500, utf8Length: 10))
        let report = TimelineReport(binding: fixture.binding, events: [fake], artifactReceipts: parsed.receipts,
            warnings: parsed.warnings, coverage: "test", parserReceipts: [parsed.parserReceipt])
        #expect(throws: TimelineError.self) { try TimelineReportExporter.validate(report) }
    }
}

private struct SyslogFixture {
    let directory: URL
    let file: VerifiedArtifactFile
    let binding: TimelineSourceBinding
    init(bytes: Data) throws {
        directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("syslog-test-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let url = directory.appendingPathComponent("verified-log")
        try bytes.write(to: url)
        file = VerifiedArtifactFile(url: url, fileID: "syslog-17", evidencePath: "/ไทย/system.log", byteCount: Int64(bytes.count), sha256: TimelineCoding.hex(SHA256.hash(data: bytes)))
        binding = TimelineSourceBinding(caseID: UUID(), evidenceID: UUID(), snapshotSHA256: String(repeating: "a", count: 64),
            orderedContainerSHA256: [String(repeating: "b", count: 64)], logicalImageSHA256: nil, engineVersion: "synthetic", engineTimezone: "Asia/Bangkok",
            snapshotSavedAt: Date(timeIntervalSince1970: 1_791_253_500), listingStatus: .completed, historical: false)
    }
    func parse(options: SyslogParserOptions = SyslogParserOptions()) throws -> SyslogTimelineResult {
        try SyslogTimelineParser.parse(file: file, binding: binding, options: options)
    }
    func report(_ parsed: SyslogTimelineResult) -> TimelineReport {
        TimelineReport(binding: binding, events: parsed.events, artifactReceipts: parsed.receipts, warnings: parsed.warnings,
            coverage: "One selected synthetic log", parserReceipts: [parsed.parserReceipt])
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
}
