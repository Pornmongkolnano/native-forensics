import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Filesystem timeline and exclusive reports")
struct FilesystemTimelineTests {
    private let hash = String(repeating: "a", count: 64)
    private func fixture(status: EngineTerminalStatus = .completed, modified: Int64 = 1_700_000_010) -> (UUID, EvidenceRecord, EnumerationResult) {
        let evidence = EvidenceRecord(sourcePath: "/synthetic/fixture.dd", byteCount: 4096, sha256: hash, container: .raw, filesystemHint: "ntfs")
        let file = FilesystemEntry(id: "file-17", path: "/ไทย/notes.txt", name: "notes.txt", fsOffsetBytes: 0, metaAddress: 17,
            size: 5, isDirectory: false, isDeleted: true, createdEpoch: 1_700_000_000, modifiedEpoch: modified, accessedEpoch: nil,
            changedEpoch: 1_700_000_005, createdNanoseconds: 123_456_700)
        let result = EnumerationResult(engineVersion: "test-engine", patchDigest: "test-patch", sourcePaths: [evidence.sourcePath],
            sourceFileHashes: [evidence.sourcePath: hash], options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 4096, sectorSize: 512),
            volumes: [EngineVolume(id: "volume", offsetBytes: 0, filesystem: "ntfs", blockSize: 512, blockCount: 8)],
            files: [file], warnings: [], status: status, savedAt: Date(timeIntervalSince1970: 1_800_000_000))
        return (UUID(), evidence, result)
    }
    @Test func metadataHasExactEpochsNoDeletionTimeAndStableSnapshot() throws {
        let (caseID, evidence, listing) = fixture()
        let result = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        #expect(result.events.count == 3)
        #expect(result.events.map(\.kind) == [.filesystemCreated, .filesystemChanged, .filesystemModified])
        #expect(result.events.map { $0.timestamp.epochSeconds } == [1_700_000_000, 1_700_000_005, 1_700_000_010])
        #expect(result.events.first?.timestamp.nanoseconds == 123_456_700)
        #expect(result.events.allSatisfy { $0.isDeleted })
        #expect(result.events.allSatisfy { $0.artifactSHA256 == nil })
        #expect(result.events.first?.timestamp.precision.contains("unavailable") == true)
        #expect(result.binding.engineProvenance?.options == listing.options)
        #expect(result.binding.engineProvenance?.patchDigest == listing.patchDigest)
        #expect(result.binding.engineProvenance?.orderedInputs.first?.ordinal == 0)
        #expect(result.binding.engineProvenance?.orderedInputs.first?.byteCount == evidence.byteCount)
        #expect(result.binding.engineProvenance?.orderedInputs.first?.hashScope == "selected-file-bytes")
        #expect(result.binding.hashScopes == TimelineSourceBinding.currentHashScopes)
        #expect(result.binding == (try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)).binding)
    }
    @Test func rawFilesystemGapOverlapAndInvalidCalendarRemainUnresolvedObservations() throws {
        let (caseID, evidence, original) = fixture()
        let overlap = FilesystemCivilTimestamp(rawDate: 23905, rawTime: 3008, civil: "2026-11-01T01:30:00", status: .ambiguousLocalTime,
            timezone: "America/New_York", candidateEpochs: [1_793_511_000, 1_793_514_600], precisionNanoseconds: 2_000_000_000)
        let gap = FilesystemCivilTimestamp(rawDate: 23656, rawTime: 5056, civil: "2026-03-08T02:30:00", status: .nonexistentLocalTime,
            timezone: "America/New_York", precisionNanoseconds: 2_000_000_000)
        let invalid = FilesystemCivilTimestamp(rawDate: 65535, rawTime: 65535, status: .invalidCalendar, precisionNanoseconds: 2_000_000_000)
        let file = FilesystemEntry(id: "uncertain", path: "/uncertain.txt", name: "uncertain.txt", fsOffsetBytes: 0, metaAddress: 22,
            size: 1, isDirectory: false, isDeleted: false, timestampProvenance: FilesystemTimestampProvenance(created: overlap, modified: gap, accessed: invalid))
        let listing = EnumerationResult(engineVersion: original.engineVersion, patchDigest: original.patchDigest, sourcePaths: original.sourcePaths,
            sourceFileHashes: original.sourceFileHashes, options: original.options, image: original.image, volumes: original.volumes, files: [file], warnings: [], status: .completed,
            savedAt: original.savedAt)
        let report = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        #expect(report.events.count == 3)
        #expect(report.events.allSatisfy { $0.timestamp.epochSeconds == nil && $0.filesystemTimestamp != nil })
        let retained = try #require(report.events.first { $0.kind == .filesystemCreated })
        #expect(retained.timestamp.alternativeEpochSeconds == [1_793_511_000, 1_793_514_600])
        #expect(retained.timestamp.rawValue.contains("2026-11-01T01:30:00"))
        #expect(retained.timestamp.precision == "native resolution=2000000000 nanoseconds")
        #expect(try TimelineFilter(includeUnresolved: false).apply(to: report.events).isEmpty)
        try TimelineReportExporter.validate(report)
    }
    @Test func changedEntryChangesDigestAndHistoricalPartialWarnings() throws {
        let (caseID, evidence, listing) = fixture(status: .partial)
        let report = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: true)
        let changed = fixture(modified: 1_700_000_011)
        let other = try FilesystemTimeline.make(caseID: caseID, evidence: changed.1, result: changed.2, historical: true)
        #expect(report.binding.snapshotSHA256 != other.binding.snapshotSHA256)
        #expect(report.warnings.contains { $0.contains("Partial") })
        #expect(report.warnings.contains { $0.contains("Historical") })
        #expect(report.binding.historical)
    }
    @Test func mismatchedEvidenceRejected() throws {
        let (caseID, evidence, listing) = fixture()
        let wrong = EvidenceRecord(id: evidence.id, sourcePath: evidence.sourcePath, byteCount: evidence.byteCount, sha256: String(repeating: "b", count: 64), container: .raw, filesystemHint: nil)
        #expect(throws: TimelineError.sourceChanged) { try FilesystemTimeline.make(caseID: caseID, evidence: wrong, result: listing, historical: false) }
    }
    @Test func dateAndThaiSearchAreDeterministic() throws {
        let (caseID, evidence, listing) = fixture()
        let report = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        let filtered = try TimelineFilter(query: "ไทย", from: Date(timeIntervalSince1970: 1_700_000_004), through: Date(timeIntervalSince1970: 1_700_000_007)).apply(to: report.events)
        #expect(filtered.count == 1); #expect(filtered.first?.kind == .filesystemChanged)
        #expect(try TimelineFilter(query: "absent").apply(to: report.events).isEmpty)
    }
    @Test func reversedDateBoundsRejected() throws {
        #expect(throws: (any Error).self) { try TimelineFilter(from: Date(timeIntervalSince1970: 2), through: Date(timeIntervalSince1970: 1)).apply(to: []) }
    }
    @Test func unresolvedTimeIsExplicitlyIncludedOrExcluded() throws {
        let event = TimelineEvent(id: hash, kind: .browserVisit, timestamp: TimelineTimestamp.rfc3339("2026-01-01T12:00:00-00:00"),
            fileID: "history", evidencePath: "/History", title: "example", detail: "", parser: "test", recordID: "1")
        #expect(try TimelineFilter(from: Date(), includeUnresolved: true).apply(to: [event]) == [event])
        #expect(try TimelineFilter(includeUnresolved: false).apply(to: [event]).isEmpty)
    }
    @Test func reportSeparatesInterpretationAndNotesAndRedactsHostSource() throws {
        let (caseID, evidence, listing) = fixture()
        let base = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        let report = TimelineReport(binding: base.binding, events: base.events, warnings: base.warnings, coverage: base.coverage,
            aiInterpretation: "Hypothesis only", examinerNotes: "Examiner | notes <script>")
        let markdown = String(decoding: try TimelineReportExporter.markdown(report), as: UTF8.self)
        #expect(markdown.contains("## Deterministic parser observations"))
        #expect(markdown.contains("## AI interpretation (unverified)"))
        #expect(markdown.contains("## Examiner notes"))
        #expect(markdown.contains("deleted entry; deletion time unknown"))
        #expect(markdown.contains("Examiner \\| notes &lt;script&gt;"))
        #expect(!markdown.contains(evidence.sourcePath))
        let json = try TimelineCoding.encode(report)
        #expect(!String(decoding: json, as: UTF8.self).contains(evidence.sourcePath))
        #expect(try JSONDecoder.timeline.decode(TimelineReport.self, from: json) == report)
    }
    @Test func exclusiveExportHashesAndExistingOutputRemainIntact() async throws {
        let (caseID, evidence, listing) = fixture()
        let report = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-test-\(UUID())")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: parent) }
        let destination = parent.appendingPathComponent("report")
        let receipt = try await TimelineReportExporter.export(report, to: destination, forbiddenURLs: [])
        let json = try Data(contentsOf: destination.appendingPathComponent("timeline.json"))
        let markdown = try Data(contentsOf: destination.appendingPathComponent("timeline.md"))
        let pdf = try Data(contentsOf: destination.appendingPathComponent("timeline.pdf"))
        #expect(receipt.jsonSHA256 == TimelineCoding.hex(SHA256.hash(data: json)))
        #expect(receipt.markdownSHA256 == TimelineCoding.hex(SHA256.hash(data: markdown)))
        #expect(receipt.pdfSHA256 == TimelineCoding.hex(SHA256.hash(data: pdf)))
        #expect(pdf.starts(with: Data("%PDF-".utf8)))
        let shareable = try Data(contentsOf: destination.appendingPathComponent("receipt.json"))
        #expect(String(decoding: shareable, as: UTF8.self).contains(try #require(receipt.pdfSHA256)))
        #expect(!String(decoding: shareable, as: UTF8.self).contains(parent.path))
        #expect(receipt.eventCount == 3)
        do { _ = try await TimelineReportExporter.export(report, to: destination, forbiddenURLs: []); Issue.record("Existing report was replaced") } catch { }
        #expect(try Data(contentsOf: destination.appendingPathComponent("timeline.json")) == json)
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.path) == ["report"])
    }
    @Test("Directory-hinted panel-style URLs publish outside evidence and case", arguments: [false, true])
    func panelStyleDirectoryURL(directoryHint: Bool) async throws {
        let (caseID, evidence, listing) = fixture()
        let report = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-panel-style-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: parent) }
        let protectedCase = parent.appendingPathComponent("Original Case.nativecase", isDirectory: true)
        let protectedSource = parent.appendingPathComponent("source.dd")
        try FileManager.default.createDirectory(at: protectedCase, withIntermediateDirectories: false)
        try Data("frozen synthetic source".utf8).write(to: protectedSource)
        let destination = parent.appendingPathComponent("Panel style report with spaces", isDirectory: directoryHint)
        let receipt = try await TimelineReportExporter.export(report, to: destination, forbiddenURLs: [protectedSource, protectedCase])
        #expect(receipt.destinationPath == destination.path)
        #expect(FileManager.default.fileExists(atPath: destination.appendingPathComponent("timeline.json").path))
        #expect(try Data(contentsOf: protectedSource) == Data("frozen synthetic source".utf8))
        #expect(try FileManager.default.contentsOfDirectory(atPath: protectedCase.path).isEmpty)
    }
    @Test func evidenceAndCaseOverlapAndSymlinkRejected() async throws {
        let (caseID, evidence, listing) = fixture()
        let report = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("timeline-test-\(UUID())")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: parent) }
        let caseURL = parent.appendingPathComponent("protected.nativecase")
        try FileManager.default.createDirectory(at: caseURL, withIntermediateDirectories: false)
        do { _ = try await TimelineReportExporter.export(report, to: caseURL.appendingPathComponent("report"), forbiddenURLs: [caseURL]); Issue.record("Case export allowed") } catch { }
        let link = parent.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: caseURL)
        do { _ = try await TimelineReportExporter.export(report, to: link.appendingPathComponent("report"), forbiddenURLs: []); Issue.record("Symlink export allowed") } catch { }
        #expect(try FileManager.default.contentsOfDirectory(atPath: caseURL.path).isEmpty)
    }
    @Test func duplicateEventsAndOversizedNotesRejected() throws {
        let (caseID, evidence, listing) = fixture()
        let base = try FilesystemTimeline.make(caseID: caseID, evidence: evidence, result: listing, historical: false)
        let duplicate = TimelineReport(binding: base.binding, events: base.events + base.events, warnings: [], coverage: "test")
        #expect(throws: (any Error).self) { try TimelineReportExporter.validate(duplicate) }
        let oversized = TimelineReport(binding: base.binding, events: [], warnings: [], coverage: "test", examinerNotes: String(repeating: "a", count: TimelineLimits.maximumNotesBytes + 1))
        #expect(throws: (any Error).self) { try TimelineReportExporter.validate(oversized) }
    }
}

private extension JSONDecoder {
    static var timeline: JSONDecoder { let value = JSONDecoder(); value.dateDecodingStrategy = .iso8601; return value }
}
