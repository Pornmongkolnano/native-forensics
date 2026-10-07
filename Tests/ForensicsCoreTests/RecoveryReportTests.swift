import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

struct RecoveryReportTests {
    @Test("Reports distinguish verified bytes, decoder status, raw EXIF and manual observations")
    func observationBoundaries() async throws {
        let fixture = try await ReportFixture.make(filename: "candidate.jpg")
        defer { fixture.remove() }
        let result = fixture.result
        let artifact = try #require(result.artifacts.first)
        let date = "2001:01:06 11:12:30"
        let analysis = DocumentAnalysis(contentKind: .image, mimeType: "image/jpeg", status: .decoded,
            sourceSHA256: artifact.sha256, sourceByteCount: artifact.byteCount, pixelWidth: 20, pixelHeight: 10,
            rawMetadata: [DocumentRawMetadata(name: "EXIF.DateTimeOriginal", value: date)])
        let annotation = RecoveryAnnotation(artifactID: artifact.id, assessment: .damaged,
            note: "Examiner: part of the scene is missing.")
        let report = RecoveryReportBuilder.renderMarkdown(result: result, analyses: [artifact.id: analysis],
            annotations: [artifact.id: annotation])
        #expect(report.contains(result.sourceSHA256))
        #expect(report.contains(artifact.sha256))
        #expect(report.contains("selected-file-bytes"))
        #expect(report.contains("sourceBytesVerified"))
        #expect(report.contains("0 → 64 + \(artifact.byteCount) bytes"))
        #expect(report.contains(date))
        #expect(report.contains("zone unknown"))
        #expect(report.contains("Examiner assessment (manual): damaged"))
        #expect(report.contains("Deletion status: unknown"))
        #expect(report.contains("MIME image/jpeg"))
        #expect(!report.contains(fixture.source.path))
        #expect(!report.contains(fixture.caseURL.path))
        #expect(report.contains(try RecoveryAnnotationStore.resultDigest(result)))
    }

    @Test("PDF page references and incomplete text scope remain explicit")
    func partialPDF() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let analysis = DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: artifact.sha256, sourceByteCount: artifact.byteCount, pageCount: 2,
            textPages: [DocumentTextPage(pageNumber: 1, text: "Diary of Jack", isTruncated: true)])
        let report = RecoveryReportBuilder.renderMarkdown(result: fixture.result, analyses: [artifact.id: analysis])
        #expect(report.contains("partial or unavailable decoded-text coverage"))
        #expect(report.contains("Page 1 (decoder text truncated): Diary of Jack"))
        #expect(report.contains("decoded pages 1/2"))
        #expect(report.contains("No OCR"))
        #expect(!report.contains("absence proven"))
    }

    @Test("Office reports preserve worksheet references and separate recognition from readability")
    func officeReferences() async throws {
        let fixture = try await ReportFixture.make(filename: "misleading.jpg")
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let xlsx = DocumentAnalysis(contentKind: .office,
            mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", status: .decoded,
            sourceSHA256: artifact.sha256, sourceByteCount: artifact.byteCount, officeFormat: .xlsx,
            contentUnitCount: 1, structuralValidation: .validated,
            textPages: [DocumentTextPage(pageNumber: 1, text: "Jan1 diary",
                referenceLabel: "Sheet 1: Summary", referenceKind: .sheet)])
        let report = RecoveryReportBuilder.renderMarkdown(result: fixture.result, analyses: [artifact.id: xlsx])
        #expect(report.contains("misleading.jpg"))
        #expect(report.contains("Office format: xlsx; structural validation: validated"))
        #expect(report.contains("Sheet 1: Summary: Jan1 diary"))
        #expect(report.contains("decoded text units 1/1"))
        #expect(!report.contains("Page 1: Jan1 diary"))
        let legacy = DocumentAnalysis(contentKind: .office, mimeType: "application/msword", status: .unsupported,
            sourceSHA256: artifact.sha256, sourceByteCount: artifact.byteCount,
            officeFormat: .doc, structuralValidation: .validated)
        let legacyReport = RecoveryReportBuilder.renderMarkdown(result: fixture.result, analyses: [artifact.id: legacy])
        #expect(legacyReport.contains("Decoder observation: unsupported"))
        #expect(legacyReport.contains("Structural recognition alone does not establish readable document content"))
        #expect(legacyReport.contains("partial or unavailable decoded-text coverage"))
    }

    @Test("Untrusted report text cannot inject table rows, links, HTML or host paths")
    func escaping() async throws {
        let fixture = try await ReportFixture.make(filename: "[claim](evil)|<b>candidate</b>".replacingOccurrences(of: "/", with: ""))
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let annotation = RecoveryAnnotation(artifactID: artifact.id, assessment: .unknown,
            note: "![embed](https://evil.invalid)\n<script>alert(1)</script> /Users/private-person/private-note")
        let report = RecoveryReportBuilder.renderMarkdown(result: fixture.result, analyses: [:],
            annotations: [artifact.id: annotation])
        #expect(!report.contains("[claim](evil)"))
        #expect(!report.contains("![embed]"))
        #expect(!report.contains("<script>"))
        #expect(!report.contains("/Users/private-person"))
        #expect(report.contains("&#124;"))
        #expect(report.contains("&lt;script&gt;"))
        #expect(report.contains("host path redacted"))
    }

    @Test("Mismatched analysis receipts are omitted in preview and refused by export")
    func mismatchedAnalysis() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let analysis = DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: String(repeating: "b", count: 64), sourceByteCount: artifact.byteCount,
            pageCount: 1, textPages: [DocumentTextPage(pageNumber: 1, text: "FALSE FINDING")])
        let report = RecoveryReportBuilder.renderMarkdown(result: fixture.result, analyses: [artifact.id: analysis])
        #expect(report.contains("1 mismatched/invalid decoder results"))
        #expect(!report.contains("FALSE FINDING"))
        let destination = fixture.root.appendingPathComponent("invalid.md")
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [artifact.id: analysis],
                in: fixture.caseURL, to: destination)
        }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test("Exports are exclusive and cannot overwrite any evidence or case storage")
    func exportSafety() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let destination = fixture.root.appendingPathComponent("report.md")
        #expect(try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [:],
            in: fixture.caseURL, to: destination) == destination)
        let original = try Data(contentsOf: destination)
        #expect(throws: RecoveryError.destinationExists) {
            try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [:], in: fixture.caseURL, to: destination)
        }
        for path in [fixture.source, fixture.caseURL.appendingPathComponent("report.md")] {
            #expect(throws: RecoveryError.scopeMismatch) {
                try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [:], in: fixture.caseURL, to: path)
            }
        }
        let alias = fixture.root.appendingPathComponent("alias.md")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture.source)
        #expect(throws: RecoveryError.destinationExists) {
            try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [:], in: fixture.caseURL, to: alias)
        }
        #expect(try Data(contentsOf: destination) == original)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Report export catches same-size stored payload tampering before publishing")
    func tamperedPayloadExport() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let payload = fixture.resultURL.deletingLastPathComponent().appendingPathComponent(artifact.relativePath)
        try Data(repeating: 0x7f, count: Int(artifact.byteCount)).write(to: payload)
        let destination = fixture.root.appendingPathComponent("rejected.md")
        #expect(throws: RecoveryError.artifactChanged) {
            try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [:],
                in: fixture.caseURL, to: destination)
        }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test("Report export refuses intermediate destination directory symlinks")
    func intermediateExportSymlink() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let alias = fixture.root.appendingPathComponent("output-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture.root)
        #expect(throws: (any Error).self) {
            try RecoveryReportBuilder.exportMarkdown(result: fixture.result, analyses: [:],
                in: fixture.caseURL, to: alias.appendingPathComponent("rejected.md"))
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("rejected.md").path))
    }

    @Test("Manual annotations are scoped to known artifact IDs and capped by UTF-8 bytes")
    func annotationScope() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let foreign = RecoveryAnnotation(artifactID: UUID(), note: "FOREIGN FINDING")
        let report = RecoveryReportBuilder.renderMarkdown(result: fixture.result, analyses: [:],
            annotations: [foreign.artifactID: foreign])
        #expect(report.contains("1 out-of-scope/invalid annotations"))
        #expect(!report.contains("FOREIGN FINDING"))
        #expect(throws: RecoveryError.scopeMismatch) {
            try RecoveryAnnotationStore.save(annotation: foreign, result: fixture.result, in: fixture.caseURL)
        }
        let artifact = try #require(fixture.result.artifacts.first)
        let oversized = RecoveryAnnotation(artifactID: artifact.id, note: String(repeating: "😀", count: 2_049))
        #expect(throws: RecoveryError.invalidResult) {
            try RecoveryAnnotationStore.save(annotation: oversized, result: fixture.result, in: fixture.caseURL)
        }
    }

    @Test("Annotation revisions are durable, immutable, scoped to a job and usable with source offline")
    func annotationHistory() async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let manifestBefore = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        let resultBefore = try Data(contentsOf: fixture.resultURL)
        #expect(try RecoveryAnnotationStore.latest(result: fixture.result, in: fixture.caseURL).isEmpty)
        let first = try RecoveryAnnotationStore.save(annotation: RecoveryAnnotation(artifactID: artifact.id,
            assessment: .accessible, note: "First review"), result: fixture.result, in: fixture.caseURL)
        let second = try RecoveryAnnotationStore.save(annotation: RecoveryAnnotation(artifactID: artifact.id,
            assessment: .damaged, note: "Second review"), result: fixture.result, in: fixture.caseURL)
        #expect(first.revision == 1 && first.previousRevisionID == nil)
        #expect(second.revision == 2 && second.previousRevisionID == first.id)
        #expect(first.resultSHA256 == second.resultSHA256)
        #expect(try RecoveryAnnotationStore.history(result: fixture.result, in: fixture.caseURL) == [first, second])
        try FileManager.default.removeItem(at: fixture.source)
        let latest = try RecoveryAnnotationStore.latest(result: fixture.result, in: fixture.caseURL)
        #expect(latest[artifact.id] == second.annotation)
        #expect(try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json")) == manifestBefore)
        #expect(try Data(contentsOf: fixture.resultURL) == resultBefore)
    }

    @Test("Corrupt and symlinked annotation history never silently falls back", arguments: ["corrupt", "symlink", "hardlink", "missing-previous"])
    func unsafeAnnotationHistory(_ mode: String) async throws {
        let fixture = try await ReportFixture.make()
        defer { fixture.remove() }
        let artifact = try #require(fixture.result.artifacts.first)
        let first = try RecoveryAnnotationStore.save(annotation: RecoveryAnnotation(artifactID: artifact.id,
            note: "Keep first revision"), result: fixture.result, in: fixture.caseURL)
        let firstURL = fixture.notesURL.appendingPathComponent(first.id.uuidString.lowercased() + ".json")
        switch mode {
        case "corrupt": try Data("{".utf8).write(to: firstURL)
        case "symlink":
            try FileManager.default.removeItem(at: firstURL)
            try FileManager.default.createSymbolicLink(at: firstURL, withDestinationURL: fixture.input)
        case "hardlink":
            let extra = fixture.root.appendingPathComponent("annotation-copy")
            try FileManager.default.linkItem(at: firstURL, to: extra)
        default:
            _ = try RecoveryAnnotationStore.save(annotation: RecoveryAnnotation(artifactID: artifact.id,
                note: "Second revision"), result: fixture.result, in: fixture.caseURL)
            try FileManager.default.removeItem(at: firstURL)
        }
        #expect(throws: (any Error).self) { try RecoveryAnnotationStore.latest(result: fixture.result, in: fixture.caseURL) }
        #expect(throws: (any Error).self) {
            try RecoveryAnnotationStore.save(annotation: RecoveryAnnotation(artifactID: artifact.id,
                note: "Should not append"), result: fixture.result, in: fixture.caseURL)
        }
    }
}

private struct ReportFixture: Sendable {
    let root: URL
    let source: URL
    let sourceBytes: Data
    let caseURL: URL
    let input: URL
    let result: CarvingResult
    var resultURL: URL {
        caseURL.appendingPathComponent("recovery").appendingPathComponent(result.sourceEvidenceID.uuidString.lowercased())
            .appendingPathComponent(result.jobID.uuidString.lowercased()).appendingPathComponent("result.json")
    }
    var notesURL: URL {
        caseURL.appendingPathComponent("recovery-notes").appendingPathComponent(result.sourceEvidenceID.uuidString.lowercased())
            .appendingPathComponent(result.jobID.uuidString.lowercased())
    }
    static func make(filename: String = "candidate.pdf") async throws -> ReportFixture {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("RecoveryReportTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            let payload = Data("synthetic recovered document bytes".utf8)
            var bytes = Data(repeating: 0x42, count: 64); bytes.append(payload)
            let source = root.appendingPathComponent("synthetic.dd")
            try bytes.write(to: source, options: .withoutOverwriting)
            let inspected = try await ImageInspector.inspect(url: source) { _ in }
            let created = try CaseStore.create(name: "Report", in: root)
            let forensicCase = try CaseStore.adding(image: inspected, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let input = root.appendingPathComponent("independent-candidate")
            try payload.write(to: input, options: .withoutOverwriting)
            let id = UUID(), run = RecoveryByteRun(outputOffset: 0, sourceOffset: 64, length: Int64(payload.count))
            let artifact = CarvedArtifact(id: id, filename: filename, relativePath: "files/\(id.uuidString.lowercased())",
                formatHint: "pdf", byteCount: Int64(payload.count),
                sha256: SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined(),
                reportedByteRuns: [run], verifiedByteRuns: [run], validationStatus: .sourceBytesVerified)
            let result = CarvingResult(caseID: forensicCase.manifest.id, sourceEvidenceID: evidence.id,
                sourceSHA256: evidence.sha256, sourceByteCount: evidence.byteCount, status: .completed,
                artifacts: [artifact], warnings: [], photoRecVersion: "synthetic-test",
                executableSHA256: String(repeating: "a", count: 64), options: RecoveryOptions())
            try RecoveryResultStore.save(result: result, artifactFiles: [id: input], in: forensicCase)
            return ReportFixture(root: root, source: source, sourceBytes: bytes,
                caseURL: forensicCase.bundleURL, input: input, result: result)
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
