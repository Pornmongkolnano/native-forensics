import Foundation
import Testing
@testable import ForensicsCore

struct CaseIntegrityComparisonTests {
    @Test("Digest-only follow-up audits enforce the same exact disclosure parent as normal reads", arguments: ["selectedRanges", "redactedRanges", "disclosedSHA256"])
    func changedParentDisclosure(_ field: String) async throws {
        let fixture = try await IntegrityComparisonFixture.make()
        defer { fixture.remove() }
        let context = try MultiEvidenceContext.make(files: fixture.files, selections: [
            .init(ranges: [.init(start: 0, end: 3)]), fixture.files[1].defaultSelection
        ])
        let parentPrompt = try MultiEvidencePrompt.make(context: context, question: "Compare these synthetic excerpts")
        let parent = try MultiEvidenceAnalysisRecord.make(context: context, question: "Compare these synthetic excerpts",
            prompt: parentPrompt, result: fixture.response(prompt: parentPrompt), retention: .digestOnly)
        try MultiEvidenceRecordStore.save(parent, in: fixture.forensicCase.bundleURL)
        let childPrompt = try MultiEvidencePrompt.make(context: context, question: "What remains uncertain?", parent: parent)
        let child = try MultiEvidenceAnalysisRecord.make(context: context, question: "What remains uncertain?",
            prompt: childPrompt, result: fixture.response(prompt: childPrompt), retention: .digestOnly, parent: parent)
        try MultiEvidenceRecordStore.save(child, in: fixture.forensicCase.bundleURL)

        let relativePath = "comparisons/\(child.id.uuidString.lowercased()).json"
        let childURL = fixture.forensicCase.bundleURL.appendingPathComponent(relativePath)
        let parentURL = fixture.forensicCase.bundleURL.appendingPathComponent("comparisons/\(parent.id.uuidString.lowercased()).json")
        let manifestURL = fixture.forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let originalParent = try Data(contentsOf: parentURL), originalManifest = try Data(contentsOf: manifestURL)
        #expect(try MultiEvidenceRecordStore.load(id: child.id, in: fixture.forensicCase.bundleURL) == child)
        let validAudit = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(!validAudit.hasFailures)
        #expect(validAudit.checks.contains { $0.relativePath == relativePath && $0.code == "metadata.valid" })

        // Each edit remains valid as an individual digest-only receipt. The
        // failure must come from its exact persisted follow-up-parent relation,
        // rather than malformed JSON, a changed file binding or full-file hash.
        var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: childURL)) as? [String: Any])
        var savedContext = try #require(object["context"] as? [String: Any])
        var disclosures = try #require(savedContext["files"] as? [[String: Any]])
        switch field {
        case "selectedRanges":
            // A different, internally consistent disclosure still refers to
            // the same complete verified file. Keep its ranges, segment and
            // counts aligned; only the persisted parent relation may fail.
            let changed = try MultiEvidenceContext.make(files: fixture.files, selections: [
                .init(ranges: [.init(start: 0, end: 4)]), fixture.files[1].defaultSelection
            ])
            let segment = try #require(changed.files[0].segments.first)
            #expect(segment.text == "one ")
            #expect(segment.byteCount == 4)
            #expect(segment.disclosedSHA256 == MultiEvidenceCoding.digest(Data("one ".utf8)))
            disclosures[0] = try #require(JSONSerialization.jsonObject(with:
                CaseWorkCoding.encode(changed.withoutText().files[0])) as? [String: Any])
        case "redactedRanges": disclosures[0]["redactedRanges"] = [["start": 4, "end": 11]]
        default:
            var segments = try #require(disclosures[0]["segments"] as? [[String: Any]])
            segments[0]["disclosedSHA256"] = MultiEvidenceCoding.digest(Data("bad".utf8))
            disclosures[0]["segments"] = segments
        }
        savedContext["files"] = disclosures; object["context"] = savedContext
        let editedBytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let edited = try CaseWorkCoding.decode(MultiEvidenceAnalysisRecord.self, editedBytes)
        try edited.validate()
        #expect(edited.retention == .digestOnly)
        #expect(edited.context.files.map(\.binding) == parent.context.files.map(\.binding))
        #expect(edited.context.files.map(\.contentSHA256) == parent.context.files.map(\.contentSHA256))
        #expect(edited.parentRequestSHA256 == parent.requestSHA256)
        try editedBytes.write(to: childURL)
        #expect(throws: MultiEvidenceError.parentMismatch) {
            try MultiEvidenceRecordStore.load(id: child.id, in: fixture.forensicCase.bundleURL)
        }

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.relativePath == relativePath && $0.code == "metadata.invalid" && $0.status == .fail })
        #expect(!report.checks.contains { $0.relativePath == relativePath && $0.code == "metadata.valid" })
        #expect(!report.sourceRehashed)
        #expect(try Data(contentsOf: childURL) == editedBytes)
        #expect(try Data(contentsOf: parentURL) == originalParent)
        #expect(try Data(contentsOf: manifestURL) == originalManifest)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }
}

private struct IntegrityComparisonFixture {
    let directory: URL
    let source: URL
    let sourceBytes: Data
    let forensicCase: ForensicCase
    let files: [MultiEvidenceVerifiedFile]

    static func make() async throws -> Self {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("IntegrityComparison-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            let source = directory.appendingPathComponent("synthetic-source.dd")
            let sourceBytes = Data("synthetic image".utf8)
            try sourceBytes.write(to: source)
            let created = try CaseStore.create(name: "Synthetic Integrity Comparison", in: directory)
            let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
            let forensicCase = try CaseStore.adding(image: inspected, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let texts = ["one PRIVATE tail", "two"]
            let entries = texts.enumerated().map { index, text in
                FilesystemEntry(id: "0:\(index + 1)", path: "/FILE\(index + 1).txt", name: "FILE\(index + 1).txt",
                    fsOffsetBytes: 0, metaAddress: UInt64(index + 1), size: Int64(text.utf8.count),
                    isDirectory: false, isDeleted: false)
            }
            let result = EnumerationResult(engineVersion: "synthetic-integrity-comparison", patchDigest: "synthetic-only",
                sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
                image: .init(imageType: "raw", logicalSize: Int64(sourceBytes.count), sectorSize: 512),
                volumes: [], files: entries, warnings: [], status: .partial,
                savedAt: Date(timeIntervalSinceReferenceDate: 813_457_691.1234567))
            let files = try entries.enumerated().map { index, entry in
                let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entry)
                let bytes = Data(texts[index].utf8)
                let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entry.id, byteCount: entry.size,
                    sha256: MultiEvidenceCoding.digest(bytes), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
                return try MultiEvidenceVerifiedFile(binding: binding, content: .init(bytes: bytes, receipt: receipt))
            }
            return Self(directory: directory, source: source, sourceBytes: sourceBytes, forensicCase: forensicCase, files: files)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func response(prompt: String) -> CodexAnalysisResult {
        .init(response: .init(summary: "Synthetic comparison", observations: [], hypotheses: [],
            limitations: ["Synthetic model fixture only; no AI request was submitted."], nextSteps: []),
            requestSHA256: MultiEvidenceCoding.digest(Data(prompt.utf8)),
            completedAt: Date(timeIntervalSinceReferenceDate: 813_457_694.9876543))
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }
}
