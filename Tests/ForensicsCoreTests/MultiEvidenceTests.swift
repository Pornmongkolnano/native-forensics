import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Reviewed two-file Codex comparisons")
struct MultiEvidenceTests {
    @Test("Redactions are removed before serialization and surviving citations map exact original UTF-8 bytes")
    func redactionMapping() async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "one SECRET two", second: "หลักฐานสอง")
        defer { fixture.remove() }
        let context = try fixture.context(selections: [.init(ranges: [.init(start: 0, end: 14)], redactions: [.init(start: 4, end: 10)]), fixture.files[1].defaultSelection])
        let prompt = try MultiEvidencePrompt.make(context: context, question: "Compare")
        #expect(!prompt.contains("SECRET")); #expect(context.files[0].segments.map(\.text) == ["one ", " two"])
        let references = MultiEvidenceReferences.validate(response: fixture.answer("Support [[A2:1:4]]"), context: context)
        let reference = try #require(references.first)
        #expect(reference.state == .disclosed); #expect(reference.sourceRange == .init(start: 11, end: 14))
        #expect(try MultiEvidenceReferences.open(reference, context: context, current: fixture.files) == "two")
        #expect(!prompt.contains(fixture.source.path)); #expect(!prompt.contains("private engine warning"))
    }

    @Test("Unknown, malformed, out-of-range and split UTF-8 citations remain unresolved", arguments: ["[[X9:0:2]]", "[[A1:-1:2]]", "[[A1:0:99]]", "[[A1:1:3]]", "[[A1:not:a-range]]", "[[A1:3:3]]", "[[A1:0:03]]"])
    func forgedReferences(_ marker: String) async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "ไทย", second: "two")
        defer { fixture.remove() }
        let refs = MultiEvidenceReferences.validate(response: fixture.answer(marker), context: try fixture.context())
        #expect(refs.count == 1); #expect(refs.first?.state == .unresolved)
    }

    @Test("Redacted intervals cannot be selected through disclosed segment offsets")
    func hiddenRangeCannotResolve() async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "visible SECRET tail", second: "two")
        defer { fixture.remove() }
        let context = try fixture.context(selections: [.init(ranges: [.init(start: 0, end: 19)], redactions: [.init(start: 8, end: 14)]), fixture.files[1].defaultSelection])
        let refs = MultiEvidenceReferences.validate(response: fixture.answer("[[A1:8:14]]"), context: context)
        #expect(refs.first?.state == .unresolved)
    }

    @Test("Source/content mutation makes an originally disclosed citation stale")
    func staleReferences() async throws {
        let fixture = try await MultiEvidenceFixture.make()
        defer { fixture.remove() }
        let context = try fixture.context()
        let ref = try #require(MultiEvidenceReferences.validate(response: fixture.answer("[[A1:0:3]]"), context: context).first)
        let changed = try fixture.verified(index: 0, bytes: Data("bad".utf8))
        #expect(throws: MultiEvidenceError.staleReference) { try MultiEvidenceReferences.open(ref, context: context, current: [changed, fixture.files[1]]) }
        #expect(throws: MultiEvidenceError.staleReference) { try MultiEvidenceReferences.open(ref, context: context, current: []) }
    }

    @Test("Forged references and altered digest-only source mappings cannot open hidden bytes")
    func forgedOpenAndDigestMapping() async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "one SECRET two", second: "two"); defer { fixture.remove() }
        let context = try fixture.context(selections: [.init(ranges: [.init(start: 0, end: 14)], redactions: [.init(start: 4, end: 10)]), fixture.files[1].defaultSelection])
        let prompt = try MultiEvidencePrompt.make(context: context, question: "Compare")
        let record = try MultiEvidenceAnalysisRecord.make(context: context, question: "Compare", prompt: prompt,
            result: fixture.response(prompt: prompt, summary: "Support [[A1:0:3]]"), retention: .digestOnly)
        let original = try #require(record.references.first)
        let forged = MultiEvidenceReference(id: original.id, marker: original.marker, segmentID: original.segmentID,
            disclosedRange: original.disclosedRange, sourceRange: .init(start: 4, end: 7), fileID: original.fileID,
            state: .disclosed, reason: original.reason)
        #expect(throws: MultiEvidenceError.staleReference) { try MultiEvidenceReferences.open(forged, context: context, current: fixture.files) }
        // Syntactically plausible historic metadata remains untrusted. Even a
        // digest-only mapping edited toward a hidden range must match the
        // independently recorded disclosed segment digest before opening.
        var json = try #require(JSONSerialization.jsonObject(with: MultiEvidenceCoding.encode(record)) as? [String: Any])
        var savedContext = try #require(json["context"] as? [String: Any])
        var disclosures = try #require(savedContext["files"] as? [[String: Any]])
        var segments = try #require(disclosures[0]["segments"] as? [[String: Any]])
        segments[0]["sourceRange"] = ["start": 4, "end": 8]
        disclosures[0]["segments"] = segments; disclosures[0]["redactedRanges"] = []; disclosures[0]["selectedRanges"] = [["start": 4, "end": 8], ["start": 10, "end": 14]]
        savedContext["files"] = disclosures; json["context"] = savedContext
        var refs = try #require(json["references"] as? [[String: Any]])
        refs[0]["sourceRange"] = ["start": 4, "end": 7]; json["references"] = refs
        let tampered = try CaseWorkCoding.decode(MultiEvidenceAnalysisRecord.self, JSONSerialization.data(withJSONObject: json))
        try tampered.validate()
        #expect(throws: MultiEvidenceError.staleReference) {
            try MultiEvidenceReferences.open(try #require(tampered.references.first), context: tampered.context, current: fixture.files)
        }
    }

    @Test("Ranges reject overlap, overflow, reversed order and partial multibyte boundaries", arguments: [
        [MultiEvidenceRange(start: -1, end: 3)], [.init(start: 0, end: 99)], [.init(start: 4, end: 2)],
        [.init(start: 1, end: 3)], [.init(start: 0, end: 3), .init(start: 2, end: 6)],
        [.init(start: 3, end: 6), .init(start: 0, end: 3)]])
    func invalidRanges(_ ranges: [MultiEvidenceRange]) async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "ไทย", second: "two")
        defer { fixture.remove() }
        #expect(throws: MultiEvidenceError.invalidRange) { try fixture.context(selections: [.init(ranges: ranges), fixture.files[1].defaultSelection]) }
    }

    @Test("Per-file excerpts and escaping-amplified serialized requests have independent budgets")
    func independentBudgets() async throws {
        let fixture = try await MultiEvidenceFixture.make(first: String(repeating: "a", count: 32_769), second: "two")
        defer { fixture.remove() }
        #expect(throws: MultiEvidenceError.budgetExceeded) {
            try fixture.context(selections: [.init(ranges: [.init(start: 0, end: 32_769)]), fixture.files[1].defaultSelection])
        }
        let controls = try await MultiEvidenceFixture.make(first: String(repeating: "\u{0001}", count: 32_768), second: String(repeating: "\u{0001}", count: 32_768))
        defer { controls.remove() }
        let context = try controls.context()
        #expect(context.files.reduce(0) { $0 + $1.disclosedByteCount } == 65_536)
        #expect(throws: MultiEvidenceError.budgetExceeded) { try MultiEvidencePrompt.make(context: context, question: "Compare") }
    }

    @Test("Invalid complete UTF-8, receipt hash, or selected file size cannot create a disclosure", arguments: ["binary", "digest", "size"])
    func invalidVerifiedBytes(_ fault: String) async throws {
        let fixture = try await MultiEvidenceFixture.make()
        defer { fixture.remove() }
        let bytes = fault == "binary" ? Data([0xff, 0xff, 0xff]) : fault == "size" ? Data("four".utf8) : Data("one".utf8)
        let receipt = VerifiedContentReceipt(evidenceID: fixture.evidence.id, fileID: fixture.entries[0].id, byteCount: Int64(bytes.count),
            sha256: fault == "digest" ? String(repeating: "e", count: 64) : MultiEvidenceCoding.digest(bytes), verifiedAt: Date(),
            orderedContainerSHA256: [fixture.evidence.sha256])
        #expect(throws: MultiEvidenceError.invalidContent) { try MultiEvidenceVerifiedFile(binding: fixture.files[0].binding, content: .init(bytes: bytes, receipt: receipt)) }
    }

    @Test("Full and digest-only immutable receipts reopen offline without retaining hidden/source text", arguments: AnalysisRetention.allCases)
    func durableRetention(_ retention: AnalysisRetention) async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "one PRIVATE_SECRET two", second: "second")
        defer { fixture.remove() }
        let context = try fixture.context(selections: [.init(ranges: [.init(start: 0, end: 22)], redactions: [.init(start: 4, end: 18)]), fixture.files[1].defaultSelection])
        let prompt = try MultiEvidencePrompt.make(context: context, question: "Compare")
        let record = try MultiEvidenceAnalysisRecord.make(context: context, question: "Compare", prompt: prompt,
            result: fixture.response(prompt: prompt, summary: "one [[A1:0:3]]"), retention: retention)
        let manifest = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        try MultiEvidenceRecordStore.save(record, in: fixture.caseURL)
        let bytes = try Data(contentsOf: fixture.recordURL(record.id))
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(!text.contains("PRIVATE_SECRET")); #expect(!text.contains(fixture.source.path)); #expect(!text.contains(fixture.caseURL.path))
        #expect(record.context.files[0].segments.first?.text == (retention == .full ? "one " : nil))
        #expect(record.prompt == (retention == .full ? prompt : nil))
        try FileManager.default.removeItem(at: fixture.source)
        #expect(try MultiEvidenceRecordStore.load(id: record.id, in: fixture.caseURL) == record)
        #expect(try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json")) == manifest)
        #expect(try MultiEvidenceRecordStore.history(in: fixture.caseURL).map(\.id) == [record.id])
    }

    @Test("Duplicate save and symlink record/directory replacements never overwrite immutable receipts")
    func immutableAndNoFollow() async throws {
        let fixture = try await MultiEvidenceFixture.make(); defer { fixture.remove() }
        let record = try fixture.record()
        try MultiEvidenceRecordStore.save(record, in: fixture.caseURL)
        let original = try Data(contentsOf: fixture.recordURL(record.id))
        #expect(throws: CaseWorkError.alreadyExists) { try MultiEvidenceRecordStore.save(record, in: fixture.caseURL) }
        #expect(try Data(contentsOf: fixture.recordURL(record.id)) == original)
        try FileManager.default.removeItem(at: fixture.recordURL(record.id))
        try FileManager.default.createSymbolicLink(at: fixture.recordURL(record.id), withDestinationURL: fixture.source)
        #expect(throws: CaseWorkError.unsafePath) { try MultiEvidenceRecordStore.load(id: record.id, in: fixture.caseURL) }
        try FileManager.default.removeItem(at: fixture.caseURL.appendingPathComponent("comparisons"))
        try FileManager.default.createSymbolicLink(at: fixture.caseURL.appendingPathComponent("comparisons"), withDestinationURL: fixture.directory)
        #expect(throws: CaseWorkError.unsafePath) { try MultiEvidenceRecordStore.save(try fixture.record(), in: fixture.caseURL) }
        #expect(try Data(contentsOf: fixture.source) == Data("synthetic image".utf8))
    }

    @Test("Follow-up requires a persisted exact parent and records it as untrusted interpretation")
    func reviewedFollowUp() async throws {
        let fixture = try await MultiEvidenceFixture.make(); defer { fixture.remove() }
        let parent = try fixture.record(retention: .digestOnly)
        let context = try fixture.context()
        let prompt = try MultiEvidencePrompt.make(context: context, question: "What remains uncertain?", parent: parent)
        #expect(prompt.contains("priorUntrustedInterpretation")); #expect(prompt.contains(parent.id.uuidString))
        let child = try MultiEvidenceAnalysisRecord.make(context: context, question: "What remains uncertain?", prompt: prompt,
            result: fixture.response(prompt: prompt), retention: .full, parent: parent)
        #expect(throws: CaseWorkError.unsafePath) { try MultiEvidenceRecordStore.save(child, in: fixture.caseURL) }
        try MultiEvidenceRecordStore.save(parent, in: fixture.caseURL)
        try MultiEvidenceRecordStore.save(child, in: fixture.caseURL)
        #expect(try MultiEvidenceRecordStore.load(id: child.id, in: fixture.caseURL) == child)
        #expect(child.parentRecordID == parent.id); #expect(child.parentRequestSHA256 == parent.requestSHA256)
    }

    @Test("Mismatched review, oversized prior answer, and invalid protocol cannot become a saved record")
    func reviewMismatch() async throws {
        let fixture = try await MultiEvidenceFixture.make(); defer { fixture.remove() }
        let context = try fixture.context(), prompt = try MultiEvidencePrompt.make(context: context, question: "Compare")
        #expect(throws: MultiEvidenceError.requestMismatch) {
            try MultiEvidenceAnalysisRecord.make(context: context, question: "Changed", prompt: prompt,
                result: fixture.response(prompt: prompt), retention: .full)
        }
        #expect(throws: MultiEvidenceError.requestMismatch) {
            try MultiEvidenceAnalysisRecord.make(context: context, question: "Compare", prompt: prompt,
                result: fixture.response(prompt: "another request"), retention: .digestOnly)
        }
        #expect(throws: CodexAnalysisError.invalidProtocol) {
            try MultiEvidenceAnalysisRecord.make(context: context, question: "Compare", prompt: prompt,
                result: fixture.response(prompt: prompt, summary: ""), retention: .digestOnly)
        }
        let largeAnswer = CodexAnalysisResponse(summary: "Long interpretation", observations: Array(repeating: String(repeating: "x", count: 2_048), count: 20), hypotheses: [], limitations: [], nextSteps: [])
        let largeResult = CodexAnalysisResult(response: largeAnswer, requestSHA256: MultiEvidenceCoding.digest(Data(prompt.utf8)), completedAt: Date())
        let parent = try MultiEvidenceAnalysisRecord.make(context: context, question: "Compare", prompt: prompt, result: largeResult, retention: .digestOnly)
        #expect(throws: MultiEvidenceError.budgetExceeded) { try MultiEvidencePrompt.make(context: context, question: "Follow-up", parent: parent) }
    }

    @Test("Malformed sidecar Int extremes are refused by load/history instead of overflowing", arguments: ["aggregate", "omitted", "segment", "range"])
    func malformedSidecarIntegers(_ fault: String) async throws {
        let fixture = try await MultiEvidenceFixture.make(); defer { fixture.remove() }
        let record = try fixture.record(retention: .digestOnly)
        try MultiEvidenceRecordStore.save(record, in: fixture.caseURL)
        var json = try #require(JSONSerialization.jsonObject(with: MultiEvidenceCoding.encode(record)) as? [String: Any])
        var context = try #require(json["context"] as? [String: Any])
        var files = try #require(context["files"] as? [[String: Any]])
        if fault == "aggregate" { files[0]["disclosedByteCount"] = Int.max; files[1]["disclosedByteCount"] = Int.max }
        else if fault == "omitted" { files[0]["omittedByteCount"] = Int.max }
        else {
            var segments = try #require(files[0]["segments"] as? [[String: Any]])
            if fault == "segment" { segments[0]["byteCount"] = Int.max }
            else { segments[0]["sourceRange"] = ["start": Int.min, "end": Int.max] }
            files[0]["segments"] = segments
        }
        context["files"] = files; json["context"] = context
        let bytes = try JSONSerialization.data(withJSONObject: json)
        try bytes.write(to: fixture.recordURL(record.id))
        #expect(throws: (any Error).self) { try MultiEvidenceRecordStore.load(id: record.id, in: fixture.caseURL) }
        #expect(throws: (any Error).self) { try MultiEvidenceRecordStore.history(in: fixture.caseURL) }
        #expect(try Data(contentsOf: fixture.recordURL(record.id)) == bytes)
        #expect(try Data(contentsOf: fixture.source) == Data("synthetic image".utf8))
    }

    @Test("A prior answer cannot silently bypass a newly changed redaction")
    func changedFollowUpDisclosure() async throws {
        let fixture = try await MultiEvidenceFixture.make(first: "one SECRET two", second: "two"); defer { fixture.remove() }
        let parent = try fixture.record()
        let redacted = try fixture.context(selections: [.init(ranges: [.init(start: 0, end: 14)], redactions: [.init(start: 4, end: 10)]), fixture.files[1].defaultSelection])
        #expect(throws: MultiEvidenceError.parentMismatch) { try MultiEvidencePrompt.make(context: redacted, question: "Follow-up", parent: parent) }
    }

    @Test("Cancellation before async sidecar publication creates no record and preserves source bytes")
    func cancelledPublication() async throws {
        let fixture = try await MultiEvidenceFixture.make(); defer { fixture.remove() }
        let record = try fixture.record()
        let task = Task { try await MultiEvidenceRecordStore.saveAsync(record, in: fixture.caseURL) }
        task.cancel()
        do { try await task.value; Issue.record("Cancelled publication unexpectedly completed") }
        catch is CancellationError {}
        #expect(!FileManager.default.fileExists(atPath: fixture.recordURL(record.id).path))
        #expect(try Data(contentsOf: fixture.source) == Data("synthetic image".utf8))
    }

    @Test("History retains bounded summaries with a stable older-page boundary")
    func historyPages() async throws {
        let fixture = try await MultiEvidenceFixture.make(); defer { fixture.remove() }
        var records: [MultiEvidenceAnalysisRecord] = []
        for _ in 0..<4 { let record = try fixture.record(); try MultiEvidenceRecordStore.save(record, in: fixture.caseURL); records.append(record) }
        let first = try MultiEvidenceRecordStore.history(in: fixture.caseURL, limit: 2)
        let second = try MultiEvidenceRecordStore.history(in: fixture.caseURL, before: try #require(first.last), limit: 2)
        #expect(first.count == 2); #expect(second.count == 2); #expect(Set((first + second).map(\.id)) == Set(records.map(\.id)))
        #expect(throws: CaseWorkError.sizeLimit) { try MultiEvidenceRecordStore.history(in: fixture.caseURL, limit: 51) }
    }
}

private struct MultiEvidenceFixture {
    let directory: URL, source: URL, caseURL: URL
    let evidence: EvidenceRecord
    let entries: [FilesystemEntry]
    let files: [MultiEvidenceVerifiedFile]
    static func make(first: String = "one", second: String = "two") async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("MultiEvidence-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let source = directory.appendingPathComponent("private-source.dd")
        try Data("synthetic image".utf8).write(to: source)
        let created = try CaseStore.create(name: "Synthetic Comparison", in: directory)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspected, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let texts = [first, second]
        let entries = texts.enumerated().map { index, text in FilesystemEntry(id: "0:\(index + 1)", path: "/FILE\(index + 1).txt", name: "FILE\(index + 1).txt",
            fsOffsetBytes: 0, metaAddress: UInt64(index + 1), size: Int64(text.utf8.count), isDirectory: false, isDeleted: false) }
        let result = EnumerationResult(engineVersion: "synthetic-comparison", patchDigest: "synthetic-only", sourcePaths: [source.path],
            sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 15, sectorSize: 512), volumes: [], files: entries,
            warnings: ["private engine warning \(source.path)"], status: .partial, savedAt: Date(timeIntervalSinceReferenceDate: 813_457_691.1234567))
        let files = try entries.enumerated().map { index, entry in
            let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entry)
            let bytes = Data(texts[index].utf8)
            let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entry.id, byteCount: entry.size,
                sha256: MultiEvidenceCoding.digest(bytes), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
            return try MultiEvidenceVerifiedFile(binding: binding, content: .init(bytes: bytes, receipt: receipt))
        }
        return Self(directory: directory, source: source, caseURL: forensicCase.bundleURL, evidence: evidence, entries: entries, files: files)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    func context(selections: [MultiEvidenceSelection]? = nil) throws -> MultiEvidenceContext { try .make(files: files, selections: selections ?? files.map(\.defaultSelection)) }
    func answer(_ summary: String = "Comparison") -> CodexAnalysisResponse { .init(summary: summary, observations: [], hypotheses: [], limitations: ["Synthetic only"], nextSteps: []) }
    func response(prompt: String, summary: String = "Comparison") -> CodexAnalysisResult {
        .init(response: answer(summary), requestSHA256: MultiEvidenceCoding.digest(Data(prompt.utf8)), completedAt: Date(timeIntervalSinceReferenceDate: 813_457_694.9876543))
    }
    func record(retention: AnalysisRetention = .full) throws -> MultiEvidenceAnalysisRecord {
        let context = try context(), prompt = try MultiEvidencePrompt.make(context: context, question: "Compare")
        return try .make(context: context, question: "Compare", prompt: prompt, result: response(prompt: prompt), retention: retention)
    }
    func recordURL(_ id: UUID) -> URL { caseURL.appendingPathComponent("comparisons").appendingPathComponent(id.uuidString.lowercased() + ".json") }
    func verified(index: Int, bytes: Data) throws -> MultiEvidenceVerifiedFile {
        let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entries[index].id, byteCount: Int64(bytes.count), sha256: MultiEvidenceCoding.digest(bytes), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
        return try .init(binding: files[index].binding, content: .init(bytes: bytes, receipt: receipt))
    }
}
