import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

struct CaseWorkTests {
    @Test("Full and digest-only receipts retain the exact request binding across offline reopen", arguments: AnalysisRetention.allCases)
    func analysisRoundtrip(_ retention: AnalysisRetention) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let bytes = Data("UNIQUE_PRIVATE_EXCERPT หลักฐาน\n".utf8)
        let context = try fixture.textContext(bytes)
        let prompt = "Examiner question\n" + (try context.untrustedPromptContext())
        let record = try fixture.analysis(context: context, prompt: prompt, retention: retention)
        let manifest = try Data(contentsOf: fixture.manifestURL)
        try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL)
        let savedBytes = try Data(contentsOf: fixture.recordURL(record.id, .analysis))
        let savedJSON = String(decoding: savedBytes, as: UTF8.self)
        #expect(!savedJSON.contains(fixture.source.path))
        #expect(!savedJSON.contains(fixture.caseURL.path))
        #expect(!savedJSON.contains("private diagnostic"))
        #expect(savedJSON.contains("UNIQUE_PRIVATE_EXCERPT") == (retention == .full))
        #expect(record.prompt == (retention == .full ? prompt : nil))
        #expect(record.requestSHA256 == CaseWorkFixture.hash(Data(prompt.utf8)))
        #expect(record.contentHash?.scope == "extracted-file-bytes")
        #expect(record.contentHash?.sha256 == CaseWorkFixture.hash(bytes))
        #expect(record.sourceBytesVerifiedForContentAtRequest)
        #expect(record.modelVersion == nil)
        // No source read is needed to reopen an already saved advisory receipt.
        try FileManager.default.removeItem(at: fixture.source)
        let reopenedCase = try CaseStore.open(at: fixture.caseURL)
        let reopened = try #require(try CaseWorkStore.loadAnalysis(id: record.id, in: reopenedCase.bundleURL))
        #expect(reopened == record)
        #expect(try Data(contentsOf: fixture.manifestURL) == manifest)
        #expect(reopened.binding.selectedContainerHash.scope == FileHashScope.selectedFileBytes)
        #expect(reopened.binding.logicalImageHash?.scope == "logical-image-bytes")
        #expect(reopened.binding.selectedContainerHash.sha256 != reopened.binding.logicalImageHash?.sha256)
    }

    @Test("Fractional snapshot and completion dates survive canonical save/load and cursor boundaries")
    func fractionalDates() async throws {
        let fixture = try await CaseWorkFixture.make(savedAt: Date(timeIntervalSinceReferenceDate: 813_457_691.1234567))
        defer { fixture.remove() }
        let date = Date(timeIntervalSinceReferenceDate: 813_457_693.9876543)
        let firstID = try #require(UUID(uuidString: "00000000-0000-0000-0000-000000000001"))
        let secondID = try #require(UUID(uuidString: "00000000-0000-0000-0000-000000000002"))
        let first = try fixture.analysis(id: firstID, completedAt: date)
        let second = try fixture.analysis(id: secondID, completedAt: date)
        try CaseWorkStore.saveAnalysis(first, in: fixture.caseURL)
        try CaseWorkStore.saveAnalysis(second, in: fixture.caseURL)
        #expect(try CaseWorkStore.loadAnalysis(id: first.id, in: fixture.caseURL) == first)
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, limit: 1, in: fixture.caseURL)
        #expect(page.items.map(\.id) == [secondID])
        let cursor = try #require(page.nextCursor)
        let next = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis,
            cursor: cursor, limit: 1, in: fixture.caseURL)
        #expect(next.items.map(\.id) == [firstID])
        #expect(next.nextCursor == nil)
    }

    @Test("Request digest or disclosure selection mismatch cannot create a saved AI record", arguments: ["digest", "selection", "snapshot"])
    func mismatchedRequest(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let context = mode == "selection" ? try fixture.context(file: fixture.otherFile) : fixture.context
        let binding = mode == "snapshot" ? try fixture.binding(savedAt: fixture.result.savedAt.addingTimeInterval(1)) : fixture.binding
        let prompt = "exact reviewed payload"
        let result = fixture.response(prompt: mode == "digest" ? "different payload" : prompt)
        #expect(throws: CaseWorkError.requestMismatch) {
            try AnalysisRecord.make(binding: binding, context: context, prompt: prompt,
                question: "Summarize", result: result, retention: .full)
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.directoryURL(.analysis).path))
    }

    @Test("A locator remains stable after reanalysis, while entry and snapshot hashes disclose changed metadata")
    func stableLocatorAndChangingSnapshot() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let changed = fixture.file(size: fixture.file.size, modifiedEpoch: 1_700_000_001)
        let later = try fixture.binding(file: changed, savedAt: fixture.result.savedAt.addingTimeInterval(1))
        #expect(fixture.binding.refersToSameFile(as: later))
        #expect(fixture.binding.locatorSHA256 == later.locatorSHA256)
        #expect(fixture.binding.entrySHA256 != later.entrySHA256)
        #expect(fixture.binding.snapshotSHA256 != later.snapshotSHA256)
        let renamed = try fixture.binding(file: fixture.file(path: "/RENAMED.TXT"))
        #expect(!fixture.binding.refersToSameFile(as: renamed))
    }

    @Test("Redacted snapshot identity is independent of host source paths and diagnostic text")
    func redactedSnapshotIdentity() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let relocated = fixture.directory.appendingPathComponent("not-present-relocated-source.dd").path
        let evidence = EvidenceRecord(id: fixture.evidence.id, sourcePath: relocated,
            byteCount: fixture.evidence.byteCount, sha256: fixture.evidence.sha256, container: .raw, filesystemHint: nil)
        let result = fixture.enumeration(sourcePath: relocated, warnings: ["different private diagnostic location"])
        let binding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: evidence, result: result, file: fixture.file)
        #expect(binding.snapshotSHA256 == fixture.binding.snapshotSHA256)
        let bytes = try CaseWorkCoding.encode(binding)
        #expect(!String(decoding: bytes, as: UTF8.self).contains(relocated))
        #expect(!String(decoding: bytes, as: UTF8.self).contains("private diagnostic"))
        let changedOther = fixture.file(id: "0:2", path: "/OTHER.TXT", metaAddress: 2, size: 99)
        let changedResult = fixture.enumeration(files: [fixture.file, changedOther])
        let changedBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: changedResult, file: fixture.file)
        #expect(changedBinding.snapshotSHA256 != fixture.binding.snapshotSHA256)
        #expect(changedBinding.entrySHA256 == fixture.binding.entrySHA256)
    }

    @Test("Duplicate analysis publication never overwrites the first immutable record")
    func immutableDuplicate() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let first = try fixture.analysis()
        let replacement = try fixture.analysis(prompt: "different second request", id: first.id)
        try CaseWorkStore.saveAnalysis(first, in: fixture.caseURL)
        let original = try Data(contentsOf: fixture.recordURL(first.id, .analysis))
        #expect(throws: CaseWorkError.alreadyExists) { try CaseWorkStore.saveAnalysis(replacement, in: fixture.caseURL) }
        #expect(try Data(contentsOf: fixture.recordURL(first.id, .analysis)) == original)
        #expect(try CaseWorkStore.loadAnalysis(id: first.id, in: fixture.caseURL) == first)
        #expect(try fixture.recordNames(.analysis) == [first.id.uuidString.lowercased() + ".json"])
    }

    @Test("Concurrent publication of one analysis UUID commits one record and refuses the duplicate")
    func concurrentImmutablePublication() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let record = try fixture.analysis()
        let outcomes = await withTaskGroup(of: CaseWorkSaveOutcome.self) { group in
            for _ in 0..<2 {
                group.addTask {
                    do { try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL); return .saved }
                    catch let error as CaseWorkError { return .refused(error) }
                    catch { return .otherFailure }
                }
            }
            var values: [CaseWorkSaveOutcome] = []
            for await value in group { values.append(value) }
            return values
        }
        #expect(outcomes.filter { $0 == .saved }.count == 1)
        #expect(outcomes.filter { $0 == .refused(.alreadyExists) }.count == 1)
        #expect(try CaseWorkStore.loadAnalysis(id: record.id, in: fixture.caseURL) == record)
    }

    @Test("Finding revisions retain old notes, require review reasons and reject stale concurrent edits")
    func findingRevisionsAndRace() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let initial = try FindingRecord.create(binding: fixture.binding, note: "Initial examiner note", bookmarked: true, tags: ["thai", "review"])
        try CaseWorkStore.saveFinding(initial, expectedLatestRevisionID: nil, in: fixture.caseURL)
        #expect(initial.reviewStatus == .unreviewed)
        #expect(throws: CaseWorkError.invalidRecord) {
            try initial.revised(note: "Verified", bookmarked: true, tags: [], reviewStatus: .verified, reviewReason: "")
        }
        let first = try initial.revised(note: "Revision A", bookmarked: true, tags: ["verified"], reviewStatus: .verified, reviewReason: "Compared exact bytes independently")
        let second = try initial.revised(note: "Revision B", bookmarked: false, tags: [], reviewStatus: .rejected, reviewReason: "Contradicts recorded timeline")
        let outcomes = await withTaskGroup(of: CaseWorkSaveOutcome.self) { group in
            for record in [first, second] {
                group.addTask {
                    do {
                        try CaseWorkStore.saveFinding(record, expectedLatestRevisionID: initial.id, in: fixture.caseURL)
                        return .saved
                    } catch let error as CaseWorkError { return .refused(error) }
                    catch { return .otherFailure }
                }
            }
            var values: [CaseWorkSaveOutcome] = []
            for await value in group { values.append(value) }
            return values
        }
        #expect(outcomes.filter { $0 == .saved }.count == 1)
        #expect(outcomes.filter { $0 == .refused(.staleRevision) }.count == 1)
        #expect(try CaseWorkStore.loadFinding(id: initial.id, in: fixture.caseURL) == initial)
        let latest = try #require(try CaseWorkStore.latestFinding(binding: fixture.binding, in: fixture.caseURL))
        #expect(latest.revision == 2)
        #expect(latest.previousRevisionID == initial.id)
        #expect([first.id, second.id].contains(latest.id))
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .finding, in: fixture.caseURL)
        #expect(page.items.count == 2)
        #expect(Set(page.items.map(\.id)) == Set([initial.id, latest.id]))
    }

    @Test("Finding revisions cannot be applied to a different path sharing an inode ID")
    func findingWrongFile() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let initial = try FindingRecord.create(binding: fixture.binding, note: "One path")
        let otherBinding = try fixture.binding(file: fixture.file(path: "/OTHER_LINK.TXT"))
        #expect(throws: CaseWorkError.invalidRecord) {
            try initial.revised(note: "Changed", bookmarked: false, tags: [], reviewStatus: .unreviewed, reviewReason: "", binding: otherBinding)
        }
    }

    @Test("Missing or branched finding history is preserved and cannot silently start a new branch", arguments: ["missingParent", "corrupt", "branch"])
    func ambiguousFindingHistory(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let first = try FindingRecord.create(binding: fixture.binding, note: "First")
        let second = try first.revised(note: "Second", bookmarked: false, tags: [], reviewStatus: .unreviewed, reviewReason: "")
        try CaseWorkStore.saveFinding(first, expectedLatestRevisionID: nil, in: fixture.caseURL)
        try CaseWorkStore.saveFinding(second, expectedLatestRevisionID: first.id, in: fixture.caseURL)
        let preserved = try Data(contentsOf: fixture.recordURL(second.id, .finding))
        if mode == "missingParent" { try FileManager.default.removeItem(at: fixture.recordURL(first.id, .finding)) }
        else if mode == "corrupt" { try Data("not-json".utf8).write(to: fixture.recordURL(UUID(), .finding)) }
        else {
            let branch = try first.revised(note: "Conflicting revision two", bookmarked: false, tags: [], reviewStatus: .unreviewed, reviewReason: "")
            try CaseWorkCoding.encode(branch).write(to: fixture.recordURL(branch.id, .finding))
        }
        #expect(throws: CaseWorkError.historyUnavailable) { try CaseWorkStore.latestFinding(binding: fixture.binding, in: fixture.caseURL) }
        let third = try second.revised(note: "Third", bookmarked: false, tags: [], reviewStatus: .unreviewed, reviewReason: "")
        #expect(throws: CaseWorkError.historyUnavailable) {
            try CaseWorkStore.saveFinding(third, expectedLatestRevisionID: second.id, in: fixture.caseURL)
        }
        #expect(try Data(contentsOf: fixture.recordURL(second.id, .finding)) == preserved)
        #expect(!FileManager.default.fileExists(atPath: fixture.recordURL(third.id, .finding).path))
    }

    @Test("Same-evidence byte-count drift is disclosed by history and cannot become a latest finding or new revision")
    func findingContainerByteCountDrift() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let first = try FindingRecord.create(binding: fixture.binding, note: "Recorded examiner note")
        try CaseWorkStore.saveFinding(first, expectedLatestRevisionID: nil, in: fixture.caseURL)
        let path = fixture.recordURL(first.id, .finding)
        var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
        var binding = try #require(object["binding"] as? [String: Any])
        binding["selectedContainerByteCount"] = fixture.evidence.byteCount + 1
        object["binding"] = binding
        let edited = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        try edited.write(to: path)
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .finding, in: fixture.caseURL)
        #expect(page.items.isEmpty)
        #expect(page.totalDiagnosticCount == 1)
        #expect(page.diagnostics.first?.recordID == first.id)
        #expect(throws: CaseWorkError.historyUnavailable) {
            try CaseWorkStore.latestFinding(binding: fixture.binding, in: fixture.caseURL)
        }
        #expect(throws: CaseWorkError.scopeMismatch) {
            try CaseWorkStore.loadFinding(id: first.id, in: fixture.caseURL)
        }
        let next = try first.revised(note: "Attempted revision", bookmarked: false, tags: [],
            reviewStatus: .unreviewed, reviewReason: "")
        #expect(throws: CaseWorkError.historyUnavailable) {
            try CaseWorkStore.saveFinding(next, expectedLatestRevisionID: first.id, in: fixture.caseURL)
        }
        #expect(try Data(contentsOf: path) == edited)
        #expect(!FileManager.default.fileExists(atPath: fixture.recordURL(next.id, .finding).path))
    }

    @Test("Extraction history records output-byte scope and omits user destination paths")
    func extractionReceipt() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let privateOutput = fixture.directory.appendingPathComponent("private-export.txt").path
        let receipt = ExtractionResult(outputPath: privateOutput, byteCount: fixture.file.size, sha256: CaseWorkFixture.hash(Data("abc".utf8)))
        let record = try ExtractionRecord.make(binding: fixture.binding, receipt: receipt)
        try CaseWorkStore.saveExtraction(record, in: fixture.caseURL)
        let saved = try #require(try CaseWorkStore.loadExtraction(id: record.id, in: fixture.caseURL))
        #expect(saved == record)
        #expect(saved.outputHash.scope == "extracted-file-bytes")
        #expect(saved.outputHash.sha256 != saved.binding.logicalImageHash?.sha256)
        #expect(saved.verificationDescription.contains("not current source/output verification"))
        #expect(!String(decoding: try Data(contentsOf: fixture.recordURL(record.id, .extraction)), as: UTF8.self).contains(privateOutput))
        #expect(throws: CaseWorkError.invalidRecord) {
            try ExtractionRecord.make(binding: fixture.binding,
                receipt: ExtractionResult(outputPath: privateOutput, byteCount: 99, sha256: receipt.sha256))
        }
    }

    @Test("Serialized record limit accepts exactly 1 MiB and rejects one extra byte without truncation")
    func exactSerializedSizeLimit() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let id = UUID()
        let sample = try fixture.analysis(prompt: "a", id: id)
        let overhead = try CaseWorkCoding.encode(sample).count - 1
        let prompt = String(repeating: "a", count: CaseWorkStore.maximumRecordBytes - overhead)
        let exact = try fixture.analysis(prompt: prompt, id: id)
        let exactBytes = try CaseWorkCoding.encode(exact)
        #expect(exactBytes.count == CaseWorkStore.maximumRecordBytes)
        try CaseWorkStore.saveAnalysis(exact, in: fixture.caseURL)
        #expect(try CaseWorkStore.loadAnalysis(id: id, in: fixture.caseURL) == exact)
        let oversized = try fixture.analysis(prompt: prompt + "a")
        #expect(try CaseWorkCoding.encode(oversized).count == CaseWorkStore.maximumRecordBytes + 1)
        #expect(throws: CaseWorkError.sizeLimit) { try CaseWorkStore.saveAnalysis(oversized, in: fixture.caseURL) }
        #expect(try Data(contentsOf: fixture.recordURL(id, .analysis)) == exactBytes)
        #expect(!FileManager.default.fileExists(atPath: fixture.recordURL(oversized.id, .analysis).path))
    }

    @Test("History paginates all 55 receipts without duplicates, with bounded summaries and record buffers")
    func paginatedHistory() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        var records: [AnalysisRecord] = []
        let base = Date(timeIntervalSinceReferenceDate: 813_457_690.1234567)
        for index in 0..<55 {
            let record = try fixture.analysis(completedAt: base.addingTimeInterval(Double(index) / 8))
            try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL)
            records.append(record)
        }
        let first = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, in: fixture.caseURL)
        #expect(first.items.count == 50)
        #expect(first.diagnostics.isEmpty)
        #expect(first.maximumSerializedRecordBytesObserved <= CaseWorkStore.maximumRecordBytes)
        let cursor = try #require(first.nextCursor)
        let second = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis,
            cursor: cursor, in: fixture.caseURL)
        #expect(second.items.count == 5)
        #expect(second.nextCursor == nil)
        #expect((first.items + second.items).map(\.id) == records.reversed().map(\.id))
        #expect(Set((first.items + second.items).map(\.id)).count == 55)
        #expect(throws: CaseWorkError.invalidRecord) {
            try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, limit: 51, in: fixture.caseURL)
        }
        #expect(throws: CaseWorkError.invalidRecord) {
            try CaseWorkStore.history(binding: fixture.binding, kind: .extraction, cursor: first.nextCursor, in: fixture.caseURL)
        }
    }

    @Test("Corrupt, unknown-schema, oversized and wrong-ID records are disclosed and preserved", arguments: ["corrupt", "future", "oversized", "wrongID"])
    func preservedHistoryDiagnostics(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let valid = try fixture.analysis()
        try CaseWorkStore.saveAnalysis(valid, in: fixture.caseURL)
        let id = UUID()
        let badBytes: Data
        switch mode {
        case "future": badBytes = Data("{\"schemaVersion\":99}".utf8)
        case "oversized": badBytes = Data(repeating: 0x61, count: CaseWorkStore.maximumRecordBytes + 1)
        case "wrongID": badBytes = try CaseWorkCoding.encode(valid)
        default: badBytes = Data("{invalid".utf8)
        }
        let path = fixture.recordURL(id, .analysis)
        try badBytes.write(to: path)
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, in: fixture.caseURL)
        #expect(page.items.map(\.id) == [valid.id])
        #expect(page.totalDiagnosticCount == 1)
        #expect(page.diagnostics.count == 1)
        #expect(page.diagnostics.first?.recordID == id)
        #expect(page.diagnostics.first?.message.contains(fixture.directory.path) == false)
        #expect(throws: (any Error).self) { try CaseWorkStore.loadAnalysis(id: id, in: fixture.caseURL) }
        #expect(try Data(contentsOf: path) == badBytes)
    }

    @Test("Large malformed histories cap diagnostic detail while preserving the full issue count")
    func boundedDiagnosticHistory() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let valid = try fixture.analysis()
        try CaseWorkStore.saveAnalysis(valid, in: fixture.caseURL)
        let unsupported = Data("{\"schemaVersion\":99}".utf8)
        for _ in 0..<60 { try unsupported.write(to: fixture.recordURL(UUID(), .analysis)) }
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, in: fixture.caseURL)
        #expect(page.items.map(\.id) == [valid.id])
        #expect(page.totalDiagnosticCount == 60)
        #expect(page.diagnostics.count == CaseWorkStore.maximumPageSize)
        #expect(try fixture.recordNames(.analysis).count == 61)
    }

    @Test("Combining-character notes cannot create unbounded history titles")
    func boundedUnicodeTitle() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let note = "a" + String(repeating: "\u{0301}", count: 20_000)
        #expect(note.count == 1) // One extended grapheme can still contain 40 KiB.
        let finding = try FindingRecord.create(binding: fixture.binding, note: note)
        try CaseWorkStore.saveFinding(finding, expectedLatestRevisionID: nil, in: fixture.caseURL)
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .finding, in: fixture.caseURL)
        let title = try #require(page.items.first?.title)
        #expect(title.unicodeScalars.count <= 160)
        #expect(title.utf8.count <= 640)
        #expect(try CaseWorkStore.loadFinding(id: finding.id, in: fixture.caseURL)?.note == note)
    }

    @Test("Saving or loading a record from another case or evidence is rejected", arguments: ["case", "evidence", "hash", "byteCount"])
    func wrongManifestScope(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let binding: CaseWorkBinding
        if mode == "case" { binding = try fixture.binding(caseID: UUID()) }
        else if mode == "evidence" { binding = try fixture.binding(evidenceID: UUID()) }
        else if mode == "hash" { binding = try fixture.binding(hash: String(repeating: "f", count: 64)) }
        else {
            binding = fixture.binding
            let evidence = EvidenceRecord(id: fixture.evidence.id, sourcePath: fixture.source.path,
                byteCount: fixture.evidence.byteCount + 1, sha256: fixture.evidence.sha256, container: .raw, filesystemHint: nil)
            let manifest = fixture.forensicCase.manifest
            let changed = CaseManifest(id: manifest.id, name: manifest.name, createdAt: manifest.createdAt, evidence: [evidence])
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(changed).write(to: fixture.manifestURL)
        }
        let context = try fixture.context(binding: binding)
        let record = try fixture.analysis(binding: binding, context: context)
        #expect(throws: CaseWorkError.scopeMismatch) { try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL) }
        #expect(!FileManager.default.fileExists(atPath: fixture.directoryURL(.analysis).path))
        try FileManager.default.createDirectory(at: fixture.directoryURL(.analysis), withIntermediateDirectories: false)
        let bytes = try CaseWorkCoding.encode(record)
        try bytes.write(to: fixture.recordURL(record.id, .analysis))
        #expect(throws: CaseWorkError.scopeMismatch) { try CaseWorkStore.loadAnalysis(id: record.id, in: fixture.caseURL) }
        #expect(try Data(contentsOf: fixture.recordURL(record.id, .analysis)) == bytes)
    }

    @Test("Sidecar directory symlinks and FIFOs cannot redirect saves or block opens", arguments: ["symlink", "fifo"])
    func unsafeDirectory(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let destination = fixture.directoryURL(.analysis)
        let outside = fixture.directory.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        if mode == "symlink" { try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: outside) }
        else { #expect(Darwin.mkfifo(destination.path, mode_t(0o600)) == 0) }
        let record = try fixture.analysis()
        #expect(throws: CaseWorkError.unsafePath) { try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL) }
        #expect(throws: CaseWorkError.unsafePath) { try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, in: fixture.caseURL) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
    }

    @Test("Sidecar record symlinks, FIFOs and hard links are refused without touching their targets", arguments: ["symlink", "fifo", "hardlink"])
    func unsafeRecord(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let record = try fixture.analysis()
        try FileManager.default.createDirectory(at: fixture.directoryURL(.analysis), withIntermediateDirectories: false)
        let target = fixture.directory.appendingPathComponent("outside-record.json")
        let targetBytes = try CaseWorkCoding.encode(record)
        try targetBytes.write(to: target)
        let path = fixture.recordURL(record.id, .analysis)
        if mode == "symlink" { try FileManager.default.createSymbolicLink(at: path, withDestinationURL: target) }
        else if mode == "fifo" { #expect(Darwin.mkfifo(path.path, mode_t(0o600)) == 0) }
        else { #expect(Darwin.link(target.path, path.path) == 0) }
        #expect(throws: CaseWorkError.unsafePath) { try CaseWorkStore.loadAnalysis(id: record.id, in: fixture.caseURL) }
        #expect(throws: CaseWorkError.alreadyExists) { try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL) }
        let page = try CaseWorkStore.history(binding: fixture.binding, kind: .analysis, in: fixture.caseURL)
        #expect(page.items.isEmpty)
        #expect(page.totalDiagnosticCount == 1)
        #expect(try Data(contentsOf: target) == targetBytes)
    }

    @Test("Case lock symlinks, FIFOs and hard links are refused before record access", arguments: ["symlink", "fifo", "hardlink"])
    func unsafeLock(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let lock = fixture.caseURL.appendingPathComponent(".case.lock")
        try FileManager.default.removeItem(at: lock)
        let target = fixture.directory.appendingPathComponent("outside-lock")
        let marker = Data("must remain untouched".utf8)
        try marker.write(to: target)
        if mode == "symlink" { try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: target) }
        else if mode == "fifo" { #expect(Darwin.mkfifo(lock.path, mode_t(0o600)) == 0) }
        else { #expect(Darwin.link(target.path, lock.path) == 0) }
        let record = try fixture.analysis()
        #expect(throws: CaseWorkError.invalidCase) { try CaseWorkStore.saveAnalysis(record, in: fixture.caseURL) }
        #expect(throws: CaseWorkError.invalidCase) { try CaseWorkStore.loadAnalysis(id: record.id, in: fixture.caseURL) }
        #expect(try Data(contentsOf: target) == marker)
    }

    @Test("Interrupted or disk-full publication preserves existing records and removes owned staging", arguments: ["cancel", "diskFull"])
    func interruptedPublication(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let prior = try fixture.analysis()
        try CaseWorkStore.saveAnalysis(prior, in: fixture.caseURL)
        let priorBytes = try Data(contentsOf: fixture.recordURL(prior.id, .analysis))
        let next = try fixture.analysis(prompt: "another analysis")
        #expect(throws: (any Error).self) {
            try CaseWorkStore.saveAnalysisForTesting(next, in: fixture.caseURL) {
                if mode == "cancel" { throw CancellationError() }
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(ENOSPC))
            }
        }
        #expect(try Data(contentsOf: fixture.recordURL(prior.id, .analysis)) == priorBytes)
        #expect(try fixture.recordNames(.analysis) == [prior.id.uuidString.lowercased() + ".json"])
        #expect(!FileManager.default.fileExists(atPath: fixture.recordURL(next.id, .analysis).path))
    }

    @Test("Task cancellation arriving inside the prepublication hook cannot publish when the hook returns normally")
    func cancellationAtPublicationBoundary() async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let record = try fixture.analysis()
        let gate = CaseWorkPublicationGate()
        let task = Task.detached {
            try CaseWorkStore.saveAnalysisForTesting(record, in: fixture.caseURL) { gate.arriveAndWait() }
        }
        // Poll an observed stage boundary rather than guessing a staging delay.
        for _ in 0..<500 where !gate.hasArrived { try await Task.sleep(for: .milliseconds(10)) }
        let arrived = gate.hasArrived
        task.cancel()
        gate.release()
        #expect(arrived)
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(try fixture.recordNames(.analysis).isEmpty)
        #expect(!FileManager.default.fileExists(atPath: fixture.recordURL(record.id, .analysis).path))
    }

    @Test("Directory, lock and manifest swaps at publication cannot commit into a replaced case reference", arguments: ["directory", "lock", "manifest", "root"])
    func replacedPublicationReference(_ mode: String) async throws {
        let fixture = try await CaseWorkFixture.make()
        defer { fixture.remove() }
        let prior = try fixture.analysis()
        try CaseWorkStore.saveAnalysis(prior, in: fixture.caseURL)
        let priorBytes = try Data(contentsOf: fixture.recordURL(prior.id, .analysis))
        let next = try fixture.analysis()
        let heldDirectory = fixture.directory.appendingPathComponent("held-analyses", isDirectory: true)
        let heldRoot = fixture.directory.appendingPathComponent("held.nativecase", isDirectory: true)
        let marker = Data("replacement must remain untouched".utf8)
        #expect(throws: CaseWorkError.changedDuringOperation) {
            try CaseWorkStore.saveAnalysisForTesting(next, in: fixture.caseURL) {
                switch mode {
                case "directory":
                    try FileManager.default.moveItem(at: fixture.directoryURL(.analysis), to: heldDirectory)
                    try FileManager.default.createDirectory(at: fixture.directoryURL(.analysis), withIntermediateDirectories: false)
                    try marker.write(to: fixture.directoryURL(.analysis).appendingPathComponent("replacement-marker"))
                case "root":
                    try FileManager.default.moveItem(at: fixture.caseURL, to: heldRoot)
                    try FileManager.default.createDirectory(at: fixture.caseURL, withIntermediateDirectories: false)
                    try marker.write(to: fixture.caseURL.appendingPathComponent("replacement-marker"))
                default:
                    let target = mode == "lock" ? fixture.caseURL.appendingPathComponent(".case.lock") : fixture.manifestURL
                    let backup = fixture.directory.appendingPathComponent("held-" + target.lastPathComponent)
                    try FileManager.default.moveItem(at: target, to: backup)
                    try marker.write(to: target)
                }
            }
        }
        let originalDirectory = mode == "directory" ? heldDirectory : (mode == "root" ? heldRoot.appendingPathComponent("analyses") : fixture.directoryURL(.analysis))
        #expect(try Data(contentsOf: originalDirectory.appendingPathComponent(prior.id.uuidString.lowercased() + ".json")) == priorBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: originalDirectory.path) == [prior.id.uuidString.lowercased() + ".json"])
        if mode == "directory" {
            #expect(try Data(contentsOf: fixture.directoryURL(.analysis).appendingPathComponent("replacement-marker")) == marker)
        } else if mode == "root" {
            #expect(try Data(contentsOf: fixture.caseURL.appendingPathComponent("replacement-marker")) == marker)
        } else {
            let target = mode == "lock" ? fixture.caseURL.appendingPathComponent(".case.lock") : fixture.manifestURL
            #expect(try Data(contentsOf: target) == marker)
        }
    }
}

private enum CaseWorkSaveOutcome: Equatable, Sendable { case saved, refused(CaseWorkError), otherFailure }

private final class CaseWorkPublicationGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var arrived = false
    private var released = false
    var hasArrived: Bool { condition.lock(); defer { condition.unlock() }; return arrived }
    func arriveAndWait() {
        condition.lock()
        arrived = true
        condition.broadcast()
        while !released { condition.wait() }
        condition.unlock()
    }
    func release() {
        condition.lock()
        released = true
        condition.broadcast()
        condition.unlock()
    }
}

private struct CaseWorkFixture: Sendable {
    let directory: URL
    let source: URL
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let file: FilesystemEntry
    let otherFile: FilesystemEntry
    let result: EnumerationResult
    let binding: CaseWorkBinding
    let context: EvidenceAnalysisContext
    var caseURL: URL { forensicCase.bundleURL }
    var manifestURL: URL { caseURL.appendingPathComponent("manifest.json") }

    static func make(savedAt: Date = Date(timeIntervalSinceReferenceDate: 813_457_690.25)) async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("CaseWorkTests-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            let source = directory.appendingPathComponent("private-source.dd")
            try Data("abc".utf8).write(to: source)
            let created = try CaseStore.create(name: "Synthetic Work", in: directory)
            let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
            let forensicCase = try CaseStore.adding(image: inspected, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let file = FilesystemEntry(id: "0:1", path: "/HELLO.TXT", name: "HELLO.TXT", fsOffsetBytes: 0,
                metaAddress: 1, size: 3, isDirectory: false, isDeleted: false, modifiedEpoch: 1_700_000_000)
            let other = FilesystemEntry(id: "0:2", path: "/OTHER.TXT", name: "OTHER.TXT", fsOffsetBytes: 0,
                metaAddress: 2, size: 3, isDirectory: false, isDeleted: false)
            let result = EnumerationResult(engineVersion: "casework-synthetic", patchDigest: "synthetic-only", sourcePaths: [source.path],
                sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(),
                image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512, logicalSha256: String(repeating: "e", count: 64)),
                volumes: [], files: [file, other], warnings: ["private diagnostic \(source.path)"], status: .partial, savedAt: savedAt)
            let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
            let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: file)
            return Self(directory: directory, source: source, forensicCase: forensicCase, evidence: evidence,
                file: file, otherFile: other, result: result, binding: binding, context: context)
        } catch { try? FileManager.default.removeItem(at: directory); throw error }
    }

    func file(id: String = "0:1", path: String = "/HELLO.TXT", metaAddress: UInt64 = 1, size: Int64 = 3,
        modifiedEpoch: Int64 = 1_700_000_000) -> FilesystemEntry {
        FilesystemEntry(id: id, path: path, name: URL(fileURLWithPath: path).lastPathComponent, fsOffsetBytes: 0,
            metaAddress: metaAddress, size: size, isDirectory: false, isDeleted: false, modifiedEpoch: modifiedEpoch)
    }

    func enumeration(sourcePath: String? = nil, hash: String? = nil, files: [FilesystemEntry]? = nil,
        warnings: [String]? = nil, savedAt: Date? = nil) -> EnumerationResult {
        let path = sourcePath ?? source.path
        return EnumerationResult(engineVersion: result.engineVersion, patchDigest: result.patchDigest, sourcePaths: [path],
            sourceFileHashes: [path: hash ?? evidence.sha256], options: result.options, image: result.image,
            volumes: result.volumes, files: files ?? result.files, warnings: warnings ?? result.warnings,
            status: result.status, savedAt: savedAt ?? result.savedAt)
    }

    func binding(file: FilesystemEntry? = nil, savedAt: Date? = nil, caseID: UUID? = nil,
        evidenceID: UUID? = nil, hash: String? = nil) throws -> CaseWorkBinding {
        let evidence = EvidenceRecord(id: evidenceID ?? evidence.id, sourcePath: source.path,
            byteCount: self.evidence.byteCount, sha256: hash ?? self.evidence.sha256, container: .raw, filesystemHint: nil)
        let selected = file ?? self.file
        let result = enumeration(hash: hash, files: [selected, otherFile], savedAt: savedAt)
        return try CaseWorkBinding.make(caseID: caseID ?? forensicCase.manifest.id, evidence: evidence, result: result, file: selected)
    }

    func context(file: FilesystemEntry) throws -> EvidenceAnalysisContext {
        try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
    }

    func context(binding: CaseWorkBinding) throws -> EvidenceAnalysisContext {
        let evidence = EvidenceRecord(id: binding.evidenceID, sourcePath: source.path, byteCount: self.evidence.byteCount,
            sha256: binding.selectedContainerHash.sha256, container: .raw, filesystemHint: nil)
        return try AssistantContextBuilder.metadata(evidence: evidence,
            result: enumeration(hash: binding.selectedContainerHash.sha256, files: [binding.selectedEntry, otherFile], savedAt: binding.snapshotSavedAt),
            file: binding.selectedEntry)
    }

    func textContext(_ bytes: Data) throws -> EvidenceAnalysisContext {
        let text = try AssistantContextBuilder.textContent(bytes: bytes,
            receipt: ExtractionResult(outputPath: "/not-saved", byteCount: Int64(bytes.count), sha256: Self.hash(bytes)))
        let selected = file(size: Int64(bytes.count))
        let metadata = try AssistantContextBuilder.metadata(evidence: evidence, result: enumeration(files: [selected, otherFile]), file: selected)
        let snapshot = metadata.analysis
        return EvidenceAnalysisContext(schemaVersion: 1, evidenceID: metadata.evidenceID,
            selectedContainerHash: metadata.selectedContainerHash, containerHashes: metadata.containerHashes,
            logicalImageHash: metadata.logicalImageHash, file: selected,
            analysis: AssistantAnalysisSnapshot(engineVersion: snapshot.engineVersion, patchDigest: snapshot.patchDigest,
                status: snapshot.status, imageType: snapshot.imageType, logicalImageByteCount: snapshot.logicalImageByteCount,
                timezone: snapshot.timezone, savedAt: snapshot.savedAt, enumeratedFileCount: snapshot.enumeratedFileCount,
                engineWarningCount: snapshot.engineWarningCount, sourceBytesVerifiedForContent: true), warnings: metadata.warnings, textContent: text)
    }

    func response(prompt: String, completedAt: Date = Date(timeIntervalSinceReferenceDate: 813_457_693.25)) -> CodexAnalysisResult {
        CodexAnalysisResult(response: CodexAnalysisResponse(summary: "Synthetic advisory only", observations: ["Recorded metadata"],
            hypotheses: ["Requires examiner verification"], limitations: ["Partial source listing"], nextSteps: ["Compare source facts"]),
            requestSHA256: Self.hash(Data(prompt.utf8)), completedAt: completedAt)
    }

    func analysis(binding: CaseWorkBinding? = nil, context: EvidenceAnalysisContext? = nil,
        prompt: String = "Exact reviewed request ภาษาไทย", retention: AnalysisRetention = .full, id: UUID = UUID(),
        completedAt: Date = Date(timeIntervalSinceReferenceDate: 813_457_693.25)) throws -> AnalysisRecord {
        let context = context ?? self.context
        let binding = try binding ?? self.binding(file: context.file, savedAt: context.analysis.savedAt)
        return try AnalysisRecord.make(binding: binding, context: context, prompt: prompt, question: "Summarize this selected file",
            result: response(prompt: prompt, completedAt: completedAt), retention: retention, cliVersion: "synthetic-cli", id: id)
    }

    func directoryURL(_ kind: CaseWorkKind) -> URL {
        let name: String
        switch kind { case .analysis: name = "analyses"; case .finding: name = "findings"; case .extraction: name = "extractions" }
        return caseURL.appendingPathComponent(name, isDirectory: true)
    }
    func recordURL(_ id: UUID, _ kind: CaseWorkKind) -> URL { directoryURL(kind).appendingPathComponent(id.uuidString.lowercased() + ".json") }
    func recordNames(_ kind: CaseWorkKind) throws -> [String] { try FileManager.default.contentsOfDirectory(atPath: directoryURL(kind).path).sorted() }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func hash(_ bytes: Data) -> String { CaseWorkCoding.hex(SHA256.hash(data: bytes)) }
}
