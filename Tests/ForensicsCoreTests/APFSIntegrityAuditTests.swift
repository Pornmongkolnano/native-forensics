import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Read-only APFS generation integrity")
struct APFSIntegrityAuditTests {
    @Test("Schema 1 metadata and schema 2 jobs audit exact APFS generations without mounting or opening sources", arguments: [false, true])
    func validOfflineGeneration(_ schema2: Bool) async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: schema2)
        defer { fixture.remove() }
        let resultBytes = try Data(contentsOf: fixture.resultURL)
        #expect(fixture.receipt.resultSHA256 == APFSIntegrityFixture.hash(resultBytes))
        #expect(fixture.receipt.serializedByteCount == resultBytes.count)
        #expect(try JSONDecoder().decode(APFSInspectionResult.self, from: resultBytes) == fixture.result)
        try fixture.replaceSourceWithFIFO()
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(!report.hasFailures)
        #expect(!report.isPartial)
        #expect(!report.sourceRehashed)
        #expect(report.verifiedSourceCount == 0)
        #expect(report.manifestSHA256 == APFSIntegrityFixture.hash(try Data(contentsOf: fixture.manifestURL)))
        #expect(report.checks.contains { $0.code == "source.historical" && $0.status == .historical })
        #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "apfs.checksum.valid" && $0.status == .pass })
        #expect(report.checks.contains { $0.relativePath == fixture.latestRelativePath && $0.code == "apfs.pointer.valid" && $0.status == .pass })
        if schema2 {
            #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.verified" && $0.status == .pass && $0.sha256 == APFSIntegrityFixture.hash(resultBytes) })
            #expect(fixture.forensicCase.manifest.provenance?.jobs.first?.component.executableSHA256 == nil)
            #expect(fixture.forensicCase.manifest.provenance?.jobs.first?.artifactByteCount == resultBytes.count)
        } else {
            #expect(fixture.forensicCase.manifest.schemaVersion == 1)
            #expect(fixture.forensicCase.manifest.provenance == nil)
            #expect(!report.checks.contains { $0.code == "job.artifact.verified" })
        }
        #expect(!report.checks.contains { $0.code == "storage.unrecognized" })
        #expect(try fixture.snapshot() == before)
        try fixture.expectFIFOUnchanged()
    }

    @Test("Earlier APFS generations and jobs remain valid when a newer partial view becomes latest")
    func historicalAndLatestGenerations() async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: true)
        defer { fixture.remove() }
        let oldResult = try Data(contentsOf: fixture.resultURL)
        let oldChecksum = try Data(contentsOf: fixture.checksumURL)
        let nextResult = fixture.makeResult(coverage: .partialAllocatedView, marker: "second")
        let nextReceipt = try APFSResultStore.save(nextResult, in: fixture.forensicCase)
        let nextJob = try APFSResultStore.jobProvenance(result: nextResult, receipt: nextReceipt,
            startedAt: fixture.startedAt, completedAt: fixture.completedAt)
        let updated = try CaseStore.recording(job: nextJob, in: fixture.forensicCase)
        #expect(nextJob.status == .partial)
        #expect(nextJob.isPartial)
        #expect(try Data(contentsOf: fixture.resultURL) == oldResult)
        #expect(try Data(contentsOf: fixture.checksumURL) == oldChecksum)
        #expect(try APFSResultStore.loadLatest(in: updated, evidenceID: fixture.evidence.id) == nextResult)
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: updated)
        #expect(!report.hasFailures)
        #expect(!report.isPartial)
        for receipt in [fixture.receipt, nextReceipt] {
            #expect(report.checks.contains { $0.relativePath == receipt.relativePath && $0.code == "apfs.checksum.valid" && $0.status == .pass })
            #expect(report.checks.contains { $0.relativePath == receipt.relativePath && $0.code == "job.artifact.verified" && $0.status == .pass && $0.sha256 == receipt.resultSHA256 })
        }
        #expect(report.checks.filter { $0.code == "apfs.pointer.valid" && $0.status == .pass }.count == 1)
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourceUnchanged()
    }

    @Test("Missing result, checksum or latest pointer fails its named APFS integrity relation without repair", arguments: ["result", "checksum", "latest"])
    func missingGenerationRecords(_ missing: String) async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: true)
        defer { fixture.remove() }
        let removed = missing == "result" ? fixture.resultURL : missing == "checksum" ? fixture.checksumURL : fixture.latestURL
        try FileManager.default.removeItem(at: removed)
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.code == "apfs.pointer.invalid" && $0.status == .fail && $0.relativePath == fixture.latestRelativePath })
        if missing != "latest" { #expect(report.checks.contains { $0.code == "apfs.checksum.invalid" && $0.status == .fail }) }
        if missing == "checksum" {
            #expect(!report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.verified" })
        }
        if missing == "latest" {
            #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.verified" && $0.status == .pass })
        }
        #expect(!FileManager.default.fileExists(atPath: removed.path))
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourceUnchanged()
    }

    @Test("Schema-valid result byte drift is detected by the checksum, latest pointer and exact job artifact hash")
    func changedResultBytes() async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: true)
        defer { fixture.remove() }
        let edited = try APFSIntegrityFixture.encode(fixture.makeResult(marker: "changed"))
        try edited.write(to: fixture.resultURL)
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "apfs.checksum.invalid" && $0.status == .fail })
        #expect(report.checks.contains { $0.relativePath == fixture.latestRelativePath && $0.code == "apfs.pointer.invalid" && $0.status == .fail })
        #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.changed" && $0.status == .fail && $0.sha256 == APFSIntegrityFixture.hash(edited) })
        #expect(!report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.verified" })
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourceUnchanged()
    }

    @Test("Wrong receipt identity, path, size and coverage cannot validate checksum or latest pointer", arguments: ["caseID", "evidenceID", "generationID", "relativePath", "serializedByteCount", "coverage", "resultSHA256"])
    func invalidReceiptRelations(_ field: String) async throws {
        for record in ["checksum", "latest"] {
            let fixture = try await APFSIntegrityFixture.make(schema2: false)
            defer { fixture.remove() }
            let target = record == "checksum" ? fixture.checksumURL : fixture.latestURL
            var object = try APFSIntegrityFixture.object(target)
            switch field {
            case "caseID", "evidenceID", "generationID": object[field] = UUID().uuidString
            case "relativePath": object[field] = "apfs/../outside/result.json"
            case "serializedByteCount": object[field] = fixture.receipt.serializedByteCount + 1
            case "coverage": object[field] = APFSReadCoverage.partialAllocatedView.rawValue
            default: object[field] = String(repeating: "a", count: 64)
            }
            try APFSIntegrityFixture.encodeObject(object).write(to: target)
            let before = try fixture.snapshot()
            let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
            #expect(report.hasFailures, "\(record) \(field)")
            if record == "checksum" { #expect(report.checks.contains { $0.code == "apfs.checksum.invalid" && $0.status == .fail }) }
            #expect(report.checks.contains { $0.relativePath == fixture.latestRelativePath && $0.code == "apfs.pointer.invalid" && $0.status == .fail })
            #expect(try fixture.snapshot() == before)
            try fixture.expectSourceUnchanged()
        }
    }

    @Test("Matching unsigned hashes cannot validate wrong source scope, traversal or false complete coverage", arguments: ["evidenceID", "containerSHA256", "containerByteCount", "hashScope", "entryPath", "completeWithoutFileHash"])
    func semanticallyInvalidResultWithMatchingReceipts(_ mode: String) async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: true)
        defer { fixture.remove() }
        var object = try APFSIntegrityFixture.object(fixture.resultURL)
        switch mode {
        case "evidenceID": object[mode] = UUID().uuidString
        case "containerSHA256": object[mode] = String(repeating: "a", count: 64)
        case "containerByteCount": object[mode] = fixture.evidence.byteCount + 1
        case "hashScope": object[mode] = "logical-image-bytes"
        default:
            var entries = try #require(object["entries"] as? [[String: Any]])
            if mode == "entryPath" { entries[0]["relativePath"] = "../outside.txt" }
            else { entries[0].removeValue(forKey: "sha256") }
            object["entries"] = entries
        }
        let forgedBytes = try APFSIntegrityFixture.encodeObject(object)
        try forgedBytes.write(to: fixture.resultURL)
        for target in [fixture.checksumURL, fixture.latestURL] {
            var receipt = try APFSIntegrityFixture.object(target)
            receipt["resultSHA256"] = APFSIntegrityFixture.hash(forgedBytes)
            receipt["serializedByteCount"] = forgedBytes.count
            try APFSIntegrityFixture.encodeObject(receipt).write(to: target)
        }
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.code == "apfs.checksum.invalid" && $0.status == .fail })
        #expect(report.checks.contains { $0.relativePath == fixture.latestRelativePath && $0.code == "apfs.pointer.invalid" && $0.status == .fail })
        #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.changed" && $0.status == .fail && $0.sha256 == APFSIntegrityFixture.hash(forgedBytes) })
        #expect(!report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "apfs.checksum.valid" })
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourceUnchanged()
    }

    @Test("Malformed or unknown APFS record schemas are unavailable or invalid and preserved", arguments: ["result", "checksum", "latest"])
    func malformedOrUnsupportedRecords(_ record: String) async throws {
        for unsupported in [false, true] {
            let fixture = try await APFSIntegrityFixture.make(schema2: true)
            defer { fixture.remove() }
            let target = record == "result" ? fixture.resultURL : record == "checksum" ? fixture.checksumURL : fixture.latestURL
            if unsupported {
                var object = try APFSIntegrityFixture.object(target)
                object["schemaVersion"] = 999
                try APFSIntegrityFixture.encodeObject(object).write(to: target)
            } else { try Data("{\"schemaVersion\":1,".utf8).write(to: target) }
            let before = try fixture.snapshot()
            let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
            let path = record == "result" ? fixture.receipt.relativePath : record == "checksum" ? fixture.checksumRelativePath : fixture.latestRelativePath
            #expect(report.checks.contains { $0.relativePath == path && ["metadata.invalid", "metadata.schema.unsupported", "apfs.pointer.invalid", "apfs.checksum.invalid"].contains($0.code) && [.fail, .unavailable].contains($0.status) })
            #expect(!report.checks.contains { $0.relativePath == path && $0.code == "metadata.valid" && $0.status == .pass })
            #expect(report.checks.contains { $0.relativePath == fixture.latestRelativePath &&
                $0.code == (unsupported ? "apfs.pointer.unavailable" : "apfs.pointer.invalid") &&
                $0.status == (unsupported ? .unavailable : .fail) })
            if unsupported && record == "checksum" {
                #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.unavailable" && $0.status == .unavailable })
                #expect(!report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.verified" })
            }
            #expect(try fixture.snapshot() == before)
            try fixture.expectSourceUnchanged()
        }
    }

    @Test("Linked and nonregular APFS result storage is never followed or silently repaired", arguments: ["directoryLink", "resultLink", "checksumLink", "resultHardLink", "resultFIFO"])
    func unsafeStorage(_ mode: String) async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: true)
        defer { fixture.remove() }
        let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent("private.json")
        let outsideBytes = Data("UNRELATED_OUTSIDE_BYTES_MUST_NOT_BE_READ_OR_CHANGED".utf8)
        try outsideBytes.write(to: sentinel)
        if mode == "directoryLink" {
            let directory = fixture.forensicCase.bundleURL.appendingPathComponent("apfs")
            try FileManager.default.moveItem(at: directory, to: fixture.root.appendingPathComponent("detached-apfs"))
            try FileManager.default.createSymbolicLink(at: directory, withDestinationURL: outside)
        } else {
            let target = mode == "checksumLink" ? fixture.checksumURL : fixture.resultURL
            try FileManager.default.removeItem(at: target)
            if mode == "resultHardLink" { #expect(Darwin.link(sentinel.path, target.path) == 0) }
            else if mode == "resultFIFO" { #expect(Darwin.mkfifo(target.path, mode_t(0o600)) == 0) }
            else { try FileManager.default.createSymbolicLink(at: target, withDestinationURL: sentinel) }
        }
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.code == "storage.unsafe" && $0.status == .fail })
        #expect(!report.checks.contains { $0.sha256 == APFSIntegrityFixture.hash(outsideBytes) })
        #expect(try fixture.snapshot() == before)
        #expect(try Data(contentsOf: sentinel) == outsideBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path) == ["private.json"])
        try fixture.expectSourceUnchanged()
    }

    @Test("A valid APFS result larger than 32 MiB is read completely within the advertised 64 MiB store budget")
    func advertisedFullResultBudget() async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: true, largeResult: true)
        defer { fixture.remove() }
        let bytes = try Data(contentsOf: fixture.resultURL)
        #expect(bytes.count > 32 * 1_024 * 1_024)
        #expect(bytes.count <= 64 * 1_024 * 1_024)
        #expect(fixture.receipt.serializedByteCount == bytes.count)
        #expect(fixture.forensicCase.manifest.provenance?.jobs.first?.artifactByteCount == bytes.count)
        #expect(fixture.receipt.resultSHA256 == APFSIntegrityFixture.hash(bytes))
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(!report.hasFailures)
        #expect(!report.isPartial)
        #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "apfs.checksum.valid" && $0.status == .pass })
        #expect(report.checks.contains { $0.relativePath == fixture.receipt.relativePath && $0.code == "job.artifact.verified" && $0.status == .pass && $0.sha256 == APFSIntegrityFixture.hash(bytes) })
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourceUnchanged()
    }

    @Test("A receipt exceeding 4 KiB discloses bounded audit coverage instead of verification", arguments: ["checksum", "latest"])
    func boundedReceiptBudget(_ record: String) async throws {
        let fixture = try await APFSIntegrityFixture.make(schema2: false)
        defer { fixture.remove() }
        let target = record == "checksum" ? fixture.checksumURL : fixture.latestURL
        var bytes = try Data(contentsOf: target)
        bytes.append(Data(repeating: 0x20, count: 4_097 - bytes.count))
        #expect(try JSONDecoder().decode(APFSCacheReceipt.self, from: bytes) == fixture.receipt)
        try bytes.write(to: target)
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(report.isPartial)
        #expect(report.checks.contains { $0.code == "coverage.limit" && $0.status == .unavailable })
        #expect(!report.checks.contains { $0.relativePath == fixture.latestRelativePath && $0.code == "apfs.pointer.valid" && $0.status == .pass })
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourceUnchanged()
    }
}

private struct APFSIntegritySnapshotItem: Equatable {
    let type: mode_t
    let bytes: Data?
    let linkTarget: String?
    let identity: SourceIdentity?
    let permissions: mode_t?
    let linkCount: Int?
}

private struct APFSIntegrityFixture {
    let root: URL
    let source: URL
    let sourceBytes: Data
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let result: APFSInspectionResult
    let receipt: APFSCacheReceipt
    let startedAt = Date(timeIntervalSince1970: 1_700_000_000.125)
    let completedAt = Date(timeIntervalSince1970: 1_700_000_005.987)
    var resultURL: URL { forensicCase.bundleURL.appendingPathComponent(receipt.relativePath) }
    var checksumURL: URL { resultURL.deletingLastPathComponent().appendingPathComponent("checksum.json") }
    var checksumRelativePath: String { receipt.relativePath.replacingOccurrences(of: "result.json", with: "checksum.json") }
    var latestRelativePath: String { "apfs/" + evidence.id.uuidString.lowercased() + "/latest.json" }
    var latestURL: URL { forensicCase.bundleURL.appendingPathComponent(latestRelativePath) }
    var manifestURL: URL { forensicCase.bundleURL.appendingPathComponent("manifest.json") }

    static func make(schema2: Bool, largeResult: Bool = false) async throws -> Self {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("APFSIntegrity-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            let source = root.appendingPathComponent("synthetic.dd"), sourceBytes = Data("abc".utf8)
            try sourceBytes.write(to: source)
            let image = try await ImageInspector.inspect(url: source, progress: { _ in })
            let created = try CaseStore.create(name: "Synthetic APFS integrity", in: root)
            let withEvidence = try CaseStore.adding(image: image, to: created)
            var current = try schema2 ? CaseStore.migrateToSchema2(withEvidence) : withEvidence
            let evidence = try #require(current.manifest.evidence.first)
            #expect(evidence.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            let entries: [APFSFileEntry]
            if largeResult {
                let component = String(repeating: "p", count: 210)
                let prefix = Array(repeating: component, count: 15).joined(separator: "/")
                entries = (0..<11_000).map { index in
                    .init(relativePath: prefix + "/directory-\(index)", kind: .directory, inode: UInt64(index + 100),
                        byteCount: 0, sha256: nil, modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 123_456_789)
                }
            } else {
                entries = [.init(relativePath: "sample.txt", kind: .regular, inode: 42, byteCount: 3,
                    sha256: evidence.sha256, modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 123_456_789)]
            }
            let result = APFSInspectionResult(evidenceID: evidence.id, containerSHA256: evidence.sha256,
                containerByteCount: evidence.byteCount, driverVersion: "synthetic-metadata-driver.v1", volumeUUID: UUID(),
                containerEncryption: .none, volumeEncryption: .none, entries: entries,
                snapshots: [.init(uuid: UUID(), name: "synthetic snapshot", transactionID: 900)],
                snapshotInventoryAvailable: true, coverage: .completeAllocatedView, warnings: [])
            let receipt = try APFSResultStore.save(result, in: current)
            if schema2 {
                let job = try APFSResultStore.jobProvenance(result: result, receipt: receipt,
                    startedAt: Date(timeIntervalSince1970: 1_700_000_000.125),
                    completedAt: Date(timeIntervalSince1970: 1_700_000_005.987))
                current = try CaseStore.recording(job: job, in: current)
            }
            return Self(root: root, source: source, sourceBytes: sourceBytes, forensicCase: current,
                evidence: evidence, result: result, receipt: receipt)
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }

    func makeResult(coverage: APFSReadCoverage = .completeAllocatedView, marker: String = "same") -> APFSInspectionResult {
        .init(evidenceID: evidence.id, containerSHA256: evidence.sha256, containerByteCount: evidence.byteCount,
            driverVersion: result.driverVersion, options: result.options, volumeUUID: result.volumeUUID,
            containerEncryption: result.containerEncryption, volumeEncryption: result.volumeEncryption,
            entries: [.init(relativePath: marker == "same" ? "sample.txt" : "\(marker).txt", kind: .regular,
                inode: 42, byteCount: 3, sha256: evidence.sha256, modifiedSeconds: 1_700_000_000, modifiedNanoseconds: 123_456_789)],
            snapshots: result.snapshots, snapshotInventoryAvailable: true, coverage: coverage,
            warnings: coverage == .partialAllocatedView ? ["synthetic-partial-view"] : [])
    }
    func replaceSourceWithFIFO() throws {
        try FileManager.default.removeItem(at: source)
        #expect(Darwin.mkfifo(source.path, mode_t(0o600)) == 0)
    }
    func expectFIFOUnchanged() throws {
        var metadata = stat()
        #expect(Darwin.lstat(source.path, &metadata) == 0)
        #expect(metadata.st_mode & S_IFMT == S_IFIFO)
    }
    func expectSourceUnchanged() throws { #expect(try Data(contentsOf: source) == sourceBytes) }
    func snapshot() throws -> [String: APFSIntegritySnapshotItem] {
        var values: [String: APFSIntegritySnapshotItem] = [:]
        func visit(_ directory: URL, prefix: String) throws {
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() {
                let url = directory.appendingPathComponent(name)
                var metadata = stat()
                guard Darwin.lstat(url.path, &metadata) == 0 else { throw FileAccess.posixError("Cannot snapshot synthetic APFS store") }
                let type = metadata.st_mode & S_IFMT, path = prefix + name
                values[path] = .init(type: type, bytes: type == S_IFREG ? try Data(contentsOf: url) : nil,
                    linkTarget: type == S_IFLNK ? try FileManager.default.destinationOfSymbolicLink(atPath: url.path) : nil,
                    identity: type == S_IFREG ? SourceIdentity(metadata) : nil,
                    permissions: type == S_IFREG ? metadata.st_mode : nil,
                    linkCount: type == S_IFREG ? Int(metadata.st_nlink) : nil)
                if type == S_IFDIR { try visit(url, prefix: path + "/") }
            }
        }
        try visit(forensicCase.bundleURL, prefix: "")
        return values
    }
    static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    static func object(_ url: URL) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }
    static func encodeObject(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
