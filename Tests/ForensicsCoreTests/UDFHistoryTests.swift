import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@_silgen_name("flock")
private func udfTestFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

@Suite("Bounded read-only UDF history")
struct UDFHistoryTests {
    @Test("Autopsy logical import publishes exact current/history bytes with complete source metadata")
    func autopsyLogicalImport() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let output = fixture.directory.appendingPathComponent("Autopsy Import")
        let exported = try await UDFLogicalFilesExporter.export(sourceURL: fixture.source, to: output)
        #expect(exported.status == "completed")
        #expect(exported.entries.count == 2)
        #expect(exported.sourceSHA256 == fixture.evidence.sha256)
        let historyBytes = try Data(contentsOf: output.appendingPathComponent("Reports/udf-history.json"))
        let history = try JSONDecoder().decode(UDFInspectionResult.self, from: historyBytes)
        #expect(exported.historyJSONSHA256 == UDFFixture.hash(historyBytes))
        #expect(history.snapshots.count == 2)
        #expect(history.entries.first(where: { $0.state == .historicalDeletedAncestor })?.deletedAncestorProof.count == 1)
        #expect(history.entries.first(where: { $0.state == .historicalDeletedAncestor })?.sourceExtents.count == 2)
        for entry in exported.entries {
            let bytes = try Data(contentsOf: output.appendingPathComponent(entry.outputRelativePath))
            #expect(UDFFixture.hash(bytes) == entry.sha256)
            #expect(bytes.count == entry.byteCount)
            #expect(entry.outputRelativePath.hasPrefix("LogicalFiles/\(entry.state.rawValue)/\(entry.entryID)/"))
            #expect(entry.outputRelativePath.hasSuffix(entry.originalPath))
        }
        let report = try Data(contentsOf: output.appendingPathComponent("Reports/udf-history.md"))
        #expect(UDFFixture.hash(report) == exported.historyReportSHA256)
        #expect(try JSONDecoder().decode(UDFLogicalFilesExport.self, from: Data(contentsOf: output.appendingPathComponent("Reports/manifest.json"))) == exported)
        let reopened = try CaseStore.open(at: output.appendingPathComponent("Reports/UDF Source Receipt.nativecase"))
        #expect(try UDFInspector.loadLatest(in: reopened, evidenceID: history.sourceEvidenceID) == history)
        #expect(try Data(contentsOf: fixture.source) == fixture.image)
        // Packaging may request this fully synthetic fixture. No user evidence
        // is involved; an existing generated fixture must already be identical.
        if let path = ProcessInfo.processInfo.environment["NF_UDF_SHARE_FIXTURE_OUTPUT"] {
            let target = URL(fileURLWithPath: path)
            if FileManager.default.fileExists(atPath: target.path) {
                #expect(try Data(contentsOf: target) == fixture.image)
            } else { try fixture.image.write(to: target, options: .withoutOverwriting) }
        }
    }

    @Test("Logical import does not overwrite outputs or follow a source/output symlink")
    func autopsyLogicalSafety() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let output = fixture.directory.appendingPathComponent("Exists")
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
        let sentinel = Data("Keep examiner output".utf8)
        try sentinel.write(to: output.appendingPathComponent("keep.txt"))
        await #expect(throws: (any Error).self) {
            try await UDFLogicalFilesExporter.export(sourceURL: fixture.source, to: output)
        }
        #expect(try Data(contentsOf: output.appendingPathComponent("keep.txt")) == sentinel)
        let linked = fixture.directory.appendingPathComponent("symlink.dd")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: fixture.source)
        await #expect(throws: (any Error).self) {
            try await UDFLogicalFilesExporter.export(sourceURL: linked, to: fixture.directory.appendingPathComponent("Linked Import"))
        }
        let parent = fixture.directory.appendingPathComponent("Output Alias")
        try FileManager.default.createSymbolicLink(at: parent, withDestinationURL: output)
        await #expect(throws: (any Error).self) {
            try await UDFLogicalFilesExporter.export(sourceURL: fixture.source, to: parent.appendingPathComponent("New"))
        }
        #expect(!FileManager.default.fileExists(atPath: output.appendingPathComponent("New").path))
        #expect(try Data(contentsOf: fixture.source) == fixture.image)
    }

    @Test("Logical import cancellation and overall timeout never publish an incomplete collection")
    func autopsyLogicalCancellation() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let cancelledOutput = fixture.directory.appendingPathComponent("Cancelled")
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await UDFLogicalFilesExporter.export(sourceURL: fixture.source, to: cancelledOutput)
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(!FileManager.default.fileExists(atPath: cancelledOutput.path))
        let timeoutOutput = fixture.directory.appendingPathComponent("TimedOut")
        await #expect(throws: UDFError.timeout) {
            try await UDFLogicalFilesExporter.export(sourceURL: fixture.source, to: timeoutOutput,
                beforePublication: { usleep(50_000) }, timeoutSeconds: 0.01)
        }
        #expect(!FileManager.default.fileExists(atPath: timeoutOutput.path))
        #expect(try Data(contentsOf: fixture.source) == fixture.image)
    }

    @Test("Modified payload/manifest, extra files or changed sources cannot publish a completed logical import", arguments: ["payload", "manifest", "extra", "source"])
    func autopsyLogicalPublication(_ mutation: String) async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let output = fixture.directory.appendingPathComponent("MustNotPublish")
        await #expect(throws: (any Error).self) {
            try await UDFLogicalFilesExporter.export(sourceURL: fixture.source, to: output, beforePublication: {
                let children = try FileManager.default.contentsOfDirectory(at: fixture.directory, includingPropertiesForKeys: nil)
                let stage = try #require(children.first { $0.lastPathComponent.hasPrefix(".udf-logical-import-") })
                let manifestURL = stage.appendingPathComponent("Reports/manifest.json")
                let manifest = try JSONDecoder().decode(UDFLogicalFilesExport.self, from: Data(contentsOf: manifestURL))
                let changed: URL
                switch mutation {
                case "manifest": changed = manifestURL
                case "extra": changed = stage.appendingPathComponent("LogicalFiles/unclaimed.txt")
                case "source": changed = fixture.source
                default: changed = stage.appendingPathComponent(manifest.entries[0].outputRelativePath)
                }
                try Data("tampered".utf8).write(to: changed)
            })
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
        if mutation != "source" { #expect(try Data(contentsOf: fixture.source) == fixture.image) }
    }

    @Test("Logical import path mapping preserves names, escapes traversal hazards and separates versions")
    func autopsyLogicalPathMapping() throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let reference = try #require(fixture.parse().entries.first)
        func entry(path: String, id: String = String(repeating: "a", count: 64)) -> UDFFileEntry {
            .init(id: id, originalPath: path, state: .current, fidCharacteristics: reference.fidCharacteristics,
                fidSourceOffset: reference.fidSourceOffset, deletedAncestorProof: [], byteCount: reference.byteCount,
                sha256: reference.sha256, icb: reference.icb, sourceExtents: reference.sourceExtents,
                timestamps: reference.timestamps, snapshotIDs: reference.snapshotIDs)
        }
        let a = try UDFLogicalFilesExporter.relativePath(for: entry(path: "/folder/document.docx"))
        #expect(a.path.hasSuffix("/folder/document.docx"))
        #expect(try UDFLogicalFilesExporter.relativePath(for: entry(path: "/name:with%colon.txt")).path.hasSuffix("/name%3Awith%25colon.txt"))
        #expect(try UDFLogicalFilesExporter.relativePath(for: entry(path: "/NAME.txt", id: String(repeating: "b", count: 64))).path != UDFLogicalFilesExporter.relativePath(for: entry(path: "/name.txt")).path)
        let long = try UDFLogicalFilesExporter.relativePath(for: entry(path: "/" + String(repeating: "long-component/", count: 100) + "file.txt"))
        #expect(long.path.utf8.count < 600)
        #expect(long.note.contains("long namespace"))
        #expect(throws: (any Error).self) { try UDFLogicalFilesExporter.relativePath(for: entry(path: "/../escape")) }
        #expect(throws: (any Error).self) { try UDFLogicalFilesExporter.relativePath(for: entry(path: "/double//empty")) }
        #expect(throws: (any Error).self) { try UDFLogicalFilesExporter.relativePath(for: entry(path: "/valid", id: "../escape")) }
    }

    @Test("A selected UDF image can be read through a search-only parent without folder enumeration")
    func searchOnlyParent() throws {
        let fixture = try UDFFixture()
        defer { _ = Darwin.chmod(fixture.directory.path, mode_t(0o700)); fixture.remove() }
        #expect(Darwin.chmod(fixture.directory.path, mode_t(0o100)) == 0)
        let result = try fixture.parse()
        #expect(result.entries.count == 2)
        #expect(try Data(contentsOf: fixture.source) == fixture.image)
    }

    @Test("Current and historical namespaces preserve original names, ancestor proof, exact extents and UTC times")
    func namespacesAndExtents() throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let result = try fixture.parse()
        #expect(result.volumeIdentifier == "Synthetic Optical")
        #expect(result.udfRevision == "2.01")
        #expect(result.snapshots.map(\.id) == ["vat-399", "vat-397"])
        #expect(result.entries.count == 2)
        let current = try #require(result.entries.first { $0.state == .current })
        #expect(current.originalPath == "/current.txt")
        #expect(current.sha256 == UDFFixture.hash(fixture.currentPayload))
        #expect(current.sourceExtents.first?.allocation == "inline")
        let historical = try #require(result.entries.first { $0.state == .historicalDeletedAncestor })
        #expect(historical.originalPath == "/deleted/note.dat")
        #expect(historical.fidCharacteristics == 0)
        #expect(historical.deletedAncestorProof.count == 1)
        #expect(historical.deletedAncestorProof[0].fidCharacteristics == 6)
        #expect(historical.deletedAncestorProof[0].nullICB)
        #expect(historical.deletedAncestorProof[0].rawNameHex.hasPrefix("fe"))
        #expect(historical.sha256 == UDFFixture.hash(fixture.historicalPayload))
        #expect(historical.byteCount == Int64(fixture.historicalPayload.count))
        #expect(historical.sourceExtents.count == 2)
        #expect(historical.timestamps.modification.timezoneMinutes == 420)
        #expect(historical.timestamps.modification.microsecond == 123_456)
        #expect(historical.timestamps.modification.utcDate?.timeIntervalSince1970 == 1_577_836_800.123456)
        #expect(historical.timestamps.modification.rawHex.count == 24)
        #expect(try Data(contentsOf: fixture.source) == fixture.image)
    }

    @Test("Short allocation descriptors map virtual blocks without losing payload bytes")
    func shortAllocation() throws {
        let fixture = try UDFFixture(shortAllocations: true); defer { fixture.remove() }
        let result = try fixture.parse()
        let historical = try #require(result.entries.first { $0.state == .historicalDeletedAncestor })
        #expect(historical.sha256 == UDFFixture.hash(fixture.historicalPayload))
        #expect(historical.sourceExtents.map(\.offset) == [294 * 2_048, 296 * 2_048])
    }

    @Test("External directory allocations validate each FID's logical block provenance")
    func externalDirectory() throws {
        let fixture = try UDFFixture(externalDirectories: true); defer { fixture.remove() }
        let result = try fixture.parse()
        #expect(result.entries.count == 2)
        let historical = try #require(result.entries.first { $0.state == .historicalDeletedAncestor })
        #expect(historical.sha256 == UDFFixture.hash(fixture.historicalPayload))
        #expect(historical.fidSourceOffset == 300 * 2_048)
    }

    @Test("Invalid tags, CRC coverage, cycles, missing bytes and unsupported profiles fail closed", arguments: ["checksum", "crc", "coverage", "cycle", "outside", "gap", "map", "name", "allocation", "fidLocation", "retainedDeletedICB", "hardlink", "stream"])
    func malformed(_ mode: String) throws {
        let fixture = try UDFFixture(mutation: mode); defer { fixture.remove() }
        #expect(throws: (any Error).self) { try fixture.parse() }
        #expect(try Data(contentsOf: fixture.source) == fixture.image)
    }

    @Test("Snapshot, file, payload and metadata limits cannot publish partial history", arguments: ["snapshots", "files", "payload", "metadata", "directory", "file"])
    func limits(_ mode: String) throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        var options = UDFInspectionOptions()
        switch mode {
        case "snapshots": options.maximumSnapshots = 1
        case "files": options.maximumFiles = 1
        case "payload": options.maximumPayloadBytes = 1
        case "metadata": options.maximumMetadataBlocks = 1
        case "directory": options.maximumDirectoryBytes = 1
        default: options.maximumFileBytes = 1
        }
        #expect(throws: (any Error).self) { try fixture.parse(options: options) }
    }

    @Test("Source replacement, symlinks and wrong selected-file hash are rejected")
    func sourceProtection() throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        #expect(throws: ForensicsError.sourceChanged) {
            try UDFInspector.parseForTesting(evidence: fixture.evidence, caseID: UUID(), afterParse: {
                let replacement = fixture.directory.appendingPathComponent("replacement.dd")
                try fixture.image.write(to: replacement)
                guard Darwin.rename(replacement.path, fixture.source.path) == 0 else { throw ForensicsError.io("fixture rename") }
            })
        }
        let link = fixture.directory.appendingPathComponent("linked.dd")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fixture.source)
        let linkedEvidence = EvidenceRecord(sourcePath: link.path, byteCount: fixture.evidence.byteCount,
            sha256: fixture.evidence.sha256, container: .raw, filesystemHint: nil)
        #expect(throws: (any Error).self) { try UDFInspector.parseForTesting(evidence: linkedEvidence, caseID: UUID()) }
        let wrong = EvidenceRecord(sourcePath: fixture.source.path, byteCount: fixture.evidence.byteCount,
            sha256: String(repeating: "0", count: 64), container: .raw, filesystemHint: nil)
        #expect(throws: ForensicsError.sourceChanged) { try UDFInspector.parseForTesting(evidence: wrong, caseID: UUID()) }
        let wrongSize = EvidenceRecord(sourcePath: fixture.source.path, byteCount: fixture.evidence.byteCount - 1,
            sha256: fixture.evidence.sha256, container: .raw, filesystemHint: nil)
        #expect(throws: ForensicsError.sourceChanged) { try UDFInspector.parseForTesting(evidence: wrongSize, caseID: UUID()) }
    }

    @Test("New generations and exports survive reopen; existing output and a failed generation remain intact")
    func saveAndExport() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let selected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        let fresh = try CaseStore.create(name: "Optical", in: fixture.directory)
        let forensicCase = try CaseStore.adding(image: selected, to: fresh)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let result = try await UDFInspector.inspect(evidence: evidence, in: forensicCase)
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == result)
        let historical = try #require(result.entries.first { $0.state == .historicalDeletedAncestor })
        let destination = fixture.directory.appendingPathComponent("recovered.dat")
        let receipt = try await UDFInspector.export(entryID: historical.id, from: result, in: forensicCase, to: destination)
        #expect(receipt.sha256 == historical.sha256)
        #expect(try Data(contentsOf: destination) == fixture.historicalPayload)
        await #expect(throws: (any Error).self) {
            try await UDFInspector.export(entryID: historical.id, from: result, in: forensicCase, to: destination)
        }
        let next = try UDFInspector.parseForTesting(evidence: evidence, caseID: forensicCase.manifest.id)
        #expect(throws: CancellationError.self) {
            try UDFResultStore.save(next, in: forensicCase, prePublicationValidation: { throw CancellationError() })
        }
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == result)
        #expect(try Data(contentsOf: destination) == fixture.historicalPayload)
    }

    @Test("A task cancelled before parsing cannot publish a new optical result")
    func cancellation() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let selected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: selected, to: CaseStore.create(name: "Cancelled", in: fixture.directory))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await UDFInspector.inspect(evidence: evidence, in: forensicCase)
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == nil)
    }

    @Test("Cancellation during namespace traversal preserves the previous generation")
    func cancellationDuringTraversal() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let selected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: selected, to: CaseStore.create(name: "Traversal", in: fixture.directory))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let previous = try await UDFInspector.inspect(evidence: evidence, in: forensicCase)
        await #expect(throws: CancellationError.self) {
            try await UDFInspector.inspect(evidence: evidence, in: forensicCase, progress: { progress in
                if progress.stage.hasPrefix("Reading UDF namespace") { withUnsafeCurrentTask { $0?.cancel() } }
            })
        }
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == previous)
    }

    @Test("A busy case lock observes the configured deadline and leaves no optical generation")
    func caseLockDeadline() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let selected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: selected, to: CaseStore.create(name: "Locked", in: fixture.directory))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let result = try UDFInspector.parseForTesting(evidence: evidence, caseID: forensicCase.manifest.id,
            options: .init(timeoutSeconds: 0.1))
        let descriptor = Darwin.open(forensicCase.bundleURL.appendingPathComponent(".case.lock").path,
                                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        #expect(descriptor >= 0)
        guard descriptor >= 0 else { return }
        defer { _ = udfTestFlock(descriptor, LOCK_UN); Darwin.close(descriptor) }
        #expect(udfTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
        let worker = Task.detached { try UDFResultStore.save(result, in: forensicCase) }
        await #expect(throws: UDFError.timeout) { try await worker.value }
        #expect(udfTestFlock(descriptor, LOCK_UN) == 0)
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == nil)
    }

    @Test("Stored JSON mutation and offline source replacement cannot produce an export")
    func tamperAndChangedExport() async throws {
        let fixture = try UDFFixture(); defer { fixture.remove() }
        let selected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: selected, to: CaseStore.create(name: "Tamper", in: fixture.directory))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let result = try await UDFInspector.inspect(evidence: evidence, in: forensicCase)
        let entry = try #require(result.entries.first)
        let destination = fixture.directory.appendingPathComponent("not-exported.bin")
        var changed = fixture.image; changed[0] ^= 1
        try changed.write(to: fixture.source)
        await #expect(throws: ForensicsError.sourceChanged) {
            try await UDFInspector.export(entryID: entry.id, from: result, in: forensicCase, to: destination)
        }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == result)
        let generation = forensicCase.bundleURL.appendingPathComponent("optical/\(evidence.id.uuidString.lowercased())/generations/\(result.jobID.uuidString.lowercased())/result.json")
        var bytes = try Data(contentsOf: generation); bytes[0] = 0x20
        try bytes.write(to: generation)
        #expect(throws: (any Error).self) { try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) }
        await #expect(throws: (any Error).self) {
            try await UDFInspector.export(entryID: entry.id, from: result, in: forensicCase, to: destination)
        }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test("Optional local assignment matches independent oracle and exports each original extent",
          .enabled(if: ProcessInfo.processInfo.environment["NF_UDF_ASSIGNMENT_IMAGE"] != nil &&
                   ProcessInfo.processInfo.environment["NF_UDF_ASSIGNMENT_ORACLE"] != nil))
    func localAssignmentOracle() async throws {
        let environment = ProcessInfo.processInfo.environment
        let source = URL(fileURLWithPath: try #require(environment["NF_UDF_ASSIGNMENT_IMAGE"]))
        let oracleURL = URL(fileURLWithPath: try #require(environment["NF_UDF_ASSIGNMENT_ORACLE"]))
        let suppliedOutput = environment["NF_UDF_ASSIGNMENT_OUTPUT"]
        let output = suppliedOutput.map { URL(fileURLWithPath: $0).standardizedFileURL }
            ?? FileManager.default.temporaryDirectory.appendingPathComponent("AssignmentUDF-" + UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
        defer { if suppliedOutput == nil { try? FileManager.default.removeItem(at: output) } }
        let selected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: selected, to: CaseStore.create(name: "Assignment Optical", in: output))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let result = try await UDFInspector.inspect(evidence: evidence, in: forensicCase)
        let oracle = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: oracleURL)) as? [String: Any])
        let expected = try #require(oracle["files"] as? [[String: Any]])
        #expect(result.entries.count == expected.count)
        #expect(result.snapshots.count == 9)
        #expect(result.entries.filter { $0.state == .current }.count == 3)
        #expect(result.entries.filter { $0.state == .historicalDeletedAncestor }.count == 17)
        let exports = output.appendingPathComponent("exports")
        try FileManager.default.createDirectory(at: exports, withIntermediateDirectories: false)
        var receipts: [UDFExportReceipt] = []
        for entry in result.entries {
            let reference = try #require(expected.first { ($0["imagePath"] as? String) == entry.originalPath })
            #expect(entry.sha256 == reference["sha256"] as? String)
            #expect(entry.byteCount == (reference["bytes"] as? NSNumber)?.int64Value)
            let times = try #require(reference["metadata"] as? [String: [String: Any]])
            for (key, timestamp) in [("access", entry.timestamps.access), ("modification", entry.timestamps.modification),
                                      ("attribute", entry.timestamps.attribute), ("creation", try #require(entry.timestamps.creation))] {
                #expect(timestamp.rawHex == times[key]?["raw_hex"] as? String)
                #expect(timestamp.timezoneMinutes == times[key]?["timezone_minutes"] as? Int)
            }
            let extents = try #require(reference["rawDataExtents"] as? [[String: Any]])
            #expect(entry.sourceExtents.count == extents.count)
            for (actual, expectedExtent) in zip(entry.sourceExtents, extents) {
                #expect(actual.offset == (expectedExtent["offset"] as? NSNumber)?.int64Value)
                #expect(actual.byteCount == (expectedExtent["length"] as? NSNumber)?.int64Value)
            }
            let receipt = try await UDFInspector.export(entryID: entry.id, from: result, in: forensicCase,
                to: exports.appendingPathComponent(entry.id + ".bin"))
            #expect(receipt.sha256 == entry.sha256 && receipt.byteCount == entry.byteCount)
            receipts.append(receipt)
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(result).write(to: output.appendingPathComponent("native-udf-result.json"), options: .withoutOverwriting)
        try encoder.encode(receipts).write(to: output.appendingPathComponent("native-udf-exports.json"), options: .withoutOverwriting)
        #expect(try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == result)
    }

    @Test("Unspecified timezone preserves raw fields without inventing a UTC value")
    func unspecifiedTime() throws {
        var bytes = UDFFixture.timestamp()
        bytes[0] = 0x01; bytes[1] = 0x18 // Local time with -2047 unspecified timezone.
        let timestamp = try UDFDescriptor.timestamp(bytes, sourceOffset: 42)
        #expect(timestamp.utcDate == nil)
        #expect(timestamp.timezoneMinutes == nil)
        #expect(timestamp.sourceOffset == 42)
    }
}

private struct UDFFixture {
    let directory: URL
    let source: URL
    let image: Data
    let evidence: EvidenceRecord
    let currentPayload = Data("Current file\n".utf8)
    let historicalPayload = Data("This historical payload uses two noncontiguous recorded extents.\n".utf8)

    init(shortAllocations: Bool = false, externalDirectories: Bool = false, mutation: String = "") throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("NativeUDF-" + UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        source = directory.appendingPathComponent("synthetic.dd")
        var image = Data(count: 400 * 2_048)
        func write(_ block: Int, _ bytes: Data) { image.replaceSubrange((block * 2_048)..<(block * 2_048 + bytes.count), with: bytes) }
        var recognition = Data(count: 2_048); recognition.replaceSubrange(1..<6, with: Data("NSR03".utf8)); write(17, recognition)
        var anchor = Data(count: 2_048); anchor.put32(16, 5 * 2_048); anchor.put32(20, 32); Self.tag(&anchor, id: 2, location: 256, coverage: 496); write(256, anchor)
        var partition = Data(count: 2_048); partition.put16(22, 0); partition.put32(188, 288); partition.put32(192, 112); Self.tag(&partition, id: 5, location: 32, coverage: 496); write(32, partition)
        var logical = Data(count: 2_048)
        let volume = Data([8]) + Data("Synthetic Optical".utf8)
        logical.replaceSubrange(84..<(84 + volume.count), with: volume); logical[211] = UInt8(volume.count)
        logical.put32(212, 2_048); logical.put16(240, 0x0201); logical.put32(248, 2_048); logical.put16(256, 1)
        logical.put32(264, 70); logical.put32(268, 2)
        logical[440] = 1; logical[441] = 6
        logical[446] = 2; logical[447] = 64
        logical.replaceSubrange(451..<473, with: Data("*UDF Virtual Partition".utf8)); logical.put16(474, 0x0201)
        if mutation == "map" { logical[451] = 0x58 }
        Self.tag(&logical, id: 6, location: 33, coverage: 494); write(33, logical)
        var terminator = Data(count: 2_048); Self.tag(&terminator, id: 8, location: 34, coverage: 496); write(34, terminator)
        for block in [288, 290] {
            var fsd = Data(count: 2_048); fsd.put32(400, 2_048); fsd.put32(404, 1); fsd.put16(408, 1)
            Self.tag(&fsd, id: 256, location: 0, coverage: 496); write(block, fsd)
        }
        let external = externalDirectories || mutation == "fidLocation"
        let currentLocation: UInt32 = external ? 10 : 1
        let currentFID = Self.fid("current.txt", block: 4, location: mutation == "fidLocation" ? 999 : currentLocation)
        let deletedFID = Self.fid("deleted", block: mutation == "retainedDeletedICB" ? 2 : 0,
            location: currentLocation, flags: 6, nullICB: mutation != "retainedDeletedICB", compression: mutation == "name" ? 7 : 254)
        let currentDirectory = currentFID + deletedFID + (mutation == "hardlink" ? Self.fid("alias.txt", block: 4, location: currentLocation) : Data())
        let olderDirectory = Self.fid("current.txt", block: 4, location: external ? 11 : 1)
            + Self.fid("deleted", block: 2, location: external ? 11 : 1, flags: 2)
        let childDirectory = Self.fid("note.dat", block: 3, location: external ? 12 : 2)
        if external {
            func externalNode(location: UInt32, dataBlock: UInt32, bytes: Data) -> Data {
                var ad = Data(count: 16); ad.put32(0, UInt32(bytes.count)); ad.put32(4, dataBlock)
                return Self.node(type: 4, location: location, allocations: ad, infoLength: bytes.count)
            }
            write(289, externalNode(location: 1, dataBlock: 10, bytes: currentDirectory)); write(298, currentDirectory)
            write(291, externalNode(location: 1, dataBlock: 11, bytes: olderDirectory)); write(299, olderDirectory)
            write(292, externalNode(location: 2, dataBlock: 12, bytes: childDirectory)); write(300, childDirectory)
        } else {
            write(289, Self.node(type: 4, location: 1, inline: currentDirectory))
            write(291, Self.node(type: 4, location: 1, inline: olderDirectory))
            write(292, Self.node(type: 4, location: 2, inline: childDirectory))
        }
        let split = 25
        var allocations = Data(count: shortAllocations ? 16 : 32)
        allocations.put32(0, UInt32(split) | (mutation == "gap" ? 0x4000_0000 : 0)); allocations.put32(4, mutation == "outside" ? 999_999 : 6)
        allocations.put32(shortAllocations ? 8 : 16, UInt32(historicalPayload.count - split)); allocations.put32(shortAllocations ? 12 : 20, 8)
        if !shortAllocations { allocations.put16(8, 0); allocations.put16(24, 0) }
        var historical = Self.node(type: 5, location: 3, allocations: allocations,
            infoLength: historicalPayload.count, allocationKind: shortAllocations ? 0 : 1)
        if mutation == "allocation" { historical.put16(34, 2); Self.tag(&historical, id: 266, location: 3, coverage: 2_032) }
        write(293, historical)
        write(294, historicalPayload.prefix(split)); write(296, historicalPayload.dropFirst(split))
        var current = Self.node(type: 5, location: 4, inline: currentPayload)
        if mutation == "stream" { current.put32(152, 2_048); Self.tag(&current, id: 266, location: 4, coverage: 2_032) }
        write(295, current)
        let currentMap: [UInt32] = [0, 1, 4, 5, 7, 0, 6, 0, 8]
        let olderMap: [UInt32] = [2, 3, 4, 5, 7, 0, 6, 0, 8]
        write(397, Self.vat(location: 109, previous: UInt32.max, mappings: olderMap))
        write(399, Self.vat(location: 111, previous: mutation == "cycle" ? 111 : 109, mappings: currentMap))
        if mutation == "checksum" { image[256 * 2_048 + 4] ^= 1 }
        if mutation == "crc" { image[293 * 2_048 + 216] ^= 1 }
        if mutation == "coverage" {
            var uncovered = image.subdata(in: (293 * 2_048)..<(294 * 2_048))
            Self.tag(&uncovered, id: 266, location: 3, coverage: 0); write(293, uncovered)
        }
        self.image = image
        try image.write(to: source, options: .withoutOverwriting)
        evidence = EvidenceRecord(sourcePath: source.path, byteCount: Int64(image.count), sha256: Self.hash(image), container: .raw, filesystemHint: "UDF")
    }

    func parse(options: UDFInspectionOptions = .init()) throws -> UDFInspectionResult {
        try UDFInspector.parseForTesting(evidence: evidence, caseID: UUID(), options: options)
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func timestamp() -> Data {
        var data = Data([0xa4, 0x11, 0xe4, 0x07, 1, 1, 7, 0, 0, 12, 34, 56])
        data.put16(2, 2020); return data
    }
    static func node(type: UInt8, location: UInt32, inline: Data? = nil,
                     allocations: Data = Data(), infoLength: Int = 0, allocationKind: UInt16 = 1) -> Data {
        var data = Data(count: 2_048); data.put16(20, 4); data[27] = type
        data.put16(34, inline == nil ? allocationKind : 3)
        data.put64(56, UInt64(inline?.count ?? infoLength))
        for offset in [80, 92, 104, 116] { data.replaceSubrange(offset..<(offset + 12), with: timestamp()) }
        let payload = inline ?? allocations; data.put32(212, UInt32(payload.count))
        data.replaceSubrange(216..<(216 + payload.count), with: payload)
        tag(&data, id: 266, location: location, coverage: 2_032); return data
    }
    static func fid(_ name: String, block: UInt32, location: UInt32, flags: UInt8 = 0,
                    nullICB: Bool = false, compression: UInt8 = 8) -> Data {
        let bytes = Data([compression]) + Data(name.utf8), length = (38 + bytes.count + 3) & ~3
        var data = Data(count: length); data.put16(16, 1); data[18] = flags; data[19] = UInt8(bytes.count)
        data.put32(20, nullICB ? 0 : 2_048); data.put32(24, block); data.put16(28, 1)
        data.replaceSubrange(38..<(38 + bytes.count), with: bytes)
        tag(&data, id: 257, location: location, coverage: length - 16); return data
    }
    static func vat(location: UInt32, previous: UInt32, mappings: [UInt32]) -> Data {
        var payload = Data(count: 152 + mappings.count * 4); payload.put16(0, 152); payload.put32(132, previous)
        payload.put16(144, 0x0201); payload.put16(146, 0x0201); payload.put16(148, 0x0201)
        for (index, mapped) in mappings.enumerated() { payload.put32(152 + index * 4, mapped) }
        var data = Data(count: 2_048); data.put16(20, 4); data[27] = 248; data.put16(34, 3)
        data.put64(56, UInt64(payload.count)); data.put32(172, UInt32(payload.count))
        for offset in [72, 84, 96] { data.replaceSubrange(offset..<(offset + 12), with: timestamp()) }
        data.replaceSubrange(176..<(176 + payload.count), with: payload)
        tag(&data, id: 261, location: location, coverage: 2_032); return data
    }
    // Fixture checksum is independent of UDFDescriptor.crc, so a shared bug in
    // production and test generation cannot silently validate corrupt metadata.
    static func tag(_ data: inout Data, id: UInt16, location: UInt32, coverage: Int) {
        data.put16(0, id); data.put16(2, 3); data.put16(10, UInt16(coverage)); data.put32(12, location)
        var crc: UInt32 = 0
        for byte in data[16..<(16 + coverage)] {
            crc ^= UInt32(byte) << 8
            for _ in 0..<8 { crc = (crc << 1) ^ (crc & 0x8000 == 0 ? 0 : 0x1021); crc &= 0xffff }
        }
        data.put16(8, UInt16(crc)); data[4] = 0
        data[4] = UInt8(truncatingIfNeeded: data.prefix(16).reduce(UInt32(0)) { $0 + UInt32($1) })
    }
}

private extension Data {
    mutating func put16(_ offset: Int, _ value: UInt16) {
        self[offset] = UInt8(truncatingIfNeeded: value); self[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
    }
    mutating func put32(_ offset: Int, _ value: UInt32) {
        put16(offset, UInt16(truncatingIfNeeded: value)); put16(offset + 2, UInt16(truncatingIfNeeded: value >> 16))
    }
    mutating func put64(_ offset: Int, _ value: UInt64) {
        put32(offset, UInt32(truncatingIfNeeded: value)); put32(offset + 4, UInt32(truncatingIfNeeded: value >> 32))
    }
}
