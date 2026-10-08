import CryptoKit
import Darwin
import Foundation
import ForensicsCore

/// Development-only headless measurements over an independent synthetic oracle.
/// The Python owner creates fixtures and measures all owned process RSS. No GUI,
/// AI provider or user case is opened by this probe.
@main
struct NativeWorkloadProbe {
    static func main() async {
        do { try await run() }
        catch {
            FileHandle.standardError.write(Data("Native workload failed: \(error)\n".utf8))
            Darwin.exit(1)
        }
    }

    static func run() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        var values: [String: String] = [:]
        let keys = ["--fixture", "--engine", "--decoder", "--output", "--mode", "--rows"]
        guard arguments.count.isMultiple(of: 2) else { throw ProbeError.arguments }
        for index in stride(from: 0, to: arguments.count, by: 2) {
            guard keys.contains(arguments[index]), values[arguments[index]] == nil else { throw ProbeError.arguments }
            values[arguments[index]] = arguments[index + 1]
        }
        guard let outputPath = values["--output"] else { throw ProbeError.arguments }
        let output = URL(fileURLWithPath: outputPath).standardizedFileURL
        let local = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("local").resolvingSymlinksInPath()
        guard output.deletingLastPathComponent().path.hasPrefix(local.path + "/"),
              output == output.resolvingSymlinksInPath(),
              !FileManager.default.fileExists(atPath: output.path) else { throw ProbeError.destination }
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let mode = values["--mode"] ?? "workflow"
        if mode == "listing" {
            guard let rows = Int(values["--rows"] ?? "50000"), [50_000, 100_000, 1_000_000].contains(rows) else { throw ProbeError.arguments }
            try listing(rows: rows, output: output)
            return
        }
        guard ["workflow", "cancel"].contains(mode), let fixturePath = values["--fixture"],
              let enginePath = values["--engine"], let decoderPath = values["--decoder"] else { throw ProbeError.arguments }
        let fixture = URL(fileURLWithPath: fixturePath).standardizedFileURL
        guard fixture.path.hasPrefix(local.path + "/"), fixture == fixture.resolvingSymlinksInPath(),
              !fixture.path.hasPrefix(output.path + "/"), !output.path.hasPrefix(fixture.path + "/") else { throw ProbeError.destination }
        let oracle: Oracle = try read(fixture.appendingPathComponent("oracle.json"))
        guard oracle.schemaVersion == 1, oracle.syntheticOnly,
              oracle.imageByteCount >= 256 * 1_048_576 else { throw ProbeError.oracle }
        let source = fixture.appendingPathComponent("workload-fat32.raw")
        let metadata = fixture.appendingPathComponent("metadata-only.raw")
        let engineURL = URL(fileURLWithPath: enginePath).standardizedFileURL
        let decoderURL = URL(fileURLWithPath: decoderPath).standardizedFileURL
        let engine = EngineClient(helperURL: engineURL)
        let clock = ContinuousClock(), totalStart = clock.now
        var stageSeconds: [String: Double] = [:]
        var start = clock.now
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let metadataInspected = try await ImageInspector.inspect(url: metadata, progress: { _ in })
        guard inspected.sha256 == oracle.imageSHA256, inspected.byteCount == oracle.imageByteCount,
              metadataInspected.sha256 == oracle.metadataSHA256,
              metadataInspected.byteCount == oracle.metadataByteCount else { throw ProbeError.oracle }
        stageSeconds["initialSourceVerification"] = seconds(start.duration(to: clock.now))
        start = clock.now
        let listing = try await engine.enumerate(imageURL: source,
            options: .init(timezone: "UTC", hashLogicalImage: false))
        guard listing.status == .completed else { throw ProbeError.incomplete }
        let regular = listing.files.filter { !$0.isDirectory }
        guard Set(regular.map(\.path)) == Set(oracle.files.keys) else { throw ProbeError.listing }
        for file in regular {
            guard let expected = oracle.files[file.path], file.size == expected.byteCount,
                  !file.isDeleted else { throw ProbeError.oracle }
        }
        let evidence = EvidenceRecord(sourcePath: source.path, byteCount: inspected.byteCount,
            sha256: inspected.sha256, container: inspected.container, filesystemHint: inspected.filesystemHint)
        let metadataEvidence = EvidenceRecord(sourcePath: metadata.path, byteCount: metadataInspected.byteCount,
            sha256: metadataInspected.sha256, container: metadataInspected.container,
            filesystemHint: metadataInspected.filesystemHint)
        stageSeconds["enumeration"] = seconds(start.duration(to: clock.now))
        if mode == "cancel" {
            try await cancel(source: source, metadata: metadata, evidence: evidence, metadataEvidence: metadataEvidence,
                listing: listing, oracle: oracle, engineURL: engineURL, decoderURL: decoderURL,
                output: output, stageSeconds: stageSeconds)
            return
        }
        start = clock.now
        var forensicCase = try CaseStore.create(name: "Synthetic Large Workload", in: output)
        forensicCase = try CaseStore.adding(image: inspected, to: forensicCase)
        forensicCase = try CaseStore.adding(image: metadataInspected, to: forensicCase)
        guard let caseEvidence = forensicCase.manifest.evidence.first(where: { $0.sourcePath == source.path }),
              let caseMetadata = forensicCase.manifest.evidence.first(where: { $0.sourcePath == metadata.path }) else { throw ProbeError.reopen }
        try EngineResultStore.save(result: listing, evidenceID: caseEvidence.id, in: forensicCase.bundleURL)
        guard let reopenedListing = try EngineResultStore.load(evidenceID: caseEvidence.id, in: forensicCase.bundleURL),
              reopenedListing.files == listing.files,
              reopenedListing.sourceFileHashes == listing.sourceFileHashes else { throw ProbeError.reopen }
        let manifestBefore = try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json"))
        stageSeconds["caseListingPersistenceReopen"] = seconds(start.duration(to: clock.now))
        try write(reopenedListing, to: output.appendingPathComponent("filesystem-listing.json"))
        let exports = output.appendingPathComponent("verified-files")
        try FileManager.default.createDirectory(at: exports, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var verifiedFiles: [String: FileReceipt] = [:], decoded: [String: DecodeReceipt] = [:]
        var decodeSeconds = 0.0
        start = clock.now
        for (offset, path) in oracle.files.keys.sorted().enumerated() {
            guard let file = regular.first(where: { $0.path == path }), let expected = oracle.files[path] else { throw ProbeError.oracle }
            let filename = String(format: "%04d-", offset) + file.name
            let target = exports.appendingPathComponent(filename)
            let receipt = try await engine.extract(imageURL: source, file: file, outputURL: target,
                options: reopenedListing.options, expectedSourceHashes: reopenedListing.sourceFileHashes)
            guard receipt.sha256 == expected.sha256, receipt.byteCount == expected.byteCount else { throw ProbeError.oracle }
            verifiedFiles[path] = FileReceipt(byteCount: receipt.byteCount, sha256: receipt.sha256,
                exportFile: "verified-files/" + filename)
            // Keep standalone decode work and byte budget identical to index eligibility.
            if file.size <= 32 * 1_048_576 {
                let decodeStart = clock.now
                let value = try await DocumentAnalysisClient(helperURL: decoderURL).analyze(.init(fileURL: target,
                    expectedSHA256: expected.sha256, expectedByteCount: expected.byteCount))
                decodeSeconds += seconds(decodeStart.duration(to: clock.now))
                try validateDecode(value, expected: expected)
                decoded[path] = DecodeReceipt(status: value.status.rawValue, textPages: value.textPages,
                    textIsComplete: value.textIsComplete, sourceSHA256: value.sourceSHA256)
            }
        }
        stageSeconds["extractionIndependentVerification"] = seconds(start.duration(to: clock.now)) - decodeSeconds
        stageSeconds["isolatedDecode"] = decodeSeconds
        start = clock.now
        let index = try await CaseContentIndexService(engineHelperURL: engineURL, documentHelperURL: decoderURL)
            .rebuild(caseID: forensicCase.manifest.id, inputs: [.init(evidence: caseEvidence, result: reopenedListing),
                .init(evidence: caseMetadata, result: nil)])
        stageSeconds["contentIndexBuild"] = seconds(start.duration(to: clock.now))
        guard index.indexedCount == oracle.expectedCounts.indexed,
              index.skippedCount == oracle.expectedCounts.skipped, index.failedCount == oracle.expectedCounts.failed,
              index.pendingCount == oracle.expectedCounts.pending, index.missingListingCount == 1,
              index.isPartial else { throw ProbeError.index }
        var documents: [String: IndexReceipt] = [:]
        for document in index.documents {
            guard let expected = oracle.files[document.file.path], document.status.rawValue == expected.indexStatus,
                  document.reason == expected.indexReason else { throw ProbeError.index }
            if document.status == .indexed {
                guard document.contentSHA256 == expected.sha256,
                      document.textPages.count == 1, document.textPages[0].text == expected.text,
                      document.textIsComplete == expected.textIsComplete else { throw ProbeError.index }
            }
            documents[document.file.path] = IndexReceipt(status: document.status.rawValue, reason: document.reason,
                textPages: document.textPages, textIsComplete: document.textIsComplete,
                contentSHA256: document.contentSHA256)
        }
        start = clock.now
        try CaseContentIndexStore.save(index, expectedSnapshotID: nil, in: forensicCase.bundleURL)
        let reopenedCase = try CaseStore.open(at: forensicCase.bundleURL)
        guard let reopened = try CaseContentIndexStore.load(in: reopenedCase.bundleURL),
              reopened.documents == index.documents, reopened.sources == index.sources,
              reopened.id == index.id else { throw ProbeError.reopen }
        stageSeconds["indexPersistenceReopen"] = seconds(start.duration(to: clock.now))
        start = clock.now
        var searchHits: [String: [Hit]] = [:]
        for query in oracle.queries.keys.sorted() {
            let found = try CaseContentIndexSearch.search(query, in: reopened, caseSensitive: true)
            let hits = found.hits.map { Hit(path: $0.reference.file.path,
                utf16Offset: $0.reference.utf16Offset, utf16Length: $0.reference.utf16Length) }.sorted()
            guard hits == oracle.queries[query]?.sorted(), found.coverageIsPartial, !found.hitLimitReached else { throw ProbeError.search }
            for hit in found.hits {
                guard let page = CaseContentIndexSearch.resolve(hit.reference, in: reopened),
                      (page.text as NSString).substring(with: NSRange(location: hit.reference.utf16Offset,
                        length: hit.reference.utf16Length)) == query,
                      hit.reference.contentSHA256 == oracle.files[hit.reference.file.path]?.sha256,
                      hit.reference.orderedContainerSHA256 == [inspected.sha256] else { throw ProbeError.search }
            }
            searchHits[query] = hits
        }
        guard try FilesystemSearchIndex(files: listing.files).rows(matching: "needleOnlyInPayload").isEmpty else { throw ProbeError.search }
        stageSeconds["contentSearch"] = seconds(start.duration(to: clock.now))
        start = clock.now
        let batch = try await FilesystemBatchExportService(engine: engine).export(analysis: reopenedListing,
            files: regular.sorted { $0.path < $1.path }, to: output.appendingPathComponent("batch-export"), caseURL: forensicCase.bundleURL)
        guard batch.status == .completed, batch.successfulCount == oracle.files.count else { throw ProbeError.export }
        var batchFiles: [String: FileReceipt] = [:]
        for item in batch.entries {
            guard let expected = oracle.files[item.sourceFile.path], item.byteCount == expected.byteCount,
                  item.sha256 == expected.sha256, let filename = item.outputFilename else { throw ProbeError.export }
            batchFiles[item.sourceFile.path] = FileReceipt(byteCount: expected.byteCount,
                sha256: expected.sha256, exportFile: "batch-export/" + filename)
        }
        stageSeconds["batchExport"] = seconds(start.duration(to: clock.now))
        start = clock.now
        let after = try await ImageInspector.inspect(url: source, progress: { _ in })
        let metadataAfter = try await ImageInspector.inspect(url: metadata, progress: { _ in })
        guard after.sha256 == inspected.sha256, after.byteCount == inspected.byteCount,
              metadataAfter.sha256 == metadataInspected.sha256,
              try Data(contentsOf: forensicCase.bundleURL.appendingPathComponent("manifest.json")) == manifestBefore else { throw ProbeError.integrity }
        stageSeconds["finalSourceVerification"] = seconds(start.duration(to: clock.now))
        stageSeconds["totalWorkflow"] = seconds(totalStart.duration(to: clock.now))
        let indexBytes = try FileManager.default.attributesOfItem(atPath: forensicCase.bundleURL.appendingPathComponent(CaseContentIndexStore.filename).path)[.size] as? Int ?? 0
        let previews = regular.filter { $0.size <= 32 * 1_048_576 }.count
        let receipt = WorkflowReceipt(schemaVersion: 1, syntheticOnly: true, providerExecuted: false,
            measurementKind: "ForensicsCore-headless-workflow", mode: mode,
            sourceBeforeSHA256: inspected.sha256, sourceAfterSHA256: after.sha256,
            metadataBeforeSHA256: metadataInspected.sha256, metadataAfterSHA256: metadataAfter.sha256,
            verifiedFiles: verifiedFiles, batchExportFiles: batchFiles, decoded: decoded,
            documents: documents, searchHits: searchHits, counts: oracle.expectedCounts,
            missingListingCount: reopened.missingListingCount, indexReopened: true, manifestUnchanged: true,
            byteAccounting: ["sourceContainerBytes": inspected.byteCount,
                "metadataContainerBytes": metadataInspected.byteCount,
                "indexPreviewAttempts": Int64(previews),
                "legacyIndexSourceHashReadBytesStatic": Int64(2 * previews + 2) * inspected.byteCount + 2 * metadataInspected.byteCount,
                "extractedBytes": regular.reduce(0) { $0 + $1.size },
                "derivedTextBytes": Int64(index.textByteCount), "serializedIndexBytes": Int64(indexBytes),
                "indexFileByteCap": 32 * 1_048_576, "indexInputByteCap": 256 * 1_048_576,
                "indexTextByteCap": 16 * 1_048_576, "listingEntryCap": 50_000], stageSeconds: stageSeconds)
        try write(receipt, to: output.appendingPathComponent("workload-receipt.json"))
        print("Large synthetic workflow verified: \(inspected.byteCount) source bytes, \(regular.count) exact payloads, \(index.indexedCount) indexed, \(index.skippedCount) skipped; \(index.missingListingCount) metadata-only source. Headless measurement only.")
    }

    private static func validateDecode(_ value: DocumentAnalysis, expected: ExpectedFile) throws {
        guard value.sourceSHA256 == expected.sha256, value.sourceByteCount == expected.byteCount else { throw ProbeError.decode }
        if let text = expected.text {
            guard value.status == .decoded, value.textPages.count == 1,
                  value.textPages[0].text == text, value.textIsComplete == expected.textIsComplete else { throw ProbeError.decode }
        } else if expected.byteCount == 0 {
            guard value.status == .decoded, value.textPages.count == 1,
                  value.textPages[0].text.isEmpty, !value.textIsComplete else { throw ProbeError.decode }
        } else {
            guard value.status == .unsupported, value.textPages.isEmpty else { throw ProbeError.decode }
        }
    }

    private static func cancel(source: URL, metadata: URL, evidence: EvidenceRecord, metadataEvidence: EvidenceRecord,
                       listing: EnumerationResult, oracle: Oracle, engineURL: URL, decoderURL: URL,
                       output: URL, stageSeconds initial: [String: Double]) async throws {
        let before = try scratchNames()
        let state = ProgressState()
        let task = Task {
            try await CaseContentIndexService(engineHelperURL: engineURL, documentHelperURL: decoderURL)
                .rebuild(caseID: UUID(), inputs: [.init(evidence: evidence, result: listing),
                    .init(evidence: metadataEvidence, result: nil)], progress: { value in state.observe(value.filename) })
        }
        let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(30))
        while !state.hasStartedPreview && clock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
        guard state.hasStartedPreview else { task.cancel(); _ = try? await task.value; throw ProbeError.cancel }
        // Cancel an active per-file verification/extraction operation. Waiting
        // for the task also waits for its owned helper/decoder reaping contract.
        try await Task.sleep(for: .milliseconds(25))
        let start = clock.now
        task.cancel()
        var cancelled = false
        do { _ = try await task.value } catch is CancellationError { cancelled = true }
        let elapsed = seconds(start.duration(to: clock.now))
        let afterScratch = try scratchNames()
        guard cancelled, afterScratch.subtracting(before).isEmpty else { throw ProbeError.cancel }
        let after = try await ImageInspector.inspect(url: source, progress: { _ in })
        let metadataAfter = try await ImageInspector.inspect(url: metadata, progress: { _ in })
        guard after.sha256 == oracle.imageSHA256, metadataAfter.sha256 == oracle.metadataSHA256 else { throw ProbeError.integrity }
        var stages = initial; stages["cancellationDrain"] = elapsed
        try write(CancelReceipt(schemaVersion: 1, syntheticOnly: true, providerExecuted: false,
            mode: "cancel", sourceBeforeSHA256: oracle.imageSHA256, sourceAfterSHA256: after.sha256,
            metadataBeforeSHA256: oracle.metadataSHA256, metadataAfterSHA256: metadataAfter.sha256,
            cancelled: cancelled, newScratchRemaining: afterScratch.subtracting(before).count,
            stageSeconds: stages), to: output.appendingPathComponent("workload-receipt.json"))
        print("Cancelled active index work; drained in \(elapsed)s; no new document scratch remained.")
    }

    static func scratchNames() throws -> Set<String> {
        Set(try FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
            .filter { $0.hasPrefix(".native-document-") })
    }

    static func listing(rows count: Int, output: URL) throws {
        let clock = ContinuousClock(), start = clock.now
        let files = (0..<count).map { offset in
            let label = offset.isMultiple(of: 8) ? "เอกสาร" : "alpha"
            return FilesystemEntry(id: "row-\(offset)", path: "/derived-only/\(label)-\(offset)/item-\(offset).TXT",
                name: "item-\(offset).TXT", fsOffsetBytes: 0, metaAddress: UInt64(offset),
                size: Int64(offset % 4096), isDirectory: false, isDeleted: offset.isMultiple(of: 17))
        }
        let generation = seconds(start.duration(to: clock.now))
        let production = FilesystemSearchIndex(files: files)
        guard production.count == 50_000 else { throw ProbeError.listing }
        var samples: [Double] = [], digest = "", matchingRows = 0
        // A derived harness may exercise larger arrays. These are never
        // admitted to engine caches, content indexes, cases or the GUI.
        for block in 0..<6 {
            let begin = clock.now
            var found: [FilesystemEntry] = []
            if count == 50_000 { found = try production.rows(matching: "เอกสาร") }
            else {
                for (offset, file) in files.enumerated() {
                    if offset.isMultiple(of: 128) { try Task.checkCancellation() }
                    if file.path.localizedCaseInsensitiveContains("เอกสาร") { found.append(file) }
                }
            }
            let elapsed = seconds(begin.duration(to: clock.now))
            let expected = stride(from: 0, to: count, by: 8).map { files[$0] }
            guard found == expected else { throw ProbeError.search }
            var hasher = SHA256()
            for file in found { hasher.update(data: Data((file.id + "\n").utf8)) }
            digest = hex(hasher.finalize()); matchingRows = found.count
            if block > 0 { samples.append(elapsed) }
        }
        let capped = try production.rows(matching: "เอกสาร")
        guard capped.count == 6_250, capped.last?.id == "row-49992" else { throw ProbeError.listing }
        try write(ListingReceipt(schemaVersion: 1, syntheticOnly: true, providerExecuted: false, mode: "listing",
            measurementKind: count == 50_000 ? "production-bounded-search" : "derived-harness-only",
            rows: count, productionCap: 50_000, productionCount: production.count,
            matchingRows: matchingRows, matchingIDsSHA256: digest,
            stageSeconds: ["generation": generation], searchSamplesSeconds: samples),
            to: output.appendingPathComponent("workload-receipt.json"))
        print("Verified \(count) synthetic rows; production retains \(production.count); matching \(matchingRows).")
    }

    static func seconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
    static func hex(_ digest: SHA256.Digest) -> String { digest.map { String(format: "%02x", $0) }.joined() }
    static func read<T: Decodable>(_ url: URL) throws -> T { try JSONDecoder().decode(T.self, from: Data(contentsOf: url)) }
    static func write<T: Encodable>(_ value: T, to url: URL) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(value).write(to: url, options: .withoutOverwriting)
    }
}

private final class ProgressState: @unchecked Sendable {
    private let lock = NSLock()
    private var started = false
    var hasStartedPreview: Bool { lock.withLock { started } }
    func observe(_ filename: String) { if !filename.isEmpty { lock.withLock { started = true } } }
}

private enum ProbeError: Error { case arguments, destination, oracle, incomplete, listing, reopen, index, search, export, integrity, decode, cancel }
private struct Oracle: Decodable {
    let schemaVersion: Int; let syntheticOnly: Bool; let imageSHA256: String; let imageByteCount: Int64
    let metadataSHA256: String; let metadataByteCount: Int64
    let files: [String: ExpectedFile]; let queries: [String: [Hit]]; let expectedCounts: Counts
}
private struct ExpectedFile: Decodable {
    let byteCount: Int64; let sha256: String; let text: String?; let textIsComplete: Bool
    let indexStatus: String; let indexReason: String?
}
private struct Hit: Codable, Equatable, Comparable {
    let path: String; let utf16Offset: Int; let utf16Length: Int
    static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.path == rhs.path ? lhs.utf16Offset < rhs.utf16Offset : lhs.path < rhs.path
    }
}
private struct Counts: Codable { let indexed: Int; let skipped: Int; let pending: Int; let failed: Int }
private struct FileReceipt: Encodable { let byteCount: Int64; let sha256: String; let exportFile: String }
private struct DecodeReceipt: Encodable { let status: String; let textPages: [DocumentTextPage]; let textIsComplete: Bool; let sourceSHA256: String }
private struct IndexReceipt: Encodable { let status: String; let reason: String?; let textPages: [DocumentTextPage]; let textIsComplete: Bool; let contentSHA256: String? }
private struct WorkflowReceipt: Encodable {
    let schemaVersion: Int; let syntheticOnly: Bool; let providerExecuted: Bool; let measurementKind: String; let mode: String
    let sourceBeforeSHA256: String; let sourceAfterSHA256: String; let metadataBeforeSHA256: String; let metadataAfterSHA256: String
    let verifiedFiles: [String: FileReceipt]; let batchExportFiles: [String: FileReceipt]; let decoded: [String: DecodeReceipt]
    let documents: [String: IndexReceipt]; let searchHits: [String: [Hit]]; let counts: Counts
    let missingListingCount: Int; let indexReopened: Bool; let manifestUnchanged: Bool
    let byteAccounting: [String: Int64]; let stageSeconds: [String: Double]
}
private struct CancelReceipt: Encodable {
    let schemaVersion: Int; let syntheticOnly: Bool; let providerExecuted: Bool; let mode: String
    let sourceBeforeSHA256: String; let sourceAfterSHA256: String; let metadataBeforeSHA256: String; let metadataAfterSHA256: String
    let cancelled: Bool; let newScratchRemaining: Int; let stageSeconds: [String: Double]
}
private struct ListingReceipt: Encodable {
    let schemaVersion: Int; let syntheticOnly: Bool; let providerExecuted: Bool; let mode: String; let measurementKind: String
    let rows: Int; let productionCap: Int; let productionCount: Int; let matchingRows: Int; let matchingIDsSHA256: String
    let stageSeconds: [String: Double]; let searchSamplesSeconds: [Double]
}
