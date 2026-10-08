import CryptoKit
import Darwin
import Foundation
import ForensicsCore

/// Synthetic-only local history workload. It never invokes Codex or reads user
/// evidence. The external runner measures this process's actual peak RSS.
@main
struct CaseHistoryWorkloadProbe {
    static func main() async {
        do { try await run(); Darwin.exit(0) }
        catch { FileHandle.standardError.write(Data("history workload failed: \(error)\n".utf8)); Darwin.exit(1) }
    }

    private static func run() async throws {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.count >= 2, args[0] == "--mode", args[1] == "populate-gui" {
            try populateGUI(try GUIPopulationArguments(args))
            return
        }
        guard args.count == 8, args[0] == "--mode", ["generate", "scan"].contains(args[1]),
              args[2] == "--root", args[4] == "--records", args[6] == "--prompt-bytes",
              let count = Int(args[5]), (1...1_000).contains(count),
              let promptByteCount = Int(args[7]), (1...900_000).contains(promptByteCount) else {
            throw ProbeError.invalidArguments
        }
        let mode = args[1]
        let directory = URL(fileURLWithPath: args[3], isDirectory: true).standardizedFileURL
        guard directory.isFileURL, directory.path.hasPrefix("/") else { throw ProbeError.invalidArguments }
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        let source = directory.appendingPathComponent("synthetic-source.dd")
        let sourceBytes = Data("owned synthetic source\n".utf8)
        let sourceSHA = digest(sourceBytes)
        let forensicCase: ForensicCase
        if mode == "generate" {
            try sourceBytes.write(to: source, options: .withoutOverwriting)
            let created = try CaseStore.create(name: "History Benchmark", in: directory)
            let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
            forensicCase = try CaseStore.adding(image: inspected, to: created)
        } else {
            forensicCase = try CaseStore.open(at: directory.appendingPathComponent("History Benchmark.nativecase"))
        }
        guard let evidence = forensicCase.manifest.evidence.first else { throw ProbeError.oracle }
        let manifest = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let manifestBytes = try Data(contentsOf: manifest)
        let manifestSHA = digest(manifestBytes)
        if mode == "scan" {
            let fixture = try JSONDecoder().decode(FixtureReceipt.self,
                from: Data(contentsOf: directory.appendingPathComponent("history-fixture-receipt.json")))
            guard fixture.syntheticOnly, fixture.providerRequests == 0, fixture.recordCount == count,
                  fixture.promptBytes == promptByteCount, fixture.manifestSHA256 == manifestSHA,
                  fixture.sourceSHA256 == sourceSHA, evidence.sha256 == sourceSHA,
                  evidence.sourcePath == source.path else { throw ProbeError.oracle }
        }
        let file = FilesystemEntry(id: "0:1", path: "/SYNTHETIC.TXT", name: "SYNTHETIC.TXT", fsOffsetBytes: 0,
            metaAddress: 1, size: Int64(sourceBytes.count), isDirectory: false, isDeleted: false)
        let result = EnumerationResult(engineVersion: "synthetic-history-oracle", patchDigest: "synthetic-only",
            sourcePaths: [source.path], sourceFileHashes: [source.path: sourceSHA], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: Int64(sourceBytes.count), sectorSize: 512),
            volumes: [], files: [file], warnings: [], status: .completed,
            savedAt: Date(timeIntervalSinceReferenceDate: 813_457_690.125))
        let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: file)
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
        let prompt = String(repeating: "H", count: promptByteCount)
        let requestSHA = digest(Data(prompt.utf8))
        var ids: [UUID] = []
        ids.reserveCapacity(count)
        var serializedTotal: Int64 = 0
        var serializedMaximum = 0
        let generateStart = ProcessInfo.processInfo.systemUptime
        for index in 0..<count {
            guard let id = UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", index + 1)) else { throw ProbeError.oracle }
            if mode == "generate" {
            let response = CodexAnalysisResult(response: .init(summary: "Synthetic local history receipt \(index + 1)",
                observations: ["Known input marker"], hypotheses: ["No provider request was made"],
                limitations: ["Benchmark-only synthetic advisory"], nextSteps: ["Verify the independent oracle"]),
                requestSHA256: requestSHA, completedAt: Date(timeIntervalSinceReferenceDate: 813_457_693.25 + Double(index)))
            let record = try AnalysisRecord.make(binding: binding, context: context, prompt: prompt,
                question: "Synthetic local workload", result: response, retention: .full,
                cliVersion: "synthetic-no-provider", id: id)
            try CaseWorkStore.saveAnalysis(record, in: forensicCase.bundleURL)
            }
            let path = forensicCase.bundleURL.appendingPathComponent("analyses").appendingPathComponent(id.uuidString.lowercased() + ".json")
            var metadata = stat()
            guard Darwin.lstat(path.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
                  metadata.st_size > 0, metadata.st_size <= CaseWorkStore.maximumRecordBytes else { throw ProbeError.oracle }
            serializedTotal += metadata.st_size; serializedMaximum = max(serializedMaximum, Int(metadata.st_size))
            ids.append(id)
        }
        let generateSeconds = mode == "generate" ? ProcessInfo.processInfo.systemUptime - generateStart : 0
        if mode == "generate" {
            guard try Data(contentsOf: manifest) == manifestBytes, try Data(contentsOf: source) == sourceBytes else { throw ProbeError.oracle }
            let fixture = FixtureReceipt(syntheticOnly: true, providerRequests: 0, recordCount: count,
                promptBytes: promptByteCount, manifestSHA256: manifestSHA, sourceSHA256: sourceSHA,
                serializedTotalBytes: serializedTotal, maximumSerializedRecordBytes: serializedMaximum,
                generationSeconds: generateSeconds)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
            let bytes = try encoder.encode(fixture)
            try bytes.write(to: directory.appendingPathComponent("history-fixture-receipt.json"), options: .withoutOverwriting)
            FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data("\n".utf8))
            return
        }
        let scanStart = ProcessInfo.processInfo.systemUptime
        var observed: [UUID] = []
        var pages: [[String]] = []
        var maximumObserved = 0
        var cursor: CaseWorkCursor?
        repeat {
            let page = try CaseWorkStore.history(binding: binding, kind: .analysis, cursor: cursor,
                limit: CaseWorkStore.maximumPageSize, in: forensicCase.bundleURL)
            guard page.totalDiagnosticCount == 0, page.diagnostics.isEmpty,
                  page.items.count <= CaseWorkStore.maximumPageSize else { throw ProbeError.oracle }
            maximumObserved = max(maximumObserved, page.maximumSerializedRecordBytesObserved)
            pages.append(page.items.map { $0.id.uuidString.lowercased() })
            observed.append(contentsOf: page.items.map(\.id))
            cursor = page.nextCursor
            guard pages.count <= (count + CaseWorkStore.maximumPageSize - 1) / CaseWorkStore.maximumPageSize else { throw ProbeError.oracle }
        } while cursor != nil
        let scanSeconds = ProcessInfo.processInfo.systemUptime - scanStart
        guard observed == Array(ids.reversed()), maximumObserved == serializedMaximum else { throw ProbeError.oracle }
        let verifyStart = ProcessInfo.processInfo.systemUptime
        for (index, id) in ids.enumerated() {
            guard let loaded = try CaseWorkStore.loadAnalysis(id: id, in: forensicCase.bundleURL),
                  loaded.id == id, loaded.prompt == prompt, loaded.retention == .full,
                  loaded.requestSHA256 == requestSHA,
                  loaded.result.response.summary == "Synthetic local history receipt \(index + 1)",
                  digest(Data((loaded.prompt ?? "").utf8)) == requestSHA else { throw ProbeError.oracle }
        }
        let verifySeconds = ProcessInfo.processInfo.systemUptime - verifyStart
        guard try Data(contentsOf: manifest) == manifestBytes,
              try digest(Data(contentsOf: source)) == sourceSHA,
              try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest else { throw ProbeError.oracle }
        let receipt = Receipt(schemaVersion: 1, syntheticOnly: true, providerRequests: 0,
            processID: ProcessInfo.processInfo.processIdentifier, recordCount: count, promptBytes: promptByteCount,
            requestSHA256: requestSHA, serializedTotalBytes: serializedTotal,
            maximumSerializedRecordBytes: serializedMaximum, maximumScanSerializedBytes: maximumObserved,
            historyPages: pages, exactOrderVerified: true, everyStoredRequestVerified: true,
            originalManifestSHA256: manifestSHA, originalManifestUnchanged: true,
            originalSourceSHA256: sourceSHA, originalSourceUnchanged: true,
            generationSeconds: generateSeconds, historyScanSeconds: scanSeconds, verifySeconds: verifySeconds,
            rssMeasurement: "Fresh scan process excludes fixture generation. External runner peak RSS includes history paging and per-record verification; stage-separated RSS requires sampling.")
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let bytes = try encoder.encode(receipt)
        FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data("\n".utf8))
    }


    /// Populate only an operator-owned new clone with real, already saved TSK
    /// metadata. This mode never constructs an EnumerationResult, invokes an
    /// engine/provider, or rewrites the cache to make a synthetic entry reachable.
    /// Each save is individually committed. A failure retains the partial owned
    /// clone; population is not a batch-atomic operation and must not be retried
    /// against that nonempty analysis namespace or the original operator case.
    private static func populateGUI(_ arguments: GUIPopulationArguments) throws {
        let forensicCase = try CaseStore.open(at: arguments.caseURL)
        guard forensicCase.manifest.id == arguments.caseID else { throw ProbeError.caseMismatch }
        guard let evidence = forensicCase.manifest.evidence.first(where: { $0.id == arguments.evidenceID }) else {
            throw ProbeError.evidenceMissing
        }
        guard let result = try EngineResultStore.load(evidenceID: evidence.id, in: forensicCase.bundleURL) else {
            throw ProbeError.missingCachedListing
        }
        // Exclude the retained headless synthetic fixture explicitly. The
        // operator must independently establish the selected cache's actual
        // enumeration provenance; a metadata label is not engine attestation.
        guard !result.engineVersion.lowercased().contains("synthetic"),
              result.patchDigest != "synthetic-only" else { throw ProbeError.syntheticCachedListing }
        let matching = result.files.filter { $0.id == arguments.fileID }
        guard matching.count == 1, let file = matching.first else { throw ProbeError.selectedFileMissing }
        guard !file.isDirectory, !file.isDeleted, [.completed, .partial].contains(result.status) else {
            throw ProbeError.selectedFileUnsupported
        }
        let directory = forensicCase.bundleURL.appendingPathComponent("analyses", isDirectory: true)
        if FileManager.default.fileExists(atPath: directory.path) {
            guard try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty else {
                throw ProbeError.analysisNamespaceNotEmpty
            }
        }
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let originalManifest = try Data(contentsOf: manifestURL)
        let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: file)
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
        let prompt = String(repeating: "H", count: arguments.promptBytes)
        let requestSHA = digest(Data(prompt.utf8))
        let start = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        var ids: [UUID] = []
        var serializedTotal: Int64 = 0
        var serializedMaximum = 0
        for index in 0..<arguments.records {
            let id = UUID()
            let response = CodexAnalysisResult(response: .init(
                summary: "Synthetic GUI history receipt \(index + 1)",
                observations: ["Known local fixture metadata"], hypotheses: ["No provider request was made"],
                limitations: ["GUI-memory fixture only; this was not an actual outbound app request"],
                nextSteps: ["Verify the independent fixture oracle"]), requestSHA256: requestSHA,
                completedAt: start.addingTimeInterval(Double(index)))
            let record = try AnalysisRecord.make(binding: binding, context: context, prompt: prompt,
                question: "Synthetic GUI workload record \(index + 1)", result: response, retention: .full,
                cliVersion: "synthetic-no-provider", promptTemplateVersion: "synthetic-gui-memory.v1", id: id)
            try CaseWorkStore.saveAnalysis(record, in: forensicCase.bundleURL)
            guard let loaded = try CaseWorkStore.loadAnalysis(id: id, in: forensicCase.bundleURL),
                  loaded.id == id, loaded.binding == binding, loaded.retention == .full,
                  loaded.prompt == prompt, loaded.requestSHA256 == requestSHA,
                  loaded.result.response == response.response else { throw ProbeError.populationOracle }
            let path = directory.appendingPathComponent(id.uuidString.lowercased() + ".json")
            var metadata = stat()
            guard Darwin.lstat(path.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
                  metadata.st_size > 0, metadata.st_size <= CaseWorkStore.maximumRecordBytes else {
                throw ProbeError.populationOracle
            }
            serializedTotal += metadata.st_size
            serializedMaximum = max(serializedMaximum, Int(metadata.st_size))
            ids.append(id)
        }
        var observed: [UUID] = []
        var pages: [[String]] = []
        var cursor: CaseWorkCursor?
        repeat {
            let page = try CaseWorkStore.history(binding: binding, kind: .analysis, cursor: cursor,
                limit: CaseWorkStore.maximumPageSize, in: forensicCase.bundleURL)
            guard page.totalDiagnosticCount == 0, page.diagnostics.isEmpty,
                  page.items.count <= CaseWorkStore.maximumPageSize else { throw ProbeError.populationOracle }
            observed.append(contentsOf: page.items.map(\.id))
            pages.append(page.items.map { $0.id.uuidString.lowercased() })
            cursor = page.nextCursor
            guard pages.count <= (arguments.records + CaseWorkStore.maximumPageSize - 1) / CaseWorkStore.maximumPageSize else {
                throw ProbeError.populationOracle
            }
        } while cursor != nil
        guard observed == Array(ids.reversed()), try Data(contentsOf: manifestURL) == originalManifest,
              try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest else {
            throw ProbeError.populationOracle
        }
        let receipt = GUIPopulationReceipt(schemaVersion: 1, syntheticOnly: true, providerRequests: 0,
            datasetScope: "New GUI-memory fixture from independently established genuine cached metadata; not the retained headless dataset",
            caseID: forensicCase.manifest.id, evidenceID: evidence.id, fileID: file.id,
            filePath: file.path, selectedEntryBytes: file.size, cachedEngineVersion: result.engineVersion,
            cachedPatchDigest: result.patchDigest, bindingLocatorSHA256: binding.locatorSHA256,
            bindingSnapshotSHA256: binding.snapshotSHA256, sourceBytesVerifiedForContent: false,
            recordCount: arguments.records, promptBytes: arguments.promptBytes, requestSHA256: requestSHA,
            serializedTotalBytes: serializedTotal, maximumSerializedRecordBytes: serializedMaximum,
            historyPages: pages, exactOrderVerified: true, everyStoredRequestVerified: true,
            originalManifestSHA256: digest(originalManifest), originalManifestUnchanged: true)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let bytes = try encoder.encode(receipt)
        FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data("\n".utf8))
    }

    private struct GUIPopulationArguments {
        let caseURL: URL
        let caseID: UUID
        let evidenceID: UUID
        let fileID: String
        let records: Int
        let promptBytes: Int
        init(_ args: [String]) throws {
            guard args.count == 14, args[0] == "--mode", args[1] == "populate-gui",
                  args[2] == "--case", args[4] == "--case-id", args[6] == "--evidence-id",
                  args[8] == "--file-id", args[10] == "--records", args[12] == "--prompt-bytes",
                  args[3].hasPrefix("/"), args[3].hasSuffix(".nativecase"),
                  let caseID = UUID(uuidString: args[5]), let evidenceID = UUID(uuidString: args[7]),
                  !args[9].isEmpty, args[9].utf8.count <= 1_024,
                  !args[9].contains("\n"), !args[9].contains("\r"),
                  !args[11].isEmpty, args[11].utf8.allSatisfy({ (48...57).contains($0) }),
                  !args[13].isEmpty, args[13].utf8.allSatisfy({ (48...57).contains($0) }),
                  let records = Int(args[11]), (1...1_000).contains(records),
                  let promptBytes = Int(args[13]), (1...900_000).contains(promptBytes) else {
                throw ProbeError.invalidGUIArguments
            }
            self.caseURL = URL(fileURLWithPath: args[3], isDirectory: true).standardizedFileURL
            self.caseID = caseID; self.evidenceID = evidenceID; self.fileID = args[9]
            self.records = records; self.promptBytes = promptBytes
        }
    }

    private struct GUIPopulationReceipt: Encodable {
        let schemaVersion: Int; let syntheticOnly: Bool; let providerRequests: Int; let datasetScope: String
        let caseID: UUID; let evidenceID: UUID; let fileID: String; let filePath: String
        let selectedEntryBytes: Int64; let cachedEngineVersion: String; let cachedPatchDigest: String
        let bindingLocatorSHA256: String; let bindingSnapshotSHA256: String; let sourceBytesVerifiedForContent: Bool
        let recordCount: Int; let promptBytes: Int; let requestSHA256: String
        let serializedTotalBytes: Int64; let maximumSerializedRecordBytes: Int
        let historyPages: [[String]]; let exactOrderVerified: Bool; let everyStoredRequestVerified: Bool
        let originalManifestSHA256: String; let originalManifestUnchanged: Bool
    }

    private static func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    private enum ProbeError: Error {
        case invalidArguments, oracle, invalidGUIArguments, caseMismatch, evidenceMissing, missingCachedListing
        case syntheticCachedListing, selectedFileMissing, selectedFileUnsupported, analysisNamespaceNotEmpty, populationOracle
    }
    private struct FixtureReceipt: Codable {
        let syntheticOnly: Bool; let providerRequests: Int; let recordCount: Int; let promptBytes: Int
        let manifestSHA256: String; let sourceSHA256: String; let serializedTotalBytes: Int64
        let maximumSerializedRecordBytes: Int; let generationSeconds: Double
    }
    private struct Receipt: Encodable {
        let schemaVersion: Int; let syntheticOnly: Bool; let providerRequests: Int; let processID: Int32
        let recordCount: Int; let promptBytes: Int; let requestSHA256: String
        let serializedTotalBytes: Int64; let maximumSerializedRecordBytes: Int; let maximumScanSerializedBytes: Int
        let historyPages: [[String]]; let exactOrderVerified: Bool; let everyStoredRequestVerified: Bool
        let originalManifestSHA256: String; let originalManifestUnchanged: Bool
        let originalSourceSHA256: String; let originalSourceUnchanged: Bool
        let generationSeconds: Double; let historyScanSeconds: Double; let verifySeconds: Double; let rssMeasurement: String
    }
}
