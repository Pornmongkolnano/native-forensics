import Darwin
import Foundation
import ForensicsCore

/// Development-only, read-only input workflow. All outputs are new, under the
/// ignored local directory. Independent reference comparison is a separate step.
@main
struct AssignmentWorkflowProbe {
    static func main() async {
        do { try await run() }
        catch {
            FileHandle.standardError.write(Data("Assignment workflow failed: \(error)\n".utf8))
            Darwin.exit(1)
        }
    }

    private static func run() async throws {
        let keys = ["--p2", "--rm2", "--rm3", "--engine", "--decoder", "--photorec", "--output"]
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count == keys.count * 2 || args.count == (keys.count + 1) * 2 else { throw ProbeError.arguments }
        var values: [String: String] = [:]
        for index in stride(from: 0, to: args.count, by: 2) {
            guard (keys.contains(args[index]) || args[index] == "--only"), values[args[index]] == nil else { throw ProbeError.arguments }
            values[args[index]] = args[index + 1]
        }
        guard keys.allSatisfy({ values[$0] != nil }) else { throw ProbeError.arguments }
        guard values["--only"] == nil || ["p2", "verify"].contains(values["--only"]!) else { throw ProbeError.arguments }
        let output = URL(fileURLWithPath: values["--output"]!).standardizedFileURL
        let local = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("local").resolvingSymlinksInPath()
        guard output.deletingLastPathComponent().resolvingSymlinksInPath().path.hasPrefix(local.path + "/") else { throw ProbeError.destination }
        if values["--only"] == "verify" {
            let reopened = try CaseStore.open(at: output.appendingPathComponent("Assignment Validation.nativecase"))
            let recovery: CarvingResult = try read(output.appendingPathComponent("p2-recovery.json"))
            let filesystem: EnumerationResult = try read(output.appendingPathComponent("rm2-filesystem.json"))
            let optical: UDFInspectionResult = try read(output.appendingPathComponent("rm3-history.json"))
            guard try equivalent(RecoveryResultStore.latest(evidenceID: recovery.sourceEvidenceID, in: reopened.bundleURL), recovery),
                  let evidence = reopened.manifest.evidence.first(where: { filesystem.sourcePaths.contains($0.sourcePath) }),
                  try equivalent(EngineResultStore.load(evidenceID: evidence.id, in: reopened.bundleURL), filesystem),
                  try equivalent(UDFInspector.loadLatest(in: reopened, evidenceID: optical.sourceEvidenceID), optical) else { throw ProbeError.reopen }
            for record in reopened.manifest.evidence {
                let after = try await ImageInspector.inspect(url: URL(fileURLWithPath: record.sourcePath), progress: { _ in })
                guard after.sha256 == record.sha256, after.byteCount == record.byteCount else { throw ForensicsError.sourceChanged }
            }
            try Data("Post-workflow verification completed: serialized result stores reopened exactly; source bytes unchanged. Initial probe rejected subsecond savedAt normalization, corrected in comparator; no inputs or results rewritten.\n".utf8)
                .write(to: output.appendingPathComponent("completed.txt"), options: .withoutOverwriting)
            return
        }
        guard !FileManager.default.fileExists(atPath: output.path) else { throw ProbeError.destination }
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var forensicCase = try CaseStore.create(name: "Assignment Validation", in: output)
        var records: [String: EvidenceRecord] = [:]
        for key in ["--p2", "--rm2", "--rm3"] {
            let image = try await ImageInspector.inspect(url: URL(fileURLWithPath: values[key]!), progress: { _ in })
            forensicCase = try CaseStore.adding(image: image, to: forensicCase)
            records[key] = forensicCase.manifest.evidence.last!
        }
        try write(forensicCase.manifest, to: output.appendingPathComponent("input-receipts.json"))
        let engine = EngineClient(helperURL: URL(fileURLWithPath: values["--engine"]!))
        let documents = DocumentAnalysisClient(helperURL: URL(fileURLWithPath: values["--decoder"]!))
        let clock = ContinuousClock()
        var timings: [String: Double] = [:]

        var started = clock.now
        let recovery = try await PhotoRecRecoveryService(executableURL: URL(fileURLWithPath: values["--photorec"]!))
            .recover(evidence: records["--p2"]!, in: forensicCase)
        timings["p2RecoverySeconds"] = seconds(started.duration(to: clock.now))
        try write(recovery, to: output.appendingPathComponent("p2-recovery.json"))
        let p2Exports = try directory("p2-exports", in: output)
        var recoveryAnalyses: [UUID: DocumentAnalysis] = [:]
        for (index, artifact) in recovery.artifacts.enumerated() {
            let target = p2Exports.appendingPathComponent("\(index)-\(artifact.filename)")
            let exported = try RecoveryResultStore.export(artifact: artifact, result: recovery, in: forensicCase.bundleURL, to: target)
            let analysis = try await documents.analyze(.init(fileURL: target, expectedSHA256: exported.sha256, expectedByteCount: exported.byteCount))
            recoveryAnalyses[artifact.id] = analysis
        }
        try write(recoveryAnalyses.map { AnalysisRecord(key: $0.key.uuidString, analysis: $0.value) }.sorted { $0.key < $1.key }, to: output.appendingPathComponent("p2-documents.json"))
        _ = try RecoveryReportBuilder.exportMarkdown(result: recovery, analyses: recoveryAnalyses, in: forensicCase.bundleURL, to: output.appendingPathComponent("p2-report.md"))
        print("P2: \(recovery.artifacts.count) primary recoveries, exported and decoded")
        if values["--only"] == "p2" {
            let reopened = try CaseStore.open(at: forensicCase.bundleURL)
            guard reopened.manifest == forensicCase.manifest,
                  try equivalent(RecoveryResultStore.latest(evidenceID: records["--p2"]!.id, in: reopened.bundleURL), recovery) else { throw ProbeError.reopen }
            for record in reopened.manifest.evidence {
                let after = try await ImageInspector.inspect(url: URL(fileURLWithPath: record.sourcePath), progress: { _ in })
                guard after.sha256 == record.sha256, after.byteCount == record.byteCount else { throw ForensicsError.sourceChanged }
            }
            try write(timings, to: output.appendingPathComponent("timings.json"))
            try Data("P2 workflow completed; source bytes unchanged and recovery store reopened exactly.\n".utf8)
                .write(to: output.appendingPathComponent("completed.txt"), options: .withoutOverwriting)
            return
        }

        started = clock.now
        let filesystem = try await engine.enumerate(imageURL: URL(fileURLWithPath: records["--rm2"]!.sourcePath), options: .init(timezone: "UTC"))
        guard filesystem.status == .completed else { throw ProbeError.incomplete }
        try EngineResultStore.save(result: filesystem, evidenceID: records["--rm2"]!.id, in: forensicCase.bundleURL)
        timings["rm2EnumerationSeconds"] = seconds(started.duration(to: clock.now))
        try write(filesystem, to: output.appendingPathComponent("rm2-filesystem.json"))
        let regular = filesystem.files.filter { !$0.isDirectory && $0.size > 0 && !$0.name.hasPrefix("$") }
        started = clock.now
        let batch = try await FilesystemBatchExportService(engine: engine).export(analysis: filesystem, files: regular,
            to: output.appendingPathComponent("rm2-exports"), caseURL: forensicCase.bundleURL,
            progress: { update in
                if update.currentFilename == nil || update.completedFiles % 10 == 0 {
                    print("RM2 batch: \(update.completedFiles)/\(update.totalFiles)")
                }
            })
        timings["rm2BatchExportSeconds"] = seconds(started.duration(to: clock.now))
        try write(batch, to: output.appendingPathComponent("rm2-export-receipts.json"))
        guard batch.status == .completed else { throw ProbeError.incomplete }
        var filesystemAnalyses: [AnalysisRecord] = []
        for entry in batch.entries {
            let analysis = try await documents.analyze(.init(fileURL: URL(fileURLWithPath: batch.destinationPath).appendingPathComponent(entry.outputFilename!),
                expectedSHA256: entry.sha256!, expectedByteCount: entry.byteCount!))
            filesystemAnalyses.append(.init(key: entry.sourceFile.id, analysis: analysis))
        }
        try write(filesystemAnalyses, to: output.appendingPathComponent("rm2-documents.json"))
        print("RM2: \(filesystem.files.count) records; \(batch.successfulCount) payload exports")

        started = clock.now
        let optical = try await UDFInspector.inspect(evidence: records["--rm3"]!, in: forensicCase)
        timings["rm3HistorySeconds"] = seconds(started.duration(to: clock.now))
        try write(optical, to: output.appendingPathComponent("rm3-history.json"))
        let opticalExports = try directory("rm3-exports", in: output)
        var opticalAnalyses: [String: DocumentAnalysis] = [:]
        var opticalReceipts: [UDFExportReceipt] = []
        for (index, entry) in optical.entries.enumerated() {
            let target = opticalExports.appendingPathComponent("payload-\(index)")
            let receipt = try await UDFInspector.export(entryID: entry.id, from: optical, in: forensicCase, to: target)
            opticalReceipts.append(receipt)
            opticalAnalyses[entry.id] = try await documents.analyze(.init(fileURL: target, expectedSHA256: entry.sha256, expectedByteCount: entry.byteCount))
        }
        try write(opticalReceipts, to: output.appendingPathComponent("rm3-export-receipts.json"))
        try write(opticalAnalyses.map { AnalysisRecord(key: $0.key, analysis: $0.value) }.sorted { $0.key < $1.key }, to: output.appendingPathComponent("rm3-documents.json"))
        _ = try UDFReportBuilder.exportMarkdown(result: optical, analyses: opticalAnalyses, in: forensicCase, to: output.appendingPathComponent("rm3-report.md"))
        print("RM3: \(optical.snapshots.count) VAT states, \(optical.entries.count) exact payload exports")

        let reopened = try CaseStore.open(at: forensicCase.bundleURL)
        guard reopened.manifest == forensicCase.manifest,
              try equivalent(EngineResultStore.load(evidenceID: records["--rm2"]!.id, in: reopened.bundleURL), filesystem),
              try equivalent(RecoveryResultStore.latest(evidenceID: records["--p2"]!.id, in: reopened.bundleURL), recovery),
              try equivalent(UDFInspector.loadLatest(in: reopened, evidenceID: records["--rm3"]!.id), optical) else { throw ProbeError.reopen }
        for record in reopened.manifest.evidence {
            let after = try await ImageInspector.inspect(url: URL(fileURLWithPath: record.sourcePath), progress: { _ in })
            guard after.sha256 == record.sha256, after.byteCount == record.byteCount else { throw ForensicsError.sourceChanged }
        }
        try write(timings, to: output.appendingPathComponent("timings.json"))
        try Data("Workflow completed; independent reference comparison required. Source bytes unchanged; all three result stores reopened exactly.\n".utf8)
            .write(to: output.appendingPathComponent("completed.txt"), options: .withoutOverwriting)
        print("Completed; source integrity and reopening passed")
    }

    private static func write<T: Encodable>(_ value: T, to url: URL) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(value).write(to: url, options: .withoutOverwriting)
    }
    private static func read<T: Decodable>(_ url: URL) throws -> T {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(T.self, from: Data(contentsOf: url))
    }
    /// Stores intentionally serialize application savedAt using ISO8601 seconds.
    /// Compare every serialized field instead of requiring unpersisted fractions.
    private static func equivalent<T: Encodable>(_ actual: T?, _ expected: T) throws -> Bool {
        guard let actual else { return false }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(actual) == encoder.encode(expected)
    }
    private static func directory(_ name: String, in parent: URL) throws -> URL {
        let result = parent.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return result
    }
    private static func seconds(_ duration: Duration) -> Double {
        Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
    }
    private struct AnalysisRecord: Codable { let key: String; let analysis: DocumentAnalysis }
    private enum ProbeError: Error { case arguments, destination, incomplete, reopen }
}
