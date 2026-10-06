import Foundation
import ForensicsCore

/// A development benchmark of the application's create/inspect/analyze/save
/// path, without panels, SwiftUI rendering or ingest modules.
@main
struct ForensicsPipelineBenchmark {
    static func main() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let allowed = Set(["--image", "--helper", "--case-base", "--report"])
        guard arguments.count == 8 else { throw ProbeError.arguments }
        var options: [String: String] = [:]
        for index in stride(from: 0, to: arguments.count, by: 2) {
            let key = arguments[index]
            guard allowed.contains(key), options[key] == nil else { throw ProbeError.arguments }
            options[key] = arguments[index + 1]
        }
        guard let imagePath = options["--image"], let helperPath = options["--helper"],
              let basePath = options["--case-base"], let reportPath = options["--report"] else {
            throw ProbeError.arguments
        }
        let source = URL(fileURLWithPath: imagePath)
        let base = URL(fileURLWithPath: basePath)
        let reportURL = URL(fileURLWithPath: reportPath)
        let local = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("local", isDirectory: true).resolvingSymlinksInPath().path + "/"
        guard base.resolvingSymlinksInPath().path.hasPrefix(local),
              reportURL.resolvingSymlinksInPath().path.hasPrefix(local),
              !FileManager.default.fileExists(atPath: reportURL.path) else { throw ProbeError.destination }
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false)
        let clock = ContinuousClock()
        let started = clock.now
        var stages: [String: Double] = [:]
        var stageStart = clock.now
        let forensicCase = try CaseStore.create(name: "Pipeline", in: base)
        stages["caseCreateMilliseconds"] = ms(stageStart.duration(to: clock.now))
        stageStart = clock.now
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let recordedCase = try CaseStore.adding(image: inspected, to: forensicCase)
        guard let evidence = recordedCase.manifest.evidence.first else { throw ProbeError.result }
        stages["selectedFileInspectionAndManifestMilliseconds"] = ms(stageStart.duration(to: clock.now))
        // WorkspaceFilesystemStore verifies the recorded file before and after
        // EngineClient enumeration. Keep both checks and the logical hash.
        stageStart = clock.now
        try await verify(source, hash: evidence.sha256, size: evidence.byteCount)
        stages["sourceVerificationBeforeMilliseconds"] = ms(stageStart.duration(to: clock.now))
        stageStart = clock.now
        let result = try await EngineClient(helperURL: URL(fileURLWithPath: helperPath))
            .enumerate(imageURL: source, options: EngineOptions(timezone: "UTC"))
        guard result.status == .completed, result.warnings.isEmpty else { throw ProbeError.result }
        stages["clientEnumerationMilliseconds"] = ms(stageStart.duration(to: clock.now))
        stageStart = clock.now
        try await verify(source, hash: evidence.sha256, size: evidence.byteCount)
        stages["sourceVerificationAfterMilliseconds"] = ms(stageStart.duration(to: clock.now))
        stageStart = clock.now
        try EngineResultStore.save(result: result, evidenceID: evidence.id, in: recordedCase.bundleURL)
        stages["resultPublicationMilliseconds"] = ms(stageStart.duration(to: clock.now))
        let pipelineMilliseconds = ms(started.duration(to: clock.now))
        let report = Report(schemaVersion: 1, status: "completed", scope: "NativeForensics application core create/inspect/analyze/save workflow. Default source checks and logical hashing retained. SwiftUI, panels and export excluded.",
                            casePath: recordedCase.bundleURL.path, cachePath: recordedCase.bundleURL
                                .appendingPathComponent("filesystem/\(evidence.id.uuidString.lowercased()).json").path,
                            selectedFileSHA256: evidence.sha256, pipelineMilliseconds: pipelineMilliseconds,
                            stageMilliseconds: stages, entryCount: result.files.count, engineVersion: result.engineVersion)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(report).write(to: reportURL, options: .withoutOverwriting)
        print("Completed native core pipeline: \(result.files.count) entries")
    }

    private static func verify(_ source: URL, hash: String, size: Int64) async throws {
        let checked = try await ImageInspector.inspect(url: source, progress: { _ in })
        guard checked.sha256 == hash, checked.byteCount == size else { throw ForensicsError.sourceChanged }
    }

    private static func ms(_ duration: Duration) -> Double {
        Double(duration.components.seconds) * 1000 + Double(duration.components.attoseconds) / 1e15
    }

    private struct Report: Codable {
        let schemaVersion: Int
        let status: String
        let scope: String
        let casePath: String
        let cachePath: String
        let selectedFileSHA256: String
        let pipelineMilliseconds: Double
        let stageMilliseconds: [String: Double]
        let entryCount: Int
        let engineVersion: String
    }

    private enum ProbeError: Error { case arguments, destination, result }
}
