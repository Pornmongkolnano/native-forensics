import CryptoKit
import Darwin
import Foundation
import ForensicsCore

private struct QueryMeasurement: Codable, Sendable {
    let query: String
    let milliseconds: Double
    let count: Int
    let outputSHA256: String
}

private struct ScenarioMeasurement: Codable {
    let block: Int
    let mode: String
    let queries: [QueryMeasurement]
    let queryWorkMilliseconds: Double
    let elapsedIncludingEventPacingMilliseconds: Double
    let maximumMainActorHeartbeatGapMilliseconds: Double
    let heartbeatSamples: Int
}

private struct CancellationMeasurement: Codable {
    let cancelled: Bool
    let millisecondsAfterCancellation: Double
}

private struct Report: Codable {
    let schemaVersion: Int
    let generatedAt: Date
    let operatingSystem: String
    let locale: String
    let processorCount: Int
    let physicalMemoryBytes: UInt64
    let entryCount: Int
    let inputSHA256: String
    let expectedOutputSHA256: [String: String]
    let warmupBlocks: Int
    let measuredPairedBlocks: Int
    let requestedHeartbeatMilliseconds: Int
    let queryEventPacingMilliseconds: Int
    let scope: String
    let measurements: [ScenarioMeasurement]
    let cancellation: [CancellationMeasurement]
}

@MainActor
private final class Heartbeat {
    private let clock = ContinuousClock()
    private var last: ContinuousClock.Instant?
    private(set) var gaps: [Double] = []

    func sample() {
        let now = clock.now
        if let last { gaps.append(milliseconds(last.duration(to: now))) }
        last = now
    }
}

private actor SearchStarted {
    private var started = false
    private var waiter: CheckedContinuation<Void, Never>?

    func signal() {
        started = true
        waiter?.resume()
        waiter = nil
    }

    func wait() async {
        guard !started else { return }
        await withCheckedContinuation { waiter = $0 }
    }
}

@main
private struct FilesystemSearchBenchmark {
    @MainActor
    static func main() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.count == 2, arguments[0] == "--output" else {
            throw BenchmarkError.invalidArguments
        }
        let destination = URL(fileURLWithPath: arguments[1])
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw BenchmarkError.outputExists
        }
        let files = fixture()
        let index = FilesystemSearchIndex(files: files)
        let queries = ["", "HELLO.TXT", "หลักฐาน", "CAFÉ", "straße", "東京", "🔎",
                       String(repeating: "a", count: 256) + "x", "missing-file-no-match"]
        let expected = Dictionary(uniqueKeysWithValues: queries.map { ($0, baseline(files: files, query: $0)) })
        let expectedDigests = expected.mapValues { digestIDs($0) }

        // Warm both paths before the interleaved measured blocks. No warmup
        // timings enter the report. Output verification is outside timing.
        for mode in ["baseline-main-actor", "snapshot-background"] {
            _ = try await scenario(block: -1, mode: mode, files: files, index: index,
                                   queries: queries, expected: expected, digests: expectedDigests)
        }
        var measurements: [ScenarioMeasurement] = []
        for block in 0..<5 {
            let order = block.isMultiple(of: 2)
                ? ["baseline-main-actor", "snapshot-background"]
                : ["snapshot-background", "baseline-main-actor"]
            for mode in order {
                measurements.append(try await scenario(block: block, mode: mode, files: files, index: index,
                                                       queries: queries, expected: expected, digests: expectedDigests))
            }
        }

        var cancellation: [CancellationMeasurement] = []
        for _ in 0..<5 {
            let started = SearchStarted()
            let worker = Task.detached(priority: .userInitiated) {
                await started.signal()
                do {
                    _ = try index.rows(matching: "missing-file-no-match")
                    return false
                } catch is CancellationError { return true }
                catch { throw error }
            }
            await started.wait()
            try await Task.sleep(for: .milliseconds(5))
            let clock = ContinuousClock()
            let start = clock.now
            worker.cancel()
            let cancelled = try await worker.value
            cancellation.append(CancellationMeasurement(cancelled: cancelled,
                                                        millisecondsAfterCancellation: milliseconds(start.duration(to: clock.now))))
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let inputDigest = sha256(try encoder.encode(files))
        let report = Report(schemaVersion: 1, generatedAt: Date(),
                            operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString,
                            locale: Locale.current.identifier, processorCount: ProcessInfo.processInfo.processorCount,
                            physicalMemoryBytes: ProcessInfo.processInfo.physicalMemory,
                            entryCount: files.count, inputSHA256: inputDigest,
                            expectedOutputSHA256: expectedDigests, warmupBlocks: 1, measuredPairedBlocks: 5,
                            requestedHeartbeatMilliseconds: 2, queryEventPacingMilliseconds: 10,
                            scope: "Release/debug build as invoked. Fixed 50,000 generated records; exact Foundation path-match semantics. Each query's scan/result time is measured; input creation, digest/equivalence validation and 10 ms simulated input-event pacing are excluded from query work. MainActor heartbeat is a headless scheduling probe, not SwiftUI frame or table-rendering measurement. Background timing includes detached dispatch/await. Cancellation trials may complete before cancellation, reported explicitly. No source image I/O, hashing, engine, cache, debounce, or full-app memory measurement.",
                            measurements: measurements, cancellation: cancellation)
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(report).write(to: destination, options: .withoutOverwriting)
        print("Verified \(measurements.count) scenarios × \(queries.count) queries; report: \(destination.path)")
    }

    @MainActor
    private static func scenario(block: Int, mode: String, files: [FilesystemEntry], index: FilesystemSearchIndex,
                                 queries: [String], expected: [String: [FilesystemEntry]], digests: [String: String]) async throws -> ScenarioMeasurement {
        let heartbeat = Heartbeat()
        heartbeat.sample()
        let sampler = Task { @MainActor in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .milliseconds(2)) } catch { break }
                if !Task.isCancelled { heartbeat.sample() }
            }
        }
        defer { sampler.cancel() }
        try await Task.sleep(for: .milliseconds(10))
        let clock = ContinuousClock()
        let scenarioStart = clock.now
        var outputs: [[FilesystemEntry]] = []
        var queryMeasurements: [QueryMeasurement] = []
        for query in queries {
            let start = clock.now
            let rows: [FilesystemEntry]
            if mode == "baseline-main-actor" {
                rows = baseline(files: files, query: query)
            } else {
                rows = try await Task.detached(priority: .userInitiated) { try index.rows(matching: query) }.value
            }
            let elapsed = milliseconds(start.duration(to: clock.now))
            queryMeasurements.append(QueryMeasurement(query: query, milliseconds: elapsed, count: rows.count,
                                                      outputSHA256: digests[query]!))
            outputs.append(rows)
            // Simulate independent input events; this wait is not query work.
            try await Task.sleep(for: .milliseconds(10))
        }
        let elapsed = milliseconds(scenarioStart.duration(to: clock.now))
        heartbeat.sample()
        sampler.cancel()
        await sampler.value
        // Full row equality validates IDs, order and all metadata, outside time.
        for (query, rows) in zip(queries, outputs) {
            guard rows == expected[query] else { throw BenchmarkError.outputMismatch }
            guard digestIDs(rows) == digests[query] else { throw BenchmarkError.outputMismatch }
        }
        return ScenarioMeasurement(block: block, mode: mode, queries: queryMeasurements,
                                   queryWorkMilliseconds: queryMeasurements.reduce(0) { $0 + $1.milliseconds },
                                   elapsedIncludingEventPacingMilliseconds: elapsed,
                                   maximumMainActorHeartbeatGapMilliseconds: heartbeat.gaps.max() ?? 0,
                                   heartbeatSamples: heartbeat.gaps.count)
    }

    private static func baseline(files: [FilesystemEntry], query: String) -> [FilesystemEntry] {
        query.isEmpty ? Array(files.prefix(50_000))
            : Array(files.lazy.filter { $0.path.localizedCaseInsensitiveContains(query) }.prefix(50_000))
    }

    private static func fixture() -> [FilesystemEntry] {
        let names = ["HELLO.txt", "หลักฐาน.txt", "café-évidence.txt", "cafe\u{301}.txt",
                     "Straße.txt", "東京.txt", "🔎-evidence.txt", String(repeating: "a", count: 256) + ".bin"]
        return (0..<50_000).map { offset in
            let name = names[offset % names.count]
            return FilesystemEntry(id: "entry-\(offset)", path: "/folder-\(offset % 97)/\(offset)/\(name)",
                                   name: name, fsOffsetBytes: 4096, metaAddress: UInt64(offset), size: Int64(offset * 7),
                                   isDirectory: offset.isMultiple(of: 13), isDeleted: offset.isMultiple(of: 19),
                                   modifiedEpoch: 1_700_000_000 + Int64(offset), modifiedNanoseconds: 123_456_789)
        }
    }
}

private func milliseconds(_ duration: Duration) -> Double {
    let parts = duration.components
    return Double(parts.seconds) * 1_000 + Double(parts.attoseconds) / 1e15
}

private func digestIDs(_ files: [FilesystemEntry]) -> String {
    sha256(Data(files.map(\.id).joined(separator: "\n").utf8))
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private enum BenchmarkError: Error {
    case invalidArguments, outputExists, outputMismatch
}
