import CryptoKit
import Foundation
import Darwin
import ForensicsCore
import Testing

/// These admission tests require Root's freshly built opt-in executable. An
/// absent environment flag is an explicit skip, not execution evidence.
@Suite("GUI history population argument and scope admission", .serialized)
struct CaseHistoryGUIPopulationTests {
    @Test("Malformed population arguments fail before opening a case",
          .enabled(if: ProcessInfo.processInfo.environment["NF_CASE_HISTORY_GUI_PROBE"] != nil),
          arguments: Array(0..<12))
    func malformedArguments(_ index: Int) throws {
        var arguments = Self.arguments(caseURL: URL(fileURLWithPath: "/not-opened.nativecase"),
            caseID: UUID(), evidenceID: UUID())
        switch index {
        case 0: arguments.removeLast()
        case 1: arguments[3] = "relative.nativecase"
        case 2: arguments[3] = "/not-opened"
        case 3: arguments[5] = "not-a-uuid"
        case 4: arguments[7] = "not-a-uuid"
        case 5: arguments[9] = ""
        case 6: arguments[11] = "0"
        case 7: arguments[11] = "1001"
        case 8: arguments[13] = "0"
        case 9: arguments[13] = "900001"
        case 10: arguments[11] = "+120"
        default: arguments.append(contentsOf: ["--force", "yes"])
        }
        let outcome = try Self.run(arguments)
        #expect(outcome.reason == .exit)
        #expect(outcome.code == 1)
        #expect(outcome.stdout.isEmpty)
        #expect(outcome.stderr.contains("invalidGUIArguments"))
    }

    @Test("An exact target-case ID is required before fixture publication",
          .enabled(if: ProcessInfo.processInfo.environment["NF_CASE_HISTORY_GUI_PROBE"] != nil))
    func wrongCase() async throws {
        let fixture = try await ScopeFixture.make()
        defer { fixture.remove() }
        let before = try Self.snapshot(fixture)
        let manifest = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        let outcome = try Self.run(Self.arguments(caseURL: fixture.caseURL, caseID: UUID(), evidenceID: fixture.evidence.id))
        #expect(outcome.reason == .exit)
        #expect(outcome.code == 1)
        #expect(outcome.stderr.contains("caseMismatch"))
        let after = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        #expect(after == manifest)
        #expect(!FileManager.default.fileExists(atPath: fixture.caseURL.appendingPathComponent("analyses").path))
        let final = try Self.snapshot(fixture)
        #expect(final == before)
    }

    @Test("A source ID from another scope cannot acquire a record binding",
          .enabled(if: ProcessInfo.processInfo.environment["NF_CASE_HISTORY_GUI_PROBE"] != nil))
    func wrongEvidence() async throws {
        let fixture = try await ScopeFixture.make()
        defer { fixture.remove() }
        let before = try Self.snapshot(fixture)
        let source = try Data(contentsOf: fixture.source)
        let outcome = try Self.run(Self.arguments(caseURL: fixture.caseURL,
            caseID: fixture.forensicCase.manifest.id, evidenceID: UUID()))
        #expect(outcome.reason == .exit)
        #expect(outcome.code == 1)
        #expect(outcome.stderr.contains("evidenceMissing"))
        let after = try Data(contentsOf: fixture.source)
        #expect(after == source)
        #expect(!FileManager.default.fileExists(atPath: fixture.caseURL.appendingPathComponent("analyses").path))
        let final = try Self.snapshot(fixture)
        #expect(final == before)
    }

    @Test("An unenumerated source is not turned into a fabricated GUI selection",
          .enabled(if: ProcessInfo.processInfo.environment["NF_CASE_HISTORY_GUI_PROBE"] != nil))
    func absentListing() async throws {
        let fixture = try await ScopeFixture.make()
        defer { fixture.remove() }
        let before = try Self.snapshot(fixture)
        let manifest = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        let outcome = try Self.run(Self.arguments(caseURL: fixture.caseURL,
            caseID: fixture.forensicCase.manifest.id, evidenceID: fixture.evidence.id))
        #expect(outcome.reason == .exit)
        #expect(outcome.code == 1)
        #expect(outcome.stderr.contains("missingCachedListing"))
        let after = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        #expect(after == manifest)
        #expect(!FileManager.default.fileExists(atPath: fixture.caseURL.appendingPathComponent("analyses").path))
        let final = try Self.snapshot(fixture)
        #expect(final == before)
    }

    @Test("The retained headless synthetic cache is explicitly ineligible",
          .enabled(if: ProcessInfo.processInfo.environment["NF_CASE_HISTORY_GUI_PROBE"] != nil))
    func syntheticListing() async throws {
        let fixture = try await ScopeFixture.make()
        defer { fixture.remove() }
        let source = try Data(contentsOf: fixture.source)
        let entry = FilesystemEntry(id: "0:1", path: "/SYNTHETIC.TXT", name: "SYNTHETIC.TXT",
            fsOffsetBytes: 0, metaAddress: 1, size: Int64(source.count), isDirectory: false, isDeleted: false)
        let result = EnumerationResult(engineVersion: "synthetic-history-oracle", patchDigest: "synthetic-only",
            sourcePaths: [fixture.source.path], sourceFileHashes: [fixture.source.path: fixture.evidence.sha256],
            options: EngineOptions(hashLogicalImage: false), image: .init(imageType: "raw", logicalSize: Int64(source.count), sectorSize: 512),
            volumes: [], files: [entry], warnings: [], status: .completed, savedAt: Date(timeIntervalSince1970: 1_700_000_000))
        try EngineResultStore.save(result: result, evidenceID: fixture.evidence.id, in: fixture.caseURL)
        let cacheURL = fixture.caseURL.appendingPathComponent("filesystem").appendingPathComponent(fixture.evidence.id.uuidString.lowercased() + ".json")
        let before = try Self.snapshot(fixture)
        let cache = try Data(contentsOf: cacheURL)
        let outcome = try Self.run(Self.arguments(caseURL: fixture.caseURL,
            caseID: fixture.forensicCase.manifest.id, evidenceID: fixture.evidence.id))
        #expect(outcome.reason == .exit)
        #expect(outcome.code == 1)
        #expect(outcome.stderr.contains("syntheticCachedListing"))
        let after = try Data(contentsOf: cacheURL)
        #expect(after == cache)
        #expect(!FileManager.default.fileExists(atPath: fixture.caseURL.appendingPathComponent("analyses").path))
        let final = try Self.snapshot(fixture)
        #expect(final == before)
    }

    private static func arguments(caseURL: URL, caseID: UUID, evidenceID: UUID) -> [String] {
        ["--mode", "populate-gui", "--case", caseURL.path, "--case-id", caseID.uuidString,
         "--evidence-id", evidenceID.uuidString, "--file-id", "0:1", "--records", "3", "--prompt-bytes", "128"]
    }

    private static func run(_ arguments: [String]) throws -> Outcome {
        guard let path = ProcessInfo.processInfo.environment["NF_CASE_HISTORY_GUI_PROBE"], !path.isEmpty else {
            throw FixtureError.missingExecutable
        }
        let process = Process(); process.executableURL = URL(fileURLWithPath: path); process.arguments = arguments
        let output = Pipe(); let errors = Pipe(); process.standardOutput = output; process.standardError = errors
        let terminal = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminal.signal() }
        try process.run()
        try? output.fileHandleForWriting.close(); try? errors.fileHandleForWriting.close()
        let group = DispatchGroup()
        let stdout = PipeCollector(output.fileHandleForReading)
        let stderr = PipeCollector(errors.fileHandleForReading)
        for collector in [stdout, stderr] {
            group.enter()
            DispatchQueue.global(qos: .utility).async { collector.drain(); group.leave() }
        }
        let timedOut = terminal.wait(timeout: .now() + 5) != .success
        if timedOut {
            // This is the directly spawned Process owner, not an arbitrary PID.
            process.terminate()
            if terminal.wait(timeout: .now() + 2) != .success {
                process.interrupt()
                guard terminal.wait(timeout: .now() + 2) == .success else {
                    cleanupState.retainUnconfirmed(process)
                    stdout.close(); stderr.close()
                    throw FixtureError.childCleanupUnconfirmed
                }
            }
        }
        // Called only after the natural/owned-termination event was received.
        process.waitUntilExit()
        guard group.wait(timeout: .now() + 2) == .success else {
            stdout.close(); stderr.close(); throw FixtureError.pipeDrainUnconfirmed
        }
        let out = stdout.snapshot(); let err = stderr.snapshot()
        guard !timedOut else { throw FixtureError.processTimedOut }
        guard !out.failed, !err.failed else { throw FixtureError.outputLimitOrReadError }
        return Outcome(code: process.terminationStatus, reason: process.terminationReason,
            stdout: out.data, stderr: String(decoding: err.data, as: UTF8.self))
    }
    private struct Outcome { let code: Int32; let reason: Process.TerminationReason; let stdout: Data; let stderr: String }
    private static let cleanupState = CleanupState()
    private final class CleanupState: @unchecked Sendable {
        private let lock = NSLock()
        private var unconfirmedOwners: [Process] = []
        func retainUnconfirmed(_ process: Process) {
            lock.lock(); unconfirmedOwners.append(process); lock.unlock()
        }
        var canRemoveFixtures: Bool {
            lock.lock(); defer { lock.unlock() }; return unconfirmedOwners.isEmpty
        }
    }
    private enum FixtureError: Error {
        case missingExecutable, missingEvidence, processTimedOut, childCleanupUnconfirmed
        case pipeDrainUnconfirmed, outputLimitOrReadError, unexpectedNamespaceEntry
    }
    private final class PipeCollector: @unchecked Sendable {
        private let handle: FileHandle
        private let lock = NSLock()
        private var data = Data()
        private var failed = false
        init(_ handle: FileHandle) { self.handle = handle }
        func drain() {
            do {
                while let chunk = try handle.read(upToCount: 4_096), !chunk.isEmpty {
                    lock.lock()
                    let remaining = max(0, 1_048_576 - data.count)
                    data.append(chunk.prefix(remaining))
                    if chunk.count > remaining { failed = true }
                    lock.unlock()
                    // Continue draining after the cap instead of blocking the child.
                }
            } catch { lock.lock(); failed = true; lock.unlock() }
        }
        func snapshot() -> (data: Data, failed: Bool) {
            lock.lock(); defer { lock.unlock() }; return (data, failed)
        }
        func close() { try? handle.close() }
    }
    private struct NamespaceSnapshot: Equatable { let entries: [String: Fingerprint]; let source: Fingerprint }
    private struct Fingerprint: Equatable { let identity: [String]; let sha256: String? }
    private static func snapshot(_ fixture: ScopeFixture) throws -> NamespaceSnapshot {
        var entries = [".": try fingerprint(fixture.caseURL)]
        guard let enumerator = FileManager.default.enumerator(at: fixture.caseURL, includingPropertiesForKeys: nil) else {
            throw FixtureError.unexpectedNamespaceEntry
        }
        for case let url as URL in enumerator {
            let relative = String(url.path.dropFirst(fixture.caseURL.path.count + 1))
            entries[relative] = try fingerprint(url)
        }
        return NamespaceSnapshot(entries: entries, source: try fingerprint(fixture.source))
    }
    private static func fingerprint(_ url: URL) throws -> Fingerprint {
        var info = stat()
        guard Darwin.lstat(url.path, &info) == 0,
              [S_IFREG, S_IFDIR].contains(info.st_mode & S_IFMT) else { throw FixtureError.unexpectedNamespaceEntry }
        let identity = [String(info.st_dev), String(info.st_ino), String(info.st_mode), String(info.st_uid),
            String(info.st_nlink), String(info.st_size), String(info.st_mtimespec.tv_sec), String(info.st_mtimespec.tv_nsec),
            String(info.st_ctimespec.tv_sec), String(info.st_ctimespec.tv_nsec)]
        // Access time is deliberately excluded: the comparison itself reads bytes.
        let sha = info.st_mode & S_IFMT == S_IFREG
            ? SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined() : nil
        return Fingerprint(identity: identity, sha256: sha)
    }

    private struct ScopeFixture {
        let directory: URL; let source: URL; let forensicCase: ForensicCase; let evidence: EvidenceRecord
        var caseURL: URL { forensicCase.bundleURL }
        static func make() async throws -> Self {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("CaseHistoryGUIScope-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            do {
                let source = directory.appendingPathComponent("owned-scope-source.dd")
                try Data("owned synthetic source\n".utf8).write(to: source, options: .withoutOverwriting)
                let created = try CaseStore.create(name: "GUI Population Scope", in: directory)
                let image = try await ImageInspector.inspect(url: source, progress: { _ in })
                let forensicCase = try CaseStore.adding(image: image, to: created)
                guard let evidence = forensicCase.manifest.evidence.first else { throw FixtureError.missingEvidence }
                let entry = FilesystemEntry(id: "0:1", path: "/SYNTHETIC.TXT", name: "SYNTHETIC.TXT",
                    fsOffsetBytes: 0, metaAddress: 1, size: evidence.byteCount, isDirectory: false, isDeleted: false)
                let model = EnumerationResult(engineVersion: "synthetic-scope-primer", patchDigest: "synthetic-only",
                    sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256],
                    options: EngineOptions(hashLogicalImage: false), image: .init(imageType: "raw", logicalSize: evidence.byteCount, sectorSize: 512),
                    volumes: [], files: [entry], warnings: [], status: .completed, savedAt: Date(timeIntervalSince1970: 1_700_000_000))
                let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: model, file: entry)
                _ = try CaseWorkStore.history(binding: binding, kind: .analysis, in: forensicCase.bundleURL)
                return Self(directory: directory, source: source, forensicCase: forensicCase, evidence: evidence)
            } catch { try? FileManager.default.removeItem(at: directory); throw error }
        }
        func remove() {
            // An unconfirmed directly owned child retains its Process and all
            // fixtures for manual review. Do not remove bytes under a live owner.
            guard CaseHistoryGUIPopulationTests.cleanupState.canRemoveFixtures else { return }
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
