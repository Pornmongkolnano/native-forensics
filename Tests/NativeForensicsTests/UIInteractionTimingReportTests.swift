import Darwin
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("UIInteractionTimingReportTests")
struct UIInteractionTimingReportTests {
    @Test("Opt-in report is a private bounded numeric receipt in a fresh owned file")
    func boundedPublication() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        let timing = UIInteractionTiming(enabled: true)
        for _ in 0..<300 {
            let trial = try #require(timing.begin())
            #expect(timing.record(.rowsPublished, trialID: trial))
            #expect(timing.finish(.published, trialID: trial))
        }
        let output = directory.output("bounded")
        #expect(timing.writeReport(to: output.path))
        let descriptor = Darwin.open(output.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try #require(descriptor >= 0)
        defer { Darwin.close(descriptor) }
        var state = stat()
        try #require(Darwin.fstat(descriptor, &state) == 0)
        #expect((state.st_mode & S_IFMT) == S_IFREG)
        #expect((state.st_mode & 0o7777) == 0o600)
        #expect(state.st_uid == Darwin.geteuid())
        #expect(state.st_size > 0 && state.st_size <= 1_048_576)
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let data = try #require(try file.readToEnd())
        #expect(data.count <= 1_048_576)
        let report = try JSONDecoder().decode(UIInteractionTraceReport.self, from: data)
        #expect(report.trials.count == 256 && report.evictedTrialCount == 44)
        #expect(report.trials.first?.id == 45 && report.trials.last?.id == 300)
        #expect(report.trials.allSatisfy { $0.outcome == .published && $0.stages.count == 2 })
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == ["trials", "evictedTrialCount", "rejectedMutationCount"])
        let trials = try #require(object["trials"] as? [[String: Any]])
        #expect(trials.allSatisfy { Set($0.keys) == ["id", "stages", "outcome", "completedUptimeSeconds"] })
    }

    @Test("Existing report cannot be replaced even on a repeated diagnostic write")
    func existingPreserved() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        let output = directory.output("existing"), sentinel = Data("synthetic sentinel".utf8)
        try sentinel.write(to: output)
        #expect(!UIInteractionTiming(enabled: true).writeReport(to: output.path))
        #expect(try Data(contentsOf: output) == sentinel)
    }

    @Test("A named symlink cannot redirect the fresh report publication")
    func outputSymlinkRejected() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        let target = directory.url.appendingPathComponent("sentinel"), output = directory.output("symlink")
        let sentinel = Data("synthetic target".utf8)
        try sentinel.write(to: target)
        #expect(Darwin.symlink(target.path, output.path) == 0)
        #expect(!UIInteractionTiming(enabled: true).writeReport(to: output.path))
        #expect(try Data(contentsOf: target) == sentinel)
        var state = stat()
        #expect(Darwin.lstat(output.path, &state) == 0 && (state.st_mode & S_IFMT) == S_IFLNK)
    }

    @Test("Symlinked and noncanonical parents are rejected without creating reports")
    func parentPathRejected() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        let actual = directory.url.appendingPathComponent("actual"), link = directory.url.appendingPathComponent("link")
        #expect(Darwin.mkdir(actual.path, 0o700) == 0)
        #expect(Darwin.symlink(actual.path, link.path) == 0)
        let name = ".nativeforensics-ui-timing-parent.json", timing = UIInteractionTiming(enabled: true)
        #expect(!timing.writeReport(to: link.appendingPathComponent(name).path))
        #expect(!timing.writeReport(to: directory.url.path + "/actual/../" + name))
        #expect(try FileManager.default.contentsOfDirectory(atPath: actual.path).isEmpty)
        #expect(!FileManager.default.fileExists(atPath: directory.url.appendingPathComponent(name).path))
    }

    @Test("Diagnostic output requires exact private permissions on its owned parent")
    func permissionsRejected() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        #expect(Darwin.chmod(directory.url.path, 0o750) == 0)
        let output = directory.output("permissions")
        #expect(!UIInteractionTiming(enabled: true).writeReport(to: output.path))
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    @Test("Disabled timing performs no writes even with an injected valid destination")
    func disabledDoesNotWrite() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        let timing = UIInteractionTiming(enabled: false), output = directory.output("disabled")
        #expect(timing.begin() == nil && timing.writeRequestedReport() == nil)
        #expect(!timing.writeReport(to: output.path))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path).isEmpty)
    }

    @Test("Only an absolute canonical bounded diagnostic filename is accepted")
    func filenamesRejected() throws {
        let directory = try TimingReportDirectory(); defer { directory.remove() }
        let timing = UIInteractionTiming(enabled: true)
        for name in ["report.json", ".nativeforensics-ui-timing-.json", ".nativeforensics-ui-timing-x.txt",
                     ".nativeforensics-ui-timing-query text.json", ".nativeforensics-ui-timing-ภาษา.json",
                     ".nativeforensics-ui-timing-" + String(repeating: "a", count: 200) + ".json"] {
            #expect(!timing.writeReport(to: directory.url.appendingPathComponent(name).path))
        }
        #expect(!timing.writeReport(to: ".nativeforensics-ui-timing-relative.json"))
        #expect(!timing.writeReport(to: directory.output("nul").path + "\0"))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path).isEmpty)
    }
}

private struct TimingReportDirectory {
    let url: URL
    init() throws {
        // macOS Foundation can preserve the /var alias even after resolution;
        // the production component-by-component no-follow gate rejects it.
        // Derive the canonical ignored parent from this source file; a fresh
        // checkout may not yet contain local/. Never chmod an existing base.
        let local = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("local", isDirectory: true).standardizedFileURL
        guard Darwin.mkdir(local.path, 0o700) == 0 || errno == EEXIST else {
            throw CocoaError(.fileWriteUnknown)
        }
        guard local.path == local.resolvingSymlinksInPath().path else {
            throw CocoaError(.fileWriteUnknown)
        }
        let baseDescriptor = try Self.openDirectoryWithoutFollowingLinks(local.path)
        defer { Darwin.close(baseDescriptor) }
        var baseState = stat()
        guard Darwin.fstat(baseDescriptor, &baseState) == 0, (baseState.st_mode & S_IFMT) == S_IFDIR,
              baseState.st_uid == Darwin.geteuid() else {
            throw CocoaError(.fileWriteUnknown)
        }
        let leaf = "nativeforensics-ui-report-test-" + UUID().uuidString
        url = local.appendingPathComponent(leaf, isDirectory: true)
        guard Darwin.mkdirat(baseDescriptor, leaf, 0o700) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
        var verified = false
        defer { if !verified { try? FileManager.default.removeItem(at: url) } }
        let descriptor = try Self.openDirectoryWithoutFollowingLinks(url.path)
        defer { Darwin.close(descriptor) }
        var state = stat()
        guard Darwin.fstat(descriptor, &state) == 0, (state.st_mode & S_IFMT) == S_IFDIR,
              state.st_uid == Darwin.geteuid(), Darwin.fchmod(descriptor, 0o700) == 0,
              Darwin.fstat(descriptor, &state) == 0, state.st_uid == Darwin.geteuid(),
              (state.st_mode & 0o7777) == 0o700 else {
            throw CocoaError(.fileWriteUnknown)
        }
        verified = true
    }

    private static func openDirectoryWithoutFollowingLinks(_ path: String) throws -> Int32 {
        var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw CocoaError(.fileReadUnknown) }
        for component in path.split(separator: "/") {
            let next = Darwin.openat(descriptor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            Darwin.close(descriptor)
            guard next >= 0 else { throw CocoaError(.fileReadUnknown) }
            descriptor = next
        }
        return descriptor
    }

    func output(_ name: String) -> URL { url.appendingPathComponent(".nativeforensics-ui-timing-" + name + ".json") }
    func remove() { try? FileManager.default.removeItem(at: url) }
}
