import CryptoKit
import Darwin
import Foundation

public struct TimelineExportReceipt: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let destinationPath: String
    public let snapshotSHA256: String
    public let eventCount: Int
    public let jsonSHA256: String
    public let markdownSHA256: String
    public let artifactReceipts: [TimelineArtifactReceipt]
}

public enum TimelineReportExporter {
    /// Publishes all reports together into a NEW directory. Existing outputs,
    /// evidence paths and case bundles are never replaced.
    public static func export(_ report: TimelineReport, to destination: URL, forbiddenURLs: [URL]) async throws -> TimelineExportReceipt {
        let worker = Task.detached(priority: .userInitiated) {
            try synchronous(report, destination: destination, forbiddenURLs: forbiddenURLs)
        }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }

    private static func synchronous(_ report: TimelineReport, destination: URL, forbiddenURLs: [URL]) throws -> TimelineExportReceipt {
        try validate(report)
        let json = try TimelineCoding.encode(report)
        guard json.count <= TimelineLimits.maximumReportBytes else { throw TimelineError.limitExceeded("Timeline JSON exceeds 64 MiB.") }
        let markdown = try markdown(report)
        try Task.checkCancellation()
        let output = try TimelineReportTransaction(destination: destination, forbiddenURLs: forbiddenURLs)
        defer { output.cleanup() }
        let receipt = TimelineExportReceipt(schemaVersion: 1, destinationPath: destination.standardizedFileURL.path,
            snapshotSHA256: report.binding.snapshotSHA256, eventCount: report.events.count,
            jsonSHA256: TimelineCoding.hex(SHA256.hash(data: json)), markdownSHA256: TimelineCoding.hex(SHA256.hash(data: markdown)), artifactReceipts: report.artifactReceipts)
        try output.write(json, name: "timeline.json")
        try output.write(markdown, name: "timeline.md")
        // Runtime destination paths are not placed into the shareable report receipt.
        struct ShareableReceipt: Encodable {
            let schemaVersion = 1
            let snapshotSHA256: String; let eventCount: Int
            let jsonSHA256: String; let markdownSHA256: String
            let artifactReceipts: [TimelineArtifactReceipt]
        }
        try output.write(TimelineCoding.encode(ShareableReceipt(snapshotSHA256: receipt.snapshotSHA256, eventCount: receipt.eventCount,
            jsonSHA256: receipt.jsonSHA256, markdownSHA256: receipt.markdownSHA256, artifactReceipts: receipt.artifactReceipts)), name: "receipt.json")
        try Task.checkCancellation(); try output.publish()
        return receipt
    }

    public static func validate(_ report: TimelineReport) throws {
        try report.binding.validate()
        guard report.schemaVersion == 1, report.parserVersion == "timeline.v1",
              report.events.count <= TimelineLimits.maximumFilesystemEvents + TimelineLimits.maximumBrowserEvents,
              Set(report.events.map(\.id)).count == report.events.count,
              report.warnings.count <= 128, report.warnings.allSatisfy({ EngineValidation.text($0, maximum: 4096) }),
              EngineValidation.text(report.coverage, maximum: 4096),
              report.examinerNotes.utf8.count <= TimelineLimits.maximumNotesBytes,
              (report.aiInterpretation?.utf8.count ?? 0) <= TimelineLimits.maximumNotesBytes,
              report.artifactReceipts.count <= 3,
              Set(report.artifactReceipts.map(\.role)).count == report.artifactReceipts.count else {
            throw TimelineError.invalidInput("Invalid timeline report, duplicate events or oversized notes.")
        }
        var estimated = 4096 + report.examinerNotes.utf8.count * 6 + (report.aiInterpretation?.utf8.count ?? 0) * 6
        for file in report.artifactReceipts {
            guard ["database", "wal", "shm"].contains(file.role), file.byteCount >= 0, file.byteCount <= 64 * 1_048_576,
                  EngineValidation.validHash(file.sha256), EngineValidation.text(file.fileID, maximum: 1024),
                  EngineValidation.text(file.evidencePath), file.evidencePath.hasPrefix("/") else { throw TimelineError.invalidInput("Invalid artifact receipt.") }
        }
        let hashes = Set(report.artifactReceipts.map(\.sha256))
        for event in report.events {
            try Task.checkCancellation()
            guard EngineValidation.validHash(event.id), EngineValidation.text(event.fileID, maximum: 1024),
                  event.evidencePath.hasPrefix("/"), EngineValidation.text(event.evidencePath),
                  EngineValidation.text(event.title, maximum: 4096, allowEmpty: true),
                  EngineValidation.text(event.detail, maximum: 16_384, allowEmpty: true),
                  EngineValidation.text(event.parser, maximum: 128), EngineValidation.text(event.recordID, maximum: 1024),
                  event.artifactSHA256.map({ hashes.contains($0) }) ?? true,
                  (0..<1_000_000_000).contains(event.timestamp.nanoseconds),
                  EngineValidation.text(event.timestamp.rawValue, maximum: 4096, allowEmpty: true),
                  EngineValidation.text(event.timestamp.precision, maximum: 256),
                  EngineValidation.text(event.timestamp.interpretation, maximum: 128),
                  (event.timestamp.timezoneAssumption?.utf8.count ?? 0) <= 1024,
                  event.timestamp.alternativeEpochSeconds.count <= 2,
                  event.timestamp.epochSeconds.map({ (0...253_402_300_799).contains($0) }) ?? true else {
                throw TimelineError.invalidInput("Invalid timeline event or timestamp provenance.")
            }
            let addition = (event.title.utf8.count + event.detail.utf8.count + event.evidencePath.utf8.count + event.fileID.utf8.count + event.timestamp.rawValue.utf8.count) * 6 + 2048
            guard addition <= TimelineLimits.maximumReportBytes - estimated else { throw TimelineError.limitExceeded("Timeline report exceeds the 64 MiB output budget.") }
            estimated += addition
        }
    }

    public static func markdown(_ report: TimelineReport) throws -> Data {
        try validate(report)
        var bytes = Data()
        func add(_ text: String) throws {
            let chunk = Data(text.utf8)
            guard chunk.count <= TimelineLimits.maximumReportBytes - bytes.count else { throw TimelineError.limitExceeded("Timeline Markdown exceeds 64 MiB.") }
            bytes.append(chunk)
        }
        func cell(_ text: String) -> String {
            text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "|", with: "\\|")
                .replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
                .replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        }
        try add("# NativeForensics timeline\n\n## Provenance and coverage\n\nCase: \(report.binding.caseID.uuidString)\n\nEvidence: \(report.binding.evidenceID.uuidString)\n\nRecorded snapshot SHA-256: \(report.binding.snapshotSHA256)\n\nEngine: \(cell(report.binding.engineVersion)); selected timezone: \(cell(report.binding.engineTimezone)); status: \(report.binding.listingStatus.rawValue); historical: \(report.binding.historical).\n\n\(cell(report.coverage))\n\nContainer hashes describe selected file bytes in recorded input order:\n\n")
        for (index, hash) in report.binding.orderedContainerSHA256.enumerated() { try add("- \(index): \(hash)\n") }
        if let logical = report.binding.logicalImageSHA256 { try add("\nLogical-image bytes SHA-256: \(logical)\n") }
        for file in report.artifactReceipts { try add("\nArtifact \(file.role): \(cell(file.evidencePath)); \(file.byteCount) extracted bytes; SHA-256 \(file.sha256).\n") }
        try add("\n## Limits and assumptions\n\n")
        for warning in report.warnings { try add("- \(cell(warning))\n") }
        try add("\n## Deterministic parser observations\n\nUTC epoch seconds/nanoseconds are normalized values; raw timestamp and assumptions remain explicit. Unresolved local times have no normalized instant.\n\n| Epoch seconds | Nanoseconds | Kind | Entry state | Evidence path | Record | Raw timestamp | Precision | Assumption / interpretation | Observation |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for event in report.events {
            try Task.checkCancellation()
            try add("| \(event.timestamp.epochSeconds.map(String.init) ?? "unresolved") | \(event.timestamp.nanoseconds) | \(event.kind.rawValue) | \(event.isDeleted ? "deleted entry; deletion time unknown" : "allocated / recorded") | \(cell(event.evidencePath)) | \(cell(event.recordID)) | \(cell(event.timestamp.rawValue)) | \(cell(event.timestamp.precision)) | \(cell(event.timestamp.timezoneAssumption ?? "none")) / \(cell(event.timestamp.interpretation)) | \(cell(event.title + " — " + event.detail)) |\n")
        }
        try add("\n## AI interpretation (unverified)\n\n")
        try add(cell(report.aiInterpretation ?? "No AI interpretation was included.") + "\n")
        try add("\n## Examiner notes\n\n" + cell(report.examinerNotes.isEmpty ? "No examiner notes were included." : report.examinerNotes) + "\n")
        return bytes
    }
}

private final class TimelineReportTransaction {
    private let parentURL: URL
    private let parent: Int32
    private let root: Int32
    private let stagedURL: URL
    private let stage: String
    private let destination: URL
    private var files: [String: SourceIdentity] = [:]
    private var expectedHashes: [String: String] = [:]
    private var published = false
    private var cleaned = false
    init(destination: URL, forbiddenURLs: [URL]) throws {
        guard destination.isFileURL, destination.host == nil || destination.host == "" || destination.host == "localhost",
              destination.query == nil, destination.fragment == nil,
              !destination.path.utf8.contains(0), !destination.lastPathComponent.isEmpty else { throw TimelineError.invalidInput("Choose a new local report folder.") }
        let requested = destination.standardizedFileURL
        // NSOpenPanel may retain URL representation/resource hints. Filesystem
        // paths decide alias equivalence; parent/root ownership is then pinned
        // with O_NOFOLLOW descriptors and revalidated before publication.
        guard requested.path == requested.resolvingSymlinksInPath().path,
              !requested.pathComponents.contains("..") else {
            throw TimelineError.invalidInput("The report destination resolves through a filesystem alias. Select its real parent folder, without symlinks.")
        }
        for forbidden in forbiddenURLs {
            let protected = forbidden.standardizedFileURL
            if FileAccess.isInside(requested, directory: protected) || FileAccess.isInside(protected, directory: requested) {
                throw TimelineError.invalidInput(protected.pathExtension == "nativecase"
                    ? "The report destination overlaps the case bundle. Select a separate parent folder."
                    : "The report destination overlaps an evidence source. Select a separate parent folder.")
            }
        }
        guard !requested.pathComponents.contains(where: { $0.hasSuffix(".nativecase") }) else {
            throw TimelineError.invalidInput("The report destination is nested inside a .nativecase bundle. Select a separate parent folder.")
        }
        self.destination = requested; parentURL = requested.deletingLastPathComponent()
        parent = try EvidenceViewFiles.openDirectory(parentURL)
        stage = ".timeline-report-\(UUID().uuidString.lowercased())"
        stagedURL = parentURL.appendingPathComponent(stage, isDirectory: true)
        guard Darwin.mkdirat(parent, stage, 0o700) == 0 else { let error = FileAccess.posixError("Create timeline report staging"); Darwin.close(parent); throw error }
        let descriptor = Darwin.openat(parent, stage, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { let error = FileAccess.posixError("Open timeline report staging"); Darwin.close(parent); throw error }
        root = descriptor
    }
    func write(_ data: Data, name: String) throws {
        try validate()
        let fd = Darwin.openat(root, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw FileAccess.posixError("Create timeline report") }
        defer { Darwin.close(fd) }
        // Claim the actual descriptor immediately; failure cleanup must not rely
        // on a later successful write or a replacement path.
        files[name] = try FileAccess.identity(of: fd)
        var offset = 0
        do {
            while offset < data.count {
                try Task.checkCancellation()
                let count = data.withUnsafeBytes { raw in Darwin.write(fd, raw.baseAddress!.advanced(by: offset), min(65_536, data.count - offset)) }
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Write timeline report") }
                offset += count
            }
            guard Darwin.fsync(fd) == 0 else { throw FileAccess.posixError("Sync timeline report") }
        } catch { files[name] = try? FileAccess.identity(of: fd); throw error }
        files[name] = try FileAccess.identity(of: fd)
        expectedHashes[name] = TimelineCoding.hex(SHA256.hash(data: data))
        try validate()
    }
    func validate() throws {
        try EvidenceViewFiles.validateDirectory(parentURL, descriptor: parent)
        try EvidenceViewFiles.validateDirectory(stagedURL, descriptor: root)
        for (name, identity) in files { guard (try? FileAccess.identity(at: name, in: root)) == identity else { throw TimelineError.publication("Timeline report staging changed.") } }
    }
    func publish() throws {
        try validate()
        guard files.count == 3, expectedHashes.count == 3 else { throw TimelineError.publication("Timeline report is incomplete.") }
        for (name, identity) in files {
            let descriptor = try FileAccess.openReadOnly(name, in: root)
            defer { Darwin.close(descriptor) }
            guard try FileAccess.identity(of: descriptor) == identity else { throw TimelineError.publication("Timeline report output changed before verification.") }
            var hasher = SHA256(), remaining = identity.size
            var buffer = [UInt8](repeating: 0, count: 65_536)
            while remaining > 0 {
                try Task.checkCancellation()
                let wanted = Int(min(remaining, Int64(buffer.count)))
                let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: wanted) }
                guard count > 0 else { throw TimelineError.publication("Timeline report output is incomplete.") }
                hasher.update(data: Data(buffer.prefix(count))); remaining -= Int64(count)
            }
            guard TimelineCoding.hex(hasher.finalize()) == expectedHashes[name],
                  try FileAccess.identity(of: descriptor) == identity else { throw TimelineError.publication("Timeline report output failed independent byte verification.") }
        }
        let duplicate = Darwin.dup(root)
        guard duplicate >= 0, let listing = Darwin.fdopendir(duplicate) else {
            if duplicate >= 0 { Darwin.close(duplicate) }; throw FileAccess.posixError("Read timeline staging directory")
        }
        var names = Set<String>(), unexpected = false, readError: Int32 = 0
        while true {
            errno = 0
            guard let entry = Darwin.readdir(listing) else { readError = errno; break }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in pointer.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) } }
            if name != ".", name != ".." {
                guard files[name] != nil, names.count < 3 else { unexpected = true; break }
                names.insert(name)
            }
        }
        Darwin.closedir(listing)
        guard !unexpected, readError == 0, names == Set(files.keys) else { throw TimelineError.publication("Unexpected files or directory read failure in timeline staging.") }
        try validate(); try Task.checkCancellation()
        guard Darwin.fsync(root) == 0 else { throw FileAccess.posixError("Sync timeline report folder") }
        guard Darwin.renameatx_np(parent, stage, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else { throw FileAccess.posixError("Publish new timeline report folder") }
        published = true
        // Do not mask a completed commit with late cancellation.
    }
    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        if !published {
            for (name, identity) in files where (try? FileAccess.identity(at: name, in: root)) == identity { _ = Darwin.unlinkat(root, name, 0) }
            if (try? EvidenceViewFiles.validateDirectory(stagedURL, descriptor: root)) != nil { _ = Darwin.unlinkat(parent, stage, AT_REMOVEDIR) }
        }
        Darwin.close(root); Darwin.close(parent)
    }
    deinit { cleanup() }
}
