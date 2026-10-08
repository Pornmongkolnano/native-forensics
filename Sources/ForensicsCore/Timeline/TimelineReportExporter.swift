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
    public let pdfSHA256: String?
    public let componentVersions: [String: String]?
    public let outputParameters: [String: String]?
    public let artifactReceipts: [TimelineArtifactReceipt]
}

public enum TimelineReportExporter {
    /// Publishes all reports together into a NEW directory. Existing outputs,
    /// evidence paths and case bundles are never replaced.
    public static func export(_ report: TimelineReport, to destination: URL, forbiddenURLs: [URL]) async throws -> TimelineExportReceipt {
        let requested = ForensicWorkExecutionContext.requestedPriority
        let worker = Task.detached(priority: ForensicWorkExecutionContext.requestedTaskPriority) {
            try ForensicWorkExecutionContext.$requestedPriority.withValue(requested) {
                try synchronous(report, destination: destination, forbiddenURLs: forbiddenURLs)
            }
        }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }

    private static func synchronous(_ report: TimelineReport, destination: URL, forbiddenURLs: [URL]) throws -> TimelineExportReceipt {
        try validate(report)
        let json = try TimelineCoding.encode(report)
        guard json.count <= TimelineLimits.maximumReportBytes else { throw TimelineError.limitExceeded("Timeline JSON exceeds 64 MiB.") }
        let markdown = try markdown(report)
        let pdf = try TimelinePDFRenderer.render(report)
        try Task.checkCancellation()
        let output = try TimelineReportTransaction(destination: destination, forbiddenURLs: forbiddenURLs)
        defer { output.cleanup() }
        let receipt = TimelineExportReceipt(schemaVersion: 1, destinationPath: destination.standardizedFileURL.path,
            snapshotSHA256: report.binding.snapshotSHA256, eventCount: report.events.count,
            jsonSHA256: TimelineCoding.hex(SHA256.hash(data: json)), markdownSHA256: TimelineCoding.hex(SHA256.hash(data: markdown)),
            pdfSHA256: TimelineCoding.hex(SHA256.hash(data: pdf)), componentVersions: ["timelineReport": report.parserVersion, "PDFRenderer": TimelinePDFRenderer.version],
            outputParameters: ["maximumReportBytes": String(TimelineLimits.maximumReportBytes), "maximumPDFPages": String(TimelinePDFRenderer.maximumPages),
                "filterPolicy": "complete report; presentation filters do not reduce exported events", "publication": "exclusive new directory; independently rehashed written bytes"], artifactReceipts: report.artifactReceipts)
        try output.write(json, name: "timeline.json")
        try output.write(markdown, name: "timeline.md")
        try output.write(pdf, name: "timeline.pdf")
        // Runtime destination paths are not placed into the shareable report receipt.
        struct ShareableReceipt: Encodable {
            let schemaVersion = 1
            let snapshotSHA256: String; let eventCount: Int
            let jsonSHA256: String; let markdownSHA256: String
            let pdfSHA256: String?
            let componentVersions: [String: String]?
            let outputParameters: [String: String]?
            let artifactReceipts: [TimelineArtifactReceipt]
        }
        try output.write(TimelineCoding.encode(ShareableReceipt(snapshotSHA256: receipt.snapshotSHA256, eventCount: receipt.eventCount,
            jsonSHA256: receipt.jsonSHA256, markdownSHA256: receipt.markdownSHA256, pdfSHA256: receipt.pdfSHA256,
            componentVersions: receipt.componentVersions, outputParameters: receipt.outputParameters,
            artifactReceipts: receipt.artifactReceipts)), name: "receipt.json")
        try Task.checkCancellation(); try output.publish()
        return receipt
    }

    public static func validate(_ report: TimelineReport) throws {
        try report.binding.validate()
        guard report.schemaVersion == 1, ["timeline.v1", "timeline.v2"].contains(report.parserVersion),
              report.events.count <= TimelineLimits.maximumFilesystemEvents + TimelineLimits.maximumBrowserEvents + TimelineLimits.maximumSyslogEvents,
              Set(report.events.map(\.id)).count == report.events.count,
              report.warnings.count <= 128, report.warnings.allSatisfy({ EngineValidation.text($0, maximum: 4096) }),
              EngineValidation.text(report.coverage, maximum: 4096),
              report.examinerNotes.utf8.count <= TimelineLimits.maximumNotesBytes,
              (report.aiInterpretation?.utf8.count ?? 0) <= TimelineLimits.maximumNotesBytes,
              report.artifactReceipts.count <= 4,
              Set(report.artifactReceipts.map(\.role)).count == report.artifactReceipts.count else {
            throw TimelineError.invalidInput("Invalid timeline report, duplicate events or oversized notes.")
        }
        var estimated = 4096 + report.examinerNotes.utf8.count * 6 + (report.aiInterpretation?.utf8.count ?? 0) * 6
        for file in report.artifactReceipts {
            guard ["database", "wal", "shm", "syslog"].contains(file.role), file.byteCount >= 0, file.byteCount <= 64 * 1_048_576,
                  file.hashScope == nil || file.hashScope == "extracted-file-bytes",
                  EngineValidation.validHash(file.sha256), EngineValidation.text(file.fileID, maximum: 1024),
                  EngineValidation.text(file.evidencePath), file.evidencePath.hasPrefix("/") else { throw TimelineError.invalidInput("Invalid artifact receipt.") }
            if file.role == "syslog", file.byteCount > TimelineLimits.maximumSyslogBytes { throw TimelineError.invalidInput("Syslog receipt exceeds its byte bound.") }
        }
        let hashes = Set(report.artifactReceipts.map(\.sha256))
        if let receipts = report.parserReceipts {
            guard receipts.count <= 8 else { throw TimelineError.invalidInput("Too many timeline parser receipts.") }
            for receipt in receipts {
                guard EngineValidation.text(receipt.parser, maximum: 128), EngineValidation.text(receipt.version, maximum: 128),
                      receipt.parameters.count <= 32,
                      receipt.parameters.allSatisfy({ EngineValidation.text($0.key, maximum: 128) && EngineValidation.text($0.value, maximum: 4096, allowEmpty: true) }),
                      receipt.sourceSHA256.map({ hashes.contains($0) }) ?? true,
                      receipt.derivedTextSHA256.map(EngineValidation.validHash) ?? true,
                      receipt.sourceHashScope == nil || (receipt.sourceHashScope == "extracted-file-bytes" && receipt.sourceSHA256 != nil),
                      receipt.derivedTextHashScope == nil || (receipt.derivedTextHashScope == "derived-utf8-text-bytes" && receipt.derivedTextSHA256 != nil),
                      (receipt.unitCount.map { (1...200).contains($0) } ?? true),
                      (receipt.lineCount.map { (0...1_048_576).contains($0) } ?? true),
                      receipt.eventCount >= 0, receipt.eventCount <= report.events.count else { throw TimelineError.invalidInput("Invalid parser parameters or text provenance.") }
            }
        }
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
                  event.timestamp.alternativeEpochSeconds.allSatisfy({ (0...253_402_300_799).contains($0) }),
                  event.timestamp.epochSeconds.map({ (0...253_402_300_799).contains($0) }) ?? true else {
                throw TimelineError.invalidInput("Invalid timeline event or timestamp provenance.")
            }
            if let pointer = event.sourceReference {
                let artifact = report.artifactReceipts.first { $0.role == "syslog" && $0.fileID == event.fileID && $0.evidencePath == event.evidencePath && $0.sha256 == event.artifactSHA256 }
                guard event.kind == .syslogRecord, event.artifactSHA256 != nil,
                      EngineValidation.validHash(pointer.derivedTextSHA256), pointer.unit == 1,
                      pointer.unitKind == "raw-utf8-document", pointer.line > 0, pointer.line <= 1_048_576,
                      pointer.utf8Offset >= 0, pointer.utf8Length >= 0, pointer.utf8Length <= TimelineLimits.maximumSyslogLineBytes,
                      pointer.utf8Offset <= TimelineLimits.maximumSyslogBytes - pointer.utf8Length,
                      artifact.map({ Int64(pointer.utf8Offset + pointer.utf8Length) <= $0.byteCount }) == true,
                      report.parserReceipts?.contains(where: { $0.derivedTextSHA256 == pointer.derivedTextSHA256 && $0.sourceSHA256 == event.artifactSHA256
                          && $0.parser == "syslog-record" && $0.unitCount == 1 && ($0.lineCount.map { pointer.line <= $0 } ?? false) }) == true else {
                    throw TimelineError.invalidInput("Invalid syslog text source pointer.")
                }
            } else if event.kind == .syslogRecord { throw TimelineError.invalidInput("Syslog event has no source line reference.") }
            if let native = event.filesystemTimestamp {
                guard [.filesystemCreated, .filesystemModified, .filesystemAccessed].contains(event.kind) else { throw TimelineError.invalidInput("Civil filesystem timestamp is attached to a non-filesystem event.") }
                let expected = try TimelineTimestamp.filesystem(native, epoch: event.timestamp.epochSeconds, nanos: event.timestamp.nanoseconds)
                guard expected == event.timestamp else { throw TimelineError.invalidInput("Filesystem timestamp interpretation contradicts its raw fields.") }
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
                .replacingOccurrences(of: "[", with: "\\[").replacingOccurrences(of: "]", with: "\\]")
                .replacingOccurrences(of: "`", with: "\\`")
                .replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
                .replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        }
        try add("# NativeForensics timeline\n\n## Provenance and coverage\n\nCase: \(report.binding.caseID.uuidString)\n\nEvidence: \(report.binding.evidenceID.uuidString)\n\nRecorded snapshot SHA-256: \(report.binding.snapshotSHA256)\n\nEngine: \(cell(report.binding.engineVersion)); selected timezone: \(cell(report.binding.engineTimezone)); status: \(report.binding.listingStatus.rawValue); historical: \(report.binding.historical).\n\n\(cell(report.coverage))\n\nContainer hashes describe selected file bytes in recorded input order:\n\n")
        for (index, hash) in report.binding.orderedContainerSHA256.enumerated() { try add("- \(index): \(hash)\n") }
        if let scopes = report.binding.hashScopes {
            for key in scopes.keys.sorted() { try add("- Hash scope \(cell(key)): \(cell(scopes[key]!))\n") }
        } else { try add("\nHistorical binding: an explicit encoded hash-scope map was not retained.\n") }
        if let engine = report.binding.engineProvenance {
            try add("\nEngine protocol schema: \(engine.schemaVersion); patch digest/version label: \(cell(engine.patchDigest))\n\n")
            try add("Engine options (complete): \(cell(String(decoding: try TimelineCoding.encode(engine.options), as: UTF8.self)))\n\n")
            try add("Image parameters: \(cell(String(decoding: try TimelineCoding.encode(engine.image), as: UTF8.self)))\n\n")
            for input in engine.orderedInputs { try add("- Ordered input \(input.ordinal); \(input.byteCount.map(String.init) ?? "byte count unavailable in historical listing") bytes; scope=\(cell(input.hashScope)); SHA-256=\(input.sha256)\n") }
            for volume in engine.volumes { try add("- Volume: \(cell(String(decoding: try TimelineCoding.encode(volume), as: UTF8.self)))\n") }
        } else { try add("\nHistorical v1 report: complete engine options, patch identity, image/volume parameters and source sizes were not retained. The snapshot digest cannot reconstruct those fields.\n") }
        if let logical = report.binding.logicalImageSHA256 { try add("\nLogical-image bytes SHA-256: \(logical)\n") }
        for file in report.artifactReceipts { try add("\nArtifact \(file.role): \(cell(file.evidencePath)); \(file.byteCount) extracted bytes; SHA-256 \(file.sha256); encoded hash scope=\(file.hashScope ?? "unavailable in historical receipt").\n") }
        try add("\nParser versions and selected parameters:\n\n")
        for parser in report.parserReceipts ?? [] {
            try add("- \(cell(parser.parser)) v\(cell(parser.version)); events=\(parser.eventCount); source extracted-content SHA-256=\(parser.sourceSHA256 ?? "none") (\(parser.sourceHashScope ?? "unavailable encoded scope")); derived-text SHA-256=\(parser.derivedTextSHA256 ?? "none") (\(parser.derivedTextHashScope ?? "unavailable encoded scope")); units=\(parser.unitCount.map(String.init) ?? "none"); lines=\(parser.lineCount.map(String.init) ?? "none")\n")
            for key in parser.parameters.keys.sorted() { try add("  - \(cell(key)): \(cell(parser.parameters[key]!))\n") }
        }
        if report.parserReceipts == nil { try add("Historical v1 report: parser parameters were not retained.\n") }
        try add("\n## Limits and assumptions\n\n")
        for warning in report.warnings { try add("- \(cell(warning))\n") }
        try add("\n## Deterministic parser observations\n\nUTC epoch seconds/nanoseconds are normalized values; raw timestamp and assumptions remain explicit. Unresolved local times have no normalized instant.\n\n| Event ID / parser | Epoch seconds | Nanoseconds | Alternatives | Kind | Entry state | Evidence path / file ID | Record / source pointer | Artifact SHA-256 | Raw timestamp | Precision | Assumption / interpretation | Observation |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for event in report.events {
            try Task.checkCancellation()
            let pointer = try event.sourceReference.map { cell(String(decoding: try TimelineCoding.encode($0), as: UTF8.self)) } ?? "none"
            try add("| \(event.id) / \(cell(event.parser)) | \(event.timestamp.epochSeconds.map(String.init) ?? "unresolved") | \(event.timestamp.nanoseconds) | \(event.timestamp.alternativeEpochSeconds.map(String.init).joined(separator: ", ")) | \(event.kind.rawValue) | \(event.isDeleted ? "deleted entry; deletion time unknown" : "allocated / recorded") | \(cell(event.evidencePath)) / \(cell(event.fileID)) | \(cell(event.recordID)) / \(pointer) | \(event.artifactSHA256 ?? "none") | \(cell(event.timestamp.rawValue)) | \(cell(event.timestamp.precision)) | \(cell(event.timestamp.timezoneAssumption ?? "none")) / \(cell(event.timestamp.interpretation)) | \(cell(event.title + " — " + event.detail)) |\n")
        }
        if report.events.contains(where: { $0.filesystemTimestamp != nil }) {
            try add("\n## Raw filesystem timestamp fields\n\n")
            for event in report.events {
                if let native = event.filesystemTimestamp { try add("- Event \(event.id): \(cell(String(decoding: try TimelineCoding.encode(native), as: UTF8.self)))\n") }
            }
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
        guard files.count == 4, expectedHashes.count == 4 else { throw TimelineError.publication("Timeline report is incomplete.") }
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
                guard files[name] != nil, names.count < 4 else { unexpected = true; break }
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
