import CryptoKit
import Darwin
import Foundation

public enum SyslogLocalTimePolicy: String, Codable, Sendable, CaseIterable {
    case preserveUnresolved
    case rejectAmbiguousOrNonexistent
}

public struct SyslogParserOptions: Codable, Sendable, Equatable {
    public let year: Int?
    public let timezone: String?
    public let localTimePolicy: SyslogLocalTimePolicy
    public init(year: Int? = nil, timezone: String? = nil, localTimePolicy: SyslogLocalTimePolicy = .preserveUnresolved) {
        self.year = year; self.timezone = timezone; self.localTimePolicy = localTimePolicy
    }
    func validate() throws {
        guard year.map({ (1970...9999).contains($0) }) ?? true,
              timezone.map({ !$0.isEmpty && $0.utf8.count <= 256 && TimeZone(identifier: $0) != nil }) ?? true else {
            throw TimelineError.invalidInput("Syslog assumptions require a year from 1970 through 9999 and a valid IANA timezone.")
        }
    }
}

public struct SyslogTimelineResult: Sendable {
    public let events: [TimelineEvent]
    public let receipts: [TimelineArtifactReceipt]
    public let parserReceipt: TimelineParserReceipt
    public let binding: TimelineSourceBinding
    public let warnings: [String]
    public init(events: [TimelineEvent], receipts: [TimelineArtifactReceipt], parserReceipt: TimelineParserReceipt,
                binding: TimelineSourceBinding, warnings: [String]) {
        self.events = events; self.receipts = receipts; self.parserReceipt = parserReceipt; self.binding = binding; self.warnings = warnings
    }
}

/// The raw UTF-8 path is intentionally bounded and byte preserving. It does not
/// launch arbitrary document handlers, infer identities, or synthesize events.
public enum SyslogTimelineParser {
    public static func parse(file: VerifiedArtifactFile, binding: TimelineSourceBinding, options: SyslogParserOptions) throws -> SyslogTimelineResult {
        try binding.validate(); try options.validate()
        guard EngineValidation.validHash(file.sha256), file.byteCount >= 0,
              file.byteCount <= TimelineLimits.maximumSyslogBytes,
              file.evidencePath.hasPrefix("/"), EngineValidation.text(file.evidencePath),
              EngineValidation.text(file.fileID, maximum: 1024) else {
            throw TimelineError.invalidInput("Syslog import requires a verified UTF-8 regular file up to 1 MiB.")
        }
        let descriptor = try FileAccess.openReadOnly(file.url)
        defer { Darwin.close(descriptor) }
        let identity = try FileAccess.identity(of: descriptor)
        guard identity.size == file.byteCount else { throw TimelineError.sourceChanged }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        while data.count < Int(identity.size) {
            try Task.checkCancellation()
            let wanted = min(buffer.count, Int(identity.size) - data.count)
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: wanted) }
            guard count > 0 else { throw TimelineError.sourceChanged }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard TimelineCoding.hex(SHA256.hash(data: data)) == file.sha256,
              try FileAccess.identity(of: descriptor) == identity,
              try FileAccess.identity(at: file.url) == identity else { throw TimelineError.sourceChanged }
        guard String(data: data, encoding: .utf8) != nil,
              !data.contains(where: { $0 < 32 && $0 != 9 && $0 != 10 && $0 != 13 }) else {
            throw TimelineError.unsupported("Syslog bytes are not strict UTF-8 text or contain unsupported binary control bytes. No lossy decoding was used.")
        }
        let bytes = Array(data), derivedDigest = file.sha256
        var events: [TimelineEvent] = [], lineNumber = 0, lineStart = 0, skipped = 0, invalid = 0
        while lineStart < bytes.count {
            try Task.checkCancellation(); lineNumber += 1
            var end = lineStart
            while end < bytes.count, bytes[end] != 10 { end += 1 }
            let length = end - lineStart
            guard length <= TimelineLimits.maximumSyslogLineBytes else { throw TimelineError.limitExceeded("Syslog line \(lineNumber) exceeds 16 KiB. The import was rejected without truncation.") }
            var contentEnd = end
            if contentEnd > lineStart, bytes[contentEnd - 1] == 13 { contentEnd -= 1 }
            let rawLine = String(decoding: bytes[lineStart..<contentEnd], as: UTF8.self)
            var parsedLine = rawLine
            if lineNumber == 1, parsedLine.hasPrefix("\u{feff}") { parsedLine.removeFirst() }
            if let raw = timestampPrefix(parsedLine) {
                let stamp: TimelineTimestamp
                if raw.classic {
                    guard options.year != nil, options.timezone != nil else {
                        throw TimelineError.invalidInput("Classic syslog at line \(lineNumber) omits year/timezone. Select both explicitly before import.")
                    }
                    stamp = TimelineTimestamp.syslog(raw.value, year: options.year, timezone: options.timezone)
                    if options.localTimePolicy == .rejectAmbiguousOrNonexistent,
                       ["ambiguous-local-time", "nonexistent-local-time"].contains(stamp.interpretation) {
                        throw TimelineError.invalidInput("Classic syslog line \(lineNumber) has a DST overlap/gap under the selected IANA zone. The selected policy rejects it.")
                    }
                } else { stamp = TimelineTimestamp.rfc3339(raw.value) }
                // Invalid source fields do not become a guessed event. The
                // rejected-line count makes incomplete parsing visible.
                if stamp.interpretation.hasPrefix("invalid") { invalid += 1 }
                else {
                    guard events.count < TimelineLimits.maximumSyslogEvents else { throw TimelineError.limitExceeded("Syslog import exceeds 20,000 observations. No partial complete report was created.") }
                    let pointer = TimelineTextSourceReference(derivedTextSHA256: derivedDigest, unit: 1, unitKind: "raw-utf8-document",
                        line: lineNumber, utf8Offset: lineStart, utf8Length: length)
                    let id = try TimelineCoding.digest([binding.snapshotSHA256, file.fileID, file.sha256, "syslog-record.v1", String(lineNumber), rawLine])
                    events.append(TimelineEvent(id: id, kind: .syslogRecord, timestamp: stamp, fileID: file.fileID,
                        evidencePath: file.evidencePath, title: "Recorded syslog line \(lineNumber)", detail: rawLine,
                        parser: "syslog-record.v1", recordID: "unit:1/line:\(lineNumber)", artifactSHA256: file.sha256, sourceReference: pointer))
                }
            } else if !rawLine.trimmingCharacters(in: .whitespaces).isEmpty { skipped += 1 }
            lineStart = end < bytes.count ? end + 1 : end
        }
        guard try FileAccess.identity(of: descriptor) == identity, try FileAccess.identity(at: file.url) == identity else { throw TimelineError.sourceChanged }
        let parameters = ["decoder": "raw-utf8.v1", "decoderEncoding": "strict UTF-8; byte preserving; optional leading BOM ignored only by timestamp parser",
            "year": options.year.map(String.init) ?? "not supplied; RFC3339 only", "IANA_timezone": options.timezone ?? "not supplied; RFC3339 only",
            "DST_overlap_gap_policy": options.localTimePolicy.rawValue, "maximumInputBytes": String(TimelineLimits.maximumSyslogBytes),
            "maximumLineBytes": String(TimelineLimits.maximumSyslogLineBytes), "maximumEvents": String(TimelineLimits.maximumSyslogEvents),
            "timestampBounds": "UTC years 1970...9999; leap seconds unsupported; fixed explicitly supplied year for every classic line (no rollover inference)",
            "unrecognizedNonemptyLines": String(skipped), "invalidTimestampLines": String(invalid), "timestampFormats": "classic RFC3164 prefix; RFC3339 prefix; RFC5424 PRI/version=1 RFC3339 prefix"]
        let receipt = TimelineParserReceipt(parser: "syslog-record", version: "1", parameters: parameters, sourceSHA256: file.sha256,
            derivedTextSHA256: derivedDigest, unitCount: 1, lineCount: lineNumber, eventCount: events.count)
        return SyslogTimelineResult(events: FilesystemTimeline.sort(events), receipts: [TimelineArtifactReceipt(file: file, role: "syslog")],
            parserReceipt: receipt, binding: binding, warnings: [
                "Syslog raw UTF-8 extracted-content and derived-text SHA-256 match because decoding is byte preserving. References are one-based document/line plus UTF-8 ranges, not fabricated PDF pages.",
                "\(lineNumber) source lines; \(events.count) timestamped observations; \(skipped) unrecognized nonempty lines; \(invalid) invalid timestamps. Non-event lines remain outside event coverage.",
                "A log message is recorded file content; it does not establish a person's identity, action, truth of the message or completion. DST gaps/overlaps remain unresolved under preserveUnresolved."])
    }

    private static func timestampPrefix(_ line: String) -> (value: String, classic: Bool)? {
        var bytes = Array(line.utf8), start = 0
        if bytes.first == 60 {
            guard let closing = bytes.firstIndex(of: 62), (2...4).contains(closing),
                  bytes[1..<closing].allSatisfy({ (48...57).contains($0) }),
                  let priority = Int(String(decoding: bytes[1..<closing], as: UTF8.self)), (0...191).contains(priority) else { return nil }
            start = closing + 1
            // RFC5424 version 1 followed by an ASCII space. Classic PRI logs
            // have the month directly after their priority.
            if bytes.count >= start + 2, bytes[start] == 49, bytes[start + 1] == 32 { start += 2 }
        }
        guard start < bytes.count else { return nil }
        bytes = Array(bytes[start...])
        if bytes.count >= 15, (65...90).contains(bytes[0]), bytes[3] == 32,
           bytes[6] == 32, bytes[9] == 58, bytes[12] == 58,
           bytes.count == 15 || bytes[15] == 32 || bytes[15] == 9 {
            return (String(decoding: bytes.prefix(15), as: UTF8.self), true)
        }
        let token = bytes.prefix { $0 != 32 && $0 != 9 }
        guard token.count >= 20, token.count <= 35, token.count > 10, token[token.startIndex + 4] == 45 else { return nil }
        return (String(decoding: token, as: UTF8.self), false)
    }
}

public struct FilesystemSyslogTimelineService: Sendable {
    public let engine: EngineClient
    public init(engine: EngineClient) { self.engine = engine }
    public func parse(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult,
                      file: FilesystemEntry, options: SyslogParserOptions) async throws -> SyslogTimelineResult {
        try VerifiedContentService.validateSelection(evidence: evidence, result: result, file: file)
        try options.validate()
        guard !file.isDirectory, !file.isDeleted, file.size >= 0, file.size <= TimelineLimits.maximumSyslogBytes else {
            throw TimelineError.unsupported("Select an allocated UTF-8 log file up to 1 MiB. Deleted or oversized log extraction is outside this importer.")
        }
        let binding = try TimelineSourceBinding.make(caseID: caseID, evidence: evidence, result: result, historical: false)
        let scratch = try TimelineExtractScratch(); defer { scratch.cleanup() }
        var extractionOptions = result.options; extractionOptions.hashLogicalImage = false
        let output = scratch.url("syslog")
        let owned = try await engine.extractOwned(imagePaths: result.sourcePaths.map { URL(fileURLWithPath: $0) }, file: file,
            outputURL: output, options: extractionOptions, expectedSourceHashes: result.sourceFileHashes)
        try scratch.claim("syslog", output: owned.receipt, identity: owned.identity)
        guard owned.receipt.byteCount == file.size else { throw TimelineError.sourceChanged }
        let input = VerifiedArtifactFile(url: output, fileID: file.id, evidencePath: file.path, byteCount: owned.receipt.byteCount, sha256: owned.receipt.sha256)
        let parsed = try SyslogTimelineParser.parse(file: input, binding: binding, options: options)
        try scratch.validate()
        var identities: [(URL, SourceIdentity)] = []
        for path in result.sourcePaths {
            try Task.checkCancellation()
            let verified = try await ImageInspector.inspect(url: URL(fileURLWithPath: path), progress: { _ in })
            guard verified.sha256 == result.sourceFileHashes[path], let identity = verified.sourceIdentity else { throw TimelineError.sourceChanged }
            identities.append((verified.sourceURL, identity))
        }
        guard identities.allSatisfy({ (try? FileAccess.identity(at: $0.0)) == $0.1 }) else { throw TimelineError.sourceChanged }
        try scratch.validate(); try Task.checkCancellation()
        return parsed
    }
}
