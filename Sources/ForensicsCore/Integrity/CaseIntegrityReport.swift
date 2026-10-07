import Darwin
import Foundation

public enum CaseIntegrityReportRenderer {
    public static func json(_ report: CaseIntegrityReport, includePrivatePaths: Bool = false) throws -> Data {
        try validate(report)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(ExportReport(report, includePrivatePaths: includePrivatePaths))
        guard data.count <= 16 * 1_048_576 else { throw CaseIntegrityAuditError.limit }
        return data
    }

    public static func markdown(_ report: CaseIntegrityReport, includePrivatePaths: Bool = false) throws -> Data {
        try validate(report)
        let formatter = ISO8601DateFormatter()
        var lines = ["# Case integrity audit", "", "Case ID: `\(report.caseID.uuidString.lowercased())`",
            "Audit ID: `\(report.id.uuidString.lowercased())`", "Completed: \(formatter.string(from: report.completedAt))",
            "Mode: \(report.sourceRehashed ? "Fresh selected-file rehash requested" : "Historical metadata only; evidence bytes not opened")",
            "Coverage: \(report.isPartial ? "Partial / unavailable items" : "Completed within declared audit scope")",
            "Freshly verified selected-file sources: \(report.verifiedSourceCount)", "",
            "SHA-256 detects byte changes relative to unsigned stored receipts. It does not authenticate an examiner, prove chain of custody or prevent coordinated receipt rewriting. Historical metadata validation is not fresh source verification.", "",
            "No baseline rewrite, repair, migration, evidence modification or AI request was performed.", ""]
        if let digest = report.manifestSHA256 { lines += ["Audited manifest bytes SHA-256: `\(digest)`", ""] }
        if includePrivatePaths { lines += ["Private case path: \(literal(report.casePath))", ""] }
        for check in report.checks {
            lines += ["- **\(check.status.rawValue.uppercased())** · \(literal(check.code)) · \(literal(check.relativePath ?? "Case / source receipt"))",
                "  \(literal(check.message))"]
            if let id = check.evidenceID { lines.append("  Evidence ID: `\(id.uuidString.lowercased())`") }
            if let size = check.byteCount { lines.append("  Bytes: \(size)") }
            if let digest = check.sha256 { lines.append("  SHA-256: `\(digest)`") }
            if let recorded = check.recordedByteCount { lines.append("  Recorded selected-file bytes: \(recorded)") }
            if let recorded = check.recordedSHA256 { lines.append("  Recorded selected-file SHA-256: `\(recorded)`") }
            if includePrivatePaths, let path = check.privatePath { lines.append("  Private source path: \(literal(path))") }
            lines.append("")
        }
        let data = Data((lines.joined(separator: "\n") + "\n").utf8)
        guard data.count <= 16 * 1_048_576 else { throw CaseIntegrityAuditError.limit }
        return data
    }

    private static func literal(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "`", with: "\\`").replacingOccurrences(of: "[", with: "\\[")
            .replacingOccurrences(of: "]", with: "\\]").replacingOccurrences(of: "*", with: "\\*")
    }

    private static func validate(_ report: CaseIntegrityReport) throws {
        guard report.schemaVersion == 1, report.checks.count <= 20_001,
              report.manifestSHA256.map(EngineValidation.validHash) ?? true,
              report.startedAt.timeIntervalSince1970.isFinite, report.completedAt.timeIntervalSince1970.isFinite,
              report.casePath.utf8.count <= 32_768, report.checks.allSatisfy({
                  $0.message.utf8.count <= 4_096 && $0.code.utf8.count <= 256
                    && ($0.relativePath?.utf8.count ?? 0) <= 4_096 && ($0.privatePath?.utf8.count ?? 0) <= 32_768
                    && ($0.sha256.map(EngineValidation.validHash) ?? true)
                    && ($0.recordedSHA256.map(EngineValidation.validHash) ?? true)
              }) else { throw CaseIntegrityAuditError.invalid }
    }

    private struct ExportReport: Encodable {
        let schemaVersion: Int; let id: UUID; let caseID: UUID; let casePath: String?
        let manifestSHA256: String?; let startedAt: Date; let completedAt: Date
        let sourceRehashed: Bool; let isPartial: Bool; let hasFailures: Bool
        let verifiedSourceCount: Int; let privatePathsIncluded: Bool; let checks: [CaseIntegrityCheck]
        let interpretation = "Unsigned digests detect changes, not authenticity. Historical receipts are not fresh source verification."
        init(_ report: CaseIntegrityReport, includePrivatePaths: Bool) {
            schemaVersion = report.schemaVersion; id = report.id; caseID = report.caseID
            casePath = includePrivatePaths ? report.casePath : nil; manifestSHA256 = report.manifestSHA256
            startedAt = report.startedAt; completedAt = report.completedAt; sourceRehashed = report.sourceRehashed
            isPartial = report.isPartial; hasFailures = report.hasFailures; verifiedSourceCount = report.verifiedSourceCount
            privatePathsIncluded = includePrivatePaths
            checks = report.checks.map { check in
                .init(id: check.id, status: check.status, code: check.code, relativePath: check.relativePath,
                      evidenceID: check.evidenceID, privatePath: includePrivatePaths ? check.privatePath : nil,
                      byteCount: check.byteCount, sha256: check.sha256,
                      recordedByteCount: check.recordedByteCount, recordedSHA256: check.recordedSHA256, message: check.message)
            }
        }
    }
}

public enum CaseIntegrityReportExporter {
    public static func export(report: CaseIntegrityReport, forensicCase: ForensicCase,
                              format: CaseIntegrityReportFormat, to outputURL: URL,
                              includePrivatePaths: Bool = false) async throws -> URL {
        let task = Task.detached(priority: .utility) {
            try publish(report: report, forensicCase: forensicCase, format: format, outputURL: outputURL,
                        includePrivatePaths: includePrivatePaths)
        }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }

    /// A failed/offline audit can still be exported. Export does not reopen or
    /// repair a corrupt manifest; it records the historical audit's own identity.
    private static func publish(report: CaseIntegrityReport, forensicCase: ForensicCase,
                                format: CaseIntegrityReportFormat, outputURL: URL, includePrivatePaths: Bool) throws -> URL {
        try Task.checkCancellation()
        guard report.caseID == forensicCase.manifest.id, report.casePath == forensicCase.bundleURL.path,
              outputURL.isFileURL, outputURL.host == nil || outputURL.host == "" || outputURL.host == "localhost",
              !outputURL.path.utf8.contains(0) else { throw ForensicsError.invalidFileURL }
        let destination = outputURL.standardizedFileURL
        let bundle = forensicCase.bundleURL.standardizedFileURL.resolvingSymlinksInPath()
        let parentURL = destination.deletingLastPathComponent()
        guard !FileAccess.isInside(destination.resolvingSymlinksInPath(), directory: bundle),
              !parentURL.pathComponents.contains(where: { $0.hasSuffix(".nativecase") }),
              !forensicCase.manifest.evidence.contains(where: { URL(fileURLWithPath: $0.sourcePath).standardizedFileURL.path == destination.path }) else {
            throw ForensicsError.invalidCase("Export the integrity report outside case storage and evidence files.")
        }
        let bytes = try format == .json ? CaseIntegrityReportRenderer.json(report, includePrivatePaths: includePrivatePaths)
            : CaseIntegrityReportRenderer.markdown(report, includePrivatePaths: includePrivatePaths)
        let parent = try EvidenceViewFiles.openDirectory(parentURL)
        defer { Darwin.close(parent) }
        let staging = ".integrity-report-\(UUID().uuidString.lowercased()).tmp"
        let fd = Darwin.openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw FileAccess.posixError("Cannot stage integrity report") }
        defer {
            if EvidenceViewFiles.referenceMatches(staging, parent: parent, descriptor: fd) { _ = Darwin.unlinkat(parent, staging, 0) }
            Darwin.close(fd)
        }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(fd, buffer.baseAddress?.advanced(by: offset), min(65_536, buffer.count - offset))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write integrity report") }
                offset += count
            }
        }
        guard Darwin.fsync(fd) == 0 else { throw FileAccess.posixError("Cannot flush integrity report") }
        let identity = try FileAccess.identity(of: fd)
        var offset = 0, buffer = [UInt8](repeating: 0, count: 65_536)
        while offset < bytes.count {
            try Task.checkCancellation()
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(fd, $0.baseAddress, min($0.count, bytes.count - offset), off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0, Data(buffer.prefix(count)) == bytes.subdata(in: offset..<offset + count) else { throw CaseIntegrityAuditError.changed }
            offset += count
        }
        try EvidenceViewFiles.validateDirectory(parentURL, descriptor: parent)
        var stagedMetadata = stat()
        guard Darwin.fstat(fd, &stagedMetadata) == 0, stagedMetadata.st_nlink == 1,
              identity.size == Int64(bytes.count), try FileAccess.identity(of: fd) == identity,
              EvidenceViewFiles.referenceMatches(staging, parent: parent, descriptor: fd) else { throw CaseIntegrityAuditError.changed }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, staging, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw ForensicsError.caseAlreadyExists }
            throw FileAccess.posixError("Cannot publish integrity report")
        }
        // Committed exports remain successful when cancellation arrives later.
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush integrity report directory") }
        return destination
    }
}
