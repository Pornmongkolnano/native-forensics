import Darwin
import Foundation

/// The external scanner receives copies in one private workspace. The original
/// evidence stays read-only and every accepted source extent is independently
/// compared against a held descriptor before immutable case publication.
public struct PhotoRecRecoveryService: Sendable {
    public let executableURL: URL
    public init(executableURL: URL) { self.executableURL = executableURL }

    public func recover(evidence: EvidenceRecord, in forensicCase: ForensicCase,
                        options: RecoveryOptions = RecoveryOptions(),
                        progress: @escaping @Sendable (RecoveryProgress) -> Void = { _ in }) async throws -> CarvingResult {
        let requestedPriority = ForensicWorkExecutionContext.requestedPriority
        let worker = Task.detached(priority: (requestedPriority ?? .userInitiated).taskPriority) {
            try ForensicWorkExecutionContext.$requestedPriority.withValue(requestedPriority) {
                try recoverSynchronously(evidence: evidence, in: forensicCase, options: options, progress: progress)
            }
        }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
    }

    private func recoverSynchronously(evidence: EvidenceRecord, in forensicCase: ForensicCase,
                                     options: RecoveryOptions,
                                     progress: @escaping @Sendable (RecoveryProgress) -> Void) throws -> CarvingResult {
        try options.validate(); try Task.checkCancellation()
        guard evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.byteCount > 0, evidence.byteCount <= options.maximumInputBytes,
              EngineValidation.validHash(evidence.sha256),
              forensicCase.manifest.evidence.contains(evidence) else { throw RecoveryError.unsupportedSource }
        let current = try CaseStore.open(at: forensicCase.bundleURL)
        guard current.manifest.id == forensicCase.manifest.id,
              current.manifest.evidence.contains(evidence) else { throw RecoveryError.scopeMismatch }
        let sourceURL = URL(fileURLWithPath: evidence.sourcePath)
        guard !FileAccess.isInside(sourceURL, directory: try FileAccess.localURL(forensicCase.bundleURL)) else { throw RecoveryError.unsupportedSource }
        let source = try FileAccess.openReadOnly(sourceURL)
        defer { Darwin.close(source) }
        let sourceIdentity = try FileAccess.identity(of: source)
        guard sourceIdentity.size == evidence.byteCount else { throw RecoveryError.sourceChanged }
        // Older manifests could label sparse/encoded UDIF as RAW from its
        // filesystem-looking prefix. Reclassify bounded framing from this held
        // source before executable access, scratch creation or scanner launch;
        // later complete SHA/copy/publication fences remain mandatory.
        func readFraming(offset: Int64, count: Int) throws -> Data {
            var bytes = Data(count: count)
            try bytes.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
                var consumed = 0
                while consumed < count {
                    try Task.checkCancellation()
                    let part = UnsafeMutableRawBufferPointer(rebasing: buffer[consumed..<count])
                    let amount = try RecoveryIO.readAt(source, offset: offset + Int64(consumed), into: part, count: count - consumed)
                    guard amount > 0, amount <= count - consumed else { throw RecoveryError.sourceChanged }
                    consumed += amount
                }
            }
            return bytes
        }
        let header = try readFraming(offset: 0, count: Int(min(sourceIdentity.size, 4_096)))
        let footer = try readFraming(offset: max(0, sourceIdentity.size - 512), count: Int(min(sourceIdentity.size, 512)))
        guard try FileAccess.identity(of: source) == sourceIdentity,
              (try? FileAccess.identity(at: sourceURL)) == sourceIdentity else { throw RecoveryError.sourceChanged }
        guard ImageInspector.classify(header: header, footer: footer, byteCount: sourceIdentity.size, url: sourceURL).container == .raw else {
            throw RecoveryError.unsupportedSource
        }

        let executable = try FileAccess.localURL(executableURL)
        guard Darwin.access(executable.path, X_OK) == 0 else { throw RecoveryError.unavailable }
        let executableFD = try FileAccess.openReadOnly(executable)
        defer { Darwin.close(executableFD) }
        let executableIdentity = try FileAccess.identity(of: executableFD)
        let scratch = try RecoveryScratch()
        defer {
            // The runner has killed/reaped its owner before unwinding. Claim
            // final regular leaves as well when cancel/timeout happened before
            // the first periodic inventory, then clean only observed inodes.
            _ = try? scratch.inventory(options: options)
            if !scratch.cleanup() {
                progress(RecoveryProgress(stage: "Temporary recovery bytes were retained at \(scratch.url.path) because safe cleanup could not prove ownership.", unit: "files"))
            }
        }
        progress(RecoveryProgress(stage: "Verifying and snapshotting RAW evidence", total: evidence.byteCount))
        var lastProgress: Int64 = 0
        let snapshot = try scratch.copy(source: source, named: "input.raw", maximumBytes: options.maximumInputBytes, mode: 0o400) { bytes in
            if bytes - lastProgress >= 8 * 1_048_576 || bytes == evidence.byteCount {
                progress(RecoveryProgress(stage: "Verifying and snapshotting RAW evidence", completed: bytes, total: evidence.byteCount)); lastProgress = bytes
            }
        }
        guard snapshot.sha256 == evidence.sha256, snapshot.byteCount == evidence.byteCount,
              try FileAccess.identity(of: source) == sourceIdentity,
              (try? FileAccess.identity(at: sourceURL)) == sourceIdentity else { throw RecoveryError.sourceChanged }
        let snapshotFD = try scratch.open("input.raw")
        defer { Darwin.close(snapshotFD) }
        let snapshotIdentity = try FileAccess.identity(of: snapshotFD)
        let tool = try scratch.copy(source: executableFD, named: "photorec", maximumBytes: 64 * 1_048_576, mode: 0o500)
        guard try FileAccess.identity(of: executableFD) == executableIdentity,
              (try? FileAccess.identity(at: executable)) == executableIdentity else { throw RecoveryError.unavailable }
        let ownedTool = scratch.url.appendingPathComponent("photorec")
        let versionOutcome = try RecoveryProcessRunner.run(executableURL: ownedTool, arguments: ["/version"],
            workingDirectory: scratch.url, workingDirectoryDescriptor: scratch.descriptor,
            timeout: min(options.timeout, 15), maximumStdoutBytes: 65_536) { try scratch.validate() }
        guard versionOutcome.exitStatus == 0,
              let versionText = String(data: versionOutcome.stdout, encoding: .utf8),
              let firstLine = versionText.split(whereSeparator: \.isNewline).first,
              firstLine.hasPrefix("PhotoRec "), firstLine.utf8.count <= 4_096 else { throw RecoveryError.unavailable }
        let version = String(firstLine)
        progress(RecoveryProgress(stage: "Recovering signature candidates", unit: "files"))
        // Explicit None partition type forces byte offset 0 through the RAW
        // image size. Bare `search` auto-selects the first real MBR/GPT partition
        // and can miss candidates elsewhere in the input image.
        let outcome = try RecoveryProcessRunner.run(executableURL: ownedTool,
            arguments: ["/d", "recovered", "/cmd", "input.raw", options.photoRecCommand],
            workingDirectory: scratch.url, workingDirectoryDescriptor: scratch.descriptor, timeout: options.timeout) {
                let inventory = try scratch.inventory(options: options)
                progress(RecoveryProgress(stage: "Recovering signature candidates",
                    completed: Int64(inventory.keys.filter { !$0.hasSuffix("/report.xml") }.count), unit: "files"))
            }
        guard outcome.exitStatus == 0 else { throw RecoveryError.toolFailed(outcome.exitStatus) }
        try Task.checkCancellation()
        let inventory = try scratch.inventory(options: options)
        let reports = inventory.keys.filter { $0.hasSuffix("/report.xml") }.sorted()
        guard !reports.isEmpty, reports.count <= 10 else { throw RecoveryError.invalidReport }
        var artifacts: [CarvedArtifact] = []
        var artifactFiles: [UUID: URL] = [:]
        var referenced: Set<String> = []
        progress(RecoveryProgress(stage: "Verifying recovered byte mappings", total: Int64(inventory.count), unit: "files"))
        for report in reports {
            let reportFD = try scratch.open(report)
            let bytes: Data
            do { bytes = try RecoveryIO.data(reportFD, maximumBytes: RecoveryReportParser.maximumReportBytes) }
            catch { Darwin.close(reportFD); throw error }
            Darwin.close(reportFD)
            let entries = try RecoveryReportParser.parse(bytes, sourceSize: evidence.byteCount, maximumFiles: options.maximumFiles)
            for entry in entries {
                try Task.checkCancellation()
                let path = try outputPath(filename: entry.filename, report: report)
                guard let recorded = inventory[path], referenced.insert(path).inserted,
                      entry.byteCount == recorded.size, entry.byteCount <= options.maximumArtifactBytes else { throw RecoveryError.invalidReport }
                let output = try scratch.open(path)
                defer { Darwin.close(output) }
                guard try FileAccess.identity(of: output) == recorded else { throw RecoveryError.storageChanged }
                let digest = try RecoveryIO.digest(output, maximumBytes: options.maximumArtifactBytes)
                let verified = try verifiedRuns(entry.byteRuns, output: output, source: source, byteCount: entry.byteCount)
                guard try FileAccess.identity(of: output) == recorded else { throw RecoveryError.storageChanged }
                let id = UUID(), filename = URL(fileURLWithPath: path).lastPathComponent
                let warnings = verified == nil ? ["Recovered bytes could not be mapped completely to the reported source extents. The candidate is unverified."] : []
                artifacts.append(CarvedArtifact(id: id, filename: filename,
                    relativePath: "files/\(id.uuidString.lowercased())", formatHint: (filename as NSString).pathExtension.lowercased(),
                    byteCount: digest.size, sha256: digest.hash, reportedByteRuns: entry.byteRuns,
                    verifiedByteRuns: verified ?? [], validationStatus: verified == nil ? .unverified : .sourceBytesVerified, warnings: warnings))
                artifactFiles[id] = scratch.url.appendingPathComponent(path)
                guard artifacts.count <= options.maximumFiles else { throw RecoveryError.outputLimit }
                progress(RecoveryProgress(stage: "Verifying recovered byte mappings", completed: Int64(artifacts.count), unit: "files"))
            }
        }
        // PhotoRec writes t<sector>.jpg embedded-thumbnail side products without
        // DFXML fileobjects. Autopsy's primary carver also excludes these. Do
        // not fabricate their source extents: exclude only this narrow, checked
        // derivative shape and disclose it. Every other unreported leaf is an
        // inconsistent report and vetoes publication.
        let unreported = Set(inventory.keys.filter { !$0.hasSuffix("/report.xml") }).subtracting(referenced)
        for path in unreported {
            guard try isUnreportedThumbnail(path, inventory: inventory, primaryPaths: referenced, scratch: scratch) else {
                throw RecoveryError.invalidReport
            }
        }
        progress(RecoveryProgress(stage: "Reverifying evidence before publication", total: evidence.byteCount))
        let after = try RecoveryIO.digest(source, maximumBytes: options.maximumInputBytes)
        let snapshotAfter = try RecoveryIO.digest(snapshotFD, maximumBytes: options.maximumInputBytes)
        guard after.hash == evidence.sha256, after.size == evidence.byteCount,
              try FileAccess.identity(of: source) == sourceIdentity,
              (try? FileAccess.identity(at: sourceURL)) == sourceIdentity,
              snapshotAfter.hash == evidence.sha256, snapshotAfter.size == evidence.byteCount,
              try FileAccess.identity(of: snapshotFD) == snapshotIdentity,
              (try? FileAccess.identity(at: "input.raw", in: scratch.descriptor)) == snapshotIdentity else { throw RecoveryError.sourceChanged }
        let toolFD = try scratch.open("photorec")
        let toolAfter: (hash: String, size: Int64)
        do { toolAfter = try RecoveryIO.digest(toolFD, maximumBytes: 64 * 1_048_576) }
        catch { Darwin.close(toolFD); throw error }
        Darwin.close(toolFD)
        guard toolAfter.hash == tool.sha256 else { throw RecoveryError.unavailable }
        try scratch.validate(); try Task.checkCancellation()
        var warnings = ["Signature recovery candidates have unknown original names, timestamps and deletion state.",
                        "Format hints come from PhotoRec filenames. Decoder accessibility and embedded metadata require separate analysis.",
                        "This job used PhotoRec \(options.photoRecCommand) with isolated default settings; scan scope: \(options.scanScope). A source-byte mapping is independent of file-format validity."]
        if !unreported.isEmpty {
            warnings.append("PhotoRec produced \(unreported.count) unreported JPEG thumbnail derivative(s). These are excluded from the primary recovered-file listing because the XML contains no source extents for them; no source ranges were inferred.")
        }
        let result = CarvingResult(caseID: current.manifest.id, sourceEvidenceID: evidence.id,
            sourceSHA256: evidence.sha256, sourceByteCount: evidence.byteCount, status: .completed,
            artifacts: artifacts.sorted { $0.filename < $1.filename },
            warnings: warnings,
            photoRecVersion: version, executableSHA256: tool.sha256, options: options)
        try result.validate()
        progress(RecoveryProgress(stage: "Saving immutable recovery generation", unit: "files"))
        try RecoveryResultStore.save(result: result, artifactFiles: artifactFiles, in: current) {
            // A lock wait and large payload copy can outlive the post-scan
            // check. Repeat inside the atomic publication boundary.
            let publishedSource = try RecoveryIO.digest(source, maximumBytes: options.maximumInputBytes)
            guard publishedSource.hash == evidence.sha256, publishedSource.size == evidence.byteCount,
                  try FileAccess.identity(of: source) == sourceIdentity,
                  (try? FileAccess.identity(at: sourceURL)) == sourceIdentity else { throw RecoveryError.sourceChanged }
        }
        return result
    }

    private func isUnreportedThumbnail(_ path: String, inventory: [String: SourceIdentity],
                                      primaryPaths: Set<String>, scratch: RecoveryScratch) throws -> Bool {
        let parts = path.split(separator: "/").map(String.init)
        guard parts.count == 2, parts[1].hasPrefix("t"), parts[1].hasSuffix(".jpg") else { return false }
        let number = parts[1].dropFirst().dropLast(4)
        guard !number.isEmpty, number.utf8.allSatisfy({ (48...57).contains($0) }),
              primaryPaths.contains(parts[0] + "/f" + number + ".jpg"),
              let identity = inventory[path], identity.size >= 5 else { return false }
        let output = try scratch.open(path)
        defer { Darwin.close(output) }
        guard try FileAccess.identity(of: output) == identity else { throw RecoveryError.storageChanged }
        var prefix = [UInt8](repeating: 0, count: 3), suffix = [UInt8](repeating: 0, count: 2)
        let header = try prefix.withUnsafeMutableBytes { try RecoveryIO.readAt(output, offset: 0, into: $0, count: 3) }
        let footer = try suffix.withUnsafeMutableBytes { try RecoveryIO.readAt(output, offset: identity.size - 2, into: $0, count: 2) }
        guard try FileAccess.identity(of: output) == identity else { throw RecoveryError.storageChanged }
        return header == 3 && footer == 2 && prefix == [0xff, 0xd8, 0xff] && suffix == [0xff, 0xd9]
    }

    private func outputPath(filename: String, report: String) throws -> String {
        guard !filename.hasPrefix("/"), !filename.contains("\\"), !filename.utf8.contains(0) else { throw RecoveryError.invalidReport }
        let parts = filename.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 1 || parts.count == 2,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              parts.last != "report.xml" else { throw RecoveryError.invalidReport }
        if parts.count == 1 { return String(report.split(separator: "/")[0]) + "/" + filename }
        guard parts[0].hasPrefix("recovered."), parts[0].dropFirst("recovered.".count).utf8.allSatisfy({ (48...57).contains($0) }) else { throw RecoveryError.invalidReport }
        return filename
    }

    private func verifiedRuns(_ reported: [RecoveryByteRun], output: Int32, source: Int32, byteCount: Int64) throws -> [RecoveryByteRun]? {
        var covered: Int64 = 0, verified: [RecoveryByteRun] = []
        var sourceBuffer = [UInt8](repeating: 0, count: 65_536), outputBuffer = sourceBuffer
        for run in reported {
            if covered == byteCount { break }
            guard run.outputOffset == covered else { return nil }
            let length = min(run.length, byteCount - covered)
            var offset: Int64 = 0
            while offset < length {
                try Task.checkCancellation()
                let amount = Int(min(Int64(sourceBuffer.count), length - offset))
                let sourceRead = try sourceBuffer.withUnsafeMutableBytes {
                    try RecoveryIO.readAt(source, offset: run.sourceOffset + offset, into: $0, count: amount)
                }
                let outputRead = try outputBuffer.withUnsafeMutableBytes {
                    try RecoveryIO.readAt(output, offset: run.outputOffset + offset, into: $0, count: amount)
                }
                guard sourceRead == amount, outputRead == amount,
                      sourceBuffer.prefix(amount).elementsEqual(outputBuffer.prefix(amount)) else { return nil }
                offset += Int64(amount)
            }
            if length > 0 { verified.append(RecoveryByteRun(outputOffset: covered, sourceOffset: run.sourceOffset, length: length)) }
            covered += length
        }
        return covered == byteCount ? verified : nil
    }
}
