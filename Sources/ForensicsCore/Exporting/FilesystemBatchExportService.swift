import Darwin
import Foundation

/// Sequential, bounded extraction keeps helper processes and evidence hashing
/// within a predictable resource budget. A directory becomes visible only when
/// its independently verified outputs and manifest have been flushed together.
public struct FilesystemBatchExportService: Sendable {
    public static let maxFiles = 1_000
    public static let maxTotalBytes: Int64 = 2 * 1_024 * 1_024 * 1_024
    public static let maxFileBytes: Int64 = 512 * 1_024 * 1_024
    public static let maximumFiles = maxFiles
    public static let maximumTotalBytes = maxTotalBytes
    public static let maximumFileBytes = maxFileBytes

    private typealias Extractor = @Sendable ([URL], FilesystemEntry, URL, EngineOptions, [String: String]) async throws -> (ExtractionResult, SourceIdentity)
    private let extract: Extractor
    private let helperURL: URL?
    private let extractorVerifiesSourceHashes: Bool

    public init(engine: EngineClient) {
        helperURL = engine.helperURL
        extractorVerifiesSourceHashes = true
        extract = { paths, file, output, options, hashes in
            let result = try await engine.extractOwned(imagePaths: paths, file: file, outputURL: output, options: options, expectedSourceHashes: hashes)
            return (result.receipt, result.identity)
        }
    }

    /// Test seams still perform all source, output and publication checks.
    init(extract: @escaping @Sendable ([URL], FilesystemEntry, URL, EngineOptions, [String: String]) async throws -> ExtractionResult) {
        helperURL = nil
        extractorVerifiesSourceHashes = false
        self.extract = { paths, file, output, options, hashes in
            let result = try await extract(paths, file, output, options, hashes)
            let identity = try FileAccess.identity(at: output)
            return (result, identity)
        }
    }

    public func export(
        analysis: EnumerationResult,
        files: [FilesystemEntry],
        to destination: URL,
        caseURL: URL?,
        progress: @escaping @Sendable (FilesystemBatchExportProgress) -> Void = { _ in }
    ) async throws -> FilesystemBatchExportResult {
        try Task.checkCancellation()
        try EngineValidation.result(analysis)
        guard !files.isEmpty, files.count <= Self.maxFiles,
              Set(files.map(\.id)).count == files.count else {
            throw EngineError.invalidRequest("Choose between 1 and 1,000 distinct filesystem files for export.")
        }
        let knownFiles = Dictionary(uniqueKeysWithValues: analysis.files.map { ($0.id, $0) })
        var totalBytes: Int64 = 0
        for file in files {
            guard knownFiles[file.id] == file, !file.isDirectory else {
                throw EngineError.invalidRequest("Every selected file must exactly match the validated filesystem analysis.")
            }
            guard file.size <= Self.maxFileBytes else {
                throw EngineError.limitExceeded("A batch export file exceeds the 512 MiB limit.")
            }
            let addition = totalBytes.addingReportingOverflow(file.size)
            guard !addition.overflow, addition.partialValue <= Self.maxTotalBytes else {
                throw EngineError.limitExceeded("The batch export exceeds the 2 GiB limit.")
            }
            totalBytes = addition.partialValue
        }
        let sources = try analysis.sourcePaths.map { try FileAccess.localURL(URL(fileURLWithPath: $0)) }
        guard sources.map(\.path) == analysis.sourcePaths else {
            throw EngineError.invalidCache("The ordered source paths must use their exact canonical names.")
        }
        let output = try Self.destination(destination, sources: sources, caseURL: caseURL)
        let transaction = try FilesystemBatchExportTransaction(destination: output)
        defer { transaction.cleanup() }
        let sourceIdentities = try await Self.verifySources(analysis, sources: sources, expected: nil)
        let helper = try await inspectHelper()
        var extractionOptions = analysis.options
        // Container hashes and pinned identities still verify every source.
        // Recomputing a full decompressed logical image is not needed to export
        // one chosen stream, and can dwarf the requested extraction itself.
        extractionOptions.hashLogicalImage = false
        var entries: [FilesystemBatchExportEntry] = []
        entries.reserveCapacity(files.count)
        for (index, file) in files.enumerated() {
            try Task.checkCancellation()
            try transaction.validate()
            try validateHelper(helper)
            // Production EngineClient performs the exact ordered full-source
            // hash check before extracting. Retain an identity guard here and
            // an independent post-extraction full hash, without duplicating
            // its prehash. Injectable extractors have no such contract.
            if extractorVerifiesSourceHashes {
                try Self.verifySourceIdentities(sources: sources, expected: sourceIdentities)
            } else {
                _ = try await Self.verifySources(analysis, sources: sources, expected: sourceIdentities)
            }
            progress(.init(completedFiles: index, totalFiles: files.count, currentFilename: file.name))
            let filename = Self.filename(index: index, file: file)
            let target = transaction.stagedURL.appendingPathComponent(filename)
            do {
                let (receipt, identity) = try await extract(sources, file, target, extractionOptions, analysis.sourceFileHashes)
                try transaction.claim(filename, identity: identity)
                try transaction.validate()
                guard receipt.outputPath == target.path, receipt.byteCount == file.size,
                      identity.size == file.size, EngineValidation.validHash(receipt.sha256) else {
                    throw EngineError.protocolViolation("The batch output size/path does not match the extraction receipt.")
                }
                // Reject an oversized output before a potentially unbounded
                // independent hashing pass, even through the injectable seam.
                let inspected = try await ImageInspector.inspect(url: target, progress: { _ in })
                guard inspected.byteCount == file.size,
                      inspected.sha256 == receipt.sha256, inspected.sourceIdentity == identity else {
                    throw EngineError.protocolViolation("The batch output bytes do not match the extraction receipt.")
                }
                _ = try await Self.verifySources(analysis, sources: sources, expected: sourceIdentities)
                try validateHelper(helper)
                entries.append(.init(sourceFile: file, outputFilename: filename, byteCount: receipt.byteCount, sha256: receipt.sha256, errorMessage: nil))
            } catch {
                try Task.checkCancellation()
                if error is CancellationError { throw error }
                // A failed extraction must not conceal a concurrently changed
                // input. No partial result survives a broken integrity check.
                _ = try await Self.verifySources(analysis, sources: sources, expected: sourceIdentities)
                try validateHelper(helper)
                try transaction.validate()
                guard Self.recoverable(error), !transaction.hasChild(filename) else { throw error }
                entries.append(.init(sourceFile: file, outputFilename: nil, byteCount: nil, sha256: nil, errorMessage: error.localizedDescription))
            }
            progress(.init(completedFiles: index + 1, totalFiles: files.count, currentFilename: file.name))
        }
        let result = FilesystemBatchExportResult(
            destinationPath: output.path,
            manifestPath: output.appendingPathComponent("manifest.json").path,
            status: entries.allSatisfy { $0.errorMessage == nil } ? .completed : .partial,
            entries: entries,
            sourcePaths: analysis.sourcePaths,
            sourceFileHashes: analysis.sourceFileHashes,
            engineVersion: analysis.engineVersion,
            patchDigest: analysis.patchDigest,
            analysisSavedAt: analysis.savedAt,
            evidenceTimezone: analysis.options.timezone,
            extractionHelperSha256: helper?.sha256
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try transaction.writeManifest(encoder.encode(result))
        _ = try await Self.verifySources(analysis, sources: sources, expected: sourceIdentities)
        if let helper {
            let current = try await inspectHelper()
            guard current?.sha256 == helper.sha256, current?.sourceIdentity == helper.sourceIdentity else {
                throw EngineError.protocolViolation("The extraction helper changed during the batch export.")
            }
            try validateHelper(helper)
        }
        try Task.checkCancellation()
        try transaction.publish()
        progress(.init(completedFiles: files.count, totalFiles: files.count, currentFilename: nil))
        return result
    }

    private func inspectHelper() async throws -> InspectedImage? {
        guard let helperURL else { return nil }
        return try await ImageInspector.inspect(url: helperURL, progress: { _ in })
    }

    private func validateHelper(_ helper: InspectedImage?) throws {
        guard let helperURL else { return }
        guard let helper, let identity = helper.sourceIdentity,
              (try? FileAccess.localURL(helperURL)) == helper.sourceURL,
              (try? FileAccess.identity(at: helper.sourceURL)) == identity else {
            throw EngineError.protocolViolation("The extraction helper changed during the batch export.")
        }
    }

    private static func verifySourceIdentities(sources: [URL], expected: [SourceIdentity]) throws {
        guard sources.count == expected.count else { throw EngineError.sourceChanged }
        for (source, identity) in zip(sources, expected) {
            guard (try? FileAccess.localURL(source)) == source,
                  (try? FileAccess.identity(at: source)) == identity else { throw EngineError.sourceChanged }
        }
    }

    private static func verifySources(_ analysis: EnumerationResult, sources: [URL], expected: [SourceIdentity]?) async throws -> [SourceIdentity] {
        var identities: [SourceIdentity] = []
        for (index, source) in sources.enumerated() {
            let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
            guard inspected.sha256 == analysis.sourceFileHashes[source.path], let identity = inspected.sourceIdentity,
                  expected == nil || expected?[index] == identity,
                  analysis.sourceIdentities.isEmpty || analysis.sourceIdentities[index].matches(identity) else {
                throw EngineError.sourceChanged
            }
            guard !identities.contains(where: { $0.device == identity.device && $0.inode == identity.inode }) else {
                throw EngineError.invalidCache("Source segments must refer to distinct physical files.")
            }
            identities.append(identity)
        }
        for (source, identity) in zip(sources, identities) {
            guard (try? FileAccess.identity(at: source)) == identity else { throw EngineError.sourceChanged }
        }
        return identities
    }

    private static func destination(_ url: URL, sources: [URL], caseURL: URL?) throws -> URL {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.utf8.contains(0),
              !url.lastPathComponent.isEmpty, ![".", ".."].contains(url.lastPathComponent) else {
            throw ForensicsError.invalidFileURL
        }
        // Walk the supplied parent before canonicalization: user-created
        // symlink aliases must never redirect an export or its cleanup.
        let suppliedParent = url.deletingLastPathComponent()
        let parentDescriptor = try EvidenceViewFiles.openDirectory(suppliedParent)
        defer { Darwin.close(parentDescriptor) }
        let parent = try FileAccess.localURL(suppliedParent)
        try EvidenceViewFiles.validateDirectory(parent, descriptor: parentDescriptor)
        let output = parent.appendingPathComponent(url.lastPathComponent, isDirectory: true)
        guard !sources.contains(where: { Self.inside($0, directory: output) }) else {
            throw EngineError.invalidRequest("The export directory cannot contain an evidence source.")
        }
        if let caseURL {
            let canonicalCase = try FileAccess.localURL(caseURL)
            guard !Self.inside(output, directory: canonicalCase), !Self.inside(canonicalCase, directory: output) else {
                throw EngineError.invalidRequest("Export files outside the case bundle.")
            }
        }
        var metadata = stat()
        guard Darwin.fstatat(parentDescriptor, output.lastPathComponent, &metadata, AT_SYMLINK_NOFOLLOW) != 0 else {
            throw EngineError.invalidRequest("The export destination already exists.")
        }
        guard errno == ENOENT else { throw FileAccess.posixError("Cannot inspect batch export destination") }
        return output
    }

    private static func inside(_ url: URL, directory: URL) -> Bool {
        let prefix = directory.standardizedFileURL.path
        let candidate = url.standardizedFileURL.path
        return candidate == prefix || candidate.hasPrefix(prefix == "/" ? "/" : prefix + "/")
    }

    private static func filename(index: Int, file: FilesystemEntry) -> String {
        let original = file.name.isEmpty ? "file" : file.name
        var name = String(original.unicodeScalars.map { scalar -> Character in
            if CharacterSet.controlCharacters.contains(scalar) || "/\\:".unicodeScalars.contains(scalar) { return "_" }
            return Character(String(scalar))
        })
        while name.utf8.count > 160 { name.removeLast() }
        if name.isEmpty || [".", ".."].contains(name) { name = "file" }
        return String(format: "%04d-", index + 1) + name
    }

    private static func recoverable(_ error: any Error) -> Bool {
        guard let error = error as? EngineError else { return false }
        switch error {
        case .timeout: return true
        case .helperFailed(let detail):
            let message = detail.lowercased()
            return !["hash", "receipt", "changed", "mismatch", "do not match", "bytes do not", "protocol"].contains(where: message.contains)
        default: return false
        }
    }
}
