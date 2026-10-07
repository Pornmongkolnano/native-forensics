import Darwin
import Foundation

/// Runs one narrowly scoped native helper per job. Source files are opened
/// read-only and retained while the helper reads the same canonical paths.
public struct EngineClient: Sendable {
    public let helperURL: URL
    public let timeouts: EngineTimeouts

    public init(helperURL: URL, timeouts: EngineTimeouts = EngineTimeouts()) {
        self.helperURL = helperURL
        self.timeouts = timeouts
    }

    public func enumerate(imageURL: URL, options: EngineOptions = EngineOptions(), progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> EnumerationResult {
        try await enumerate(imagePaths: Self.imagePaths(for: imageURL), options: options, progress: progress)
    }

    public func enumerate(imagePaths: [URL], options: EngineOptions = EngineOptions(), progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> EnumerationResult {
        try options.validate()
        let inspections = try await Self.inspectSources(imagePaths, expectedHashes: [:], progress: progress)
        let outcome = try await execute(imagePaths: imagePaths, operation: "enumerate", options: options, file: nil, outputPath: nil, progress: progress)
        try Self.matchInspections(inspections, sources: outcome.sources)
        guard let image = outcome.image, let status = outcome.status else {
            throw EngineError.protocolViolation("The engine did not provide a filesystem result.")
        }
        let result = EnumerationResult(
            engineVersion: outcome.engineVersion, patchDigest: outcome.patchDigest,
            sourcePaths: outcome.sources.map(\.path), sourceIdentities: outcome.sources,
            sourceFileHashes: Dictionary(uniqueKeysWithValues: inspections.map { ($0.sourceURL.path, $0.sha256) }),
            options: options, image: image, volumes: outcome.volumes, files: outcome.files,
            warnings: outcome.warnings, status: status
        )
        try EngineValidation.result(result)
        return result
    }

    public func inspect(imagePaths: [URL], options: EngineOptions = EngineOptions(), progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> EngineImageMetadata {
        let outcome = try await execute(imagePaths: imagePaths, operation: "inspect", options: options, file: nil, outputPath: nil, progress: progress)
        guard outcome.status == .completed, let image = outcome.image else {
            throw EngineError.helperFailed("Image inspection did not complete.")
        }
        return image
    }

    public func inspect(imageURL: URL, options: EngineOptions = EngineOptions(), progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> EngineImageMetadata {
        try await inspect(imagePaths: Self.imagePaths(for: imageURL), options: options, progress: progress)
    }

    public func extract(imageURL: URL, file: FilesystemEntry, outputURL: URL, options: EngineOptions = EngineOptions(), expectedSourceHashes: [String: String] = [:], progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> ExtractionResult {
        try await extract(imagePaths: Self.imagePaths(for: imageURL), file: file, outputURL: outputURL, options: options, expectedSourceHashes: expectedSourceHashes, progress: progress)
    }

    public func extract(imagePaths: [URL], file: FilesystemEntry, outputURL: URL, options: EngineOptions = EngineOptions(), expectedSourceHashes: [String: String] = [:], progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> ExtractionResult {
        try await extractOwned(imagePaths: imagePaths, file: file, outputURL: outputURL, options: options,
            expectedSourceHashes: expectedSourceHashes, progress: progress).receipt
    }

    /// Private-content consumers retain publication identity independently of
    /// the public, serializable receipt. Never adopt a later pathname occupant.
    func extractOwned(imagePaths: [URL], file: FilesystemEntry, outputURL: URL, options: EngineOptions = EngineOptions(), expectedSourceHashes: [String: String] = [:], progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> (receipt: ExtractionResult, identity: SourceIdentity) {
        try options.validate()
        try EngineValidation.file(file)
        guard !file.isDirectory else { throw EngineError.invalidRequest("Choose a regular file for extraction.") }
        let destination = try Self.outputDestination(outputURL, sources: imagePaths)
        let transaction = try EngineOutputTransaction(destination: destination)
        defer { transaction.cleanup() }
        let inspections = try await Self.inspectSources(imagePaths, expectedHashes: expectedSourceHashes, progress: progress)
        let stagedOutput = transaction.stagedOutput
        let outcome = try await execute(imagePaths: imagePaths, operation: "extract", options: options, file: file, outputPath: stagedOutput.path, progress: progress)
        try Self.matchInspections(inspections, sources: outcome.sources)
        guard outcome.status == .completed, let receipt = outcome.extraction,
              receipt.outputPath == stagedOutput.path, receipt.byteCount == file.size else {
            throw EngineError.protocolViolation("The extraction receipt does not describe the requested file.")
        }
        // Verify independently before publishing; a helper receipt alone is not
        // proof that all bytes reached the destination.
        let inspected = try await ImageInspector.inspect(url: stagedOutput, progress: { _ in })
        guard inspected.byteCount == receipt.byteCount, inspected.sha256 == receipt.sha256,
              let outputIdentity = inspected.sourceIdentity,
              (try? FileAccess.identity(at: stagedOutput)) == outputIdentity else {
            throw EngineError.helperFailed("Extracted bytes do not match the engine's size/hash receipt.")
        }
        try Self.verifySources(outcome.sources)
        try Task.checkCancellation()
        // RENAME_EXCL makes the final publication race-safe. Existing files,
        // directories and symlinks are preserved, even if created mid-job.
        let publishedIdentity = try transaction.publish(identity: outputIdentity)
        return (ExtractionResult(outputPath: destination.path, byteCount: receipt.byteCount, sha256: receipt.sha256), publishedIdentity)
    }

    /// Single-file convenience. Multi-segment EWF requires explicit ordered
    /// paths; implicit helper discovery is rejected to retain integrity scope.
    public static func imagePaths(for selectedURL: URL) throws -> [URL] {
        [try FileAccess.localURL(selectedURL)]
    }

    private static func inspectSources(_ paths: [URL], expectedHashes: [String: String], progress: @escaping @Sendable (EngineProgress) -> Void) async throws -> [InspectedImage] {
        guard !paths.isEmpty, paths.count <= 1024 else { throw EngineError.invalidRequest("Supply between 1 and 1,024 ordered image files.") }
        let canonical = try paths.map(FileAccess.localURL)
        guard Set(canonical.map(\.path)).count == canonical.count else { throw EngineError.invalidRequest("Image segments must not be duplicated.") }
        if !expectedHashes.isEmpty {
            guard Set(expectedHashes.keys) == Set(canonical.map(\.path)), expectedHashes.values.allSatisfy(EngineValidation.validHash) else {
                throw EngineError.invalidRequest("The expected container hashes must cover every ordered source file.")
            }
        }
        var inspections: [InspectedImage] = []
        var inputIdentities = Set<EngineInputIdentity>()
        for source in canonical {
            let inspected = try await ImageInspector.inspect(url: source) { update in
                progress(EngineProgress(stage: "source-file-sha256", completed: update.bytesRead, total: update.totalBytes, unit: "bytes"))
            }
            if let expected = expectedHashes[source.path], expected != inspected.sha256 { throw EngineError.sourceChanged }
            guard let identity = inspected.sourceIdentity,
                  inputIdentities.insert(EngineInputIdentity(identity)).inserted else {
                throw EngineError.invalidRequest("Image segments must refer to distinct source files; hard-link aliases are duplicates.")
            }
            inspections.append(inspected)
        }
        for inspection in inspections {
            guard let identity = inspection.sourceIdentity,
                  (try? FileAccess.identity(at: inspection.sourceURL)) == identity else { throw EngineError.sourceChanged }
        }
        return inspections
    }

    private static func matchInspections(_ inspections: [InspectedImage], sources: [EngineSourceIdentity]) throws {
        guard inspections.count == sources.count else { throw EngineError.sourceChanged }
        for (inspection, source) in zip(inspections, sources) {
            guard inspection.sourceURL.path == source.path, let identity = inspection.sourceIdentity, source.matches(identity) else {
                throw EngineError.sourceChanged
            }
        }
    }

    private func execute(imagePaths: [URL], operation: String, options: EngineOptions, file: FilesystemEntry?, outputPath: String?, progress: @escaping @Sendable (EngineProgress) -> Void) async throws -> EngineOutcome {
        try Task.checkCancellation()
        try options.validate()
        guard [timeouts.startup, timeouts.inactivity, timeouts.cancellationGrace, timeouts.terminationGrace].allSatisfy({ $0.isFinite && $0 > 0 }) else {
            throw EngineError.invalidRequest("Engine timeouts must be finite and positive.")
        }
        let cancellation = EngineCancellation()
        let helper = helperURL
        let limits = timeouts
        let worker = Task.detached(priority: .userInitiated) {
            try EngineRunner(helperURL: helper, timeouts: limits, cancellation: cancellation).run(
                imagePaths: imagePaths, operation: operation, options: options, file: file,
                outputPath: outputPath, progress: progress
            )
        }
        do {
            let outcome = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                cancellation.cancel()
            }
            try Task.checkCancellation()
            return outcome
        } catch {
            // The owned worker has already unwound/reaped before this point.
            // A cancelled caller stays cancelled even if shutdown emits a bad
            // frame or exits unsuccessfully during the cancellation grace.
            try Task.checkCancellation()
            throw error
        }
    }

    private static func outputDestination(_ url: URL, sources: [URL]) throws -> URL {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              !url.path.utf8.contains(0), !url.lastPathComponent.isEmpty else { throw ForensicsError.invalidFileURL }
        let parent = try FileAccess.localURL(url.deletingLastPathComponent())
        var metadata = stat()
        guard Darwin.lstat(parent.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
            throw EngineError.invalidRequest("Choose an existing extraction directory.")
        }
        let destination = parent.appendingPathComponent(url.lastPathComponent)
        guard !sources.contains(where: { (try? FileAccess.localURL($0)) == destination }) else {
            throw EngineError.invalidRequest("An extraction destination cannot be an evidence source.")
        }
        if Darwin.lstat(destination.path, &metadata) == 0 {
            throw EngineError.invalidRequest("The extraction destination already exists.")
        }
        guard errno == ENOENT else { throw FileAccess.posixError("Cannot inspect extraction destination") }
        return destination
    }

    fileprivate static func verifySources(_ identities: [EngineSourceIdentity]) throws {
        for source in identities {
            guard let current = try? FileAccess.identity(at: URL(fileURLWithPath: source.path)), source.matches(current) else {
                throw EngineError.sourceChanged
            }
        }
    }
}

/// Directory descriptors keep publication and cleanup in the exact directory
/// selected by the caller even if another process renames surrounding paths.
private final class EngineOutputTransaction {
    let stagedOutput: URL
    private let destination: URL
    private var parentFD: Int32
    private var stagingFD: Int32
    private let stagingName: String
    private var cleaned = false

    init(destination: URL) throws {
        self.destination = destination
        let parent = destination.deletingLastPathComponent()
        parentFD = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw FileAccess.posixError("Cannot open extraction directory") }
        stagingName = ".native-extract-\(UUID().uuidString)"
        stagedOutput = parent.appendingPathComponent(stagingName, isDirectory: true).appendingPathComponent("output")
        stagingFD = -1
        if Darwin.mkdirat(parentFD, stagingName, mode_t(0o700)) != 0 {
            let error = FileAccess.posixError("Cannot create private extraction directory")
            Darwin.close(parentFD); parentFD = -1
            throw error
        }
        stagingFD = Darwin.openat(parentFD, stagingName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard stagingFD >= 0 else {
            let error = FileAccess.posixError("Cannot open private extraction directory")
            _ = Darwin.unlinkat(parentFD, stagingName, AT_REMOVEDIR)
            Darwin.close(parentFD); parentFD = -1
            throw error
        }
    }

    func publish(identity: SourceIdentity) throws -> SourceIdentity {
        var parent = stat(), requestedParent = stat(), staging = stat(), requestedStaging = stat()
        guard Darwin.fstat(parentFD, &parent) == 0,
              Darwin.lstat(destination.deletingLastPathComponent().path, &requestedParent) == 0,
              Self.sameDirectory(parent, requestedParent),
              Darwin.fstat(stagingFD, &staging) == 0,
              Darwin.fstatat(parentFD, stagingName, &requestedStaging, AT_SYMLINK_NOFOLLOW) == 0,
              Self.sameDirectory(staging, requestedStaging) else {
            throw EngineError.invalidRequest("The extraction directory changed during the job; publication was refused.")
        }
        let output = Darwin.openat(stagingFD, "output", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard output >= 0 else { throw FileAccess.posixError("Cannot verify extracted file before publication") }
        defer { Darwin.close(output) }
        guard try FileAccess.identity(of: output) == identity else {
            throw EngineError.helperFailed("The extracted file changed before publication.")
        }
        // Durability belongs to this publication transaction too. A valid
        // size/hash receipt does not establish that a helper flushed its bytes.
        guard Darwin.fsync(output) == 0 else { throw FileAccess.posixError("Cannot synchronize verified extracted file") }
        guard Darwin.renameatx_np(stagingFD, "output", parentFD, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw EngineError.invalidRequest("The extraction destination already exists.") }
            throw FileAccess.posixError("Cannot publish extracted file")
        }
        // Synchronize the newly published directory entry too.
        if Darwin.fsync(parentFD) != 0 {
            let error = FileAccess.posixError("Cannot synchronize extraction destination")
            rollbackPublished(identity: identity)
            throw error
        }
        if Darwin.lstat(destination.deletingLastPathComponent().path, &requestedParent) != 0 || !Self.sameDirectory(parent, requestedParent) {
            rollbackPublished(identity: identity)
            throw EngineError.invalidRequest("The extraction directory moved during publication; its newly created output was removed.")
        }
        // Rename may change ctime. Capture it from the still-held output
        // descriptor, then ensure the published name still refers to that file.
        let publishedIdentity = try FileAccess.identity(of: output)
        guard (try? FileAccess.identity(at: destination.lastPathComponent, in: parentFD)) == publishedIdentity else {
            rollbackPublished(identity: publishedIdentity)
            throw EngineError.helperFailed("The published extraction changed before its receipt was returned.")
        }
        return publishedIdentity
    }

    func cleanup() {
        guard !cleaned else { return }
        cleaned = true
        if stagingFD >= 0 {
            // Only the reserved output leaf is ours. Unknown files/directories
            // are left intact; cleanup never recursively removes user contents.
            var output = stat()
            if Darwin.fstatat(stagingFD, "output", &output, AT_SYMLINK_NOFOLLOW) == 0 && output.st_mode & S_IFMT == S_IFREG {
                _ = Darwin.unlinkat(stagingFD, "output", 0)
            }
            var owned = stat(), current = stat()
            if parentFD >= 0, Darwin.fstat(stagingFD, &owned) == 0,
               Darwin.fstatat(parentFD, stagingName, &current, AT_SYMLINK_NOFOLLOW) == 0,
               Self.sameDirectory(owned, current) {
                _ = Darwin.unlinkat(parentFD, stagingName, AT_REMOVEDIR)
            }
            Darwin.close(stagingFD); stagingFD = -1
        }
        if parentFD >= 0 { Darwin.close(parentFD); parentFD = -1 }
    }

    deinit { cleanup() }

    private func rollbackPublished(identity: SourceIdentity) {
        var current = stat()
        if Darwin.fstatat(parentFD, destination.lastPathComponent, &current, AT_SYMLINK_NOFOLLOW) == 0,
           current.st_mode & S_IFMT == S_IFREG, current.st_dev == identity.device, current.st_ino == identity.inode {
            _ = Darwin.unlinkat(parentFD, destination.lastPathComponent, 0)
        }
    }

    private static func sameDirectory(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_mode & S_IFMT == S_IFDIR && rhs.st_mode & S_IFMT == S_IFDIR && lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }
}

private struct EngineInputIdentity: Hashable {
    let device: dev_t
    let inode: ino_t
    init(_ identity: SourceIdentity) { device = identity.device; inode = identity.inode }
}

private final class EngineCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func cancel() { lock.lock(); value = true; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return value }
}

private struct EngineRequest: Encodable {
    let protocolVersion = 1
    let jobID: String
    let operation: String
    let imagePaths: [String]
    let imageType: String
    let sectorSize: Int
    let timezone: String
    let maxFiles: Int
    let hashLogicalImage: Bool
    let file: EngineExtractionRequest?
    let outputPath: String?
}

private struct EngineExtractionRequest: Encodable {
    let fsOffsetBytes: Int64
    let metaAddress: UInt64
    let attributeType: Int32?
    let attributeID: Int32?
    let size: Int64
    init(_ file: FilesystemEntry) {
        fsOffsetBytes = file.fsOffsetBytes; metaAddress = file.metaAddress
        attributeType = file.attributeType; attributeID = file.attributeID; size = file.size
    }
}

private struct EngineFrame: Decodable {
    let protocolVersion: Int
    let jobID: String
    let sequence: Int64
    let type: String
    let engineVersion: String?
    let patchDigest: String?
    let capabilities: [String]?
    let imageType: String?
    let logicalSize: Int64?
    let sectorSize: Int?
    let logicalSha256: String?
    let imagePaths: [String]?
    let volume: EngineVolume?
    let files: [FilesystemEntry]?
    let stage: String?
    let completed: Int64?
    let total: Int64?
    let unit: String?
    let code: String?
    let message: String?
    let outputPath: String?
    let byteCount: Int64?
    let sha256: String?
    let fileCount: Int64?
}

private struct EngineOutcome: Sendable {
    var engineVersion = ""
    var patchDigest = ""
    var sources: [EngineSourceIdentity] = []
    var image: EngineImageMetadata?
    var volumes: [EngineVolume] = []
    var files: [FilesystemEntry] = []
    var warnings: [String] = []
    var status: EngineTerminalStatus?
    var extraction: ExtractionResult?
}

private struct EngineStream {
    let jobID: String
    let operation: String
    let options: EngineOptions
    var outcome: EngineOutcome
    var nextSequence: Int64 = 0
    var receivedHello = false
    var fileIDs = Set<String>()
    var volumeIDs = Set<String>()
    var errorMessages: [String] = []
    var rawByteCount = 0
    var pending = Data()

    mutating func receive(_ bytes: Data, progress: @Sendable (EngineProgress) -> Void) throws {
        rawByteCount += bytes.count
        guard rawByteCount <= EngineValidation.resultLimit else { throw EngineError.limitExceeded("The engine response exceeds 64 MiB.") }
        pending.append(bytes)
        while let newline = pending.firstIndex(of: 10) {
            let length = pending.distance(from: pending.startIndex, to: newline)
            guard length <= EngineValidation.frameLimit else { throw EngineError.limitExceeded("An engine frame exceeds 1 MiB.") }
            let line = Data(pending.prefix(length))
            pending.removeFirst(length + 1)
            guard !line.isEmpty else { throw EngineError.protocolViolation("An empty engine frame is invalid.") }
            let frame: EngineFrame
            do { frame = try JSONDecoder().decode(EngineFrame.self, from: line) }
            catch { throw EngineError.protocolViolation("The engine emitted malformed or incomplete JSON.") }
            try consume(frame, progress: progress)
        }
        guard pending.count <= EngineValidation.frameLimit else { throw EngineError.limitExceeded("An engine frame exceeds 1 MiB.") }
    }

    mutating func consume(_ frame: EngineFrame, progress: @Sendable (EngineProgress) -> Void) throws {
        guard frame.protocolVersion == 1, frame.jobID == jobID, frame.sequence == nextSequence,
              outcome.status == nil else { throw EngineError.protocolViolation("Unexpected protocol version, job, sequence or frame after terminal status.") }
        nextSequence += 1
        if !receivedHello, frame.type != "hello" { throw EngineError.protocolViolation("The first engine frame must be hello.") }
        switch frame.type {
        case "hello":
            guard !receivedHello, let version = frame.engineVersion, let digest = frame.patchDigest,
                  let capabilities = frame.capabilities, EngineValidation.text(version, maximum: 256),
                  EngineValidation.text(digest, maximum: 256), capabilities.count <= 128,
                  capabilities.allSatisfy({ EngineValidation.text($0, maximum: 256) }) else {
                throw EngineError.protocolViolation("Invalid or repeated engine hello.")
            }
            receivedHello = true
            outcome.engineVersion = version; outcome.patchDigest = digest
        case "image":
            guard outcome.image == nil, let type = frame.imageType, let size = frame.logicalSize,
                  let sector = frame.sectorSize, let actualPaths = frame.imagePaths else {
                throw EngineError.protocolViolation("Missing or repeated image metadata, including its ordered source paths.")
            }
            let expectedPaths = outcome.sources.map(\.path)
            guard actualPaths.count == expectedPaths.count,
                  actualPaths.allSatisfy({ $0.hasPrefix("/") && EngineValidation.text($0) }) else {
                throw EngineError.protocolViolation("The engine read images outside the verified ordered source scope.")
            }
            // Darwin realpath exposes /private/var while Foundation deliberately
            // presents the same source as /var. Normalize only this live frame
            // through the same URL rules used for the pinned inputs. Keep the
            // ordered Foundation paths/hash keys stable in saved results.
            let normalizedPaths: [String]
            do { normalizedPaths = try actualPaths.map { try FileAccess.localURL(URL(fileURLWithPath: $0)).path } }
            catch { throw EngineError.protocolViolation("The engine supplied an invalid source path.") }
            guard normalizedPaths == expectedPaths else {
                throw EngineError.protocolViolation("The engine read images outside the verified ordered source scope.")
            }
            let image = EngineImageMetadata(imageType: type, logicalSize: size, sectorSize: sector, logicalSha256: frame.logicalSha256, imagePaths: expectedPaths)
            try EngineValidation.image(image)
            outcome.image = image
        case "volume":
            guard operation != "extract", let volume = frame.volume,
                  volumeIDs.insert(volume.id).inserted, outcome.volumes.count < 4096 else {
                throw EngineError.protocolViolation("Unexpected or duplicate filesystem volume.")
            }
            try EngineValidation.volume(volume)
            outcome.volumes.append(volume)
        case "fileBatch":
            guard operation == "enumerate", let files = frame.files, files.count <= 128,
                  outcome.files.count + files.count <= options.maxFiles else {
                throw EngineError.limitExceeded("The engine file batch or result exceeds the requested limit.")
            }
            for file in files {
                try EngineValidation.file(file)
                guard fileIDs.insert(file.id).inserted else { throw EngineError.protocolViolation("The engine emitted duplicate file identifiers.") }
            }
            outcome.files.append(contentsOf: files)
        case "progress":
            guard let stage = frame.stage, let completed = frame.completed, let unit = frame.unit,
                  EngineValidation.text(stage, maximum: 128), EngineValidation.text(unit, maximum: 128), completed >= 0,
                  frame.total.map({ $0 >= 0 && completed <= $0 }) ?? true else {
                throw EngineError.protocolViolation("Invalid engine progress.")
            }
            progress(EngineProgress(stage: stage, completed: completed, total: frame.total, unit: unit))
        case "warning", "error":
            guard let code = frame.code, let message = frame.message,
                  EngineValidation.text(code, maximum: 256), EngineValidation.text(message),
                  outcome.warnings.count + errorMessages.count < 1024 else {
                throw EngineError.protocolViolation("Invalid or excessive engine diagnostics.")
            }
            if frame.type == "warning" { outcome.warnings.append("\(code): \(message)") }
            else { errorMessages.append("\(code): \(message)") }
        case "extracted":
            guard operation == "extract", outcome.extraction == nil, let path = frame.outputPath,
                  let count = frame.byteCount, let hash = frame.sha256, count >= 0,
                  path.hasPrefix("/"), EngineValidation.text(path), EngineValidation.validHash(hash) else {
                throw EngineError.protocolViolation("Invalid or unexpected extraction receipt.")
            }
            outcome.extraction = ExtractionResult(outputPath: path, byteCount: count, sha256: hash)
        case "completed", "partial", "failed", "cancelled":
            guard let status = EngineTerminalStatus(rawValue: frame.type), let count = frame.fileCount,
                  count == outcome.files.count, frame.message.map({ EngineValidation.text($0) }) ?? true else {
                throw EngineError.protocolViolation("The terminal file count does not match delivered records.")
            }
            outcome.status = status
            if let message = frame.message { outcome.warnings.append(message) }
            if status == .partial {
                outcome.warnings.append(contentsOf: errorMessages)
                if outcome.warnings.isEmpty { outcome.warnings.append("The engine returned an explicit partial result.") }
            }
            if status == .completed && !errorMessages.isEmpty {
                throw EngineError.protocolViolation("The engine reported errors but claimed complete success.")
            }
        default:
            throw EngineError.protocolViolation("Unknown engine frame type: \(frame.type.prefix(128)).")
        }
    }

    func finish(exitStatus: Int32, stderr: Data) throws -> EngineOutcome {
        guard pending.isEmpty else { throw EngineError.protocolViolation("The engine output ended in a truncated frame.") }
        guard receivedHello, let status = outcome.status else { throw EngineError.protocolViolation("The engine exited without hello and terminal status.") }
        if status == .cancelled { throw CancellationError() }
        let diagnostic = String(decoding: stderr.prefix(EngineValidation.stderrLimit), as: UTF8.self)
        guard status != .failed, exitStatus == 0 else {
            let detail = (errorMessages + outcome.warnings).joined(separator: "\n")
            throw EngineError.helperFailed("The engine failed (exit \(exitStatus)). \(detail)\(diagnostic.isEmpty ? "" : "\n" + diagnostic)")
        }
        if operation != "extract" {
            guard outcome.image != nil else { throw EngineError.protocolViolation("No image metadata accompanied the result.") }
            if options.hashLogicalImage && outcome.image?.logicalSha256 == nil {
                throw EngineError.protocolViolation("The requested logical-image SHA-256 is missing.")
            }
        } else {
            guard status == .completed, outcome.extraction != nil else { throw EngineError.helperFailed("Extraction did not complete.") }
        }
        return outcome
    }
}

private struct EngineRunner {
    let helperURL: URL
    let timeouts: EngineTimeouts
    let cancellation: EngineCancellation

    func run(imagePaths: [URL], operation: String, options: EngineOptions, file: FilesystemEntry?, outputPath: String?, progress: @Sendable (EngineProgress) -> Void) throws -> EngineOutcome {
        if cancellation.isCancelled { throw CancellationError() }
        guard !imagePaths.isEmpty, imagePaths.count <= 1024 else { throw EngineError.invalidRequest("Supply between 1 and 1,024 ordered image files.") }
        let canonical = try imagePaths.map(FileAccess.localURL)
        guard Set(canonical.map(\.path)).count == canonical.count else { throw EngineError.invalidRequest("Image segments must not be duplicated.") }
        var descriptors: [Int32] = []
        defer { for descriptor in descriptors { Darwin.close(descriptor) } }
        var identities: [EngineSourceIdentity] = []
        var inputIdentities = Set<EngineInputIdentity>()
        for url in canonical {
            let descriptor = try FileAccess.openReadOnly(url)
            descriptors.append(descriptor)
            let identity = try FileAccess.identity(of: descriptor)
            guard inputIdentities.insert(EngineInputIdentity(identity)).inserted else {
                throw EngineError.invalidRequest("Image segments must refer to distinct source files; hard-link aliases are duplicates.")
            }
            identities.append(EngineSourceIdentity(path: url.path, identity: identity))
        }
        let helper = try FileAccess.localURL(helperURL)
        _ = try FileAccess.identity(at: helper)
        guard Darwin.access(helper.path, X_OK) == 0 else { throw EngineError.invalidRequest("The native engine helper is not executable.") }
        let jobID = UUID().uuidString
        let request = EngineRequest(jobID: jobID, operation: operation, imagePaths: canonical.map(\.path), imageType: options.imageType, sectorSize: options.sectorSize, timezone: options.timezone, maxFiles: options.maxFiles, hashLogicalImage: options.hashLogicalImage, file: file.map(EngineExtractionRequest.init), outputPath: outputPath)
        var outgoing = try JSONEncoder().encode(request)
        guard outgoing.count <= EngineValidation.frameLimit else { throw EngineError.limitExceeded("The engine request exceeds 1 MiB.") }
        outgoing.append(10)
        let input = Pipe(), output = Pipe(), errors = Pipe()
        // Foundation's pipe endpoints may be inheritable. A concurrently
        // spawned child must not retain an engine writer and withhold EOF.
        // The helper's explicit standard-stream duplication remains intact.
        for handle in [input.fileHandleForReading, input.fileHandleForWriting,
                       output.fileHandleForReading, output.fileHandleForWriting,
                       errors.fileHandleForReading, errors.fileHandleForWriting] {
            guard fcntl(handle.fileDescriptor, F_SETFD, FD_CLOEXEC) == 0 else {
                throw FileAccess.posixError("Cannot protect engine pipe inheritance")
            }
        }
        let process = Process()
        process.executableURL = helper
        process.arguments = []
        process.standardInput = input; process.standardOutput = output; process.standardError = errors
        try process.run()
        try? input.fileHandleForReading.close()
        try? output.fileHandleForWriting.close()
        try? errors.fileHandleForWriting.close()
        defer {
            if process.isRunning { terminate(process, grace: timeouts.terminationGrace) }
            try? input.fileHandleForWriting.close()
            try? output.fileHandleForReading.close()
            try? errors.fileHandleForReading.close()
        }
        let stdoutFD = output.fileHandleForReading.fileDescriptor
        let stderrFD = errors.fileHandleForReading.fileDescriptor
        let stdinFD = input.fileHandleForWriting.fileDescriptor
        for fd in [stdoutFD, stderrFD, stdinFD] {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw FileAccess.posixError("Cannot configure engine pipe") }
        }
        guard fcntl(stdinFD, F_SETNOSIGPIPE, 1) == 0 else { throw FileAccess.posixError("Cannot protect engine request pipe") }
        var stream = EngineStream(jobID: jobID, operation: operation, options: options, outcome: EngineOutcome(sources: identities))
        var stderr = Data()
        var outputEOF = false, errorEOF = false, inputClosed = false
        var outgoingOffset = 0
        let started = uptime()
        var lastActivity = started
        var cancelledAt: Double?
        var terminatedAt: Double?
        var exitedAt: Double?
        var timeoutError: EngineError?
        let cancelRequest = Data("{\"protocolVersion\":1,\"jobID\":\"\(jobID)\",\"operation\":\"cancel\"}\n".utf8)
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            let now = uptime()
            let isRunning = process.isRunning
            if !isRunning && exitedAt == nil { exitedAt = now }
            if cancellation.isCancelled && cancelledAt == nil {
                cancelledAt = now
                outgoing.append(cancelRequest)
            }
            if cancelledAt == nil && timeoutError == nil {
                if !stream.receivedHello && now - started > timeouts.startup {
                    timeoutError = .timeout("The native engine did not send hello before its startup deadline.")
                } else if stream.receivedHello && now - lastActivity > timeouts.inactivity {
                    timeoutError = .timeout("The native engine stopped reporting activity before its stage deadline.")
                }
                if timeoutError != nil {
                    cancelledAt = now
                    outgoing.append(cancelRequest)
                }
            }
            if let cancelledAt, isRunning, now - cancelledAt >= timeouts.cancellationGrace, terminatedAt == nil {
                _ = Darwin.kill(process.processIdentifier, SIGTERM)
                terminatedAt = now
            }
            if let terminatedAt, isRunning, now - terminatedAt >= timeouts.terminationGrace {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
            if outputEOF && errorEOF && !isRunning { break }
            var polling = [
                pollfd(fd: outputEOF ? -1 : stdoutFD, events: Int16(POLLIN), revents: 0),
                pollfd(fd: errorEOF ? -1 : stderrFD, events: Int16(POLLIN), revents: 0),
                pollfd(fd: inputClosed || outgoingOffset == outgoing.count ? -1 : stdinFD, events: Int16(POLLOUT), revents: 0)
            ]
            let polled = Darwin.poll(&polling, nfds_t(polling.count), 50)
            if polled < 0 {
                if errno == EINTR { continue }
                throw FileAccess.posixError("Cannot poll engine pipes")
            }
            // A single poll loop continuously drains both channels, including
            // discarded stderr beyond the diagnostic cap, without deadlock.
            for index in 0..<2 where polling[index].revents != 0 {
                let fd = index == 0 ? stdoutFD : stderrFD
                for _ in 0..<16 {
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if count > 0 {
                        let data = Data(buffer.prefix(count))
                        if index == 0 {
                            let previousSequence = stream.nextSequence
                            try stream.receive(data, progress: progress)
                            // Partial bytes are not a heartbeat. Only validated
                            // complete protocol frames refresh the stage timer.
                            if stream.nextSequence > previousSequence { lastActivity = uptime() }
                        } else if stderr.count < EngineValidation.stderrLimit {
                            stderr.append(data.prefix(EngineValidation.stderrLimit - stderr.count))
                        }
                    } else if count == 0 {
                        if index == 0 { outputEOF = true } else { errorEOF = true }
                        break
                    } else if errno == EINTR {
                        continue
                    } else if errno == EAGAIN || errno == EWOULDBLOCK {
                        break
                    } else {
                        throw FileAccess.posixError("Cannot read engine pipe")
                    }
                }
            }
            // A worker can be descheduled after observing process exit while
            // the final bytes/EOF are already waiting in its pipes. Drain them
            // before applying the descendant guard; elapsed wall time alone
            // cannot establish that an output writer is still alive.
            try EnginePipeExitDeadline.validate(
                exitedAt: exitedAt, now: uptime(),
                stdoutFD: outputEOF ? nil : stdoutFD,
                stderrFD: errorEOF ? nil : stderrFD
            )
            if !inputClosed && polling[2].revents != 0 {
                if polling[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                    try? input.fileHandleForWriting.close(); inputClosed = true
                } else {
                    let written = outgoing.withUnsafeBytes {
                        Darwin.write(stdinFD, $0.baseAddress?.advanced(by: outgoingOffset), $0.count - outgoingOffset)
                    }
                    if written > 0 { outgoingOffset += written }
                    else if written < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
                        if errno == EPIPE { try? input.fileHandleForWriting.close(); inputClosed = true }
                        else { throw FileAccess.posixError("Cannot write engine request") }
                    }
                }
            }
            if stream.outcome.status != nil && !inputClosed {
                try? input.fileHandleForWriting.close(); inputClosed = true
            }
        }
        process.waitUntilExit()
        if let timeoutError { throw timeoutError }
        if cancellation.isCancelled { throw CancellationError() }
        for (index, source) in identities.enumerated() {
            guard source.matches(try FileAccess.identity(of: descriptors[index])) else { throw EngineError.sourceChanged }
        }
        try EngineClient.verifySources(identities)
        return try stream.finish(exitStatus: process.terminationStatus, stderr: stderr)
    }

    private func uptime() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }

    private func terminate(_ process: Process, grace: TimeInterval) {
        guard process.isRunning else { return }
        _ = Darwin.kill(process.processIdentifier, SIGTERM)
        let deadline = uptime() + grace
        while process.isRunning && uptime() < deadline {
            _ = Darwin.poll(nil, 0, 20)
        }
        if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
    }
}

/// Keeps the original two-second post-exit bound for live output writers, but
/// permits a finite buffered tail from pipes whose writers have all closed.
/// This narrow probe is separate from the protocol reader so scheduler stalls
/// can be tested deterministically against real pipe readiness.
enum EnginePipeExitDeadline {
    static func validate(exitedAt: Double?, now: Double, stdoutFD: Int32?, stderrFD: Int32?) throws {
        guard let exitedAt, now - exitedAt >= 2 else { return }
        let descriptors = [stdoutFD, stderrFD].compactMap { $0 }
        guard !descriptors.isEmpty else { return }
        var readiness = descriptors.map { pollfd(fd: $0, events: Int16(POLLIN), revents: 0) }
        let status = Darwin.poll(&readiness, nfds_t(readiness.count), 0)
        if status < 0 {
            if errno == EINTR { return }
            throw FileAccess.posixError("Cannot inspect exited engine pipes")
        }
        // POLLIN alone is insufficient: a descendant can continuously flood
        // discarded stderr and otherwise evade a readiness-based deadline.
        // POLLHUP proves no writer remains; any buffered tail is finite and
        // the next normal read pass can consume it or observe EOF.
        guard readiness.allSatisfy({ $0.revents & Int16(POLLHUP) != 0 }) else {
            throw EngineError.protocolViolation("The helper exited while a descendant kept its output pipes open.")
        }
    }
}
