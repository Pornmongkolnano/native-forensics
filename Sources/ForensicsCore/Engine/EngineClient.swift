import CryptoKit
import Darwin
import Foundation

/// Runs one narrowly scoped native helper per job. Source files are opened
/// read-only and retained while the helper reads the same canonical paths.
public struct EngineClient: Sendable {
    public let helperURL: URL
    public let timeouts: EngineTimeouts
    private let afterValidatedActivityForTesting: (@Sendable () -> Void)?
    private let inputWriteForTesting: (@Sendable (Int32, UnsafeRawBufferPointer) -> Int)?

    public init(helperURL: URL, timeouts: EngineTimeouts = EngineTimeouts()) {
        self.helperURL = helperURL
        self.timeouts = timeouts
        self.afterValidatedActivityForTesting = nil
        self.inputWriteForTesting = nil
    }

    /// Internal, per-call scheduling checkpoint after validated activity is
    /// recorded. Public clients never install it or bypass any deadline.
    init(helperURL: URL, timeouts: EngineTimeouts, afterValidatedActivityForTesting: @escaping @Sendable () -> Void) {
        self.helperURL = helperURL; self.timeouts = timeouts
        self.afterValidatedActivityForTesting = afterValidatedActivityForTesting
        self.inputWriteForTesting = nil
    }

    /// Synchronous actual-pipe write seam. Buffers remain borrowed inside the
    /// blocking runner; public clients always use the bounded POSIX writer.
    init(helperURL: URL, timeouts: EngineTimeouts, inputWriteForTesting: @escaping @Sendable (Int32, UnsafeRawBufferPointer) -> Int) {
        self.helperURL = helperURL; self.timeouts = timeouts
        self.afterValidatedActivityForTesting = nil
        self.inputWriteForTesting = inputWriteForTesting
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

    /// Explicit EFS derivation with single-use, borrowed credential buffers.
    /// Key bytes travel only over this job's anonymous stdin pipe. Source
    /// verification and exclusive output publication match ordinary extraction.
    public func extractDecrypted(imageURL: URL, file: FilesystemEntry, outputURL: URL, keyMaterial: EFSKeyMaterial, options: EngineOptions = EngineOptions(), expectedSourceHashes: [String: String] = [:], progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> ExtractionResult {
        defer { keyMaterial.discard() }
        return try await extractDecrypted(imagePaths: Self.imagePaths(for: imageURL), file: file, outputURL: outputURL,
            keyMaterial: keyMaterial, options: options, expectedSourceHashes: expectedSourceHashes, progress: progress)
    }

    public func extractDecrypted(imagePaths: [URL], file: FilesystemEntry, outputURL: URL, keyMaterial: EFSKeyMaterial, options: EngineOptions = EngineOptions(), expectedSourceHashes: [String: String] = [:], progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> ExtractionResult {
        defer { keyMaterial.discard() }
        return try await extractOwned(imagePaths: imagePaths, file: file, outputURL: outputURL, options: options,
            expectedSourceHashes: expectedSourceHashes, progress: progress, decryptionKey: keyMaterial).receipt
    }

    /// Private-content consumers retain publication identity independently of
    /// the public, serializable receipt. Never adopt a later pathname occupant.
    func extractOwned(imagePaths: [URL], file: FilesystemEntry, outputURL: URL, options: EngineOptions = EngineOptions(), expectedSourceHashes: [String: String] = [:], progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }, decryptionKey: EFSKeyMaterial? = nil) async throws -> (receipt: ExtractionResult, identity: SourceIdentity) {
        try options.validate()
        try EngineValidation.file(file)
        guard !file.isDirectory else { throw EngineError.invalidRequest("Choose a regular file for extraction.") }
        if decryptionKey != nil {
            guard !file.isDeleted, file.encryptionStatus == .ntfsEFSEncrypted,
                  file.attributeType == 128, file.attributeID != nil, file.attributeName == "" else {
                throw EngineError.invalidRequest("Choose an allocated NTFS EFS unnamed DATA candidate with explicit stream metadata.")
            }
        }
        let destination = try Self.outputDestination(outputURL, sources: imagePaths)
        let transaction = try EngineOutputTransaction(destination: destination)
        defer { transaction.cleanup() }
        let inspections = try await Self.inspectSources(imagePaths, expectedHashes: expectedSourceHashes, progress: progress)
        let stagedOutput = transaction.stagedOutput
        let operation = decryptionKey == nil ? "extract" : "extract-efs"
        let outcome = try await execute(imagePaths: imagePaths, operation: operation, options: options, file: file, outputPath: stagedOutput.path, progress: progress, keyMaterial: decryptionKey)
        try Self.matchInspections(inspections, sources: outcome.sources)
        guard outcome.status == .completed, let receipt = outcome.extraction,
              receipt.outputPath == stagedOutput.path, receipt.byteCount == file.size,
              (decryptionKey == nil
                ? (receipt.decryption == nil && (receipt.contentStatus.map({ $0 == (file.isDeleted ? "recovery-candidate" : "logical-content") }) ?? true))
                : (receipt.contentStatus == "decrypted-content" && receipt.decryption != nil)) else {
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
        return (ExtractionResult(outputPath: destination.path, byteCount: receipt.byteCount, sha256: receipt.sha256,
            contentStatus: receipt.contentStatus, warnings: receipt.warnings, decryption: receipt.decryption), publishedIdentity)
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

    private func execute(imagePaths: [URL], operation: String, options: EngineOptions, file: FilesystemEntry?, outputPath: String?, progress: @escaping @Sendable (EngineProgress) -> Void, keyMaterial: EFSKeyMaterial? = nil) async throws -> EngineOutcome {
        try Task.checkCancellation()
        try options.validate()
        guard [timeouts.startup, timeouts.inactivity, timeouts.cancellationGrace, timeouts.terminationGrace].allSatisfy({ $0.isFinite && $0 > 0 }) else {
            throw EngineError.invalidRequest("Engine timeouts must be finite and positive.")
        }
        let cancellation = EngineCancellation()
        let helper = helperURL
        let limits = timeouts
        let activityCheckpoint = afterValidatedActivityForTesting
        let inputWrite = inputWriteForTesting
        do {
            let outcome = try await withTaskCancellationHandler {
                try await BlockingWork.run {
                    let runner = EngineRunner(helperURL: helper, timeouts: limits, cancellation: cancellation,
                        afterValidatedActivityForTesting: activityCheckpoint, inputWriteForTesting: inputWrite)
                    if let keyMaterial {
                        return try keyMaterial.consume { privateKey, certificate in
                            // The certificate is public derivation provenance.
                            // Hash its borrowed bytes directly; never derive a
                            // private-key digest or create a credential Data.
                            var certificateHasher = Insecure.SHA1()
                            certificateHasher.update(bufferPointer: certificate)
                            let certificateSHA1 = certificateHasher.finalize().map { String(format: "%02x", $0) }.joined()
                            return try runner.run(imagePaths: imagePaths, operation: operation, options: options, file: file,
                                outputPath: outputPath, progress: progress,
                                credentials: EngineCredentialBuffers(privateKey: privateKey, certificate: certificate, certificateSHA1: certificateSHA1))
                        }
                    }
                    return try runner.run(
                        imagePaths: imagePaths, operation: operation, options: options, file: file,
                        outputPath: outputPath, progress: progress
                    )
                }
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
    let credentialTransport: EngineCredentialDescriptor?
}

private struct EngineCredentialDescriptor: Encodable {
    let profile = EFSKeyMaterial.profile
    let privateKeyBytes: Int
    let certificateBytes: Int
}

/// These non-Sendable pointers never leave the synchronous producer callback.
private struct EngineCredentialBuffers {
    let privateKey: UnsafeRawBufferPointer
    let certificate: UnsafeRawBufferPointer
    let certificateSHA1: String
}

private struct EngineExtractionRequest: Encodable {
    let fsOffsetBytes: Int64
    let metaAddress: UInt64
    let attributeType: Int32?
    let attributeID: Int32?
    let size: Int64
    let attributeName: String?
    init(_ file: FilesystemEntry) {
        fsOffsetBytes = file.fsOffsetBytes; metaAddress = file.metaAddress
        attributeType = file.attributeType; attributeID = file.attributeID; size = file.size
        attributeName = file.attributeName
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
    let contentStatus: String?
    let warnings: [String]?
    let decryption: ExtractionDecryptionReceipt?
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
    let expectedCertificateSHA1: String?
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
              outcome.status == nil, frame.decryption == nil || frame.type == "extracted" else { throw EngineError.protocolViolation("Unexpected protocol version, job, sequence or frame after terminal status.") }
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
            if operation == "extract-efs", !capabilities.contains("ntfs-efs-rsa-aes256-der") {
                throw EngineError.protocolViolation("The native engine does not advertise the required EFS key profile.")
            }
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
            guard !["extract", "extract-efs"].contains(operation), let volume = frame.volume,
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
            // A failed credential job never promotes raw helper diagnostics to
            // caller-visible logs. Structured successful provenance is checked
            // separately, while ordinary jobs retain their existing messages.
            let diagnostic = operation == "extract-efs" ? "The native engine reported an EFS diagnostic." : "\(code): \(message)"
            if frame.type == "warning" { outcome.warnings.append(diagnostic) }
            else { errorMessages.append(diagnostic) }
        case "extracted":
            guard ["extract", "extract-efs"].contains(operation), outcome.extraction == nil, let path = frame.outputPath,
                  let count = frame.byteCount, let hash = frame.sha256, count >= 0,
                  path.hasPrefix("/"), EngineValidation.text(path), EngineValidation.validHash(hash),
                  frame.warnings.map({ $0.count <= 32 && $0.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) }) ?? true else {
                throw EngineError.protocolViolation("Invalid or unexpected extraction receipt.")
            }
            let receiptWarnings: [String]?
            if operation == "extract-efs" {
                guard frame.contentStatus == "decrypted-content", let decryption = frame.decryption,
                      frame.warnings?.isEmpty == false else {
                    throw EngineError.protocolViolation("An EFS extraction requires explicit decryption provenance and its authentication limitation.")
                }
                try EngineValidation.decryption(decryption, plaintextBytes: count)
                guard decryption.certificateSHA1 == expectedCertificateSHA1 else {
                    throw EngineError.protocolViolation("The EFS receipt does not identify the selected DER certificate.")
                }
                receiptWarnings = [ExtractionDecryptionReceipt.unauthenticatedPlaintextWarning]
            } else {
                guard frame.decryption == nil,
                      frame.contentStatus.map({ ["logical-content", "recovery-candidate"].contains($0) }) ?? true else {
                    throw EngineError.protocolViolation("An ordinary extraction cannot claim decrypted content.")
                }
                receiptWarnings = frame.warnings
            }
            outcome.extraction = ExtractionResult(outputPath: path, byteCount: count, sha256: hash,
                contentStatus: frame.contentStatus, warnings: receiptWarnings, decryption: frame.decryption)
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
            throw EngineError.protocolViolation(operation == "extract-efs" ? "Unknown EFS engine frame type." : "Unknown engine frame type: \(frame.type.prefix(128)).")
        }
    }

    func finish(exitStatus: Int32, stderr: Data) throws -> EngineOutcome {
        guard pending.isEmpty else { throw EngineError.protocolViolation("The engine output ended in a truncated frame.") }
        guard receivedHello, let status = outcome.status else { throw EngineError.protocolViolation("The engine exited without hello and terminal status.") }
        if status == .cancelled { throw CancellationError() }
        let diagnostic = operation == "extract-efs" ? "" : String(decoding: stderr.prefix(EngineValidation.stderrLimit), as: UTF8.self)
        guard status != .failed, exitStatus == 0 else {
            if operation == "extract-efs" { throw EngineError.helperFailed("The native engine could not complete the EFS extraction (exit \(exitStatus)).") }
            let detail = (errorMessages + outcome.warnings).joined(separator: "\n")
            throw EngineError.helperFailed("The engine failed (exit \(exitStatus)). \(detail)\(diagnostic.isEmpty ? "" : "\n" + diagnostic)")
        }
        if !["extract", "extract-efs"].contains(operation) {
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

/// The JSON line and borrowed DER buffers are distinct segments. In particular
/// no growing Data/String ever contains credential bytes or a JSON cancel line
/// spliced into an incomplete binary credential segment.
private struct EngineInputTransport {
    enum WriteFailure: Error { case closedPipe }
    let request: Data
    let credentials: EngineCredentialBuffers?
    let cancelRequest: Data
    private var phase = 0 // request, private DER, certificate DER, idle, cancel, complete
    private var offset = 0

    init(request: Data, credentials: EngineCredentialBuffers?, cancelRequest: Data) {
        self.request = request; self.credentials = credentials; self.cancelRequest = cancelRequest
    }

    var hasPendingBytes: Bool { phase < 3 || phase == 4 }
    var credentialsAreComplete: Bool { credentials == nil || phase >= 3 }

    /// Returns false when the helper would still interpret JSON as DER. The
    /// caller must close owned stdin and terminate its owned process instead.
    mutating func enqueueCancellation() -> Bool {
        guard credentialsAreComplete else { return false }
        if phase == 3 { phase = 4; offset = 0 }
        // Ordinary jobs preserve request-first then cancel ordering.
        if credentials == nil && phase == 0 { cancellationQueued = true }
        return true
    }

    private var cancellationQueued = false

    mutating func writeNext(to descriptor: Int32, using hook: (@Sendable (Int32, UnsafeRawBufferPointer) -> Int)?) throws {
        guard hasPendingBytes else { return }
        let currentOffset = offset
        let written: Int
        let remaining: Int
        switch phase {
        case 0:
            remaining = request.count - currentOffset
            written = request.withUnsafeBytes { bytes in
                Self.write(UnsafeRawBufferPointer(rebasing: bytes[currentOffset..<(currentOffset + min(remaining, 65_536))]), to: descriptor, hook: hook)
            }
        case 1, 2:
            guard let credentials else { throw EngineError.protocolViolation("Missing credential transport segment.") }
            let bytes = phase == 1 ? credentials.privateKey : credentials.certificate
            remaining = bytes.count - currentOffset
            written = Self.write(UnsafeRawBufferPointer(rebasing: bytes[currentOffset..<(currentOffset + min(remaining, 65_536))]), to: descriptor, hook: hook)
        case 4:
            remaining = cancelRequest.count - currentOffset
            written = cancelRequest.withUnsafeBytes { bytes in
                Self.write(UnsafeRawBufferPointer(rebasing: bytes[currentOffset..<(currentOffset + min(remaining, 65_536))]), to: descriptor, hook: hook)
            }
        default: return
        }
        if written > 0 {
            guard written <= min(remaining, 65_536) else { throw EngineError.protocolViolation("The engine input writer exceeded its borrowed segment.") }
            offset += written
            if offset == currentOffset + remaining {
                offset = 0
                switch phase {
                case 0: phase = credentials == nil ? (cancellationQueued ? 4 : 3) : 1
                case 1: phase = 2
                case 2: phase = 3
                case 4: phase = 5
                default: break
                }
            }
        } else if written < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
            if errno == EPIPE { throw WriteFailure.closedPipe }
            throw FileAccess.posixError("Cannot write engine request")
        }
    }

    private static func write(_ bytes: UnsafeRawBufferPointer, to descriptor: Int32, hook: (@Sendable (Int32, UnsafeRawBufferPointer) -> Int)?) -> Int {
        if let hook { return hook(descriptor, bytes) }
        return Darwin.write(descriptor, bytes.baseAddress, bytes.count)
    }
}

private struct EngineRunner {
    let helperURL: URL
    let timeouts: EngineTimeouts
    let cancellation: EngineCancellation
    let afterValidatedActivityForTesting: (@Sendable () -> Void)?
    let inputWriteForTesting: (@Sendable (Int32, UnsafeRawBufferPointer) -> Int)?

    func run(imagePaths: [URL], operation: String, options: EngineOptions, file: FilesystemEntry?, outputPath: String?, progress: @Sendable (EngineProgress) -> Void, credentials: EngineCredentialBuffers? = nil) throws -> EngineOutcome {
        if cancellation.isCancelled { throw CancellationError() }
        guard (operation == "extract-efs") == (credentials != nil) else {
            throw EngineError.invalidRequest("Only an explicit EFS extraction may supply binary credentials.")
        }
        if let credentials {
            guard (1...EFSKeyMaterial.maximumPrivateKeyBytes).contains(credentials.privateKey.count),
                  (1...EFSKeyMaterial.maximumCertificateBytes).contains(credentials.certificate.count) else {
                throw EngineError.invalidRequest("EFS credential transport exceeds its bounded DER profile.")
            }
        }
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
        let credentialDescriptor = credentials.map { EngineCredentialDescriptor(privateKeyBytes: $0.privateKey.count, certificateBytes: $0.certificate.count) }
        let request = EngineRequest(jobID: jobID, operation: operation, imagePaths: canonical.map(\.path), imageType: options.imageType, sectorSize: options.sectorSize, timezone: options.timezone, maxFiles: options.maxFiles, hashLogicalImage: options.hashLogicalImage, file: file.map(EngineExtractionRequest.init), outputPath: outputPath, credentialTransport: credentialDescriptor)
        var outgoing = try JSONEncoder().encode(request)
        guard outgoing.count <= EngineValidation.frameLimit else { throw EngineError.limitExceeded("The engine request exceeds 1 MiB.") }
        outgoing.append(10)
        let cancelRequest = Data("{\"protocolVersion\":1,\"jobID\":\"\(jobID)\",\"operation\":\"cancel\"}\n".utf8)
        var input = EngineInputTransport(request: outgoing, credentials: credentials, cancelRequest: cancelRequest)
        let channels = try EngineChannels()
        defer { channels.close() }
        let process = try EngineProcess(executable: helper, channels: channels)
        channels.closeChildEnds()
        defer { process.terminateAndReap(grace: timeouts.terminationGrace) }
        let stdoutFD = channels.outputRead
        let stderrFD = channels.errorRead
        let stdinFD = channels.inputWrite
        var stream = EngineStream(jobID: jobID, operation: operation, options: options,
            expectedCertificateSHA1: credentials?.certificateSHA1, outcome: EngineOutcome(sources: identities))
        var stderr = Data()
        var outputEOF = false, errorEOF = false, inputClosed = false
        let started = uptime()
        var lastActivity = started
        var cancelledAt: Double?
        var terminatedAt: Double?
        var exitedAt: Double?
        var timeoutError: EngineError?
        var buffer = [UInt8](repeating: 0, count: 65_536)
        // A maximum-size legal frame plus its newline fits within one pass's
        // byte ceiling; each channel still has a finite read-count bound.
        let maximumReadPasses = EngineValidation.frameLimit / buffer.count + 1
        func requestCancellation(at instant: Double) {
            cancelledAt = instant
            if !input.enqueueCancellation() {
                // Until both complete DER segments have been written, a JSON
                // cancel would corrupt credential framing. Close only this
                // job's stdin and use its pinned owned process group instead.
                if !inputClosed { channels.closeInput(); inputClosed = true }
                process.signal(SIGTERM); terminatedAt = instant
            }
        }
        while true {
            var validatedActivityInPass = false
            let now = uptime()
            let isRunning = try process.isRunning()
            if !isRunning && exitedAt == nil { exitedAt = now }
            if cancellation.isCancelled && cancelledAt == nil {
                requestCancellation(at: now)
            }
            if let cancelledAt, isRunning, now - cancelledAt >= timeouts.cancellationGrace, terminatedAt == nil {
                process.signal(SIGTERM)
                terminatedAt = now
            }
            if let terminatedAt, isRunning, now - terminatedAt >= timeouts.terminationGrace {
                process.signal(SIGKILL)
            }
            if outputEOF && errorEOF && !isRunning { break }
            var polling = [
                pollfd(fd: outputEOF ? -1 : stdoutFD, events: Int16(POLLIN), revents: 0),
                pollfd(fd: errorEOF ? -1 : stderrFD, events: Int16(POLLIN), revents: 0),
                pollfd(fd: inputClosed || !input.hasPendingBytes ? -1 : stdinFD, events: Int16(POLLOUT), revents: 0)
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
                for _ in 0..<maximumReadPasses {
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if count > 0 {
                        if index == 0 {
                            let data = Data(buffer.prefix(count))
                            let previousSequence = stream.nextSequence
                            try stream.receive(data, progress: progress)
                            // Partial bytes are not a heartbeat. Only validated
                            // complete protocol frames refresh the stage timer.
                            if stream.nextSequence > previousSequence {
                                lastActivity = uptime()
                                validatedActivityInPass = true
                            }
                        } else if operation != "extract-efs" && stderr.count < EngineValidation.stderrLimit {
                            let data = Data(buffer.prefix(count))
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
            // Buffered, complete frames may already be waiting after this
            // worker was descheduled. Validate that bounded tail before using
            // a fresh clock to decide whether the helper stopped reporting.
            let afterDrain = uptime()
            let runningAfterDrain = try process.isRunning()
            if !runningAfterDrain && exitedAt == nil { exitedAt = afterDrain }
            let terminalAndExited = stream.outcome.status != nil && !runningAfterDrain
            if cancelledAt == nil && timeoutError == nil && !terminalAndExited {
                if !stream.receivedHello && afterDrain - started > timeouts.startup {
                    timeoutError = .timeout("The native engine did not send hello before its startup deadline.")
                } else if stream.receivedHello && afterDrain - lastActivity > timeouts.inactivity {
                    timeoutError = .timeout("The native engine stopped reporting activity before its stage deadline.")
                }
                if timeoutError != nil {
                    requestCancellation(at: afterDrain)
                }
            }
            // Progress callbacks can request cancellation during the drain.
            // Observe that request before another credential segment write.
            if cancellation.isCancelled && cancelledAt == nil { requestCancellation(at: afterDrain) }
            // A worker can be descheduled after observing process exit while
            // the final bytes/EOF are already waiting in its pipes. Drain them
            // before applying the descendant guard; elapsed wall time alone
            // cannot establish that an output writer is still alive.
            try EnginePipeExitDeadline.validate(
                exitedAt: exitedAt, now: afterDrain,
                stdoutFD: outputEOF ? nil : stdoutFD,
                stderrFD: errorEOF ? nil : stderrFD
            )
            if stream.outcome.status != nil && !inputClosed {
                channels.closeInput(); inputClosed = true
            }
            if !inputClosed && polling[2].revents != 0 {
                if polling[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                    channels.closeInput(); inputClosed = true
                } else {
                    do { try input.writeNext(to: stdinFD, using: inputWriteForTesting) }
                    catch EngineInputTransport.WriteFailure.closedPipe {
                        channels.closeInput(); inputClosed = true
                    }
                    catch {
                        throw error
                    }
                }
            }
            // The per-call test checkpoint is outside this pass's read loop:
            // any frames released here can only be drained on the next pass.
            if validatedActivityInPass { afterValidatedActivityForTesting?() }
        }
        if let timeoutError { throw timeoutError }
        if cancellation.isCancelled { throw CancellationError() }
        for (index, source) in identities.enumerated() {
            guard source.matches(try FileAccess.identity(of: descriptors[index])) else { throw EngineError.sourceChanged }
        }
        try EngineClient.verifySources(identities)
        return try stream.finish(exitStatus: process.terminationStatus, stderr: stderr)
    }

    private func uptime() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }

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
