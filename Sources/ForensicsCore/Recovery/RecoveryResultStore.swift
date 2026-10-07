import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func recoveryFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// Immutable recovery generations. Filesystem metadata is deliberately absent:
/// these are signature candidates bound to the selected RAW container hash.
public enum RecoveryResultStore {
    private static let maximumResultBytes: Int64 = 32 * 1_048_576
    private static let maximumJobs = 1_000

    /// Live recovery services use prePublicationValidation to recheck pinned
    /// evidence after lock waiting and candidate copying, immediately before
    /// publication. Historical imports can omit this callback; the stored hash
    /// binding itself does not claim that an offline RAW source was revalidated.
    public static func save(result: CarvingResult, artifactFiles: [UUID: URL], in forensicCase: ForensicCase,
        prePublicationValidation: @escaping @Sendable () throws -> Void = {}) throws {
        try Task.checkCancellation(); try result.validate()
        guard Set(artifactFiles.keys) == Set(result.artifacts.map(\.id)),
              forensicCase.manifest.id == result.caseID else { throw RecoveryError.scopeMismatch }
        let bytes = try encode(result)
        try withCase(forensicCase.bundleURL, write: true) { root, bundle, manifest, validateCase in
            try validateBinding(result, manifest: manifest)
            let sourcePaths = try canonicalSourcePaths(manifest)
            let recovery = try directory("recovery", parent: root, create: true)
            defer { Darwin.close(recovery) }
            let evidenceName = name(result.sourceEvidenceID)
            let evidence = try directory(evidenceName, parent: recovery, create: true)
            defer { Darwin.close(evidence) }
            let validate = {
                try validateCase()
                try validateReference("recovery", parent: root, descriptor: recovery, kind: S_IFDIR)
                try validateReference(evidenceName, parent: recovery, descriptor: evidence, kind: S_IFDIR)
            }
            try validate()
            let transaction = try RecoveryGenerationTransaction(parent: evidence)
            defer { transaction.cleanup() }
            var inputs: [(URL, SourceIdentity)] = []
            for artifact in result.artifacts {
                try Task.checkCancellation()
                guard let supplied = artifactFiles[artifact.id] else { throw RecoveryError.invalidResult }
                let inputURL = try strictURL(supplied)
                // A generation must never use its own case storage or the RAW
                // source as an input payload, even if a malicious DTO matches it.
                guard !isInsideCanonical(inputURL, directory: bundle),
                      !sourcePaths.contains(inputURL.path) else {
                    throw RecoveryError.scopeMismatch
                }
                let input = try PinnedRecoveryFile(url: inputURL)
                defer { input.close() }
                let output = try transaction.newPayload(name(artifact.id))
                defer { Darwin.close(output) }
                let copiedIdentity = try copyVerified(input: input, output: output, artifact: artifact)
                transaction.claimPayload(name(artifact.id), identity: copiedIdentity)
                inputs.append((inputURL, input.identity))
            }
            try transaction.writeResult(bytes)
            try Task.checkCancellation(); try validate()
            for (url, identity) in inputs {
                try Task.checkCancellation()
                let current = try PinnedRecoveryFile(url: url)
                defer { current.close() }
                guard current.identity == identity else { throw RecoveryError.artifactChanged }
                try current.validate()
            }
            try Task.checkCancellation()
            try transaction.publish(as: name(result.jobID), validate: validate,
                prePublicationValidation: prePublicationValidation)
        }
    }

    /// Loads bounded metadata and validates every stored payload's identity and
    /// size. Payload hashes are independently checked when bytes are accessed.
    /// The original RAW image need not be online to read historical results.
    public static func load(jobID: UUID, evidenceID: UUID, in caseURL: URL) throws -> CarvingResult? {
        try withCase(caseURL, write: false) { root, _, manifest, validate in
            try withEvidence(evidenceID, root: root, validateCase: validate) { evidence, validateEvidence in
                guard evidence >= 0 else { return nil }
                return try loadGeneration(jobID, evidenceID: evidenceID, evidence: evidence,
                    manifest: manifest, validate: validateEvidence)
            }
        }
    }

    /// Corrupt or unexpected generation names are diagnostic errors. They are
    /// never silently skipped in favor of an apparently healthy older result.
    public static func latest(evidenceID: UUID, in caseURL: URL) throws -> CarvingResult? {
        try withCase(caseURL, write: false) { root, _, manifest, validate in
            try withEvidence(evidenceID, root: root, validateCase: validate) { evidence, validateEvidence in
                guard evidence >= 0 else { return nil }
                var latest: CarvingResult?
                var count = 0
                try eachName(in: evidence) { filename in
                    // Only our private staging namespace is excluded. A crashed
                    // transaction can leave a staging directory for diagnosis.
                    if filename.hasPrefix(".recovery-"), filename.hasSuffix(".tmp") { return }
                    count += 1
                    guard count <= maximumJobs, let id = UUID(uuidString: filename), filename == name(id) else {
                        throw RecoveryError.invalidResult
                    }
                    guard let result = try loadGeneration(id, evidenceID: evidenceID, evidence: evidence,
                        manifest: manifest, validate: validateEvidence) else { throw RecoveryError.storageChanged }
                    if latest == nil || result.savedAt > latest!.savedAt ||
                        (result.savedAt == latest!.savedAt && name(result.jobID) > name(latest!.jobID)) {
                        latest = result
                    }
                }
                try validateEvidence()
                return latest
            }
        }
    }

    /// This URL is verified at return time, not a descriptor lease. Decoders
    /// should use readArtifact (or export to owned scratch) instead of reopening
    /// this pathname after another process could have changed case storage.
    public static func artifactURL(artifact: CarvedArtifact, result: CarvingResult, in caseURL: URL) throws -> URL {
        try withArtifact(artifact, result: result, in: caseURL) { input, url, validate in
            try verify(input: input, artifact: artifact)
            try validate(); return url
        }
    }

    public static func readArtifact(artifact: CarvedArtifact, result: CarvingResult,
                                    in caseURL: URL, maximumBytes: Int64) throws -> Data {
        guard maximumBytes >= 0, maximumBytes <= 536_870_912, artifact.byteCount <= maximumBytes else {
            throw RecoveryError.outputLimit
        }
        return try withArtifact(artifact, result: result, in: caseURL) { input, _, validate in
            var data = Data(); data.reserveCapacity(Int(artifact.byteCount))
            try verify(input: input, artifact: artifact) { data.append($0) }
            try validate(); return data
        }
    }

    public static func export(artifact: CarvedArtifact, result: CarvingResult,
                              in caseURL: URL, to outputURL: URL) throws -> ExtractionResult {
        try export(artifact: artifact, result: result, in: caseURL, to: outputURL, afterPublication: {})
    }

    /// Internal observer makes the cancellation/atomic-publication boundary
    /// deterministic in regression tests; it cannot throw or alter the commit.
    static func export(artifact: CarvedArtifact, result: CarvingResult,
        in caseURL: URL, to outputURL: URL, afterPublication: @Sendable () -> Void) throws -> ExtractionResult {
        try withArtifact(artifact, result: result, in: caseURL, revalidateAfterBody: false) { input, _, validate in
            let destination = try strictURL(outputURL)
            let bundle = try strictURL(caseURL)
            guard !isInsideCanonical(destination, directory: bundle) else { throw RecoveryError.scopeMismatch }
            let forensicCase = try CaseStore.open(at: bundle)
            let sourcePaths = try canonicalSourcePaths(forensicCase.manifest)
            guard !sourcePaths.contains(destination.path) else {
                throw RecoveryError.scopeMismatch
            }
            let transaction = try RecoveryExportTransaction(destination: destination)
            defer { transaction.cleanup() }
            let copiedIdentity = try copyVerified(input: input, output: transaction.output, artifact: artifact)
            transaction.claimOutput(identity: copiedIdentity)
            try Task.checkCancellation(); try validate()
            try transaction.publish(validate: validate, afterPublication: afterPublication)
            return ExtractionResult(outputPath: destination.path, byteCount: artifact.byteCount, sha256: artifact.sha256)
        }
    }

    private static func withArtifact<T>(_ artifact: CarvedArtifact, result: CarvingResult, in caseURL: URL,
        revalidateAfterBody: Bool = true,
        body: (PinnedRecoveryFile, URL, () throws -> Void) throws -> T) throws -> T {
        try result.validate()
        guard result.artifacts.first(where: { $0.id == artifact.id }) == artifact else { throw RecoveryError.scopeMismatch }
        return try withCase(caseURL, write: false) { root, bundle, manifest, validateCase in
            try validateBinding(result, manifest: manifest)
            return try withEvidence(result.sourceEvidenceID, root: root, validateCase: validateCase) { evidence, validateEvidence in
                guard evidence >= 0 else { throw RecoveryError.invalidResult }
                let generation = try directory(name(result.jobID), parent: evidence, create: false)
                guard generation >= 0 else { throw RecoveryError.invalidResult }
                defer { Darwin.close(generation) }
                let stored = try readResult(in: generation)
                guard stored == result else { throw RecoveryError.scopeMismatch }
                let files = try directory("files", parent: generation, create: false)
                guard files >= 0 else { throw RecoveryError.invalidResult }
                defer { Darwin.close(files) }
                let input = try PinnedRecoveryFile(name: name(artifact.id), parent: files)
                defer { input.close() }
                let validate = {
                    try validateEvidence()
                    try validateReference(name(result.jobID), parent: evidence, descriptor: generation, kind: S_IFDIR)
                    try validateReference("files", parent: generation, descriptor: files, kind: S_IFDIR)
                    try input.validate()
                    guard try readResult(in: generation) == result else { throw RecoveryError.storageChanged }
                }
                try validate()
                let url = bundle.appendingPathComponent("recovery", isDirectory: true)
                    .appendingPathComponent(name(result.sourceEvidenceID), isDirectory: true)
                    .appendingPathComponent(name(result.jobID), isDirectory: true)
                    .appendingPathComponent(artifact.relativePath)
                let value = try body(input, url, validate)
                // Exports already passed this cancellable check immediately
                // before their atomic rename. A cancellation after commit must
                // return the receipt, not reread metadata and discard success.
                if revalidateAfterBody { try validate() }
                return value
            }
        }
    }

    private static func loadGeneration(_ jobID: UUID, evidenceID: UUID, evidence: Int32,
        manifest: CaseManifest, validate: () throws -> Void) throws -> CarvingResult? {
        let generation = try directory(name(jobID), parent: evidence, create: false)
        guard generation >= 0 else { return nil }
        defer { Darwin.close(generation) }
        let result = try readResult(in: generation)
        guard result.jobID == jobID, result.sourceEvidenceID == evidenceID else { throw RecoveryError.scopeMismatch }
        try validateBinding(result, manifest: manifest)
        let files = try directory("files", parent: generation, create: false)
        guard files >= 0 else { throw RecoveryError.invalidResult }
        defer { Darwin.close(files) }
        let expectedNames = Set(result.artifacts.map { name($0.id) })
        var names = Set<String>()
        try eachName(in: files) { filename in
            guard names.count < result.options.maximumFiles, names.insert(filename).inserted,
                  expectedNames.contains(filename) else { throw RecoveryError.invalidResult }
        }
        guard names == expectedNames else { throw RecoveryError.invalidResult }
        for artifact in result.artifacts {
            try Task.checkCancellation()
            let input = try PinnedRecoveryFile(name: name(artifact.id), parent: files)
            defer { input.close() }
            guard input.identity.size == artifact.byteCount else { throw RecoveryError.artifactChanged }
            try input.validate()
        }
        var generationNames = Set<String>()
        try eachName(in: generation) { generationNames.insert($0) }
        guard generationNames == ["files", "result.json"] else { throw RecoveryError.invalidResult }
        try validate()
        try validateReference(name(jobID), parent: evidence, descriptor: generation, kind: S_IFDIR)
        try validateReference("files", parent: generation, descriptor: files, kind: S_IFDIR)
        guard try readResult(in: generation) == result else { throw RecoveryError.storageChanged }
        return result
    }

    private static func withEvidence<T>(_ evidenceID: UUID, root: Int32, validateCase: @escaping () throws -> Void,
        body: (Int32, @escaping () throws -> Void) throws -> T) throws -> T {
        let recovery = try directory("recovery", parent: root, create: false)
        guard recovery >= 0 else { return try body(-1, validateCase) }
        defer { Darwin.close(recovery) }
        let evidence = try directory(name(evidenceID), parent: recovery, create: false)
        guard evidence >= 0 else {
            try validateCase()
            try validateReference("recovery", parent: root, descriptor: recovery, kind: S_IFDIR)
            return try body(-1, validateCase)
        }
        defer { Darwin.close(evidence) }
        let validate = {
            try validateCase()
            try validateReference("recovery", parent: root, descriptor: recovery, kind: S_IFDIR)
            try validateReference(name(evidenceID), parent: recovery, descriptor: evidence, kind: S_IFDIR)
        }
        try validate(); let value = try body(evidence, validate); try validate(); return value
    }

    private static func withCase<T>(_ caseURL: URL, write: Bool,
        body: (Int32, URL, CaseManifest, @escaping () throws -> Void) throws -> T) throws -> T {
        try Task.checkCancellation()
        let bundle = try strictURL(caseURL)
        guard bundle.pathExtension == CaseStore.bundleExtension else { throw RecoveryError.invalidCase }
        let root = try openAbsoluteDirectory(bundle)
        defer { Darwin.close(root) }
        let lock = try PinnedRecoveryFile(name: ".case.lock", parent: root)
        defer { lock.close() }
        while recoveryFlock(lock.descriptor, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock recovery storage") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = recoveryFlock(lock.descriptor, LOCK_UN) }
        try Task.checkCancellation()
        let manifestFile = try PinnedRecoveryFile(name: "manifest.json", parent: root)
        defer { manifestFile.close() }
        guard manifestFile.identity.size <= 16 * 1_048_576 else { throw RecoveryError.invalidCase }
        let manifestBytes = try readBounded(manifestFile, maximum: 16 * 1_048_576)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let manifest: CaseManifest
        do { manifest = try decoder.decode(CaseManifest.self, from: manifestBytes) }
        catch { throw RecoveryError.invalidCase }
        // Reuse case schema/path validation, but require the decoded manifest
        // to equal the independently pinned manifest read above.
        guard try CaseStore.open(at: bundle).manifest == manifest else { throw RecoveryError.storageChanged }
        let validate = {
            try validateAbsoluteDirectory(bundle, descriptor: root)
            try lock.validate(); try manifestFile.validate()
        }
        try validate()
        let value = try body(root, bundle, manifest, validate)
        try validate(); return value
    }

    private static func validateBinding(_ result: CarvingResult, manifest: CaseManifest) throws {
        guard result.caseID == manifest.id,
              let evidence = manifest.evidence.first(where: { $0.id == result.sourceEvidenceID }),
              evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.sha256 == result.sourceSHA256, evidence.byteCount == result.sourceByteCount else {
            throw RecoveryError.scopeMismatch
        }
    }

    private static func encode(_ result: CarvingResult) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(result)
        guard Int64(bytes.count) <= maximumResultBytes else { throw RecoveryError.outputLimit }
        return bytes
    }

    private static func readResult(in generation: Int32) throws -> CarvingResult {
        let input = try PinnedRecoveryFile(name: "result.json", parent: generation)
        defer { input.close() }
        let bytes = try readBounded(input, maximum: maximumResultBytes)
        let result: CarvingResult
        do { result = try JSONDecoder().decode(CarvingResult.self, from: bytes) }
        catch { throw RecoveryError.invalidResult }
        try result.validate(); return result
    }

    private static func readBounded(_ input: PinnedRecoveryFile, maximum: Int64) throws -> Data {
        guard input.identity.size <= maximum else { throw RecoveryError.outputLimit }
        var bytes = Data(); bytes.reserveCapacity(Int(input.identity.size))
        try stream(input) { bytes.append($0) }
        return bytes
    }

    private static func copyVerified(input: PinnedRecoveryFile, output: Int32, artifact: CarvedArtifact) throws -> SourceIdentity {
        try verify(input: input, artifact: artifact) { try write($0, to: output) }
        guard Darwin.fsync(output) == 0 else { throw FileAccess.posixError("Cannot flush recovered bytes") }
        let identity = try FileAccess.identity(of: output)
        guard identity.size == artifact.byteCount else { throw RecoveryError.artifactChanged }
        // The input digest alone does not prove the staged output bytes. Read
        // back the held output descriptor before claiming this immutable leaf.
        guard Darwin.lseek(output, 0, SEEK_SET) == 0 else { throw RecoveryError.artifactChanged }
        var hash = SHA256(), count: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while count < identity.size {
            try Task.checkCancellation()
            let amount = Int(min(Int64(buffer.count), identity.size - count))
            let read = try buffer.withUnsafeMutableBytes { try FileAccess.read(output, into: $0, count: amount) }
            guard read > 0 else { throw RecoveryError.artifactChanged }
            hash.update(data: Data(buffer.prefix(read))); count += Int64(read)
        }
        guard try FileAccess.identity(of: output) == identity,
              hash.finalize().map({ String(format: "%02x", $0) }).joined() == artifact.sha256 else {
            throw RecoveryError.artifactChanged
        }
        return identity
    }

    private static func verify(input: PinnedRecoveryFile, artifact: CarvedArtifact,
                               consume: (Data) throws -> Void = { _ in }) throws {
        guard input.identity.size == artifact.byteCount else { throw RecoveryError.artifactChanged }
        var hash = SHA256()
        try stream(input) { bytes in hash.update(data: bytes); try consume(bytes) }
        guard hash.finalize().map({ String(format: "%02x", $0) }).joined() == artifact.sha256 else {
            throw RecoveryError.artifactChanged
        }
    }

    private static func stream(_ input: PinnedRecoveryFile, consume: (Data) throws -> Void) throws {
        guard Darwin.lseek(input.descriptor, 0, SEEK_SET) == 0 else { throw RecoveryError.artifactChanged }
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        var count: Int64 = 0
        while count < input.identity.size {
            try Task.checkCancellation()
            let amount = Int(min(Int64(buffer.count), input.identity.size - count))
            let read = try buffer.withUnsafeMutableBytes { try FileAccess.read(input.descriptor, into: $0, count: amount) }
            guard read > 0 else { throw RecoveryError.artifactChanged }
            try consume(Data(buffer.prefix(read))); count += Int64(read)
        }
        try input.validate(); try Task.checkCancellation()
    }

    fileprivate static func write(_ bytes: Data, to descriptor: Int32) throws {
        try bytes.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                try Task.checkCancellation()
                let amount = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: written), buffer.count - written)
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw FileAccess.posixError("Cannot write recovered bytes") }
                written += amount
            }
        }
    }

    private static func name(_ id: UUID) -> String { id.uuidString.lowercased() }

    /// Inputs to this comparison already passed strictURL. Standardizing them
    /// again can collapse only the existing /private/var side to /var while a
    /// not-yet-created output remains /private/var, defeating containment.
    private static func isInsideCanonical(_ source: URL, directory: URL) -> Bool {
        source.path == directory.path || source.path.hasPrefix(directory.path + "/")
    }

    private static func canonicalSourcePaths(_ manifest: CaseManifest) throws -> Set<String> {
        try Set(manifest.evidence.map { try strictURL(URL(fileURLWithPath: $0.sourcePath)).path })
    }

    fileprivate static func strictURL(_ url: URL) throws -> URL {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw RecoveryError.storageChanged }
        let path = url.standardizedFileURL.path
        // Foundation can normalize /private/var back to /var. Admit only
        // macOS's two verified system aliases; the openat walk still refuses
        // every user-created intermediate or final symlink.
        for alias in ["tmp", "var"] {
            let prefix = "/" + alias
            if path == prefix || path.hasPrefix(prefix + "/") {
                var metadata = stat()
                if Darwin.lstat(prefix, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFLNK {
                    var buffer = [CChar](repeating: 0, count: 1_024)
                    let amount = Darwin.readlink(prefix, &buffer, buffer.count - 1)
                    guard amount > 0, amount < buffer.count - 1 else { throw RecoveryError.storageChanged }
                    let target = String(decoding: buffer.prefix(amount).map { UInt8(bitPattern: $0) }, as: UTF8.self)
                    guard target == "private/" + alias || target == "/private/" + alias else {
                        throw RecoveryError.storageChanged
                    }
                    return URL(fileURLWithPath: "/private/" + alias + path.dropFirst(prefix.count),
                        isDirectory: url.hasDirectoryPath)
                }
            }
        }
        return URL(fileURLWithPath: path, isDirectory: url.hasDirectoryPath)
    }

    /// Walk components with openat/O_NOFOLLOW; checking only the final path
    /// component would let a swapped intermediate symlink redirect the read.
    fileprivate static func openAbsoluteDirectory(_ url: URL) throws -> Int32 {
        let canonical = try strictURL(url)
        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw RecoveryError.storageChanged }
        do {
            for component in canonical.pathComponents.dropFirst() {
                let next = Darwin.openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw RecoveryError.storageChanged }
                Darwin.close(current); current = next
            }
            return current
        } catch { Darwin.close(current); throw error }
    }

    fileprivate static func validateAbsoluteDirectory(_ url: URL, descriptor: Int32) throws {
        let current = try openAbsoluteDirectory(url)
        defer { Darwin.close(current) }
        var lhs = stat(), rhs = stat()
        guard Darwin.fstat(current, &lhs) == 0, Darwin.fstat(descriptor, &rhs) == 0,
              lhs.st_dev == rhs.st_dev, lhs.st_ino == rhs.st_ino else { throw RecoveryError.storageChanged }
    }

    fileprivate static func directory(_ name: String, parent: Int32, create: Bool) throws -> Int32 {
        if create && Darwin.mkdirat(parent, name, mode_t(0o700)) != 0 && errno != EEXIST {
            throw FileAccess.posixError("Cannot create recovery directory")
        }
        let descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if !create && errno == ENOENT { return -1 }
            throw RecoveryError.storageChanged
        }
        do { try validateReference(name, parent: parent, descriptor: descriptor, kind: S_IFDIR); return descriptor }
        catch { Darwin.close(descriptor); throw error }
    }

    fileprivate static func referenceMatches(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var current = stat(), opened = stat()
        return Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0 && Darwin.fstat(descriptor, &opened) == 0
            && current.st_mode & S_IFMT == kind && opened.st_mode & S_IFMT == kind
            && current.st_dev == opened.st_dev && current.st_ino == opened.st_ino
    }

    fileprivate static func validateReference(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) throws {
        guard referenceMatches(name, parent: parent, descriptor: descriptor, kind: kind) else { throw RecoveryError.storageChanged }
    }

    private static func eachName(in directory: Int32, body: (String) throws -> Void) throws {
        let scan = Darwin.openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard scan >= 0 else { throw RecoveryError.storageChanged }
        guard let stream = Darwin.fdopendir(scan) else { Darwin.close(scan); throw RecoveryError.storageChanged }
        defer { Darwin.closedir(stream) }
        var scanned = 0
        while true {
            try Task.checkCancellation(); errno = 0
            guard let entry = Darwin.readdir(stream) else {
                guard errno == 0 else { throw RecoveryError.storageChanged }; break
            }
            let filename = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if filename == "." || filename == ".." { continue }
            scanned += 1
            guard scanned <= 6_000 else { throw RecoveryError.outputLimit }
            try body(filename)
        }
    }
}

private final class PinnedRecoveryFile {
    let descriptor: Int32
    let identity: SourceIdentity
    private let parent: Int32
    private let filename: String
    private let parentURL: URL?
    private var closed = false

    convenience init(url: URL) throws {
        let canonical = try RecoveryResultStore.strictURL(url)
        let parentURL = canonical.deletingLastPathComponent()
        let parent = try RecoveryResultStore.openAbsoluteDirectory(parentURL)
        do { try self.init(name: canonical.lastPathComponent, parent: parent, parentURL: parentURL) }
        catch { Darwin.close(parent); throw error }
        Darwin.close(parent)
    }

    convenience init(name: String, parent: Int32) throws { try self.init(name: name, parent: parent, parentURL: nil) }

    private init(name: String, parent: Int32, parentURL: URL?) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw RecoveryError.storageChanged
        }
        self.parent = Darwin.fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard self.parent >= 0 else { throw RecoveryError.storageChanged }
        self.filename = name; self.parentURL = parentURL
        descriptor = Darwin.openat(self.parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { Darwin.close(self.parent); throw RecoveryError.storageChanged }
        do {
            identity = try FileAccess.identity(of: descriptor)
            var metadata = stat()
            guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1 else { throw RecoveryError.storageChanged }
            try validate()
        } catch {
            // A throw after all stored properties are initialized can execute
            // deinit; mark ownership released before closing the descriptors.
            closed = true
            Darwin.close(descriptor); Darwin.close(self.parent); throw error
        }
    }

    func validate() throws {
        guard try FileAccess.identity(of: descriptor) == identity,
              (try? FileAccess.identity(at: filename, in: parent)) == identity else { throw RecoveryError.artifactChanged }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1 else { throw RecoveryError.storageChanged }
        if let parentURL { try RecoveryResultStore.validateAbsoluteDirectory(parentURL, descriptor: parent) }
    }

    func close() {
        guard !closed else { return }; closed = true
        Darwin.close(descriptor); Darwin.close(parent)
    }
    deinit { close() }
}

private final class RecoveryGenerationTransaction {
    private let parent: Int32
    private let generation: Int32
    private let files: Int32
    private var currentName: String
    private var leaves: [(String, SourceIdentity)] = []
    private var resultIdentity: SourceIdentity?
    private var committed = false
    private var cleaned = false

    init(parent: Int32) throws {
        self.parent = Darwin.fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard self.parent >= 0 else { throw RecoveryError.storageChanged }
        currentName = ".recovery-\(UUID().uuidString.lowercased()).tmp"
        guard Darwin.mkdirat(self.parent, currentName, mode_t(0o700)) == 0 else {
            Darwin.close(self.parent); throw FileAccess.posixError("Cannot create recovery staging directory")
        }
        var created = stat()
        guard Darwin.fstatat(self.parent, currentName, &created, AT_SYMLINK_NOFOLLOW) == 0,
              created.st_mode & S_IFMT == S_IFDIR else {
            Darwin.close(self.parent); throw RecoveryError.storageChanged
        }
        generation = Darwin.openat(self.parent, currentName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard generation >= 0 else { Darwin.close(self.parent); throw RecoveryError.storageChanged }
        do {
            try RecoveryResultStore.validateReference(currentName, parent: self.parent, descriptor: generation, kind: S_IFDIR)
            var opened = stat()
            guard Darwin.fstat(generation, &opened) == 0, opened.st_dev == created.st_dev,
                  opened.st_ino == created.st_ino else { throw RecoveryError.storageChanged }
            files = try RecoveryResultStore.directory("files", parent: generation, create: true)
        } catch {
            if RecoveryResultStore.referenceMatches(currentName, parent: self.parent, descriptor: generation, kind: S_IFDIR) {
                _ = Darwin.unlinkat(self.parent, currentName, AT_REMOVEDIR)
            }
            Darwin.close(generation); Darwin.close(self.parent); throw error
        }
    }

    func newPayload(_ name: String) throws -> Int32 {
        let output = Darwin.openat(files, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { throw RecoveryError.storageChanged }
        do { leaves.append((name, try FileAccess.identity(of: output))); return output }
        catch { Darwin.close(output); throw error }
    }

    func claimPayload(_ name: String, identity: SourceIdentity) {
        if let index = leaves.firstIndex(where: { $0.0 == name }) { leaves[index] = (name, identity) }
    }

    func writeResult(_ bytes: Data) throws {
        let output = Darwin.openat(generation, "result.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { throw RecoveryError.storageChanged }
        defer { Darwin.close(output) }
        resultIdentity = try FileAccess.identity(of: output)
        try RecoveryResultStore.write(bytes, to: output)
        guard Darwin.fsync(output) == 0, Darwin.fsync(files) == 0, Darwin.fsync(generation) == 0 else {
            throw FileAccess.posixError("Cannot flush recovery generation")
        }
        resultIdentity = try FileAccess.identity(of: output)
    }

    func publish(as name: String, validate: () throws -> Void, prePublicationValidation: () throws -> Void) throws {
        // A scan's earlier source check is insufficient if this transaction
        // waited for .case.lock or copied gigabytes of candidates afterwards.
        // Invoke the service's pinned-source revalidation once at this boundary,
        // then repeat the inexpensive directory/leaf guards before rename.
        try Task.checkCancellation()
        try prePublicationValidation()
        try validate()
        try RecoveryResultStore.validateReference(currentName, parent: parent, descriptor: generation, kind: S_IFDIR)
        try RecoveryResultStore.validateReference("files", parent: generation, descriptor: files, kind: S_IFDIR)
        for (name, identity) in leaves {
            guard (try? FileAccess.identity(at: name, in: files)) == identity else { throw RecoveryError.artifactChanged }
        }
        guard let resultIdentity,
              (try? FileAccess.identity(at: "result.json", in: generation)) == resultIdentity else {
            throw RecoveryError.storageChanged
        }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, currentName, parent, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw RecoveryError.destinationExists }
            throw FileAccess.posixError("Cannot publish recovery generation")
        }
        currentName = name
        // The exclusive rename committed the complete immutable generation.
        // Later durability/path errors must preserve its published contents.
        committed = true
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush recovery directory") }
        try validate()
        try RecoveryResultStore.validateReference(currentName, parent: parent, descriptor: generation, kind: S_IFDIR)
        try RecoveryResultStore.validateReference("files", parent: generation, descriptor: files, kind: S_IFDIR)
        for (name, identity) in leaves {
            guard (try? FileAccess.identity(at: name, in: files)) == identity else { throw RecoveryError.artifactChanged }
        }
        guard (try? FileAccess.identity(at: "result.json", in: generation)) == resultIdentity else {
            throw RecoveryError.storageChanged
        }
        // No cancellation after the atomic commit: save must return its receipt.
    }

    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        if !committed {
            // Remove only leaves whose inode we created. Unknown content or a
            // replacement name is preserved; no recursive path deletion occurs.
            for (name, identity) in leaves { removeOwned(name, in: files, identity: identity) }
            if let identity = resultIdentity { removeOwned("result.json", in: generation, identity: identity) }
            if RecoveryResultStore.referenceMatches("files", parent: generation, descriptor: files, kind: S_IFDIR) {
                _ = Darwin.unlinkat(generation, "files", AT_REMOVEDIR)
            }
            if RecoveryResultStore.referenceMatches(currentName, parent: parent, descriptor: generation, kind: S_IFDIR) {
                _ = Darwin.unlinkat(parent, currentName, AT_REMOVEDIR)
            }
        }
        Darwin.close(files); Darwin.close(generation); Darwin.close(parent)
    }

    private func removeOwned(_ name: String, in directory: Int32, identity: SourceIdentity) {
        var metadata = stat()
        if Darwin.fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
           metadata.st_mode & S_IFMT == S_IFREG, metadata.st_dev == identity.device, metadata.st_ino == identity.inode {
            _ = Darwin.unlinkat(directory, name, 0)
        }
    }
    deinit { cleanup() }
}

private final class RecoveryExportTransaction {
    let output: Int32
    private let parent: Int32
    private let destination: URL
    private let stagingName: String
    private let initialIdentity: SourceIdentity
    private var copiedIdentity: SourceIdentity?
    private var published = false
    private var committed = false
    private var cleaned = false

    init(destination: URL) throws {
        self.destination = destination
        parent = try RecoveryResultStore.openAbsoluteDirectory(destination.deletingLastPathComponent())
        var existing = stat()
        if Darwin.fstatat(parent, destination.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            Darwin.close(parent); throw RecoveryError.destinationExists
        }
        guard errno == ENOENT else { Darwin.close(parent); throw RecoveryError.storageChanged }
        stagingName = ".recovery-export-\(UUID().uuidString.lowercased()).tmp"
        output = Darwin.openat(parent, stagingName, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { Darwin.close(parent); throw RecoveryError.storageChanged }
        do { initialIdentity = try FileAccess.identity(of: output) }
        catch { Darwin.close(output); Darwin.close(parent); throw error }
    }

    func claimOutput(identity: SourceIdentity) { copiedIdentity = identity }

    func publish(validate: () throws -> Void, afterPublication: () -> Void) throws {
        try validate()
        try RecoveryResultStore.validateAbsoluteDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        try RecoveryResultStore.validateReference(stagingName, parent: parent, descriptor: output, kind: S_IFREG)
        guard let copiedIdentity, try FileAccess.identity(of: output) == copiedIdentity else {
            throw RecoveryError.artifactChanged
        }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, stagingName, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw RecoveryError.destinationExists }
            throw FileAccess.posixError("Cannot publish recovered export")
        }
        published = true
        committed = true
        afterPublication()
        // Rename committed the complete export. From here no cancellation
        // checks or cancellable record reads may roll it back or hide success.
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush recovered export directory") }
        try RecoveryResultStore.validateAbsoluteDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        try RecoveryResultStore.validateReference(destination.lastPathComponent, parent: parent, descriptor: output, kind: S_IFREG)
    }

    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        if !committed {
            let name = published ? destination.lastPathComponent : stagingName
            var current = stat()
            if Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
               current.st_mode & S_IFMT == S_IFREG, current.st_dev == initialIdentity.device,
               current.st_ino == initialIdentity.inode { _ = Darwin.unlinkat(parent, name, 0) }
        }
        Darwin.close(output); Darwin.close(parent)
    }
    deinit { cleanup() }
}
