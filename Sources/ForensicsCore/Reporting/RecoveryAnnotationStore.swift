import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func annotationFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// A reviewer assessment is an immutable revision, separate from recovered
/// bytes and the recovery tool's findings. Digests bind its original context.
public struct RecoveryAnnotationRevision: Codable, Sendable, Equatable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let revision: Int
    public let previousRevisionID: UUID?
    public let annotation: RecoveryAnnotation
    public let resultSHA256: String
    /// Digest of the pinned manifest bytes when saved. This is historical
    /// recorded provenance: the current manifest may gain unrelated evidence,
    /// so reads revalidate the evidence binding rather than this whole digest.
    public let manifestSHA256: String
    public let caseID: UUID
    public let evidenceID: UUID
    public let jobID: UUID
    public let savedAt: Date

    public init(schemaVersion: Int = 1, id: UUID = UUID(), revision: Int,
                previousRevisionID: UUID?, annotation: RecoveryAnnotation,
                resultSHA256: String, manifestSHA256: String, caseID: UUID,
                evidenceID: UUID, jobID: UUID, savedAt: Date = Date()) {
        self.schemaVersion = schemaVersion; self.id = id; self.revision = revision
        self.previousRevisionID = previousRevisionID; self.annotation = annotation
        self.resultSHA256 = resultSHA256; self.manifestSHA256 = manifestSHA256
        self.caseID = caseID; self.evidenceID = evidenceID; self.jobID = jobID; self.savedAt = savedAt
    }

    fileprivate func validate(result: CarvingResult, digest: String) throws {
        try annotation.validate()
        guard schemaVersion == 1, (1...10_000).contains(revision),
              (revision == 1) == (previousRevisionID == nil), previousRevisionID != id,
              EngineValidation.validHash(resultSHA256), EngineValidation.validHash(manifestSHA256),
              savedAt.timeIntervalSince1970.isFinite else { throw RecoveryError.invalidResult }
        guard caseID == result.caseID, evidenceID == result.sourceEvidenceID, jobID == result.jobID,
              resultSHA256 == digest, result.artifacts.contains(where: { $0.id == annotation.artifactID }) else {
            throw RecoveryError.scopeMismatch
        }
    }
}

/// Append-only reviewer notes under recovery-notes/<evidence>/<job>/<revision>.json.
/// Reads and writes hold the existing case lock and never open evidence bytes.
public enum RecoveryAnnotationStore {
    private static let maximumRecords = 10_000
    private static let maximumRecordBytes: Int64 = 65_536
    private static let maximumResultBytes: Int64 = 32 * 1_048_576

    /// A canonical model digest, independent of JSON whitespace on disk.
    public static func resultDigest(_ result: CarvingResult) throws -> String {
        try result.validate()
        let bytes = try encode(result)
        guard Int64(bytes.count) <= maximumResultBytes else { throw RecoveryError.outputLimit }
        return digest(bytes)
    }

    @discardableResult
    public static func save(annotation: RecoveryAnnotation, result: CarvingResult,
                            in caseURL: URL) throws -> RecoveryAnnotationRevision {
        try annotation.validate(); try result.validate()
        guard result.artifacts.contains(where: { $0.id == annotation.artifactID }) else {
            throw RecoveryError.scopeMismatch
        }
        return try withContext(result: result, in: caseURL, write: true) { context in
            try withHistoryDirectory(root: context.root, result: result, create: true,
                                     validateCase: context.validate) { directory, validateDirectory in
                let snapshot = try readHistory(in: directory, result: result, digest: context.resultDigest)
                defer { snapshot.close() }
                guard snapshot.records.count < maximumRecords else { throw RecoveryError.outputLimit }
                let prior = snapshot.records.filter { $0.annotation.artifactID == annotation.artifactID }
                    .max { $0.revision < $1.revision }
                let revision = RecoveryAnnotationRevision(revision: (prior?.revision ?? 0) + 1,
                    previousRevisionID: prior?.id, annotation: annotation,
                    resultSHA256: context.resultDigest, manifestSHA256: context.manifestDigest,
                    caseID: result.caseID, evidenceID: result.sourceEvidenceID, jobID: result.jobID,
                    savedAt: max(Date(), prior?.savedAt ?? .distantPast))
                try revision.validate(result: result, digest: context.resultDigest)
                let bytes = try encode(revision)
                guard Int64(bytes.count) <= maximumRecordBytes else { throw RecoveryError.outputLimit }
                // An interrupted, uncommitted stage must not poison the
                // directory containing previously published history.
                let staging = try AnnotationStagingFile(bytes: bytes, parent: context.root)
                defer { staging.cleanup() }
                try Task.checkCancellation()
                try validateDirectory()
                try snapshot.validate(in: directory)
                try staging.publish(as: name(revision.id) + ".json", in: directory) {
                    try validateDirectory()
                    try snapshot.validate(in: directory)
                }
                return revision
            }
        }
    }

    public static func latest(result: CarvingResult, in caseURL: URL) throws -> [UUID: RecoveryAnnotation] {
        let records = try history(result: result, in: caseURL)
        var latest = [UUID: RecoveryAnnotationRevision]()
        for record in records {
            if latest[record.annotation.artifactID].map({ $0.revision < record.revision }) ?? true {
                latest[record.annotation.artifactID] = record
            }
        }
        return latest.mapValues(\.annotation)
    }

    /// Every history leaf and every per-artifact chain is validated. Malformed
    /// entries are not skipped to silently fall back to an earlier assessment.
    public static func history(result: CarvingResult, in caseURL: URL) throws -> [RecoveryAnnotationRevision] {
        try result.validate()
        return try withContext(result: result, in: caseURL, write: false) { context in
            try withHistoryDirectory(root: context.root, result: result, create: false,
                                     validateCase: context.validate) { directory, validateDirectory in
                guard directory >= 0 else { return [] }
                let snapshot = try readHistory(in: directory, result: result, digest: context.resultDigest)
                defer { snapshot.close() }
                try validateDirectory(); try snapshot.validate(in: directory)
                return snapshot.records.sorted {
                    if $0.savedAt != $1.savedAt { return $0.savedAt < $1.savedAt }
                    if $0.annotation.artifactID == $1.annotation.artifactID { return $0.revision < $1.revision }
                    return name($0.id) < name($1.id)
                }
            }
        }
    }

    private struct Context {
        let root: Int32
        let manifestDigest: String
        let resultDigest: String
        let validate: () throws -> Void
    }

    private static func withContext<T>(result: CarvingResult, in caseURL: URL, write: Bool,
                                       body: (Context) throws -> T) throws -> T {
        try Task.checkCancellation()
        let bundle = try canonicalURL(caseURL)
        guard bundle.pathExtension == CaseStore.bundleExtension else { throw RecoveryError.invalidCase }
        let root = try openAbsoluteDirectory(bundle)
        defer { Darwin.close(root) }
        let lock = try AnnotationPinnedFile(name: ".case.lock", parent: root)
        defer { lock.close() }
        while annotationFlock(lock.descriptor, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock recovery notes") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = annotationFlock(lock.descriptor, LOCK_UN) }
        try Task.checkCancellation()
        let manifestFile = try AnnotationPinnedFile(name: "manifest.json", parent: root)
        defer { manifestFile.close() }
        let manifestBytes = try manifestFile.read(maximum: 16 * 1_048_576)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let manifest: CaseManifest
        do { manifest = try decoder.decode(CaseManifest.self, from: manifestBytes) }
        catch { throw RecoveryError.invalidCase }
        guard try CaseStore.open(at: bundle).manifest == manifest else { throw RecoveryError.storageChanged }
        guard result.caseID == manifest.id,
              let evidence = manifest.evidence.first(where: { $0.id == result.sourceEvidenceID }),
              evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.sha256 == result.sourceSHA256, evidence.byteCount == result.sourceByteCount else {
            throw RecoveryError.scopeMismatch
        }

        // Pin and compare the saved job metadata directly. Calling another
        // storage API here would reacquire flock on a different descriptor.
        let recovery = try requiredDirectory("recovery", parent: root)
        defer { Darwin.close(recovery) }
        let evidenceDirectory = try requiredDirectory(name(result.sourceEvidenceID), parent: recovery)
        defer { Darwin.close(evidenceDirectory) }
        let generation = try requiredDirectory(name(result.jobID), parent: evidenceDirectory)
        defer { Darwin.close(generation) }
        let resultFile = try AnnotationPinnedFile(name: "result.json", parent: generation)
        defer { resultFile.close() }
        let resultBytes = try resultFile.read(maximum: maximumResultBytes)
        let saved: CarvingResult
        do { saved = try JSONDecoder().decode(CarvingResult.self, from: resultBytes) }
        catch { throw RecoveryError.invalidResult }
        try saved.validate()
        let expectedDigest = try resultDigest(result)
        guard try resultDigest(saved) == expectedDigest, saved == result else { throw RecoveryError.scopeMismatch }
        let validate = {
            try validateAbsoluteDirectory(bundle, descriptor: root)
            try lock.validate(); try manifestFile.validate(); try resultFile.validate()
            try validateReference("recovery", parent: root, descriptor: recovery, kind: S_IFDIR)
            try validateReference(name(result.sourceEvidenceID), parent: recovery,
                                  descriptor: evidenceDirectory, kind: S_IFDIR)
            try validateReference(name(result.jobID), parent: evidenceDirectory,
                                  descriptor: generation, kind: S_IFDIR)
            guard try manifestFile.read(maximum: 16 * 1_048_576) == manifestBytes,
                  try resultFile.read(maximum: maximumResultBytes) == resultBytes else {
                throw RecoveryError.storageChanged
            }
        }
        try validate()
        let value = try body(Context(root: root, manifestDigest: digest(manifestBytes),
                                     resultDigest: expectedDigest, validate: validate))
        // The write path has revalidated immediately before atomic commit.
        // No cancellation or fallible reread follows a published receipt.
        if !write { try validate() }
        return value
    }

    private static func withHistoryDirectory<T>(root: Int32, result: CarvingResult, create: Bool,
        validateCase: @escaping () throws -> Void, body: (Int32, () throws -> Void) throws -> T) throws -> T {
        let notes = try directory("recovery-notes", parent: root, create: create)
        guard notes >= 0 else { try validateCase(); return try body(-1, validateCase) }
        defer { Darwin.close(notes) }
        let evidenceName = name(result.sourceEvidenceID), jobName = name(result.jobID)
        let evidence = try directory(evidenceName, parent: notes, create: create)
        guard evidence >= 0 else {
            try validateCase(); try validateReference("recovery-notes", parent: root, descriptor: notes, kind: S_IFDIR)
            return try body(-1, validateCase)
        }
        defer { Darwin.close(evidence) }
        let job = try directory(jobName, parent: evidence, create: create)
        guard job >= 0 else {
            try validateCase(); try validateReference("recovery-notes", parent: root, descriptor: notes, kind: S_IFDIR)
            try validateReference(evidenceName, parent: notes, descriptor: evidence, kind: S_IFDIR)
            return try body(-1, validateCase)
        }
        defer { Darwin.close(job) }
        let validate = {
            try validateCase()
            try validateReference("recovery-notes", parent: root, descriptor: notes, kind: S_IFDIR)
            try validateReference(evidenceName, parent: notes, descriptor: evidence, kind: S_IFDIR)
            try validateReference(jobName, parent: evidence, descriptor: job, kind: S_IFDIR)
        }
        try validate()
        return try body(job, validate)
    }

    private static func readHistory(in directory: Int32, result: CarvingResult, digest: String) throws -> HistorySnapshot {
        let snapshot = HistorySnapshot()
        do {
            try eachName(in: directory) { filename in
                guard snapshot.files.count < maximumRecords, filename.hasSuffix(".json"),
                      let identifier = UUID(uuidString: String(filename.dropLast(5))),
                      filename == name(identifier) + ".json" else { throw RecoveryError.invalidResult }
                let file = try AnnotationPinnedFile(name: filename, parent: directory)
                defer { file.close() }
                let bytes = try file.read(maximum: maximumRecordBytes)
                let record: RecoveryAnnotationRevision
                do { record = try JSONDecoder().decode(RecoveryAnnotationRevision.self, from: bytes) }
                catch { throw RecoveryError.invalidResult }
                guard record.id == identifier else { throw RecoveryError.invalidResult }
                try record.validate(result: result, digest: digest)
                snapshot.files[filename] = (file.identity, RecoveryAnnotationStore.digest(bytes))
                snapshot.records.append(record)
            }
            try validateChains(snapshot.records)
            try snapshot.validate(in: directory)
            return snapshot
        } catch { snapshot.close(); throw error }
    }

    private static func validateChains(_ records: [RecoveryAnnotationRevision]) throws {
        guard Set(records.map(\.id)).count == records.count else { throw RecoveryError.invalidResult }
        for chain in Dictionary(grouping: records, by: { $0.annotation.artifactID }).values {
            let ordered = chain.sorted { $0.revision < $1.revision }
            for (index, record) in ordered.enumerated() {
                guard record.revision == index + 1,
                      record.previousRevisionID == (index == 0 ? nil : ordered[index - 1].id),
                      index == 0 || record.savedAt >= ordered[index - 1].savedAt else {
                    throw RecoveryError.invalidResult
                }
            }
        }
    }

    fileprivate static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    private static func name(_ identifier: UUID) -> String { identifier.uuidString.lowercased() }

    fileprivate static func canonicalURL(_ url: URL) throws -> URL {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw RecoveryError.storageChanged }
        let path = url.standardizedFileURL.path
        // macOS owns these two system aliases; user-created intermediate
        // symlinks remain prohibited by the descriptor walk below.
        for alias in ["tmp", "var"] {
            let prefix = "/" + alias
            if path == prefix || path.hasPrefix(prefix + "/") {
                var metadata = stat()
                if Darwin.lstat(prefix, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFLNK {
                    var buffer = [CChar](repeating: 0, count: 1_024)
                    let amount = Darwin.readlink(prefix, &buffer, buffer.count - 1)
                    guard amount > 0 else { throw RecoveryError.storageChanged }
                    let target = String(decoding: buffer.prefix(amount).map { UInt8(bitPattern: $0) }, as: UTF8.self)
                    guard target == "private/" + alias || target == "/private/" + alias else {
                        throw RecoveryError.storageChanged
                    }
                    return URL(fileURLWithPath: "/private/" + alias + path.dropFirst(prefix.count), isDirectory: true)
                }
            }
        }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    fileprivate static func openAbsoluteDirectory(_ url: URL) throws -> Int32 {
        let canonical = try canonicalURL(url)
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
        var original = stat(), checked = stat()
        guard Darwin.fstat(descriptor, &original) == 0, Darwin.fstat(current, &checked) == 0,
              original.st_dev == checked.st_dev, original.st_ino == checked.st_ino else {
            throw RecoveryError.storageChanged
        }
    }

    private static func requiredDirectory(_ name: String, parent: Int32) throws -> Int32 {
        let descriptor = try directory(name, parent: parent, create: false)
        guard descriptor >= 0 else { throw RecoveryError.invalidResult }
        return descriptor
    }

    private static func directory(_ name: String, parent: Int32, create: Bool) throws -> Int32 {
        var created = false
        if create {
            if Darwin.mkdirat(parent, name, mode_t(0o700)) == 0 { created = true }
            else if errno != EEXIST { throw FileAccess.posixError("Cannot create recovery notes directory") }
        }
        let descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if !create && errno == ENOENT { return -1 }
            throw RecoveryError.storageChanged
        }
        do {
            try validateReference(name, parent: parent, descriptor: descriptor, kind: S_IFDIR)
            if created && Darwin.fsync(parent) != 0 { throw FileAccess.posixError("Cannot flush recovery notes parent") }
            return descriptor
        } catch { Darwin.close(descriptor); throw error }
    }

    fileprivate static func referenceMatches(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var current = stat(), pinned = stat()
        return Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            Darwin.fstat(descriptor, &pinned) == 0 && current.st_mode & S_IFMT == kind &&
            pinned.st_mode & S_IFMT == kind && current.st_dev == pinned.st_dev && current.st_ino == pinned.st_ino
    }

    fileprivate static func validateReference(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) throws {
        guard referenceMatches(name, parent: parent, descriptor: descriptor, kind: kind) else {
            throw RecoveryError.storageChanged
        }
    }

    fileprivate static func eachName(in directory: Int32, excluding: String? = nil,
                                     body: (String) throws -> Void) throws {
        let scan = Darwin.openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard scan >= 0 else { throw RecoveryError.storageChanged }
        guard let stream = Darwin.fdopendir(scan) else { Darwin.close(scan); throw RecoveryError.storageChanged }
        defer { Darwin.closedir(stream) }
        var count = 0
        while true {
            try Task.checkCancellation(); errno = 0
            guard let entry = Darwin.readdir(stream) else {
                guard errno == 0 else { throw RecoveryError.storageChanged }; break
            }
            let filename = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if filename == "." || filename == ".." || filename == excluding { continue }
            count += 1
            guard count <= maximumRecords else { throw RecoveryError.outputLimit }
            try body(filename)
        }
    }

    private final class HistorySnapshot {
        var files = [String: (SourceIdentity, String)]()
        var records = [RecoveryAnnotationRevision]()
        func validate(in directory: Int32, excluding: String? = nil) throws {
            var current = Set<String>()
            try RecoveryAnnotationStore.eachName(in: directory, excluding: excluding) { current.insert($0) }
            guard current == Set(files.keys) else { throw RecoveryError.storageChanged }
            // Reopen each leaf relative to the held directory, verifying its
            // original inode/content without retaining 10,000 descriptors.
            for (filename, (identity, hash)) in files {
                let file = try AnnotationPinnedFile(name: filename, parent: directory)
                defer { file.close() }
                guard file.identity == identity,
                      try RecoveryAnnotationStore.digest(file.read(maximum: maximumRecordBytes)) == hash else {
                    throw RecoveryError.storageChanged
                }
            }
        }
        func close() { files.removeAll() }
        deinit { close() }
    }
}

private final class AnnotationPinnedFile {
    let descriptor: Int32
    let identity: SourceIdentity
    private let parent: Int32
    private let filename: String
    private var closed = false

    init(name: String, parent: Int32) throws {
        self.parent = Darwin.fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard self.parent >= 0 else { throw RecoveryError.storageChanged }
        filename = name
        descriptor = Darwin.openat(self.parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { Darwin.close(self.parent); throw RecoveryError.storageChanged }
        do {
            identity = try FileAccess.identity(of: descriptor)
            try validate()
        } catch {
            closed = true; Darwin.close(descriptor); Darwin.close(self.parent); throw error
        }
    }

    func validate() throws {
        var metadata = stat()
        guard try FileAccess.identity(of: descriptor) == identity,
              (try? FileAccess.identity(at: filename, in: parent)) == identity,
              Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1,
              RecoveryAnnotationStore.referenceMatches(filename, parent: parent, descriptor: descriptor, kind: S_IFREG) else {
            throw RecoveryError.storageChanged
        }
    }

    func read(maximum: Int64) throws -> Data {
        guard identity.size <= maximum else { throw RecoveryError.outputLimit }
        guard Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else { throw RecoveryError.storageChanged }
        var bytes = Data(); bytes.reserveCapacity(Int(identity.size))
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < identity.size {
            try Task.checkCancellation()
            let amount = Int(min(Int64(buffer.count), identity.size - Int64(bytes.count)))
            let read = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: amount) }
            guard read > 0 else { throw RecoveryError.storageChanged }
            bytes.append(contentsOf: buffer.prefix(read))
        }
        try validate(); return bytes
    }

    func close() {
        guard !closed else { return }; closed = true
        Darwin.close(descriptor); Darwin.close(parent)
    }
    deinit { close() }
}

private final class AnnotationStagingFile {
    let filename: String
    private let parent: Int32
    private let output: Int32
    private var identity: SourceIdentity?
    private let bytes: Data
    private var published = false
    private var cleaned = false

    init(bytes: Data, parent: Int32) throws {
        self.bytes = bytes
        self.parent = Darwin.fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard self.parent >= 0 else { throw RecoveryError.storageChanged }
        filename = ".annotation-\(UUID().uuidString.lowercased()).tmp"
        output = Darwin.openat(self.parent, filename, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { cleaned = true; Darwin.close(self.parent); throw RecoveryError.storageChanged }
        do {
            try bytes.withUnsafeBytes { buffer in
                var written = 0
                while written < buffer.count {
                    try Task.checkCancellation()
                    let count = Darwin.write(output, buffer.baseAddress?.advanced(by: written), buffer.count - written)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw FileAccess.posixError("Cannot write recovery note") }
                    written += count
                }
            }
            guard Darwin.fsync(output) == 0 else { throw FileAccess.posixError("Cannot flush recovery note") }
            identity = try FileAccess.identity(of: output)
            try validate()
        } catch {
            // Initialization has not transferred ownership to a usable object.
            if RecoveryAnnotationStore.referenceMatches(filename, parent: self.parent, descriptor: output, kind: S_IFREG) {
                _ = Darwin.unlinkat(self.parent, filename, 0)
            }
            cleaned = true; Darwin.close(output); Darwin.close(self.parent); throw error
        }
    }

    private func validate() throws {
        try RecoveryAnnotationStore.validateReference(filename, parent: parent, descriptor: output, kind: S_IFREG)
        guard let identity, try FileAccess.identity(of: output) == identity,
              identity.size == Int64(bytes.count), Darwin.lseek(output, 0, SEEK_SET) == 0 else {
            throw RecoveryError.storageChanged
        }
        var readback = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        while readback.count < bytes.count {
            try Task.checkCancellation()
            let amount = min(buffer.count, bytes.count - readback.count)
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(output, into: $0, count: amount) }
            guard count > 0 else { throw RecoveryError.storageChanged }
            readback.append(contentsOf: buffer.prefix(count))
        }
        guard readback == bytes else { throw RecoveryError.storageChanged }
        var metadata = stat()
        guard Darwin.fstat(output, &metadata) == 0, metadata.st_nlink == 1 else { throw RecoveryError.storageChanged }
    }

    func publish(as destination: String, in destinationParent: Int32, validateContext: () throws -> Void) throws {
        try validateContext(); try validate(); try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, filename, destinationParent, destination, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw RecoveryError.destinationExists }
            throw FileAccess.posixError("Cannot publish recovery note")
        }
        // Once published, the immutable revision is never removed or rewritten.
        published = true
        guard Darwin.fsync(destinationParent) == 0, Darwin.fsync(parent) == 0 else {
            throw FileAccess.posixError("Cannot flush recovery notes directory")
        }
        try RecoveryAnnotationStore.validateReference(destination, parent: destinationParent, descriptor: output, kind: S_IFREG)
    }

    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        if !published && RecoveryAnnotationStore.referenceMatches(filename, parent: parent, descriptor: output, kind: S_IFREG) {
            _ = Darwin.unlinkat(parent, filename, 0)
        }
        Darwin.close(output); Darwin.close(parent)
    }
    deinit { cleanup() }
}
