import Darwin
import Foundation

@_silgen_name("flock")
private func multiEvidenceFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

public struct MultiEvidenceRecordSummary: Sendable, Equatable, Identifiable {
    public let id: UUID
    public let createdAt: Date
    public let title: String
    public let retention: AnalysisRetention
    public let parentRecordID: UUID?
}

/// Immutable bounded sidecars anchored to the case lock and held no-follow
/// descriptors. Opening a historical record never reads source image bytes.
public enum MultiEvidenceRecordStore {
    public static let maximumRecordBytes = 1_048_576
    public static let maximumPageSize = 50
    private static let directoryName = "comparisons"

    public static func saveAsync(_ record: MultiEvidenceAnalysisRecord, in caseURL: URL) async throws {
        let cancellation = CodexCancellation()
        try await withTaskCancellationHandler {
            try await BlockingWork.run { try save(record, in: caseURL, cancelled: { cancellation.isCancelled }) }
        } onCancel: { cancellation.cancel() }
    }

    public static func save(_ record: MultiEvidenceAnalysisRecord, in caseURL: URL,
                            cancelled: @escaping @Sendable () -> Bool = { false }) throws {
        try record.validate()
        let bytes = try MultiEvidenceCoding.encode(record)
        guard bytes.count <= maximumRecordBytes else { throw CaseWorkError.sizeLimit }
        try transaction(in: caseURL, write: true, cancelled: cancelled) { root, manifest, validate in
            try bind(record, manifest: manifest)
            let directory = try openDirectory(root, create: true)
            defer { Darwin.close(directory) }
            try validateParent(record, directory: directory, manifest: manifest)
            let staging = ".comparison-\(UUID().uuidString.lowercased()).tmp"
            let descriptor = Darwin.openat(directory, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw CaseWorkError.unsafePath }
            defer {
                if matches(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) { _ = Darwin.unlinkat(directory, staging, 0) }
                Darwin.close(descriptor)
            }
            try bytes.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    try checkCancellation(cancelled)
                    let written = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: offset), buffer.count - offset)
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { throw CaseWorkError.unsafePath }
                    offset += written
                }
            }
            guard Darwin.fsync(descriptor) == 0 else { throw CaseWorkError.unsafePath }
            try checkCancellation(cancelled); try validate()
            guard matches(directoryName, parent: root, descriptor: directory, kind: S_IFDIR),
                  matches(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) else { throw CaseWorkError.changedDuringOperation }
            try checkCancellation(cancelled)
            guard Darwin.renameatx_np(directory, staging, directory, filename(record.id), UInt32(RENAME_EXCL)) == 0 else {
                if errno == EEXIST { throw CaseWorkError.alreadyExists }
                throw CaseWorkError.unsafePath
            }
            guard Darwin.fsync(directory) == 0 else { throw CaseWorkError.unsafePath }
            // A committed receipt survives late cancellation, never resaved.
        }
    }

    public static func load(id: UUID, in caseURL: URL) throws -> MultiEvidenceAnalysisRecord? {
        try transaction(in: caseURL, write: false) { root, manifest, validate in
            let directory = try openDirectory(root, create: false)
            guard directory >= 0 else { return nil }
            defer { Darwin.close(directory) }
            var metadata = stat()
            if Darwin.fstatat(directory, filename(id), &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
                if errno == ENOENT { return nil }; throw CaseWorkError.unsafePath
            }
            let record = try read(id: id, directory: directory)
            try bind(record, manifest: manifest); try validateParent(record, directory: directory, manifest: manifest)
            try validate()
            guard matches(directoryName, parent: root, descriptor: directory, kind: S_IFDIR) else { throw CaseWorkError.changedDuringOperation }
            return record
        }
    }

    /// Scans one ≤1 MiB record at a time and retains at most 50 small summaries.
    /// Older pages use the last summary as an explicit stable boundary.
    public static func history(in caseURL: URL, before: MultiEvidenceRecordSummary? = nil,
                               limit: Int = maximumPageSize) throws -> [MultiEvidenceRecordSummary] {
        guard (1...maximumPageSize).contains(limit) else { throw CaseWorkError.sizeLimit }
        return try transaction(in: caseURL, write: false) { root, manifest, validate in
            let directory = try openDirectory(root, create: false)
            guard directory >= 0 else { return [] }
            defer { Darwin.close(directory) }
            let scan = Darwin.openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard scan >= 0, let stream = Darwin.fdopendir(scan) else { if scan >= 0 { Darwin.close(scan) }; throw CaseWorkError.unsafePath }
            defer { Darwin.closedir(stream) }
            var summaries: [MultiEvidenceRecordSummary] = []
            while true {
                try Task.checkCancellation(); errno = 0
                guard let entry = Darwin.readdir(stream) else { if errno != 0 { throw CaseWorkError.changedDuringOperation }; break }
                let name = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
                }
                if name == "." || name == ".." || (name.hasPrefix(".") && name.hasSuffix(".tmp")) { continue }
                guard name.hasSuffix(".json"), let id = UUID(uuidString: String(name.dropLast(5))), name == filename(id) else {
                    throw CaseWorkError.historyUnavailable
                }
                let record = try read(id: id, directory: directory)
                try bind(record, manifest: manifest); try validateParent(record, directory: directory, manifest: manifest)
                let summary = MultiEvidenceRecordSummary(id: id, createdAt: record.createdAt,
                    title: String(record.result.response.summary.unicodeScalars.prefix(160)), retention: record.retention,
                    parentRecordID: record.parentRecordID)
                if let before, !newer(before, than: summary) { continue }
                summaries.append(summary); summaries.sort { newer($0, than: $1) }
                if summaries.count > limit { summaries.removeLast() }
            }
            try validate()
            guard matches(directoryName, parent: root, descriptor: directory, kind: S_IFDIR) else { throw CaseWorkError.changedDuringOperation }
            return summaries
        }
    }

    private static func validateParent(_ record: MultiEvidenceAnalysisRecord, directory: Int32, manifest: CaseManifest) throws {
        var parent: MultiEvidenceAnalysisRecord?
        if let parentID = record.parentRecordID {
            parent = try read(id: parentID, directory: directory)
            guard let parent, parent.requestSHA256 == record.parentRequestSHA256,
                  parent.context.hasSameDisclosure(as: record.context) else { throw MultiEvidenceError.parentMismatch }
            try bind(parent, manifest: manifest)
        }
        if record.retention == .full {
            guard record.prompt == (try MultiEvidencePrompt.make(context: record.context, question: record.question, parent: parent)) else {
                throw MultiEvidenceError.requestMismatch
            }
        }
    }
    private static func newer(_ first: MultiEvidenceRecordSummary, than second: MultiEvidenceRecordSummary) -> Bool {
        first.createdAt > second.createdAt || (first.createdAt == second.createdAt && first.id.uuidString > second.id.uuidString)
    }
    private static func read(id: UUID, directory: Int32) throws -> MultiEvidenceAnalysisRecord {
        let data = try readFile(filename(id), directory: directory, maximum: maximumRecordBytes)
        let record: MultiEvidenceAnalysisRecord
        do { record = try CaseWorkCoding.decode(MultiEvidenceAnalysisRecord.self, data) }
        catch { throw CaseWorkError.invalidRecord }
        guard record.id == id else { throw CaseWorkError.invalidRecord }
        try record.validate(); return record
    }
    private static func bind(_ record: MultiEvidenceAnalysisRecord, manifest: CaseManifest) throws {
        for file in record.context.files {
            let binding = file.binding
            guard binding.caseID == manifest.id, let evidence = manifest.evidence.first(where: { $0.id == binding.evidenceID }),
                  evidence.sha256 == binding.selectedContainerHash.sha256, evidence.byteCount == binding.selectedContainerByteCount,
                  evidence.hashScope == binding.selectedContainerHash.scope else { throw CaseWorkError.scopeMismatch }
        }
    }
    private static func filename(_ id: UUID) -> String { id.uuidString.lowercased() + ".json" }
    private static func openDirectory(_ root: Int32, create: Bool) throws -> Int32 {
        if create && Darwin.mkdirat(root, directoryName, 0o700) != 0 && errno != EEXIST { throw CaseWorkError.unsafePath }
        let descriptor = Darwin.openat(root, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 { if !create && errno == ENOENT { return -1 }; throw CaseWorkError.unsafePath }
        guard matches(directoryName, parent: root, descriptor: descriptor, kind: S_IFDIR) else {
            Darwin.close(descriptor); throw CaseWorkError.changedDuringOperation
        }
        return descriptor
    }
    private static func readFile(_ name: String, directory: Int32, maximum: Int) throws -> Data {
        let descriptor = Darwin.openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw CaseWorkError.unsafePath }
        defer { Darwin.close(descriptor) }
        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_nlink == 1 else { throw CaseWorkError.unsafePath }
        guard before.st_size >= 0, before.st_size <= maximum else { throw CaseWorkError.sizeLimit }
        var bytes = Data(); var buffer = [UInt8](repeating: 0, count: 65_536)
        while bytes.count < before.st_size {
            try Task.checkCancellation()
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, min($0.count, Int(before.st_size) - bytes.count)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw CaseWorkError.changedDuringOperation }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              matches(name, parent: directory, descriptor: descriptor, kind: S_IFREG) else { throw CaseWorkError.changedDuringOperation }
        return bytes
    }
    private static func transaction<T>(in caseURL: URL, write: Bool, cancelled: @Sendable () -> Bool = { false },
        operation: (Int32, CaseManifest, () throws -> Void) throws -> T) throws -> T {
        guard caseURL.isFileURL, caseURL.pathExtension == CaseStore.bundleExtension else { throw CaseWorkError.invalidCase }
        let bundle = try FileAccess.localURL(caseURL)
        var supplied = stat()
        guard Darwin.lstat(caseURL.standardizedFileURL.path, &supplied) == 0, supplied.st_mode & S_IFMT == S_IFDIR else { throw CaseWorkError.invalidCase }
        let root = Darwin.open(bundle.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw CaseWorkError.invalidCase }
        defer { Darwin.close(root) }
        let lock = Darwin.openat(root, ".case.lock", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard lock >= 0 else { throw CaseWorkError.invalidCase }
        defer { Darwin.close(lock) }
        var metadata = stat()
        guard Darwin.fstat(lock, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG, metadata.st_nlink == 1 else { throw CaseWorkError.invalidCase }
        while multiEvidenceFlock(lock, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw CaseWorkError.invalidCase }
            try checkCancellation(cancelled); usleep(10_000)
        }
        defer { _ = multiEvidenceFlock(lock, LOCK_UN) }
        let manifestBytes = try readFile("manifest.json", directory: root, maximum: 16 * 1_048_576)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(CaseManifest.self, from: manifestBytes)
        guard try CaseStore.open(at: bundle).manifest == manifest else { throw CaseWorkError.changedDuringOperation }
        let validate = {
            var current = stat(), opened = stat()
            guard Darwin.lstat(bundle.path, &current) == 0, Darwin.fstat(root, &opened) == 0,
                  current.st_mode & S_IFMT == S_IFDIR, current.st_dev == opened.st_dev, current.st_ino == opened.st_ino,
                  matches(".case.lock", parent: root, descriptor: lock, kind: S_IFREG),
                  try readFile("manifest.json", directory: root, maximum: 16 * 1_048_576) == manifestBytes else { throw CaseWorkError.changedDuringOperation }
        }
        try validate(); try checkCancellation(cancelled)
        let value = try operation(root, manifest, validate)
        if !write { try validate() }
        return value
    }
    private static func checkCancellation(_ cancelled: @Sendable () -> Bool) throws {
        try Task.checkCancellation()
        if cancelled() { throw CancellationError() }
    }
    private static func matches(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var current = stat(), opened = stat()
        return Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0 && Darwin.fstat(descriptor, &opened) == 0
            && current.st_mode & S_IFMT == kind && current.st_dev == opened.st_dev && current.st_ino == opened.st_ino
    }
}
