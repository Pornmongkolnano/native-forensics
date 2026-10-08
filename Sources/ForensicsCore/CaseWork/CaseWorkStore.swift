import Darwin
import Foundation

@_silgen_name("flock")
private func caseWorkFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// Immutable sidecars inside a v1 case. All filesystem operations are anchored
/// to held, no-follow descriptors; no record operation opens evidence bytes.
public enum CaseWorkStore {
    public static let maximumRecordBytes = 1_048_576
    public static let maximumPageSize = 50

    public static func saveAnalysis(_ record: AnalysisRecord, in caseURL: URL) throws {
        try record.validate()
        try save(record, id: record.id, binding: record.binding, kind: .analysis, in: caseURL)
    }

    /// Deterministic fault boundary after synchronized staging and before the
    /// identity rechecks/atomic commit. Tests never require filling a real disk.
    static func saveAnalysisForTesting(_ record: AnalysisRecord, in caseURL: URL,
        beforePublish: () throws -> Void) throws {
        try record.validate()
        try save(record, id: record.id, binding: record.binding, kind: .analysis,
            in: caseURL, beforePublish: beforePublish)
    }

    /// Fault injection crosses actual persistence boundaries, including partial
    /// staging writes. It is internal and cannot be selected by a user payload.
    static func saveAnalysisForTesting(_ record: AnalysisRecord, in caseURL: URL,
        persistenceCheckpoint: (CasePersistenceCheckpoint, Int) throws -> Void) throws {
        try record.validate()
        try save(record, id: record.id, binding: record.binding, kind: .analysis,
            in: caseURL, persistenceCheckpoint: persistenceCheckpoint)
    }

    public static func saveExtraction(_ record: ExtractionRecord, in caseURL: URL) throws {
        try record.validate()
        try save(record, id: record.id, binding: record.binding, kind: .extraction, in: caseURL)
    }

    /// Per-call internal seam at actual immutable extraction commit boundaries.
    /// This models a failed syscall; it does not simulate physical power loss.
    static func saveExtractionForTesting(_ record: ExtractionRecord, in caseURL: URL,
        persistenceCheckpoint: (CasePersistenceCheckpoint, Int) throws -> Void) throws {
        try record.validate()
        try save(record, id: record.id, binding: record.binding, kind: .extraction,
            in: caseURL, persistenceCheckpoint: persistenceCheckpoint)
    }

    public static func saveFinding(_ record: FindingRecord, expectedLatestRevisionID: UUID?, in caseURL: URL) throws {
        try record.validate()
        let bytes = try encoded(record)
        guard expectedLatestRevisionID == record.previousRevisionID else { throw CaseWorkError.staleRevision }
        try withCase(record.binding, in: caseURL, write: true, publishedRecordID: record.id) { root, validateCase in
            let directory = try subdirectory(.finding, root: root, create: true)
            defer { Darwin.close(directory) }
            let current = try latestFinding(in: directory, binding: record.binding)
            guard current?.id == expectedLatestRevisionID else { throw CaseWorkError.staleRevision }
            if let current {
                guard record.findingID == current.findingID, record.revision == current.revision + 1 else {
                    throw CaseWorkError.staleRevision
                }
            } else {
                guard record.revision == 1, record.previousRevisionID == nil else { throw CaseWorkError.staleRevision }
            }
            try publish(bytes, id: record.id, directory: directory) {
                try validateCase(); try validateSubdirectory(.finding, descriptor: directory, root: root)
            }
        }
    }

    public static func loadAnalysis(id: UUID, in caseURL: URL) throws -> AnalysisRecord? {
        try load(id: id, kind: .analysis, in: caseURL) { try decodedAnalysis($0) }
    }
    public static func loadFinding(id: UUID, in caseURL: URL) throws -> FindingRecord? {
        try load(id: id, kind: .finding, in: caseURL) { try decodedFinding($0) }
    }
    public static func loadExtraction(id: UUID, in caseURL: URL) throws -> ExtractionRecord? {
        try load(id: id, kind: .extraction, in: caseURL) { try decodedExtraction($0) }
    }

    public static func latestFinding(binding: CaseWorkBinding, in caseURL: URL) throws -> FindingRecord? {
        try binding.validate()
        return try withCase(binding, in: caseURL, write: false) { root, validateCase in
            let directory = try subdirectory(.finding, root: root, create: false)
            guard directory >= 0 else { return nil }
            defer { Darwin.close(directory) }
            let result = try latestFinding(in: directory, binding: binding)
            try validateCase(); try validateSubdirectory(.finding, descriptor: directory, root: root)
            return result
        }
    }

    /// Newest first, with a deterministic UUID tie-break. Every scan has a
    /// bounded working set even when the case contains many megabyte records.
    /// Diagnostics concern the scanned directory, including records whose
    /// selection cannot be established because they are malformed.
    public static func history(binding: CaseWorkBinding, kind: CaseWorkKind,
        cursor: CaseWorkCursor? = nil, limit: Int = maximumPageSize, in caseURL: URL) throws -> CaseWorkHistoryPage {
        try binding.validate()
        guard (1...maximumPageSize).contains(limit), cursor.map({
            $0.caseID == binding.caseID && $0.evidenceID == binding.evidenceID &&
            $0.bindingLocator == binding.locatorSHA256 && $0.kind == kind
        }) ?? true else { throw CaseWorkError.invalidRecord }
        return try withCase(binding, in: caseURL, write: false) { root, validateCase in
            let directory = try subdirectory(kind, root: root, create: false)
            guard directory >= 0 else {
                return CaseWorkHistoryPage(items: [], diagnostics: [], totalDiagnosticCount: 0,
                    nextCursor: nil, maximumSerializedRecordBytesObserved: 0)
            }
            defer { Darwin.close(directory) }
            var items: [CaseWorkSummary] = []
            var diagnostics: [CaseWorkDiagnostic] = []
            var issueCount = 0
            var maximumBytes = 0
            try eachRecord(in: directory) { name, id in
                do {
                    let data = try read(name, directory: directory)
                    maximumBytes = max(maximumBytes, data.count)
                    let (recordBinding, summary) = try summarize(data, kind: kind)
                    guard summary.id == id else { throw CaseWorkError.invalidRecord }
                    try validateBinding(recordBinding, matching: binding)
                    guard binding.refersToSameFile(as: recordBinding) else { return }
                    if let cursor {
                        guard summary.createdAt < cursor.createdAt ||
                            (summary.createdAt == cursor.createdAt && summary.id.uuidString < cursor.id.uuidString) else { return }
                    }
                    items.append(summary)
                    items.sort { newer($0, than: $1) }
                    if items.count > limit + 1 { items.removeLast() }
                } catch is CancellationError { throw CancellationError() }
                catch {
                    issueCount += 1
                    if diagnostics.count < maximumPageSize {
                        diagnostics.append(CaseWorkDiagnostic(recordID: id,
                            message: (error as? CaseWorkError)?.localizedDescription ?? CaseWorkError.invalidRecord.localizedDescription))
                    }
                }
            }
            let hasNext = items.count > limit
            if hasNext { items.removeLast() }
            let next = hasNext ? items.last.map { CaseWorkCursor(bindingLocator: binding.locatorSHA256,
                caseID: binding.caseID, evidenceID: binding.evidenceID, kind: kind, createdAt: $0.createdAt, id: $0.id) } : nil
            try validateCase(); try validateSubdirectory(kind, descriptor: directory, root: root)
            return CaseWorkHistoryPage(items: items, diagnostics: diagnostics, totalDiagnosticCount: issueCount,
                nextCursor: next, maximumSerializedRecordBytesObserved: maximumBytes)
        }
    }

    private static func save<T: Encodable>(_ record: T, id: UUID, binding: CaseWorkBinding,
        kind: CaseWorkKind, in caseURL: URL, beforePublish: () throws -> Void = {},
        persistenceCheckpoint: (CasePersistenceCheckpoint, Int) throws -> Void = { _, _ in }) throws {
        let bytes = try encoded(record)
        try withCase(binding, in: caseURL, write: true, publishedRecordID: id) { root, validateCase in
            let directory = try subdirectory(kind, root: root, create: true)
            defer { Darwin.close(directory) }
            try publish(bytes, id: id, directory: directory, persistenceCheckpoint: persistenceCheckpoint) {
                try beforePublish()
                try validateCase(); try validateSubdirectory(kind, descriptor: directory, root: root)
            }
        }
    }

    private static func load<T>(id: UUID, kind: CaseWorkKind, in caseURL: URL,
        decode: (Data) throws -> T) throws -> T? {
        try withCase(nil, in: caseURL, write: false) { root, validateCase in
            let directory = try subdirectory(kind, root: root, create: false)
            guard directory >= 0 else { return nil }
            defer { Darwin.close(directory) }
            let name = filename(id)
            var metadata = stat()
            if Darwin.fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
                if errno == ENOENT { return nil }
                throw CaseWorkError.unsafePath
            }
            let bytes = try read(name, directory: directory)
            let record = try decode(bytes)
            let recordBinding: CaseWorkBinding
            let recordID: UUID
            switch record {
            case let value as AnalysisRecord: recordBinding = value.binding; recordID = value.id
            case let value as FindingRecord: recordBinding = value.binding; recordID = value.id
            case let value as ExtractionRecord: recordBinding = value.binding; recordID = value.id
            default: throw CaseWorkError.invalidRecord
            }
            guard recordID == id else { throw CaseWorkError.invalidRecord }
            try validateManifestBinding(recordBinding, root: root)
            try validateCase(); try validateSubdirectory(kind, descriptor: directory, root: root)
            return record
        }
    }

    private static func latestFinding(in directory: Int32, binding: CaseWorkBinding) throws -> FindingRecord? {
        var current: FindingRecord?
        var matchingCount = 0
        // Preserve and refuse ambiguous/corrupt history instead of silently
        // creating a replacement branch. Only one revision is retained in RAM.
        try eachRecord(in: directory) { name, id in
            let record: FindingRecord
            do {
                record = try decodedFinding(read(name, directory: directory))
                guard record.id == id else { throw CaseWorkError.invalidRecord }
                try validateBinding(record.binding, matching: binding)
            } catch is CancellationError { throw CancellationError() }
            catch { throw CaseWorkError.historyUnavailable }
            guard binding.refersToSameFile(as: record.binding) else { return }
            matchingCount += 1
            if let previous = current {
                guard previous.findingID == record.findingID,
                      previous.revision != record.revision else { throw CaseWorkError.historyUnavailable }
                if record.revision > previous.revision { current = record }
            } else { current = record }
        }
        // Independently establish the complete immutable revision chain without
        // an unbounded map. Revision jumps/missing parents cannot be overwritten.
        if let latest = current {
            guard matchingCount == latest.revision else { throw CaseWorkError.historyUnavailable }
            var child = latest
            while let parentID = child.previousRevisionID {
                try Task.checkCancellation()
                let parent: FindingRecord
                do { parent = try decodedFinding(read(filename(parentID), directory: directory)) }
                catch { throw CaseWorkError.historyUnavailable }
                guard parent.id == parentID, parent.findingID == latest.findingID,
                      parent.revision == child.revision - 1,
                      parent.binding.refersToSameFile(as: binding) else { throw CaseWorkError.historyUnavailable }
                child = parent
            }
            guard child.revision == 1 else { throw CaseWorkError.historyUnavailable }
        }
        return current
    }

    private static func validateBinding(_ record: CaseWorkBinding, matching binding: CaseWorkBinding) throws {
        guard record.caseID == binding.caseID else { throw CaseWorkError.scopeMismatch }
        if record.evidenceID == binding.evidenceID,
           (record.selectedContainerHash != binding.selectedContainerHash ||
            record.selectedContainerByteCount != binding.selectedContainerByteCount) {
            throw CaseWorkError.scopeMismatch
        }
    }

    private static func summarize(_ data: Data, kind: CaseWorkKind) throws -> (CaseWorkBinding, CaseWorkSummary) {
        switch kind {
        case .analysis:
            let value = try decodedAnalysis(data)
            return (value.binding, CaseWorkSummary(id: value.id, kind: kind, createdAt: value.createdAt,
                title: boundedTitle(value.result.response.summary), snapshotSHA256: value.binding.snapshotSHA256,
                reviewStatus: nil, retention: value.retention, revision: nil))
        case .finding:
            let value = try decodedFinding(data)
            return (value.binding, CaseWorkSummary(id: value.id, kind: kind, createdAt: value.createdAt,
                title: value.note.isEmpty ? (value.bookmarked ? "Bookmark" : "Examiner finding") : boundedTitle(value.note),
                snapshotSHA256: value.binding.snapshotSHA256, reviewStatus: value.reviewStatus, retention: nil, revision: value.revision))
        case .extraction:
            let value = try decodedExtraction(data)
            return (value.binding, CaseWorkSummary(id: value.id, kind: kind, createdAt: value.createdAt,
                title: "\(value.outputByteCount) extracted bytes · historical receipt", snapshotSHA256: value.binding.snapshotSHA256,
                reviewStatus: nil, retention: nil, revision: nil))
        }
    }

    private static func newer(_ value: CaseWorkSummary, than other: CaseWorkSummary) -> Bool {
        value.createdAt > other.createdAt || (value.createdAt == other.createdAt && value.id.uuidString > other.id.uuidString)
    }
    private static func boundedTitle(_ text: String) -> String {
        // A grapheme can contain arbitrarily many combining scalars. Limit
        // scalars so history summaries remain ≤640 UTF-8 bytes each.
        String(text.unicodeScalars.prefix(160))
    }
    private static func filename(_ id: UUID) -> String { id.uuidString.lowercased() + ".json" }
    private static func directoryName(_ kind: CaseWorkKind) -> String {
        switch kind { case .analysis: "analyses"; case .finding: "findings"; case .extraction: "extractions" }
    }
    private static func encoded<T: Encodable>(_ value: T) throws -> Data {
        let bytes = try CaseWorkCoding.encode(value)
        guard bytes.count <= maximumRecordBytes else { throw CaseWorkError.sizeLimit }
        return bytes
    }
    private static func decodedAnalysis(_ data: Data) throws -> AnalysisRecord {
        try checkVersion(data)
        let record: AnalysisRecord
        do { record = try CaseWorkCoding.decode(AnalysisRecord.self, data) }
        catch { throw CaseWorkError.invalidRecord }
        try record.validate(); return record
    }
    private static func decodedFinding(_ data: Data) throws -> FindingRecord {
        try checkVersion(data)
        let record: FindingRecord
        do { record = try CaseWorkCoding.decode(FindingRecord.self, data) }
        catch { throw CaseWorkError.invalidRecord }
        try record.validate(); return record
    }
    private static func decodedExtraction(_ data: Data) throws -> ExtractionRecord {
        try checkVersion(data)
        let record: ExtractionRecord
        do { record = try CaseWorkCoding.decode(ExtractionRecord.self, data) }
        catch { throw CaseWorkError.invalidRecord }
        try record.validate(); return record
    }
    private static func checkVersion(_ data: Data) throws {
        struct Header: Decodable { let schemaVersion: Int }
        let header: Header
        do { header = try CaseWorkCoding.decode(Header.self, data) }
        catch { throw CaseWorkError.invalidRecord }
        guard header.schemaVersion == 1 else { throw CaseWorkError.unsupportedVersion }
    }

    private static func read(_ name: String, directory: Int32, checkCancellation: Bool = true) throws -> Data {
        if checkCancellation { try Task.checkCancellation() }
        let descriptor = Darwin.openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw CaseWorkError.unsafePath }
        defer { Darwin.close(descriptor) }
        let before: SourceIdentity
        do { before = try FileAccess.identity(of: descriptor) }
        catch { throw CaseWorkError.unsafePath }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1 else { throw CaseWorkError.unsafePath }
        guard before.size <= maximumRecordBytes else { throw CaseWorkError.sizeLimit }
        var bytes = Data(); bytes.reserveCapacity(Int(before.size))
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < before.size {
            if checkCancellation { try Task.checkCancellation() }
            let amount = Int(min(Int64(buffer.count), before.size - Int64(bytes.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: amount) }
            guard count > 0 else { throw CaseWorkError.changedDuringOperation }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        guard try FileAccess.identity(of: descriptor) == before,
              (try? FileAccess.identity(at: name, in: directory)) == before else { throw CaseWorkError.changedDuringOperation }
        return bytes
    }

    private static func eachRecord(in directory: Int32, body: (String, UUID) throws -> Void) throws {
        // dup shares directory offsets; open "." instead so every scan starts at
        // the beginning and keeps the parent descriptor independently owned.
        let scan = Darwin.openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard scan >= 0 else { throw CaseWorkError.unsafePath }
        guard let stream = Darwin.fdopendir(scan) else { Darwin.close(scan); throw CaseWorkError.unsafePath }
        defer { Darwin.closedir(stream) }
        while true {
            try Task.checkCancellation(); errno = 0
            guard let entry = Darwin.readdir(stream) else {
                if errno != 0 { throw CaseWorkError.changedDuringOperation }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." || (name.hasPrefix(".") && name.hasSuffix(".tmp")) { continue }
            guard name.hasSuffix(".json"), let id = UUID(uuidString: String(name.dropLast(5))), name == filename(id) else {
                throw CaseWorkError.historyUnavailable
            }
            try body(name, id)
        }
    }

    private static func subdirectory(_ kind: CaseWorkKind, root: Int32, create: Bool) throws -> Int32 {
        let name = directoryName(kind)
        if create && Darwin.mkdirat(root, name, mode_t(0o700)) != 0 && errno != EEXIST { throw FileAccess.posixError("Cannot create case-work directory") }
        let descriptor = Darwin.openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if !create && errno == ENOENT { return -1 }
            throw CaseWorkError.unsafePath
        }
        do { try validateSubdirectory(kind, descriptor: descriptor, root: root) }
        catch { Darwin.close(descriptor); throw error }
        return descriptor
    }
    private static func validateSubdirectory(_ kind: CaseWorkKind, descriptor: Int32, root: Int32) throws {
        guard referenceMatches(directoryName(kind), parent: root, descriptor: descriptor, kind: S_IFDIR) else {
            throw CaseWorkError.changedDuringOperation
        }
    }

    private static func publish(_ bytes: Data, id: UUID, directory: Int32,
        persistenceCheckpoint: (CasePersistenceCheckpoint, Int) throws -> Void = { _, _ in },
        validate: () throws -> Void) throws {
        try Task.checkCancellation()
        let name = filename(id)
        let staging = ".casework-\(UUID().uuidString.lowercased()).tmp"
        let descriptor = Darwin.openat(directory, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot create case-work record") }
        defer {
            if referenceMatches(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) {
                _ = Darwin.unlinkat(directory, staging, 0)
            }
            Darwin.close(descriptor)
        }
        try persistenceCheckpoint(.beforeWrite, 0)
        try bytes.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: written), min(65_536, buffer.count - written))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write case-work record") }
                written += count
                try persistenceCheckpoint(.afterWriteChunk, written)
            }
        }
        try persistenceCheckpoint(.beforeFileFlush, bytes.count)
        try sync(descriptor, message: "Cannot flush case-work record")
        try persistenceCheckpoint(.afterFileFlush, bytes.count)
        try Task.checkCancellation(); try validate()
        try Task.checkCancellation()
        guard referenceMatches(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) else {
            throw CaseWorkError.changedDuringOperation
        }
        try persistenceCheckpoint(.beforeRename, bytes.count)
        try validate()
        guard referenceMatches(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) else {
            throw CaseWorkError.changedDuringOperation
        }
        guard Darwin.renameatx_np(directory, staging, directory, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw CaseWorkError.alreadyExists }
            throw FileAccess.posixError("Cannot publish case-work record")
        }
        do {
            try persistenceCheckpoint(.afterRename, bytes.count)
            try persistenceCheckpoint(.beforeDirectoryFlush, bytes.count)
            try sync(directory, message: "Cannot flush case-work directory")
            try persistenceCheckpoint(.afterDirectoryFlush, bytes.count)
            guard referenceMatches(name, parent: directory, descriptor: descriptor, kind: S_IFREG),
                  try read(name, directory: directory, checkCancellation: false) == bytes else {
                throw CaseWorkError.changedDuringOperation
            }
            try validate()
        } catch {
            // The exclusive rename already committed. Do not remove the final
            // record or tell the caller that retrying its UUID is a fresh save.
            throw CasePublicationError.publishedButDurabilityUnconfirmed(recordID: id)
        }
        // No cancellation check after publication: the caller must receive a
        // committed receipt even if cancellation arrived during the atomic rename.
    }

    private static func sync(_ descriptor: Int32, message: String) throws {
        while Darwin.fsync(descriptor) != 0 {
            if errno == EINTR { continue }
            throw FileAccess.posixError(message)
        }
    }

    private static func withCase<T>(_ binding: CaseWorkBinding?, in url: URL, write: Bool,
        publishedRecordID: UUID? = nil, body: (Int32, () throws -> Void) throws -> T) throws -> T {
        guard url.isFileURL else { throw CaseWorkError.invalidCase }
        var supplied = stat()
        guard Darwin.lstat(url.standardizedFileURL.path, &supplied) == 0,
              supplied.st_mode & S_IFMT == S_IFDIR else { throw CaseWorkError.invalidCase }
        let bundle = try FileAccess.localURL(url)
        guard bundle.pathExtension == CaseStore.bundleExtension else { throw CaseWorkError.invalidCase }
        let root: Int32
        do { root = try EvidenceViewFiles.openDirectory(url.standardizedFileURL) }
        catch { throw CaseWorkError.invalidCase }
        defer { Darwin.close(root) }
        try validateRoot(bundle, descriptor: root)
        let lock = Darwin.openat(root, ".case.lock", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard lock >= 0 else { throw CaseWorkError.invalidCase }
        defer { Darwin.close(lock) }
        let lockIdentity: SourceIdentity
        do { lockIdentity = try FileAccess.identity(of: lock) }
        catch { throw CaseWorkError.invalidCase }
        var lockMetadata = stat()
        guard Darwin.fstat(lock, &lockMetadata) == 0, lockMetadata.st_nlink == 1 else { throw CaseWorkError.invalidCase }
        // Nonblocking polling lets cancelled background tasks leave a busy lock
        // promptly without a blocking MainActor or an orphaned waiting thread.
        while caseWorkFlock(lock, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock case-work records") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = caseWorkFlock(lock, LOCK_UN) }
        try validateRoot(bundle, descriptor: root)
        guard (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity else { throw CaseWorkError.changedDuringOperation }
        let manifestIdentity = try FileAccess.identity(at: "manifest.json", in: root)
        let current = try CaseStore.open(at: bundle)
        let validate = {
            try validateRoot(bundle, descriptor: root)
            guard (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity,
                  (try? FileAccess.identity(at: "manifest.json", in: root)) == manifestIdentity else {
                throw CaseWorkError.changedDuringOperation
            }
        }
        try validate()
        if let binding { try validateManifestBinding(binding, manifest: current.manifest) }
        let value = try body(root, validate)
        do { try validate() }
        catch {
            if let id = publishedRecordID { throw CasePublicationError.publishedButDurabilityUnconfirmed(recordID: id) }
            throw error
        }
        return value
    }

    private static func validateManifestBinding(_ binding: CaseWorkBinding, root: Int32) throws {
        // Anchored manifest decoding for read-by-ID callers, whose selection is
        // discovered only after the record is read. CaseStore validated this
        // unchanged manifest when acquiring the case transaction above.
        let descriptor = try FileAccess.openReadOnly("manifest.json", in: root)
        defer { Darwin.close(descriptor) }
        let before = try FileAccess.identity(of: descriptor)
        guard before.size <= 16 * 1_048_576 else { throw CaseWorkError.invalidCase }
        var bytes = Data(); var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < before.size {
            let requested = Int(min(Int64(buffer.count), before.size - Int64(bytes.count)))
            let count = try buffer.withUnsafeMutableBytes {
                try FileAccess.read(descriptor, into: $0, count: requested)
            }
            guard count > 0 else { throw CaseWorkError.changedDuringOperation }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        guard (try? FileAccess.identity(at: "manifest.json", in: root)) == before,
              try FileAccess.identity(of: descriptor) == before else { throw CaseWorkError.changedDuringOperation }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let manifest: CaseManifest
        do { manifest = try decoder.decode(CaseManifest.self, from: bytes) }
        catch { throw CaseWorkError.invalidCase }
        try validateManifestBinding(binding, manifest: manifest)
    }
    private static func validateManifestBinding(_ binding: CaseWorkBinding, manifest: CaseManifest) throws {
        guard binding.caseID == manifest.id,
              let evidence = manifest.evidence.first(where: { $0.id == binding.evidenceID }),
              evidence.hashScope == binding.selectedContainerHash.scope,
              evidence.byteCount == binding.selectedContainerByteCount,
              evidence.sha256 == binding.selectedContainerHash.sha256 else { throw CaseWorkError.scopeMismatch }
    }
    private static func validateRoot(_ url: URL, descriptor: Int32) throws {
        do { try EvidenceViewFiles.validateDirectory(url, descriptor: descriptor) }
        catch { throw CaseWorkError.changedDuringOperation }
    }
    private static func referenceMatches(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var current = stat(); var opened = stat()
        return Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0 && Darwin.fstat(descriptor, &opened) == 0
            && current.st_mode & S_IFMT == kind && current.st_dev == opened.st_dev && current.st_ino == opened.st_ino
    }
}
