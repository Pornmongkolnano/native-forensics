import CSQLite3
import CryptoKit
import Darwin
import Foundation

/// Parses only a receipt-bound, extracted Chromium History artifact. SQLite
/// never opens an evidence image or even the supplied extracted file: pinned
/// descriptors are independently hashed into a private, immutable scratch copy.
public enum ChromiumHistoryParser {
    public static let version = "chromium-history.v1"
    public static let maximumDatabaseBytes: Int64 = 64 * 1_048_576
    public static let maximumSidecarBytes: Int64 = 16 * 1_048_576

    public static func parse(input: VerifiedBrowserArtifact) async throws -> [TimelineEvent] {
        try Task.checkCancellation()
        let budget = ChromiumBudget()
        return try await withTaskCancellationHandler {
            let result = try await BlockingWork.run { try parseBlocking(input, budget: budget) }
            try Task.checkCancellation()
            return result
        } onCancel: { budget.cancel() }
    }

    private static func parseBlocking(_ input: VerifiedBrowserArtifact, budget: ChromiumBudget) throws -> [TimelineEvent] {
        try budget.check()
        try input.binding.validate()
        guard !input.expectedWAL || input.wal != nil, !input.expectedSHM || input.shm != nil else {
            throw TimelineError.inconsistentSnapshot("A known Chromium WAL/SHM sidecar was not supplied. Extract the complete artifact set.")
        }
        guard input.shm == nil || input.wal != nil else {
            throw TimelineError.inconsistentSnapshot("A Chromium SHM sidecar without its WAL is not a complete artifact set.")
        }
        for (file, suffix) in [(input.wal, "-wal"), (input.shm, "-shm")] {
            guard let file else { continue }
            guard file.evidencePath == input.database.evidencePath + suffix,
                  file.fileID != input.database.fileID else {
                throw TimelineError.inconsistentSnapshot("Chromium sidecars must be exact siblings of the selected database in the evidence listing.")
            }
        }
        let files = [input.database] + [input.wal, input.shm].compactMap { $0 }
        guard Set(files.map(\.fileID)).count == files.count,
              Set(files.map { $0.url.standardizedFileURL.path }).count == files.count else {
            throw TimelineError.invalidInput("Artifact receipts must identify distinct extracted files.")
        }
        let pinned = try files.enumerated().map { index, file in
            try ChromiumPinnedFile(file: file, limit: index == 0 ? maximumDatabaseBytes : maximumSidecarBytes)
        }
        defer { pinned.forEach { $0.close() } }
        let bytes = try pinned.map { try $0.readVerified(budget: budget) }
        var database = bytes[0]
        let pageSize = try validateHeader(database)
        if input.wal != nil {
            guard database[18] == 2, database[19] == 2 else {
                throw TimelineError.inconsistentSnapshot("A supplied WAL requires a WAL-mode database header.")
            }
            let wal = try ChromiumWAL(bytes: bytes[1], pageSize: pageSize, budget: budget)
            if input.shm != nil { try wal.validateSHM(bytes[2]) }
            database = try wal.materialize(database: database, budget: budget)
        }
        // Rehash every pinned source after materializing and again after SQL.
        // Reading via the same descriptors prevents pathname replacement from
        // silently selecting another file; identity checks also bind the path.
        for file in pinned { try file.verifyAgain(budget: budget) }
        // Only the derived private clone is normalized to standalone journal
        // mode. Its committed pages already contain the WAL state; no evidence
        // bytes are rewritten, checkpointed, or opened by SQLite.
        database[18] = 1; database[19] = 1
        let scratch = try ChromiumScratch(bytes: database)
        defer { scratch.remove() }
        try scratch.validate(budget: budget)
        let sqlite = try ChromiumSQLite(url: scratch.databaseURL, budget: budget)
        defer { sqlite.close() }
        let events = try sqlite.events(input: input)
        try scratch.validate(budget: budget)
        for file in pinned { try file.verifyAgain(budget: budget) }
        try budget.check()
        return events
    }

    private static func validateHeader(_ bytes: Data) throws -> Int {
        guard bytes.count >= 100, bytes.prefix(16) == Data("SQLite format 3\0".utf8),
              [1, 2].contains(bytes[18]), [1, 2].contains(bytes[19]) else {
            throw TimelineError.unsupported("The selected artifact is not a supported SQLite 3 database.")
        }
        let raw = Int(bytes[16]) * 256 + Int(bytes[17])
        let pageSize = raw == 1 ? 65_536 : raw
        guard pageSize >= 512, pageSize <= 65_536, pageSize.nonzeroBitCount == 1,
              bytes.count % pageSize == 0 else {
            throw TimelineError.inconsistentSnapshot("The SQLite database has an invalid page size or incomplete page.")
        }
        return pageSize
    }
}

private final class ChromiumBudget: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private let deadline = ContinuousClock.now.advanced(by: .seconds(10))
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    var interrupted: Bool {
        lock.lock(); let value = cancelled; lock.unlock()
        return value || ContinuousClock.now >= deadline
    }
    func check() throws {
        lock.lock(); let value = cancelled; lock.unlock()
        if value { throw CancellationError() }
        if ContinuousClock.now >= deadline { throw TimelineError.limitExceeded("Chromium parsing exceeded its 10 second work budget.") }
    }
}

private final class ChromiumPinnedFile {
    let file: VerifiedArtifactFile
    private var descriptor: Int32
    private let identity: SourceIdentity
    init(file: VerifiedArtifactFile, limit: Int64) throws {
        guard file.url.isFileURL, file.url.host == nil || file.url.host == "" || file.url.host == "localhost",
              !file.url.path.utf8.contains(0), EngineValidation.text(file.fileID, maximum: 1_024),
              EngineValidation.text(file.evidencePath, maximum: 32_768),
              file.byteCount >= 0, file.byteCount <= limit, EngineValidation.validHash(file.sha256) else {
            throw TimelineError.invalidInput("Invalid or oversized Chromium artifact receipt.")
        }
        self.file = file
        descriptor = try FileAccess.openReadOnly(file.url.standardizedFileURL)
        do {
            identity = try FileAccess.identity(of: descriptor)
            guard identity.size == file.byteCount else { throw TimelineError.sourceChanged }
        } catch { Darwin.close(descriptor); throw error }
    }
    func close() { if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 } }
    deinit { close() }
    func readVerified(budget: ChromiumBudget) throws -> Data {
        var bytes = Data(); bytes.reserveCapacity(Int(identity.size))
        var offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var hash = SHA256()
        while offset < identity.size {
            try budget.check()
            let wanted = Int(min(Int64(buffer.count), identity.size - offset))
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress, wanted, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw TimelineError.sourceChanged }
            buffer.withUnsafeBytes { hash.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0[..<count])) }
            bytes.append(contentsOf: buffer.prefix(count)); offset += Int64(count)
        }
        guard TimelineCoding.hex(hash.finalize()) == file.sha256.lowercased(),
              try FileAccess.identity(of: descriptor) == identity,
              try FileAccess.identity(at: file.url.standardizedFileURL) == identity else { throw TimelineError.sourceChanged }
        return bytes
    }
    func verifyAgain(budget: ChromiumBudget) throws { _ = try readVerified(budget: budget) }
}

/// The persistent WAL format is cross-platform. Validate chained checksums and
/// salts, then use only frames through the final commit marker. SHM is a cache,
/// not recovery authority, but a supplied initialized header must agree with
/// that committed WAL. Unknown/reset tails are rejected, not silently ignored.
private struct ChromiumWAL {
    let bytes: Data
    let pageSize: Int
    let bigEndianChecksum: Bool
    let committedFrames: Int
    let committedPages: Int
    let committedChecksum: (UInt32, UInt32)
    init(bytes: Data, pageSize: Int, budget: ChromiumBudget) throws {
        self.bytes = bytes; self.pageSize = pageSize
        guard bytes.count >= 32 else { throw TimelineError.inconsistentSnapshot("A supplied Chromium WAL is empty or incomplete.") }
        let magic = Self.word(bytes, 0)
        guard magic == 0x377f0682 || magic == 0x377f0683, Self.word(bytes, 4) == 3_007_000,
              Int(Self.word(bytes, 8)) == pageSize, (bytes.count - 32) % (pageSize + 24) == 0 else {
            throw TimelineError.inconsistentSnapshot("Unsupported Chromium WAL header or incomplete frame.")
        }
        bigEndianChecksum = magic == 0x377f0683
        var checksum = Self.checksum(bytes, range: 0..<24, bigEndian: bigEndianChecksum, seed: (0, 0))
        guard checksum.0 == Self.word(bytes, 24), checksum.1 == Self.word(bytes, 28) else {
            throw TimelineError.inconsistentSnapshot("Chromium WAL header checksum failed.")
        }
        let frameCount = (bytes.count - 32) / (pageSize + 24)
        var lastCommit = 0, pages = 0, lastChecksum: (UInt32, UInt32) = (0, 0)
        for index in 0..<frameCount {
            try budget.check()
            let offset = 32 + index * (pageSize + 24)
            let page = Int(Self.word(bytes, offset)), commit = Int(Self.word(bytes, offset + 4))
            guard page > 0, page <= Int(ChromiumHistoryParser.maximumDatabaseBytes) / pageSize,
                  commit <= Int(ChromiumHistoryParser.maximumDatabaseBytes) / pageSize,
                  bytes[(offset + 8)..<(offset + 16)] == bytes[16..<24] else {
                throw TimelineError.inconsistentSnapshot("Chromium WAL frame salts or page bounds do not match.")
            }
            checksum = Self.checksum(bytes, range: offset..<(offset + 8), bigEndian: bigEndianChecksum, seed: checksum)
            checksum = Self.checksum(bytes, range: (offset + 24)..<(offset + 24 + pageSize), bigEndian: bigEndianChecksum, seed: checksum)
            guard checksum.0 == Self.word(bytes, offset + 16), checksum.1 == Self.word(bytes, offset + 20) else {
                throw TimelineError.inconsistentSnapshot("Chromium WAL frame checksum failed; the snapshot was rejected.")
            }
            if commit > 0 { lastCommit = index + 1; pages = commit; lastChecksum = checksum }
        }
        committedFrames = lastCommit; committedPages = pages; committedChecksum = lastChecksum
    }
    func materialize(database: Data, budget: ChromiumBudget) throws -> Data {
        guard committedFrames > 0 else { return database }
        let count = committedPages * pageSize
        var output = Data(database.prefix(count))
        if output.count < count { output.append(Data(repeating: 0, count: count - output.count)) }
        for index in 0..<committedFrames {
            try budget.check()
            let offset = 32 + index * (pageSize + 24), page = Int(Self.word(bytes, offset))
            if page <= committedPages {
                output.replaceSubrange(((page - 1) * pageSize)..<(page * pageSize), with: bytes[(offset + 24)..<(offset + 24 + pageSize)])
            }
        }
        guard output.prefix(16) == Data("SQLite format 3\0".utf8) else { throw TimelineError.inconsistentSnapshot("The committed WAL does not reconstruct a SQLite database.") }
        return output
    }
    func validateSHM(_ shm: Data) throws {
        guard shm.count >= 32_768, shm.count % 32_768 == 0, shm[0..<48] == shm[48..<96] else {
            throw TimelineError.inconsistentSnapshot("Chromium SHM headers are incomplete or disagree.")
        }
        let little = Self.word(shm, 0, little: true) == 3_007_000
        guard Self.word(shm, 0, little: little) == 3_007_000, shm[12] == 1,
              shm[13] == (bigEndianChecksum ? 1 : 0), shm[32..<40] == bytes[16..<24] else {
            throw TimelineError.inconsistentSnapshot("Chromium SHM does not match the supplied WAL.")
        }
        let encodedPage = little ? Int(shm[14]) + Int(shm[15]) * 256 : Int(shm[14]) * 256 + Int(shm[15])
        let checksum = Self.checksum(shm, range: 0..<40, bigEndian: !little, seed: (0, 0))
        guard (encodedPage == 1 ? 65_536 : encodedPage) == pageSize,
              Int(Self.word(shm, 16, little: little)) == committedFrames,
              committedFrames == 0 || Int(Self.word(shm, 20, little: little)) == committedPages,
              checksum.0 == Self.word(shm, 40, little: little), checksum.1 == Self.word(shm, 44, little: little),
              committedFrames == 0 || (Self.word(shm, 24, little: little) == committedChecksum.0 && Self.word(shm, 28, little: little) == committedChecksum.1),
              Int(Self.word(shm, 96, little: little)) <= committedFrames else {
            throw TimelineError.inconsistentSnapshot("Chromium SHM committed-frame metadata or checksum is inconsistent.")
        }
    }
    static func word(_ bytes: Data, _ offset: Int, little: Bool = false) -> UInt32 {
        if little {
            return UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8)
                | (UInt32(bytes[offset + 2]) << 16) | (UInt32(bytes[offset + 3]) << 24)
        }
        return (UInt32(bytes[offset]) << 24) | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8) | UInt32(bytes[offset + 3])
    }
    static func checksum(_ bytes: Data, range: Range<Int>, bigEndian: Bool, seed: (UInt32, UInt32)) -> (UInt32, UInt32) {
        var (first, second) = seed
        for offset in stride(from: range.lowerBound, to: range.upperBound, by: 8) {
            first = first &+ word(bytes, offset, little: !bigEndian) &+ second
            second = second &+ word(bytes, offset + 4, little: !bigEndian) &+ first
        }
        return (first, second)
    }
}

private final class ChromiumScratch {
    let directory: URL
    let databaseURL: URL
    private var parent: Int32 = -1, root: Int32 = -1, file: Int32 = -1
    private let name = "NativeForensics-Chromium-" + UUID().uuidString.lowercased()
    private var rootDevice: dev_t = 0, rootInode: ino_t = 0
    private var identity: SourceIdentity?
    private let digest: String
    init(bytes: Data) throws {
        let temporary = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        directory = temporary.appendingPathComponent(name)
        databaseURL = directory.appendingPathComponent("History")
        digest = TimelineCoding.hex(SHA256.hash(data: bytes))
        do {
            parent = Darwin.open(temporary.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard parent >= 0, Darwin.mkdirat(parent, name, 0o700) == 0 else { throw TimelineError.publication("Cannot create private Chromium scratch.") }
            root = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            var metadata = stat()
            guard root >= 0, Darwin.fstat(root, &metadata) == 0 else { throw TimelineError.publication("Cannot pin private Chromium scratch.") }
            rootDevice = metadata.st_dev; rootInode = metadata.st_ino
            file = Darwin.openat(root, "History", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard file >= 0 else { throw TimelineError.publication("Cannot write private Chromium scratch.") }
            identity = try FileAccess.identity(of: file)
            try bytes.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(file, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                    if count < 0, errno == EINTR { continue }
                    guard count > 0 else { throw TimelineError.publication("Cannot finish private Chromium scratch.") }
                    offset += count
                }
            }
            identity = try FileAccess.identity(of: file)
        } catch { remove(); throw error }
    }
    func validate(budget: ChromiumBudget) throws {
        guard let identity, file >= 0, root >= 0,
              try FileAccess.identity(of: file) == identity,
              try FileAccess.identity(at: "History", in: root) == identity else { throw TimelineError.sourceChanged }
        var current = stat()
        guard Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
              current.st_mode & S_IFMT == S_IFDIR, current.st_dev == rootDevice,
              current.st_ino == rootInode else { throw TimelineError.sourceChanged }
        var hash = SHA256(), offset: Int64 = 0, buffer = [UInt8](repeating: 0, count: 65_536)
        while offset < identity.size {
            try budget.check()
            let wanted = Int(min(Int64(buffer.count), identity.size - offset))
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(file, $0.baseAddress, wanted, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw TimelineError.sourceChanged }
            buffer.withUnsafeBytes { hash.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0[..<count])) }
            offset += Int64(count)
        }
        guard TimelineCoding.hex(hash.finalize()) == digest else { throw TimelineError.sourceChanged }
    }
    func remove() {
        if root >= 0, let identity, let current = try? FileAccess.identity(at: "History", in: root),
           current.device == identity.device, current.inode == identity.inode {
            _ = Darwin.unlinkat(root, "History", 0)
        }
        if file >= 0 { Darwin.close(file); file = -1 }
        if root >= 0 { Darwin.close(root); root = -1 }
        var current = stat()
        if parent >= 0, Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
           current.st_mode & S_IFMT == S_IFDIR, current.st_dev == rootDevice, current.st_ino == rootInode {
            _ = Darwin.unlinkat(parent, name, AT_REMOVEDIR)
        }
        if parent >= 0 { Darwin.close(parent); parent = -1 }
    }
    deinit { remove() }
}

private final class ChromiumSQLite {
    private var database: OpaquePointer?
    private let budget: ChromiumBudget
    init(url: URL, budget: ChromiumBudget) throws {
        self.budget = budget
        let uri = url.absoluteString + "?mode=ro&immutable=1"
        guard sqlite3_open_v2(uri, &database, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK else {
            if let database { sqlite3_close(database) }; database = nil
            throw TimelineError.inconsistentSnapshot("Cannot open the private SQLite snapshot read-only.")
        }
        guard nf_sqlite_harden(database) == SQLITE_OK else { close(); throw TimelineError.unsupported("SQLite defensive settings are unavailable.") }
        sqlite3_limit(database, SQLITE_LIMIT_LENGTH, 1_048_576)
        sqlite3_limit(database, SQLITE_LIMIT_SQL_LENGTH, 4_096)
        sqlite3_limit(database, SQLITE_LIMIT_COLUMN, 256)
        sqlite3_limit(database, SQLITE_LIMIT_ATTACHED, 0)
        sqlite3_limit(database, SQLITE_LIMIT_EXPR_DEPTH, 256)
        sqlite3_progress_handler(database, 1_000, { context in
            guard let context else { return 1 }
            return Unmanaged<ChromiumBudget>.fromOpaque(context).takeUnretainedValue().interrupted ? 1 : 0
        }, Unmanaged.passUnretained(budget).toOpaque())
        do {
            try rows("PRAGMA quick_check") { statement in
                guard try text(statement, 0, limit: 32) == "ok" else { throw TimelineError.inconsistentSnapshot("The private SQLite snapshot failed its integrity check.") }
            }
        } catch { close(); throw error }
    }
    func close() { if let database { sqlite3_close(database); self.database = nil } }
    func events(input: VerifiedBrowserArtifact) throws -> [TimelineEvent] {
        try requireTable("urls", columns: ["id", "url", "title"])
        try requireTable("visits", columns: ["id", "url", "visit_time"])
        var output = [TimelineEvent](), identities = Set<String>(), estimatedBytes = 65_536
        func append(_ event: TimelineEvent) throws {
            guard output.count < TimelineLimits.maximumBrowserEvents else { throw TimelineError.limitExceeded("Chromium artifacts exceed 20,000 timeline events; no partial timeline was published.") }
            let addition = (event.title.utf8.count + event.detail.utf8.count + event.evidencePath.utf8.count
                + event.fileID.utf8.count + event.timestamp.rawValue.utf8.count) * 6 + 2_048
            guard addition <= TimelineLimits.maximumReportBytes - estimatedBytes else {
                throw TimelineError.limitExceeded("Chromium timeline events exceed the 64 MiB report budget.")
            }
            guard identities.insert(event.id).inserted else { throw TimelineError.inconsistentSnapshot("Duplicate Chromium row identities make the snapshot ambiguous.") }
            estimatedBytes += addition; output.append(event)
        }
        try rows("SELECT v.id,v.visit_time,u.url,u.title FROM visits v LEFT JOIN urls u ON u.id=v.url ORDER BY v.id LIMIT 20001") { row in
            let id = try integer(row, 0), raw = try integer(row, 1)
            let url = try text(row, 2, limit: 2_048), title = try text(row, 3, limit: 1_024)
            try append(event(input, kind: .browserVisit, id: id, raw: raw, field: "visits.visit_time", title: title.isEmpty ? url : title, detail: url))
        }
        if try tableExists("downloads") {
            try requireTable("downloads", columns: ["id", "target_path", "start_time", "end_time", "received_bytes", "total_bytes", "state"])
            let hasChains = try tableExists("downloads_url_chains")
            if hasChains { try requireTable("downloads_url_chains", columns: ["id", "chain_index", "url"]) }
            let query = "SELECT id,target_path,start_time,end_time,received_bytes,total_bytes,state FROM downloads ORDER BY id LIMIT 20001"
            try rows(query) { row in
                let id = try integer(row, 0), target = try text(row, 1, limit: 2_048)
                let start = try integer(row, 2), end = try integer(row, 3)
                let received = try integer(row, 4), total = try integer(row, 5), state = try integer(row, 6)
                guard received >= 0, total >= 0 else { throw TimelineError.inconsistentSnapshot("Chromium download byte counts are invalid.") }
                var detail = "Target: \(target) · received \(received)/\(total) bytes · state \(state)"
                if hasChains, let url = try downloadURL(id: id) { detail += " · URL: \(url)" }
                try append(event(input, kind: .downloadStarted, id: id, raw: start, field: "downloads.start_time", title: "Download started", detail: detail))
                // A zero end-time means no end was recorded, not the year 1601.
                if end != 0 { try append(event(input, kind: .downloadEnded, id: id, raw: end, field: "downloads.end_time", title: "Download ended", detail: detail)) }
            }
        }
        return output
    }
    private func event(_ input: VerifiedBrowserArtifact, kind: TimelineEventKind, id: Int64, raw: Int64, field: String, title: String, detail: String) throws -> TimelineEvent {
        struct EventIdentity: Encodable {
            let parser: String
            let caseID: UUID
            let evidenceID: UUID
            let snapshotSHA256: String
            let fileID: String
            let databaseSHA256: String
            let walSHA256: String?
            let shmSHA256: String?
            let kind: TimelineEventKind
            let recordID: Int64
        }
        let timestamp = TimelineTimestamp.chromium(microseconds: raw)
        let identity = try TimelineCoding.digest(EventIdentity(parser: ChromiumHistoryParser.version,
            caseID: input.binding.caseID, evidenceID: input.binding.evidenceID, snapshotSHA256: input.binding.snapshotSHA256,
            fileID: input.database.fileID, databaseSHA256: input.database.sha256, walSHA256: input.wal?.sha256,
            shmSHA256: input.shm?.sha256, kind: kind, recordID: id))
        return TimelineEvent(id: identity,
            kind: kind, timestamp: timestamp, fileID: input.database.fileID, evidencePath: input.database.evidencePath,
            title: title, detail: "\(detail) · \(field)=\(raw)", parser: ChromiumHistoryParser.version, recordID: "\(id)", artifactSHA256: input.database.sha256)
    }
    private func tableExists(_ name: String) throws -> Bool {
        var count = 0
        try rows("SELECT type,rootpage,sql FROM sqlite_schema WHERE name='\(name)'") { row in
            count += 1
            let type = try text(row, 0, limit: 32), root = try integer(row, 1), sql = try text(row, 2, limit: 4_096)
            guard type == "table", root > 0, !sql.uppercased().contains("CREATE VIRTUAL TABLE") else { throw TimelineError.unsupported("Chromium tables must be ordinary stored SQLite tables.") }
        }
        guard count <= 1 else { throw TimelineError.inconsistentSnapshot("Ambiguous Chromium schema.") }
        return count == 1
    }
    private func requireTable(_ name: String, columns: Set<String>) throws {
        guard try tableExists(name) else { throw TimelineError.unsupported("The database does not contain the supported Chromium \(name) schema.") }
        var actual = Set<String>()
        try rows("PRAGMA table_info('\(name)')") { row in actual.insert(try text(row, 1, limit: 256)) }
        guard columns.isSubset(of: actual) else { throw TimelineError.unsupported("Unsupported Chromium \(name) columns; no schema was guessed.") }
    }
    private func downloadURL(id: Int64) throws -> String? {
        var url: String?
        try rows("SELECT url,chain_index FROM downloads_url_chains WHERE id=\(id) ORDER BY chain_index DESC LIMIT 1") { row in
            guard try integer(row, 1) >= 0 else { throw TimelineError.inconsistentSnapshot("Invalid Chromium download chain index.") }
            url = try text(row, 0, limit: 2_048)
        }
        return url
    }
    private func rows(_ sql: String, consume: (OpaquePointer) throws -> Void) throws {
        try budget.check()
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            try budget.check(); throw TimelineError.inconsistentSnapshot("The Chromium SQLite query could not be prepared.")
        }
        defer { sqlite3_finalize(statement) }
        while true {
            try budget.check()
            let status = sqlite3_step(statement)
            if status == SQLITE_DONE { return }
            guard status == SQLITE_ROW else { try budget.check(); throw TimelineError.inconsistentSnapshot("The Chromium SQLite query failed.") }
            try consume(statement)
        }
    }
    private func integer(_ row: OpaquePointer, _ index: Int32) throws -> Int64 {
        guard sqlite3_column_type(row, index) == SQLITE_INTEGER else { throw TimelineError.inconsistentSnapshot("Chromium integer fields cannot be missing, text, or floating-point values.") }
        return sqlite3_column_int64(row, index)
    }
    private func text(_ row: OpaquePointer, _ index: Int32, limit: Int) throws -> String {
        guard sqlite3_column_type(row, index) == SQLITE_TEXT, let pointer = sqlite3_column_text(row, index) else {
            throw TimelineError.inconsistentSnapshot("Chromium text fields cannot be missing or non-text values.")
        }
        let count = Int(sqlite3_column_bytes(row, index))
        guard count <= limit else { throw TimelineError.limitExceeded("A Chromium text field exceeds the supported timeline size.") }
        let bytes = Data(bytes: pointer, count: count)
        guard !bytes.contains(0), let value = String(data: bytes, encoding: .utf8) else { throw TimelineError.inconsistentSnapshot("Chromium text is not bounded UTF-8.") }
        return value
    }
}
