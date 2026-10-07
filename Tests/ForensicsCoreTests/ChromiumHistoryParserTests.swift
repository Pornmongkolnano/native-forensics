import CSQLite3
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

struct ChromiumHistoryParserTests {
    @Test("Apple system SQLite hardening supports ordinary reads and denies writes and extension execution")
    func sqliteHardening() throws {
        var database: OpaquePointer?
        #expect(sqlite3_open_v2(":memory:", &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK)
        let opened = try #require(database)
        defer { sqlite3_close(opened) }
        #expect(sqlite3_exec(opened, "CREATE TABLE synthetic(id INTEGER)", nil, nil, nil) == SQLITE_OK)
        #expect(nf_sqlite_harden(opened) == SQLITE_OK)
        #expect(sqlite3_exec(opened, "SELECT id FROM synthetic", nil, nil, nil) == SQLITE_OK)
        #expect(sqlite3_exec(opened, "PRAGMA quick_check", nil, nil, nil) == SQLITE_OK)
        #expect(sqlite3_exec(opened, "INSERT INTO synthetic VALUES(1)", nil, nil, nil) == SQLITE_AUTH)
        #expect(sqlite3_exec(opened, "SELECT load_extension('synthetic-denied')", nil, nil, nil) != SQLITE_OK)
    }

    @Test("SQLite rows preserve exact Chromium microseconds and receipts without changing artifact bytes")
    func standaloneRows() async throws {
        let fixture = try ChromiumFixture(mode: "standalone")
        defer { fixture.remove() }
        let events = try await ChromiumHistoryParser.parse(input: fixture.input())
        #expect(events.count == 3)
        let visit = try #require(events.first { $0.kind == .browserVisit })
        #expect(visit.title == "Synthetic example")
        #expect(visit.detail.contains("https://example.test/one"))
        #expect(visit.timestamp.epochSeconds == 1_700_000_000)
        #expect(visit.timestamp.nanoseconds == 123_456_000)
        #expect(visit.timestamp.rawValue == "13344473600123456")
        #expect(visit.timestamp.precision == "microsecond")
        #expect(visit.recordID == "1")
        #expect(visit.artifactSHA256 == fixture.database.sha256)
        #expect(EngineValidation.validHash(visit.id))
        #expect(events.first { $0.kind == .downloadEnded }?.timestamp.nanoseconds == 987_654_000)
        #expect(events.first { $0.kind == .downloadStarted }?.detail.contains("https://example.test/download") == true)
        try fixture.expectUnchanged()
        #expect(events == (try await ChromiumHistoryParser.parse(input: fixture.input())))
    }

    @Test("Committed WAL rows are recovered from a private clone, with and without transient SHM", arguments: [false, true])
    func committedWAL(includeSHM: Bool) async throws {
        let fixture = try ChromiumFixture(mode: "wal")
        defer { fixture.remove() }
        let events = try await ChromiumHistoryParser.parse(input: fixture.input(includeSHM: includeSHM))
        #expect(events.filter { $0.kind == .browserVisit }.map(\.recordID) == ["1", "2"])
        #expect(events.first { $0.recordID == "2" }?.detail.contains("https://example.test/wal-committed") == true)
        try fixture.expectUnchanged()
    }

    @Test("Checksum-valid uncommitted WAL tail is excluded from the committed timeline")
    func uncommittedTail() async throws {
        let fixture = try ChromiumFixture(mode: "uncommitted")
        defer { fixture.remove() }
        let events = try await ChromiumHistoryParser.parse(input: fixture.input())
        #expect(events.filter { $0.kind == .browserVisit }.map(\.recordID) == ["1", "2"])
        #expect(!events.contains { $0.detail.contains("uncommitted") })
        try fixture.expectUnchanged()
    }

    @Test("Event identities bind the exact WAL receipt even when main database and row facts are unchanged")
    func sidecarIdentity() async throws {
        let first = try ChromiumFixture(mode: "wal"), second = try ChromiumFixture(mode: "uncommitted")
        defer { first.remove(); second.remove() }
        #expect(first.database.sha256 == second.database.sha256)
        let firstInput = VerifiedBrowserArtifact(binding: first.binding, database: first.database, wal: first.wal)
        let secondInput = VerifiedBrowserArtifact(binding: first.binding, database: first.database, wal: second.wal)
        let firstEvents = try await ChromiumHistoryParser.parse(input: firstInput)
        let secondEvents = try await ChromiumHistoryParser.parse(input: secondInput)
        #expect(firstEvents.map(\.recordID) == secondEvents.map(\.recordID))
        #expect(firstEvents.map(\.timestamp) == secondEvents.map(\.timestamp))
        #expect(firstEvents.map(\.id) != secondEvents.map(\.id))
        try first.expectUnchanged(); try second.expectUnchanged()
    }

    @Test("Missing listed WAL and SHM never silently reduce the parsed snapshot", arguments: ["wal", "shm"])
    func missingSidecars(_ role: String) async throws {
        let fixture = try ChromiumFixture(mode: "wal")
        defer { fixture.remove() }
        let input = VerifiedBrowserArtifact(binding: fixture.binding, database: fixture.database,
            wal: role == "wal" ? nil : fixture.wal, shm: nil, expectedWAL: true, expectedSHM: role == "shm")
        await #expect(throws: TimelineError.self) { try await ChromiumHistoryParser.parse(input: input) }
        try fixture.expectUnchanged()
    }

    @Test("Incorrect WAL checksums, truncated WAL, and mismatched SHM are rejected", arguments: ["corrupt-wal", "truncated-wal", "mismatched-shm"])
    func inconsistentSidecars(_ mode: String) async throws {
        let fixture = try ChromiumFixture(mode: mode)
        defer { fixture.remove() }
        await #expect(throws: TimelineError.self) { try await ChromiumHistoryParser.parse(input: fixture.input()) }
        try fixture.expectUnchanged()
    }

    @Test("Same-sized changed bytes and symlink artifacts cannot satisfy the extracted receipt", arguments: [false, true])
    func receiptMismatch(symlink: Bool) async throws {
        let fixture = try ChromiumFixture(mode: "standalone")
        defer { fixture.remove() }
        let original = fixture.database
        if symlink {
            let alias = fixture.root.appendingPathComponent("Alias")
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: original.url)
            let changed = VerifiedArtifactFile(url: alias, fileID: original.fileID, evidencePath: original.evidencePath, byteCount: original.byteCount, sha256: original.sha256)
            await #expect(throws: (any Error).self) {
                try await ChromiumHistoryParser.parse(input: VerifiedBrowserArtifact(binding: fixture.binding, database: changed))
            }
        } else {
            var bytes = try Data(contentsOf: original.url); bytes[bytes.count - 1] ^= 1
            try bytes.write(to: original.url)
            await #expect(throws: TimelineError.sourceChanged) { try await ChromiumHistoryParser.parse(input: fixture.input()) }
        }
    }

    @Test("Sidecars are matched by exact evidence path instead of extracted host filename")
    func wrongSidecarPath() async throws {
        let fixture = try ChromiumFixture(mode: "wal")
        defer { fixture.remove() }
        let wal = try #require(fixture.wal)
        let mismatch = VerifiedArtifactFile(url: wal.url, fileID: wal.fileID, evidencePath: "/other-profile/History-wal", byteCount: wal.byteCount, sha256: wal.sha256)
        await #expect(throws: TimelineError.self) {
            try await ChromiumHistoryParser.parse(input: VerifiedBrowserArtifact(binding: fixture.binding, database: fixture.database, wal: mismatch))
        }
    }

    @Test("Unsupported schemas, ambiguous row IDs, and noninteger timestamps do not become guessed events", arguments: ["missing-schema", "duplicate-visits", "text-time", "view-schema"])
    func strictSchema(_ mode: String) async throws {
        let fixture = try ChromiumFixture(mode: mode)
        defer { fixture.remove() }
        await #expect(throws: TimelineError.self) { try await ChromiumHistoryParser.parse(input: fixture.input()) }
        try fixture.expectUnchanged()
    }

    @Test("More than 20000 events is a failure, never a truncated successful timeline")
    func eventLimit() async throws {
        let fixture = try ChromiumFixture(mode: "too-many")
        defer { fixture.remove() }
        await #expect(throws: TimelineError.self) { try await ChromiumHistoryParser.parse(input: fixture.input()) }
        try fixture.expectUnchanged()
    }

    @Test("Pre-cancelled caller never publishes browser events")
    func cancellation() async throws {
        let fixture = try ChromiumFixture(mode: "standalone")
        defer { fixture.remove() }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await ChromiumHistoryParser.parse(input: fixture.input())
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        try fixture.expectUnchanged()
    }

    @Test("Oversized receipt is rejected before a database can be opened")
    func databaseByteLimit() async throws {
        let binding = ChromiumFixture.makeBinding()
        let file = VerifiedArtifactFile(url: URL(fileURLWithPath: "/nonexistent-synthetic-history"), fileID: "history", evidencePath: "/profile/History", byteCount: ChromiumHistoryParser.maximumDatabaseBytes + 1, sha256: String(repeating: "a", count: 64))
        await #expect(throws: TimelineError.self) {
            try await ChromiumHistoryParser.parse(input: VerifiedBrowserArtifact(binding: binding, database: file))
        }
    }
}

/// Python's standard SQLite library produces the database/WAL independently of
/// the production C API. The only manually transformed fixture is an explicitly
/// uncommitted, checksum-valid WAL tail; Python supplies the independent checksum.
private final class ChromiumFixture: @unchecked Sendable {
    let root: URL
    let database: VerifiedArtifactFile
    let wal: VerifiedArtifactFile?
    let shm: VerifiedArtifactFile?
    let binding: TimelineSourceBinding
    private let originals: [URL: Data]

    init(mode: String) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("Chromium-parser-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let script = root.appendingPathComponent("fixture.py")
        try Data(Self.python.utf8).write(to: script)
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", script.path, root.path, mode]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            try? FileManager.default.removeItem(at: root)
            throw TimelineError.invalidInput("Synthetic Python SQLite fixture failed.")
        }
        let databaseURL = root.appendingPathComponent("receipt-main")
        let walURL = root.appendingPathComponent("receipt-wal"), shmURL = root.appendingPathComponent("receipt-shm")
        database = try Self.receipt(databaseURL, id: "history", path: "/profile/History")
        wal = FileManager.default.fileExists(atPath: walURL.path) ? try Self.receipt(walURL, id: "wal", path: "/profile/History-wal") : nil
        shm = FileManager.default.fileExists(atPath: shmURL.path) ? try Self.receipt(shmURL, id: "shm", path: "/profile/History-shm") : nil
        binding = Self.makeBinding()
        originals = try Dictionary(uniqueKeysWithValues: [database, wal, shm].compactMap { $0 }.map { ($0.url, try Data(contentsOf: $0.url)) })
    }
    static func makeBinding() -> TimelineSourceBinding {
        TimelineSourceBinding(caseID: UUID(), evidenceID: UUID(), snapshotSHA256: String(repeating: "b", count: 64), orderedContainerSHA256: [String(repeating: "c", count: 64)], logicalImageSHA256: nil, engineVersion: "synthetic-engine", engineTimezone: "UTC", snapshotSavedAt: Date(timeIntervalSince1970: 1_700_000_000), listingStatus: .completed, historical: false)
    }
    func input(includeSHM: Bool = true) -> VerifiedBrowserArtifact {
        VerifiedBrowserArtifact(binding: binding, database: database, wal: wal, shm: includeSHM ? shm : nil, expectedWAL: wal != nil, expectedSHM: includeSHM && shm != nil)
    }
    func expectUnchanged() throws {
        for (url, original) in originals { #expect(try Data(contentsOf: url) == original) }
        #expect(!FileManager.default.fileExists(atPath: database.url.path + "-wal"))
        #expect(!FileManager.default.fileExists(atPath: database.url.path + "-shm"))
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
    private static func receipt(_ url: URL, id: String, path: String) throws -> VerifiedArtifactFile {
        let bytes = try Data(contentsOf: url)
        return VerifiedArtifactFile(url: url, fileID: id, evidencePath: path, byteCount: Int64(bytes.count), sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined())
    }
    private static let python = #"""
import os, pathlib, sqlite3, struct, sys
root, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
path = root / 'generator-history'
db = sqlite3.connect(path)
db.execute('CREATE TABLE urls(id INTEGER, url TEXT, title TEXT)')
db.execute('CREATE TABLE visits(id INTEGER, url INTEGER, visit_time INTEGER)')
db.execute('CREATE TABLE downloads(id INTEGER,target_path TEXT,start_time INTEGER,end_time INTEGER,received_bytes INTEGER,total_bytes INTEGER,state INTEGER)')
db.execute('CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT)')
db.execute('INSERT INTO urls VALUES(1,?,?)', ('https://example.test/one', 'Synthetic example'))
db.execute('INSERT INTO visits VALUES(1,1,13344473600123456)')
db.execute('INSERT INTO downloads VALUES(7,?,13344473601123456,13344473602987654,123,123,1)', ('/synthetic/download.txt',))
db.execute('INSERT INTO downloads_url_chains VALUES(7,0,?)', ('https://example.test/download',))
db.commit()
wal_mode = mode in ('wal','uncommitted','corrupt-wal','truncated-wal','mismatched-shm')
if wal_mode:
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('INSERT INTO urls VALUES(2,?,?)', ('https://example.test/wal-committed', 'Committed WAL row'))
    db.execute('INSERT INTO visits VALUES(2,2,13344473603123456)')
    db.commit()
    walpath, shmpath = pathlib.Path(str(path)+'-wal'), pathlib.Path(str(path)+'-shm')
    wal = bytearray(walpath.read_bytes())
    shm = shmpath.read_bytes()
    if mode == 'uncommitted':
        oldlen = len(wal)
        db.execute('INSERT INTO urls VALUES(3,?,?)', ('https://example.test/uncommitted', 'Uncommitted tail row'))
        db.execute('INSERT INTO visits VALUES(3,3,13344473604123456)')
        db.commit()
        wal = bytearray(walpath.read_bytes())
        pagesize = struct.unpack('>I', wal[8:12])[0]
        endian = '<' if struct.unpack('>I', wal[:4])[0] == 0x377f0682 else '>'
        def checksum(data, state):
            first, second = state
            words = struct.unpack(endian + str(len(data)//4)+'I', data)
            for index in range(0, len(words), 2):
                first = (first+words[index]+second) & 0xffffffff
                second = (second+words[index+1]+first) & 0xffffffff
            return first, second
        state = checksum(wal[:24], (0,0))
        for offset in range(32, len(wal), pagesize+24):
            if offset >= oldlen: wal[offset+4:offset+8] = b'\0'*4
            state = checksum(wal[offset:offset+8], state)
            state = checksum(wal[offset+24:offset+24+pagesize], state)
            wal[offset+16:offset+24] = struct.pack('>II', *state)
    if mode == 'corrupt-wal': wal[-1] ^= 1
    if mode == 'truncated-wal': wal = wal[:-1]
    if mode == 'mismatched-shm':
        shm = bytearray(shm); shm[32] ^= 1; shm[80] ^= 1
    (root / 'receipt-wal').write_bytes(wal)
    (root / 'receipt-shm').write_bytes(shm)
else:
    if mode == 'missing-schema': db.execute('DROP TABLE visits')
    if mode == 'duplicate-visits': db.execute('INSERT INTO visits VALUES(1,1,13344473600123456)')
    if mode == 'text-time': db.execute("UPDATE visits SET visit_time='not-an-integer'")
    if mode == 'view-schema':
        db.execute('DROP TABLE visits'); db.execute('CREATE VIEW visits AS SELECT 1 AS id,1 AS url,13344473600123456 AS visit_time')
    if mode == 'too-many':
        db.executemany('INSERT INTO visits VALUES(?,1,13344473600123456)', ((value,) for value in range(2,20002)))
    db.commit()
(root / 'receipt-main').write_bytes(path.read_bytes())
db.close()
"""#
}
