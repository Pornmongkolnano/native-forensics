import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@_silgen_name("flock")
private func readinessCoreFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

@Suite("Core readiness regressions")
struct ReadinessCoreTests {
    @Test("Edited manifests cannot treat case output files as evidence")
    func caseInternalEvidenceIsRejected() throws {
        let temporary = try ReadinessDirectory()
        defer { temporary.remove() }
        let original = try CaseStore.create(name: "Boundary", in: temporary.url)
        let manifestURL = original.bundleURL.appendingPathComponent("manifest.json")
        let paths = [manifestURL.path, original.bundleURL.appendingPathComponent("filesystem/output.raw").path]
        for path in paths {
            let data = try manifestData(original.manifest, evidence: [record(path: path)])
            try data.write(to: manifestURL)
            #expect(throws: ForensicsError.self) { try CaseStore.open(at: original.bundleURL) }
            #expect(try Data(contentsOf: manifestURL) == data)
        }
    }

    @Test("Absolute paths with traversal or alternate spellings are malformed")
    func noncanonicalManifestPathsAreRejected() throws {
        let temporary = try ReadinessDirectory()
        defer { temporary.remove() }
        let original = try CaseStore.create(name: "Path validation", in: temporary.url)
        let manifestURL = original.bundleURL.appendingPathComponent("manifest.json")
        for path in ["/", "/offline/./evidence.raw", "/offline/sub/../evidence.raw", "//offline/evidence.raw", "/offline//evidence.raw", "/offline/evidence.raw/"] {
            let data = try manifestData(original.manifest, evidence: [record(path: path)])
            try data.write(to: manifestURL)
            #expect(throws: ForensicsError.self) { try CaseStore.open(at: original.bundleURL) }
            #expect(try Data(contentsOf: manifestURL) == data)
        }
    }

    @Test("Historical cases open without reading a missing source or rejecting sibling prefixes")
    func historicalSourcesRemainOffline() throws {
        let temporary = try ReadinessDirectory()
        defer { temporary.remove() }
        let original = try CaseStore.create(name: "History", in: temporary.url)
        let missing = original.bundleURL.path + "-source/evidence.raw"
        let data = try manifestData(original.manifest, evidence: [record(path: missing)])
        try data.write(to: original.bundleURL.appendingPathComponent("manifest.json"))
        #expect(!FileManager.default.fileExists(atPath: missing))
        let reopened = try CaseStore.open(at: original.bundleURL)
        #expect(reopened.manifest.evidence.first?.sourcePath == missing)
        #expect(!FileManager.default.fileExists(atPath: missing))
    }

    @Test("Pinned metadata reads cannot be redirected by an ancestor symbolic link swap")
    func pinnedDirectoryRead() throws {
        let temporary = try ReadinessDirectory()
        defer { temporary.remove() }
        let opened = temporary.url.appendingPathComponent("opened", isDirectory: true)
        let moved = temporary.url.appendingPathComponent("moved", isDirectory: true)
        let target = temporary.url.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: opened, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        let original = Data("original metadata".utf8)
        let external = Data("unrelated metadata".utf8)
        try original.write(to: opened.appendingPathComponent("manifest.json"))
        try external.write(to: target.appendingPathComponent("manifest.json"))
        let parent = Darwin.open(opened.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        #expect(parent >= 0)
        defer { Darwin.close(parent) }
        try FileManager.default.moveItem(at: opened, to: moved)
        try FileManager.default.createSymbolicLink(at: opened, withDestinationURL: target)
        let descriptor = try FileAccess.openReadOnly("manifest.json", in: parent)
        defer { Darwin.close(descriptor) }
        var bytes = [UInt8](repeating: 0, count: 64)
        let count = try bytes.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: $0.count) }
        #expect(Data(bytes.prefix(count)) == original)
        #expect(try Data(contentsOf: target.appendingPathComponent("manifest.json")) == external)
        #expect(throws: ForensicsError.invalidFileURL) { try FileAccess.openReadOnly("../outside/manifest.json", in: parent) }
        #expect(throws: ForensicsError.invalidFileURL) { try FileAccess.openReadOnly(target.appendingPathComponent("manifest.json").path, in: parent) }
    }

    @Test("Case lock symbolic links cannot mutate either manifest or external file")
    func caseLockLinkIsRejected() async throws {
        let temporary = try ReadinessDirectory()
        defer { temporary.remove() }
        let source = temporary.url.appendingPathComponent("source.raw")
        let external = temporary.url.appendingPathComponent("unrelated.lock")
        try Data("source bytes".utf8).write(to: source)
        let unrelated = Data("unrelated bytes".utf8)
        try unrelated.write(to: external)
        let image = try await ImageInspector.inspect(url: source, progress: { _ in })
        let original = try CaseStore.create(name: "Lock boundary", in: temporary.url)
        let manifestURL = original.bundleURL.appendingPathComponent("manifest.json")
        let manifestBefore = try Data(contentsOf: manifestURL)
        let lockURL = original.bundleURL.appendingPathComponent(".case.lock")
        try FileManager.default.removeItem(at: lockURL)
        try FileManager.default.createSymbolicLink(at: lockURL, withDestinationURL: external)
        #expect(throws: ForensicsError.self) { try CaseStore.adding(image: image, to: original) }
        #expect(try Data(contentsOf: manifestURL) == manifestBefore)
        #expect(try Data(contentsOf: external) == unrelated)
        #expect(try Data(contentsOf: source) == Data("source bytes".utf8))
    }

    @Test("A queued case transaction cannot write through a replaced bundle directory")
    func queuedCaseDirectorySwapIsRejected() async throws {
        let temporary = try ReadinessDirectory()
        defer { temporary.remove() }
        let source = temporary.url.appendingPathComponent("source.raw")
        let sourceBytes = Data("source bytes".utf8)
        try sourceBytes.write(to: source)
        let image = try await ImageInspector.inspect(url: source, progress: { _ in })
        let original = try CaseStore.create(name: "Queued", in: temporary.url)
        let external = try CaseStore.create(name: "Unrelated", in: temporary.url)
        let moved = temporary.url.appendingPathComponent("Moved.nativecase", isDirectory: true)
        let originalData = try Data(contentsOf: original.bundleURL.appendingPathComponent("manifest.json"))
        // A copied case has the same case UUID and manifest; pathname validation
        // must still keep a waiting transaction bound to the original directory.
        try originalData.write(to: external.bundleURL.appendingPathComponent("manifest.json"))
        let lockURL = original.bundleURL.appendingPathComponent(".case.lock")
        let lock = Darwin.open(lockURL.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        #expect(lock >= 0)
        defer { Darwin.close(lock) }
        let identity = try FileAccess.identity(of: lock)
        #expect(readinessCoreFlock(lock, LOCK_EX) == 0)
        defer { _ = readinessCoreFlock(lock, LOCK_UN) }
        let transaction = ReadinessTransaction()
        // flock is a blocking system call. Keep this deliberately queued writer
        // off Swift's cooperative executor so parallel suites cannot starve it.
        let writer = Thread {
            transaction.complete(Result { try CaseStore.adding(image: image, to: original) })
        }
        writer.start()

        // Observe its second descriptor to our unique lock inode instead of
        // guessing a sleep duration. The caller has opened the case and lock,
        // and cannot pass LOCK_EX while this test owns the lock.
        var waiting = false
        let deadline = ContinuousClock().now.advanced(by: .seconds(3))
        while ContinuousClock().now < deadline {
            if descriptors(matching: identity) >= 2 { waiting = true; break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(waiting)
        if !waiting {
            _ = readinessCoreFlock(lock, LOCK_UN)
            _ = await transaction.value()
            return
        }
        try FileManager.default.moveItem(at: original.bundleURL, to: moved)
        try FileManager.default.createSymbolicLink(at: original.bundleURL, withDestinationURL: external.bundleURL)
        #expect(readinessCoreFlock(lock, LOCK_UN) == 0)
        let result = await transaction.value()
        switch result {
        case .success: Issue.record("A transaction was published through a replaced case directory.")
        case .failure(let error):
            if case .invalidCase = error as? ForensicsError {} else {
                Issue.record("Expected a changed-directory error, got \(error)")
            }
        }
        #expect(try Data(contentsOf: moved.appendingPathComponent("manifest.json")) == originalData)
        #expect(try Data(contentsOf: external.bundleURL.appendingPathComponent("manifest.json")) == originalData)
        #expect(try Data(contentsOf: source) == sourceBytes)
    }

    private func descriptors(matching identity: SourceIdentity) -> Int {
        var count = 0
        for descriptor in Int32(0)..<Int32(min(getdtablesize(), 4096)) {
            var metadata = stat()
            if Darwin.fstat(descriptor, &metadata) == 0,
               metadata.st_dev == identity.device, metadata.st_ino == identity.inode { count += 1 }
        }
        return count
    }

    private func record(path: String) -> EvidenceRecord {
        EvidenceRecord(sourcePath: path, byteCount: 3,
                       sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                       container: .raw, filesystemHint: nil)
    }

    private func manifestData(_ current: CaseManifest, evidence: [EvidenceRecord]) throws -> Data {
        let manifest = CaseManifest(id: current.id, name: current.name, createdAt: current.createdAt, evidence: evidence)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(manifest)
    }
}

private final class ReadinessTransaction: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<ForensicCase, Error>?
    private var continuation: CheckedContinuation<Result<ForensicCase, Error>, Never>?

    func complete(_ value: Result<ForensicCase, Error>) {
        lock.lock()
        result = value
        let waiter = continuation
        continuation = nil
        lock.unlock()
        waiter?.resume(returning: value)
    }

    func value() async -> Result<ForensicCase, Error> {
        await withCheckedContinuation { waiter in
            lock.lock()
            let completed = result
            if completed == nil { continuation = waiter }
            lock.unlock()
            if let completed { waiter.resume(returning: completed) }
        }
    }
}

private struct ReadinessDirectory {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("ReadinessCore-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    }

    func remove() { try? FileManager.default.removeItem(at: url) }
}
