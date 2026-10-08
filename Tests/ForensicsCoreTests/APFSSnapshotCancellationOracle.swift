import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Actual APFS snapshot cooperative cancellation", .serialized)
struct APFSSnapshotCancellationOracle {
    private static let enabled = ProcessInfo.processInfo.environment["NF_APFS_SNAPSHOT_INTEGRATION"] == "1"

    @Test("Cancellation at snapshot-client startup drains the actual command before cleanup and preserves the source",
          .enabled(if: APFSSnapshotCancellationOracle.enabled))
    func cooperativeSnapshotMountCancellation() async throws {
        let context = try APFSSnapshotCancellationContext()
        // Failure/quarantine is retained. Cleanup only removes known empty
        // directories; it never recursively deletes a backing image or mount.
        defer { try? context.cleanupIfEmpty() }
        let before = try await ImageInspector.inspect(url: context.image, progress: { _ in })
        try context.requireUnchangedSource()
        #expect(before.sha256 == APFSSnapshotCancellationContext.sha256)
        #expect(before.byteCount == 392_537 && before.sourceIdentity == context.sourceIdentity)
        let evidence = EvidenceRecord(sourcePath: context.image.path, byteCount: before.byteCount,
            sha256: before.sha256, container: before.container, filesystemHint: before.filesystemHint)
        let control = APFSSnapshotCancellationControl()
        let adapter = APFSMountedImageAdapter(scratchRoot: context.scratch) { event in control.observe(event) }
        let options = APFSReadOptions(maximumEntries: 128, maximumFileBytes: 32_768,
            maximumContainerBytes: 1_048_576, commandTimeoutSeconds: 30, maximumDepth: 8,
            maximumMetadataBytes: 65_536, maximumAggregateFileBytes: 65_536, jobTimeoutSeconds: 180,
            selectedVolumeUUID: APFSSnapshotCancellationContext.volumeUUID,
            selectedSnapshotUUID: APFSSnapshotCancellationContext.snapshotUUID)
        let task = Task {
            await control.waitUntilInstalled()
            return try await adapter.inspect(evidence: evidence, options: options)
        }
        control.install(task)
        defer { control.releaseTask() }
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        let observed = control.observation()
        #expect(observed.requested && observed.started == 1 && observed.terminal == 1)
        #expect(observed.detached == 1 && observed.mounted == 0 && observed.validOrder)
        // .mounted precedes creation/use of the directory walker in inspect.
        // Its absence plus CancellationError rules out file walking or a result
        // publication; this test never invokes an output cache/export API.
        try context.requireEmptyScratch()
        try context.requireUnchangedSource()
        let after = try await ImageInspector.inspect(url: context.image, progress: { _ in })
        #expect(after.sha256 == before.sha256 && after.byteCount == before.byteCount)
        #expect(after.sourceIdentity == before.sourceIdentity)
        try context.requireUnchangedSource()
        try context.cleanupIfEmpty()
    }
}

private final class APFSSnapshotCancellationControl: @unchecked Sendable {
    struct Observation: Sendable {
        let requested: Bool
        let started: Int
        let terminal: Int
        let detached: Int
        let mounted: Int
        let validOrder: Bool
    }
    private let lock = NSLock()
    private var task: Task<APFSInspectionResult, any Error>?
    private var installationWaiter: CheckedContinuation<Void, Never>?
    private var requested = false
    private var started = 0, terminal = 0, detached = 0, mounted = 0
    private var validOrder = true

    func waitUntilInstalled() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if task != nil { lock.unlock(); continuation.resume() }
            else { installationWaiter = continuation; lock.unlock() }
        }
    }
    func install(_ value: Task<APFSInspectionResult, any Error>) {
        lock.lock()
        task = value
        let pendingCancellation = requested, waiter = installationWaiter
        installationWaiter = nil
        lock.unlock()
        if pendingCancellation { value.cancel() }
        waiter?.resume()
    }
    func observe(_ event: APFSReadLifecycleStage) {
        lock.lock()
        var cancellationTarget: Task<APFSInspectionResult, any Error>?
        switch event {
        case .snapshotMountClientStarted(let pid):
            started += 1
            validOrder = validOrder && pid > 0 && started == 1 && terminal == 0 && detached == 0
            requested = true
            cancellationTarget = task
        case .snapshotMountCommandTerminal:
            terminal += 1
            validOrder = validOrder && started == 1 && terminal == 1 && detached == 0
        case .mounted:
            mounted += 1
        case .detached:
            detached += 1
            validOrder = validOrder && started == 1 && terminal == 1 && detached == 1
        default:
            break
        }
        lock.unlock()
        cancellationTarget?.cancel()
    }
    func observation() -> Observation {
        lock.lock(); defer { lock.unlock() }
        return .init(requested: requested, started: started, terminal: terminal,
            detached: detached, mounted: mounted, validOrder: validOrder)
    }
    func releaseTask() { lock.lock(); task = nil; lock.unlock() }
}

private final class APFSSnapshotCancellationContext {
    static let sha256 = "11ddb1a8aa08625a21ba923efdf3cc8c1c11928db0d936d3d009a14651c502b6"
    static let volumeUUID = UUID(uuidString: "3322234B-EE3F-467B-9D1E-D1E430DF8F5B")!
    static let snapshotUUID = UUID(uuidString: "3222234B-EE3F-467B-9D1E-D1E430DF8F5B")!
    let image: URL
    let scratch: URL
    let sourceIdentity: SourceIdentity
    private let sourceParent: Int32
    private let source: Int32
    private let root: URL
    private let rootParent: Int32
    private let rootFD: Int32
    private let rootIdentity: (dev_t, ino_t)
    private let scratchIdentity: (dev_t, ino_t)
    private var cleaned = false

    init() throws {
        guard let path = ProcessInfo.processInfo.environment["NF_APFS_SNAPSHOT_FIXTURE_PATH"],
              path.hasPrefix("/"), !path.utf8.contains(0), !path.split(separator: "/").contains("..") else {
            throw ForensicsError.invalidSource("An absolute pinned synthetic snapshot fixture is required.")
        }
        image = URL(fileURLWithPath: path).standardizedFileURL
        sourceParent = try EvidenceViewFiles.openDirectory(image.deletingLastPathComponent(), searchOnly: true)
        source = Darwin.openat(sourceParent, image.lastPathComponent, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0 else { Darwin.close(sourceParent); throw APFSReadError.invalidEvidence }
        var sourceStatus = stat()
        guard Darwin.fstat(source, &sourceStatus) == 0, sourceStatus.st_mode & S_IFMT == S_IFREG,
              sourceStatus.st_uid == geteuid(), sourceStatus.st_nlink == 1,
              sourceStatus.st_mode & 0o7777 == 0o400, sourceStatus.st_size == 392_537 else {
            Darwin.close(source); Darwin.close(sourceParent); throw APFSReadError.invalidEvidence
        }
        sourceIdentity = SourceIdentity(sourceStatus)
        do {
            guard try Self.hashDescriptor(source) == Self.sha256 else { throw APFSReadError.sourceChanged }
            rootParent = try EvidenceViewFiles.openDirectory(URL(fileURLWithPath: "/private/tmp"))
            var template = Array("/private/tmp/NF-APFS-snapshot-cancel-XXXXXX".utf8CString)
            let created = template.withUnsafeMutableBufferPointer { buffer -> String? in
                guard let path = Darwin.mkdtemp(buffer.baseAddress!) else { return nil }
                return String(cString: path)
            }
            guard let created else { Darwin.close(rootParent); throw APFSReadError.invalidEvidence }
            root = URL(fileURLWithPath: created, isDirectory: true)
            rootFD = Darwin.openat(rootParent, root.lastPathComponent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard rootFD >= 0 else { Darwin.close(rootParent); throw APFSReadError.invalidEvidence }
            var rootStatus = stat()
            guard Darwin.fstat(rootFD, &rootStatus) == 0, rootStatus.st_uid == geteuid(),
                  rootStatus.st_mode & 0o7777 == 0o700,
                  Darwin.mkdirat(rootFD, "adapter-scratch", 0o700) == 0 else {
                Darwin.close(rootFD); Darwin.close(rootParent); throw APFSReadError.invalidEvidence
            }
            rootIdentity = (rootStatus.st_dev, rootStatus.st_ino)
            scratch = root.appendingPathComponent("adapter-scratch", isDirectory: true)
            var scratchStatus = stat()
            guard Darwin.fstatat(rootFD, "adapter-scratch", &scratchStatus, AT_SYMLINK_NOFOLLOW) == 0,
                  scratchStatus.st_mode & S_IFMT == S_IFDIR else {
                Darwin.close(rootFD); Darwin.close(rootParent); throw APFSReadError.invalidEvidence
            }
            scratchIdentity = (scratchStatus.st_dev, scratchStatus.st_ino)
        } catch { Darwin.close(source); Darwin.close(sourceParent); throw error }
    }
    deinit { Darwin.close(rootFD); Darwin.close(rootParent); Darwin.close(source); Darwin.close(sourceParent) }

    func requireUnchangedSource() throws {
        var descriptor = stat(), leaf = stat()
        guard Darwin.fstat(source, &descriptor) == 0,
              Darwin.fstatat(sourceParent, image.lastPathComponent, &leaf, AT_SYMLINK_NOFOLLOW) == 0,
              SourceIdentity(descriptor) == sourceIdentity, SourceIdentity(leaf) == sourceIdentity,
              descriptor.st_uid == geteuid(), descriptor.st_nlink == 1, descriptor.st_mode & 0o7777 == 0o400,
              try Self.hashDescriptor(source) == Self.sha256 else { throw APFSReadError.sourceChanged }
    }
    func requireEmptyScratch() throws {
        var rootLeaf = stat(), rootHeld = stat(), scratchLeaf = stat()
        guard Darwin.fstat(rootFD, &rootHeld) == 0,
              Darwin.fstatat(rootParent, root.lastPathComponent, &rootLeaf, AT_SYMLINK_NOFOLLOW) == 0,
              rootHeld.st_dev == rootIdentity.0, rootHeld.st_ino == rootIdentity.1,
              rootLeaf.st_dev == rootIdentity.0, rootLeaf.st_ino == rootIdentity.1,
              Darwin.fstatat(rootFD, "adapter-scratch", &scratchLeaf, AT_SYMLINK_NOFOLLOW) == 0,
              scratchLeaf.st_dev == scratchIdentity.0, scratchLeaf.st_ino == scratchIdentity.1,
              scratchLeaf.st_mode & S_IFMT == S_IFDIR,
              try FileManager.default.contentsOfDirectory(atPath: scratch.path).isEmpty else {
            throw APFSReadError.cleanupIncomplete
        }
    }
    func cleanupIfEmpty() throws {
        if cleaned { return }
        try requireEmptyScratch()
        guard Darwin.unlinkat(rootFD, "adapter-scratch", AT_REMOVEDIR) == 0,
              Darwin.unlinkat(rootParent, root.lastPathComponent, AT_REMOVEDIR) == 0 else {
            throw APFSReadError.cleanupIncomplete
        }
        cleaned = true
    }
    private static func hashDescriptor(_ fd: Int32) throws -> String {
        var hasher = SHA256(), buffer = [UInt8](repeating: 0, count: 65_536)
        var offset: Int64 = 0
        while offset < 392_537 {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.pread(fd, $0.baseAddress, min($0.count, Int(392_537 - offset)), off_t(offset))
            }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw APFSReadError.sourceChanged }
            hasher.update(data: Data(buffer.prefix(count)))
            offset += Int64(count)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
