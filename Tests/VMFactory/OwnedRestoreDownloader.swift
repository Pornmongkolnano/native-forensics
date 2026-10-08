import CryptoKit
import Darwin
import Foundation

// Standalone laboratory component: no main, automatic download, VM, or VZ call.
// The caller must resolve the license/guest allowance and authorize download first.
enum OwnedRestoreDownloader {
    static let gib: UInt64 = 1_073_741_824
    static let guestBytes = 50 * gib
    static let workingBytes = 8 * gib
    static let reserveBytes = 30 * gib
    static let checkpointInterval: UInt64 = 8 * 1_024 * 1_024

    struct Pin: Codable, Equatable, Sendable {
        let url: URL
        let operatingSystem: String
        let build: String
        let byteCount: UInt64
        let eTag: String
        let lastModified: String
        let headObservedAt: String

        // Exact receipt, not "latest". Changing this requires a new reviewed pin.
        static let approved = Pin(
            url: URL(string: "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw")!,
            operatingSystem: "27.0.1", build: "26A434", byteCount: 26_637_307_067,
            eTag: "\"8faf3ef623fa1c181712440496ccc188-3175\"",
            lastModified: "Thu, 24 Sep 2026 21:23:41 GMT", headObservedAt: "2026-10-08T04:49:25Z")
    }

    // This is the caller's explicit decision record, not a legal determination
    // made by this helper. There is intentionally no default approval.
    struct Approval: Sendable {
        let licenseAndGuestAllowanceConfirmed: Bool
        let confirmedHostLicenseSHA256: String
        let existingMacOSGuestCopies: Int
        let newMacOSCopiesCovered: Int
        let permittedAdditionalCopies: Int

        func validate() throws {
            guard licenseAndGuestAllowanceConfirmed,
                  confirmedHostLicenseSHA256.count == 64,
                  confirmedHostLicenseSHA256.allSatisfy({ $0.isHexDigit && $0.isASCII }),
                  existingMacOSGuestCopies >= 0, newMacOSCopiesCovered >= 1,
                  permittedAdditionalCopies >= 1, permittedAdditionalCopies <= 2,
                  newMacOSCopiesCovered <= permittedAdditionalCopies,
                  existingMacOSGuestCopies <= permittedAdditionalCopies - newMacOSCopiesCovered else {
                throw Failure.approvalRequired
            }
        }
    }

    enum Failure: Error, Equatable {
        case approvalRequired, unsafePath, unsafeOwner, unsafePermissions, notRegularFile
        case invalidJob, alreadyRunning, lockedJob, changedFile, invalidCheckpoint
        case untrustedURL, tooManyRedirects, methodChanged, responseRejected
        case validatorChanged, lengthChanged, rangeMismatch, excessBytes, shortTransfer
        case insufficientStorage, storageOverflow, cancelled, downloadedHashMismatch
        indirect case publishedButUnconfirmed(cause: Failure)
        case posix(operation: String, code: Int32)
        case transport(domain: String, code: Int)
    }

    struct Checkpoint: Codable {
        let schemaVersion: Int
        let jobID: UUID
        let pin: Pin
        let committedBytes: UInt64
        let prefixSHA256: String
        let fileDevice: UInt64
        let fileInode: UInt64
        let allocatedBytes: UInt64
    }

    struct Manifest: Codable {
        let schemaVersion: Int
        let jobID: UUID
        let pin: Pin
        let finalResponseURL: URL
        let completedAt: String
        let selectedFileBytes: UInt64
        let selectedFileSHA256: String
        let allocatedBytes: UInt64
        let freshFreeBytes: UInt64
        let hostLicenseSHA256: String
        let existingMacOSGuestCopies: Int
        let newMacOSCopiesCovered: Int
        let permittedAdditionalCopies: Int
        let httpValidatorsAreArtifactAuthentication: Bool
        let selectedFileSHA256IsObservedIntegrityOnly: Bool
        let callerMustReloadSupportedLocalVZBuildAndRequirements: Bool
        let vmCreationAuthorizedByDownload: Bool
    }

    struct Receipt: Sendable {
        let jobID: UUID
        let artifactURL: URL
        let selectedFileBytes: UInt64
        let selectedFileSHA256: String
        let manifestURL: URL
        let manifestSHA256: String
        let allocatedBytes: UInt64
        let freshFreeBytes: UInt64
    }

    // atime changes during a reread, so it is deliberately not an identity
    // field. mtime and ctime are both exact, including nanoseconds. Restoring
    // mtime after an in-place same-size write does not hide the ctime change.
    struct FileIdentity: Equatable, Sendable {
        let device: UInt64
        let inode: UInt64
        let size: UInt64
        let mode: UInt32
        let owner: UInt32
        let group: UInt32
        let links: UInt64
        let flags: UInt32
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let changeSeconds: Int64
        let changeNanoseconds: Int64

        fileprivate init(_ value: stat) throws {
            try validateRegularFile(value)
            guard value.st_size >= 0 else { throw Failure.changedFile }
            device = deviceIdentifier(value); inode = UInt64(value.st_ino); size = UInt64(value.st_size)
            mode = UInt32(value.st_mode); owner = value.st_uid; group = value.st_gid
            links = UInt64(value.st_nlink); flags = value.st_flags
            modificationSeconds = Int64(value.st_mtimespec.tv_sec)
            modificationNanoseconds = Int64(value.st_mtimespec.tv_nsec)
            changeSeconds = Int64(value.st_ctimespec.tv_sec)
            changeNanoseconds = Int64(value.st_ctimespec.tv_nsec)
        }

        fileprivate func preservesEverythingExceptChangeTime(_ other: FileIdentity) -> Bool {
            device == other.device && inode == other.inode && size == other.size && mode == other.mode &&
            owner == other.owner && group == other.group && links == other.links && flags == other.flags &&
            modificationSeconds == other.modificationSeconds && modificationNanoseconds == other.modificationNanoseconds
        }
    }

    // Directory timestamps legitimately change when our checkpoint/manifest
    // names change. The fence pins each held parent and named job directory by
    // inode, device and safe ownership/mode, and reopens the absolute parent path.
    final class DirectoryAnchor {
        private final class Descriptor {
            let value: Int32
            init(_ value: Int32) { self.value = value }
            deinit { close(value) }
        }
        private struct Identity: Equatable {
            let device: UInt64
            let inode: UInt64
            let mode: UInt32
            let owner: UInt32
            let group: UInt32
            init(_ value: stat) {
                device = deviceIdentifier(value); inode = UInt64(value.st_ino)
                mode = UInt32(value.st_mode); owner = value.st_uid; group = value.st_gid
            }
        }
        private let heldParent: Descriptor
        private let parentURL: URL
        private let name: String
        private let parentIdentity: Identity
        private let directoryIdentity: Identity

        init(parent: Int32, directory: Int32, directoryURL: URL) throws {
            try ownedDirectory(parent, exactPrivate: false)
            try ownedDirectory(directory, exactPrivate: true)
            var parentValue = stat(), directoryValue = stat()
            guard fstat(parent, &parentValue) == 0, fstat(directory, &directoryValue) == 0 else {
                throw posix("stat-directory-anchor")
            }
            let duplicate = fcntl(parent, F_DUPFD_CLOEXEC, 0)
            guard duplicate >= 0 else { throw posix("hold-parent-anchor") }
            heldParent = Descriptor(duplicate); parentURL = directoryURL.deletingLastPathComponent()
            name = directoryURL.lastPathComponent
            parentIdentity = Identity(parentValue); directoryIdentity = Identity(directoryValue)
            try check(directory: directory)
        }

        func check(directory: Int32) throws {
            let reopenedParent = try openAbsoluteDirectory(parentURL)
            defer { close(reopenedParent) }
            try ownedDirectory(heldParent.value, exactPrivate: false)
            try ownedDirectory(reopenedParent, exactPrivate: false)
            try ownedDirectory(directory, exactPrivate: true)
            var heldParent = stat(), namedParent = stat(), heldDirectory = stat()
            guard fstat(self.heldParent.value, &heldParent) == 0, fstat(reopenedParent, &namedParent) == 0,
                  fstat(directory, &heldDirectory) == 0,
                  Identity(heldParent) == parentIdentity, Identity(namedParent) == parentIdentity,
                  Identity(heldDirectory) == directoryIdentity else { throw Failure.changedFile }
            let namedDirectory = try openDirectory(parent: self.heldParent.value, name: name, exactPrivate: true)
            defer { close(namedDirectory) }
            var named = stat()
            guard fstat(namedDirectory, &named) == 0, Identity(named) == directoryIdentity else {
                throw Failure.changedFile
            }
        }
    }

    struct FencedHash {
        let identity: FileIdentity
        let sha256: String
    }

    // Generic small-file helpers are also used by the no-network harness. A
    // reread closure supplies the bytes/hash operation; it cannot waive fences.
    static func fencedReread(file: Int32, directory: Int32, name: String,
                             checkParent: () throws -> Void, reread: () throws -> String) throws -> FencedHash {
        try checkParent()
        let before = try fencedFile(file: file, directory: directory, name: name)
        let observed = try reread()
        _ = try fencedFile(file: file, directory: directory, name: name, expected: before)
        try checkParent()
        return FencedHash(identity: before, sha256: observed)
    }

    static func fencedFile(file: Int32, directory: Int32, name: String,
                           expected: FileIdentity? = nil) throws -> FileIdentity {
        let held = try FileIdentity(regularFile(file))
        var named = stat()
        guard fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw posix("stat-fenced-name") }
        let namedIdentity = try FileIdentity(named)
        guard held == namedIdentity, expected == nil || held == expected else { throw Failure.changedFile }
        return held
    }

    // Only a successful exclusive owned rename permits adopting a new ctime.
    // Its immediate identity must preserve dev/inode/size/mtime and safety
    // fields; fsync and all subsequent fences require that entire new identity.
    @discardableResult
    static func exclusivePublish(file: Int32, directory: Int32, source: String, destination: String,
                                 before: FileIdentity, checkParent: () throws -> Void,
                                 didRename: () -> Void = {},
                                 syncDirectory: ((Int32, String) throws -> Void)? = nil) throws -> FileIdentity {
        try checkParent()
        _ = try fencedFile(file: file, directory: directory, name: source, expected: before)
        guard renameatx_np(directory, source, directory, destination, UInt32(RENAME_EXCL)) == 0 else {
            throw posix("publish-owned-file")
        }
        didRename()
        do {
            let adopted = try fencedFile(file: file, directory: directory, name: destination)
            guard before.preservesEverythingExceptChangeTime(adopted) else { throw Failure.changedFile }
            try checkParent()
            if let syncDirectory { try syncDirectory(directory, "sync-published-owned-file") }
            else { try sync(directory, "sync-published-owned-file") }
            _ = try fencedFile(file: file, directory: directory, name: destination, expected: adopted)
            try checkParent()
            return adopted
        } catch { throw publicationUncertainty(error) }
    }

    // This is the last fence before a receipt can be returned. It keeps both
    // held descriptors alive, verifies manifest bytes under unchanged full
    // identity, then rechecks both names and their anchored parent. No failure
    // removes a published artifact or manifest.
    static func finalPublicationFence(file: Int32, directory: Int32, name: String,
                                      expected: FileIdentity, manifestFile: Int32, manifestName: String,
                                      manifestBytes: Data, manifestIdentity: FileIdentity,
                                      checkParent: () throws -> Void) throws {
        do {
            try checkParent()
            _ = try fencedFile(file: file, directory: directory, name: name, expected: expected)
            _ = try fencedFile(file: manifestFile, directory: directory, name: manifestName, expected: manifestIdentity)
            guard manifestIdentity.size == UInt64(manifestBytes.count), manifestBytes.count <= 16_384 else {
                throw Failure.invalidCheckpoint
            }
            let observed = try readExactBytes(fd: manifestFile, count: manifestBytes.count)
            guard observed == manifestBytes else { throw Failure.changedFile }
            _ = try fencedFile(file: manifestFile, directory: directory, name: manifestName, expected: manifestIdentity)
            _ = try fencedFile(file: file, directory: directory, name: name, expected: expected)
            try checkParent()
        } catch { throw publicationUncertainty(error) }
    }

    private static func publicationUncertainty(_ error: Error) -> Failure {
        let cause = (error as? Failure) ?? .invalidJob
        if case .publishedButUnconfirmed = cause { return cause }
        return .publishedButUnconfirmed(cause: cause)
    }

    static func remainingBytes(_ verifiedOffset: UInt64) throws -> UInt64 {
        guard verifiedOffset <= Pin.approved.byteCount else { throw Failure.excessBytes }
        return Pin.approved.byteCount - verifiedOffset
    }

    static func requiredFreeBytes(verifiedOffset: UInt64) throws -> UInt64 {
        try guestBytes + remainingBytes(verifiedOffset) + workingBytes + reserveBytes
    }

    static func admitStorage(freeBytes: UInt64, verifiedOffset: UInt64) throws {
        guard freeBytes >= reserveBytes,
              freeBytes >= (try requiredFreeBytes(verifiedOffset: verifiedOffset)) else {
            throw Failure.insufficientStorage
        }
    }

    static func admittedOffset(current: UInt64, incoming: UInt64) throws -> UInt64 {
        guard incoming <= (try remainingBytes(current)) else { throw Failure.excessBytes }
        return current + incoming
    }

    static func trustedURL(_ url: URL) -> Bool {
        guard url.scheme == "https", let host = url.host?.lowercased(),
              host == "apple.com" || host.hasSuffix(".apple.com") || host == "updates.cdn-apple.com",
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.port == nil || url.port == 443,
              url.lastPathComponent == Pin.approved.url.lastPathComponent else { return false }
        return true
    }

    static func request(url: URL, offset: UInt64) throws -> URLRequest {
        guard trustedURL(url) else { throw Failure.untrustedURL }
        _ = try remainingBytes(offset)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = "GET"
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue(Pin.approved.eTag, forHTTPHeaderField: "If-Match")
        request.setValue(Pin.approved.lastModified, forHTTPHeaderField: "If-Unmodified-Since")
        if offset > 0 {
            request.setValue("bytes=\(offset)-", forHTTPHeaderField: "Range")
            request.setValue(Pin.approved.eTag, forHTTPHeaderField: "If-Range")
        }
        return request
    }

    // All validation happens before URLSession is allowed to deliver data.
    static func validateResponse(_ response: HTTPURLResponse, offset: UInt64) throws {
        guard let url = response.url, trustedURL(url) else { throw Failure.untrustedURL }
        guard response.statusCode == (offset == 0 ? 200 : 206) else { throw Failure.responseRejected }
        guard response.value(forHTTPHeaderField: "ETag") == Pin.approved.eTag,
              response.value(forHTTPHeaderField: "Last-Modified") == Pin.approved.lastModified else {
            throw Failure.validatorChanged
        }
        let encoding = response.value(forHTTPHeaderField: "Content-Encoding")?.lowercased()
        guard encoding == nil || encoding == "identity" else { throw Failure.responseRejected }
        guard let rawLength = response.value(forHTTPHeaderField: "Content-Length"),
              !rawLength.isEmpty, rawLength.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let length = UInt64(rawLength), length == (try remainingBytes(offset)) else {
            throw Failure.lengthChanged
        }
        let contentRange = response.value(forHTTPHeaderField: "Content-Range")
        if offset == 0 {
            guard contentRange == nil else { throw Failure.rangeMismatch }
        } else {
            guard contentRange == "bytes \(offset)-\(Pin.approved.byteCount - 1)/\(Pin.approved.byteCount)" else {
                throw Failure.rangeMismatch
            }
        }
    }

    // HEAD may be repeated by the caller; it never permits a changed size or
    // validator. A tiny tolerance may be used for HTTP overhead, not IPSW bytes.
    static func validateRepeatedHEAD(_ response: HTTPURLResponse) throws {
        try validateResponse(response, offset: 0)
    }

    static func prepare(repositoryRoot: URL) throws -> Job {
        let lab = try openLab(repositoryRoot: repositoryRoot)
        defer { close(lab) }
        let id = UUID(), name = id.uuidString.lowercased()
        guard mkdirat(lab, name, 0o700) == 0 else { throw posix("mkdir-job") }
        let directory = try openDirectory(parent: lab, name: name, exactPrivate: true)
        do {
            let fd = openat(directory, "restore.partial", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw posix("create-partial") }
            do {
                try lockFile(fd)
                let file = try regularFile(fd)
                try sync(fd, "sync-new-partial")
                let checkpoint = Checkpoint(schemaVersion: 1, jobID: id, pin: .approved,
                    committedBytes: 0, prefixSHA256: digest(SHA256()),
                    fileDevice: deviceIdentifier(file), fileInode: UInt64(file.st_ino),
                    allocatedBytes: try allocation(file))
                try atomicJSON(checkpoint, directory: directory, name: "checkpoint.json")
                try sync(lab, "sync-lab")
                let directoryURL = labURL(repositoryRoot).appendingPathComponent(name)
                let anchor = try DirectoryAnchor(parent: lab, directory: directory, directoryURL: directoryURL)
                // Ownership transfers only after every throwing setup operation.
                return Job(id: id, directoryURL: directoryURL, anchor: anchor,
                    directory: directory, file: fd, identity: file, offset: 0, hasher: SHA256(), published: false)
            } catch { close(fd); throw error }
        } catch { close(directory); throw error }
    }

    static func resume(repositoryRoot: URL, jobID: UUID) throws -> Job {
        let lab = try openLab(repositoryRoot: repositoryRoot, create: false)
        defer { close(lab) }
        let name = jobID.uuidString.lowercased()
        let directory = try openDirectory(parent: lab, name: name, exactPrivate: true)
        do {
            let data = try readOwned(directory: directory, name: "checkpoint.json", limit: 16_384)
            let checkpoint: Checkpoint
            do { checkpoint = try JSONDecoder().decode(Checkpoint.self, from: data) }
            catch { throw Failure.invalidCheckpoint }
            guard checkpoint.schemaVersion == 1, checkpoint.jobID == jobID, checkpoint.pin == Pin.approved,
                  checkpoint.committedBytes <= Pin.approved.byteCount,
                  checkpoint.prefixSHA256.count == 64 else { throw Failure.invalidCheckpoint }
            var published = false
            var fd = openat(directory, "restore.partial", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            if fd < 0 && errno == ENOENT && checkpoint.committedBytes == Pin.approved.byteCount {
                published = true
                fd = openat(directory, "restore.ipsw", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            }
            guard fd >= 0 else { throw posix("open-partial") }
            do {
                try lockFile(fd)
                let file = try regularFile(fd)
                guard deviceIdentifier(file) == checkpoint.fileDevice, UInt64(file.st_ino) == checkpoint.fileInode,
                      file.st_size >= 0, UInt64(file.st_size) >= checkpoint.committedBytes,
                      UInt64(file.st_size) <= Pin.approved.byteCount else { throw Failure.changedFile }
                let hasher = try hashPrefix(fd: fd, count: checkpoint.committedBytes)
                guard digest(hasher) == checkpoint.prefixSHA256 else { throw Failure.invalidCheckpoint }
                // Discard only the uncommitted tail of this verified owned file.
                // This handles a process interruption between file and ledger fsync.
                if UInt64(file.st_size) > checkpoint.committedBytes {
                    guard !published, ftruncate(fd, off_t(checkpoint.committedBytes)) == 0 else {
                        throw posix("truncate-uncommitted-tail")
                    }
                    try sync(fd, "sync-truncated-partial")
                }
                let directoryURL = labURL(repositoryRoot).appendingPathComponent(name)
                let anchor = try DirectoryAnchor(parent: lab, directory: directory, directoryURL: directoryURL)
                return Job(id: jobID, directoryURL: directoryURL, anchor: anchor,
                           directory: directory, file: fd, identity: file,
                           offset: checkpoint.committedBytes, hasher: hasher, published: published)
            } catch { close(fd); throw error }
        } catch { close(directory); throw error }
    }

    final class Job: @unchecked Sendable {
        let id: UUID
        let directoryURL: URL
        fileprivate let anchor: DirectoryAnchor
        fileprivate let directory: Int32
        fileprivate let file: Int32
        fileprivate let identity: stat
        fileprivate var offset: UInt64
        fileprivate var hasher: SHA256
        fileprivate var published: Bool
        private let lock = NSLock()
        private var running = false

        fileprivate init(id: UUID, directoryURL: URL, anchor: DirectoryAnchor, directory: Int32, file: Int32,
                         identity: stat, offset: UInt64, hasher: SHA256, published: Bool) {
            self.id = id; self.directoryURL = directoryURL; self.anchor = anchor; self.directory = directory
            self.file = file; self.identity = identity; self.offset = offset
            self.hasher = hasher; self.published = published
        }
        deinit { close(file); close(directory) }

        func download(approval: Approval) async throws -> Receipt {
            try approval.validate()
            try claimDownload()
            defer { releaseDownload() }
            let transfer = Transfer(job: self, approval: approval)
            return try await withTaskCancellationHandler(operation: {
                try await withCheckedThrowingContinuation { continuation in transfer.start(continuation) }
            }, onCancel: { transfer.cancel() })
        }

        private func claimDownload() throws {
            lock.lock(); defer { lock.unlock() }
            guard !running else { throw Failure.alreadyRunning }
            running = true
        }
        private func releaseDownload() {
            lock.lock(); running = false; lock.unlock()
        }

        fileprivate func checkFile() throws -> stat {
            try anchor.check(directory: directory)
            let value = try regularFile(file)
            let name = published ? "restore.ipsw" : "restore.partial"
            _ = try fencedFile(file: file, directory: directory, name: name)
            guard value.st_dev == identity.st_dev, value.st_ino == identity.st_ino,
                  value.st_size >= 0, UInt64(value.st_size) == offset else { throw Failure.changedFile }
            return value
        }

        fileprivate func checkpoint() throws {
            let value = try checkFile()
            guard try freeBytes(directory) >= reserveBytes else { throw Failure.insufficientStorage }
            try sync(file, "sync-partial")
            let checkpoint = Checkpoint(schemaVersion: 1, jobID: id, pin: .approved,
                committedBytes: offset, prefixSHA256: digest(hasher),
                fileDevice: deviceIdentifier(value), fileInode: UInt64(value.st_ino),
                allocatedBytes: try allocation(value))
            try atomicJSON(checkpoint, directory: directory, name: "checkpoint.json")
            guard try freeBytes(directory) >= reserveBytes else { throw Failure.insufficientStorage }
        }

        fileprivate func append(_ data: Data) throws {
            guard !published else { throw Failure.invalidJob }
            let nextOffset = try admittedOffset(current: offset, incoming: UInt64(data.count))
            _ = try checkFile()
            try admitStorage(freeBytes: freeBytes(directory), verifiedOffset: offset)
            // pwrite is anchored to our locked, exclusively created regular file.
            try data.withUnsafeBytes { bytes in
                var written = 0
                while written < bytes.count {
                    let n = pwrite(file, bytes.baseAddress!.advanced(by: written), bytes.count - written, off_t(offset) + off_t(written))
                    if n < 0 && errno == EINTR { continue }
                    guard n > 0 else { throw posix("write-partial") }
                    written += n
                }
            }
            hasher.update(data: data); offset = nextOffset
            try admitStorage(freeBytes: freeBytes(directory), verifiedOffset: offset)
        }

        fileprivate func finish(approval: Approval, finalURL: URL, cancelled: () -> Bool) throws -> Receipt {
            guard offset == Pin.approved.byteCount else { throw Failure.shortTransfer }
            do {
                try checkpoint()
                try admitStorage(freeBytes: freeBytes(directory), verifiedOffset: offset)
                let reread = try fencedReread(file: file, directory: directory,
                    name: published ? "restore.ipsw" : "restore.partial",
                    checkParent: { try self.anchor.check(directory: self.directory) },
                    reread: { digest(try hashPrefix(fd: self.file, count: self.offset, cancelled: cancelled)) })
                let observed = reread.sha256
                guard reread.identity.size == offset else { throw Failure.changedFile }
                guard observed == digest(hasher) else { throw Failure.downloadedHashMismatch }
                guard !cancelled() else { throw Failure.cancelled }
                let publicationIdentity: FileIdentity
                if !published {
                    publicationIdentity = try exclusivePublish(file: file, directory: directory,
                        source: "restore.partial", destination: "restore.ipsw", before: reread.identity,
                        checkParent: { try self.anchor.check(directory: self.directory) },
                        didRename: { self.published = true })
                } else {
                    publicationIdentity = try fencedFile(file: file, directory: directory,
                        name: "restore.ipsw", expected: reread.identity)
                }
                let value = try checkFile(), allocated = try allocation(value), free = try freeBytes(directory)
                try admitStorage(freeBytes: free, verifiedOffset: offset)
                _ = try fencedFile(file: file, directory: directory, name: "restore.ipsw", expected: publicationIdentity)
                let manifest = Manifest(schemaVersion: 1, jobID: id, pin: .approved,
                    finalResponseURL: finalURL, completedAt: ISO8601DateFormatter().string(from: Date()),
                    selectedFileBytes: offset, selectedFileSHA256: observed, allocatedBytes: allocated,
                    freshFreeBytes: free, hostLicenseSHA256: approval.confirmedHostLicenseSHA256,
                    existingMacOSGuestCopies: approval.existingMacOSGuestCopies,
                    newMacOSCopiesCovered: approval.newMacOSCopiesCovered,
                    permittedAdditionalCopies: approval.permittedAdditionalCopies,
                    httpValidatorsAreArtifactAuthentication: false, selectedFileSHA256IsObservedIntegrityOnly: true,
                    callerMustReloadSupportedLocalVZBuildAndRequirements: true, vmCreationAuthorizedByDownload: false)
                var manifestFile: Int32 = -1
                var manifestIdentity: FileIdentity?
                defer { if manifestFile >= 0 { close(manifestFile) } }
                let manifestBytes = try atomicJSON(manifest, directory: directory, name: "download-manifest.json",
                    checkParent: { try self.anchor.check(directory: self.directory) },
                    afterPublication: { heldFile, _, confirmedIdentity in
                        let duplicate = fcntl(heldFile, F_DUPFD_CLOEXEC, 0)
                        guard duplicate >= 0 else { throw posix("hold-published-manifest") }
                        manifestFile = duplicate; manifestIdentity = confirmedIdentity
                    })
                guard manifestFile >= 0, let manifestIdentity else { throw Failure.invalidJob }
                guard !cancelled() else { throw Failure.cancelled }
                let confirmedFree = try freeBytes(directory)
                try admitStorage(freeBytes: confirmedFree, verifiedOffset: offset)
                try finalPublicationFence(file: file, directory: directory, name: "restore.ipsw",
                    expected: publicationIdentity, manifestFile: manifestFile, manifestName: "download-manifest.json",
                    manifestBytes: manifestBytes, manifestIdentity: manifestIdentity,
                    checkParent: { try self.anchor.check(directory: self.directory) })
                return Receipt(jobID: id, artifactURL: directoryURL.appendingPathComponent("restore.ipsw"),
                    selectedFileBytes: offset, selectedFileSHA256: observed,
                    manifestURL: directoryURL.appendingPathComponent("download-manifest.json"),
                    manifestSHA256: digest(manifestBytes), allocatedBytes: allocated, freshFreeBytes: confirmedFree)
            } catch {
                if published { throw publicationUncertainty(error) }
                throw error
            }
        }
    }

    private final class Transfer: NSObject, URLSessionDataDelegate, @unchecked Sendable {
        let job: Job
        let approval: Approval
        let queue: OperationQueue
        let cancellationLock = NSLock()
        var cancelled = false
        var task: URLSessionDataTask?
        var session: URLSession?
        var continuation: CheckedContinuation<Receipt, Error>?
        var failure: Failure?
        var responseAccepted = false
        var redirects = 0
        var finalURL = Pin.approved.url
        var checkpointOffset: UInt64
        let requestOffset: UInt64

        init(job: Job, approval: Approval) {
            self.job = job; self.approval = approval
            requestOffset = job.offset; checkpointOffset = job.offset
            queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
            queue.name = "OwnedRestoreDownload"
        }

        func isCancelled() -> Bool {
            cancellationLock.lock(); defer { cancellationLock.unlock() }; return cancelled
        }
        func cancel() {
            cancellationLock.lock(); cancelled = true; let task = self.task; cancellationLock.unlock()
            task?.cancel()
        }
        func start(_ continuation: CheckedContinuation<Receipt, Error>) {
            queue.addOperation {
                self.continuation = continuation
                do {
                    guard !self.isCancelled() else { throw Failure.cancelled }
                    _ = try self.job.checkFile()
                    try admitStorage(freeBytes: freeBytes(self.job.directory), verifiedOffset: self.job.offset)
                    if self.job.offset == Pin.approved.byteCount {
                        self.complete(.success(try self.job.finish(approval: self.approval, finalURL: self.finalURL, cancelled: self.isCancelled)))
                        return
                    }
                    let configuration = URLSessionConfiguration.ephemeral
                    configuration.urlCache = nil; configuration.httpCookieStorage = nil
                    configuration.urlCredentialStorage = nil; configuration.httpShouldSetCookies = false
                    configuration.waitsForConnectivity = false
                    configuration.timeoutIntervalForRequest = 30; configuration.timeoutIntervalForResource = 3_600
                    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: self.queue)
                    self.session = session
                    let task = session.dataTask(with: try request(url: Pin.approved.url, offset: self.requestOffset))
                    self.cancellationLock.lock(); self.task = task; let cancelled = self.cancelled; self.cancellationLock.unlock()
                    if cancelled { task.cancel() }
                    task.resume()
                } catch { self.complete(.failure(error)) }
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest proposed: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            redirects += 1
            do {
                guard !isCancelled() else { throw Failure.cancelled }
                guard redirects <= 3 else { throw Failure.tooManyRedirects }
                guard proposed.httpMethod == "GET" else { throw Failure.methodChanged }
                guard let target = proposed.url, trustedURL(target),
                      [301, 302, 303, 307, 308].contains(response.statusCode) else { throw Failure.untrustedURL }
                // Rebuild only approved headers; never inherit credentials/cookies.
                completionHandler(try request(url: target, offset: requestOffset))
            } catch {
                failure = (error as? Failure) ?? .responseRejected
                completionHandler(nil); task.cancel()
            }
        }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            // Standard TLS server trust only; no account or client-keychain identity.
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                completionHandler(.performDefaultHandling, nil)
            } else {
                failure = .responseRejected; completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            self.urlSession(session, didReceive: challenge, completionHandler: completionHandler)
        }

        func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
            do {
                guard !isCancelled() else { throw Failure.cancelled }
                guard let response = response as? HTTPURLResponse else { throw Failure.responseRejected }
                try validateResponse(response, offset: requestOffset)
                finalURL = response.url!; responseAccepted = true
                completionHandler(.allow)
            } catch {
                failure = (error as? Failure) ?? .responseRejected
                completionHandler(.cancel)
            }
        }

        func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
            do {
                guard responseAccepted, failure == nil else { throw Failure.responseRejected }
                guard !isCancelled() else { throw Failure.cancelled }
                try job.append(data)
                if job.offset - checkpointOffset >= checkpointInterval {
                    try job.checkpoint()
                    try admitStorage(freeBytes: freeBytes(job.directory), verifiedOffset: job.offset)
                    checkpointOffset = job.offset
                }
            } catch {
                if failure == nil { failure = (error as? Failure) ?? .responseRejected }
                dataTask.cancel()
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
            do {
                // Persist verified received bytes even after interruption; resume
                // never trusts URLSession opaque resume data or an arbitrary path.
                try job.checkpoint()
                if let failure { throw failure }
                guard !isCancelled() else { throw Failure.cancelled }
                if let error {
                    let ns = error as NSError
                    throw Failure.transport(domain: ns.domain, code: ns.code)
                }
                guard responseAccepted else { throw Failure.responseRejected }
                complete(.success(try job.finish(approval: approval, finalURL: finalURL, cancelled: isCancelled)))
            } catch { complete(.failure(error)) }
        }

        func complete(_ result: Result<Receipt, Error>) {
            guard let continuation else { return }
            self.continuation = nil
            session?.invalidateAndCancel(); session = nil
            cancellationLock.lock(); task = nil; cancellationLock.unlock()
            if case .failure(let error) = result, job.published {
                continuation.resume(throwing: publicationUncertainty(error))
            } else { continuation.resume(with: result) }
        }
    }

    private static func labURL(_ repositoryRoot: URL) -> URL {
        repositoryRoot.appendingPathComponent("local", isDirectory: true).appendingPathComponent(".vm-lab", isDirectory: true)
    }

    private static func openLab(repositoryRoot: URL, create: Bool = true) throws -> Int32 {
        var parent = try openAbsoluteDirectory(repositoryRoot)
        do {
            try ownedDirectory(parent, exactPrivate: false)
            for part in ["local", ".vm-lab"] {
                if create && mkdirat(parent, part, 0o700) != 0 && errno != EEXIST { throw posix("mkdir-lab") }
                if create { try sync(parent, "sync-lab-parent") }
                let next = try openDirectory(parent: parent, name: part, exactPrivate: false)
                close(parent); parent = next
            }
            return parent
        } catch { close(parent); throw error }
    }

    private static func openAbsoluteDirectory(_ repositoryRoot: URL) throws -> Int32 {
        guard repositoryRoot.isFileURL, repositoryRoot.path.hasPrefix("/") else { throw Failure.unsafePath }
        let parts = repositoryRoot.path.split(separator: "/").map(String.init)
        guard !parts.isEmpty, !parts.contains("."), !parts.contains("..") else { throw Failure.unsafePath }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw posix("open-root") }
        do {
            for part in parts {
                let next = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw posix("open-repository-component") }
                close(parent); parent = next
            }
            return parent
        } catch { close(parent); throw error }
    }

    private static func openDirectory(parent: Int32, name: String, exactPrivate: Bool) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posix("open-owned-directory") }
        do { try ownedDirectory(fd, exactPrivate: exactPrivate); return fd }
        catch { close(fd); throw error }
    }

    private static func ownedDirectory(_ fd: Int32, exactPrivate: Bool) throws {
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw posix("stat-directory") }
        guard value.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), value.st_uid == geteuid() else { throw Failure.unsafeOwner }
        let mode = value.st_mode & 0o7777
        guard exactPrivate ? mode == 0o700 : mode & 0o7022 == 0 else { throw Failure.unsafePermissions }
    }

    private static func regularFile(_ fd: Int32) throws -> stat {
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw posix("stat-file") }
        try validateRegularFile(value)
        return value
    }

    private static func validateRegularFile(_ value: stat) throws {
        guard value.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), value.st_nlink == 1 else { throw Failure.notRegularFile }
        guard value.st_uid == geteuid() else { throw Failure.unsafeOwner }
        guard value.st_mode & 0o7777 == 0o600 else { throw Failure.unsafePermissions }
    }

    private static func lockFile(_ fd: Int32) throws {
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw Failure.lockedJob }
    }

    private static func freeBytes(_ fd: Int32) throws -> UInt64 {
        var value = statfs()
        guard fstatfs(fd, &value) == 0, value.f_bsize > 0 else { throw posix("stat-free-storage") }
        let type = withUnsafeBytes(of: value.f_fstypename) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        guard type == "apfs" else { throw Failure.unsafePath }
        let (bytes, overflow) = UInt64(value.f_bavail).multipliedReportingOverflow(by: UInt64(value.f_bsize))
        guard !overflow else { throw Failure.storageOverflow }
        return bytes
    }

    private static func allocation(_ value: stat) throws -> UInt64 {
        guard value.st_blocks >= 0 else { throw Failure.storageOverflow }
        let (bytes, overflow) = UInt64(value.st_blocks).multipliedReportingOverflow(by: 512)
        guard !overflow else { throw Failure.storageOverflow }
        return bytes
    }

    private static func deviceIdentifier(_ value: stat) -> UInt64 {
        UInt64(UInt32(bitPattern: value.st_dev))
    }

    private static func hashPrefix(fd: Int32, count: UInt64, cancelled: () -> Bool = { false }) throws -> SHA256 {
        var result = SHA256(), offset: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 256 * 1_024)
        while offset < count {
            guard !cancelled() else { throw Failure.cancelled }
            let amount = Int(min(UInt64(buffer.count), count - offset))
            let readCount = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress!, amount, off_t(offset)) }
            if readCount < 0 && errno == EINTR { continue }
            guard readCount > 0 else { throw Failure.changedFile }
            result.update(data: Data(buffer.prefix(readCount))); offset += UInt64(readCount)
        }
        return result
    }

    private static func digest(_ hasher: SHA256) -> String {
        var copy = hasher
        return copy.finalize().map { String(format: "%02x", $0) }.joined()
    }
    private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    @discardableResult
    private static func atomicJSON<T: Encodable>(_ value: T, directory: Int32, name: String,
                                               checkParent: (() throws -> Void)? = nil,
                                               afterPublication: ((Int32, Data, FileIdentity) throws -> Void)? = nil) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(value)
        guard bytes.count <= 16_384 else { throw Failure.invalidCheckpoint }
        let temporary = "receipt-\(UUID().uuidString.lowercased()).tmp"
        let fd = openat(directory, temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posix("create-checkpoint") }
        defer {
            // Remove only our still-named unpublished temporary inode. An
            // unexpected replacement is retained rather than broadly cleaned.
            var held = stat(), named = stat()
            if fstat(fd, &held) == 0, fstatat(directory, temporary, &named, AT_SYMLINK_NOFOLLOW) == 0,
               held.st_dev == named.st_dev, held.st_ino == named.st_ino { unlinkat(directory, temporary, 0) }
            close(fd)
        }
        _ = try regularFile(fd)
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let n = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw posix("write-checkpoint") }
                offset += n
            }
        }
        try sync(fd, "sync-checkpoint")
        if let afterPublication {
            guard let checkParent else { throw Failure.invalidJob }
            let reread = try fencedReread(file: fd, directory: directory, name: temporary,
                checkParent: checkParent, reread: { digest(try readExactBytes(fd: fd, count: bytes.count)) })
            guard reread.sha256 == digest(bytes) else { throw Failure.changedFile }
            let identity = try exclusivePublish(file: fd, directory: directory, source: temporary,
                destination: name, before: reread.identity, checkParent: checkParent)
            do { try afterPublication(fd, bytes, identity) }
            catch { throw publicationUncertainty(error) }
            return bytes
        }
        var previous = stat()
        if fstatat(directory, name, &previous, AT_SYMLINK_NOFOLLOW) == 0 {
            guard previous.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), previous.st_uid == geteuid(),
                  previous.st_nlink == 1, previous.st_mode & 0o7777 == 0o600 else { throw Failure.invalidCheckpoint }
        } else if errno != ENOENT { throw posix("stat-checkpoint-name") }
        guard renameat(directory, temporary, directory, name) == 0 else { throw posix("publish-checkpoint") }
        try sync(directory, "sync-checkpoint-directory")
        return bytes
    }

    private static func readOwned(directory: Int32, name: String, limit: Int) throws -> Data {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posix("open-checkpoint") }
        defer { close(fd) }
        let value = try regularFile(fd)
        guard value.st_size >= 0, UInt64(value.st_size) <= UInt64(limit) else { throw Failure.invalidCheckpoint }
        return try readExactBytes(fd: fd, count: Int(value.st_size))
    }

    private static func readExactBytes(fd: Int32, count: Int) throws -> Data {
        guard count >= 0, count <= 16_384 else { throw Failure.invalidCheckpoint }
        var bytes = [UInt8](repeating: 0, count: count), offset = 0
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let n = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress!.advanced(by: offset), remaining, off_t(offset)) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw Failure.changedFile }; offset += n
        }
        return Data(bytes)
    }

    private static func sync(_ fd: Int32, _ operation: String) throws {
        guard fsync(fd) == 0 else { throw posix(operation) }
    }
    private static func posix(_ operation: String) -> Failure { .posix(operation: operation, code: errno) }
}
