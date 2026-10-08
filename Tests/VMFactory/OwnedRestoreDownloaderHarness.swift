import CryptoKit
import Darwin
import Foundation

// Compile together with OwnedRestoreDownloader.swift, outside SwiftPM. This
// harness never calls download(), constructs a VM, or makes a network request.
// Its only filesystem fixtures are fresh owned private temporary directories.
@main
struct OwnedRestoreDownloaderHarness {
    typealias D = OwnedRestoreDownloader
    enum HarnessFailure: Error { case assertion(String), expectedRejection(String) }

    static func main() throws {
        try responseAndBudgetRules()
        try approvalRules()
        try withOwnedRoot { root in
            try exclusiveOwnershipAndResume(root)
            try checkpointPinTamper(root)
            try committedPrefixTamper(root)
            try replacedFileRejected(root)
            try symlinkFileRejected(root)
            try hardLinkRejected(root)
            try privateDirectoryRequired(root)
            try publicationFences(root)
        }
        try withOwnedRoot { root in try symlinkLabRejected(root) }
        print("Owned restore harness: response, reserve, ownership, resume, tamper and publication fences passed; no network or VM.")
    }

    static func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
        guard try condition() else { throw HarnessFailure.assertion(message) }
    }

    static func rejects(_ expected: D.Failure, _ message: String, _ body: () throws -> Void) throws {
        do { try body() }
        catch let failure as D.Failure {
            try check(failure == expected, message); return
        }
        throw HarnessFailure.expectedRejection(message)
    }

    static func rejectsAny(_ message: String, _ body: () throws -> Void) throws {
        do { try body() } catch is D.Failure { return }
        throw HarnessFailure.expectedRejection(message)
    }

    static func response(status: Int = 200, offset: UInt64 = 0,
                         overrides: [String: String] = [:], url: URL = D.Pin.approved.url) -> HTTPURLResponse {
        var headers = ["Content-Length": String(D.Pin.approved.byteCount - offset),
                       "ETag": D.Pin.approved.eTag, "Last-Modified": D.Pin.approved.lastModified]
        if offset > 0 {
            headers["Content-Range"] = "bytes \(offset)-\(D.Pin.approved.byteCount - 1)/\(D.Pin.approved.byteCount)"
        }
        headers.merge(overrides) { _, replacement in replacement }
        return HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
    }

    static func responseAndBudgetRules() throws {
        try D.validateResponse(response(), offset: 0)
        try D.validateRepeatedHEAD(response())
        try D.validateResponse(response(status: 206, offset: 17), offset: 17)
        try rejects(.responseRejected, "resume must reject a full 200 without appending") {
            try D.validateResponse(response(offset: 17), offset: 17)
        }
        try rejects(.validatorChanged, "changed ETag is not accepted") {
            try D.validateResponse(response(overrides: ["ETag": "\"another-build\""]), offset: 0)
        }
        try rejects(.validatorChanged, "changed Last-Modified is not accepted") {
            try D.validateResponse(response(overrides: ["Last-Modified": "Fri, 25 Sep 2026 21:23:41 GMT"]), offset: 0)
        }
        try rejects(.lengthChanged, "a larger artifact is never substituted") {
            try D.validateResponse(response(overrides: ["Content-Length": String(D.Pin.approved.byteCount + 1)]), offset: 0)
        }
        try rejects(.lengthChanged, "an unknown/chunked length is never accepted") {
            try D.validateResponse(response(overrides: ["Content-Length": ""]), offset: 0)
        }
        try rejects(.rangeMismatch, "resume range must begin at committed offset") {
            try D.validateResponse(response(status: 206, offset: 17, overrides: ["Content-Range": "bytes 0-16/17"]), offset: 17)
        }
        try rejects(.responseRejected, "content encoding must not expand behind the counter") {
            try D.validateResponse(response(overrides: ["Content-Encoding": "gzip"]), offset: 0)
        }
        try check(!D.trustedURL(URL(string: "http://updates.cdn-apple.com/\(D.Pin.approved.url.lastPathComponent)")!), "HTTPS only")
        try check(!D.trustedURL(URL(string: "https://updates.cdn-apple.com.evil.invalid/\(D.Pin.approved.url.lastPathComponent)")!), "suffix boundary")
        try check(!D.trustedURL(URL(string: "https://user:password@updates.cdn-apple.com/\(D.Pin.approved.url.lastPathComponent)")!), "URL credentials rejected")
        try check(!D.trustedURL(URL(string: "https://updates.cdn-apple.com/new-build.ipsw")!), "filename pin")
        try check(!D.trustedURL(URL(string: D.Pin.approved.url.absoluteString + "?credential=value")!), "query credentials rejected")
        let request = try D.request(url: D.Pin.approved.url, offset: 17)
        try check(request.httpMethod == "GET", "approved download method")
        try check(request.value(forHTTPHeaderField: "Range") == "bytes=17-", "range survives request rebuild")
        try check(request.value(forHTTPHeaderField: "If-Range") == D.Pin.approved.eTag, "resume validator")
        try check(request.value(forHTTPHeaderField: "Authorization") == nil, "no authorization header")
        let initial = try D.requiredFreeBytes(verifiedOffset: 0)
        let partial = try D.requiredFreeBytes(verifiedOffset: 17)
        try check(initial - partial == 17, "partial bytes not double budgeted")
        try D.admitStorage(freeBytes: partial, verifiedOffset: 17)
        try rejects(.insufficientStorage, "one byte below full plan fails") {
            try D.admitStorage(freeBytes: partial - 1, verifiedOffset: 17)
        }
        try rejects(.insufficientStorage, "30 GiB hard reserve remains mandatory at EOF") {
            try D.admitStorage(freeBytes: D.reserveBytes - 1, verifiedOffset: D.Pin.approved.byteCount)
        }
        try check(try D.admittedOffset(current: D.Pin.approved.byteCount - 1, incoming: 1) == D.Pin.approved.byteCount, "exact EOF")
        try rejects(.excessBytes, "extra byte rejected before write") {
            _ = try D.admittedOffset(current: D.Pin.approved.byteCount, incoming: 1)
        }
        try rejects(.excessBytes, "oversized incoming count cannot overflow") {
            _ = try D.admittedOffset(current: 1, incoming: UInt64.max)
        }
    }

    static func approvalRules() throws {
        let digest = String(repeating: "a", count: 64)
        try rejects(.approvalRequired, "pending approval cannot start a transfer") {
            try D.Approval(licenseAndGuestAllowanceConfirmed: false, confirmedHostLicenseSHA256: digest,
                existingMacOSGuestCopies: 0, newMacOSCopiesCovered: 2, permittedAdditionalCopies: 2).validate()
        }
        try rejects(.approvalRequired, "installed guest copies count toward allowance") {
            try D.Approval(licenseAndGuestAllowanceConfirmed: true, confirmedHostLicenseSHA256: digest,
                existingMacOSGuestCopies: 1, newMacOSCopiesCovered: 2, permittedAdditionalCopies: 2).validate()
        }
        try D.Approval(licenseAndGuestAllowanceConfirmed: true, confirmedHostLicenseSHA256: digest,
            existingMacOSGuestCopies: 0, newMacOSCopiesCovered: 2, permittedAdditionalCopies: 2).validate()
    }

    static func withOwnedRoot(_ body: (URL) throws -> Void) throws {
        var template = Array("/private/tmp/nf-restore-harness.XXXXXX".utf8CString)
        let rootPath = template.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let result = mkdtemp(buffer.baseAddress!) else { return nil }
            return String(cString: result)
        }
        guard let rootPath else { throw HarnessFailure.assertion("fresh owned temporary root") }
        let root = URL(fileURLWithPath: rootPath, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }

    static func writeOwned(_ data: Data, to url: URL, create: Bool = false) throws {
        let flags = O_WRONLY | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0)
        let fd = open(url.path, flags, 0o600)
        guard fd >= 0 else { throw HarnessFailure.assertion("owned fixture open") }
        defer { close(fd) }
        guard ftruncate(fd, 0) == 0 else { throw HarnessFailure.assertion("owned fixture truncate") }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard n > 0 else { throw HarnessFailure.assertion("owned fixture write") }
                offset += n
            }
        }
        guard fsync(fd) == 0 else { throw HarnessFailure.assertion("owned fixture fsync") }
    }

    static func exclusiveOwnershipAndResume(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, directory = job!.directoryURL
        try check((try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber)?.intValue == 0o700,
                  "job directory private")
        try rejects(.lockedJob, "a second opener cannot acquire the active partial") {
            _ = try D.resume(repositoryRoot: root, jobID: id)
        }
        job = nil
        // A crash tail may be discarded only after the committed prefix matches.
        try writeOwned(Data("uncommitted-tail".utf8), to: directory.appendingPathComponent("restore.partial"))
        let resumed = try D.resume(repositoryRoot: root, jobID: id)
        let size = try FileManager.default.attributesOfItem(atPath: resumed.directoryURL.appendingPathComponent("restore.partial").path)[.size] as? NSNumber
        try check(size?.uint64Value == 0, "only verified committed prefix survives resume")
    }

    static func checkpointPinTamper(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, receipt = job!.directoryURL.appendingPathComponent("checkpoint.json")
        job = nil
        var fields = try JSONSerialization.jsonObject(with: Data(contentsOf: receipt)) as! [String: Any]
        var pin = fields["pin"] as! [String: Any]; pin["build"] = "another-build"; fields["pin"] = pin
        try writeOwned(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]), to: receipt)
        try rejects(.invalidCheckpoint, "a stored ledger cannot substitute a new build") {
            _ = try D.resume(repositoryRoot: root, jobID: id)
        }
    }

    static func replacedFileRejected(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, directory = job!.directoryURL, file = directory.appendingPathComponent("restore.partial")
        job = nil
        try FileManager.default.moveItem(at: file, to: directory.appendingPathComponent("old-owned-partial"))
        try writeOwned(Data(), to: file, create: true)
        try rejects(.changedFile, "replacement inode cannot resume") { _ = try D.resume(repositoryRoot: root, jobID: id) }
    }

    static func committedPrefixTamper(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, directory = job!.directoryURL
        let file = directory.appendingPathComponent("restore.partial")
        let receipt = directory.appendingPathComponent("checkpoint.json")
        job = nil
        let original = try JSONDecoder().decode(D.Checkpoint.self, from: Data(contentsOf: receipt))
        let prefix = Data("verified-prefix".utf8)
        try writeOwned(prefix, to: file)
        let hash = SHA256.hash(data: prefix).map { String(format: "%02x", $0) }.joined()
        let committed = D.Checkpoint(schemaVersion: 1, jobID: id, pin: .approved,
            committedBytes: UInt64(prefix.count), prefixSHA256: hash,
            fileDevice: original.fileDevice, fileInode: original.fileInode, allocatedBytes: 0)
        try writeOwned(JSONEncoder().encode(committed), to: receipt)
        var resumed: D.Job? = try D.resume(repositoryRoot: root, jobID: id)
        try check(resumed?.id == id, "nonempty verified prefix resumes")
        resumed = nil
        try writeOwned(Data("tampered-prefix".utf8), to: file)
        try rejects(.invalidCheckpoint, "same-size prefix corruption is detected") {
            _ = try D.resume(repositoryRoot: root, jobID: id)
        }
    }

    static func symlinkFileRejected(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, directory = job!.directoryURL, file = directory.appendingPathComponent("restore.partial")
        job = nil
        try FileManager.default.moveItem(at: file, to: directory.appendingPathComponent("old-owned-partial"))
        let target = root.appendingPathComponent("owned-symlink-target")
        try writeOwned(Data("untouched".utf8), to: target, create: true)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        try rejectsAny("symlink partial never followed") { _ = try D.resume(repositoryRoot: root, jobID: id) }
        try check(try Data(contentsOf: target) == Data("untouched".utf8), "symlink target unchanged")
    }

    static func privateDirectoryRequired(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, directory = job!.directoryURL
        job = nil
        guard chmod(directory.path, 0o755) == 0 else { throw HarnessFailure.assertion("owned chmod fixture") }
        try rejects(.unsafePermissions, "publicly accessible job cannot resume") { _ = try D.resume(repositoryRoot: root, jobID: id) }
    }

    static func hardLinkRejected(_ root: URL) throws {
        var job: D.Job? = try D.prepare(repositoryRoot: root)
        let id = job!.id, file = job!.directoryURL.appendingPathComponent("restore.partial")
        job = nil
        try FileManager.default.linkItem(at: file, to: file.deletingLastPathComponent().appendingPathComponent("owned-hardlink"))
        try rejects(.notRegularFile, "shared hardlink cannot become a writable partial") {
            _ = try D.resume(repositoryRoot: root, jobID: id)
        }
    }

    static func symlinkLabRejected(_ root: URL) throws {
        let target = root.appendingPathComponent("owned-lab-target", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("local"), withDestinationURL: target)
        try rejectsAny("symlink lab ancestor never followed") { _ = try D.prepare(repositoryRoot: root) }
    }

    struct FenceFixture {
        let parentURL: URL
        let directoryURL: URL
        let directory: Int32
        let file: Int32
        let manifestFile: Int32
        let anchor: D.DirectoryAnchor
        let bodyBytes: Data
        let manifestBytes: Data

        func checkParent() throws { try anchor.check(directory: directory) }
    }

    // These exercise the same generic descriptor/hash/publication fences as
    // finish(), with less than 64 bytes of body plus manifest per fixture.
    static func withFenceFixture(_ root: URL, _ body: (FenceFixture) throws -> Void) throws {
        let parentURL = root.appendingPathComponent("fence-parent-\(UUID().uuidString.lowercased())", isDirectory: true)
        let directoryURL = parentURL.appendingPathComponent("owned-job", isDirectory: true)
        try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let bytes = Data("historical-body-A".utf8), manifest = Data("{\"verified\":true}".utf8)
        try writeOwned(bytes, to: directoryURL.appendingPathComponent("body.partial"), create: true)
        try writeOwned(manifest, to: directoryURL.appendingPathComponent("manifest.partial"), create: true)
        let parent = open(parentURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw HarnessFailure.assertion("owned fence parent") }
        defer { close(parent) }
        let directory = openat(parent, "owned-job", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw HarnessFailure.assertion("owned fence directory") }
        defer { close(directory) }
        let file = openat(directory, "body.partial", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw HarnessFailure.assertion("owned fence body") }
        defer { close(file) }
        let manifestFile = openat(directory, "manifest.partial", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard manifestFile >= 0 else { throw HarnessFailure.assertion("owned fence manifest") }
        defer { close(manifestFile) }
        let anchor = try D.DirectoryAnchor(parent: parent, directory: directory, directoryURL: directoryURL)
        try body(FenceFixture(parentURL: parentURL, directoryURL: directoryURL, directory: directory,
            file: file, manifestFile: manifestFile, anchor: anchor, bodyBytes: bytes, manifestBytes: manifest))
    }

    static func smallBytes(_ fd: Int32, count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let amount = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress!, count, 0) }
        try check(amount == count, "small owned reread")
        return Data(bytes)
    }

    static func smallHash(_ fd: Int32, count: Int) throws -> String {
        SHA256.hash(data: try smallBytes(fd, count: count)).map { String(format: "%02x", $0) }.joined()
    }

    static func mutatePreservingSizeAndMtime(_ fd: Int32, replacement: Data) throws {
        var before = stat()
        try check(fstat(fd, &before) == 0 && before.st_size == off_t(replacement.count), "same-size owned mutation")
        // Do not sleep to provoke a race. Apply a bounded sequence, checking the
        // actual ctime differs before returning; APFS carries nanosecond fields.
        for _ in 0..<128 {
            let amount = replacement.withUnsafeBytes { pwrite(fd, $0.baseAddress!, $0.count, 0) }
            try check(amount == replacement.count, "same-size owned pwrite")
            var times = [before.st_atimespec, before.st_mtimespec]
            let restored = times.withUnsafeMutableBufferPointer { futimens(fd, $0.baseAddress!) }
            try check(restored == 0 && fsync(fd) == 0, "restore owned mtime")
            var after = stat()
            try check(fstat(fd, &after) == 0 && after.st_size == before.st_size &&
                after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec &&
                after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec, "size and exact mtime restored")
            if after.st_ctimespec.tv_sec != before.st_ctimespec.tv_sec ||
                after.st_ctimespec.tv_nsec != before.st_ctimespec.tv_nsec { return }
        }
        throw HarnessFailure.assertion("owned mutation must produce observable changed ctime")
    }

    static func replaceOwnedParent(_ fixture: FenceFixture) throws {
        let moved = fixture.parentURL.deletingLastPathComponent().appendingPathComponent("retained-parent-\(UUID().uuidString.lowercased())")
        try FileManager.default.moveItem(at: fixture.parentURL, to: moved)
        try FileManager.default.createDirectory(at: fixture.parentURL, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: fixture.directoryURL, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }

    static func publishSmallPair(_ fixture: FenceFixture) throws -> (D.FileIdentity, D.FileIdentity) {
        let before = try D.fencedFile(file: fixture.file, directory: fixture.directory, name: "body.partial")
        let body = try D.exclusivePublish(file: fixture.file, directory: fixture.directory,
            source: "body.partial", destination: "body.ipsw", before: before, checkParent: fixture.checkParent)
        let manifestBefore = try D.fencedFile(file: fixture.manifestFile, directory: fixture.directory, name: "manifest.partial")
        let manifest = try D.exclusivePublish(file: fixture.manifestFile, directory: fixture.directory,
            source: "manifest.partial", destination: "manifest.json", before: manifestBefore, checkParent: fixture.checkParent)
        return (body, manifest)
    }

    static func finalFence(_ fixture: FenceFixture, _ pair: (D.FileIdentity, D.FileIdentity),
                           bytes: Data? = nil, parentCheck: (() throws -> Void)? = nil) throws {
        try D.finalPublicationFence(file: fixture.file, directory: fixture.directory, name: "body.ipsw",
            expected: pair.0, manifestFile: fixture.manifestFile, manifestName: "manifest.json",
            manifestBytes: bytes ?? fixture.manifestBytes, manifestIdentity: pair.1,
            checkParent: parentCheck ?? fixture.checkParent)
    }

    static func publicationFences(_ root: URL) throws {
        try withFenceFixture(root) { fixture in
            let reread = try D.fencedReread(file: fixture.file, directory: fixture.directory, name: "body.partial",
                checkParent: fixture.checkParent, reread: { try smallHash(fixture.file, count: fixture.bodyBytes.count) })
            try check(reread.identity.size == UInt64(fixture.bodyBytes.count), "stable full identity permits reread")
            try rejects(.changedFile, "restored mtime and size do not conceal changed ctime during reread") {
                _ = try D.fencedReread(file: fixture.file, directory: fixture.directory, name: "body.partial",
                    checkParent: fixture.checkParent, reread: {
                        let observed = try smallHash(fixture.file, count: fixture.bodyBytes.count)
                        try mutatePreservingSizeAndMtime(fixture.file, replacement: Data("historical-body-B".utf8))
                        return observed
                    })
            }
        }
        try withFenceFixture(root) { fixture in
            try rejects(.changedFile, "unchanged held bytes cannot authorize a replaced parent path") {
                _ = try D.fencedReread(file: fixture.file, directory: fixture.directory, name: "body.partial",
                    checkParent: fixture.checkParent, reread: {
                        let observed = try smallHash(fixture.file, count: fixture.bodyBytes.count)
                        try replaceOwnedParent(fixture)
                        return observed
                    })
            }
            try check(try smallBytes(fixture.file, count: fixture.bodyBytes.count) == fixture.bodyBytes, "detached completed bytes retained")
        }
        try withFenceFixture(root) { fixture in
            let before = try D.fencedFile(file: fixture.file, directory: fixture.directory, name: "body.partial")
            let occupied = fixture.directoryURL.appendingPathComponent("body.ipsw")
            let prior = Data("retained-existing-destination".utf8)
            try writeOwned(prior, to: occupied, create: true)
            try rejects(.posix(operation: "publish-owned-file", code: EEXIST), "failed exclusive rename cannot adopt ctime or replace prior bytes") {
                _ = try D.exclusivePublish(file: fixture.file, directory: fixture.directory,
                    source: "body.partial", destination: "body.ipsw", before: before, checkParent: fixture.checkParent)
            }
            _ = try D.fencedFile(file: fixture.file, directory: fixture.directory, name: "body.partial", expected: before)
            try check(try Data(contentsOf: occupied) == prior, "exclusive destination retained")
        }
        try withFenceFixture(root) { fixture in
            let before = try D.fencedFile(file: fixture.file, directory: fixture.directory, name: "body.partial")
            let expected = D.Failure.posix(operation: "injected-publication-fsync", code: EIO)
            var renamed = false
            try rejects(.publishedButUnconfirmed(cause: expected), "post-rename fsync failure cannot return a confirmed receipt") {
                _ = try D.exclusivePublish(file: fixture.file, directory: fixture.directory,
                    source: "body.partial", destination: "body.ipsw", before: before, checkParent: fixture.checkParent,
                    didRename: { renamed = true }, syncDirectory: { _, _ in throw expected })
            }
            try check(renamed && FileManager.default.fileExists(atPath: fixture.directoryURL.appendingPathComponent("body.ipsw").path), "plausible published body retained on fsync failure")
            try check(try smallBytes(fixture.file, count: fixture.bodyBytes.count) == fixture.bodyBytes, "fsync uncertainty does not discard bytes")
        }
        try withFenceFixture(root) { fixture in
            let before = try D.fencedFile(file: fixture.file, directory: fixture.directory, name: "body.partial")
            try rejects(.publishedButUnconfirmed(cause: .changedFile), "ctime cannot be adopted after the exclusive rename boundary") {
                _ = try D.exclusivePublish(file: fixture.file, directory: fixture.directory,
                    source: "body.partial", destination: "body.ipsw", before: before, checkParent: fixture.checkParent,
                    syncDirectory: { directory, _ in
                        try mutatePreservingSizeAndMtime(fixture.file, replacement: Data("historical-body-B".utf8))
                        try check(fsync(directory) == 0, "owned directory fsync")
                    })
            }
        }
        try withFenceFixture(root) { fixture in
            let pair = try publishSmallPair(fixture)
            try finalFence(fixture, pair)
            try mutatePreservingSizeAndMtime(fixture.file, replacement: Data("historical-body-B".utf8))
            try rejects(.publishedButUnconfirmed(cause: .changedFile), "body mutation after manifest publication remains unconfirmed") {
                try finalFence(fixture, pair)
            }
            try check(FileManager.default.fileExists(atPath: fixture.directoryURL.appendingPathComponent("manifest.json").path), "manifest retained on body uncertainty")
        }
        try withFenceFixture(root) { fixture in
            let pair = try publishSmallPair(fixture)
            try mutatePreservingSizeAndMtime(fixture.manifestFile, replacement: Data("{\"verified\":null}".utf8))
            try rejects(.publishedButUnconfirmed(cause: .changedFile), "manifest mutation despite restored mtime remains unconfirmed") {
                try finalFence(fixture, pair)
            }
        }
        try withFenceFixture(root) { fixture in
            let pair = try publishSmallPair(fixture)
            try rejects(.publishedButUnconfirmed(cause: .changedFile), "manifest bytes must match independently of identity") {
                try finalFence(fixture, pair, bytes: Data("{\"verified\":null}".utf8))
            }
        }
        try withFenceFixture(root) { fixture in
            let pair = try publishSmallPair(fixture)
            let path = fixture.directoryURL.appendingPathComponent("manifest.json")
            try FileManager.default.moveItem(at: path, to: fixture.directoryURL.appendingPathComponent("retained-manifest.json"))
            try writeOwned(fixture.manifestBytes, to: path, create: true)
            try rejects(.publishedButUnconfirmed(cause: .changedFile), "same-byte replacement manifest inode remains unconfirmed") {
                try finalFence(fixture, pair)
            }
        }
        try withFenceFixture(root) { fixture in
            let pair = try publishSmallPair(fixture)
            var checks = 0
            try rejects(.publishedButUnconfirmed(cause: .changedFile), "last parent fence runs after manifest byte confirmation") {
                try finalFence(fixture, pair, parentCheck: {
                    checks += 1
                    if checks == 2 { try replaceOwnedParent(fixture) }
                    try fixture.checkParent()
                })
            }
            try check(checks == 2, "final anchored parent check reached")
            try check(try smallBytes(fixture.file, count: fixture.bodyBytes.count) == fixture.bodyBytes, "parent uncertainty retains completed bytes")
        }
    }
}
