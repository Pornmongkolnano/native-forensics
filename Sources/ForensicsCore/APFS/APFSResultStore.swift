import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func apfsCacheFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

public struct APFSCacheReceipt: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let caseID: UUID
    public let evidenceID: UUID
    public let generationID: UUID
    public let resultSHA256: String
    public let relativePath: String
    public let serializedByteCount: Int
    public let coverage: APFSReadCoverage
    public init(schemaVersion: Int = 1, caseID: UUID, evidenceID: UUID, generationID: UUID, resultSHA256: String,
                relativePath: String, serializedByteCount: Int, coverage: APFSReadCoverage) {
        self.schemaVersion = schemaVersion; self.caseID = caseID; self.evidenceID = evidenceID
        self.generationID = generationID; self.resultSHA256 = resultSHA256; self.relativePath = relativePath
        self.serializedByteCount = serializedByteCount; self.coverage = coverage
    }
}

/// Immutable source-bound generations and a separately published latest
/// pointer. Loading remains historical and never opens the evidence source.
public enum APFSResultStore {
    public static let maximumResultBytes = 64 * 1_024 * 1_024

    @discardableResult
    public static func save(_ result: APFSInspectionResult, in forensicCase: ForensicCase,
                            prePublicationValidation: @Sendable () throws -> Void = {}) throws -> APFSCacheReceipt {
        let caseFiles = try APFSCaseFiles(forensicCase: forensicCase, write: true)
        defer { caseFiles.close() }
        let evidence = try caseFiles.evidence(result.evidenceID)
        try APFSMountedImageAdapter.validate(result, evidence: evidence)
        let generationID = UUID(), bytes = try encode(result)
        guard bytes.count <= maximumResultBytes else { throw APFSReadError.outputLimit }
        let receipt = APFSCacheReceipt(schemaVersion: 1, caseID: caseFiles.manifest.id, evidenceID: evidence.id,
            generationID: generationID, resultSHA256: digest(bytes), relativePath: relativePath(evidence.id, generationID),
            serializedByteCount: bytes.count, coverage: result.coverage)
        let pointer = try encode(receipt)
        let directories = try APFSStoreDirectories(root: caseFiles.root, evidenceID: evidence.id, create: true)
        defer { directories.close() }
        let previous = try readPointer(directories.evidence)
        if let previous {
            try validateReceipt(previous.value, caseID: caseFiles.manifest.id, evidenceID: evidence.id)
            _ = try readGeneration(previous.value, directories: directories, evidence: evidence)
        }
        let stagingName = ".apfs-" + UUID().uuidString.lowercased() + ".tmp"
        guard Darwin.mkdirat(directories.generations, stagingName, 0o700) == 0 else { throw FileAccess.posixError("Cannot create APFS generation") }
        let staging = try APFSCaseFiles.directory(stagingName, parent: directories.generations, create: false)
        defer { Darwin.close(staging) }
        var currentName = stagingName, resultIdentity: SourceIdentity?, checksumIdentity: SourceIdentity?
        var latestName: String?, latestIdentity: SourceIdentity?, committed = false
        defer {
            if !committed {
                if let resultIdentity { APFSCaseFiles.removeOwned("result.json", parent: staging, identity: resultIdentity) }
                if let checksumIdentity { APFSCaseFiles.removeOwned("checksum.json", parent: staging, identity: checksumIdentity) }
                if let latestName, let latestIdentity { APFSCaseFiles.removeOwned(latestName, parent: directories.evidence, identity: latestIdentity) }
                if APFSCaseFiles.matchesDirectory(currentName, parent: directories.generations, descriptor: staging) {
                    _ = Darwin.unlinkat(directories.generations, currentName, AT_REMOVEDIR)
                }
            }
        }
        resultIdentity = try APFSCaseFiles.writeNew(bytes, name: "result.json", parent: staging)
        checksumIdentity = try APFSCaseFiles.writeNew(pointer, name: "checksum.json", parent: staging)
        guard Darwin.fsync(staging) == 0 else { throw FileAccess.posixError("Cannot flush APFS generation") }
        try Task.checkCancellation(); try caseFiles.validate(); try directories.validate(root: caseFiles.root)
        guard APFSCaseFiles.matchesDirectory(stagingName, parent: directories.generations, descriptor: staging),
              (try? FileAccess.identity(at: "result.json", in: staging)) == resultIdentity,
              (try? FileAccess.identity(at: "checksum.json", in: staging)) == checksumIdentity else { throw APFSReadError.invalidResult }
        let generationName = generationID.uuidString.lowercased()
        guard Darwin.renameatx_np(directories.generations, stagingName, directories.generations, generationName, UInt32(RENAME_EXCL)) == 0 else {
            throw FileAccess.posixError("Cannot publish APFS generation")
        }
        currentName = generationName
        guard Darwin.fsync(directories.generations) == 0 else { throw FileAccess.posixError("Cannot flush APFS generations") }
        latestName = ".latest-" + UUID().uuidString.lowercased() + ".tmp"
        latestIdentity = try APFSCaseFiles.writeNew(pointer, name: latestName!, parent: directories.evidence)
        try Task.checkCancellation(); try prePublicationValidation(); try caseFiles.validate(); try directories.validate(root: caseFiles.root)
        guard APFSCaseFiles.matchesDirectory(currentName, parent: directories.generations, descriptor: staging),
              (try? FileAccess.identity(at: "result.json", in: staging)) == resultIdentity,
              (try? FileAccess.identity(at: "checksum.json", in: staging)) == checksumIdentity,
              (try? FileAccess.identity(at: latestName!, in: directories.evidence)) == latestIdentity else { throw APFSReadError.invalidResult }
        if let previous {
            guard (try? FileAccess.identity(at: "latest.json", in: directories.evidence)) == previous.identity else { throw APFSReadError.invalidResult }
        } else {
            var metadata = stat()
            guard Darwin.fstatat(directories.evidence, "latest.json", &metadata, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw APFSReadError.invalidResult }
        }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(directories.evidence, latestName!, directories.evidence, "latest.json", previous == nil ? UInt32(RENAME_EXCL) : 0) == 0 else {
            throw FileAccess.posixError("Cannot publish APFS latest pointer")
        }
        committed = true
        do {
            guard Darwin.fsync(directories.evidence) == 0 else { throw APFSReadError.invalidResult }
            try caseFiles.validate(); try directories.validate(root: caseFiles.root)
        } catch { throw CasePublicationError.publishedButDurabilityUnconfirmed(recordID: generationID) }
        return receipt
    }

    public static func loadLatest(in forensicCase: ForensicCase, evidenceID: UUID) throws -> APFSInspectionResult? {
        try loadLatestRecord(in: forensicCase, evidenceID: evidenceID)?.result
    }

    public static func loadLatestRecord(in forensicCase: ForensicCase, evidenceID: UUID)
        throws -> (result: APFSInspectionResult, receipt: APFSCacheReceipt)? {
        let files = try APFSCaseFiles(forensicCase: forensicCase, write: false); defer { files.close() }
        let evidence = try files.evidence(evidenceID)
        guard let directories = try APFSStoreDirectories.optional(root: files.root, evidenceID: evidenceID) else { return nil }
        defer { directories.close() }
        guard let pointer = try readPointer(directories.evidence) else { return nil }
        try validateReceipt(pointer.value, caseID: files.manifest.id, evidenceID: evidenceID)
        let result = try readGeneration(pointer.value, directories: directories, evidence: evidence)
        try files.validate(); try directories.validate(root: files.root)
        guard (try? FileAccess.identity(at: "latest.json", in: directories.evidence)) == pointer.identity else { throw APFSReadError.invalidResult }
        return (result, pointer.value)
    }

    public static func jobProvenance(result: APFSInspectionResult, receipt: APFSCacheReceipt, startedAt: Date,
                                     completedAt: Date = Date()) throws -> CaseJobProvenance {
        struct Options: Encodable {
            let read: APFSReadOptions; let volumeUUID: UUID
            let containerEncryption: APFSContainerEncryption; let volumeEncryption: APFSVolumeEncryption
            let view = "current-allocated-volume"
            let snapshotContentSupported = false
        }
        guard receipt.evidenceID == result.evidenceID, receipt.coverage == result.coverage,
              receipt.resultSHA256 == digest(try encode(result)) else { throw APFSReadError.invalidResult }
        return try CaseJobProvenance.make(id: receipt.generationID, evidenceID: result.evidenceID, kind: "apfs.allocated-inspection",
            startedAt: startedAt, completedAt: completedAt,
            status: result.coverage == .completeAllocatedView ? .completed : .partial,
            component: .init(identifier: result.driver, version: result.driverVersion, buildDigest: "system-OS-driver; source contract v1", executableSHA256: nil),
            options: Options(read: result.options, volumeUUID: result.volumeUUID, containerEncryption: result.containerEncryption, volumeEncryption: result.volumeEncryption),
            sourceHashes: [.init(ordinal: 0, sha256: result.containerSHA256, byteCount: result.containerByteCount)],
            warnings: result.warnings, artifactRelativePath: receipt.relativePath, artifactSHA256: receipt.resultSHA256,
            artifactByteCount: receipt.serializedByteCount)
    }

    private static func readGeneration(_ receipt: APFSCacheReceipt, directories: APFSStoreDirectories,
                                       evidence: EvidenceRecord) throws -> APFSInspectionResult {
        let name = receipt.generationID.uuidString.lowercased()
        let generation = try APFSCaseFiles.directory(name, parent: directories.generations, create: false); defer { Darwin.close(generation) }
        let (checksum, _) = try APFSCaseFiles.read("checksum.json", parent: generation, maximum: 4_096)
        guard try JSONDecoder().decode(APFSCacheReceipt.self, from: checksum) == receipt else { throw APFSReadError.invalidResult }
        let (bytes, _) = try APFSCaseFiles.read("result.json", parent: generation, maximum: maximumResultBytes)
        guard bytes.count == receipt.serializedByteCount, digest(bytes) == receipt.resultSHA256 else { throw APFSReadError.invalidResult }
        let result = try JSONDecoder().decode(APFSInspectionResult.self, from: bytes)
        try APFSMountedImageAdapter.validate(result, evidence: evidence)
        guard result.coverage == receipt.coverage, APFSCaseFiles.matchesDirectory(name, parent: directories.generations, descriptor: generation) else { throw APFSReadError.invalidResult }
        return result
    }

    private static func readPointer(_ directory: Int32) throws -> (value: APFSCacheReceipt, identity: SourceIdentity)? {
        var metadata = stat()
        if Darwin.fstatat(directory, "latest.json", &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }; throw APFSReadError.invalidResult
        }
        let (bytes, identity) = try APFSCaseFiles.read("latest.json", parent: directory, maximum: 4_096)
        return (try JSONDecoder().decode(APFSCacheReceipt.self, from: bytes), identity)
    }
    private static func validateReceipt(_ receipt: APFSCacheReceipt, caseID: UUID, evidenceID: UUID) throws {
        guard receipt.schemaVersion == 1, receipt.caseID == caseID, receipt.evidenceID == evidenceID,
              (1...maximumResultBytes).contains(receipt.serializedByteCount), EngineValidation.validHash(receipt.resultSHA256),
              receipt.relativePath == relativePath(evidenceID, receipt.generationID) else { throw APFSReadError.invalidResult }
    }
    private static func relativePath(_ evidence: UUID, _ generation: UUID) -> String {
        "apfs/" + evidence.uuidString.lowercased() + "/generations/" + generation.uuidString.lowercased() + "/result.json"
    }
    static func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    static func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}

/// Each instance is used by one serialized operation, including across awaits
/// during an export. Descriptors/manifest are immutable; no concurrent close is
/// exposed through the public API.
final class APFSCaseFiles: @unchecked Sendable {
    let root: Int32
    let manifest: CaseManifest
    private let url: URL
    private let lock: Int32
    private let lockIdentity: SourceIdentity
    private let cancellation: APFSCancellation?
    private var closed = false
    init(forensicCase: ForensicCase, write: Bool, cancellation: APFSCancellation? = nil) throws {
        try cancellation?.check()
        self.cancellation = cancellation
        url = forensicCase.bundleURL.standardizedFileURL
        root = try EvidenceViewFiles.openDirectory(url)
        do { lock = try FileAccess.openReadOnly(".case.lock", in: root) } catch { Darwin.close(root); throw error }
        do { lockIdentity = try FileAccess.identity(of: lock) } catch { Darwin.close(lock); Darwin.close(root); throw error }
        do {
            let deadline = ProcessInfo.processInfo.systemUptime + 60
            while apfsCacheFlock(lock, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0 {
                try cancellation?.check()
                try Task.checkCancellation()
                guard errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR else { throw FileAccess.posixError("Cannot lock APFS case storage") }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw APFSReadError.timeout }
                _ = Darwin.poll(nil, 0, 10)
            }
            try EvidenceViewFiles.validateDirectory(url, descriptor: root)
            let current = try CaseStore.open(at: url)
            guard current.manifest.id == forensicCase.manifest.id else { throw APFSReadError.invalidResult }
            manifest = current.manifest
        } catch { _ = apfsCacheFlock(lock, LOCK_UN); Darwin.close(lock); Darwin.close(root); throw error }
    }
    func evidence(_ id: UUID) throws -> EvidenceRecord {
        guard let evidence = manifest.evidence.first(where: { $0.id == id }), evidence.hashScope == FileHashScope.selectedFileBytes,
              !FileAccess.isInside(URL(fileURLWithPath: evidence.sourcePath), directory: url) else { throw APFSReadError.invalidResult }
        return evidence
    }
    func validate() throws {
        try cancellation?.check()
        try EvidenceViewFiles.validateDirectory(url, descriptor: root)
        guard try FileAccess.identity(of: lock) == lockIdentity,
              try FileAccess.identity(at: ".case.lock", in: root) == lockIdentity,
              try CaseStore.open(at: url).manifest == manifest else { throw APFSReadError.invalidResult }
    }
    func close() { if !closed { closed = true; _ = apfsCacheFlock(lock, LOCK_UN); Darwin.close(lock); Darwin.close(root) } }
    deinit { close() }
    static func directory(_ name: String, parent: Int32, create: Bool) throws -> Int32 {
        if create && Darwin.mkdirat(parent, name, 0o700) != 0 && errno != EEXIST { throw FileAccess.posixError("Cannot create APFS storage") }
        let fd = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw APFSReadError.invalidResult }
        guard matchesDirectory(name, parent: parent, descriptor: fd) else { Darwin.close(fd); throw APFSReadError.invalidResult }
        return fd
    }
    static func matchesDirectory(_ name: String, parent: Int32, descriptor: Int32) -> Bool {
        var named = stat(), opened = stat()
        return Darwin.fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 && Darwin.fstat(descriptor, &opened) == 0
            && named.st_mode & S_IFMT == S_IFDIR && named.st_dev == opened.st_dev && named.st_ino == opened.st_ino
    }
    static func writeNew(_ data: Data, name: String, parent: Int32) throws -> SourceIdentity {
        let fd = Darwin.openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw FileAccess.posixError("Cannot create APFS metadata") }
        defer { Darwin.close(fd) }
        var successful = false
        let created = try FileAccess.identity(of: fd)
        defer { if !successful { removeOwned(name, parent: parent, identity: created) } }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < data.count {
                try Task.checkCancellation()
                let amount = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), data.count - offset)
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw FileAccess.posixError("Cannot write APFS metadata") }; offset += amount
            }
        }
        guard Darwin.fsync(fd) == 0 else { throw FileAccess.posixError("Cannot flush APFS metadata") }
        let final = try FileAccess.identity(of: fd)
        guard final.size == data.count, try FileAccess.identity(at: name, in: parent) == final else { throw APFSReadError.invalidResult }
        successful = true; return final
    }
    static func read(_ name: String, parent: Int32, maximum: Int) throws -> (Data, SourceIdentity) {
        let fd = try FileAccess.openReadOnly(name, in: parent); defer { Darwin.close(fd) }
        let identity = try FileAccess.identity(of: fd)
        guard identity.size <= maximum else { throw APFSReadError.outputLimit }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        while bytes.count < identity.size {
            try Task.checkCancellation()
            let wanted = min(buffer.count, Int(identity.size) - bytes.count)
            let amount = try buffer.withUnsafeMutableBytes { try FileAccess.read(fd, into: $0, count: wanted) }
            guard amount > 0 else { throw APFSReadError.invalidResult }; bytes.append(contentsOf: buffer.prefix(amount))
        }
        guard try FileAccess.identity(of: fd) == identity, try FileAccess.identity(at: name, in: parent) == identity else { throw APFSReadError.invalidResult }
        return (bytes, identity)
    }
    static func removeOwned(_ name: String, parent: Int32, identity: SourceIdentity) {
        if let current = try? FileAccess.identity(at: name, in: parent), current.device == identity.device, current.inode == identity.inode {
            _ = Darwin.unlinkat(parent, name, 0)
        }
    }
}

private final class APFSStoreDirectories {
    let apfs: Int32, evidence: Int32, generations: Int32
    private let evidenceName: String
    private var closed = false
    init(root: Int32, evidenceID: UUID, create: Bool) throws {
        evidenceName = evidenceID.uuidString.lowercased()
        apfs = try APFSCaseFiles.directory("apfs", parent: root, create: create)
        do { evidence = try APFSCaseFiles.directory(evidenceName, parent: apfs, create: create) } catch { Darwin.close(apfs); throw error }
        do { generations = try APFSCaseFiles.directory("generations", parent: evidence, create: create) }
        catch { Darwin.close(evidence); Darwin.close(apfs); throw error }
    }
    static func optional(root: Int32, evidenceID: UUID) throws -> APFSStoreDirectories? {
        var metadata = stat()
        if Darwin.fstatat(root, "apfs", &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }; throw APFSReadError.invalidResult
        }
        let top = try APFSCaseFiles.directory("apfs", parent: root, create: false); defer { Darwin.close(top) }
        if Darwin.fstatat(top, evidenceID.uuidString.lowercased(), &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }; throw APFSReadError.invalidResult
        }
        return try APFSStoreDirectories(root: root, evidenceID: evidenceID, create: false)
    }
    func validate(root: Int32) throws {
        guard APFSCaseFiles.matchesDirectory("apfs", parent: root, descriptor: apfs),
              APFSCaseFiles.matchesDirectory(evidenceName, parent: apfs, descriptor: evidence),
              APFSCaseFiles.matchesDirectory("generations", parent: evidence, descriptor: generations) else { throw APFSReadError.invalidResult }
    }
    func close() { if !closed { closed = true; Darwin.close(generations); Darwin.close(evidence); Darwin.close(apfs) } }
    deinit { close() }
}
