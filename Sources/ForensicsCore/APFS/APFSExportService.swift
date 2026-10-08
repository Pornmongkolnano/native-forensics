import CryptoKit
import Darwin
import Foundation

public struct APFSExportReceipt: Codable, Sendable, Equatable {
    public let caseID: UUID
    public let evidenceID: UUID
    public let volumeUUID: UUID
    public let relativePath: String
    public let resultSHA256: String
    public let containerSHA256: String
    public let byteCount: Int64
    public let sha256: String
    public let containerHashScope: String
    public let outputHashScope: String
    public let selectedSnapshot: APFSSnapshotInventoryEntry?
    public init(caseID: UUID, evidenceID: UUID, volumeUUID: UUID, relativePath: String, resultSHA256: String,
                containerSHA256: String, byteCount: Int64, sha256: String,
                containerHashScope: String = FileHashScope.selectedFileBytes, outputHashScope: String = "logical-APFS-file-bytes",
                selectedSnapshot: APFSSnapshotInventoryEntry? = nil) {
        self.caseID = caseID; self.evidenceID = evidenceID; self.volumeUUID = volumeUUID; self.relativePath = relativePath
        self.resultSHA256 = resultSHA256; self.containerSHA256 = containerSHA256; self.byteCount = byteCount; self.sha256 = sha256
        self.containerHashScope = containerHashScope; self.outputHashScope = outputHashScope
        self.selectedSnapshot = selectedSnapshot
    }
}

public enum APFSExportService {
    public static func export(evidence: EvidenceRecord, inspection: APFSInspectionResult, entry: APFSFileEntry,
                               in forensicCase: ForensicCase, to destination: URL,
                               passphrase: APFSPassphrase? = nil, volumePassphrase: APFSPassphrase? = nil) async throws -> APFSExportReceipt {
        let cancellation = APFSCancellation()
        let worker = Task.detached(priority: .userInitiated) {
            try APFSMountedImageAdapter.validate(inspection, evidence: evidence)
            cancellation.setDeadline(seconds: inspection.options.jobTimeoutSeconds)
            let files = try await BlockingWork.run { try APFSCaseFiles(forensicCase: forensicCase, write: false, cancellation: cancellation) }
            defer { files.close() }
            guard try files.evidence(evidence.id) == evidence,
                  let entryHash = entry.sha256, entry.kind == .regular,
                  inspection.entries.contains(entry) else { throw APFSReadError.invalidResult }
            try validateDestination(destination, caseURL: forensicCase.bundleURL, evidence: files.manifest.evidence)
            let stored = try await BlockingWork.run { try APFSResultStore.loadLatestRecord(in: forensicCase, evidenceID: evidence.id) }
            guard let stored, stored.result == inspection else { throw APFSReadError.invalidResult }
            let content = try await APFSMountedImageAdapter().readVerifiedFile(evidence: evidence, inspection: inspection,
                entry: entry, passphrase: passphrase, volumePassphrase: volumePassphrase)
            guard content.sha256 == entryHash, content.data.count == entry.byteCount,
                  content.selectedSnapshot == inspection.selectedSnapshot else { throw APFSReadError.sourceChanged }
            return try await BlockingWork.run {
                try cancellation.check(); try files.validate()
                let source = try APFSExportSource(evidence: evidence)
                defer { source.close() }
                let transaction = try APFSExportTransaction(destination: destination)
                defer { transaction.cleanup() }
                try transaction.write(content.data, cancellation: cancellation)
                let outputIdentity = try transaction.verify(size: entry.byteCount, hash: entryHash, cancellation: cancellation)
                try source.verify(cancellation: cancellation)
                try files.validate(); try cancellation.check()
                try transaction.publish(identity: outputIdentity, expectedSHA256: entryHash, cancellation: cancellation,
                    validate: { try source.validate(); try files.validate() })
                // The exclusive rename is the commit. Cancellation afterwards
                // does not hide a committed export or delete its bytes.
                return APFSExportReceipt(caseID: files.manifest.id, evidenceID: evidence.id, volumeUUID: inspection.volumeUUID,
                    relativePath: entry.relativePath, resultSHA256: stored.receipt.resultSHA256,
                    containerSHA256: evidence.sha256, byteCount: entry.byteCount, sha256: entryHash,
                    selectedSnapshot: inspection.selectedSnapshot)
            }
        }
        return try await withTaskCancellationHandler { try await worker.value } onCancel: { cancellation.cancel(); worker.cancel() }
    }

    static func validateDestination(_ destination: URL, caseURL: URL, evidence: [EvidenceRecord]) throws {
        guard destination.isFileURL, destination.host == nil || destination.host == "" || destination.host == "localhost",
              destination.path.hasPrefix("/"), !destination.path.utf8.contains(0),
              !destination.lastPathComponent.isEmpty, destination.lastPathComponent != ".", destination.lastPathComponent != "..",
              !FileAccess.isInside(destination, directory: caseURL),
              !destination.deletingLastPathComponent().pathComponents.contains(where: { $0.hasSuffix(".nativecase") }),
              !evidence.contains(where: { $0.sourcePath == destination.standardizedFileURL.path }) else { throw APFSReadError.invalidResult }
        let parent = try EvidenceViewFiles.openDirectory(destination.standardizedFileURL.deletingLastPathComponent())
        defer { Darwin.close(parent) }
        var existing = stat()
        guard Darwin.fstatat(parent, destination.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) != 0,
              errno == ENOENT else { throw APFSReadError.invalidResult }
    }
}

private final class APFSExportSource {
    let evidence: EvidenceRecord
    private let url: URL
    private let parent: Int32, descriptor: Int32
    private let identity: SourceIdentity
    private var closed = false
    init(evidence: EvidenceRecord) throws {
        self.evidence = evidence; url = URL(fileURLWithPath: evidence.sourcePath).standardizedFileURL
        parent = try EvidenceViewFiles.openDirectory(url.deletingLastPathComponent(), searchOnly: true)
        do { descriptor = try FileAccess.openReadOnly(url.lastPathComponent, in: parent) } catch { Darwin.close(parent); throw error }
        do {
            let opened = try FileAccess.identity(of: descriptor)
            guard opened.size == evidence.byteCount else { throw APFSReadError.sourceChanged }
            try APFSImageSourceScope.requireMainForkOnly(descriptor)
            identity = opened
        } catch { Darwin.close(descriptor); Darwin.close(parent); throw error }
    }
    func validate() throws {
        try APFSImageSourceScope.requireMainForkOnly(descriptor)
        try EvidenceViewFiles.validateDirectory(url.deletingLastPathComponent(), descriptor: parent, searchOnly: true)
        guard try FileAccess.identity(of: descriptor) == identity,
              try FileAccess.identity(at: url.lastPathComponent, in: parent) == identity else { throw APFSReadError.sourceChanged }
    }
    func verify(cancellation: APFSCancellation) throws {
        try validate()
        guard try APFSExportCoding.fileHash(descriptor, size: identity.size, cancellation: cancellation) == evidence.sha256 else { throw APFSReadError.sourceChanged }
        try validate()
    }
    func close() { if !closed { closed = true; Darwin.close(descriptor); Darwin.close(parent) } }
    deinit { close() }
}

final class APFSExportTransaction {
    private let parent: Int32, output: Int32
    private let destination: URL, stagingName: String
    private let createdIdentity: SourceIdentity
    private var published = false, cleaned = false
    init(destination: URL) throws {
        self.destination = destination.standardizedFileURL
        parent = try EvidenceViewFiles.openDirectory(self.destination.deletingLastPathComponent())
        var metadata = stat()
        if Darwin.fstatat(parent, self.destination.lastPathComponent, &metadata, AT_SYMLINK_NOFOLLOW) == 0 {
            Darwin.close(parent); throw APFSReadError.invalidResult
        }
        guard errno == ENOENT else { Darwin.close(parent); throw APFSReadError.invalidResult }
        stagingName = ".apfs-export-" + UUID().uuidString.lowercased() + ".tmp"
        output = Darwin.openat(parent, stagingName, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { Darwin.close(parent); throw FileAccess.posixError("Cannot stage APFS export") }
        do { createdIdentity = try FileAccess.identity(of: output) }
        catch { Darwin.close(output); Darwin.close(parent); throw error }
    }
    func write(_ data: Data, cancellation: APFSCancellation) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                try cancellation.check()
                let amount = Darwin.write(output, bytes.baseAddress!.advanced(by: offset), min(1_048_576, bytes.count - offset))
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw FileAccess.posixError("Cannot write APFS export") }; offset += amount
            }
        }
        guard Darwin.fsync(output) == 0 else { throw FileAccess.posixError("Cannot flush APFS export") }
    }
    func verify(size: Int64, hash: String, cancellation: APFSCancellation) throws -> SourceIdentity {
        let identity = try FileAccess.identity(of: output)
        guard identity.device == createdIdentity.device, identity.inode == createdIdentity.inode, identity.size == size,
              try APFSExportCoding.fileHash(output, size: size, cancellation: cancellation) == hash,
              try FileAccess.identity(of: output) == identity,
              try FileAccess.identity(at: stagingName, in: parent) == identity else { throw APFSReadError.sourceChanged }
        return identity
    }
    // The defaulted callbacks are internal fault seams; production callers
    // always use the real directory flush and no mutation callbacks.
    func publish(identity: SourceIdentity, expectedSHA256: String, cancellation: APFSCancellation,
                 validate: () throws -> Void, afterRename: () throws -> Void = {},
                 afterVerification: () throws -> Void = {},
                 flushDirectory: (Int32) -> Int32 = { Darwin.fsync($0) }) throws {
        try validate(); try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        guard try FileAccess.identity(of: output) == identity,
              try FileAccess.identity(at: stagingName, in: parent) == identity else { throw APFSReadError.sourceChanged }
        try cancellation.check()
        guard Darwin.renameatx_np(parent, stagingName, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            throw FileAccess.posixError("Cannot publish APFS export without replacing an existing file")
        }
        published = true
        do {
            try afterRename()
            // Our exclusive rename changes ctime on APFS. Only this owned
            // output transition may adopt that new ctime: stable inode/device,
            // size/mtime and the independent full digest remain mandatory.
            let committedIdentity = try FileAccess.identity(of: output)
            guard committedIdentity.device == identity.device, committedIdentity.inode == identity.inode,
                  committedIdentity.size == identity.size,
                  committedIdentity.modifiedSeconds == identity.modifiedSeconds,
                  committedIdentity.modifiedNanoseconds == identity.modifiedNanoseconds,
                  try FileAccess.identity(at: destination.lastPathComponent, in: parent) == committedIdentity else {
                throw APFSReadError.invalidResult
            }
            guard flushDirectory(parent) == 0 else { throw APFSReadError.invalidResult }
            try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
            guard try APFSExportCoding.fileHash(output, size: identity.size, cancellation: cancellation,
                                                allowCancelled: true) == expectedSHA256,
                  try FileAccess.identity(of: output) == committedIdentity,
                  try FileAccess.identity(at: destination.lastPathComponent, in: parent) == committedIdentity else {
                throw APFSReadError.invalidResult
            }
            try afterVerification()
            try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        } catch { throw APFSExportPublicationError.publishedButDurabilityUnconfirmed }
    }
    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        if !published { APFSCaseFiles.removeOwned(stagingName, parent: parent, identity: createdIdentity) }
        Darwin.close(output); Darwin.close(parent)
    }
    deinit { cleanup() }
}

private enum APFSExportCoding {
    static func fileHash(_ fd: Int32, size: Int64, cancellation: APFSCancellation,
                         allowCancelled: Bool = false) throws -> String {
        var hasher = SHA256(), offset: Int64 = 0, buffer = [UInt8](repeating: 0, count: 1_048_576)
        while offset < size {
            try cancellation.check(allowCancelled: allowCancelled)
            let wanted = Int(min(Int64(buffer.count), size - offset))
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(fd, $0.baseAddress, wanted, off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw APFSReadError.sourceChanged }
            hasher.update(data: Data(buffer.prefix(count))); offset += Int64(count)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

public enum APFSExportPublicationError: Error, LocalizedError, Sendable {
    case publishedButDurabilityUnconfirmed
    public var errorDescription: String? { "The APFS export was published, but durable completion could not be confirmed. Check the chosen destination before retrying; published bytes were preserved." }
}
