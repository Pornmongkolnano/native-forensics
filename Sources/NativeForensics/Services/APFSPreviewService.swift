import CryptoKit
import Darwin
import Foundation
import ForensicsCore

enum APFSPreviewError: Error, LocalizedError, Sendable, Equatable {
    case cleanupIncomplete
    var errorDescription: String? {
        "Private APFS preview bytes could not be confirmed removed. Further APFS previews are disabled for this window until it is reopened."
    }
}

/// Fresh allocated APFS bytes are verified again before the existing isolated
/// document client receives a descriptor-backed private leaf. No mount path or
/// credential enters document metadata or the saved case record.
enum APFSPreviewService {
    static func preview(evidence: EvidenceRecord, inspection: APFSInspectionResult, entry: APFSFileEntry,
                        passphrase: APFSPassphrase?, volumePassphrase: APFSPassphrase?,
                        documentHelperURL: URL) async throws -> DocumentAnalysis {
        guard entry.kind == .regular, entry.byteCount <= DocumentLimits.maximumInputBytes,
              let expectedHash = entry.sha256 else { throw APFSReadError.fileUnavailable }
        let verified = try await APFSMountedImageAdapter().readVerifiedFile(evidence: evidence,
            inspection: inspection, entry: entry, passphrase: passphrase, volumePassphrase: volumePassphrase)
        try Task.checkCancellation()
        try validateVerifiedFile(verified, evidence: evidence, inspection: inspection, entry: entry)
        return try await decodeVerifiedBytes(verified.data, sha256: expectedHash, helperURL: documentHelperURL)
    }

    static func validateVerifiedFile(_ verified: APFSVerifiedFile, evidence: EvidenceRecord,
                                     inspection: APFSInspectionResult, entry: APFSFileEntry) throws {
        guard let expectedHash = entry.sha256,
              verified.relativePath == entry.relativePath, verified.volumeUUID == inspection.volumeUUID,
              verified.selectedSnapshot == inspection.selectedSnapshot,
              verified.containerSHA256 == evidence.sha256, verified.sha256 == expectedHash,
              Int64(verified.data.count) == entry.byteCount,
              SHA256.hash(data: verified.data).map({ String(format: "%02x", $0) }).joined() == expectedHash else {
            throw DocumentAnalysisError.integrityMismatch
        }
    }

    static func decodeVerifiedBytes(_ data: Data, sha256: String, helperURL: URL) async throws -> DocumentAnalysis {
        try Task.checkCancellation()
        let scratch = try APFSPreviewScratch()
        do {
            try scratch.writeVerified(data, sha256: sha256)
            let value = try await DocumentAnalysisClient(helperURL: helperURL).analyze(
                DocumentInput(fileURL: scratch.fileURL, expectedSHA256: sha256, expectedByteCount: Int64(data.count)))
            try Task.checkCancellation(); try scratch.validate()
            guard value.sourceSHA256 == sha256, value.sourceByteCount == Int64(data.count) else {
                throw DocumentAnalysisError.integrityMismatch
            }
            try scratch.cleanupChecked()
            return value
        } catch {
            do { try scratch.cleanupChecked() } catch { throw APFSPreviewError.cleanupIncomplete }
            throw error
        }
    }
}

/// Cleanup unlinks only the exact owned leaf and directory identities. An
/// injected sibling or replacement is never removed recursively.
final class APFSPreviewScratch {
    let directoryURL: URL
    let fileURL: URL
    private let parent: Int32
    private let directory: Int32
    private let file: Int32
    private let directoryName: String
    private let fileName = "verified-content"
    private let directoryDevice: dev_t, directoryInode: ino_t
    private let fileDevice: dev_t, fileInode: ino_t
    private var expectedSize: Int64 = 0
    private var cleaned = false
    private var cleanupConfirmed = false

    init(parentURL: URL = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()) throws {
        let parentURL = parentURL.standardizedFileURL
        guard parentURL.isFileURL, parentURL.host == nil || parentURL.host == "" || parentURL.host == "localhost",
              parentURL.path.hasPrefix("/"), !parentURL.path.utf8.contains(0) else {
            throw DocumentAnalysisError.invalidInput
        }
        parent = Darwin.open(parentURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw DocumentAnalysisError.invalidInput }
        directoryName = "NativeForensics-APFS-Preview-" + UUID().uuidString.lowercased()
        directoryURL = parentURL.appendingPathComponent(directoryName, isDirectory: true)
        fileURL = directoryURL.appendingPathComponent(fileName)
        guard Darwin.mkdirat(parent, directoryName, mode_t(0o700)) == 0 else {
            Darwin.close(parent); throw DocumentAnalysisError.invalidInput
        }
        directory = Darwin.openat(parent, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else {
            _ = Darwin.unlinkat(parent, directoryName, AT_REMOVEDIR); Darwin.close(parent)
            throw DocumentAnalysisError.invalidInput
        }
        var directoryStat = stat()
        guard Darwin.fstat(directory, &directoryStat) == 0, directoryStat.st_mode & S_IFMT == S_IFDIR else {
            Darwin.close(directory); Darwin.close(parent); throw DocumentAnalysisError.invalidInput
        }
        directoryDevice = directoryStat.st_dev; directoryInode = directoryStat.st_ino
        file = Darwin.openat(directory, fileName, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard file >= 0 else {
            _ = Darwin.unlinkat(parent, directoryName, AT_REMOVEDIR)
            Darwin.close(directory); Darwin.close(parent); throw DocumentAnalysisError.invalidInput
        }
        var fileStat = stat()
        guard Darwin.fstat(file, &fileStat) == 0, fileStat.st_mode & S_IFMT == S_IFREG, fileStat.st_nlink == 1 else {
            Darwin.close(file); Darwin.close(directory); Darwin.close(parent)
            throw DocumentAnalysisError.invalidInput
        }
        fileDevice = fileStat.st_dev; fileInode = fileStat.st_ino
        do { try validate() }
        catch { cleanup(); throw error }
    }

    func writeVerified(_ data: Data, sha256: String) throws {
        guard Int64(data.count) <= DocumentLimits.maximumInputBytes,
              SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == sha256 else {
            throw DocumentAnalysisError.integrityMismatch
        }
        try validate()
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(file, buffer.baseAddress?.advanced(by: offset), min(131_072, buffer.count-offset))
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw DocumentAnalysisError.integrityMismatch }
                offset += count
            }
        }
        expectedSize = Int64(data.count)
        guard Darwin.fsync(file) == 0 else { throw DocumentAnalysisError.integrityMismatch }
        try validate()
        var digest = SHA256(), offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 131_072)
        while offset < expectedSize {
            try Task.checkCancellation()
            let amount = Int(min(Int64(buffer.count), expectedSize-offset))
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(file, $0.baseAddress, amount, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw DocumentAnalysisError.integrityMismatch }
            digest.update(data: Data(buffer.prefix(count))); offset += Int64(count)
        }
        guard digest.finalize().map({ String(format: "%02x", $0) }).joined() == sha256 else {
            throw DocumentAnalysisError.integrityMismatch
        }
        try validate()
    }

    func validate() throws {
        guard !cleaned else { throw DocumentAnalysisError.sourceChanged }
        var heldDirectory = stat(), namedDirectory = stat(), locatedDirectory = stat(), heldFile = stat(), namedFile = stat()
        guard Darwin.fstat(directory, &heldDirectory) == 0,
              Darwin.fstatat(parent, directoryName, &namedDirectory, AT_SYMLINK_NOFOLLOW) == 0,
              Darwin.lstat(directoryURL.path, &locatedDirectory) == 0,
              Darwin.fstat(file, &heldFile) == 0,
              Darwin.fstatat(directory, fileName, &namedFile, AT_SYMLINK_NOFOLLOW) == 0,
              heldDirectory.st_mode & S_IFMT == S_IFDIR, namedDirectory.st_mode & S_IFMT == S_IFDIR,
              heldDirectory.st_dev == directoryDevice, heldDirectory.st_ino == directoryInode,
              namedDirectory.st_dev == directoryDevice, namedDirectory.st_ino == directoryInode,
              locatedDirectory.st_mode & S_IFMT == S_IFDIR,
              locatedDirectory.st_dev == directoryDevice, locatedDirectory.st_ino == directoryInode,
              heldFile.st_mode & S_IFMT == S_IFREG, namedFile.st_mode & S_IFMT == S_IFREG,
              heldFile.st_dev == fileDevice, heldFile.st_ino == fileInode,
              namedFile.st_dev == fileDevice, namedFile.st_ino == fileInode,
              heldFile.st_nlink == 1, heldFile.st_size == expectedSize else {
            throw DocumentAnalysisError.sourceChanged
        }
    }

    func cleanupChecked() throws {
        guard performCleanup() else { throw APFSPreviewError.cleanupIncomplete }
    }
    func cleanup() { _ = performCleanup() }
    @discardableResult private func performCleanup() -> Bool {
        guard !cleaned else { return cleanupConfirmed }; cleaned = true
        var confirmed = true
        var leaf = stat(), folder = stat()
        if Darwin.fstatat(directory, fileName, &leaf, AT_SYMLINK_NOFOLLOW) == 0 {
            if leaf.st_mode & S_IFMT == S_IFREG, leaf.st_dev == fileDevice, leaf.st_ino == fileInode {
                if leaf.st_nlink != 1 { confirmed = false }
                if Darwin.unlinkat(directory, fileName, 0) != 0 { confirmed = false }
            } else { confirmed = false }
        } else if errno != ENOENT { confirmed = false }
        if Darwin.fstatat(parent, directoryName, &folder, AT_SYMLINK_NOFOLLOW) == 0 {
            if folder.st_mode & S_IFMT == S_IFDIR, folder.st_dev == directoryDevice, folder.st_ino == directoryInode {
                if Darwin.unlinkat(parent, directoryName, AT_REMOVEDIR) != 0 { confirmed = false }
            } else { confirmed = false }
        } else if errno != ENOENT { confirmed = false }
        Darwin.close(file); Darwin.close(directory); Darwin.close(parent)
        cleanupConfirmed = confirmed
        return confirmed
    }
    deinit { cleanup() }
}
