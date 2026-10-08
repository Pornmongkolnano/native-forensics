import CryptoKit
import Darwin
import Foundation
import ForensicsCore
import NFDocumentDecoding

/// The decoder sees a memory snapshot, not a pathname that a framework could
/// reopen or resolve differently. The descriptor remains open for a final check.
final class VerifiedDocumentFile {
    let input: DocumentInput
    let snapshot: VerifiedDocument
    let sha256: String
    private let descriptor: Int32
    private let initial: stat

    init(input: DocumentInput) throws {
        guard input.fileURL.isFileURL, !input.fileURL.path.isEmpty,
              input.fileURL.host == nil || input.fileURL.host == "" || input.fileURL.host == "localhost",
              input.fileURL.path.utf8.count <= 8_192, !input.fileURL.path.utf8.contains(0),
              input.expectedByteCount >= 0,
              input.expectedByteCount <= DocumentLimits.maximumInputBytes,
              input.expectedSHA256.utf8.count == 64,
              input.expectedSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw DocumentAnalysisError.invalidInput
        }
        let fd = Darwin.open(input.fileURL.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw DocumentAnalysisError.invalidInput }
        var before = stat()
        guard Darwin.fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_size >= 0, before.st_size <= DocumentLimits.maximumInputBytes else {
            Darwin.close(fd)
            throw DocumentAnalysisError.invalidInput
        }
        guard before.st_size == input.expectedByteCount else {
            Darwin.close(fd)
            throw DocumentAnalysisError.integrityMismatch
        }
        do {
            var bytes = Data()
            bytes.reserveCapacity(Int(before.st_size))
            var hash = SHA256()
            var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
            while true {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                if count < 0, errno == EINTR { continue }
                guard count >= 0 else { throw DocumentAnalysisError.sourceChanged }
                if count == 0 { break }
                guard Int64(bytes.count + count) <= DocumentLimits.maximumInputBytes,
                      Int64(bytes.count + count) <= input.expectedByteCount else {
                    throw DocumentAnalysisError.sourceChanged
                }
                let chunk = Data(buffer.prefix(count))
                hash.update(data: chunk)
                bytes.append(chunk)
            }
            guard Int64(bytes.count) == input.expectedByteCount else { throw DocumentAnalysisError.sourceChanged }
            let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
            guard digest == input.expectedSHA256 else { throw DocumentAnalysisError.integrityMismatch }
            var opened = stat()
            var named = stat()
            guard Darwin.fstat(fd, &opened) == 0, Darwin.lstat(input.fileURL.path, &named) == 0,
                  named.st_mode & S_IFMT == S_IFREG,
                  Self.same(before, opened), Self.same(before, named) else {
                throw DocumentAnalysisError.sourceChanged
            }
            self.input = input
            self.descriptor = fd
            self.initial = before
            self.snapshot = try VerifiedDocument(data: bytes, expectedSHA256: digest, expectedByteCount: input.expectedByteCount)
            self.sha256 = digest
        } catch {
            Darwin.close(fd)
            throw error
        }
    }

    deinit { Darwin.close(descriptor) }

    func checkUnchanged() throws {
        try checkIdentity()
        var hash = SHA256()
        var offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress, $0.count, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw DocumentAnalysisError.sourceChanged }
            if count == 0 { break }
            offset += Int64(count)
            guard offset <= input.expectedByteCount else { throw DocumentAnalysisError.sourceChanged }
            hash.update(data: Data(buffer.prefix(count)))
        }
        guard offset == input.expectedByteCount,
              hash.finalize().map({ String(format: "%02x", $0) }).joined() == sha256 else {
            throw DocumentAnalysisError.sourceChanged
        }
        try checkIdentity()
    }

    private func checkIdentity() throws {
        var opened = stat()
        var named = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Darwin.lstat(input.fileURL.path, &named) == 0,
              named.st_mode & S_IFMT == S_IFREG,
              Self.same(initial, opened), Self.same(initial, named) else {
            throw DocumentAnalysisError.sourceChanged
        }
    }

    private static func same(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }
}
