import CryptoKit
import Darwin
import Foundation

/// Offsets refer to the selected container file, not a logical filesystem or an
/// EWF decompressed disk. This view works even when the boot sector is damaged.
public struct RawEvidenceHexSnapshot: Sendable, Equatable {
    public let offset: Int64
    /// Total bytes in the selected evidence file; bytes.count is this window.
    public let byteCount: Int64
    public let sourceSHA256: String
    public let bytes: Data
    public let hexText: String
    public var hashScope: String { FileHashScope.selectedFileBytes }
}

public enum RawEvidenceHexReader {
    public static let maximumWindowBytes = 32 * 1_024

    public static func read(evidence: EvidenceRecord, offset: Int64,
                            length: Int = 4_096) async throws -> RawEvidenceHexSnapshot {
        try Task.checkCancellation()
        let worker = Task.detached(priority: .userInitiated) {
            try readWindow(evidence: evidence, offset: offset, length: length)
        }
        return try await withTaskCancellationHandler {
            let value = try await worker.value
            try Task.checkCancellation()
            return value
        } onCancel: { worker.cancel() }
    }

    // The fault boundary makes replacement-during-read tests deterministic.
    static func readForTesting(evidence: EvidenceRecord, offset: Int64, length: Int,
                               afterRead: () throws -> Void) throws -> RawEvidenceHexSnapshot {
        try readWindow(evidence: evidence, offset: offset, length: length, afterRead: afterRead)
    }

    private static func readWindow(evidence: EvidenceRecord, offset: Int64, length: Int,
                                    afterRead: () throws -> Void = {}) throws -> RawEvidenceHexSnapshot {
        try Task.checkCancellation()
        guard evidence.byteCount >= 0, evidence.hashScope == FileHashScope.selectedFileBytes,
              EngineValidation.validHash(evidence.sha256), offset >= 0, offset <= evidence.byteCount,
              (1...maximumWindowBytes).contains(length) else {
            throw ForensicsError.invalidSource("The byte offset, window size or source receipt is invalid.")
        }
        let url = URL(fileURLWithPath: evidence.sourcePath).standardizedFileURL
        guard evidence.sourcePath.hasPrefix("/"), !evidence.sourcePath.utf8.contains(0) else {
            throw ForensicsError.invalidFileURL
        }
        let parent = try EvidenceViewFiles.openDirectory(url.deletingLastPathComponent(), searchOnly: true)
        defer { Darwin.close(parent) }
        let descriptor = try FileAccess.openReadOnly(url.lastPathComponent, in: parent)
        defer { Darwin.close(descriptor) }
        let identity = try FileAccess.identity(of: descriptor)
        guard identity.size == evidence.byteCount else { throw ForensicsError.sourceChanged }
        let validate = {
            try EvidenceViewFiles.validateDirectory(url.deletingLastPathComponent(), descriptor: parent, searchOnly: true)
            guard (try? FileAccess.identity(at: url.lastPathComponent, in: parent)) == identity,
                  (try? FileAccess.identity(of: descriptor)) == identity else {
                throw ForensicsError.sourceChanged
            }
        }
        try validate()
        try verifyHash(descriptor, evidence: evidence, validate: validate)
        let requested = Int(min(Int64(length), evidence.byteCount - offset))
        var bytes = Data(count: requested)
        try bytes.withUnsafeMutableBytes { buffer in
            var read = 0
            while read < requested {
                try Task.checkCancellation()
                let amount = Darwin.pread(descriptor, buffer.baseAddress?.advanced(by: read),
                                          requested - read, off_t(offset + Int64(read)))
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw ForensicsError.sourceChanged }
                read += amount
            }
        }
        try afterRead()
        try validate()
        // Hash every source byte again, rather than treating a matching window
        // or descriptor size as proof of the original evidence receipt.
        try verifyHash(descriptor, evidence: evidence, validate: validate)
        try Task.checkCancellation()
        return RawEvidenceHexSnapshot(offset: offset, byteCount: evidence.byteCount,
            sourceSHA256: evidence.sha256, bytes: bytes, hexText: hex(bytes, offset: offset))
    }

    private static func verifyHash(_ descriptor: Int32, evidence: EvidenceRecord,
                                   validate: () throws -> Void) throws {
        var hasher = SHA256(), offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while offset < evidence.byteCount {
            try Task.checkCancellation()
            let count = Int(min(Int64(buffer.count), evidence.byteCount - offset))
            let amount = buffer.withUnsafeMutableBytes {
                Darwin.pread(descriptor, $0.baseAddress, count, off_t(offset))
            }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw ForensicsError.sourceChanged }
            buffer.withUnsafeBytes {
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0[..<amount]))
            }
            offset += Int64(amount)
        }
        try validate()
        guard hasher.finalize().map({ String(format: "%02x", $0) }).joined() == evidence.sha256 else {
            throw ForensicsError.sourceChanged
        }
    }

    private static func hex(_ data: Data, offset: Int64) -> String {
        let bytes = [UInt8](data)
        return stride(from: 0, to: bytes.count, by: 16).map { start in
            let row = bytes[start..<min(start + 16, bytes.count)]
            let hexadecimal = row.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = row.map { (32...126).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
            return String(format: "%016llx", UInt64(offset + Int64(start))) + "  "
                + hexadecimal.padding(toLength: 47, withPad: " ", startingAt: 0) + "  " + ascii
        }.joined(separator: "\n")
    }
}

/// Used by the raw viewer and report exporter. No intermediate user-created
/// symlink may redirect a pinned file operation into a different directory.
enum EvidenceViewFiles {
    static func openDirectory(_ url: URL, searchOnly: Bool = false) throws -> Int32 {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw ForensicsError.invalidFileURL }
        var path = url.standardizedFileURL.path
        // Foundation normalizes /private/var back to /var on this host. Accept
        // only Apple's exact system aliases; all user-created links still fail
        // the no-follow walk. Recheck the alias on every validation pass.
        for alias in ["var", "tmp"] {
            let prefix = "/" + alias
            if path == prefix || path.hasPrefix(prefix + "/") {
                var metadata = stat()
                if Darwin.lstat(prefix, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFLNK {
                    var buffer = [UInt8](repeating: 0, count: 1_024)
                    let count = buffer.withUnsafeMutableBytes {
                        Darwin.readlink(prefix, $0.baseAddress, $0.count)
                    }
                    guard count > 0, count < buffer.count else { throw ForensicsError.sourceChanged }
                    let target = String(decoding: buffer.prefix(count), as: UTF8.self)
                    guard target == "private/" + alias || target == "/private/" + alias else {
                        throw ForensicsError.sourceChanged
                    }
                    path = "/private/" + alias + path.dropFirst(prefix.count)
                }
            }
        }
        // A known selected file needs only directory search, not an ability to
        // enumerate its parent. Keep readable directory handles for report and
        // storage callers that enumerate or synchronize directories.
        let flags = (searchOnly ? O_SEARCH : (O_RDONLY | O_DIRECTORY)) | O_NOFOLLOW | O_CLOEXEC
        var descriptor = Darwin.open("/", flags)
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot open directory") }
        do {
            for component in path.split(separator: "/").map(String.init) {
                let next = Darwin.openat(descriptor, component, flags)
                guard next >= 0 else { throw FileAccess.posixError("Cannot open directory without following links") }
                Darwin.close(descriptor); descriptor = next
            }
            return descriptor
        } catch { Darwin.close(descriptor); throw error }
    }

    static func validateDirectory(_ url: URL, descriptor: Int32, searchOnly: Bool = false) throws {
        let current = try openDirectory(url, searchOnly: searchOnly)
        defer { Darwin.close(current) }
        var lhs = stat(), rhs = stat()
        guard Darwin.fstat(current, &lhs) == 0, Darwin.fstat(descriptor, &rhs) == 0,
              lhs.st_dev == rhs.st_dev, lhs.st_ino == rhs.st_ino else { throw ForensicsError.sourceChanged }
    }

    static func referenceMatches(_ name: String, parent: Int32, descriptor: Int32) -> Bool {
        var current = stat(), opened = stat()
        return Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0
            && Darwin.fstat(descriptor, &opened) == 0 && current.st_mode & S_IFMT == S_IFREG
            && current.st_dev == opened.st_dev && current.st_ino == opened.st_ino
    }
}
