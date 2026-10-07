import CryptoKit
import Darwin
import Foundation

/// All ranges are read with pread from one regular O_RDONLY/O_NOFOLLOW descriptor.
/// The directory chain and source identity are pinned, and the selected-file hash
/// is checked before parsing and again immediately before publication/export.
final class UDFPinnedSource: @unchecked Sendable {
    let evidence: EvidenceRecord
    let sourceURL: URL
    private let parent: Int32
    private let descriptor: Int32
    private let identity: SourceIdentity

    init(evidence: EvidenceRecord, maximumSourceBytes: Int64) throws {
        guard evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              EngineValidation.validHash(evidence.sha256), evidence.sourcePath.hasPrefix("/"),
              !evidence.sourcePath.utf8.contains(0), evidence.byteCount > 0,
              evidence.byteCount <= maximumSourceBytes else {
            throw UDFError.unsupported("Only a bounded regular raw image with a selected-file SHA-256 receipt is accepted.")
        }
        self.evidence = evidence
        sourceURL = URL(fileURLWithPath: evidence.sourcePath).standardizedFileURL
        parent = try EvidenceViewFiles.openDirectory(sourceURL.deletingLastPathComponent())
        do {
            descriptor = try FileAccess.openReadOnly(sourceURL.lastPathComponent, in: parent)
        } catch { Darwin.close(parent); throw error }
        do {
            let openedIdentity = try FileAccess.identity(of: descriptor)
            guard openedIdentity.size == evidence.byteCount else { throw ForensicsError.sourceChanged }
            // Initialize the last stored property only after all throwing work;
            // otherwise a failing size guard also invokes deinit after this
            // catch has closed the descriptors.
            identity = openedIdentity
        } catch { Darwin.close(descriptor); Darwin.close(parent); throw error }
    }

    deinit { Darwin.close(descriptor); Darwin.close(parent) }

    func validate() throws {
        try EvidenceViewFiles.validateDirectory(sourceURL.deletingLastPathComponent(), descriptor: parent)
        guard try FileAccess.identity(of: descriptor) == identity,
              try FileAccess.identity(at: sourceURL.lastPathComponent, in: parent) == identity else {
            throw ForensicsError.sourceChanged
        }
    }

    func read(offset: Int64, count: Int) throws -> Data {
        try Task.checkCancellation()
        guard offset >= 0, count >= 0, count <= 8 * 1_024 * 1_024,
              offset <= evidence.byteCount, Int64(count) <= evidence.byteCount - offset else {
            throw UDFError.malformed("A metadata or payload range extends beyond the supplied source bytes.")
        }
        var result = Data(count: count)
        try result.withUnsafeMutableBytes { bytes in
            var copied = 0
            while copied < count {
                try Task.checkCancellation()
                let amount = Darwin.pread(descriptor, bytes.baseAddress!.advanced(by: copied),
                                          count - copied, off_t(offset + Int64(copied)))
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw ForensicsError.sourceChanged }
                copied += amount
            }
        }
        return result
    }

    func verifyHash(progress: (@Sendable (Int64) throws -> Void)? = nil) throws {
        try validate()
        var digest = SHA256(), offset: Int64 = 0
        while offset < evidence.byteCount {
            try Task.checkCancellation()
            let data = try read(offset: offset, count: Int(min(1_048_576, evidence.byteCount - offset)))
            digest.update(data: data); offset += Int64(data.count)
            try progress?(offset)
        }
        try validate()
        guard UDFCoding.hex(digest.finalize()) == evidence.sha256 else { throw ForensicsError.sourceChanged }
    }

    func digest(extents: [UDFSourceExtent], check: (() throws -> Void)? = nil) throws -> String {
        var digest = SHA256()
        for extent in extents {
            guard ["recorded", "inline"].contains(extent.allocation), extent.offset >= 0,
                  extent.byteCount >= 0, extent.offset <= evidence.byteCount,
                  extent.byteCount <= evidence.byteCount - extent.offset else {
                throw UDFError.invalidResult("The source extent is invalid or unrecorded.")
            }
            var position: Int64 = 0
            while position < extent.byteCount {
                try Task.checkCancellation()
                try check?()
                let data = try read(offset: extent.offset + position,
                                    count: Int(min(1_048_576, extent.byteCount - position)))
                digest.update(data: data); position += Int64(data.count)
            }
        }
        return UDFCoding.hex(digest.finalize())
    }
}

enum UDFCoding {
    static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
    static func hash(_ data: Data) -> String { hex(SHA256.hash(data: data)) }
}
