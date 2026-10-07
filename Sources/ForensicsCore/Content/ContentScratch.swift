import Darwin
import Foundation

/// Pinned directory descriptors retain ownership through path replacement.
/// Cleanup only removes our known leaf and empty directory, never unknown
/// contents, replacement paths or symlink targets.
final class ContentScratch {
    let outputURL: URL
    private let parentFD: Int32
    private let directoryFD: Int32
    private let name: String
    private let directoryURL: URL
    private var knownLeaf: SourceIdentity?
    private var cleaned = false

    init() throws {
        let parent = try FileAccess.localURL(FileManager.default.temporaryDirectory)
        let parentDescriptor = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentDescriptor >= 0 else { throw FileAccess.posixError("Cannot open private content temporary storage") }
        let directoryName = ".native-content-\(UUID().uuidString)"
        guard Darwin.mkdirat(parentDescriptor, directoryName, mode_t(0o700)) == 0 else {
            let error = FileAccess.posixError("Cannot create private content temporary storage")
            Darwin.close(parentDescriptor)
            throw error
        }
        let directoryDescriptor = Darwin.openat(parentDescriptor, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryDescriptor >= 0 else {
            let error = FileAccess.posixError("Cannot open content temporary directory")
            _ = Darwin.unlinkat(parentDescriptor, directoryName, AT_REMOVEDIR)
            Darwin.close(parentDescriptor)
            throw error
        }
        parentFD = parentDescriptor
        directoryFD = directoryDescriptor
        name = directoryName
        directoryURL = parent.appendingPathComponent(directoryName, isDirectory: true)
        outputURL = directoryURL.appendingPathComponent("selected-file")
    }

    func claimPublished(receipt: ExtractionResult, identity: SourceIdentity) throws {
        guard receipt.outputPath == outputURL.path else { throw VerifiedContentError.extractedContentMismatch }
        // Identity comes from the engine's held publication descriptor. Keep it
        // even if the directory path moved, so anchored cleanup can remove only
        // our actual leaf while leaving every replacement untouched.
        knownLeaf = identity
        guard (try? FileAccess.identity(at: "selected-file", in: directoryFD)) == identity,
              directoryStillOwned() else { throw VerifiedContentError.extractedContentMismatch }
    }

    func readVerified(receipt: ExtractionResult, expectedSize: Int64) throws -> Data {
        guard receipt.outputPath == outputURL.path, directoryStillOwned() else { throw VerifiedContentError.extractedContentMismatch }
        let descriptor = try FileAccess.openReadOnly("selected-file", in: directoryFD)
        defer { Darwin.close(descriptor) }
        let before = try FileAccess.identity(of: descriptor)
        guard receipt.byteCount == expectedSize, receipt.byteCount <= VerifiedContentService.maximumFileBytes,
              before.size == receipt.byteCount, before == knownLeaf else { throw VerifiedContentError.extractedContentMismatch }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < before.size {
            try Task.checkCancellation()
            let requested = Int(min(Int64(buffer.count), before.size - Int64(bytes.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: requested) }
            guard count > 0 else { throw VerifiedContentError.extractedContentMismatch }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        guard try FileAccess.identity(of: descriptor) == before,
              (try? FileAccess.identity(at: "selected-file", in: directoryFD)) == before,
              directoryStillOwned() else { throw VerifiedContentError.extractedContentMismatch }
        return bytes
    }

    func cleanup() {
        guard !cleaned else { return }
        cleaned = true
        if let knownLeaf, (try? FileAccess.identity(at: "selected-file", in: directoryFD)) == knownLeaf {
            _ = Darwin.unlinkat(directoryFD, "selected-file", 0)
        }
        if directoryStillOwned() { _ = Darwin.unlinkat(parentFD, name, AT_REMOVEDIR) }
        Darwin.close(directoryFD)
        Darwin.close(parentFD)
    }

    deinit { cleanup() }

    private func directoryStillOwned() -> Bool {
        var owned = stat(), named = stat(), requested = stat()
        guard Darwin.fstat(directoryFD, &owned) == 0,
              Darwin.fstatat(parentFD, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              Darwin.lstat(directoryURL.path, &requested) == 0 else { return false }
        return [named, requested].allSatisfy {
            $0.st_mode & S_IFMT == S_IFDIR && $0.st_dev == owned.st_dev && $0.st_ino == owned.st_ino
        }
    }
}
