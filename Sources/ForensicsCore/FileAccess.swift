import Darwin
import Foundation

struct SourceIdentity: Sendable, Equatable {
    let device: dev_t
    let inode: ino_t
    let size: Int64
    let modifiedSeconds: Int
    let modifiedNanoseconds: Int
    let changedSeconds: Int
    let changedNanoseconds: Int

    init(_ metadata: stat) {
        device = metadata.st_dev
        inode = metadata.st_ino
        size = metadata.st_size
        modifiedSeconds = metadata.st_mtimespec.tv_sec
        modifiedNanoseconds = metadata.st_mtimespec.tv_nsec
        changedSeconds = metadata.st_ctimespec.tv_sec
        changedNanoseconds = metadata.st_ctimespec.tv_nsec
    }
}

enum FileAccess {
    static func localURL(_ url: URL) throws -> URL {
        guard url.isFileURL, !url.path.isEmpty, !url.path.utf8.contains(0),
              url.host == nil || url.host == "" || url.host == "localhost" else {
            throw ForensicsError.invalidFileURL
        }
        return url.standardizedFileURL.resolvingSymlinksInPath()
    }

    static func openReadOnly(_ url: URL) throws -> Int32 {
        // Nonblocking prevents a FIFO/device from hanging before fstat rejects it.
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        return try regularDescriptor(descriptor)
    }

    /// A pinned parent descriptor prevents an intermediate directory swap from
    /// redirecting case metadata reads outside the directory that was opened.
    static func openReadOnly(_ name: String, in directory: Int32) throws -> Int32 {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw ForensicsError.invalidFileURL
        }
        let descriptor = Darwin.openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        return try regularDescriptor(descriptor)
    }

    private static func regularDescriptor(_ descriptor: Int32) throws -> Int32 {
        guard descriptor >= 0 else { throw posixError("Cannot open source") }
        do {
            _ = try identity(of: descriptor)
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    static func identity(of descriptor: Int32) throws -> SourceIdentity {
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0 else { throw posixError("Cannot read file metadata") }
        guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_size >= 0 else {
            throw ForensicsError.invalidSource("Only regular files are supported; folders, devices and pipes are excluded.")
        }
        return SourceIdentity(metadata)
    }

    static func identity(at url: URL) throws -> SourceIdentity {
        let descriptor = try openReadOnly(url)
        defer { Darwin.close(descriptor) }
        return try identity(of: descriptor)
    }

    static func identity(at name: String, in directory: Int32) throws -> SourceIdentity {
        let descriptor = try openReadOnly(name, in: directory)
        defer { Darwin.close(descriptor) }
        return try identity(of: descriptor)
    }

    static func read(_ descriptor: Int32, into buffer: UnsafeMutableRawBufferPointer, count: Int) throws -> Int {
        while true {
            let result = Darwin.read(descriptor, buffer.baseAddress, count)
            if result >= 0 { return result }
            if errno == EINTR { continue }
            throw posixError("Cannot read file")
        }
    }

    static func posixError(_ operation: String) -> ForensicsError {
        let code = errno
        return .io("\(operation): \(String(cString: strerror(code))) (\(code)).")
    }

    static func isInside(_ source: URL, directory: URL) -> Bool {
        let sourcePath = source.standardizedFileURL.path
        let directoryPath = directory.standardizedFileURL.path
        return sourcePath == directoryPath || sourcePath.hasPrefix(directoryPath + "/")
    }
}
