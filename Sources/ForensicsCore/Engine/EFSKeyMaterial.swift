import Darwin
import Foundation

public enum EFSKeyInputError: Error, LocalizedError, Sendable, Equatable {
    case invalidSelection, invalidKeyFile, invalidCertificateFile, sourceChanged, alreadyConsumed, readTimedOut

    public var errorDescription: String? {
        switch self {
        case .invalidSelection: "Choose a regular local RSA private DER file and certificate DER file."
        case .invalidKeyFile: "The private key must be a complete PKCS#1 RSA DER file no larger than 64 KiB."
        case .invalidCertificateFile: "The certificate must be a complete DER file no larger than 128 KiB."
        case .sourceChanged: "A selected credential file changed while it was being read. Select the files again."
        case .alreadyConsumed: "These credentials were already consumed. Select them again for another operation."
        case .readTimedOut: "Reading the selected credential files exceeded the read deadline. Select local files and try again."
        }
    }
}

/// Producer-owned buffers are filled directly from held read-only descriptors.
/// This type is deliberately not Codable and never exposes a key pathname or
/// digest. Its synchronous borrowed buffers must not escape `consume`.
/// Owned buffers are cleared and released after consumption, even on failure.
/// Framework/kernel copies and caller-created copies cannot be proved erased.
public final class EFSKeyMaterial: @unchecked Sendable {
    public static let maximumPrivateKeyBytes = 64 * 1_024
    public static let maximumCertificateBytes = 128 * 1_024
    /// Checked between bounded reads, including interrupted syscall retries.
    /// A kernel-stalled local file read is still awaited through descriptor
    /// release; this is not a claim that arbitrary kernel I/O can be killed.
    public static let maximumReadSeconds: TimeInterval = 10
    public static let profile = "rsa-pkcs1-der-certificate"

    public let privateKeyByteCount: Int
    public let certificateByteCount: Int
    private let lock = NSLock()
    private var buffers: Buffers?

    private init(privateKey: EFSOwnedKeyBuffer, certificate: EFSOwnedKeyBuffer) {
        privateKeyByteCount = privateKey.count; certificateByteCount = certificate.count
        buffers = Buffers(privateKey: privateKey, certificate: certificate)
    }

    public var isConsumed: Bool { lock.lock(); defer { lock.unlock() }; return buffers == nil }

    /// Call only after immediate workflow admission. Reading does not import a
    /// key, evaluate certificate trust, contact a network or use a keychain.
    public static func read(privateKeyURL: URL, certificateURL: URL) async throws -> EFSKeyMaterial {
        try await read(privateKeyURL: privateKeyURL, certificateURL: certificateURL, hooks: .production)
    }

    @discardableResult
    public func consume<Value>(_ operation: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) throws -> Value) throws -> Value {
        lock.lock()
        guard let owned = buffers else { lock.unlock(); throw EFSKeyInputError.alreadyConsumed }
        buffers = nil; lock.unlock()
        defer { owned.privateKey.clear(); owned.certificate.clear() }
        return try operation(owned.privateKey.bytes, owned.certificate.bytes)
    }

    public func discard() {
        lock.lock(); let owned = buffers; buffers = nil; lock.unlock()
        owned?.privateKey.clear(); owned?.certificate.clear()
    }

    deinit { discard() }

    private struct Buffers {
        let privateKey: EFSOwnedKeyBuffer
        let certificate: EFSOwnedKeyBuffer
    }

    static func readForTesting(privateKeyURL: URL, certificateURL: URL, hooks: EFSKeyReadHooks) async throws -> EFSKeyMaterial {
        try await read(privateKeyURL: privateKeyURL, certificateURL: certificateURL, hooks: hooks)
    }

    private static func read(privateKeyURL: URL, certificateURL: URL, hooks: EFSKeyReadHooks) async throws -> EFSKeyMaterial {
        let cancellation = EFSKeyReadCancellation()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let material = try await BlockingWork.run {
                try cancellation.check()
                let deadline = hooks.uptime() + maximumReadSeconds
                let privateKey = try EFSKeyFileReader.read(privateKeyURL, maximum: maximumPrivateKeyBytes,
                    invalid: .invalidKeyFile, cancellation: cancellation, deadline: deadline, hooks: hooks)
                do {
                    let certificate = try EFSKeyFileReader.read(certificateURL, maximum: maximumCertificateBytes,
                        invalid: .invalidCertificateFile, cancellation: cancellation, deadline: deadline, hooks: hooks)
                    try cancellation.check()
                    return EFSKeyMaterial(privateKey: privateKey, certificate: certificate)
                } catch { privateKey.clear(); throw error }
            }
            do { try Task.checkCancellation(); return material }
            catch { material.discard(); throw error }
        } onCancel: { cancellation.cancel() }
    }
}

struct EFSKeyReadHooks: Sendable {
    let read: (@Sendable (Int32, UnsafeMutableRawBufferPointer, Int) throws -> Int)?
    let afterRead: @Sendable (Int) throws -> Void
    let descriptorClosed: @Sendable () -> Void
    let bufferCleared: @Sendable (UnsafeRawBufferPointer) -> Void
    let uptime: @Sendable () -> TimeInterval
    static let production = Self(read: nil, afterRead: { _ in }, descriptorClosed: {}, bufferCleared: { _ in },
        uptime: { ProcessInfo.processInfo.systemUptime })
}

private final class EFSOwnedKeyBuffer: @unchecked Sendable {
    let count: Int
    private var allocation: UnsafeMutableRawPointer?
    private let cleared: @Sendable (UnsafeRawBufferPointer) -> Void
    init(count: Int, cleared: @escaping @Sendable (UnsafeRawBufferPointer) -> Void) {
        self.count = count; self.cleared = cleared
        allocation = .allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        allocation?.initializeMemory(as: UInt8.self, repeating: 0, count: count)
    }
    var bytes: UnsafeRawBufferPointer { UnsafeRawBufferPointer(start: allocation, count: allocation == nil ? 0 : count) }
    var mutableBytes: UnsafeMutableRawBufferPointer { UnsafeMutableRawBufferPointer(start: allocation, count: count) }
    func clear() {
        guard let allocation else { return }
        _ = Darwin.memset_s(allocation, count, 0, count)
        cleared(UnsafeRawBufferPointer(start: allocation, count: count))
        allocation.deallocate(); self.allocation = nil
    }
    deinit { clear() }
}

private final class EFSKeyReadCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    func check() throws {
        lock.lock(); let value = cancelled; lock.unlock()
        if value { throw CancellationError() }
    }
}

private enum EFSKeyFileReader {
    static func read(_ url: URL, maximum: Int, invalid: EFSKeyInputError,
                     cancellation: EFSKeyReadCancellation, deadline: TimeInterval, hooks: EFSKeyReadHooks) throws -> EFSOwnedKeyBuffer {
        try checkpoint(cancellation, deadline: deadline, hooks: hooks)
        let descriptor = try open(url)
        defer { Darwin.close(descriptor); hooks.descriptorClosed() }
        guard let original = identity(descriptor), original.size > 0, original.size <= Int64(maximum) else { throw invalid }
        let buffer = EFSOwnedKeyBuffer(count: Int(original.size), cleared: hooks.bufferCleared)
        do {
            var offset = 0
            while offset < buffer.count {
                try checkpoint(cancellation, deadline: deadline, hooks: hooks)
                let remaining = min(16 * 1_024, buffer.count - offset)
                let destination = UnsafeMutableRawBufferPointer(rebasing: buffer.mutableBytes[offset..<(offset + remaining)])
                let count: Int
                do {
                    if let injected = hooks.read { count = try injected(descriptor, destination, remaining) }
                    else { count = try checkedRead(descriptor, into: destination, count: remaining,
                        invalid: invalid, cancellation: cancellation, deadline: deadline, hooks: hooks) }
                }
                catch is CancellationError { throw CancellationError() }
                catch EFSKeyInputError.readTimedOut { throw EFSKeyInputError.readTimedOut }
                catch { throw invalid }
                guard count > 0, count <= remaining else { throw EFSKeyInputError.sourceChanged }
                offset += count; try hooks.afterRead(offset)
            }
            try checkpoint(cancellation, deadline: deadline, hooks: hooks)
            guard identity(descriptor) == original else { throw EFSKeyInputError.sourceChanged }
            let current: Int32
            do { current = try open(url) }
            catch { throw EFSKeyInputError.sourceChanged }
            defer { Darwin.close(current) }
            guard identity(current) == original else { throw EFSKeyInputError.sourceChanged }
            guard completeDERSequence(buffer.bytes) else { throw invalid }
            try checkpoint(cancellation, deadline: deadline, hooks: hooks)
            return buffer
        } catch {
            buffer.clear()
            if error is CancellationError { throw CancellationError() }
            if let known = error as? EFSKeyInputError { throw known }
            throw invalid
        }
    }

    /// Hold each ancestor while opening its child. Symlinks in any component,
    /// aliases, directories, devices and FIFOs are excluded before a byte read.
    private static func open(_ url: URL) throws -> Int32 {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw EFSKeyInputError.invalidSelection }
        let components = url.path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !components.isEmpty, components.count <= 256, components.allSatisfy({ $0 != "." && $0 != ".." }) else {
            throw EFSKeyInputError.invalidSelection
        }
        var parent = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw EFSKeyInputError.invalidSelection }
        defer { Darwin.close(parent) }
        for name in components.dropLast() {
            let child = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { throw EFSKeyInputError.invalidSelection }
            Darwin.close(parent); parent = child
        }
        let descriptor = Darwin.openat(parent, components[components.count - 1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw EFSKeyInputError.invalidSelection }
        guard identity(descriptor) != nil else { Darwin.close(descriptor); throw EFSKeyInputError.invalidSelection }
        var filesystem = statfs()
        guard Darwin.fstatfs(descriptor, &filesystem) == 0, filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            Darwin.close(descriptor); throw EFSKeyInputError.invalidSelection
        }
        return descriptor
    }

    private static func checkpoint(_ cancellation: EFSKeyReadCancellation, deadline: TimeInterval, hooks: EFSKeyReadHooks) throws {
        try cancellation.check()
        guard hooks.uptime() < deadline else { throw EFSKeyInputError.readTimedOut }
    }

    private static func checkedRead(_ descriptor: Int32, into bytes: UnsafeMutableRawBufferPointer, count: Int,
                                    invalid: EFSKeyInputError, cancellation: EFSKeyReadCancellation,
                                    deadline: TimeInterval, hooks: EFSKeyReadHooks) throws -> Int {
        while true {
            try checkpoint(cancellation, deadline: deadline, hooks: hooks)
            let actual = Darwin.read(descriptor, bytes.baseAddress, count)
            if actual >= 0 { return actual }
            if errno == EINTR { continue }
            throw invalid
        }
    }

    private static func identity(_ descriptor: Int32) -> SourceIdentity? {
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG, metadata.st_size >= 0 else { return nil }
        return SourceIdentity(metadata)
    }

    /// Only a complete, minimally sized outer DER SEQUENCE is recognized here.
    /// The native engine owns strict PKCS#1 integers and certificate validation.
    private static func completeDERSequence(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count >= 2, bytes[0] == 0x30 else { return false }
        let firstLength = bytes[1]
        if firstLength < 0x80 { return Int(firstLength) + 2 == bytes.count }
        let count = Int(firstLength & 0x7f)
        guard (1...3).contains(count), bytes.count >= count + 2, bytes[2] != 0 else { return false }
        var length = 0
        for index in 2..<(2 + count) { length = (length << 8) | Int(bytes[index]) }
        return length >= 128 && length + count + 2 == bytes.count
    }
}
