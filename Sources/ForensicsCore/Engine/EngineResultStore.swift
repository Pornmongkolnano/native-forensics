import Darwin
import Foundation

@_silgen_name("flock")
private func engineSystemFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// A separate cache preserves the Phase 0 manifest and its selected-file hash
/// semantics. Cached listings remain historical until sources are reinspected.
public enum EngineResultStore {
    public static func save(result: EnumerationResult, evidenceID: UUID, in caseURL: URL) throws {
        try EngineValidation.result(result)
        let forensicCase = try CaseStore.open(at: caseURL)
        try validateScope(result, evidenceID: evidenceID, forensicCase: forensicCase)
        let data = try encoder().encode(result)
        guard data.count <= EngineValidation.resultLimit else { throw EngineError.limitExceeded("The filesystem cache exceeds 64 MiB.") }
        try withCaseLock(forensicCase.bundleURL) {
            // The manifest may have changed while waiting for another writer.
            let current = try CaseStore.open(at: forensicCase.bundleURL)
            try validateScope(result, evidenceID: evidenceID, forensicCase: current)
            let directory = try cacheDescriptor(in: current.bundleURL, create: true)
            defer { Darwin.close(directory) }
            let name = evidenceID.uuidString.lowercased() + ".json"
            try rejectNonRegular(name, directory: directory)
            let staging = ".\(UUID().uuidString).tmp"
            let descriptor = Darwin.openat(directory, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard descriptor >= 0 else { throw FileAccess.posixError("Cannot create filesystem cache") }
            defer {
                Darwin.close(descriptor)
                _ = Darwin.unlinkat(directory, staging, 0)
            }
            try data.withUnsafeBytes { bytes in
                var written = 0
                while written < bytes.count {
                    let count = Darwin.write(descriptor, bytes.baseAddress?.advanced(by: written), bytes.count - written)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw FileAccess.posixError("Cannot write filesystem cache") }
                    written += count
                }
            }
            guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot synchronize filesystem cache") }
            try rejectNonRegular(name, directory: directory)
            guard Darwin.renameat(directory, staging, directory, name) == 0 else { throw FileAccess.posixError("Cannot publish filesystem cache") }
            guard Darwin.fsync(directory) == 0 else { throw FileAccess.posixError("Cannot synchronize filesystem cache directory") }
        }
    }

    public static func load(evidenceID: UUID, in caseURL: URL) throws -> EnumerationResult? {
        let forensicCase = try CaseStore.open(at: caseURL)
        guard forensicCase.manifest.evidence.contains(where: { $0.id == evidenceID }) else {
            throw EngineError.invalidCache("The evidence identifier does not belong to this case.")
        }
        let directory = try cacheDescriptor(in: forensicCase.bundleURL, create: false)
        guard directory >= 0 else { return nil }
        defer { Darwin.close(directory) }
        let descriptor = Darwin.openat(directory, evidenceID.uuidString.lowercased() + ".json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw EngineError.invalidCache("The filesystem cache must be a readable regular file.")
        }
        defer { Darwin.close(descriptor) }
        let before = try FileAccess.identity(of: descriptor)
        guard before.size <= EngineValidation.resultLimit else { throw EngineError.limitExceeded("The filesystem cache exceeds 64 MiB.") }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(data.count) < before.size {
            let requested = Int(min(Int64(buffer.count), before.size - Int64(data.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: requested) }
            guard count > 0 else { throw EngineError.invalidCache("The filesystem cache changed while being read.") }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard try FileAccess.identity(of: descriptor) == before else { throw EngineError.invalidCache("The filesystem cache changed while being read.") }
        let result: EnumerationResult
        do { result = try decoder().decode(EnumerationResult.self, from: data) }
        catch { throw EngineError.invalidCache("The filesystem cache is malformed or uses an unsupported schema.") }
        try EngineValidation.result(result)
        try validateScope(result, evidenceID: evidenceID, forensicCase: forensicCase)
        return result
    }

    private static func validateScope(_ result: EnumerationResult, evidenceID: UUID, forensicCase: ForensicCase) throws {
        guard let evidence = forensicCase.manifest.evidence.first(where: { $0.id == evidenceID }),
              result.sourcePaths.contains(evidence.sourcePath), result.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
              result.sourcePaths.allSatisfy({ !FileAccess.isInside(URL(fileURLWithPath: $0), directory: forensicCase.bundleURL) }) else {
            throw EngineError.invalidCache("The filesystem result does not match this evidence record and its selected-file SHA-256.")
        }
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private static func withCaseLock(_ bundle: URL, body: () throws -> Void) throws {
        let descriptor = Darwin.open(bundle.appendingPathComponent(".case.lock").path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw EngineError.invalidCache("The case lock is inaccessible.") }
        defer { Darwin.close(descriptor) }
        _ = try FileAccess.identity(of: descriptor)
        while engineSystemFlock(descriptor, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            throw FileAccess.posixError("Cannot lock filesystem cache")
        }
        defer { _ = engineSystemFlock(descriptor, LOCK_UN) }
        try body()
    }

    private static func cacheDescriptor(in bundle: URL, create: Bool) throws -> Int32 {
        let root = Darwin.open(bundle.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw EngineError.invalidCache("The case directory is inaccessible.") }
        defer { Darwin.close(root) }
        if create && Darwin.mkdirat(root, "filesystem", mode_t(0o700)) != 0 && errno != EEXIST {
            throw FileAccess.posixError("Cannot create filesystem cache directory")
        }
        let descriptor = Darwin.openat(root, "filesystem", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if !create && errno == ENOENT { return -1 }
            throw EngineError.invalidCache("The filesystem cache directory must not be a symbolic link.")
        }
        return descriptor
    }

    private static func rejectNonRegular(_ name: String, directory: Int32) throws {
        var metadata = stat()
        if Darwin.fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 {
            guard metadata.st_mode & S_IFMT == S_IFREG else { throw EngineError.invalidCache("The filesystem cache destination must be a regular file.") }
        } else if errno != ENOENT { throw FileAccess.posixError("Cannot inspect filesystem cache destination") }
    }
}
