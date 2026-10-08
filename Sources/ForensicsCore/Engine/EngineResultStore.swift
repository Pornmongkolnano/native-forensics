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
        let data = try EngineFilesystemCacheCoding.encode(result)
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

    /// Reads historical metadata under a cancellable shared case lock. Call
    /// outside an already-held writer transaction; no source is reverified.
    public static func load(evidenceID: UUID, in caseURL: URL) throws -> EnumerationResult? {
        try EngineFilesystemCacheReader.load(evidenceID: evidenceID, in: caseURL)
    }

    static func loadForTesting(evidenceID: UUID, in caseURL: URL,
        checkpoint: @escaping (EngineFilesystemCacheReadCheckpoint) throws -> Void) throws -> EnumerationResult? {
        try EngineFilesystemCacheReader.load(evidenceID: evidenceID, in: caseURL, checkpoint: checkpoint)
    }

    static func validateScope(_ result: EnumerationResult, evidenceID: UUID, forensicCase: ForensicCase) throws {
        guard let evidence = forensicCase.manifest.evidence.first(where: { $0.id == evidenceID }),
              result.sourcePaths.contains(evidence.sourcePath), result.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
              result.sourcePaths.allSatisfy({ !FileAccess.isInside(URL(fileURLWithPath: $0), directory: forensicCase.bundleURL) }) else {
            throw EngineError.invalidCache("The filesystem result does not match this evidence record and its selected-file SHA-256.")
        }
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
