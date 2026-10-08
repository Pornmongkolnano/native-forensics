import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func filesystemCacheReadFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

enum EngineFilesystemCacheReadCheckpoint: Sendable, Equatable {
    case waitingForCaseLock, didReadManifest, didReadCache, didReadArtifact, beforeReturn
}

/// Historical metadata only. A legacy timestamp can come from the verified
/// latest immutable job whose complete legacy projection equals this cache.
/// No evidence source, output destination or credential is opened here.
enum EngineFilesystemCacheReader {
    static func load(evidenceID: UUID, in caseURL: URL,
        checkpoint: ((EngineFilesystemCacheReadCheckpoint) throws -> Void)? = nil) throws -> EnumerationResult? {
        try Task.checkCancellation()
        let context = try ReadContext(caseURL: caseURL, checkpoint: checkpoint)
        try context.acquireLock()
        let manifestFile = try context.file("manifest.json", parent: context.root,
            maximumBytes: 16 * 1_048_576, optional: false)
        guard let manifestFile else { throw changed() }
        let manifest: CaseManifest
        do {
            let bytes = try context.read(manifestFile).data
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            manifest = try decoder.decode(CaseManifest.self, from: bytes)
        } catch is CancellationError { throw CancellationError() }
        catch { throw EngineError.invalidCache("The pinned case manifest could not be read or decoded.") }
        try context.reached(.didReadManifest)
        // CaseStore also validates the migration backup and full manifest
        // contract. Compare its value with the manifest read through our held
        // descriptor, then keep both namespace and file fences to the return.
        let forensicCase = try CaseStore.open(at: context.bundle)
        guard forensicCase.manifest == manifest else { throw changed() }
        try context.validate()
        guard let evidence = manifest.evidence.first(where: { $0.id == evidenceID }) else {
            throw EngineError.invalidCache("The evidence identifier does not belong to this case.")
        }
        guard let directory = try context.directory("filesystem", parent: context.root, optional: true),
              let cache = try context.file(evidenceID.uuidString.lowercased() + ".json", parent: directory,
                  maximumBytes: Int64(EngineValidation.resultLimit), optional: true) else {
            try context.finish(); return nil
        }
        let cacheData = try context.read(cache).data
        try context.reached(.didReadCache)
        let decoded: EngineFilesystemCacheCoding.DecodeReceipt
        do { decoded = try EngineFilesystemCacheCoding.decodeWithReceipt(cacheData) }
        catch { throw EngineError.invalidCache("The filesystem cache is malformed or uses an unsupported schema.") }
        try Task.checkCancellation()
        try EngineValidation.result(decoded.result)
        try EngineResultStore.validateScope(decoded.result, evidenceID: evidenceID, forensicCase: forensicCase)
        var result = decoded.result
        if !decoded.containsExactReferenceDate,
           let restored = try restoredLegacyResult(cacheData: cacheData, evidence: evidence,
                forensicCase: forensicCase, context: context) {
            result = restored
        }
        try context.finish()
        return result
    }

    private static func restoredLegacyResult(cacheData: Data, evidence: EvidenceRecord,
        forensicCase: ForensicCase, context: ReadContext) throws -> EnumerationResult? {
        // Append order is the writer's latest-job contract. Never search older
        // jobs for a matching projection after a newer job failed this proof.
        guard let job = forensicCase.manifest.provenance?.jobs.last(where: {
            $0.evidenceID == evidence.id && $0.kind == "filesystem.enumeration"
        }), let declaredCount = job.artifactByteCount,
              (0...Int(EngineValidation.resultLimit)).contains(declaredCount),
              let declaredHash = job.artifactSHA256,
              job.artifactRelativePath == "filesystem-jobs/" + job.id.uuidString.lowercased() + ".json" else { return nil }
        guard let directory = try context.directory("filesystem-jobs", parent: context.root, optional: true),
              let artifact = try context.file(job.id.uuidString.lowercased() + ".json", parent: directory,
                  maximumBytes: nil, optional: true) else { return nil }
        // Stat-only count mismatches are insufficient proof, including an
        // oversized artifact. No artifact bytes are read unless the complete
        // declared count already passed the existing 64 MiB limit above.
        guard artifact.identity.size == declaredCount else { return nil }
        // The raw artifact Data lives only in this function call. Its count,
        // full digest, decoded result and full reconstructed job are accepted
        // before returning the result, releasing raw bytes before encoding.
        guard let candidate = try verifiedArtifact(artifact, job: job, evidence: evidence,
            forensicCase: forensicCase, declaredHash: declaredHash, context: context) else { return nil }
        try Task.checkCancellation()
        let legacyData: Data
        do {
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            legacyData = try encoder.encode(candidate)
        } catch { return nil }
        guard legacyData.count <= EngineValidation.resultLimit else { return nil }
        return try sameBytes(cacheData, legacyData) ? candidate : nil
    }

    private static func verifiedArtifact(_ artifact: HeldFile, job: CaseJobProvenance,
        evidence: EvidenceRecord, forensicCase: ForensicCase, declaredHash: String,
        context: ReadContext) throws -> EnumerationResult? {
        let read = try context.read(artifact, digest: true)
        try context.reached(.didReadArtifact)
        guard read.sha256 == declaredHash, read.data.count == job.artifactByteCount else { return nil }
        do {
            let result = try CaseWorkCoding.decode(EnumerationResult.self, read.data)
            try Task.checkCancellation(); try EngineValidation.result(result)
            try EngineResultStore.validateScope(result, evidenceID: evidence.id, forensicCase: forensicCase)
            guard result.sourceIdentities.first(where: { $0.path == evidence.sourcePath })
                .map({ $0.size == evidence.byteCount }) ?? true else { return nil }
            let expected = try CaseJobProvenance.enumeration(id: job.id, evidence: evidence, result: result,
                startedAt: job.startedAt, executableSHA256: job.component.executableSHA256,
                artifactRelativePath: job.artifactRelativePath, artifactSHA256: read.sha256,
                artifactByteCount: read.data.count)
            return expected == job ? result : nil
        } catch is CancellationError { throw CancellationError() }
        catch { return nil }
    }

    private static func sameBytes(_ left: Data, _ right: Data) throws -> Bool {
        guard left.count == right.count else { return false }
        if left.isEmpty { return true }
        return try left.withUnsafeBytes { lhs in
            try right.withUnsafeBytes { rhs in
                var offset = 0
                while offset < left.count {
                    try Task.checkCancellation()
                    let count = min(65_536, left.count - offset)
                    guard memcmp(lhs.baseAddress!.advanced(by: offset), rhs.baseAddress!.advanced(by: offset), count) == 0 else { return false }
                    offset += count
                }
                return true
            }
        }
    }

    private static func changed() -> EngineError {
        .invalidCache("The case or filesystem metadata namespace changed during the read.")
    }

    private struct HeldFile {
        let descriptor: Int32
        let parent: Int32
        let name: String
        let identity: SourceIdentity
    }
    private struct HeldDirectory {
        let descriptor: Int32
        let parent: Int32
        let name: String
    }
    private struct MissingReference {
        let parent: Int32
        let name: String
    }

    private final class ReadContext {
        let bundle: URL
        let root: Int32
        let checkpoint: ((EngineFilesystemCacheReadCheckpoint) throws -> Void)?
        private var files: [HeldFile] = []
        private var directories: [HeldDirectory] = []
        private var missing: [MissingReference] = []
        private var lock: Int32?
        private var ownsLock = false

        init(caseURL: URL, checkpoint: ((EngineFilesystemCacheReadCheckpoint) throws -> Void)?) throws {
            let supplied = caseURL.standardizedFileURL
            bundle = supplied
            self.checkpoint = checkpoint
            root = try EvidenceViewFiles.openDirectory(supplied)
        }
        deinit {
            if ownsLock, let lock { _ = filesystemCacheReadFlock(lock, LOCK_UN) }
            for file in files.reversed() { Darwin.close(file.descriptor) }
            for directory in directories.reversed() { Darwin.close(directory.descriptor) }
            Darwin.close(root)
        }

        func acquireLock() throws {
            guard let held = try file(".case.lock", parent: root, maximumBytes: nil, optional: false) else { throw changed() }
            lock = held.descriptor
            while filesystemCacheReadFlock(held.descriptor, LOCK_SH | LOCK_NB) != 0 {
                if errno == EINTR { try Task.checkCancellation(); continue }
                guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock filesystem cache reader") }
                try reached(.waitingForCaseLock)
                usleep(10_000)
            }
            ownsLock = true
            try validate()
        }

        func directory(_ name: String, parent: Int32, optional: Bool) throws -> Int32? {
            try Task.checkCancellation(); try validate()
            let descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else {
                if optional && errno == ENOENT { missing.append(.init(parent: parent, name: name)); return nil }
                throw FileAccess.posixError("Cannot open pinned filesystem metadata directory")
            }
            directories.append(.init(descriptor: descriptor, parent: parent, name: name))
            try validate()
            return descriptor
        }

        func file(_ name: String, parent: Int32, maximumBytes: Int64?, optional: Bool) throws -> HeldFile? {
            try Task.checkCancellation(); try validate()
            let descriptor = Darwin.openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard descriptor >= 0 else {
                if optional && errno == ENOENT { missing.append(.init(parent: parent, name: name)); return nil }
                throw FileAccess.posixError("Cannot open pinned filesystem metadata file")
            }
            do {
                var metadata = stat()
                guard Darwin.fstat(descriptor, &metadata) == 0 else { throw FileAccess.posixError("Cannot inspect filesystem metadata") }
                guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_nlink == 1, metadata.st_size >= 0 else { throw changed() }
                if let maximumBytes, metadata.st_size > maximumBytes {
                    throw EngineError.limitExceeded("The filesystem metadata record exceeds its bounded read limit.")
                }
                let held = HeldFile(descriptor: descriptor, parent: parent, name: name, identity: SourceIdentity(metadata))
                try validateFile(held)
                files.append(held)
                return held
            } catch { Darwin.close(descriptor); throw error }
        }

        func read(_ file: HeldFile, digest: Bool = false) throws -> (data: Data, sha256: String?) {
            try Task.checkCancellation(); try validate()
            var bytes = Data(); bytes.reserveCapacity(Int(file.identity.size))
            var buffer = [UInt8](repeating: 0, count: 65_536), hash = SHA256()
            while Int64(bytes.count) < file.identity.size {
                try Task.checkCancellation()
                let requested = Int(min(Int64(buffer.count), file.identity.size - Int64(bytes.count)))
                let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(file.descriptor, into: $0, count: requested) }
                guard count > 0 else { throw changed() }
                bytes.append(contentsOf: buffer.prefix(count))
                if digest { hash.update(data: Data(buffer.prefix(count))) }
            }
            try validate(); try Task.checkCancellation()
            return (bytes, digest ? CaseWorkCoding.hex(hash.finalize()) : nil)
        }

        func reached(_ point: EngineFilesystemCacheReadCheckpoint) throws {
            try checkpoint?(point)
            try Task.checkCancellation(); try validate()
        }
        func finish() throws { try reached(.beforeReturn) }

        func validate() throws {
            try Task.checkCancellation()
            try EvidenceViewFiles.validateDirectory(bundle, descriptor: root)
            for directory in directories {
                var opened = stat(), named = stat()
                guard Darwin.fstat(directory.descriptor, &opened) == 0,
                      Darwin.fstatat(directory.parent, directory.name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                      named.st_mode & S_IFMT == S_IFDIR,
                      opened.st_dev == named.st_dev, opened.st_ino == named.st_ino else { throw changed() }
            }
            for file in files { try validateFile(file) }
            for value in missing {
                var named = stat()
                guard Darwin.fstatat(value.parent, value.name, &named, AT_SYMLINK_NOFOLLOW) != 0,
                      errno == ENOENT else { throw changed() }
            }
        }

        private func validateFile(_ file: HeldFile) throws {
            var opened = stat(), named = stat()
            guard Darwin.fstat(file.descriptor, &opened) == 0,
                  Darwin.fstatat(file.parent, file.name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  opened.st_mode & S_IFMT == S_IFREG, named.st_mode & S_IFMT == S_IFREG,
                  opened.st_nlink == 1, named.st_nlink == 1,
                  SourceIdentity(opened) == file.identity, SourceIdentity(named) == file.identity else { throw changed() }
        }
    }
}
