import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func engineJobFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

extension EngineResultStore {
    /// Schema 2 only. Saves an immutable exact listing and reconstructible job
    /// receipt before updating the independent latest-listing convenience cache.
    /// No evidence bytes are opened or modified; this is historical persistence,
    /// not a new claim of fresh source verification.
    public static func saveWithJobProvenance(result: EnumerationResult, evidenceID: UUID,
        in caseURL: URL, jobID: UUID = UUID(), startedAt: Date,
        executableSHA256: String? = nil) throws -> EngineJobSaveReceipt {
        try saveJob(result: result, evidenceID: evidenceID, in: caseURL, jobID: jobID,
            startedAt: startedAt, executableSHA256: executableSHA256,
            manifestCheckpoint: { _, _ in }, checkpoint: { _, _ in })
    }

    static func saveWithJobProvenanceForTesting(result: EnumerationResult, evidenceID: UUID,
        in caseURL: URL, jobID: UUID, startedAt: Date, executableSHA256: String? = nil,
        manifestCheckpoint: (CasePersistenceCheckpoint, Int) throws -> Void = { _, _ in },
        checkpoint: (EngineJobSaveCheckpoint, Int) throws -> Void) throws -> EngineJobSaveReceipt {
        try saveJob(result: result, evidenceID: evidenceID, in: caseURL, jobID: jobID,
            startedAt: startedAt, executableSHA256: executableSHA256,
            manifestCheckpoint: manifestCheckpoint, checkpoint: checkpoint)
    }

    private static func saveJob(result: EnumerationResult, evidenceID: UUID, in caseURL: URL,
        jobID: UUID, startedAt: Date, executableSHA256: String?,
        manifestCheckpoint: (CasePersistenceCheckpoint, Int) throws -> Void,
        checkpoint: (EngineJobSaveCheckpoint, Int) throws -> Void) throws -> EngineJobSaveReceipt {
        try EngineValidation.result(result)
        let artifactData = try CaseWorkCoding.encode(result)
        guard artifactData.count <= EngineValidation.resultLimit else { throw EngineError.limitExceeded("The immutable filesystem listing exceeds 64 MiB.") }
        let artifactSHA = jobDigest(artifactData)
        let artifactPath = "filesystem-jobs/" + jobID.uuidString.lowercased() + ".json"
        let cacheData = try EngineFilesystemCacheCoding.encode(result)
        guard cacheData.count <= EngineValidation.resultLimit else { throw EngineError.limitExceeded("The filesystem cache exceeds 64 MiB.") }
        let root = try EvidenceViewFiles.openDirectory(caseURL)
        defer { Darwin.close(root) }
        let bundle = try FileAccess.localURL(caseURL)
        try EvidenceViewFiles.validateDirectory(bundle, descriptor: root)
        let lock = try FileAccess.openReadOnly(".case.lock", in: root)
        defer { Darwin.close(lock) }
        let lockIdentity = try FileAccess.identity(of: lock)
        var lockMetadata = stat()
        guard Darwin.fstat(lock, &lockMetadata) == 0, lockMetadata.st_nlink == 1 else { throw EngineError.invalidCache("The case writer lock is unsafe.") }
        while engineJobFlock(lock, LOCK_EX | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock filesystem job store") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = engineJobFlock(lock, LOCK_UN) }
        // Read only after holding the writer lock: a read before the lock can
        // race a valid atomic manifest replacement and reject an exact retry.
        try EvidenceViewFiles.validateDirectory(bundle, descriptor: root)
        var current = try CaseStore.open(at: bundle)
        guard current.manifest.schemaVersion == 2 else { throw CaseProvenanceError.migrationRequired }
        guard let evidence = current.manifest.evidence.first(where: { $0.id == evidenceID }) else { throw EngineError.invalidCache("The selected evidence does not belong to this case.") }
        try validateJobScope(result, evidence: evidence, bundle: current.bundleURL)
        var job = try CaseJobProvenance.enumeration(id: jobID, evidence: evidence, result: result,
            startedAt: startedAt, executableSHA256: executableSHA256,
            artifactRelativePath: artifactPath, artifactSHA256: artifactSHA, artifactByteCount: artifactData.count)
        var manifestIdentity = try FileAccess.identity(at: "manifest.json", in: root)
        func validateLocked() throws {
            try EvidenceViewFiles.validateDirectory(bundle, descriptor: root)
            guard (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity,
                  (try? FileAccess.identity(at: "manifest.json", in: root)) == manifestIdentity else {
                throw EngineError.invalidCache("The case manifest or writer lock changed during job persistence.")
            }
        }
        try validateLocked()
        let artifacts = try jobDirectory("filesystem-jobs", root: root)
        defer { Darwin.close(artifacts) }
        let cache = try jobDirectory("filesystem", root: root)
        defer { Darwin.close(cache) }
        try syncJobDescriptor(root)
        func validateDirectories() throws {
            try validateLocked()
            guard jobReference("filesystem-jobs", parent: root, descriptor: artifacts, kind: S_IFDIR),
                  jobReference("filesystem", parent: root, descriptor: cache, kind: S_IFDIR) else {
                throw EngineError.invalidCache("A filesystem job directory changed during persistence.")
            }
        }
        let artifactName = jobID.uuidString.lowercased() + ".json"
        let cacheName = evidenceID.uuidString.lowercased() + ".json"
        let recorded = current.manifest.provenance?.jobs.first { $0.id == jobID }
        if recorded?.artifactByteCount == nil, recorded != nil { job = job.preservingUnknownArtifactSize() }
        if let recorded, recorded != job { throw EngineJobSaveError.jobConflict }
        var artifactState: EngineJobCommitState = .notCommitted
        var manifestState: EngineJobCommitState = recorded == nil ? .notCommitted : .confirmed
        var cacheState: EngineJobCommitState = .notCommitted
        var didPublish = false
        var latestCacheUpdated = false
        do {
            if try jobExists(artifactName, directory: artifacts) {
                guard try readJobBytes(artifactName, directory: artifacts) == artifactData else { throw EngineJobSaveError.jobConflict }
                try confirmExistingJobBytes(artifactData, name: artifactName, directory: artifacts, validate: validateDirectories)
                artifactState = .confirmed
            } else {
                guard recorded == nil else { throw EngineJobSaveError.artifactUnavailable }
                try publishJobBytes(artifactData, name: artifactName, directory: artifacts, exclusive: true,
                    role: .artifact, checkpoint: checkpoint, committed: { artifactState = .uncertain; didPublish = true }, validate: validateDirectories)
                artifactState = .confirmed
            }
            if recorded == nil {
                try checkpoint(.beforeManifestRecord, artifactData.count)
                do {
                    current = try CaseStore.recordingWhileLocked(job: job, in: current, root: root,
                        persistenceCheckpoint: manifestCheckpoint, validateBeforeCommit: validateDirectories)
                    manifestState = .confirmed; didPublish = true
                } catch let error as CaseManifestPublicationError {
                    manifestState = .uncertain; didPublish = true
                    throw error
                }
                manifestIdentity = try FileAccess.identity(at: "manifest.json", in: root)
                guard try CaseStore.open(at: current.bundleURL).manifest == current.manifest else { throw EngineError.invalidCache("The committed job manifest changed before its cache update.") }
                try checkpoint(.afterManifestRecord, artifactData.count)
            }
            // A retry of an older historical UUID never rolls the latest cache
            // back over a newer immutable job for the same evidence.
            let latestJobID = current.manifest.provenance?.jobs.last(where: { $0.evidenceID == evidenceID && $0.kind == "filesystem.enumeration" })?.id
            if latestJobID == jobID {
                if try jobExists(cacheName, directory: cache), try readJobBytes(cacheName, directory: cache) == cacheData {
                    try confirmExistingJobBytes(cacheData, name: cacheName, directory: cache, validate: validateDirectories)
                    cacheState = .confirmed
                } else {
                    try publishJobBytes(cacheData, name: cacheName, directory: cache, exclusive: false,
                        role: .latest, checkpoint: checkpoint, committed: { cacheState = .uncertain; didPublish = true }, validate: validateDirectories)
                    cacheState = .confirmed; latestCacheUpdated = true
                }
            }
            try checkpoint(.complete, artifactData.count)
            try validateDirectories()
        } catch {
            if artifactState != .notCommitted || manifestState != .notCommitted || cacheState != .notCommitted {
                if !didPublish, let typed = error as? EngineJobSaveError,
                    typed == .jobConflict || typed == .artifactUnavailable { throw typed }
                throw EngineJobSaveError.publishedButIncomplete(jobID: jobID, artifactSHA256: artifactSHA,
                    artifactState: artifactState, manifestState: manifestState, latestCacheState: cacheState)
            }
            throw error
        }
        return EngineJobSaveReceipt(forensicCase: current, job: job, artifactRelativePath: artifactPath,
            artifactSHA256: artifactSHA, artifactByteCount: artifactData.count,
            wasAlreadyRecorded: recorded != nil, latestCacheUpdated: latestCacheUpdated)
    }

    private enum JobRole: Equatable { case artifact, latest }
    private static func publishJobBytes(_ bytes: Data, name: String, directory: Int32, exclusive: Bool,
        role: JobRole, checkpoint: (EngineJobSaveCheckpoint, Int) throws -> Void,
        committed: () -> Void, validate: () throws -> Void) throws {
        try Task.checkCancellation()
        let staging = ".filesystem-job-\(UUID().uuidString.lowercased()).tmp"
        let descriptor = Darwin.openat(directory, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot stage filesystem job bytes") }
        defer {
            if jobReference(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) { _ = Darwin.unlinkat(directory, staging, 0) }
            Darwin.close(descriptor)
        }
        try checkpoint(role == .artifact ? .beforeArtifactWrite : .beforeLatestWrite, 0)
        try bytes.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                try Task.checkCancellation()
                let count = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: written), min(65_536, buffer.count - written))
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write filesystem job bytes") }
                written += count
                try checkpoint(role == .artifact ? .afterArtifactWriteChunk : .afterLatestWriteChunk, written)
            }
        }
        try checkpoint(role == .artifact ? .beforeArtifactFileFlush : .beforeLatestFileFlush, bytes.count)
        try syncJobDescriptor(descriptor)
        try checkpoint(role == .artifact ? .afterArtifactFileFlush : .afterLatestFileFlush, bytes.count)
        try Task.checkCancellation(); try validate()
        try checkpoint(role == .artifact ? .beforeArtifactRename : .beforeLatestRename, bytes.count)
        try Task.checkCancellation(); try validate()
        guard jobReference(staging, parent: directory, descriptor: descriptor, kind: S_IFREG) else { throw EngineError.invalidCache("The staged filesystem job changed.") }
        if exclusive {
            guard Darwin.renameatx_np(directory, staging, directory, name, UInt32(RENAME_EXCL)) == 0 else {
                if errno == EEXIST { throw EngineJobSaveError.jobConflict }
                throw FileAccess.posixError("Cannot publish immutable filesystem job")
            }
        } else {
            if try jobExists(name, directory: directory) { _ = try safeJobIdentity(name, directory: directory) }
            guard Darwin.renameat(directory, staging, directory, name) == 0 else { throw FileAccess.posixError("Cannot publish latest filesystem cache") }
        }
        committed()
        // Do not honor cancellation after a commit as an uncommitted save.
        try checkpoint(role == .artifact ? .afterArtifactRename : .afterLatestRename, bytes.count)
        try checkpoint(role == .artifact ? .beforeArtifactDirectoryFlush : .beforeLatestDirectoryFlush, bytes.count)
        try syncJobDescriptor(directory)
        try checkpoint(role == .artifact ? .afterArtifactDirectoryFlush : .afterLatestDirectoryFlush, bytes.count)
        guard jobReference(name, parent: directory, descriptor: descriptor, kind: S_IFREG),
              try readJobBytes(name, directory: directory, checkCancellation: false) == bytes else {
            throw EngineError.invalidCache("Published filesystem job bytes or identity changed.")
        }
        try validate()
    }

    private static func jobDirectory(_ name: String, root: Int32) throws -> Int32 {
        if Darwin.mkdirat(root, name, mode_t(0o700)) != 0 && errno != EEXIST { throw FileAccess.posixError("Cannot create filesystem job directory") }
        let descriptor = Darwin.openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw EngineError.invalidCache("A filesystem job directory is unsafe.") }
        guard jobReference(name, parent: root, descriptor: descriptor, kind: S_IFDIR) else { Darwin.close(descriptor); throw EngineError.invalidCache("A filesystem job directory changed.") }
        return descriptor
    }
    private static func jobExists(_ name: String, directory: Int32) throws -> Bool {
        var value = stat()
        if Darwin.fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        if errno == ENOENT { return false }
        throw FileAccess.posixError("Cannot inspect filesystem job path")
    }
    private static func safeJobIdentity(_ name: String, directory: Int32) throws -> SourceIdentity {
        var value = stat()
        guard Darwin.fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) == 0,
              value.st_mode & S_IFMT == S_IFREG, value.st_nlink == 1, value.st_size >= 0,
              value.st_size <= EngineValidation.resultLimit else { throw EngineJobSaveError.artifactUnavailable }
        return SourceIdentity(value)
    }
    private static func readJobBytes(_ name: String, directory: Int32, checkCancellation: Bool = true) throws -> Data {
        let before = try safeJobIdentity(name, directory: directory)
        let descriptor = try FileAccess.openReadOnly(name, in: directory)
        defer { Darwin.close(descriptor) }
        guard try FileAccess.identity(of: descriptor) == before else { throw EngineJobSaveError.artifactUnavailable }
        var bytes = Data(); bytes.reserveCapacity(Int(before.size))
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < before.size {
            if checkCancellation { try Task.checkCancellation() }
            let amount = Int(min(Int64(buffer.count), before.size - Int64(bytes.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: amount) }
            guard count > 0 else { throw EngineJobSaveError.artifactUnavailable }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        guard try FileAccess.identity(of: descriptor) == before,
              (try? FileAccess.identity(at: name, in: directory)) == before else { throw EngineJobSaveError.artifactUnavailable }
        return bytes
    }
    /// A matching orphan/retry may have stopped after its previous rename and
    /// before directory flush. Matching bytes alone cannot confirm durability.
    /// Re-flush the exact held file and namespace without replacing its bytes.
    private static func confirmExistingJobBytes(_ bytes: Data, name: String, directory: Int32,
        validate: () throws -> Void) throws {
        let expected = try safeJobIdentity(name, directory: directory)
        let descriptor = try FileAccess.openReadOnly(name, in: directory)
        defer { Darwin.close(descriptor) }
        guard try FileAccess.identity(of: descriptor) == expected else { throw EngineJobSaveError.artifactUnavailable }
        try syncJobDescriptor(descriptor)
        try syncJobDescriptor(directory)
        try validate()
        guard try FileAccess.identity(of: descriptor) == expected,
              (try? FileAccess.identity(at: name, in: directory)) == expected,
              try readJobBytes(name, directory: directory) == bytes else { throw EngineJobSaveError.artifactUnavailable }
    }
    private static func jobReference(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var current = stat(), opened = stat()
        return Darwin.fstat(descriptor, &opened) == 0 && Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0
            && current.st_mode & S_IFMT == kind && current.st_dev == opened.st_dev && current.st_ino == opened.st_ino
    }
    private static func syncJobDescriptor(_ descriptor: Int32) throws {
        while Darwin.fsync(descriptor) != 0 {
            if errno == EINTR { continue }
            throw FileAccess.posixError("Cannot synchronize filesystem job storage")
        }
    }
    private static func validateJobScope(_ result: EnumerationResult, evidence: EvidenceRecord, bundle: URL) throws {
        guard result.sourcePaths.contains(evidence.sourcePath), result.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
              result.sourceIdentities.first(where: { $0.path == evidence.sourcePath }).map({ $0.size == evidence.byteCount }) ?? true,
              result.sourcePaths.allSatisfy({ !FileAccess.isInside(URL(fileURLWithPath: $0), directory: bundle) }) else {
            throw EngineError.invalidCache("The filesystem job does not match this evidence's recorded selected-file scope.")
        }
    }
    private static func jobDigest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
