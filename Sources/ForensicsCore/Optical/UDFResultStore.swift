import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func opticalFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// UDF history is separate from TSK filesystem enumeration and signature
/// carving. Every generation is immutable and bound to a case/source receipt.
public enum UDFResultStore {
    private static let maximumResultBytes: Int64 = 32 * 1_048_576
    private static let maximumPointerBytes: Int64 = 4_096

    /// Source validation belongs to the live inspector and runs immediately
    /// before publication, after lock waiting and synchronized metadata writes.
    /// Checksums detect changed records, rather than authenticating an examiner.
    @discardableResult
    public static func save(_ result: UDFInspectionResult, in forensicCase: ForensicCase,
        prePublicationValidation: @escaping @Sendable () throws -> Void = {}) throws -> UDFInspectionResult {
        try validateResult(result)
        let bytes = try encode(result, maximum: maximumResultBytes)
        let pointer = GenerationPointer(schemaVersion: 1, caseID: result.caseID,
            evidenceID: result.sourceEvidenceID, jobID: result.jobID, resultSHA256: hash(bytes))
        let pointerBytes = try encode(pointer, maximum: maximumPointerBytes)
        let deadline = ProcessInfo.processInfo.systemUptime + result.options.timeoutSeconds
        return try withCase(forensicCase, write: true, deadline: deadline) { root, manifest, validateCase in
            _ = try binding(result, manifest: manifest)
            let saved = try withEvidence(result.sourceEvidenceID, root: root, create: true,
                validateCase: validateCase) { evidence, generations, validate in
                // A malformed current pointer is a storage error, never a reason
                // to silently replace the user's previous forensic result.
                let previous = try readPointer(in: evidence)
                if let previous {
                    try validatePointer(previous.value, caseID: result.caseID, evidenceID: result.sourceEvidenceID)
                    _ = try readGeneration(previous.value, generations: generations, manifest: manifest)
                }
                let stagingName = ".udf-\(UUID().uuidString.lowercased()).tmp"
                guard Darwin.mkdirat(generations, stagingName, mode_t(0o700)) == 0 else {
                    throw FileAccess.posixError("Cannot create optical generation")
                }
                let staging = try directory(stagingName, parent: generations, create: false)
                guard staging >= 0 else { throw UDFError.invalidResult("The generation staging directory disappeared.") }
                defer { Darwin.close(staging) }
                var currentName = stagingName
                var resultIdentity: SourceIdentity?, checksumIdentity: SourceIdentity?
                var latestName: String?, latestIdentity: SourceIdentity?
                var committed = false
                defer {
                    if !committed {
                        if let resultIdentity { removeOwned("result.json", parent: staging, identity: resultIdentity) }
                        if let checksumIdentity { removeOwned("checksum.json", parent: staging, identity: checksumIdentity) }
                        if let latestName, let latestIdentity { removeOwned(latestName, parent: evidence, identity: latestIdentity) }
                        if referenceMatches(currentName, parent: generations, descriptor: staging, kind: S_IFDIR) {
                            _ = Darwin.unlinkat(generations, currentName, AT_REMOVEDIR)
                        }
                    }
                }
                resultIdentity = try writeNewFile(bytes, named: "result.json", in: staging)
                checksumIdentity = try writeNewFile(pointerBytes, named: "checksum.json", in: staging)
                guard Darwin.fsync(staging) == 0 else { throw FileAccess.posixError("Cannot flush optical generation") }
                try Task.checkCancellation(); try validate()
                try validateReference(stagingName, parent: generations, descriptor: staging, kind: S_IFDIR)
                guard (try? FileAccess.identity(at: "result.json", in: staging)) == resultIdentity,
                      (try? FileAccess.identity(at: "checksum.json", in: staging)) == checksumIdentity else {
                    throw UDFError.invalidResult("The synchronized optical metadata changed.")
                }
                let publishedName = name(result.jobID)
                guard Darwin.renameatx_np(generations, stagingName, generations, publishedName, UInt32(RENAME_EXCL)) == 0 else {
                    throw FileAccess.posixError("Cannot publish an immutable optical generation")
                }
                currentName = publishedName
                guard Darwin.fsync(generations) == 0 else { throw FileAccess.posixError("Cannot flush optical generations") }
                latestName = ".latest-\(UUID().uuidString.lowercased()).tmp"
                latestIdentity = try writeNewFile(pointerBytes, named: latestName!, in: evidence)
                try Task.checkCancellation(); try prePublicationValidation(); try validate()
                try validateReference(currentName, parent: generations, descriptor: staging, kind: S_IFDIR)
                guard (try? FileAccess.identity(at: "result.json", in: staging)) == resultIdentity,
                      (try? FileAccess.identity(at: "checksum.json", in: staging)) == checksumIdentity,
                      (try? FileAccess.identity(at: latestName!, in: evidence)) == latestIdentity else {
                    throw UDFError.invalidResult("The optical generation changed before publication.")
                }
                if let previous {
                    guard (try? FileAccess.identity(at: "latest.json", in: evidence)) == previous.identity else {
                        throw UDFError.invalidResult("The previous optical pointer changed during the transaction.")
                    }
                } else {
                    var unexpected = stat()
                    guard Darwin.fstatat(evidence, "latest.json", &unexpected, AT_SYMLINK_NOFOLLOW) != 0,
                          errno == ENOENT else { throw UDFError.invalidResult("An optical pointer appeared during the transaction.") }
                }
                try Task.checkCancellation()
                let flags: UInt32 = previous == nil ? UInt32(RENAME_EXCL) : 0
                guard Darwin.renameatx_np(evidence, latestName!, evidence, "latest.json", flags) == 0 else {
                    throw FileAccess.posixError("Cannot publish the latest optical pointer")
                }
                // The pointer rename is the commit. A cancellation arriving
                // afterwards must not turn a published result into a failure.
                committed = true
                guard Darwin.fsync(evidence) == 0 else { throw FileAccess.posixError("Cannot flush optical pointer") }
                try validate()
                return result
            }
            guard let saved else { throw UDFError.invalidResult("Optical storage could not be created.") }
            return saved
        }
    }

    /// Reading historical metadata does not require the original image online.
    /// An invalid pointer/checksum fails closed; older generations are retained.
    public static func loadLatest(in forensicCase: ForensicCase, evidenceID: UUID) throws -> UDFInspectionResult? {
        try withCase(forensicCase, write: false) { root, manifest, validateCase in
            guard manifest.evidence.contains(where: { $0.id == evidenceID }) else {
                throw UDFError.invalidResult("The evidence is not part of this case.")
            }
            let result = try withEvidence(evidenceID, root: root, create: false, validateCase: validateCase) {
                evidence, generations, validate -> UDFInspectionResult? in
                guard let pointer = try readPointer(in: evidence) else { return nil }
                try validatePointer(pointer.value, caseID: manifest.id, evidenceID: evidenceID)
                let result = try readGeneration(pointer.value, generations: generations, manifest: manifest)
                try validate()
                guard (try? FileAccess.identity(at: "latest.json", in: evidence)) == pointer.identity else {
                    throw UDFError.invalidResult("The latest optical pointer changed while being read.")
                }
                return result
            }
            try validateCase(); return result ?? nil
        }
    }

    /// Export copies exactly the recorded source extents. The source is pinned
    /// and its entire selected-file hash is checked before and after copying.
    /// No original path from UDF metadata becomes an output filesystem path.
    public static func export(entryID: String, from result: UDFInspectionResult,
        in forensicCase: ForensicCase, to destination: URL) async throws -> UDFExportReceipt {
        let worker = Task.detached(priority: .userInitiated) {
            try exportSynchronously(entryID: entryID, from: result, in: forensicCase, to: destination)
        }
        return try await withTaskCancellationHandler {
            // Publication is the worker's commit boundary. Do not hide a
            // committed export by checking the caller's cancellation later.
            try await worker.value
        } onCancel: { worker.cancel() }
    }

    private static func exportSynchronously(entryID: String, from result: UDFInspectionResult,
        in forensicCase: ForensicCase, to destination: URL) throws -> UDFExportReceipt {
        try validateResult(result)
        guard let entry = result.entries.first(where: { $0.id == entryID }) else {
            throw UDFError.invalidResult("The selected optical entry is missing.")
        }
        let destination = try strictURL(destination)
        let bundle = try strictURL(forensicCase.bundleURL)
        let deadline = ProcessInfo.processInfo.systemUptime + result.options.timeoutSeconds
        let checkDeadline: @Sendable () throws -> Void = {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime <= deadline else { throw UDFError.timeout }
        }
        guard !FileAccess.isInside(destination, directory: bundle), !destination.lastPathComponent.isEmpty else {
            throw UDFError.invalidResult("Export outside the case bundle.")
        }
        return try withCase(forensicCase, write: false, deadline: deadline) { root, manifest, validateCase in
            let evidence = try binding(result, manifest: manifest)
            guard !manifest.evidence.contains(where: { $0.sourcePath == destination.path }) else {
                throw UDFError.invalidResult("An export must not overwrite an evidence source.")
            }
            let receipt = try withEvidence(result.sourceEvidenceID, root: root, create: false,
                validateCase: validateCase) { _, generations, validate in
                let generation = try directory(name(result.jobID), parent: generations, create: false)
                guard generation >= 0 else { throw UDFError.invalidResult("The optical generation is missing.") }
                defer { Darwin.close(generation) }
                let checksum = try PinnedOpticalFile(name: "checksum.json", parent: generation)
                defer { checksum.close() }
                let pointer = try JSONDecoder().decode(GenerationPointer.self,
                    from: readBounded(checksum, maximum: maximumPointerBytes))
                try validatePointer(pointer, caseID: manifest.id, evidenceID: evidence.id)
                let resultFile = try PinnedOpticalFile(name: "result.json", parent: generation)
                defer { resultFile.close() }
                let resultBytes = try readBounded(resultFile, maximum: maximumResultBytes)
                guard pointer.jobID == result.jobID,
                      hash(resultBytes) == pointer.resultSHA256,
                      try JSONDecoder().decode(UDFInspectionResult.self, from: resultBytes) == result else {
                    throw UDFError.invalidResult("The supplied optical result differs from its stored generation.")
                }
                let source = try UDFPinnedSource(evidence: evidence, maximumSourceBytes: result.options.maximumSourceBytes)
                try source.verifyHash(progress: { _ in try checkDeadline() })
                let transaction = try OpticalExportTransaction(destination: destination)
                defer { transaction.cleanup() }
                var outputHasher = SHA256(), count: Int64 = 0
                for extent in entry.sourceExtents {
                    var offset: Int64 = 0
                    while offset < extent.byteCount {
                        try checkDeadline()
                        let amount = Int(min(1_048_576, extent.byteCount - offset))
                        let bytes = try source.read(offset: extent.offset + offset, count: amount)
                        guard bytes.count == amount else { throw ForensicsError.sourceChanged }
                        try write(bytes, to: transaction.output)
                        outputHasher.update(data: bytes); offset += Int64(amount); count += Int64(amount)
                    }
                }
                guard count == entry.byteCount,
                      outputHasher.finalize().map({ String(format: "%02x", $0) }).joined() == entry.sha256 else {
                    throw UDFError.invalidResult("The source extents no longer match the validated entry bytes.")
                }
                try source.verifyHash(progress: { _ in try checkDeadline() }); try source.validate()
                let outputIdentity = try verifyOutput(transaction.output, byteCount: entry.byteCount, sha256: entry.sha256)
                try validate(); try checksum.validate(); try resultFile.validate()
                try validateReference(name(result.jobID), parent: generations, descriptor: generation, kind: S_IFDIR)
                try checkDeadline()
                try transaction.publish(identity: outputIdentity) {
                    try validate(); try checksum.validate(); try resultFile.validate(); try source.validate()
                    try validateReference(name(result.jobID), parent: generations, descriptor: generation, kind: S_IFDIR)
                }
                return UDFExportReceipt(caseID: result.caseID, sourceEvidenceID: result.sourceEvidenceID,
                    jobID: result.jobID, entryID: entry.id, destinationPath: destination.path,
                    byteCount: entry.byteCount, sha256: entry.sha256, sourceSHA256: result.sourceSHA256)
            }
            guard let receipt else { throw UDFError.invalidResult("The optical generation is missing.") }
            return receipt
        }
    }

    private static func binding(_ result: UDFInspectionResult, manifest: CaseManifest) throws -> EvidenceRecord {
        guard manifest.id == result.caseID,
              let evidence = manifest.evidence.first(where: { $0.id == result.sourceEvidenceID }),
              evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.sha256 == result.sourceSHA256, evidence.byteCount == result.sourceByteCount else {
            throw UDFError.invalidResult("The UDF result belongs to different case/evidence bytes.")
        }
        return evidence
    }

    static func validateResult(_ result: UDFInspectionResult) throws {
        try result.options.validate()
        guard result.schemaVersion == 1, result.blockSize == 2048, result.sourceByteCount > 0,
              result.sourceByteCount <= result.options.maximumSourceBytes,
              EngineValidation.validHash(result.sourceSHA256), safeText(result.parserVersion, limit: 128),
              safeText(result.profile, limit: 256), result.volumeIdentifier.utf8.count <= 1024,
              safeText(result.udfRevision, limit: 64), !result.snapshots.isEmpty,
              result.snapshots.count <= result.options.maximumSnapshots,
              result.entries.count <= result.options.maximumFiles, result.limitations.count <= 64,
              result.deletedAncestors.count <= result.options.maximumMetadataBlocks,
              result.limitations.allSatisfy({ $0.utf8.count <= 4096 }),
              result.savedAt.timeIntervalSince1970.isFinite else {
            throw UDFError.invalidResult("The UDF schema, source receipt or declared limits are invalid.")
        }
        let snapshots = Set(result.snapshots.map(\.id))
        guard snapshots.count == result.snapshots.count, snapshots.contains(result.latestSnapshotID),
              result.snapshots.allSatisfy({ safeText($0.id, limit: 256)
                  && $0.vatICBSourceOffset >= 0 && $0.vatICBSourceOffset <= result.sourceByteCount - 16
                  && $0.mappedBlockCount >= 0 && $0.mappedBlockCount <= result.options.maximumMetadataBlocks * 64
                  && $0.namespaceFileCount >= 0 && $0.namespaceFileCount <= result.options.maximumFiles }) else {
            throw UDFError.invalidResult("The UDF snapshot identifiers or locations are invalid.")
        }
        for snapshot in result.snapshots { try validateTimestamp(snapshot.modification, sourceByteCount: result.sourceByteCount) }
        for proof in result.deletedAncestors { try validateProof(proof, result: result) }
        // Refuse excessive metadata before JSONEncoder allocates its output.
        // The bound includes strings and conservative per-node JSON overhead.
        var metadataBudget = 4096 + result.volumeIdentifier.utf8.count
            + result.limitations.reduce(0) { $0 + $1.utf8.count + 64 }
            + result.snapshots.count * 2048
        var extentCount = 0, proofCount = result.deletedAncestors.count
        for proof in result.deletedAncestors {
            metadataBudget += proof.originalPath.utf8.count + proof.rawNameHex.utf8.count + 512
        }
        var ids = Set<String>(), totalBytes: Int64 = 0
        for entry in result.entries {
            guard ids.insert(entry.id).inserted, safeText(entry.id, limit: 256),
                  entry.originalPath.hasPrefix("/"), !entry.originalPath.utf8.contains(0),
                  entry.originalPath.utf8.count <= 4096,
                  entry.historicalPaths.count <= result.options.maximumSnapshots,
                  entry.historicalPaths.allSatisfy({ $0.hasPrefix("/") && !$0.utf8.contains(0) && $0.utf8.count <= 4096 }),
                  entry.byteCount >= 0, entry.byteCount <= result.options.maximumFileBytes,
                  EngineValidation.validHash(entry.sha256), !entry.snapshotIDs.isEmpty,
                  Set(entry.snapshotIDs).count == entry.snapshotIDs.count,
                  entry.snapshotIDs.allSatisfy({ snapshots.contains($0) }),
                  entry.state != .current || entry.snapshotIDs.contains(result.latestSnapshotID),
                  entry.fidSourceOffset >= 0, entry.fidSourceOffset <= result.sourceByteCount - 16,
                  entry.icb.sourceOffset >= 0, entry.icb.sourceOffset <= result.sourceByteCount - 16,
                  entry.sourceExtents.count <= result.options.maximumMetadataBlocks,
                  entry.deletedAncestorProof.count <= 128 else {
                throw UDFError.invalidResult("A UDF file identifier, receipt or metadata location is invalid.")
            }
            extentCount += entry.sourceExtents.count; proofCount += entry.deletedAncestorProof.count
            metadataBudget += 2048 + entry.id.utf8.count + entry.originalPath.utf8.count
                + entry.historicalPaths.reduce(0) { $0 + $1.utf8.count + 64 }
                + entry.sourceExtents.count * 128
            for proof in entry.deletedAncestorProof {
                metadataBudget += proof.originalPath.utf8.count + proof.rawNameHex.utf8.count + 512
            }
            guard extentCount <= result.options.maximumMetadataBlocks,
                  proofCount <= result.options.maximumMetadataBlocks,
                  Int64(metadataBudget) <= maximumResultBytes / 2 else {
                throw UDFError.invalidResult("The UDF generation metadata exceeds the bounded encoding budget.")
            }
            try validateTimestamp(entry.timestamps.access, sourceByteCount: result.sourceByteCount)
            try validateTimestamp(entry.timestamps.modification, sourceByteCount: result.sourceByteCount)
            try validateTimestamp(entry.timestamps.attribute, sourceByteCount: result.sourceByteCount)
            if let creation = entry.timestamps.creation { try validateTimestamp(creation, sourceByteCount: result.sourceByteCount) }
            for proof in entry.deletedAncestorProof { try validateProof(proof, result: result) }
            var extentBytes: Int64 = 0
            for extent in entry.sourceExtents {
                guard extent.offset >= 0, extent.byteCount >= 0,
                      extent.offset <= result.sourceByteCount,
                      extent.byteCount <= result.sourceByteCount - extent.offset,
                      extent.byteCount <= entry.byteCount - extentBytes,
                      extent.allocation == "recorded" || extent.allocation == "inline" else {
                    throw UDFError.invalidResult("A UDF payload extent is outside the source or declared file size.")
                }
                extentBytes += extent.byteCount
            }
            guard extentBytes == entry.byteCount,
                  totalBytes <= result.options.maximumPayloadBytes - entry.byteCount,
                  entry.state != .historicalDeletedAncestor || !entry.deletedAncestorProof.isEmpty else {
                throw UDFError.invalidResult("The UDF payload sizes or deleted-ancestor provenance are invalid.")
            }
            totalBytes += entry.byteCount
        }
    }

    private static func validateTimestamp(_ timestamp: UDFTimestamp, sourceByteCount: Int64) throws {
        guard timestamp.sourceOffset >= 0, timestamp.sourceOffset <= sourceByteCount - 12,
              timestamp.rawHex.utf8.count == 24, hexText(timestamp.rawHex), timestamp.type <= 15,
              timestamp.timezoneMinutes.map({ (-1440...1440).contains($0) }) ?? true,
              (0...999999).contains(timestamp.microsecond),
              timestamp.utcDate.map({ $0.timeIntervalSince1970.isFinite }) ?? true else {
            throw UDFError.invalidResult("A UDF timestamp or its original source range is invalid.")
        }
    }

    private static func validateProof(_ proof: UDFDeletedAncestorProof, result: UDFInspectionResult) throws {
        guard proof.originalPath.hasPrefix("/"), proof.originalPath.utf8.count <= 4096,
              !proof.originalPath.utf8.contains(0), proof.latestSnapshotID == result.latestSnapshotID,
              proof.fidSourceOffset >= 0, proof.fidSourceOffset <= result.sourceByteCount - 16,
              proof.fidCharacteristics & 4 != 0, proof.nullICB,
              proof.rawNameHex.utf8.count <= 1024, proof.rawNameHex.utf8.count % 2 == 0,
              hexText(proof.rawNameHex) else {
            throw UDFError.invalidResult("The deleted ancestor proof is not bound to a deleted FID in the latest source state.")
        }
    }

    private static func hexText(_ value: String) -> Bool {
        value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func safeText(_ value: String, limit: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= limit && !value.utf8.contains(0)
    }

    private static func validatePointer(_ pointer: GenerationPointer, caseID: UUID, evidenceID: UUID) throws {
        guard pointer.schemaVersion == 1, pointer.caseID == caseID, pointer.evidenceID == evidenceID,
              EngineValidation.validHash(pointer.resultSHA256) else {
            throw UDFError.invalidResult("The optical generation pointer has an invalid binding or checksum.")
        }
    }

    private static func readPointer(in evidence: Int32) throws -> (value: GenerationPointer, identity: SourceIdentity)? {
        var metadata = stat()
        if Darwin.fstatat(evidence, "latest.json", &metadata, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }
            throw FileAccess.posixError("Cannot read latest optical generation")
        }
        let input = try PinnedOpticalFile(name: "latest.json", parent: evidence)
        defer { input.close() }
        let pointer = try JSONDecoder().decode(GenerationPointer.self,
            from: readBounded(input, maximum: maximumPointerBytes))
        try input.validate(); return (pointer, input.identity)
    }

    private static func readGeneration(_ pointer: GenerationPointer, generations: Int32,
        manifest: CaseManifest) throws -> UDFInspectionResult {
        let filename = name(pointer.jobID)
        let generation = try directory(filename, parent: generations, create: false)
        guard generation >= 0 else { throw UDFError.invalidResult("The pointed optical generation is missing.") }
        defer { Darwin.close(generation) }
        let checksum = try PinnedOpticalFile(name: "checksum.json", parent: generation)
        defer { checksum.close() }
        let stored = try JSONDecoder().decode(GenerationPointer.self,
            from: readBounded(checksum, maximum: maximumPointerBytes))
        guard stored == pointer else { throw UDFError.invalidResult("The generation checksum differs from its pointer.") }
        let input = try PinnedOpticalFile(name: "result.json", parent: generation)
        defer { input.close() }
        let bytes = try readBounded(input, maximum: maximumResultBytes)
        guard hash(bytes) == pointer.resultSHA256 else { throw UDFError.invalidResult("The optical result checksum changed.") }
        let result = try JSONDecoder().decode(UDFInspectionResult.self, from: bytes)
        try validateResult(result); _ = try binding(result, manifest: manifest)
        guard result.jobID == pointer.jobID else { throw UDFError.invalidResult("The generation job identifier differs.") }
        try input.validate(); try checksum.validate()
        try validateReference(filename, parent: generations, descriptor: generation, kind: S_IFDIR)
        return result
    }

    private static func writeNewFile(_ bytes: Data, named filename: String, in directory: Int32) throws -> SourceIdentity {
        let output = Darwin.openat(directory, filename, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { throw FileAccess.posixError("Cannot create optical metadata") }
        defer { Darwin.close(output) }
        let initial = try FileAccess.identity(of: output)
        do {
            try write(bytes, to: output)
            let identity = try verifyOutput(output, byteCount: Int64(bytes.count), sha256: hash(bytes))
            try validateReference(filename, parent: directory, descriptor: output, kind: S_IFREG)
            return identity
        } catch { removeOwned(filename, parent: directory, identity: initial); throw error }
    }

    private static func verifyOutput(_ descriptor: Int32, byteCount: Int64, sha256: String) throws -> SourceIdentity {
        guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush optical bytes") }
        let identity = try FileAccess.identity(of: descriptor)
        guard identity.size == byteCount else { throw UDFError.invalidResult("The output byte count changed.") }
        var hasher = SHA256(), offset: Int64 = 0
        while offset < byteCount {
            try Task.checkCancellation()
            let amount = Int(min(1_048_576, byteCount - offset))
            var bytes = Data(count: amount)
            let read = try bytes.withUnsafeMutableBytes { try pread(descriptor, into: $0, count: amount, offset: offset) }
            guard read > 0 else { throw UDFError.invalidResult("The output was truncated during verification.") }
            hasher.update(data: bytes.prefix(read)); offset += Int64(read)
        }
        guard hasher.finalize().map({ String(format: "%02x", $0) }).joined() == sha256,
              (try? FileAccess.identity(of: descriptor)) == identity else {
            throw UDFError.invalidResult("The independently checked output SHA-256 differs.")
        }
        return identity
    }

    fileprivate static func removeOwned(_ filename: String, parent: Int32, identity: SourceIdentity) {
        var current = stat()
        if Darwin.fstatat(parent, filename, &current, AT_SYMLINK_NOFOLLOW) == 0,
           current.st_mode & S_IFMT == S_IFREG, current.st_dev == identity.device, current.st_ino == identity.inode {
            _ = Darwin.unlinkat(parent, filename, 0)
        }
    }

    private struct GenerationPointer: Codable, Equatable {
        let schemaVersion: Int
        let caseID: UUID
        let evidenceID: UUID
        let jobID: UUID
        let resultSHA256: String
    }

    private static func withCase<T>(_ forensicCase: ForensicCase, write: Bool,
        deadline: TimeInterval = ProcessInfo.processInfo.systemUptime + 30,
        body: (Int32, CaseManifest, @escaping () throws -> Void) throws -> T) throws -> T {
        try Task.checkCancellation()
        let bundle = try strictURL(forensicCase.bundleURL)
        guard bundle.pathExtension == CaseStore.bundleExtension else {
            throw ForensicsError.invalidCase("Choose a nativecase bundle.")
        }
        let root = try EvidenceViewFiles.openDirectory(bundle)
        defer { Darwin.close(root) }
        let lock = try PinnedOpticalFile(name: ".case.lock", parent: root)
        defer { lock.close() }
        while true {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime <= deadline else { throw UDFError.timeout }
            if opticalFlock(lock.descriptor, (write ? LOCK_EX : LOCK_SH) | LOCK_NB) == 0 { break }
            if errno == EINTR { continue }
            guard errno == EWOULDBLOCK else { throw FileAccess.posixError("Cannot lock optical storage") }
            try Task.checkCancellation(); usleep(10_000)
        }
        defer { _ = opticalFlock(lock.descriptor, LOCK_UN) }
        try Task.checkCancellation()
        guard ProcessInfo.processInfo.systemUptime <= deadline else { throw UDFError.timeout }
        let manifestFile = try PinnedOpticalFile(name: "manifest.json", parent: root)
        defer { manifestFile.close() }
        let manifestBytes = try readBounded(manifestFile, maximum: 16 * 1_048_576)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(CaseManifest.self, from: manifestBytes)
        guard try CaseStore.open(at: bundle).manifest == manifest else { throw ForensicsError.sourceChanged }
        guard manifest == forensicCase.manifest else { throw ForensicsError.staleCase }
        let validate = {
            try EvidenceViewFiles.validateDirectory(bundle, descriptor: root)
            try lock.validate(); try manifestFile.validate()
        }
        try validate()
        return try body(root, manifest, validate)
    }

    private static func withEvidence<T>(_ evidenceID: UUID, root: Int32, create: Bool,
        validateCase: @escaping () throws -> Void,
        body: (Int32, Int32, @escaping () throws -> Void) throws -> T) throws -> T? {
        let optical = try directory("optical", parent: root, create: create)
        guard optical >= 0 else { return nil }
        defer { Darwin.close(optical) }
        let evidenceName = name(evidenceID)
        let evidence = try directory(evidenceName, parent: optical, create: create)
        guard evidence >= 0 else { return nil }
        defer { Darwin.close(evidence) }
        let generations = try directory("generations", parent: evidence, create: create)
        guard generations >= 0 else { return nil }
        defer { Darwin.close(generations) }
        let validate = {
            try validateCase()
            try validateReference("optical", parent: root, descriptor: optical, kind: S_IFDIR)
            try validateReference(evidenceName, parent: optical, descriptor: evidence, kind: S_IFDIR)
            try validateReference("generations", parent: evidence, descriptor: generations, kind: S_IFDIR)
        }
        try validate()
        return try body(evidence, generations, validate)
    }

    private static func encode<T: Encodable>(_ value: T, maximum: Int64) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(value)
        guard Int64(bytes.count) <= maximum else {
            throw ForensicsError.invalidCase("The optical record exceeds the storage limit.")
        }
        return bytes
    }

    private static func hash(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func name(_ id: UUID) -> String { id.uuidString.lowercased() }

    fileprivate static func strictURL(_ url: URL) throws -> URL {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw ForensicsError.invalidFileURL }
        return url.standardizedFileURL
    }

    fileprivate static func directory(_ name: String, parent: Int32, create: Bool) throws -> Int32 {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw ForensicsError.invalidCase("The optical storage path is invalid.")
        }
        if create && Darwin.mkdirat(parent, name, mode_t(0o700)) != 0 && errno != EEXIST {
            throw FileAccess.posixError("Cannot create optical directory")
        }
        let descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if !create && errno == ENOENT { return -1 }
            throw ForensicsError.invalidCase("The optical storage directory is missing or changed.")
        }
        do { try validateReference(name, parent: parent, descriptor: descriptor, kind: S_IFDIR); return descriptor }
        catch { Darwin.close(descriptor); throw error }
    }

    fileprivate static func referenceMatches(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var named = stat(), held = stat()
        return Darwin.fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0
            && Darwin.fstat(descriptor, &held) == 0
            && named.st_mode & S_IFMT == kind && held.st_mode & S_IFMT == kind
            && named.st_dev == held.st_dev && named.st_ino == held.st_ino
    }

    fileprivate static func validateReference(_ name: String, parent: Int32, descriptor: Int32, kind: mode_t) throws {
        guard referenceMatches(name, parent: parent, descriptor: descriptor, kind: kind) else {
            throw ForensicsError.invalidCase("The optical storage reference changed.")
        }
    }

    private static func readBounded(_ input: PinnedOpticalFile, maximum: Int64) throws -> Data {
        guard input.identity.size <= maximum else {
            throw ForensicsError.invalidCase("The optical metadata exceeds the storage limit.")
        }
        var bytes = Data(); bytes.reserveCapacity(Int(input.identity.size))
        var offset: Int64 = 0
        while offset < input.identity.size {
            try Task.checkCancellation()
            let amount = Int(min(1_048_576, input.identity.size - offset))
            var buffer = Data(count: amount)
            let count = try buffer.withUnsafeMutableBytes {
                try pread(input.descriptor, into: $0, count: amount, offset: offset)
            }
            guard count > 0 else { throw ForensicsError.sourceChanged }
            bytes.append(buffer.prefix(count)); offset += Int64(count)
        }
        try input.validate(); return bytes
    }

    fileprivate static func pread(_ descriptor: Int32, into buffer: UnsafeMutableRawBufferPointer,
        count: Int, offset: Int64) throws -> Int {
        while true {
            let amount = Darwin.pread(descriptor, buffer.baseAddress, count, off_t(offset))
            if amount >= 0 { return amount }
            if errno == EINTR { continue }
            throw FileAccess.posixError("Cannot read optical bytes")
        }
    }

    fileprivate static func write(_ bytes: Data, to descriptor: Int32) throws {
        try bytes.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                try Task.checkCancellation()
                let amount = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: written), buffer.count - written)
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw FileAccess.posixError("Cannot write optical metadata") }
                written += amount
            }
        }
    }
}

/// Regular leaf with a pinned no-follow parent. Every validation checks both
/// the held inode and its original directory entry; hardlinked leaves fail.
private final class PinnedOpticalFile {
    let descriptor: Int32
    let identity: SourceIdentity
    private let parent: Int32
    private let filename: String
    private let parentURL: URL?
    private var closed = false

    convenience init(url: URL) throws {
        let canonical = try UDFResultStore.strictURL(url)
        let directoryURL = canonical.deletingLastPathComponent()
        let directory = try EvidenceViewFiles.openDirectory(directoryURL)
        defer { Darwin.close(directory) }
        try self.init(name: canonical.lastPathComponent, parent: directory, parentURL: directoryURL)
    }

    convenience init(name: String, parent: Int32) throws {
        try self.init(name: name, parent: parent, parentURL: nil)
    }

    private init(name: String, parent: Int32, parentURL: URL?) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0) else {
            throw ForensicsError.invalidFileURL
        }
        self.parent = Darwin.fcntl(parent, F_DUPFD_CLOEXEC, 0)
        guard self.parent >= 0 else { throw FileAccess.posixError("Cannot pin optical directory") }
        filename = name; self.parentURL = parentURL
        descriptor = Darwin.openat(self.parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { Darwin.close(self.parent); throw FileAccess.posixError("Cannot pin optical file") }
        do {
            identity = try FileAccess.identity(of: descriptor)
            try validate()
        } catch {
            closed = true; Darwin.close(descriptor); Darwin.close(self.parent); throw error
        }
    }

    func validate() throws {
        guard (try? FileAccess.identity(of: descriptor)) == identity,
              (try? FileAccess.identity(at: filename, in: parent)) == identity else { throw ForensicsError.sourceChanged }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_nlink == 1 else {
            throw ForensicsError.invalidCase("Optical files must not be hardlinks.")
        }
        if let parentURL { try EvidenceViewFiles.validateDirectory(parentURL, descriptor: parent) }
    }

    func close() {
        guard !closed else { return }; closed = true
        Darwin.close(descriptor); Darwin.close(parent)
    }
    deinit { close() }
}

/// Complete bytes stay under a random CREATE_NEW leaf until verified. The
/// destination is published with RENAME_EXCL and therefore never overwritten.
private final class OpticalExportTransaction {
    let output: Int32
    private let parent: Int32
    private let destination: URL
    private let stagingName: String
    private let initialIdentity: SourceIdentity
    private var committed = false
    private var cleaned = false

    init(destination: URL) throws {
        self.destination = destination
        parent = try EvidenceViewFiles.openDirectory(destination.deletingLastPathComponent())
        var existing = stat()
        if Darwin.fstatat(parent, destination.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            Darwin.close(parent); throw UDFError.invalidResult("The export destination already exists.")
        }
        guard errno == ENOENT else {
            Darwin.close(parent); throw FileAccess.posixError("Cannot inspect optical export destination")
        }
        stagingName = ".udf-export-\(UUID().uuidString.lowercased()).tmp"
        output = Darwin.openat(parent, stagingName, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { Darwin.close(parent); throw FileAccess.posixError("Cannot create optical export staging") }
        do { initialIdentity = try FileAccess.identity(of: output) }
        catch { Darwin.close(output); Darwin.close(parent); throw error }
    }

    func publish(identity: SourceIdentity, validate: () throws -> Void) throws {
        try validate()
        try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        try UDFResultStore.validateReference(stagingName, parent: parent, descriptor: output, kind: S_IFREG)
        guard (try? FileAccess.identity(of: output)) == identity else { throw ForensicsError.sourceChanged }
        try Task.checkCancellation()
        guard Darwin.renameatx_np(parent, stagingName, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            throw FileAccess.posixError("Cannot publish the optical export without overwriting")
        }
        committed = true
        // No cancellation checks follow the atomic commit.
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush optical export directory") }
        try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        try UDFResultStore.validateReference(destination.lastPathComponent, parent: parent, descriptor: output, kind: S_IFREG)
    }

    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        if !committed { UDFResultStore.removeOwned(stagingName, parent: parent, identity: initialIdentity) }
        Darwin.close(output); Darwin.close(parent)
    }
    deinit { cleanup() }
}
