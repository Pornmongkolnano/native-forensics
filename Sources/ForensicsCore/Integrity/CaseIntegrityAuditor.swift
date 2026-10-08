import CryptoKit
import Darwin
import Foundation

@_silgen_name("flock")
private func integrityFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

/// Read-only, bounded audit. Digests detect changed bytes, not an examiner's
/// identity or a malicious party rewriting both data and its unsigned receipt.
public enum CaseIntegrityAuditor {
    public static func audit(forensicCase: ForensicCase, options: CaseIntegrityAuditOptions = .init(),
                             progress: @escaping @Sendable (CaseIntegrityProgress) -> Void = { _ in }) async throws -> CaseIntegrityReport {
        try await perform(forensicCase: forensicCase, options: options, progress: progress, afterSourceRead: { _ in })
    }

    /// Deterministic fault seam at a held source descriptor boundary. This is
    /// internal test-only API; ordinary audits never mutate any filesystem.
    static func auditForTesting(forensicCase: ForensicCase, options: CaseIntegrityAuditOptions,
                                afterSourceRead: @escaping @Sendable (EvidenceRecord) throws -> Void) async throws -> CaseIntegrityReport {
        try await perform(forensicCase: forensicCase, options: options, progress: { _ in }, afterSourceRead: afterSourceRead)
    }

    private static func perform(forensicCase: ForensicCase, options: CaseIntegrityAuditOptions,
                                progress: @escaping @Sendable (CaseIntegrityProgress) -> Void,
                                afterSourceRead: @escaping @Sendable (EvidenceRecord) throws -> Void) async throws -> CaseIntegrityReport {
        let task = Task.detached(priority: .utility) {
            var worker = IntegrityAuditWorker(forensicCase: forensicCase, options: options, progress: progress, afterSourceRead: afterSourceRead)
            return try worker.run()
        }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }
}

private struct IntegrityGenerationPointer: Decodable, Equatable {
    let schemaVersion: Int; let caseID: UUID; let evidenceID: UUID; let jobID: UUID; let resultSHA256: String
}

private struct IntegrityAuditWorker {
    let forensicCase: ForensicCase
    let options: CaseIntegrityAuditOptions
    let progress: @Sendable (CaseIntegrityProgress) -> Void
    let afterSourceRead: @Sendable (EvidenceRecord) throws -> Void
    private var checks: [CaseIntegrityCheck] = []
    private var partial = false
    private var manifestDigest: String?
    private var files = 0
    private var metadataBytes: Int64 = 0
    private var payloadBytes: Int64 = 0
    private var sourceBytes: Int64 = 0
    private var deadline: TimeInterval = 0
    private var lastProgressTime: TimeInterval = -.infinity
    private var payloads: [String: (size: Int64, hash: String)] = [:]
    private var expectedPayloads: [String: (size: Int64, hash: String)] = [:]
    private var metadataDigests: [String: String] = [:]
    private var metadataSizes: [String: Int] = [:]
    private var observedStoragePaths = Set<String>()
    private var unsafeStoragePaths = Set<String>()
    private var unsupportedStoragePaths = Set<String>()
    private var migrationBackupVerified = false
    private var validFilesystemJobArtifacts = Set<UUID>()
    private var validAPFSJobArtifacts = Set<UUID>()
    private var apfsResults: [String: (hash: String, size: Int, evidence: UUID, generation: UUID, coverage: APFSReadCoverage)] = [:]
    private var apfsChecksums: [String: APFSCacheReceipt] = [:]
    private var apfsLatest: [String: APFSCacheReceipt] = [:]
    private var opticalResults: [String: (hash: String, job: UUID, evidence: UUID)] = [:]
    private var opticalChecksums: [String: IntegrityGenerationPointer] = [:]
    private var opticalLatest: [String: IntegrityGenerationPointer] = [:]
    private var findingChains: [String: [FindingLink]] = [:]
    private var comparisonParents: [UUID: ComparisonLink] = [:]
    private var recoveryBindings: [String: (digest: String, artifacts: Set<UUID>)] = [:]
    private var recoveryNoteChains: [String: [RecoveryNoteLink]] = [:]
    private var manifest: CaseManifest?
    private let startedAt = Date()

    init(forensicCase: ForensicCase, options: CaseIntegrityAuditOptions,
         progress: @escaping @Sendable (CaseIntegrityProgress) -> Void,
         afterSourceRead: @escaping @Sendable (EvidenceRecord) throws -> Void) {
        self.forensicCase = forensicCase; self.options = options; self.progress = progress; self.afterSourceRead = afterSourceRead
    }

    mutating func run() throws -> CaseIntegrityReport {
        deadline = ProcessInfo.processInfo.systemUptime + options.timeoutSeconds
        do {
            guard (1...10_000).contains(options.maximumFiles), (1...268_435_456).contains(options.maximumMetadataBytes),
                  (0...2_147_483_648).contains(options.maximumPayloadBytes),
                  (0...34_359_738_368).contains(options.maximumSourceBytes),
                  options.timeoutSeconds.isFinite, (0.01...600).contains(options.timeoutSeconds) else {
                throw CaseIntegrityAuditError.limit
            }
            try tick("Opening case")
            guard forensicCase.bundleURL.pathExtension == CaseStore.bundleExtension else { throw CaseIntegrityAuditError.invalid }
            let root = try EvidenceViewFiles.openDirectory(forensicCase.bundleURL)
            defer { Darwin.close(root) }
            let lock = try FileAccess.openReadOnly(".case.lock", in: root)
            defer { Darwin.close(lock) }
            let lockIdentity = try FileAccess.identity(of: lock)
            var lockInfo = stat()
            guard Darwin.fstat(lock, &lockInfo) == 0, lockInfo.st_nlink == 1 else { throw CaseIntegrityAuditError.unsafe }
            while integrityFlock(lock, LOCK_SH | LOCK_NB) != 0 {
                if errno == EINTR { continue }
                guard errno == EWOULDBLOCK else { throw CaseIntegrityAuditError.unsafe }
                try tick("Waiting for case writer"); usleep(10_000)
            }
            defer { _ = integrityFlock(lock, LOCK_UN) }
            let data = try read("manifest.json", parent: root, maximum: 16 * 1_048_576)
            manifestDigest = hash(data)
            try schema(data, allowedVersions: [1, 2])
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            let current = try decoder.decode(CaseManifest.self, from: data)
            try validateManifest(current)
            guard current == forensicCase.manifest else { throw CaseIntegrityAuditError.changed }
            try EvidenceViewFiles.validateDirectory(forensicCase.bundleURL, descriptor: root)
            manifest = current
            add(.pass, "manifest.valid", "Manifest v\(current.schemaVersion) is valid and matches the opened case.", path: "manifest.json", size: Int64(data.count), digest: manifestDigest)
            for (index, evidence) in current.evidence.enumerated() {
                guard index < options.maximumFiles else { throw CaseIntegrityAuditError.limit }
                try tick("Checking evidence receipts")
                if options.freshEvidenceRehash { try auditSource(evidence) }
                else {
                    add(.historical, "source.historical", "Recorded selected-file hash only; source bytes were not opened or freshly verified.", evidence: evidence, size: evidence.byteCount, digest: evidence.sha256)
                }
            }
            try walk(root, path: [], depth: 0)
            try reconcile()
            try EvidenceViewFiles.validateDirectory(forensicCase.bundleURL, descriptor: root)
            guard (try? FileAccess.identity(at: ".case.lock", in: root)) == lockIdentity,
                  hash(try read("manifest.json", parent: root, maximum: 16 * 1_048_576)) == manifestDigest else {
                throw CaseIntegrityAuditError.changed
            }
        } catch is CancellationError { throw CancellationError() }
        catch CaseIntegrityAuditError.limit { partial = true; add(.unavailable, "coverage.limit", "A file, byte, depth or time budget stopped the audit. Unchecked items are not verified.") }
        catch CaseIntegrityAuditError.unsupported { partial = true; add(.unavailable, "metadata.schema.unsupported", "The manifest uses an unknown schema. No migration or repair was performed.", path: "manifest.json") }
        catch CaseIntegrityAuditError.changed { partial = true; add(.fail, "storage.changed", "The opened case or audited storage changed during the audit; repeat after reopening the case.") }
        catch { partial = true; add(.fail, "storage.unsafe", "The case could not be audited safely. It may be malformed, inaccessible or contain a symbolic link. Original bytes were preserved.") }
        return CaseIntegrityReport(caseID: forensicCase.manifest.id, casePath: forensicCase.bundleURL.path,
            manifestSHA256: manifestDigest, startedAt: startedAt, completedAt: Date(),
            sourceRehashed: options.freshEvidenceRehash, isPartial: partial, checks: checks)
    }

    private mutating func tick(_ stage: String) throws {
        try Task.checkCancellation()
        let now = ProcessInfo.processInfo.systemUptime
        guard now < deadline else { throw CaseIntegrityAuditError.limit }
        if now - lastProgressTime >= 0.05 {
            lastProgressTime = now
            progress(.init(stage: stage, checkedFiles: files, bytesRead: metadataBytes + payloadBytes + sourceBytes))
        }
    }

    private mutating func add(_ status: CaseIntegrityStatus, _ code: String, _ message: String,
                              path: String? = nil, evidence: EvidenceRecord? = nil, size: Int64? = nil, digest: String? = nil) {
        if status == .unavailable || status == .offline { partial = true }
        // Bounded diagnostics include one final budget diagnostic even at the cap.
        guard checks.count < 20_000 else {
            partial = true
            if checks.count == 20_000 {
                checks.append(.init(status: .unavailable, code: "coverage.limit",
                    message: "The diagnostic budget omitted remaining checks. Unreported items are not verified."))
            }
            return
        }
        checks.append(.init(status: status, code: code, relativePath: path, evidenceID: evidence?.id,
            privatePath: evidence?.sourcePath, byteCount: size, sha256: digest,
            recordedByteCount: evidence?.byteCount, recordedSHA256: evidence?.sha256, message: message))
    }

    private mutating func auditSource(_ evidence: EvidenceRecord) throws {
        let url = URL(fileURLWithPath: evidence.sourcePath)
        do {
            let parent = try EvidenceViewFiles.openDirectory(url.deletingLastPathComponent(), searchOnly: true)
            defer { Darwin.close(parent) }
            var info = stat()
            if Darwin.fstatat(parent, url.lastPathComponent, &info, AT_SYMLINK_NOFOLLOW) != 0 {
                if errno == ENOENT { add(.offline, "source.offline", "The recorded source is offline. Its historical receipt was retained.", evidence: evidence); return }
                throw CaseIntegrityAuditError.unsafe
            }
            guard info.st_mode & S_IFMT == S_IFREG else { throw CaseIntegrityAuditError.unsafe }
            guard info.st_size >= 0, info.st_size <= options.maximumSourceBytes - sourceBytes else {
                add(.unavailable, "source.unavailable", "Source rehash exceeds the aggregate selected-file byte budget.", evidence: evidence); return
            }
            let digest = try streamHash(url.lastPathComponent, parent: parent, budget: .source)
            try afterSourceRead(evidence)
            try EvidenceViewFiles.validateDirectory(url.deletingLastPathComponent(), descriptor: parent, searchOnly: true)
            if digest.size == evidence.byteCount && digest.hash == evidence.sha256 {
                add(.pass, "source.verified", "Fresh selected-file bytes match the recorded size and SHA-256. This is not a logical image hash.", evidence: evidence, size: digest.size, digest: digest.hash)
            } else {
                add(.fail, "source.changed", "Fresh selected-file size or SHA-256 differs from the recorded receipt. The source and baseline were not rewritten.", evidence: evidence, size: digest.size, digest: digest.hash)
            }
        } catch is CancellationError { throw CancellationError() }
        catch CaseIntegrityAuditError.limit { throw CaseIntegrityAuditError.limit }
        catch CaseIntegrityAuditError.changed { add(.fail, "source.changed", "Source identity changed while being read; no fresh verification is established.", evidence: evidence) }
        catch ForensicsError.sourceChanged { add(.fail, "source.changed", "The recorded source parent changed while being read; no fresh verification is established.", evidence: evidence) }
        catch CaseIntegrityAuditError.unsafe { add(.fail, "source.unsafe", "Source is not a safe regular file; symbolic links and nonregular inputs were not followed.", evidence: evidence) }
        catch {
            // Missing ancestors can mean offline media; do not resolve any links
            // merely to make a source appear online or silently follow a swap.
            if errno == ENOENT { add(.offline, "source.offline", "The recorded source or its parent is offline.", evidence: evidence) }
            else { add(.fail, "source.unsafe", "Source could not be safely opened without following links; no fresh verification is established.", evidence: evidence) }
        }
    }

    private mutating func walk(_ directory: Int32, path: [String], depth: Int) throws {
        guard depth <= 6 else { throw CaseIntegrityAuditError.limit }
        var before = stat()
        guard Darwin.fstat(directory, &before) == 0 else { throw CaseIntegrityAuditError.unsafe }
        let names = try names(in: directory)
        for name in names {
            try tick("Checking case metadata")
            if path.isEmpty && ["manifest.json", ".case.lock"].contains(name) { continue }
            files += 1
            guard files <= options.maximumFiles else { throw CaseIntegrityAuditError.limit }
            let parts = path + [name]
            observedStoragePaths.insert(parts.joined(separator: "/"))
            var metadata = stat()
            guard Darwin.fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else { throw CaseIntegrityAuditError.changed }
            if metadata.st_mode & S_IFMT == S_IFDIR {
                guard knownDirectory(parts) else {
                    add(.unavailable, "storage.unrecognized", "Unrecognized or derived store was skipped; this audit does not validate its schema.", path: knownLabel(parts)); continue
                }
                let child = Darwin.openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw CaseIntegrityAuditError.unsafe }
                defer { Darwin.close(child) }
                try walk(child, path: parts, depth: depth + 1)
                var opened = stat(), current = stat()
                guard Darwin.fstat(child, &opened) == 0, Darwin.fstatat(directory, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                      current.st_mode & S_IFMT == S_IFDIR, current.st_dev == opened.st_dev, current.st_ino == opened.st_ino else {
                    throw CaseIntegrityAuditError.changed
                }
            } else if metadata.st_mode & S_IFMT != S_IFREG || metadata.st_nlink != 1 {
                unsafeStoragePaths.insert(parts.joined(separator: "/"))
                add(.fail, "storage.unsafe", "Symbolic links, hard-linked records and nonregular items are not followed.", path: knownLabel(parts))
            } else if name.hasPrefix(".") {
                add(.unavailable, "storage.staging", "Unrecognized temporary metadata was preserved and skipped.", path: knownLabel(parts))
            } else {
                do { try auditFile(name, parent: directory, parts: parts) }
                catch is CancellationError { throw CancellationError() }
                catch CaseIntegrityAuditError.limit { throw CaseIntegrityAuditError.limit }
                catch CaseIntegrityAuditError.unsupported {
                    unsupportedStoragePaths.insert(parts.joined(separator: "/"))
                    add(.unavailable, "metadata.schema.unsupported", "Unknown schema; original record was preserved.", path: knownLabel(parts))
                }
                catch { add(.fail, "metadata.invalid", "Record validation, checksum, identifier or source binding failed.", path: knownLabel(parts)) }
            }
        }
        var after = stat()
        guard Darwin.fstat(directory, &after) == 0, SourceIdentity(before) == SourceIdentity(after) else { throw CaseIntegrityAuditError.changed }
    }

    private func knownDirectory(_ parts: [String]) -> Bool {
        guard let kind = parts.first else { return true }
        if ["analyses", "findings", "extractions", "comparisons", "filesystem", "filesystem-jobs", "migrations"].contains(kind) { return parts.count == 1 }
        if kind == "optical" || kind == "apfs" {
            switch parts.count {
            case 1: return true
            case 2: return UUID(uuidString: parts[1]) != nil
            case 3: return parts[2] == "generations"
            case 4: return UUID(uuidString: parts[3]) != nil
            default: return false
            }
        }
        if kind == "recovery" {
            return parts.count == 1 || (parts.count == 2 && UUID(uuidString: parts[1]) != nil)
                || (parts.count == 3 && UUID(uuidString: parts[2]) != nil)
                || (parts.count == 4 && parts[3] == "files")
        }
        if kind == "recovery-notes" {
            return parts.count == 1 || (parts.count == 2 && UUID(uuidString: parts[1]) != nil)
                || (parts.count == 3 && UUID(uuidString: parts[2]) != nil)
        }
        return false
    }

    private func knownLabel(_ parts: [String]) -> String? {
        // Unknown names may contain private strings; retain only declared store
        // labels and valid UUID filenames in the default exportable receipt.
        guard parts.allSatisfy({ ["analyses", "findings", "extractions", "comparisons", "filesystem", "filesystem-jobs", "optical", "apfs", "recovery", "recovery-notes", "generations", "migrations", "files", "latest.json", "result.json", "checksum.json", "derived-content-index.json"].contains($0)
            || UUID(uuidString: $0.replacingOccurrences(of: ".json", with: "")) != nil }) else { return nil }
        return parts.joined(separator: "/")
    }

    private mutating func auditFile(_ name: String, parent: Int32, parts: [String]) throws {
        let path = parts.joined(separator: "/")
        let kind = parts[0]
        if parts.count == 5, kind == "recovery", parts[3] == "files", UUID(uuidString: name) != nil {
            payloads[path] = try streamHash(name, parent: parent, budget: .payload); return
        }
        let recognized = (parts.count == 1 && name == "derived-content-index.json")
            || (parts.count == 2 && ["filesystem", "filesystem-jobs", "analyses", "findings", "extractions", "comparisons", "migrations"].contains(kind)
            && name.hasSuffix(".json") && UUID(uuidString: String(name.dropLast(5))) != nil)
            || (["optical", "apfs"].contains(kind) && ((parts.count == 3 && name == "latest.json")
                || (parts.count == 5 && ["result.json", "checksum.json"].contains(name))))
            || (kind == "recovery" && parts.count == 4 && name == "result.json")
            || (kind == "recovery-notes" && parts.count == 4 && name.hasSuffix(".json") && UUID(uuidString: String(name.dropLast(5))) != nil)
        guard recognized else { add(.unavailable, "storage.unrecognized", "Unrecognized or derived file was preserved and skipped.", path: knownLabel(parts)); return }
        let maximum: Int64 = kind == "recovery-notes" ? 65_536 : (kind == "migrations" ? 16 * 1_048_576 : (["filesystem", "filesystem-jobs"].contains(kind) || (kind == "apfs" && name == "result.json") ? 64 * 1_048_576 :
            (["analyses", "findings", "extractions", "comparisons"].contains(kind) ? 1_048_576 :
                (name == "checksum.json" || name == "latest.json" ? 4_096 : 32 * 1_048_576))))
        let bytes = try read(name, parent: parent, maximum: maximum)
        metadataDigests[path] = hash(bytes)
        metadataSizes[path] = bytes.count
        try schema(bytes)
        if kind == "apfs" {
            guard let current = manifest, let evidenceID = UUID(uuidString: parts[1]),
                  let evidence = current.evidence.first(where: { $0.id == evidenceID }) else { throw CaseIntegrityAuditError.invalid }
            if name == "result.json" {
                guard let generationID = UUID(uuidString: parts[3]) else { throw CaseIntegrityAuditError.invalid }
                let value = try JSONDecoder().decode(APFSInspectionResult.self, from: bytes)
                try APFSMountedImageAdapter.validate(value, evidence: evidence)
                apfsResults[parts.dropLast().joined(separator: "/")] = (hash(bytes), bytes.count, evidenceID, generationID, value.coverage)
                if let job = current.provenance?.jobs.first(where: { $0.id == generationID }) {
                    let receipt = APFSCacheReceipt(caseID: current.id, evidenceID: evidenceID,
                        generationID: generationID, resultSHA256: hash(bytes), relativePath: path,
                        serializedByteCount: bytes.count, coverage: value.coverage)
                    var expected = try APFSResultStore.jobProvenance(result: value, receipt: receipt,
                        startedAt: job.startedAt, completedAt: job.completedAt)
                    if job.artifactByteCount == nil { expected = expected.preservingUnknownArtifactSize() }
                    guard expected == job else { throw CaseIntegrityAuditError.invalid }
                    validAPFSJobArtifacts.insert(generationID)
                }
            } else {
                let value = try JSONDecoder().decode(APFSCacheReceipt.self, from: bytes)
                let resultPath = "apfs/" + evidenceID.uuidString.lowercased() + "/generations/" + value.generationID.uuidString.lowercased() + "/result.json"
                guard value.schemaVersion == 1, value.caseID == current.id, value.evidenceID == evidenceID,
                      (1...APFSResultStore.maximumResultBytes).contains(value.serializedByteCount),
                      EngineValidation.validHash(value.resultSHA256), value.relativePath == resultPath else { throw CaseIntegrityAuditError.invalid }
                if name == "latest.json" { apfsLatest[parts.dropLast().joined(separator: "/")] = value }
                else {
                    guard value.generationID == UUID(uuidString: parts[3]) else { throw CaseIntegrityAuditError.invalid }
                    apfsChecksums[parts.dropLast().joined(separator: "/")] = value
                }
            }
            add(.pass, "metadata.valid", "APFS historical metadata schema, allocated-view limits and selected-file source scope are valid; evidence was not mounted or freshly verified.", path: path, size: Int64(bytes.count), digest: hash(bytes))
            return
        }
        if kind == "filesystem-jobs" {
            let value = try CaseWorkCoding.decode(EnumerationResult.self, bytes)
            try EngineValidation.result(value)
            guard let jobID = UUID(uuidString: String(name.dropLast(5))), let current = manifest,
                  value.sourcePaths.allSatisfy({ !FileAccess.isInside(URL(fileURLWithPath: $0), directory: forensicCase.bundleURL) }) else {
                throw CaseIntegrityAuditError.invalid
            }
            guard let job = current.provenance?.jobs.first(where: { $0.id == jobID }) else {
                add(.unavailable, "job.artifact.unrecorded", "This complete immutable listing has no recorded manifest job. It may be an interrupted save; it was preserved and is not claimed as a verified job.", path: path, size: Int64(bytes.count), digest: hash(bytes))
                return
            }
            guard job.kind == "filesystem.enumeration", let evidence = current.evidence.first(where: { $0.id == job.evidenceID }),
                  value.sourcePaths.contains(evidence.sourcePath), value.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
                  value.sourceIdentities.first(where: { $0.path == evidence.sourcePath }).map({ $0.size == evidence.byteCount }) ?? true else {
                throw CaseIntegrityAuditError.invalid
            }
            let expected = try CaseJobProvenance.enumeration(id: jobID, evidence: evidence, result: value,
                startedAt: job.startedAt, executableSHA256: job.component.executableSHA256,
                artifactRelativePath: path, artifactSHA256: hash(bytes), artifactByteCount: job.artifactByteCount)
            guard expected == job else { throw CaseIntegrityAuditError.invalid }
            validFilesystemJobArtifacts.insert(jobID)
            add(.pass, "job.listing.valid", "Immutable listing bytes, filename/job identity, selected evidence, component/options, ordered source hashes, status and warnings match their exact historical manifest job.", path: path, size: Int64(bytes.count), digest: hash(bytes))
            return
        }
        if kind == "migrations" {
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            let original = try decoder.decode(CaseManifest.self, from: bytes)
            try validateManifest(original)
            guard original.schemaVersion == 1, let current = manifest, original.id == current.id else { throw CaseIntegrityAuditError.invalid }
            if let receipt = current.provenance?.migration, receipt.backupFilename == name {
                guard bytes.count == receipt.originalManifestByteCount, hash(bytes) == receipt.originalManifestSHA256,
                      original.name == current.name, original.createdAt == current.createdAt,
                      current.evidence.starts(with: original.evidence) else { throw CaseIntegrityAuditError.invalid }
                migrationBackupVerified = true
                add(.pass, "migration.backup.valid", "The exact pre-migration manifest matches its immutable receipt; no rollback or source modification was performed.", path: path, size: Int64(bytes.count), digest: hash(bytes))
            } else {
                add(.historical, "migration.backup.historical", "A prior or interrupted migration's original manifest backup is historical metadata; it does not establish a current migration.", path: path, size: Int64(bytes.count), digest: hash(bytes))
            }
            return
        }
        if name == "derived-content-index.json", parts.count == 1 {
            let snapshot = try CaseWorkCoding.decode(CaseContentIndexSnapshot.self, bytes)
            try snapshot.validate()
            guard let manifest, snapshot.caseID == manifest.id else { throw CaseIntegrityAuditError.invalid }
            do { try CaseContentIndexStore.validateScope(snapshot, manifest: manifest) }
            catch {
                add(.unavailable, "derived.index.stale", "The derived index is valid historical metadata but no longer matches the full current evidence set. Rebuild explicitly before treating search coverage as current.", path: path, size: Int64(bytes.count), digest: hash(bytes))
                return
            }
            add(.pass, "derived.index.valid", "Derived index schema, locator/text digests and selected-source bindings are consistent. Search coverage may still be partial; evidence bytes were not redecoded by this check.", path: path, size: Int64(bytes.count), digest: hash(bytes))
            return
        } else if kind == "comparisons" {
            let value = try CaseWorkCoding.decode(MultiEvidenceAnalysisRecord.self, bytes)
            try value.validate()
            guard value.id == UUID(uuidString: String(name.dropLast(5))) else { throw CaseIntegrityAuditError.invalid }
            for file in value.context.files { try validate(file.binding) }
            var parentRecord: MultiEvidenceAnalysisRecord?
            if let parentID = value.parentRecordID {
                let parentBytes = try read(parentID.uuidString.lowercased() + ".json", parent: parent, maximum: 1_048_576)
                try schema(parentBytes)
                let record = try CaseWorkCoding.decode(MultiEvidenceAnalysisRecord.self, parentBytes); try record.validate()
                for file in record.context.files { try validate(file.binding) }
                guard record.id == parentID, record.requestSHA256 == value.parentRequestSHA256,
                      record.context.files.map(\.binding) == value.context.files.map(\.binding),
                      record.context.files.map(\.contentSHA256) == value.context.files.map(\.contentSHA256),
                      record.context.files.map(\.selectedRanges) == value.context.files.map(\.selectedRanges),
                      record.context.files.map(\.redactedRanges) == value.context.files.map(\.redactedRanges),
                      record.context.files.map({ $0.segments.map(\.disclosedSHA256) }) == value.context.files.map({ $0.segments.map(\.disclosedSHA256) }) else { throw CaseIntegrityAuditError.invalid }
                parentRecord = record
            }
            if value.retention == .full {
                guard value.prompt == (try MultiEvidencePrompt.make(context: value.context, question: value.question, parent: parentRecord)) else { throw CaseIntegrityAuditError.invalid }
            }
            comparisonParents[value.id] = .init(parent: value.parentRecordID)
        } else if kind == "filesystem" {
            let value = try EngineFilesystemCacheCoding.decode(bytes)
            try EngineValidation.result(value)
            guard let evidence = manifest?.evidence.first(where: { $0.id == UUID(uuidString: String(name.dropLast(5))) }),
                  value.sourcePaths.contains(evidence.sourcePath), value.sourceFileHashes[evidence.sourcePath] == evidence.sha256,
                  value.sourceIdentities.first(where: { $0.path == evidence.sourcePath }).map({ $0.size == evidence.byteCount }) ?? true,
                  value.sourcePaths.allSatisfy({ !FileAccess.isInside(URL(fileURLWithPath: $0), directory: forensicCase.bundleURL) }) else { throw CaseIntegrityAuditError.invalid }
        } else if ["analyses", "findings", "extractions"].contains(kind) {
            let binding: CaseWorkBinding; let id: UUID; var finding: FindingRecord?
            switch kind {
            case "analyses": let value = try CaseWorkCoding.decode(AnalysisRecord.self, bytes); try value.validate(); binding = value.binding; id = value.id
            case "findings":
                let value = try CaseWorkCoding.decode(FindingRecord.self, bytes); try value.validate(); binding = value.binding; id = value.id
                finding = value
            default: let value = try CaseWorkCoding.decode(ExtractionRecord.self, bytes); try value.validate(); binding = value.binding; id = value.id
            }
            guard id == UUID(uuidString: String(name.dropLast(5))) else { throw CaseIntegrityAuditError.invalid }
            try validate(binding)
            if let finding {
                let group = binding.evidenceID.uuidString + ":" + binding.locatorSHA256
                findingChains[group, default: []].append(.init(id: finding.id, finding: finding.findingID, revision: finding.revision, previous: finding.previousRevisionID))
            }
        } else if kind == "optical", name == "result.json" {
            let value = try JSONDecoder().decode(UDFInspectionResult.self, from: bytes)
            try UDFResultStore.validateResult(value)
            try validateSource(caseID: value.caseID, evidenceID: value.sourceEvidenceID, hash: value.sourceSHA256, size: value.sourceByteCount)
            guard value.jobID == UUID(uuidString: parts[3]), value.sourceEvidenceID == UUID(uuidString: parts[1]) else { throw CaseIntegrityAuditError.invalid }
            opticalResults[parts.dropLast().joined(separator: "/")] = (hash(bytes), value.jobID, value.sourceEvidenceID)
        } else if kind == "optical" {
            let value = try JSONDecoder().decode(IntegrityGenerationPointer.self, from: bytes)
            guard value.caseID == manifest?.id, value.evidenceID == UUID(uuidString: parts[1]), EngineValidation.validHash(value.resultSHA256) else { throw CaseIntegrityAuditError.invalid }
            if name == "latest.json" { opticalLatest[parts.dropLast().joined(separator: "/")] = value }
            else {
                guard value.jobID == UUID(uuidString: parts[3]) else { throw CaseIntegrityAuditError.invalid }
                opticalChecksums[parts.dropLast().joined(separator: "/")] = value
            }
        } else if kind == "recovery-notes" {
            let value = try JSONDecoder().decode(RecoveryAnnotationRevision.self, from: bytes)
            try value.annotation.validate()
            let generationKey = parts[1] + "/" + parts[2]
            guard value.id == UUID(uuidString: String(name.dropLast(5))), value.caseID == manifest?.id,
                  value.evidenceID == UUID(uuidString: parts[1]), value.jobID == UUID(uuidString: parts[2]),
                  (1...10_000).contains(value.revision), (value.revision == 1) == (value.previousRevisionID == nil),
                  value.previousRevisionID != value.id, EngineValidation.validHash(value.resultSHA256),
                  EngineValidation.validHash(value.manifestSHA256), value.savedAt.timeIntervalSince1970.isFinite,
                  let result = recoveryBindings[generationKey], result.digest == value.resultSHA256,
                  result.artifacts.contains(value.annotation.artifactID) else { throw CaseIntegrityAuditError.invalid }
            let group = generationKey + "/" + value.annotation.artifactID.uuidString.lowercased()
            recoveryNoteChains[group, default: []].append(.init(id: value.id, revision: value.revision, previous: value.previousRevisionID, savedAt: value.savedAt))
        } else if kind == "recovery" {
            let value = try JSONDecoder().decode(CarvingResult.self, from: bytes); try value.validate()
            try validateSource(caseID: value.caseID, evidenceID: value.sourceEvidenceID, hash: value.sourceSHA256, size: value.sourceByteCount)
            guard value.jobID == UUID(uuidString: parts[2]), value.sourceEvidenceID == UUID(uuidString: parts[1]) else { throw CaseIntegrityAuditError.invalid }
            recoveryBindings[parts[1] + "/" + parts[2]] = (try RecoveryAnnotationStore.resultDigest(value), Set(value.artifacts.map(\.id)))
            for artifact in value.artifacts {
                expectedPayloads[parts.dropLast().joined(separator: "/") + "/" + artifact.relativePath] = (artifact.byteCount, artifact.sha256)
            }
        }
        add(.pass, "metadata.valid", "Known schema and recorded identifiers, internal digests and source binding are valid. This is historical metadata, not fresh source verification.", path: path, size: Int64(bytes.count), digest: hash(bytes))
    }

    private func validate(_ binding: CaseWorkBinding) throws {
        guard binding.caseID == manifest?.id, let evidence = manifest?.evidence.first(where: { $0.id == binding.evidenceID }),
              evidence.sha256 == binding.selectedContainerHash.sha256, evidence.hashScope == binding.selectedContainerHash.scope,
              evidence.byteCount == binding.selectedContainerByteCount else { throw CaseIntegrityAuditError.invalid }
    }

    /// Validate the held manifest bytes rather than reopening the bundle by
    /// pathname. Reopening could follow a concurrently replaced ancestor.
    private func validateManifest(_ current: CaseManifest) throws {
        let name = current.name
        guard [1, 2].contains(current.schemaVersion), (current.schemaVersion == 1) == (current.provenance == nil), !name.isEmpty, name.count <= 100, name.utf8.count <= 240,
              name != ".", name != "..", !name.contains("/"), !name.contains("\\"), !name.contains(":"),
              !name.hasSuffix("."), !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              current.createdAt.timeIntervalSince1970.isFinite else { throw CaseIntegrityAuditError.invalid }
        if let provenance = current.provenance { try provenance.validate(evidence: current.evidence) }
        var identifiers = Set<UUID>(), paths = Set<String>()
        for evidence in current.evidence {
            guard identifiers.insert(evidence.id).inserted, paths.insert(evidence.sourcePath).inserted,
                  evidence.sourcePath.hasPrefix("/"), evidence.sourcePath != "/", !evidence.sourcePath.utf8.contains(0),
                  evidence.sourcePath == URL(fileURLWithPath: evidence.sourcePath).standardizedFileURL.path,
                  evidence.byteCount >= 0, EngineValidation.validHash(evidence.sha256),
                  evidence.hashScope == FileHashScope.selectedFileBytes, evidence.addedAt.timeIntervalSince1970.isFinite,
                  !FileAccess.isInside(URL(fileURLWithPath: evidence.sourcePath), directory: forensicCase.bundleURL) else {
                throw CaseIntegrityAuditError.invalid
            }
        }
    }

    private func validateSource(caseID: UUID, evidenceID: UUID, hash: String, size: Int64) throws {
        guard caseID == manifest?.id, let evidence = manifest?.evidence.first(where: { $0.id == evidenceID }),
              evidence.sha256 == hash, evidence.byteCount == size, evidence.container == .raw,
              evidence.hashScope == FileHashScope.selectedFileBytes else { throw CaseIntegrityAuditError.invalid }
    }

    private mutating func reconcile() throws {
        if let provenance = manifest?.provenance {
            if !migrationBackupVerified { add(.fail, "migration.backup.missing", "The declared exact pre-migration manifest backup was not verified.", path: "migrations") }
            for job in provenance.jobs {
                try tick("Checking job provenance")
                if let path = job.artifactRelativePath, let expected = job.artifactSHA256 {
                    var sizeChanged = false
                    if let declared = job.artifactByteCount {
                        if let actual = metadataSizes[path] {
                            if actual != declared {
                                add(.fail, "job.artifact.sizeChanged", "The stored artifact size differs from its historical producer receipt; bytes were preserved.",
                                    path: knownLabel(path.split(separator: "/").map(String.init)), size: Int64(actual))
                                sizeChanged = true
                            }
                        } else if let actual = payloads[path]?.size, actual != Int64(declared) {
                            add(.fail, "job.artifact.sizeChanged", "The stored payload size differs from its historical producer receipt; bytes were preserved.",
                                path: knownLabel(path.split(separator: "/").map(String.init)), size: actual)
                            sizeChanged = true
                        }
                    } else {
                        add(.unavailable, "job.artifact.sizeUnavailable", "This older historical job did not record an artifact byte count. No expected size was inferred or persisted.",
                            path: knownLabel(path.split(separator: "/").map(String.init)))
                    }
                    if let actual = metadataDigests[path] ?? payloads[path]?.hash, actual != expected {
                        add(.fail, "job.artifact.changed", "The stored job artifact differs from its recorded digest; historical bytes were preserved.",
                            path: knownLabel(path.split(separator: "/").map(String.init)), digest: actual)
                        continue
                    }
                    if sizeChanged { continue }
                    let generationPath = path.split(separator: "/").dropLast().joined(separator: "/")
                    if unsupportedStoragePaths.contains(path)
                        || (path.hasPrefix("apfs/") && unsupportedStoragePaths.contains(generationPath + "/checksum.json")) {
                        add(.unavailable, "job.artifact.unavailable", "The declared job artifact uses an unsupported schema and was preserved without claiming its provenance.",
                            path: knownLabel(path.split(separator: "/").map(String.init)))
                        continue
                    }
                    if (path.hasPrefix("filesystem-jobs/") && !validFilesystemJobArtifacts.contains(job.id))
                        || (path.hasPrefix("apfs/") && (!validAPFSJobArtifacts.contains(job.id) || !apfsGenerationVerified(generationPath))) {
                        let observed = observedStoragePaths.contains(path)
                            || unsafeStoragePaths.contains(where: { path.hasPrefix($0 + "/") })
                        add(.fail, observed ? "job.artifact.invalid" : "job.artifact.missing",
                            observed ? "The declared immutable job artifact was observed but failed safe schema/result/provenance validation." : "The declared immutable job artifact is absent from the fully visited supported store.",
                            path: knownLabel(path.split(separator: "/").map(String.init)))
                        continue
                    }
                    if let actual = metadataDigests[path] ?? payloads[path]?.hash {
                        add(actual == expected ? .pass : .fail, actual == expected ? "job.artifact.verified" : "job.artifact.changed",
                            actual == expected ? "Job component, reconstructible options and ordered source hashes bind this exact stored artifact." : "The stored job artifact differs from its recorded digest; historical bytes were preserved.", path: path, digest: actual)
                    } else { add(.unavailable, "job.artifact.unavailable", "The declared job artifact was not verified within this audit's supported store scope or budgets.", path: nil) }
                } else {
                    add(.historical, "job.provenance.historical", "Job component, reconstructible options, terminal status, warnings and ordered source hashes are historical; no output byte digest was declared.")
                }
            }
        }
        for (path, expected) in expectedPayloads {
            try tick("Verifying recovered payload receipts")
            guard let actual = payloads[path] else { add(.fail, "payload.missing", "A recorded recovered payload is missing or could not be safely hashed.", path: path); continue }
            let matches = actual.size == expected.size && actual.hash == expected.hash
            add(matches ? .pass : .fail, matches ? "payload.verified" : "payload.changed", matches
                ? "Recovered payload bytes match their historical result size and SHA-256."
                : "Recovered payload bytes differ from their historical receipt; original files were preserved.", path: path, size: actual.size, digest: actual.hash)
        }
        for path in payloads.keys where expectedPayloads[path] == nil {
            add(.fail, "payload.unreferenced", "Recovered payload has no validated result reference.", path: path)
        }
        for (path, result) in apfsResults {
            try tick("Checking APFS generation receipts")
            if unsupportedStoragePaths.contains(path + "/checksum.json") {
                add(.unavailable, "apfs.checksum.unavailable", "The immutable APFS checksum uses an unsupported schema; result bytes are preserved without claiming its receipt relation.", path: path + "/checksum.json")
                continue
            }
            let matches = apfsGenerationVerified(path)
            add(matches ? .pass : .fail, matches ? "apfs.checksum.valid" : "apfs.checksum.invalid",
                matches ? "Exact immutable APFS result bytes, size, generation/source identity and coverage match their historical checksum receipt." : "The immutable APFS result has no matching checksum receipt for its exact bytes, size, generation/source scope and coverage.",
                path: path + "/result.json", size: Int64(result.size), digest: result.hash)
        }
        for path in apfsChecksums.keys where apfsResults[path] == nil {
            let unsupported = unsupportedStoragePaths.contains(path + "/result.json")
            add(unsupported ? .unavailable : .fail, unsupported ? "apfs.checksum.unavailable" : "apfs.checksum.invalid",
                unsupported ? "The referenced APFS result uses an unsupported schema; its checksum relation remains unverified." : "APFS checksum has no safely validated result generation.", path: path + "/checksum.json")
        }
        let apfsNamespaces = Set((Array(apfsResults.keys) + Array(apfsChecksums.keys)).map { $0.split(separator: "/").prefix(2).joined(separator: "/") })
        for path in apfsNamespaces where apfsLatest[path] == nil {
            let latest = path + "/latest.json"
            let unsupported = unsupportedStoragePaths.contains(latest)
            add(unsupported ? .unavailable : .fail, unsupported ? "apfs.pointer.unavailable" : "apfs.pointer.invalid",
                unsupported ? "The latest APFS pointer uses an unsupported schema; immutable generations were preserved." : "The APFS generation namespace has no safely validated latest convenience pointer; immutable generations were preserved.", path: latest)
        }
        for (path, pointer) in apfsLatest {
            try tick("Checking APFS latest pointers")
            let generation = path + "/generations/" + pointer.generationID.uuidString.lowercased()
            if unsupportedStoragePaths.contains(generation + "/result.json")
                || unsupportedStoragePaths.contains(generation + "/checksum.json") {
                add(.unavailable, "apfs.pointer.unavailable", "The latest APFS pointer depends on an unsupported result/checksum schema; its generation relation remains unverified.", path: path + "/latest.json")
                continue
            }
            let result = apfsResults[generation]
            let matches = apfsChecksums[generation] == pointer && result?.hash == pointer.resultSHA256
                && result?.size == pointer.serializedByteCount && result?.coverage == pointer.coverage
                && result?.evidence == pointer.evidenceID && result?.generation == pointer.generationID
            add(matches ? .pass : .fail, matches ? "apfs.pointer.valid" : "apfs.pointer.invalid",
                matches ? "The mutable latest APFS pointer resolves to its validated immutable checksum/result generation." : "The latest APFS pointer does not resolve to its declared checksum/result generation.", path: path + "/latest.json")
        }
        for (path, result) in opticalResults {
            let pointer = opticalChecksums[path]
            let matches = pointer?.resultSHA256 == result.hash && pointer?.jobID == result.job && pointer?.evidenceID == result.evidence
            add(matches ? .pass : .fail, matches ? "optical.checksum.valid" : "optical.checksum.invalid",
                matches ? "Immutable UDF result bytes match their checksum receipt." : "Immutable UDF checksum receipt is missing or differs.", path: path + "/result.json")
        }
        for path in opticalChecksums.keys where opticalResults[path] == nil {
            add(.fail, "optical.checksum.invalid", "UDF checksum has no validated result generation.", path: path + "/checksum.json")
        }
        for (path, pointer) in opticalLatest {
            let generation = path + "/generations/" + pointer.jobID.uuidString.lowercased()
            let matches = opticalChecksums[generation] == pointer && opticalResults[generation]?.hash == pointer.resultSHA256
            add(matches ? .pass : .fail, matches ? "optical.pointer.valid" : "optical.pointer.invalid",
                matches ? "Latest UDF pointer resolves to a validated immutable generation." : "Latest UDF pointer does not resolve to its checksum and result.", path: path + "/latest.json")
        }
        for (_, chain) in findingChains {
            try tick("Checking note revision chains")
            let ordered = chain.sorted { $0.revision < $1.revision }
            let matches = ordered.enumerated().allSatisfy { index, link in
                link.revision == index + 1 && link.finding == ordered.first?.finding
                    && link.previous == (index == 0 ? nil : ordered[index - 1].id)
            }
            add(matches ? .pass : .fail, matches ? "finding.chain.valid" : "finding.chain.invalid",
                matches ? "Examiner note revisions form one complete immutable chain." : "Examiner note history has missing, duplicated or branched revisions.", path: "findings")
        }
        for chain in recoveryNoteChains.values {
            try tick("Checking recovery assessment revision chains")
            let ordered = chain.sorted { $0.revision < $1.revision }
            let matches = ordered.enumerated().allSatisfy { index, link in
                link.revision == index + 1 && link.previous == (index == 0 ? nil : ordered[index - 1].id)
                    && (index == 0 || link.savedAt >= ordered[index - 1].savedAt)
            }
            add(matches ? .pass : .fail, matches ? "recovery.note.chain.valid" : "recovery.note.chain.invalid",
                matches ? "Recovery assessment revisions form complete immutable historical chains." : "Recovery assessment revisions are missing, duplicated, branched or out of order.", path: "recovery-notes")
        }
        var finished = Set<UUID>()
        for id in comparisonParents.keys where !finished.contains(id) {
            var chain = Set<UUID>(), cursor: UUID? = id, cyclic = false
            while let current = cursor, !finished.contains(current) {
                try tick("Checking comparison follow-up references")
                guard chain.insert(current).inserted else { cyclic = true; break }
                guard let link = comparisonParents[current] else { cyclic = true; break }
                cursor = link.parent
            }
            finished.formUnion(chain)
            if cyclic { add(.fail, "comparison.chain.invalid", "Comparison follow-up references are cyclic or point to an unavailable parent record.", path: "comparisons") }
        }
    }

    private func apfsGenerationVerified(_ path: String) -> Bool {
        guard let result = apfsResults[path], let receipt = apfsChecksums[path] else { return false }
        return receipt.caseID == manifest?.id && receipt.evidenceID == result.evidence
            && receipt.generationID == result.generation && receipt.resultSHA256 == result.hash
            && receipt.serializedByteCount == result.size && receipt.coverage == result.coverage
            && receipt.relativePath == path + "/result.json"
    }

    private func schema(_ bytes: Data, allowedVersions: [Int] = [1]) throws {
        struct Header: Decodable { let schemaVersion: Int }
        guard try allowedVersions.contains(JSONDecoder().decode(Header.self, from: bytes).schemaVersion) else { throw CaseIntegrityAuditError.unsupported }
    }

    private mutating func names(in directory: Int32) throws -> [String] {
        let copy = Darwin.dup(directory)
        guard copy >= 0 else { throw CaseIntegrityAuditError.unsafe }
        guard let stream = Darwin.fdopendir(copy) else { Darwin.close(copy); throw CaseIntegrityAuditError.unsafe }
        defer { Darwin.closedir(stream) }
        var values: [String] = []
        while true {
            try tick("Enumerating case records")
            errno = 0
            guard let entry = Darwin.readdir(stream) else {
                guard errno == 0 else { throw CaseIntegrityAuditError.unsafe }; break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            guard values.count < options.maximumFiles else { throw CaseIntegrityAuditError.limit }
            values.append(name)
        }
        return values.sorted()
    }

    private mutating func read(_ name: String, parent: Int32, maximum: Int64) throws -> Data {
        let fd = try FileAccess.openReadOnly(name, in: parent)
        defer { Darwin.close(fd) }
        let before = try FileAccess.identity(of: fd)
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0, info.st_nlink == 1 else { throw CaseIntegrityAuditError.unsafe }
        guard before.size <= maximum, before.size <= options.maximumMetadataBytes - metadataBytes else { throw CaseIntegrityAuditError.limit }
        var bytes = Data(); bytes.reserveCapacity(Int(before.size))
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while Int64(bytes.count) < before.size {
            try tick("Reading bounded metadata")
            let request = Int(min(Int64(buffer.count), before.size - Int64(bytes.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(fd, into: $0, count: request) }
            guard count > 0 else { throw CaseIntegrityAuditError.changed }
            bytes.append(contentsOf: buffer.prefix(count)); metadataBytes += Int64(count)
        }
        guard try FileAccess.identity(of: fd) == before, (try? FileAccess.identity(at: name, in: parent)) == before else { throw CaseIntegrityAuditError.changed }
        return bytes
    }

    private enum HashBudget: Equatable { case source, payload }
    private mutating func streamHash(_ name: String, parent: Int32, budget: HashBudget) throws -> (size: Int64, hash: String) {
        let fd = try FileAccess.openReadOnly(name, in: parent)
        defer { Darwin.close(fd) }
        let before = try FileAccess.identity(of: fd)
        var metadata = stat()
        guard Darwin.fstat(fd, &metadata) == 0, metadata.st_nlink == 1 else { throw CaseIntegrityAuditError.unsafe }
        let allowance = budget == .source ? options.maximumSourceBytes - sourceBytes : options.maximumPayloadBytes - payloadBytes
        guard before.size <= allowance else { throw CaseIntegrityAuditError.limit }
        var digest = SHA256(), completed: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while completed < before.size {
            try tick(budget == .source ? "Rehashing selected-file evidence bytes" : "Hashing recovered payload")
            let request = Int(min(Int64(buffer.count), before.size - completed))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(fd, into: $0, count: request) }
            guard count > 0 else { throw CaseIntegrityAuditError.changed }
            digest.update(data: Data(buffer.prefix(count))); completed += Int64(count)
            if budget == .source { sourceBytes += Int64(count) } else { payloadBytes += Int64(count) }
        }
        guard try FileAccess.identity(of: fd) == before, (try? FileAccess.identity(at: name, in: parent)) == before else { throw CaseIntegrityAuditError.changed }
        return (before.size, CaseWorkCoding.hex(digest.finalize()))
    }

    private func hash(_ bytes: Data) -> String { CaseWorkCoding.hex(SHA256.hash(data: bytes)) }
    private struct FindingLink { let id: UUID; let finding: UUID; let revision: Int; let previous: UUID? }
    private struct ComparisonLink { let parent: UUID? }
    private struct RecoveryNoteLink { let id: UUID; let revision: Int; let previous: UUID?; let savedAt: Date }
}
