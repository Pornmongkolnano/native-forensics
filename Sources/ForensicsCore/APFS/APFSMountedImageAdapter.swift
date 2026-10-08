import CryptoKit
import Darwin
import Foundation

/// Experimental allocated-file adapter using an owned read-only system mount.
/// No original source image is attached, repaired, unlocked or written in place.
public struct APFSMountedImageAdapter: Sendable {
    public let scratchRoot: URL?
    private let lifecycleObserver: (@Sendable (APFSReadLifecycleStage) -> Void)?
    private let snapshotMountDiagnostic: (@Sendable (APFSSnapshotMountDiagnostic) -> Void)?
    public init(scratchRoot: URL? = nil) { self.scratchRoot = scratchRoot; lifecycleObserver = nil; snapshotMountDiagnostic = nil }
    init(scratchRoot: URL?, lifecycleObserver: @escaping @Sendable (APFSReadLifecycleStage) -> Void) {
        self.scratchRoot = scratchRoot; self.lifecycleObserver = lifecycleObserver; snapshotMountDiagnostic = nil
    }
    /// Internal fixture-only hook. No production caller retains system stderr.
    init(scratchRoot: URL?, snapshotMountDiagnostic: @escaping @Sendable (APFSSnapshotMountDiagnostic) -> Void,
         lifecycleObserver: @escaping @Sendable (APFSReadLifecycleStage) -> Void) {
        self.scratchRoot = scratchRoot; self.lifecycleObserver = lifecycleObserver
        self.snapshotMountDiagnostic = snapshotMountDiagnostic
    }

    /// Discovers source-bound metadata without unlocking APFS volumes, mounting
    /// a filesystem or traversing its content. A wrapper key can still be needed.
    public func discoverVolumes(evidence: EvidenceRecord, passphrase: APFSPassphrase? = nil,
                                options: APFSReadOptions = .init()) async throws -> APFSVolumeCatalogResult {
        let cancellation = APFSCancellation()
        return try await withTaskCancellationHandler {
            if Task.isCancelled { cancellation.cancel() }
            return try await BlockingWork.run {
                try options.validate()
                guard options.selectedSnapshotUUID == nil else { throw APFSReadError.invalidOptions }
                cancellation.setDeadline(seconds: options.jobTimeoutSeconds); try cancellation.check()
                let attachment = try APFSOwnedMount(evidence: evidence, options: options, scratchRoot: scratchRoot,
                    passphrase: passphrase, volumePassphrase: nil, cancellation: cancellation,
                    observer: lifecycleObserver, snapshotMountDiagnostic: snapshotMountDiagnostic, discoverOnly: true)
                do {
                    try attachment.verifySources(); try attachment.close(); try cancellation.check()
                    let result = APFSVolumeCatalogResult(evidenceID: evidence.id, containerSHA256: evidence.sha256,
                        containerByteCount: evidence.byteCount, driverVersion: ProcessInfo.processInfo.operatingSystemVersionString,
                        options: options, containerEncryption: attachment.encryption, volumes: attachment.catalogVolumes,
                        volumeGroupInventoryAvailable: attachment.groupInventoryAvailable, warnings: attachment.catalogWarnings)
                    try result.validate(evidence: evidence)
                    return result
                } catch {
                    do { try attachment.close() } catch { throw APFSReadError.cleanupIncomplete }
                    throw error
                }
            }
        } onCancel: { cancellation.cancel() }
    }

    public func inspect(evidence: EvidenceRecord, passphrase: APFSPassphrase? = nil, volumePassphrase: APFSPassphrase? = nil,
                        options: APFSReadOptions = .init()) async throws -> APFSInspectionResult {
        let cancellation = APFSCancellation()
        return try await withTaskCancellationHandler {
            if Task.isCancelled { cancellation.cancel() }
            return try await BlockingWork.run {
                try options.validate(); cancellation.setDeadline(seconds: options.jobTimeoutSeconds); try cancellation.check()
                let mounted = try APFSOwnedMount(evidence: evidence, options: options, scratchRoot: scratchRoot,
                                                passphrase: passphrase, volumePassphrase: volumePassphrase,
                                                cancellation: cancellation, observer: lifecycleObserver,
                                                snapshotMountDiagnostic: snapshotMountDiagnostic)
                do {
                    let walker = APFSDirectoryWalker(mount: mounted, options: options, cancellation: cancellation)
                    let entries = try walker.enumerate()
                    let inventory = try mounted.snapshots()
                    try mounted.verifySources()
                    try mounted.close()
                    try cancellation.check()
                    let result = APFSInspectionResult(schemaVersion: 1, evidenceID: evidence.id,
                        containerSHA256: evidence.sha256, containerByteCount: evidence.byteCount,
                        hashScope: FileHashScope.selectedFileBytes, driver: "apple-system-readonly-apfs-v1",
                        driverVersion: ProcessInfo.processInfo.operatingSystemVersionString, options: options,
                        volumeUUID: mounted.volumeUUID, containerEncryption: mounted.encryption,
                        volumeEncryption: mounted.volumeEncryption,
                        entries: entries, snapshots: inventory.entries, snapshotInventoryAvailable: inventory.available,
                        coverage: walker.partial ? .partialAllocatedView : .completeAllocatedView,
                        warnings: Array(Set(walker.warnings + inventory.warnings)).sorted(),
                        selectedSnapshot: mounted.selectedSnapshot)
                    try Self.validate(result, evidence: evidence)
                    return result
                } catch {
                    do { try mounted.close() } catch { throw APFSReadError.cleanupIncomplete }
                    throw error
                }
            }
        } onCancel: { cancellation.cancel() }
    }

    public func readVerifiedFile(evidence: EvidenceRecord, inspection: APFSInspectionResult,
                                 entry: APFSFileEntry, passphrase: APFSPassphrase? = nil,
                                 volumePassphrase: APFSPassphrase? = nil) async throws -> APFSVerifiedFile {
        let cancellation = APFSCancellation()
        return try await withTaskCancellationHandler {
            if Task.isCancelled { cancellation.cancel() }
            return try await BlockingWork.run {
                try Self.validate(inspection, evidence: evidence)
                cancellation.setDeadline(seconds: inspection.options.jobTimeoutSeconds); try cancellation.check()
                guard entry.kind == .regular, let expectedHash = entry.sha256,
                      entry.byteCount <= inspection.options.maximumFileBytes,
                      inspection.entries.contains(entry) else { throw APFSReadError.fileUnavailable }
                let mounted = try APFSOwnedMount(evidence: evidence, options: inspection.options, scratchRoot: scratchRoot,
                                                passphrase: passphrase, volumePassphrase: volumePassphrase,
                                                cancellation: cancellation, observer: lifecycleObserver,
                                                snapshotMountDiagnostic: snapshotMountDiagnostic)
                do {
                    guard mounted.volumeUUID == inspection.volumeUUID,
                          mounted.encryption == inspection.containerEncryption,
                          mounted.volumeEncryption == inspection.volumeEncryption,
                          mounted.selectedSnapshot == inspection.selectedSnapshot else { throw APFSReadError.invalidResult }
                    let data = try mounted.read(entry)
                    guard APFSHash.digest(data) == expectedHash else { throw APFSReadError.sourceChanged }
                    try mounted.verifySources()
                    try mounted.close()
                    try cancellation.check()
                    return APFSVerifiedFile(data: data, sha256: expectedHash, containerSHA256: evidence.sha256,
                                            volumeUUID: inspection.volumeUUID, relativePath: entry.relativePath,
                                            selectedSnapshot: inspection.selectedSnapshot)
                } catch {
                    do { try mounted.close() } catch { throw APFSReadError.cleanupIncomplete }
                    throw error
                }
            }
        } onCancel: { cancellation.cancel() }
    }

    public static func validate(_ result: APFSInspectionResult, evidence: EvidenceRecord) throws {
        try result.options.validate()
        guard result.schemaVersion == 1, result.evidenceID == evidence.id,
              result.containerSHA256 == evidence.sha256, result.containerByteCount == evidence.byteCount,
              result.hashScope == FileHashScope.selectedFileBytes, result.driver == "apple-system-readonly-apfs-v1",
              !result.driverVersion.isEmpty, result.driverVersion.utf8.count <= 256,
              result.entries.count <= result.options.maximumEntries,
              Set(result.entries.map(\.relativePath)).count == result.entries.count,
              result.snapshots.count <= 4_096,
              Set(result.snapshots.map(\.uuid)).count == result.snapshots.count,
              Set(result.snapshots.map(\.name)).count == result.snapshots.count,
              Set(result.snapshots.map(\.transactionID)).count == result.snapshots.count,
              result.warnings.count <= 32, result.warnings.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 }),
              result.snapshotInventoryAvailable || result.snapshots.isEmpty else { throw APFSReadError.invalidResult }
        if let selected = result.options.selectedVolumeUUID, selected != result.volumeUUID { throw APFSReadError.invalidResult }
        if let requested = result.options.selectedSnapshotUUID {
            guard result.snapshotInventoryAvailable, let selected = result.selectedSnapshot,
                  selected.uuid == requested, result.snapshots.contains(selected),
                  result.volumeEncryption == .none else { throw APFSReadError.invalidResult }
        } else if result.selectedSnapshot != nil { throw APFSReadError.invalidResult }
        var metadataBytes = 0, hashedBytes: Int64 = 0
        for entry in result.entries {
            guard APFSPath.components(entry.relativePath) != nil, entry.byteCount >= 0,
                  (0..<1_000_000_000).contains(entry.modifiedNanoseconds) else { throw APFSReadError.invalidResult }
            guard entry.relativePath.utf8.count + 256 <= result.options.maximumMetadataBytes - metadataBytes else { throw APFSReadError.invalidResult }
            metadataBytes += entry.relativePath.utf8.count + 256
            if let hash = entry.sha256 {
                guard entry.kind == .regular, entry.byteCount <= result.options.maximumFileBytes,
                      entry.byteCount <= result.options.maximumAggregateFileBytes - hashedBytes,
                      APFSHash.valid(hash) else { throw APFSReadError.invalidResult }
                hashedBytes += entry.byteCount
            } else if entry.kind == .regular && result.coverage == .completeAllocatedView {
                throw APFSReadError.invalidResult
            }
        }
        for snapshot in result.snapshots {
            guard !snapshot.name.isEmpty, snapshot.name.utf8.count <= 1_024,
                  snapshot.transactionID > 0,
                  !snapshot.name.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
                  snapshot.name.utf8.count + 128 <= result.options.maximumMetadataBytes - metadataBytes else { throw APFSReadError.invalidResult }
            metadataBytes += snapshot.name.utf8.count + 128
        }
    }
}

private enum APFSHash {
    static func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    static func valid(_ value: String) -> Bool { value.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    static func file(_ descriptor: Int32, size: Int64, cancellation: APFSCancellation) throws -> String {
        var digest = SHA256(), offset: Int64 = 0, buffer = [UInt8](repeating: 0, count: 1_048_576)
        while offset < size {
            try cancellation.check()
            let wanted = Int(min(Int64(buffer.count), size - offset))
            let amount = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress, wanted, off_t(offset)) }
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw APFSReadError.sourceChanged }
            digest.update(data: Data(buffer.prefix(amount))); offset += Int64(amount)
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

private enum APFSPath {
    static func components(_ path: String) -> [String]? {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.hasSuffix("/"), path.utf8.count <= 16_384,
              !path.utf8.contains(0) else { return nil }
        let pieces = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !pieces.isEmpty, pieces.count <= 128,
              pieces.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 1_024 }) else { return nil }
        return pieces
    }
}

private final class APFSOwnedMount {
    let evidence: EvidenceRecord
    let options: APFSReadOptions
    let cancellation: APFSCancellation
    private let sourceURL: URL
    private let sourceParent: Int32
    private let sourceFD: Int32
    private let sourceIdentity: SourceIdentity
    private let scratch: APFSPrivateImage
    private var rootFD: Int32 = -1
    private var rootDevice: dev_t = 0
    private var rootInode: ino_t = 0
    private var snapshotFD: Int32 = -1
    private var snapshotDevice: dev_t = 0
    private var snapshotInode: ino_t = 0
    private var baseFSID: [UInt8] = []
    private var snapshotFSID: [UInt8] = []
    private var snapshotSourceCommandPath: String?
    private var snapshotTargetCommandPath: String?
    private let attachment = APFSAttachmentLifecycle()
    private let baseMountOperation = APFSAttachmentLifecycle()
    private let snapshotMountOperation = APFSAttachmentLifecycle()
    private let snapshotUnmountOperation = APFSAttachmentLifecycle()
    private let observer: (@Sendable (APFSReadLifecycleStage) -> Void)?
    private let snapshotMountDiagnostic: (@Sendable (APFSSnapshotMountDiagnostic) -> Void)?
    private var closed = false
    private(set) var volumeUUID = UUID()
    private(set) var encryption = APFSContainerEncryption.none
    private(set) var volumeEncryption = APFSVolumeEncryption.none
    private var volumeDevice = ""
    private var imageVolumes: [(device: String, info: [String: Any])] = []
    private(set) var catalogVolumes: [APFSVolumeDescriptor] = []
    private(set) var groupInventoryAvailable = false
    private(set) var catalogWarnings: [String] = []
    private(set) var selectedSnapshot: APFSSnapshotInventoryEntry?

    init(evidence: EvidenceRecord, options: APFSReadOptions, scratchRoot: URL?, passphrase: APFSPassphrase?,
         volumePassphrase: APFSPassphrase?,
         cancellation: APFSCancellation, observer: (@Sendable (APFSReadLifecycleStage) -> Void)?,
         snapshotMountDiagnostic: (@Sendable (APFSSnapshotMountDiagnostic) -> Void)? = nil,
         discoverOnly: Bool = false) throws {
        guard evidence.hashScope == FileHashScope.selectedFileBytes, evidence.container != .ewf,
              evidence.byteCount > 0, evidence.byteCount <= options.maximumContainerBytes,
              APFSHash.valid(evidence.sha256), evidence.sourcePath.hasPrefix("/"),
              !evidence.sourcePath.utf8.contains(0) else { throw APFSReadError.invalidEvidence }
        self.evidence = evidence; self.options = options; self.cancellation = cancellation
        self.observer = observer; self.snapshotMountDiagnostic = snapshotMountDiagnostic
        sourceURL = URL(fileURLWithPath: evidence.sourcePath).standardizedFileURL
        sourceParent = try EvidenceViewFiles.openDirectory(sourceURL.deletingLastPathComponent(), searchOnly: true)
        do { sourceFD = try FileAccess.openReadOnly(sourceURL.lastPathComponent, in: sourceParent) }
        catch { Darwin.close(sourceParent); throw error }
        do {
            let source = try FileAccess.identity(of: sourceFD)
            guard source.size == evidence.byteCount else { throw APFSReadError.sourceChanged }
            try APFSImageSourceScope.requireMainForkOnly(sourceFD)
            sourceIdentity = source
        } catch { Darwin.close(sourceFD); Darwin.close(sourceParent); throw error }
        do { scratch = try APFSPrivateImage(sourceFD: sourceFD, sourceSize: evidence.byteCount,
                                          root: scratchRoot, cancellation: cancellation) }
        catch { Darwin.close(sourceFD); Darwin.close(sourceParent); throw error }
        do {
            try verifySources()
            let encrypted = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/bin/hdiutil",
                ["isencrypted", "-plist", scratch.imageURL.path], timeout: options.commandTimeoutSeconds, cancellation: cancellation))
            guard let isEncrypted = encrypted["encrypted"] as? Bool else { throw APFSReadError.invalidResult }
            encryption = isEncrypted ? .encryptedDiskImage : .none
            if isEncrypted && passphrase == nil { throw APFSReadError.invalidCredential }
            var secret = try passphrase?.consume() ?? Data([0])
            defer { secret.resetBytes(in: 0..<secret.count) }
            scratch.retainBackingImage = true
            let attached = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/bin/hdiutil", ["attach", "-readonly",
                "-noautofsck", "-noverify", "-nobrowse", "-noautoopen", "-nomount", "-plist", "-stdinpass",
                scratch.imageURL.path], input: secret, timeout: options.commandTimeoutSeconds, cancellation: cancellation,
                started: { pid in self.attachment.clientStarted(); self.observer?(.attachClientStarted(pid)) },
                confirmedTerminal: { self.attachment.commandReachedTerminal(); self.observer?(.attachCommandTerminal) },
                drainOnCancellation: true))
            guard let entities = attached["system-entities"] as? [[String: Any]], entities.count <= 64 else { throw APFSReadError.invalidResult }
            guard !entities.contains(where: { $0["mount-point"] != nil }) else { throw unsafe("attach-unexpected-mounted-entity") }
            var volumes: [(device: String, info: [String: Any])] = []
            for device in Set(entities.compactMap { $0["dev-entry"] as? String }).sorted() where Self.validDevice(device) {
                guard try ownsDevice(device, cancellation: cancellation) else { throw unsafe("ownership-before-volume-info") }
                let info = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil", ["info", "-plist", device],
                    timeout: options.commandTimeoutSeconds, cancellation: cancellation))
                if info["FilesystemType"] as? String == "apfs", info["VolumeUUID"] as? String != nil {
                    volumes.append((device, info))
                }
            }
            guard !volumes.isEmpty, volumes.count <= 64 else { throw APFSReadError.unsupported("no bounded APFS volume inventory is available") }
            let identifiers = volumes.compactMap { ($0.info["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)) }
            guard identifiers.count == volumes.count, Set(identifiers).count == volumes.count else { throw APFSReadError.invalidResult }
            imageVolumes = volumes
            if discoverOnly { try buildCatalog(); return }
            let selected: (device: String, info: [String: Any])
            if let requested = options.selectedVolumeUUID {
                let matches = volumes.filter { ($0.info["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)) == requested }
                guard matches.count == 1 else { throw APFSReadError.unsupported("the selected APFS volume UUID is unavailable or ambiguous") }
                selected = matches[0]
            } else {
                guard volumes.count == 1 else { throw APFSReadError.unsupported("an explicit APFS volume UUID is required for multiple-volume images") }
                selected = volumes[0]
            }
            volumeDevice = selected.device
            let initialInfo = selected.info
            guard let uuidText = initialInfo["VolumeUUID"] as? String, let uuid = UUID(uuidString: uuidText),
                  let locked = initialInfo["Locked"] as? Bool,
                  let encryptedVolume = (initialInfo["Encryption"] as? Bool) ?? (initialInfo["Encrypted"] as? Bool),
                  let fileVault = initialInfo["FileVault"] as? Bool,
                  encryptedVolume == fileVault else { throw APFSReadError.unsupported("the OS did not declare a recognized APFS encryption state") }
            if encryptedVolume {
                if options.selectedSnapshotUUID != nil {
                    throw APFSReadError.unsupported("snapshot content for encrypted APFS volumes awaits independent validation")
                }
                guard try ownsDevice(Self.wholeDevice(volumeDevice)!, cancellation: cancellation) else { throw unsafe("ownership-before-crypto-info") }
                let cryptoState = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil",
                    ["apfs", "list", Self.wholeDevice(volumeDevice)!, "-plist"],
                    timeout: options.commandTimeoutSeconds, cancellation: cancellation))
                guard let containers = cryptoState["Containers"] as? [[String: Any]], containers.count <= 64 else { throw APFSReadError.invalidResult }
                let cryptoVolumes = containers.flatMap { $0["Volumes"] as? [[String: Any]] ?? [] }
                    .filter { $0["APFSVolumeUUID"] as? String == uuidText }
                guard cryptoVolumes.count == 1, cryptoVolumes[0]["CryptoMigrationOn"] as? Bool == false,
                      cryptoVolumes[0]["Encryption"] as? Bool == true,
                      initialInfo["EncryptionThisVolumeProper"] as? Bool == true,
                      let volumePassphrase else { throw APFSReadError.invalidCredential }
                var key = try volumePassphrase.consume(terminator: 10)
                defer { key.resetBytes(in: 0..<key.count) }
                guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-before-unlock") }
                let unlock = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil",
                    ["apfs", "unlockVolume", volumeDevice, "-user", "disk", "-stdinpassphrase", "-nomount", "-plist"],
                    input: key, timeout: options.commandTimeoutSeconds, cancellation: cancellation))
                guard unlock["Success"] as? Bool == true,
                      (unlock["CryptoUserUUID"] as? String).flatMap(UUID.init(uuidString:)) == uuid else { throw APFSReadError.invalidResult }
                guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-after-unlock") }
                let opened = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil", ["info", "-plist", volumeDevice],
                    timeout: options.commandTimeoutSeconds, cancellation: cancellation))
                guard opened["Locked"] as? Bool == false, opened["VolumeUUID"] as? String == uuidText,
                      opened["Encryption"] as? Bool == true else { throw APFSReadError.invalidResult }
                volumeEncryption = .diskUserAPFS
            } else { guard !locked else { throw unsafe("unencrypted-volume-declared-locked") } }
            guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-before-mount") }
            _ = try APFSSystemCommand.run("/usr/sbin/diskutil", ["mount", "readOnly", "nobrowse", "-mountOptions", "noexec,nosuid,nodev",
                "-mountPoint", scratch.mountURL.path, volumeDevice], timeout: options.commandTimeoutSeconds, cancellation: cancellation,
                started: { pid in self.baseMountOperation.clientStarted(); self.observer?(.baseMountClientStarted(pid)) },
                confirmedTerminal: { self.baseMountOperation.commandReachedTerminal(); self.observer?(.baseMountCommandTerminal) },
                drainOnCancellation: true)
            guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-after-mount") }
            let mountedInfo = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil", ["info", "-plist", volumeDevice],
                timeout: options.commandTimeoutSeconds, cancellation: cancellation))
            // diskutil's actual plist has MountPoint/WritableVolume but no
            // Mounted key on this SDK/runtime. Verify the actual pinned mount
            // directory and kernel flags instead of an invented boolean field.
            guard APFSMountMetadata.declaresReadOnlyAPFS(mountedInfo, volumeUUID: uuidText,
                matchesOwnedMount: scratch.matchesMountPath) else { throw unsafe("mounted-volume-plist-or-directory") }
            try requireOtherVolumesUnmounted()
            volumeUUID = uuid
            rootFD = Darwin.open(scratch.mountURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard rootFD >= 0 else { throw unsafe("mounted-root-open") }
            var metadata = stat()
            guard Darwin.fstat(rootFD, &metadata) == 0 else { throw unsafe("mounted-root-stat") }
            rootDevice = metadata.st_dev; rootInode = metadata.st_ino
            try validateMount()
            if let requested = options.selectedSnapshotUUID { try mountSnapshot(requested) }
            observer?(.mounted)
        } catch {
            do { try close() } catch { throw APFSReadError.cleanupIncomplete }
            throw error
        }
    }

    deinit {
        if !closed { try? close() }
        Darwin.close(sourceFD); Darwin.close(sourceParent)
    }

    func verifySources() throws {
        try cancellation.check()
        try APFSImageSourceScope.requireMainForkOnly(sourceFD)
        try EvidenceViewFiles.validateDirectory(sourceURL.deletingLastPathComponent(), descriptor: sourceParent, searchOnly: true)
        guard try FileAccess.identity(of: sourceFD) == sourceIdentity,
              try FileAccess.identity(at: sourceURL.lastPathComponent, in: sourceParent) == sourceIdentity,
              try APFSHash.file(sourceFD, size: evidence.byteCount, cancellation: cancellation) == evidence.sha256 else {
            throw APFSReadError.sourceChanged
        }
        try scratch.verify(expectedHash: evidence.sha256, cancellation: cancellation)
        try APFSImageSourceScope.requireMainForkOnly(sourceFD)
        guard try FileAccess.identity(of: sourceFD) == sourceIdentity,
              try FileAccess.identity(at: sourceURL.lastPathComponent, in: sourceParent) == sourceIdentity else { throw APFSReadError.sourceChanged }
    }

    func validateMount() throws {
        try cancellation.check(); try scratch.validate()
        var metadata = stat(), pathMetadata = stat(), filesystem = statfs()
        guard rootFD >= 0, Darwin.fstat(rootFD, &metadata) == 0,
              Darwin.lstat(scratch.mountURL.path, &pathMetadata) == 0,
              metadata.st_dev == rootDevice, metadata.st_ino == rootInode,
              pathMetadata.st_dev == rootDevice, pathMetadata.st_ino == rootInode else { throw unsafe("mounted-root-path-identity") }
        guard Darwin.fstatfs(rootFD, &filesystem) == 0 else { throw unsafe("mounted-root-fstatfs") }
        guard filesystem.f_flags & UInt32(MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID | MNT_NODEV)
            == UInt32(MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID | MNT_NODEV) else { throw unsafe("kernel-mount-flags", flags: filesystem.f_flags) }
        let type = withUnsafePointer(to: &filesystem.f_fstypename) {
            $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
        }
        let source = withUnsafePointer(to: &filesystem.f_mntfromname) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1_024) { String(cString: $0) }
        }
        guard type == "apfs", source == volumeDevice else { throw unsafe("kernel-filesystem-or-volume-device", flags: filesystem.f_flags) }
        if let selected = selectedSnapshot {
            let actualBaseFSID = withUnsafeBytes(of: filesystem.f_fsid) { Array($0) }
            guard actualBaseFSID == baseFSID, let snapshotSourceCommandPath,
                  try APFSCanonicalDirectoryPath.path(for: rootFD) == snapshotSourceCommandPath,
                  try APFSSnapshotMountMetadata.filesystemUUID(of: rootFD) == volumeUUID else { throw unsafe("snapshot-base-volume-binding") }
            var snapshotMetadata = stat(), snapshotPath = stat(), snapshotStatus = statfs()
            guard snapshotFD >= 0, Darwin.fstat(snapshotFD, &snapshotMetadata) == 0,
                  Darwin.lstat(scratch.snapshotURL.path, &snapshotPath) == 0,
                  snapshotMetadata.st_dev == snapshotDevice, snapshotMetadata.st_ino == snapshotInode,
                  snapshotPath.st_dev == snapshotDevice, snapshotPath.st_ino == snapshotInode,
                  Darwin.fstatfs(snapshotFD, &snapshotStatus) == 0 else { throw unsafe("snapshot-root-path-identity") }
            let actualSnapshotFSID = withUnsafeBytes(of: snapshotStatus.f_fsid) { Array($0) }
            guard actualSnapshotFSID == snapshotFSID, let snapshotTargetCommandPath,
                  try APFSCanonicalDirectoryPath.path(for: snapshotFD) == snapshotTargetCommandPath,
                  scratch.matchesSnapshotPath(Self.mountName(snapshotStatus)),
                  APFSSnapshotMountMetadata.validatesReadOnlySnapshot(flags: snapshotStatus.f_flags,
                    filesystemType: Self.filesystemType(snapshotStatus), source: Self.mountSource(snapshotStatus),
                    snapshot: selected, volumeDevice: volumeDevice, snapshotFSID: actualSnapshotFSID,
                    baseFSID: baseFSID, filesystemUUID: try APFSSnapshotMountMetadata.filesystemUUID(of: snapshotFD)) else {
                throw unsafe("snapshot-kernel-or-uuid-binding", flags: snapshotStatus.f_flags)
            }
        }
    }

    private static func filesystemType(_ supplied: statfs) -> String {
        var value = supplied.f_fstypename
        return withUnsafePointer(to: &value) { $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) } }
    }
    private static func mountSource(_ supplied: statfs) -> String {
        var value = supplied.f_mntfromname
        return withUnsafePointer(to: &value) { $0.withMemoryRebound(to: CChar.self, capacity: 1_024) { String(cString: $0) } }
    }
    private static func mountName(_ supplied: statfs) -> String {
        var value = supplied.f_mntonname
        return withUnsafePointer(to: &value) { $0.withMemoryRebound(to: CChar.self, capacity: 1_024) { String(cString: $0) } }
    }

    private func snapshotInventoryFromOwnedVolume() throws -> [APFSSnapshotInventoryEntry] {
        guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-before-snapshot-inventory") }
        let listing = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil",
            ["apfs", "listSnapshots", "-plist", volumeDevice], timeout: options.commandTimeoutSeconds, cancellation: cancellation))
        guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-after-snapshot-inventory") }
        let entries = try APFSSnapshotMetadata.entries(from: listing)
        var charged = 0
        for entry in entries {
            guard entry.name.utf8.count + 128 <= options.maximumMetadataBytes - charged else { throw APFSReadError.invalidResult }
            charged += entry.name.utf8.count + 128
        }
        return entries
    }

    private func mountSnapshot(_ requested: UUID) throws {
        try validateMount()
        guard volumeEncryption == .none else { throw APFSReadError.unsupported("snapshot content for encrypted APFS volumes awaits independent validation") }
        let inventory = try snapshotInventoryFromOwnedVolume()
        let matches = inventory.filter { $0.uuid == requested }
        guard matches.count == 1 else { throw APFSReadError.unsupported("the selected APFS snapshot UUID is unavailable or ambiguous") }
        guard matches[0].name.utf8.count + 1 + volumeDevice.utf8.count <= 1_023 else {
            throw APFSReadError.unsupported("the snapshot name exceeds the system mount metadata bound")
        }
        var status = statfs()
        guard Darwin.fstatfs(rootFD, &status) == 0,
              try APFSSnapshotMountMetadata.filesystemUUID(of: rootFD) == volumeUUID else { throw unsafe("snapshot-base-before-mount") }
        baseFSID = withUnsafeBytes(of: status.f_fsid) { Array($0) }
        try scratch.createSnapshotTarget()
        // Foundation URL.path can reintroduce /tmp or /var aliases after
        // resolvingSymlinksInPath; MNT_NOFOLLOW correctly rejects them. Pass
        // raw canonical POSIX names from held identity/fsid-checked directory
        // descriptors, without converting the strings back through URL.path.
        let sourcePath = try APFSCanonicalDirectoryPath.path(for: rootFD)
        let targetPath = try scratch.canonicalSnapshotTargetPath()
        snapshotSourceCommandPath = sourcePath; snapshotTargetCommandPath = targetPath
        selectedSnapshot = matches[0]
        guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-before-snapshot-mount") }
        _ = try APFSSystemCommand.run("/sbin/mount_apfs",
            ["-o", "rdonly,nobrowse,noexec,nosuid,nodev,nofollow", "-s", matches[0].name,
             sourcePath, targetPath], timeout: options.commandTimeoutSeconds, cancellation: cancellation,
            started: { pid in self.snapshotMountOperation.clientStarted(); self.observer?(.snapshotMountClientStarted(pid)) },
            confirmedTerminal: { self.snapshotMountOperation.commandReachedTerminal(); self.observer?(.snapshotMountCommandTerminal) },
            drainOnCancellation: true, snapshotMountDiagnostic: snapshotMountDiagnostic)
        guard try ownsDevice(volumeDevice, cancellation: cancellation) else { throw unsafe("ownership-after-snapshot-mount") }
        snapshotFD = Darwin.open(targetPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var metadata = stat(), snapshotStatus = statfs()
        guard snapshotFD >= 0, Darwin.fstat(snapshotFD, &metadata) == 0,
              Darwin.fstatfs(snapshotFD, &snapshotStatus) == 0 else { throw unsafe("snapshot-mounted-root-open") }
        snapshotDevice = metadata.st_dev; snapshotInode = metadata.st_ino
        snapshotFSID = withUnsafeBytes(of: snapshotStatus.f_fsid) { Array($0) }
        try validateMount()
        guard try snapshotInventoryFromOwnedVolume().contains(matches[0]) else { throw APFSReadError.sourceChanged }
    }

    private func requireOtherVolumesUnmounted() throws {
        for item in imageVolumes where item.device != volumeDevice {
            guard try ownsDevice(item.device, cancellation: cancellation) else { throw unsafe("ownership-before-other-volume-info") }
            let info = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil", ["info", "-plist", item.device],
                timeout: options.commandTimeoutSeconds, cancellation: cancellation))
            guard (info["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)) ==
                    (item.info["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)),
                  info["MountPoint"] as? String == "" else {
                throw unsafe("unexpected-other-volume-mount")
            }
        }
    }

    private func buildCatalog() throws {
        var descriptors: [APFSVolumeDescriptor] = [], warnings: [String] = []
        var allGroupsAvailable = true
        let containers = Set(imageVolumes.compactMap { Self.wholeDevice($0.device) }).sorted()
        guard !containers.isEmpty, containers.count <= 64 else { throw APFSReadError.invalidResult }
        for device in containers {
            guard try ownsDevice(device, cancellation: cancellation) else { throw unsafe("ownership-before-catalog-container") }
            let listing = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil",
                ["apfs", "list", device, "-plist"], timeout: options.commandTimeoutSeconds, cancellation: cancellation))
            guard try ownsDevice(device, cancellation: cancellation) else { throw unsafe("ownership-after-catalog-container") }
            guard let rows = listing["Containers"] as? [[String: Any]], rows.count == 1,
                  rows[0]["ContainerReference"] as? String == String(device.dropFirst(5)),
                  let uuid = (rows[0]["APFSContainerUUID"] as? String).flatMap(UUID.init(uuidString:)),
                  let volumes = rows[0]["Volumes"] as? [[String: Any]], volumes.count <= 64 else {
                throw APFSReadError.invalidResult
            }
            var groups: [UUID: UUID] = [:]
            guard try ownsDevice(device, cancellation: cancellation) else { throw unsafe("ownership-before-catalog-groups") }
            do {
                let groupListing = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/sbin/diskutil",
                    ["apfs", "listVolumeGroups", device, "-plist"], timeout: options.commandTimeoutSeconds, cancellation: cancellation))
                groups = try APFSVolumeGroupMetadata.mapping(groupListing, containerUUID: uuid)
            } catch is CancellationError { throw CancellationError() }
            catch {
                allGroupsAvailable = false
                warnings.append("volume-group-inventory-unavailable; no-boot-or-FileVault-profile-is-implied")
            }
            guard try ownsDevice(device, cancellation: cancellation) else { throw unsafe("ownership-after-catalog-groups") }
            for item in imageVolumes where Self.wholeDevice(item.device) == device {
                guard item.info["WritableMedia"] as? Bool == false,
                      let volumeUUID = (item.info["VolumeUUID"] as? String).flatMap(UUID.init(uuidString:)) else {
                    throw unsafe("catalog-device-not-declared-readonly")
                }
                let matches = volumes.filter {
                    ($0["APFSVolumeUUID"] as? String).flatMap(UUID.init(uuidString:)) == volumeUUID &&
                        $0["DeviceIdentifier"] as? String == String(item.device.dropFirst(5))
                }
                guard matches.count == 1 else { throw APFSReadError.invalidResult }
                descriptors.append(try APFSVolumeCatalogMetadata.descriptor(info: item.info, volume: matches[0],
                    containerUUID: uuid, volumeGroupUUID: groups[volumeUUID]))
            }
        }
        // In discovery mode volumeDevice is empty, so every candidate is checked.
        // No mounted companion volume may silently turn this into a content read.
        try requireOtherVolumesUnmounted()
        catalogVolumes = descriptors.sorted { $0.volumeUUID.uuidString < $1.volumeUUID.uuidString }
        groupInventoryAvailable = allGroupsAvailable
        catalogWarnings = Array(Set(warnings)).sorted()
    }

    private func unsafe(_ stage: String, flags: UInt32? = nil) -> APFSReadError {
        observer?(.safetyFailure(stage: stage, mountFlags: flags))
        return .unsafeMount
    }

    private var contentRoot: Int32 { selectedSnapshot == nil ? rootFD : snapshotFD }
    func root() throws -> Int32 { try validateMount(); return contentRoot }
    func isSameDevice(_ metadata: stat) -> Bool { metadata.st_dev == (selectedSnapshot == nil ? rootDevice : snapshotDevice) }

    func read(_ entry: APFSFileEntry) throws -> Data {
        guard let components = APFSPath.components(entry.relativePath), entry.kind == .regular,
              entry.byteCount >= 0, entry.byteCount <= options.maximumFileBytes else { throw APFSReadError.fileUnavailable }
        try validateMount()
        var parent = Darwin.dup(contentRoot)
        guard parent >= 0 else { throw APFSReadError.fileUnavailable }
        defer { Darwin.close(parent) }
        for component in components.dropLast() {
            try cancellation.check()
            let next = Darwin.openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw APFSReadError.fileUnavailable }
            var metadata = stat()
            guard Darwin.fstat(next, &metadata) == 0, isSameDevice(metadata) else { Darwin.close(next); throw APFSReadError.unsafeMount }
            Darwin.close(parent); parent = next
        }
        let name = components.last!
        let fd = try FileAccess.openReadOnly(name, in: parent); defer { Darwin.close(fd) }
        let identity = try FileAccess.identity(of: fd)
        guard identity.device == (selectedSnapshot == nil ? rootDevice : snapshotDevice), UInt64(identity.inode) == entry.inode, identity.size == entry.byteCount,
              Int64(identity.modifiedSeconds) == entry.modifiedSeconds, identity.modifiedNanoseconds == entry.modifiedNanoseconds else { throw APFSReadError.sourceChanged }
        var bytes = Data(), offset: Int64 = 0, buffer = [UInt8](repeating: 0, count: 65_536)
        bytes.reserveCapacity(Int(entry.byteCount))
        while offset < entry.byteCount {
            try cancellation.check()
            let wanted = Int(min(Int64(buffer.count), entry.byteCount - offset))
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(fd, $0.baseAddress, wanted, off_t(offset)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw APFSReadError.sourceChanged }
            bytes.append(contentsOf: buffer.prefix(count)); offset += Int64(count)
        }
        guard try FileAccess.identity(of: fd) == identity, try FileAccess.identity(at: name, in: parent) == identity else { throw APFSReadError.sourceChanged }
        try validateMount()
        return bytes
    }

    func snapshots() throws -> (entries: [APFSSnapshotInventoryEntry], available: Bool, warnings: [String]) {
        try validateMount()
        do {
            let entries = try snapshotInventoryFromOwnedVolume()
            if let selected = selectedSnapshot, !entries.contains(selected) { throw APFSReadError.sourceChanged }
            return (entries.sorted { $0.uuid.uuidString < $1.uuid.uuidString }, true, [])
        } catch is CancellationError { throw CancellationError() }
        catch {
            if selectedSnapshot != nil { throw APFSReadError.unsupported("the selected snapshot inventory is unavailable") }
            return ([], false, ["snapshot-inventory-unavailable; no-snapshot-content-view-can-be-selected"])
        }
    }

    func close() throws {
        if closed { return }
        if snapshotFD >= 0 { Darwin.close(snapshotFD); snapshotFD = -1 }
        if rootFD >= 0 { Darwin.close(rootFD); rootFD = -1 }
        // Any unknown command/identity/detach outcome retains the private
        // backing image. Removal becomes eligible only after confirmed detach.
        scratch.retainBackingImage = true
        if let reason = uncertainOperationReason {
            try? scratch.markQuarantine(reason: reason)
            throw APFSReadError.cleanupIncomplete
        }
        if attachment.state == .notStarted {
            scratch.retainBackingImage = false
            try scratch.cleanup(); closed = true
            return
        }
        do { try unmountSnapshotIfPresent() }
        catch {
            if let reason = uncertainOperationReason { try? scratch.markQuarantine(reason: reason) }
            throw APFSReadError.cleanupIncomplete
        }
        // An interrupted attach may have created a device without returning its
        // plist. Discover only the unique private image, never arbitrary devices.
        var detached = false
        for _ in 0..<8 {
            let owned = try ownedAttachment()
            guard let owned else { detached = true; break }
            guard let entities = owned["system-entities"] as? [[String: Any]], !entities.isEmpty else { throw APFSReadError.cleanupIncomplete }
            let wholeNodes = entities.filter { row in
                guard let value = row["dev-entry"] as? String else { return false }
                return Self.validDevice(value) && Self.wholeDevice(value) == value
            }.sorted { lhs, rhs in
                let left = lhs["content-hint"] as? String == "GUID_partition_scheme"
                let right = rhs["content-hint"] as? String == "GUID_partition_scheme"
                return left != right ? left : (lhs["dev-entry"] as? String ?? "") < (rhs["dev-entry"] as? String ?? "")
            }
            guard let device = wholeNodes.first?["dev-entry"] as? String else { throw APFSReadError.cleanupIncomplete }
            // No attach-time disk numbers survive into cleanup. Refresh the
            // unique backing-image mapping before every normal/force detach.
            guard try ownsDevice(device) else { continue }
            do { _ = try APFSSystemCommand.run("/usr/bin/hdiutil", ["detach", device], timeout: 10, cancellation: nil) }
            catch {
                guard try ownsDevice(device) else { continue }
                _ = try APFSSystemCommand.run("/usr/bin/hdiutil", ["detach", "-force", device], timeout: 10, cancellation: nil)
            }
        }
        guard try detached || ownedAttachment() == nil else { throw APFSReadError.cleanupIncomplete }
        scratch.retainBackingImage = false
        do { try scratch.cleanup() }
        catch { scratch.retainBackingImage = true; throw error }
        closed = true
        observer?(.detached)
    }

    private var uncertainOperationReason: String? {
        if attachment.requiresQuarantine { return "attach-client-terminal-not-confirmed" }
        if baseMountOperation.requiresQuarantine { return "base-mount-client-terminal-not-confirmed" }
        if snapshotMountOperation.requiresQuarantine { return "snapshot-mount-client-terminal-not-confirmed" }
        if snapshotUnmountOperation.requiresQuarantine { return "snapshot-unmount-client-terminal-not-confirmed" }
        return nil
    }

    private func unmountSnapshotIfPresent() throws {
        guard scratch.hasSnapshotTarget else { return }
        try scratch.validate()
        let descriptor = try scratch.openSnapshotDirectory()
        var canonicalPath: String?
        do {
            if try scratch.underlyingSnapshotTargetIsOwned(descriptor) {
                Darwin.close(descriptor)
                return
            }
            guard let selected = selectedSnapshot, try ownsDevice(volumeDevice) else { throw APFSReadError.cleanupIncomplete }
            let actualPath = try APFSCanonicalDirectoryPath.path(for: descriptor)
            guard actualPath == snapshotTargetCommandPath else { throw APFSReadError.cleanupIncomplete }
            canonicalPath = actualPath
            var status = statfs()
            guard Darwin.fstatfs(descriptor, &status) == 0,
                  scratch.matchesSnapshotPath(Self.mountName(status)) else { throw APFSReadError.cleanupIncomplete }
            let actualFSID = withUnsafeBytes(of: status.f_fsid) { Array($0) }
            guard (snapshotFSID.isEmpty || actualFSID == snapshotFSID),
                  APFSSnapshotMountMetadata.validatesReadOnlySnapshot(flags: status.f_flags,
                    filesystemType: Self.filesystemType(status), source: Self.mountSource(status), snapshot: selected,
                    volumeDevice: volumeDevice, snapshotFSID: actualFSID, baseFSID: baseFSID,
                    filesystemUUID: try APFSSnapshotMountMetadata.filesystemUUID(of: descriptor)) else {
                throw APFSReadError.cleanupIncomplete
            }
        } catch { Darwin.close(descriptor); throw error }
        Darwin.close(descriptor)
        guard try ownsDevice(volumeDevice) else { throw APFSReadError.cleanupIncomplete }
        guard let canonicalPath else { throw APFSReadError.cleanupIncomplete }
        _ = try APFSSystemCommand.run("/sbin/umount", [canonicalPath], timeout: 10, cancellation: nil,
            started: { _ in self.snapshotUnmountOperation.clientStarted() },
            confirmedTerminal: { self.snapshotUnmountOperation.commandReachedTerminal() }, drainOnCancellation: true)
        let underlying = try scratch.openSnapshotDirectory()
        defer { Darwin.close(underlying) }
        guard try scratch.underlyingSnapshotTargetIsOwned(underlying) else { throw APFSReadError.cleanupIncomplete }
    }

    private func ownedAttachment(cancellation: APFSCancellation? = nil) throws -> [String: Any]? {
        try scratch.validate()
        let info = try APFSSystemCommand.plist(APFSSystemCommand.run("/usr/bin/hdiutil", ["info", "-plist"], timeout: 10, cancellation: cancellation))
        guard let rows = info["images"] as? [[String: Any]], rows.count <= 1_024 else { throw APFSReadError.cleanupIncomplete }
        let owned = rows.filter { scratch.matchesImagePath($0["image-path"] as? String) }
        guard owned.count <= 1 else { throw APFSReadError.cleanupIncomplete }
        return owned.first
    }
    private func ownsDevice(_ device: String, cancellation: APFSCancellation? = nil) throws -> Bool {
        guard let attached = try ownedAttachment(cancellation: cancellation), let entities = attached["system-entities"] as? [[String: Any]] else { return false }
        return entities.contains { $0["dev-entry"] as? String == device }
    }

    private static func validDevice(_ value: String) -> Bool {
        guard value.hasPrefix("/dev/disk"), value.utf8.count <= 64 else { return false }
        let suffix = value.dropFirst(9)
        return !suffix.isEmpty && suffix.allSatisfy { $0.isASCII && ($0.isNumber || $0 == "s") }
    }
    private static func wholeDevice(_ value: String) -> String? {
        guard validDevice(value) else { return nil }
        return "/dev/disk" + value.dropFirst(9).prefix(while: { $0.isNumber })
    }
}

private final class APFSDirectoryWalker {
    let mount: APFSOwnedMount
    let options: APFSReadOptions
    let cancellation: APFSCancellation
    private(set) var partial = false
    private(set) var warnings: [String] = []
    private var entries: [APFSFileEntry] = []
    private var examinedNames = 0
    private var metadataBytes = 0
    private var hashedBytes: Int64 = 0
    init(mount: APFSOwnedMount, options: APFSReadOptions, cancellation: APFSCancellation) {
        self.mount = mount; self.options = options; self.cancellation = cancellation
    }
    func enumerate() throws -> [APFSFileEntry] {
        try walk(try mount.root(), prefix: "", depth: 0)
        try mount.validateMount()
        return entries.sorted { $0.relativePath.utf8.lexicographicallyPrecedes($1.relativePath.utf8) }
    }
    private func mark(_ code: String) { partial = true; if !warnings.contains(code) { warnings.append(code) } }
    private func walk(_ directory: Int32, prefix: String, depth: Int) throws {
        try cancellation.check()
        guard depth < options.maximumDepth else { mark("directory-depth-limit"); return }
        let copy = Darwin.dup(directory)
        guard copy >= 0, let stream = Darwin.fdopendir(copy) else { if copy >= 0 { Darwin.close(copy) }; mark("unreadable-directory"); return }
        defer { Darwin.closedir(stream) }
        var names: [String] = []
        errno = 0
        while let item = Darwin.readdir(stream) {
            try cancellation.check()
            let name: String? = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(item.pointee.d_namlen) + 1) { String(validatingCString: $0) }
            }
            guard let name else { mark("filename-not-valid-utf8"); continue }
            if name == "." || name == ".." { continue }
            guard examinedNames < options.maximumEntries else { mark("directory-name-limit"); break }
            guard name.utf8.count + 64 <= options.maximumMetadataBytes - metadataBytes else { mark("metadata-byte-limit"); break }
            examinedNames += 1; metadataBytes += name.utf8.count + 64
            names.append(name); errno = 0
        }
        if errno != 0 { mark("directory-enumeration-error") }
        for name in names.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
            try cancellation.check()
            guard entries.count < options.maximumEntries else { mark("entry-limit"); return }
            let path = prefix.isEmpty ? name : prefix + "/" + name
            guard APFSPath.components(path) != nil else { mark("path-limit"); continue }
            guard path.utf8.count + 256 <= options.maximumMetadataBytes - metadataBytes else { mark("metadata-byte-limit"); return }
            metadataBytes += path.utf8.count + 256
            var metadata = stat()
            guard Darwin.fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else { mark("unreadable-entry"); continue }
            guard mount.isSameDevice(metadata) else { mark("nested-filesystem-refused"); continue }
            let kind: APFSFileKind
            switch metadata.st_mode & S_IFMT {
            case S_IFREG: kind = .regular
            case S_IFDIR: kind = .directory
            case S_IFLNK: kind = .symbolicLink
            default: kind = .other
            }
            var hash: String?
            if kind == .regular {
                if metadata.st_size >= 0 && metadata.st_size <= options.maximumFileBytes,
                   metadata.st_size <= options.maximumAggregateFileBytes - hashedBytes {
                    do {
                        let fd = try FileAccess.openReadOnly(name, in: directory); defer { Darwin.close(fd) }
                        let before = try FileAccess.identity(of: fd)
                        guard before == SourceIdentity(metadata) else { throw APFSReadError.sourceChanged }
                        hashedBytes += before.size
                        hash = try APFSHash.file(fd, size: before.size, cancellation: cancellation)
                        guard try FileAccess.identity(of: fd) == before, try FileAccess.identity(at: name, in: directory) == before else {
                            throw APFSReadError.sourceChanged
                        }
                    } catch is CancellationError { throw CancellationError() }
                    catch APFSReadError.sourceChanged { throw APFSReadError.sourceChanged }
                    catch { mark("regular-file-read-failed") }
                } else { mark("regular-file-or-aggregate-byte-limit") }
            }
            entries.append(.init(relativePath: path, kind: kind, inode: UInt64(metadata.st_ino), byteCount: max(0, metadata.st_size),
                sha256: hash, modifiedSeconds: Int64(metadata.st_mtimespec.tv_sec), modifiedNanoseconds: metadata.st_mtimespec.tv_nsec))
            if kind == .directory {
                let child = Darwin.openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if child < 0 { mark("unreadable-directory"); continue }
                defer { Darwin.close(child) }
                var opened = stat()
                guard Darwin.fstat(child, &opened) == 0, opened.st_dev == metadata.st_dev, opened.st_ino == metadata.st_ino else {
                    throw APFSReadError.sourceChanged
                }
                try walk(child, prefix: path, depth: depth + 1)
            }
        }
    }
}

private final class APFSPrivateImage {
    let imageURL: URL
    let mountURL: URL
    let snapshotURL: URL
    private let rootURL: URL
    private let directoryURL: URL
    private let name: String
    private let rootFD: Int32
    private let directoryFD: Int32
    private var imageFD: Int32 = -1
    private var imageIdentity: SourceIdentity?
    private var cleaned = false
    private var snapshotTargetCreated = false
    private var snapshotTargetIdentity: stat?
    var retainBackingImage = false

    init(sourceFD: Int32, sourceSize: Int64, root: URL?, cancellation: APFSCancellation) throws {
        let requestedRoot = (root ?? FileManager.default.temporaryDirectory).standardizedFileURL
        rootFD = try EvidenceViewFiles.openDirectory(requestedRoot)
        rootURL = requestedRoot.resolvingSymlinksInPath()
        name = ".native-apfs-" + UUID().uuidString
        guard Darwin.mkdirat(rootFD, name, 0o700) == 0 else { Darwin.close(rootFD); throw FileAccess.posixError("Cannot create APFS scratch") }
        directoryFD = Darwin.openat(rootFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { _ = Darwin.unlinkat(rootFD, name, AT_REMOVEDIR); Darwin.close(rootFD); throw APFSReadError.unsafeMount }
        directoryURL = rootURL.appendingPathComponent(name, isDirectory: true)
        imageURL = directoryURL.appendingPathComponent("image.dmg")
        mountURL = directoryURL.appendingPathComponent("view", isDirectory: true)
        snapshotURL = directoryURL.appendingPathComponent("snapshot-view", isDirectory: true)
        do {
            guard Darwin.mkdirat(directoryFD, "view", 0o700) == 0 else { throw APFSReadError.unsafeMount }
            if Darwin.fclonefileat(sourceFD, directoryFD, "image.dmg", UInt32(CLONE_NOOWNERCOPY)) != 0 {
                imageFD = Darwin.openat(directoryFD, "image.dmg", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                guard imageFD >= 0 else { throw FileAccess.posixError("Cannot create APFS private image") }
                var offset: Int64 = 0, buffer = [UInt8](repeating: 0, count: 1_048_576)
                while offset < sourceSize {
                    try cancellation.check()
                    let wanted = Int(min(Int64(buffer.count), sourceSize - offset))
                    let amount = buffer.withUnsafeMutableBytes { Darwin.pread(sourceFD, $0.baseAddress, wanted, off_t(offset)) }
                    if amount < 0 && errno == EINTR { continue }
                    guard amount > 0 else { throw APFSReadError.sourceChanged }
                    var copied = 0
                    while copied < amount {
                        try cancellation.check()
                        let written = buffer.withUnsafeBytes { Darwin.write(imageFD, $0.baseAddress!.advanced(by: copied), amount - copied) }
                        if written < 0 && errno == EINTR { continue }
                        guard written > 0 else { throw FileAccess.posixError("Cannot copy APFS private image") }; copied += written
                    }
                    offset += Int64(amount)
                }
                guard Darwin.fsync(imageFD) == 0 else { throw FileAccess.posixError("Cannot synchronize APFS private image") }
            } else { imageFD = try FileAccess.openReadOnly("image.dmg", in: directoryFD) }
            guard Darwin.fchmod(imageFD, 0o400) == 0 else { throw APFSReadError.unsafeMount }
            imageIdentity = try FileAccess.identity(of: imageFD)
            guard imageIdentity?.size == sourceSize else { throw APFSReadError.sourceChanged }
            try validate()
        } catch {
            if imageFD >= 0 { imageIdentity = try? FileAccess.identity(of: imageFD) }
            try? cleanup(); throw error
        }
    }
    deinit {
        if !cleaned && !retainBackingImage { try? cleanup() }
        if imageFD >= 0 { Darwin.close(imageFD) }
        Darwin.close(directoryFD); Darwin.close(rootFD)
    }
    func validate() throws {
        try EvidenceViewFiles.validateDirectory(rootURL, descriptor: rootFD)
        try EvidenceViewFiles.validateDirectory(directoryURL, descriptor: directoryFD)
        guard let identity = imageIdentity, try FileAccess.identity(of: imageFD) == identity,
              try FileAccess.identity(at: "image.dmg", in: directoryFD) == identity else { throw APFSReadError.sourceChanged }
        try APFSImageSourceScope.requireMainForkOnly(imageFD)
    }
    func verify(expectedHash: String, cancellation: APFSCancellation) throws {
        try validate()
        guard let identity = imageIdentity,
              try APFSHash.file(imageFD, size: identity.size, cancellation: cancellation) == expectedHash else { throw APFSReadError.sourceChanged }
        try validate()
    }
    func createSnapshotTarget() throws {
        try validate()
        guard !snapshotTargetCreated, Darwin.mkdirat(directoryFD, "snapshot-view", 0o700) == 0 else { throw APFSReadError.unsafeMount }
        snapshotTargetCreated = true
        let descriptor = Darwin.openat(directoryFD, "snapshot-view", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw APFSReadError.unsafeMount }
        defer { Darwin.close(descriptor) }
        var metadata = stat(), path = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Darwin.fstatat(directoryFD, "snapshot-view", &path, AT_SYMLINK_NOFOLLOW) == 0,
              metadata.st_dev == path.st_dev, metadata.st_ino == path.st_ino,
              metadata.st_mode & S_IFMT == S_IFDIR else { throw APFSReadError.unsafeMount }
        snapshotTargetIdentity = metadata
    }
    func underlyingSnapshotTargetIsOwned(_ descriptor: Int32) throws -> Bool {
        try validate()
        guard snapshotTargetCreated, let expected = snapshotTargetIdentity else { return false }
        var metadata = stat(), path = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Darwin.fstatat(directoryFD, "snapshot-view", &path, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
        return metadata.st_dev == expected.st_dev && metadata.st_ino == expected.st_ino &&
            path.st_dev == expected.st_dev && path.st_ino == expected.st_ino &&
            metadata.st_mode == expected.st_mode && metadata.st_uid == expected.st_uid &&
            metadata.st_gid == expected.st_gid && metadata.st_flags == expected.st_flags &&
            path.st_mode == expected.st_mode && path.st_uid == expected.st_uid && path.st_gid == expected.st_gid
    }
    func openSnapshotDirectory() throws -> Int32 {
        try validate()
        guard snapshotTargetCreated else { throw APFSReadError.unsafeMount }
        let descriptor = Darwin.openat(directoryFD, "snapshot-view", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw APFSReadError.unsafeMount }
        return descriptor
    }
    func canonicalSnapshotTargetPath() throws -> String {
        let descriptor = try openSnapshotDirectory()
        defer { Darwin.close(descriptor) }
        guard try underlyingSnapshotTargetIsOwned(descriptor) else { throw APFSReadError.unsafeMount }
        return try APFSCanonicalDirectoryPath.path(for: descriptor)
    }
    var hasSnapshotTarget: Bool { snapshotTargetCreated }
    func matchesImagePath(_ reported: String?) -> Bool {
        guard let reported, reported.hasPrefix("/"), !reported.utf8.contains(0),
              let identity = imageIdentity else { return false }
        let url = URL(fileURLWithPath: reported)
        guard url.standardizedFileURL.resolvingSymlinksInPath() == imageURL.standardizedFileURL.resolvingSymlinksInPath() else { return false }
        guard let directory = try? EvidenceViewFiles.openDirectory(url.deletingLastPathComponent(), searchOnly: true) else { return false }
        defer { Darwin.close(directory) }
        return (try? FileAccess.identity(at: url.lastPathComponent, in: directory)) == identity
    }
    func matchesMountPath(_ reported: String?) -> Bool {
        matchesMountedPath(reported, expected: mountURL)
    }
    func matchesSnapshotPath(_ reported: String?) -> Bool {
        matchesMountedPath(reported, expected: snapshotURL)
    }
    private func matchesMountedPath(_ reported: String?, expected: URL) -> Bool {
        guard let reported, reported.hasPrefix("/"), !reported.utf8.contains(0),
              URL(fileURLWithPath: reported).standardizedFileURL.resolvingSymlinksInPath()
                == expected.standardizedFileURL.resolvingSymlinksInPath() else { return false }
        guard let left = try? EvidenceViewFiles.openDirectory(URL(fileURLWithPath: reported)) else { return false }
        defer { Darwin.close(left) }
        guard let right = try? EvidenceViewFiles.openDirectory(expected) else { return false }
        defer { Darwin.close(right) }
        var lhs = stat(), rhs = stat(), leftFS = statfs(), rightFS = statfs()
        guard Darwin.fstat(left, &lhs) == 0, Darwin.fstat(right, &rhs) == 0,
              lhs.st_dev == rhs.st_dev, lhs.st_ino == rhs.st_ino,
              Darwin.fstatfs(left, &leftFS) == 0, Darwin.fstatfs(right, &rightFS) == 0 else { return false }
        return withUnsafeBytes(of: leftFS.f_fsid) { Array($0) } == withUnsafeBytes(of: rightFS.f_fsid) { Array($0) }
    }
    func markQuarantine(reason: String = "attach-client-terminal-not-confirmed") throws {
        guard ["attach-client-terminal-not-confirmed", "base-mount-client-terminal-not-confirmed",
               "snapshot-mount-client-terminal-not-confirmed", "snapshot-unmount-client-terminal-not-confirmed"].contains(reason) else {
            throw APFSReadError.cleanupIncomplete
        }
        try EvidenceViewFiles.validateDirectory(rootURL, descriptor: rootFD)
        try EvidenceViewFiles.validateDirectory(directoryURL, descriptor: directoryFD)
        let marker = Darwin.openat(directoryFD, "quarantine.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if marker < 0 { if errno == EEXIST { return }; throw APFSReadError.cleanupIncomplete }
        defer { Darwin.close(marker) }
        let data = Data("{\"schemaVersion\":1,\"state\":\"cleanupUncertain\",\"reason\":\"\(reason)\",\"backingImageRetained\":true}".utf8)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let amount = Darwin.write(marker, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if amount < 0 && errno == EINTR { continue }
                guard amount > 0 else { throw APFSReadError.cleanupIncomplete }; offset += amount
            }
        }
        guard Darwin.fsync(marker) == 0, Darwin.fsync(directoryFD) == 0 else { throw APFSReadError.cleanupIncomplete }
    }
    func cleanup() throws {
        if cleaned { return }
        try EvidenceViewFiles.validateDirectory(rootURL, descriptor: rootFD)
        try EvidenceViewFiles.validateDirectory(directoryURL, descriptor: directoryFD)
        guard !retainBackingImage else { throw APFSReadError.cleanupIncomplete }
        if snapshotTargetCreated {
            let descriptor = Darwin.openat(directoryFD, "snapshot-view", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw APFSReadError.cleanupIncomplete }
            defer { Darwin.close(descriptor) }
            guard try underlyingSnapshotTargetIsOwned(descriptor) else { throw APFSReadError.cleanupIncomplete }
            guard Darwin.unlinkat(directoryFD, "snapshot-view", AT_REMOVEDIR) == 0 else { throw APFSReadError.cleanupIncomplete }
            snapshotTargetCreated = false; snapshotTargetIdentity = nil
        }
        // Known leaves only. A replacement/extra file keeps the private
        // directory rather than deleting another process's paths recursively.
        if Darwin.unlinkat(directoryFD, "view", AT_REMOVEDIR) != 0 && errno != ENOENT { throw APFSReadError.cleanupIncomplete }
        if imageIdentity != nil {
            try validate()
            guard Darwin.unlinkat(directoryFD, "image.dmg", 0) == 0 else { throw APFSReadError.cleanupIncomplete }
        }
        guard Darwin.unlinkat(rootFD, name, AT_REMOVEDIR) == 0 else { throw APFSReadError.cleanupIncomplete }
        cleaned = true
    }
}
