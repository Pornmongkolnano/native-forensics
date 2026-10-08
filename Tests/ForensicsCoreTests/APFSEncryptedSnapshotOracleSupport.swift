import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// Test-only independent construction/observation. Never attaches the frozen
/// original or selected encrypted evidence. Key lifetime is this fixture only.
final class AESnapshotFixture: @unchecked Sendable {
    static let baseUUID = UUID(uuidString: "3322234B-EE3F-467B-9D1E-D1E430DF8F5B")!
    static let snapshot = APFSSnapshotInventoryEntry(uuid: UUID(uuidString: "3222234B-EE3F-467B-9D1E-D1E430DF8F5B")!, name: "nf-before", transactionID: 1)
    static let earlierSHA = "712f13ec2ad0f05759975b7b798ec8cdd1166b7f3d51d28ff279c46e487277fd"
    static let laterSHA = "f4f68d721a9e07f438bb76269b78769416256ae43cd250fd0dad9d30e8e9c2df"
    static let earlier = literal("NATIVE FORENSICS BEFORE SNAPSHOT\n", "earlier-known-block;0123456789abcdef\n")
    static let later = literal("NATIVE FORENSICS AFTER SNAPSHOT\n", "later-known-block!!;fedcba9876543210\n")
    private static let originalSHA = "11ddb1a8aa08625a21ba923efdf3cc8c1c11928db0d936d3d009a14651c502b6"
    private static let outputCap: Int64 = 512 * 1_024 * 1_024
    private static let reserve: UInt64 = 30 * 1_024 * 1_024 * 1_024
    let root: URL, scratch: URL, image: URL
    var inspectedSourceIdentity: SourceIdentity { cipherIdentity! }
    private(set) var cipherSHA = ""
    private(set) var cipherBytes: Int64 = 0
    private let originalURL: URL
    private let lock = NSLock()
    private var key = Data()
    private var rootFD: Int32 = -1, originalParentFD: Int32 = -1, originalFD: Int32 = -1
    private var cipherFD: Int32 = -1, stagingFD: Int32 = -1
    private var originalState: AESFileState?, cipherState: AESFileState?, workingState: AESFileState?
    private var originalParentState: AESFileState?, rootState: AESFileState?, stagingState: AESFileState?
    private var cipherIdentity: SourceIdentity?
    private let began = ContinuousClock().now
    private var cleanup = false, cleanupDeadline: ContinuousClock.Instant?
    private var uncertain = false, constructed = false, finished = false
    private var operationSnapshot = false, attachStarts = 0, attachTerminals = 0, mounts = 0, audits = 0
    private var terminalProofs = 0, terminalRawStatus: Int32?, failures: [String] = []
    private var expectingWrongAttach = false, wrongAttachEmptyProofs = 0
    private var knownImages: Set<String> = []
    private var knownBindings: [String: (state: AESFileState, sha256: String)] = [:]
    private var oraclePrivatePath: String?, oracleViewPath: String?, oracleSnapshotPath: String?
    private var secretCommands: [(operation: String, rawStatus: Int32, stdoutBytes: Int, stderrBytes: Int)] = []

    init() throws {
        guard let selected = ProcessInfo.processInfo.environment["NF_APFS_SNAPSHOT_FIXTURE_PATH"],
              selected.hasPrefix("/"), !selected.utf8.contains(0), !selected.split(separator: "/").contains("..") else { throw Self.failure("Pinned plaintext fixture path required.") }
        originalURL = URL(fileURLWithPath: selected).standardizedFileURL
        let lab = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            .appendingPathComponent("local/apfs-combinations", isDirectory: true)
        let labFD = try Self.openDirectory(lab.path)
        defer { Darwin.close(labFD) }
        let labPath = try Self.fdPath(labFD)
        var template = Array((labPath + "/aes-api-XXXXXX").utf8CString)
        let created = template.withUnsafeMutableBufferPointer { b -> String? in
            guard let p = mkdtemp(b.baseAddress!) else { return nil }; return String(cString: p)
        }
        guard let created else { throw Self.failure("Cannot create owned AES fixture.") }
        root = URL(fileURLWithPath: created, isDirectory: true)
        scratch = root.appendingPathComponent("adapter-scratch", isDirectory: true)
        image = root.appendingPathComponent("encrypted-source.dmg")
        do {
            rootFD = try Self.openDirectory(created); rootState = try AESFileState(rootFD)
            originalParentFD = try Self.openDirectory(originalURL.deletingLastPathComponent().path)
            originalParentState = try AESFileState(originalParentFD)
            originalFD = Darwin.openat(originalParentFD, originalURL.lastPathComponent, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            guard originalFD >= 0 else { throw Self.failure("Cannot open pinned plaintext fixture.") }
            let original = try AESFileState(originalFD)
            guard original.isRegular, original.size == 392_537, original.uid == geteuid(), original.links == 1,
                  original.mode & 0o7777 == 0o400 else { throw Self.failure("Immutable plaintext fixture scope changed.") }
            originalState = original; try requireSourcesPreserved()
            guard try Self.digest(originalFD, size: original.size) == Self.originalSHA else { throw Self.failure("Plaintext fixture hash mismatch.") }
            try requireFreeSpace(Self.reserve + 2 * 1_024 * 1_024 * 1_024)
            try makeDirectory("adapter-scratch"); try makeDirectory("oracle-scratch"); try makeDirectory("convert-staging")
            stagingFD = Darwin.openat(rootFD, "convert-staging", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard stagingFD >= 0 else { throw Self.failure("Conversion staging unavailable.") }; stagingState = try AESFileState(stagingFD)
            try clone(originalFD, parent: rootFD, name: "working-plaintext.dmg", mode: 0o600)
            let workingFD = try openLeaf(rootFD, "working-plaintext.dmg"); defer { Darwin.close(workingFD) }
            workingState = try AESFileState(workingFD)
            guard try Self.digest(workingFD, size: 392_537) == Self.originalSHA else { throw Self.failure("Construction clone mismatch.") }
            key = Self.randomKey()
            let staged = created + "/convert-staging/encrypted-wrapper.dmg"
            knownImages = [created + "/working-plaintext.dmg", staged, image.path]
            knownBindings[created + "/working-plaintext.dmg"] = (workingState!, Self.originalSHA)
            _ = try run("/usr/bin/hdiutil", ["convert", created + "/working-plaintext.dmg", "-format", "UDRO", "-encryption", "AES-256", "-stdinpass", "-o", staged], secret: true, daemon: true)
            try requireAllKnownImagesAbsent()
            let candidate = try openLeaf(stagingFD, "encrypted-wrapper.dmg"); defer { Darwin.close(candidate) }
            let candidateState = try AESFileState(candidate)
            guard candidateState.isRegular, candidateState.uid == geteuid(), candidateState.links == 1,
                  candidateState.size > 0, candidateState.size <= Self.outputCap else { throw Self.failure("Encrypted output scope exceeded.") }
            try Self.requireMainFork(candidate)
            guard Darwin.fchmod(candidate, 0o400) == 0, Darwin.fsync(candidate) == 0 else { throw Self.failure("Encrypted output freeze failed.") }
            let beforeRename = try AESFileState(candidate)
            guard Darwin.renameatx_np(stagingFD, "encrypted-wrapper.dmg", rootFD, "encrypted-source.dmg", UInt32(RENAME_EXCL)) == 0 else { throw Self.failure("Exclusive encrypted publication failed.") }
            let adopted = try AESFileState(candidate)
            guard beforeRename.equalExceptCTime(adopted), try AESFileState(rootFD, "encrypted-source.dmg") == adopted,
                  Darwin.fsync(stagingFD) == 0, Darwin.fsync(rootFD) == 0 else { throw Self.failure("Encrypted publication identity failed.") }
            cipherFD = try openLeaf(rootFD, "encrypted-source.dmg")
            cipherState = try AESFileState(cipherFD)
            guard cipherState == adopted, try AESFileState(rootFD, "encrypted-source.dmg") == adopted else { throw Self.failure("Opened encrypted publication was replaced.") }
            cipherIdentity = try FileAccess.identity(of: cipherFD)
            cipherBytes = adopted.size; cipherSHA = try Self.digest(cipherFD, size: cipherBytes)
            guard try AESFileState(cipherFD) == adopted, try AESFileState(rootFD, "encrypted-source.dmg") == adopted else { throw Self.failure("Encrypted publication changed during hashing.") }
            knownBindings[image.path] = (adopted, cipherSHA)
            let header = try Self.bytes(cipherFD, offset: 0, count: 12)
            let encryption = try plist("/usr/bin/hdiutil", ["isencrypted", "-plist", image.path])
            guard header == Data([0x65,0x6e,0x63,0x72,0x63,0x64,0x73,0x61,0,0,0,2]),
                  encryption["encrypted"] as? Bool == true else { throw Self.failure("Expected encrypted v2 declaration missing.") }
            try requireSourcesPreserved()
            try independentColdOracle()
            guard secretCommands.count == 2, secretCommands.map({ $0.operation }) == ["convert", "attach"],
                  secretCommands.allSatisfy({ $0.rawStatus == 0 && $0.stdoutBytes <= 2 * 1_024 * 1_024 && $0.stderrBytes <= 128 * 1_024 }) else { throw Self.failure("Secret command discard/count-only construction proof missing.") }
            constructed = true
        } catch {
            // Original source mutation must not prevent cleanup of separately
            // held owned backing. Unknown utility terminal keeps all artifacts.
            try? drainKnownImages()
            closeDescriptors(); eraseKey(); throw error
        }
    }
    deinit { finishBestEffort(); closeDescriptors() }

    func credential() throws -> APFSPassphrase {
        try lock.withLock { guard !key.isEmpty else { throw APFSReadError.credentialConsumed }; return try APFSPassphrase(key) }
    }
    func wrongCredential() throws -> APFSPassphrase {
        try lock.withLock {
            guard !key.isEmpty else { throw APFSReadError.credentialConsumed }
            var wrong = key; wrong[wrong.startIndex] = wrong.first == 0x30 ? 0x31 : 0x30
            defer { wrong.resetBytes(in: 0..<wrong.count) }; return try APFSPassphrase(wrong)
        }
    }
    func options(snapshot: UUID? = nil) -> APFSReadOptions {
        .init(maximumEntries: 128, maximumFileBytes: 32_768, maximumContainerBytes: max(cipherBytes, 1), commandTimeoutSeconds: 30,
              maximumDepth: 8, maximumMetadataBytes: 65_536, maximumAggregateFileBytes: 65_536,
              jobTimeoutSeconds: 180, selectedVolumeUUID: Self.baseUUID, selectedSnapshotUUID: snapshot)
    }
    func begin(snapshot: UUID? = nil, wrongAttach: Bool = false) {
        lock.withLock {
            operationSnapshot = snapshot != nil; attachStarts = 0; attachTerminals = 0; mounts = 0; audits = 0
            terminalProofs = 0; terminalRawStatus = nil; failures.removeAll()
            expectingWrongAttach = wrongAttach; wrongAttachEmptyProofs = 0
        }
    }
    func adapter(additionalLifecycle: @escaping @Sendable (APFSReadLifecycleStage) -> Void = { _ in },
                 proveSnapshotTerminal: Bool = false) -> APFSMountedImageAdapter {
        APFSMountedImageAdapter(scratchRoot: scratch, snapshotMountDiagnostic: { [self] diagnostic in
            if proveSnapshotTerminal {
                lock.withLock { terminalRawStatus = diagnostic.naturalRawWaitStatus }
                guard diagnostic.naturalRawWaitStatus == 0 else { recordFailure("Cancelled snapshot command did not succeed."); return }
                do { try mountedOracle(scratch: scratch, snapshot: true, metadataOnly: true); lock.withLock { terminalProofs += 1 } }
                catch { recordFailure("Cancelled snapshot metadata proof failed.") }
            }
        }) { [self] stage in
            switch stage {
            case .attachClientStarted: lock.withLock { attachStarts += 1 }
            case .attachCommandTerminal:
                let wrong = lock.withLock { attachTerminals += 1; return expectingWrongAttach }
                if wrong {
                    do { try requireRejectedAttachMapping(); lock.withLock { wrongAttachEmptyProofs += 1 } }
                    catch { recordFailure("Wrong-key terminal owned-device absence not proven.") }
                }
            case .mounted:
                let snapshot = lock.withLock { mounts += 1; return operationSnapshot }
                do { try mountedOracle(scratch: scratch, snapshot: snapshot, metadataOnly: false); lock.withLock { audits += 1 } }
                catch { recordFailure("Independent encrypted mounted-byte proof failed.") }
            default: break
            }
            additionalLifecycle(stage)
        }
    }
    func requireNoAttach() throws { try lock.withLock { guard attachStarts == 0, attachTerminals == 0, mounts == 0, failures.isEmpty else { throw Self.failure("Rejected credential unexpectedly attached.") } } }
    func requireWrongAttachTerminal() throws { try lock.withLock { guard attachStarts == 1, attachTerminals == 1, wrongAttachEmptyProofs == 1, mounts == 0, failures.isEmpty else { throw Self.failure("Wrong-key natural attach refusal not proven.") } } }
    func requireMountedAudit() throws { try lock.withLock { guard mounts == 1, audits == 1, failures.isEmpty else { throw Self.failure("Independent mounted audit did not pass exactly once.") } } }
    func requireSuccessfulSnapshotTerminalProof() throws { try lock.withLock { guard terminalRawStatus == 0, terminalProofs == 1, mounts == 0, failures.isEmpty else { throw Self.failure("Successful owned snapshot cancellation proof missing.") } } }
    func requireEmptyScratch() throws {
        let descriptor = try Self.openDirectory(scratch.path); defer { Darwin.close(descriptor) }
        let state = try AESFileState(descriptor)
        let entries = try FileManager.default.contentsOfDirectory(atPath: scratch.path)
        guard state.uid == geteuid(), entries.isEmpty else { throw Self.failure("Owned adapter scratch not empty.") }
    }
    func requireSourcesPreserved() throws {
        try ownedRootGuard()
        guard let originalState, try AESFileState(originalFD) == originalState,
              try AESFileState(originalParentFD, originalURL.lastPathComponent) == originalState else { throw Self.failure("Original source full identity changed.") }
        let namedParent = try Self.openDirectory(originalURL.deletingLastPathComponent().path); defer { Darwin.close(namedParent) }
        guard let originalParentState, try AESFileState(namedParent).sameDirectory(originalParentState),
              try AESFileState(originalParentFD).sameDirectory(originalParentState) else { throw Self.failure("Original named parent changed.") }
        try Self.requireMainFork(originalFD)
        guard try Self.digest(originalFD, size: 392_537) == Self.originalSHA,
              try AESFileState(originalFD) == originalState,
              try AESFileState(originalParentFD, originalURL.lastPathComponent) == originalState else { throw Self.failure("Original complete bytes changed.") }
        if let cipherState {
            try Self.requireMainFork(cipherFD)
            guard try AESFileState(cipherFD) == cipherState, try AESFileState(rootFD, "encrypted-source.dmg") == cipherState,
                  try Self.digest(cipherFD, size: cipherBytes) == cipherSHA,
                  try AESFileState(cipherFD) == cipherState else { throw Self.failure("Encrypted evidence source changed.") }
        }
        if let workingState {
            let descriptor = try openLeaf(rootFD, "working-plaintext.dmg"); defer { Darwin.close(descriptor) }
            let current = try AESFileState(descriptor)
            guard current == workingState, try Self.digest(descriptor, size: 392_537) == Self.originalSHA,
                  try AESFileState(descriptor) == workingState,
                  try AESFileState(rootFD, "working-plaintext.dmg") == workingState else { throw Self.failure("Construction clone content changed.") }
        }
    }
    func requireMetadataExcludesKey(_ bodies: [Data]) throws {
        let leaked = try lock.withLock {
            guard !key.isEmpty else { throw APFSReadError.credentialConsumed }
            return bodies.contains { $0.range(of: key) != nil }
        }
        guard !leaked else { throw Self.failure("Credential was found in owned metadata.") }
    }
    /// Public export uses its default temporary parent. A held parent plus
    /// namespace/device inventory fence proves no new default job remains.
    /// This deliberately fails on concurrent changes; run this suite alone.
    func beginDefaultExportFence() throws -> AESDefaultExportFence {
        try requireSourcesPreserved(); try requireEmptyScratch()
        let requested = FileManager.default.temporaryDirectory.path
        guard let resolved = Darwin.realpath(requested, nil) else { throw Self.failure("Default temporary parent unavailable.") }
        let canonical = String(cString: resolved); free(resolved)
        let descriptor = try Self.openDirectory(canonical)
        do {
            let state = try AESFileState(descriptor)
            guard state.uid == geteuid() else { throw Self.failure("Default temporary parent owner changed.") }
            let named = Darwin.open(requested, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard named >= 0 else { throw Self.failure("Default temporary alias unavailable.") }
            defer { Darwin.close(named) }
            guard try AESFileState(named).sameDirectory(state) else { throw Self.failure("Default temporary alias identity changed.") }
            let names = try defaultJobNames(canonical)
            let attachments = try defaultJobAttachments(parents: [canonical, requested])
            return AESDefaultExportFence(descriptor: descriptor, state: state, canonical: canonical,
                requested: requested, names: names, attachments: attachments)
        } catch { Darwin.close(descriptor); throw error }
    }
    func requireDefaultExportFence(_ fence: AESDefaultExportFence) throws {
        let named = try Self.openDirectory(fence.canonical); defer { Darwin.close(named) }
        let alias = Darwin.open(fence.requested, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard alias >= 0 else { throw Self.failure("Default export alias unavailable.") }
        defer { Darwin.close(alias) }
        guard try AESFileState(fence.descriptor).sameDirectory(fence.state),
              try AESFileState(named).sameDirectory(fence.state),
              try AESFileState(alias).sameDirectory(fence.state) else { throw Self.failure("Default export parent replaced.") }
        let names = try defaultJobNames(fence.canonical)
        let attachments = try defaultJobAttachments(parents: [fence.canonical, fence.requested])
        guard names == fence.names, attachments == fence.attachments else { throw Self.failure("Default export job or attachment did not drain.") }
        try requireSourcesPreserved(); try requireEmptyScratch()
    }
    private func defaultJobNames(_ path: String) throws -> Set<String> {
        let descriptor = try Self.openDirectory(path); defer { Darwin.close(descriptor) }
        let copy = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else { throw Self.failure("Temporary enumeration descriptor unavailable.") }
        guard let stream = Darwin.fdopendir(copy) else { Darwin.close(copy); throw Self.failure("Temporary enumeration unavailable.") }
        defer { Darwin.closedir(stream) }
        var count = 0, result: Set<String> = []
        while true {
            errno = 0
            guard let entry = Darwin.readdir(stream) else { guard errno == 0 else { throw Self.failure("Temporary enumeration failed.") }; return result }
            count += 1; guard count <= 65_536 else { throw Self.failure("Default temporary namespace bound exceeded.") }
            let name = Self.tupleString(entry.pointee.d_name)
            if name.range(of: #"^\.native-apfs-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"#, options: .regularExpression) != nil { result.insert(name) }
        }
    }
    private func defaultJobAttachments(parents: Set<String>) throws -> Set<String> {
        let inventory = try plist("/usr/bin/hdiutil", ["info", "-plist"])
        guard let rows = inventory["images"] as? [[String: Any]], rows.count <= 4_096 else { throw Self.failure("Default attachment envelope invalid.") }
        var result: Set<String> = []
        for row in rows {
            guard let path = row["image-path"] as? String else { throw Self.failure("Image inventory path missing.") }
            let file = URL(fileURLWithPath: path), job = file.deletingLastPathComponent()
            guard file.lastPathComponent == "image.dmg", parents.contains(job.deletingLastPathComponent().path),
                  job.lastPathComponent.range(of: #"^\.native-apfs-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"#, options: .regularExpression) != nil else { continue }
            guard let entities = row["system-entities"] as? [[String: Any]] else { throw Self.failure("Default attachment entities missing.") }
            let nodes = try deviceNodes(entities)
            let value = job.lastPathComponent + ":" + nodes.sorted().joined(separator: ",")
            guard result.insert(value).inserted else { throw Self.failure("Default attachment mapping ambiguous.") }
        }
        return result
    }
    func finish() throws {
        try requireSourcesPreserved(); try requireEmptyScratch(); try drainKnownImages()
        try requireSourcesPreserved(); finished = true; eraseKey()
    }
    func finishBestEffort() {
        if !finished { try? drainKnownImages() }
        eraseKey()
        // Retain this small ignored corpus, including any quarantine. No
        // recursive deletion can erase a backing image or failed proof.
    }

    private func independentColdOracle() throws {
        let oracleScratch = root.appendingPathComponent("oracle-scratch", isDirectory: true)
        let scratchFD = try Self.openDirectory(oracleScratch.path); defer { Darwin.close(scratchFD) }
        let name = ".native-apfs-" + UUID().uuidString
        guard Darwin.mkdirat(scratchFD, name, 0o700) == 0 else { throw Self.failure("Independent oracle job creation failed.") }
        let job = oracleScratch.appendingPathComponent(name, isDirectory: true)
        let jobFD = try Self.openDirectory(job.path); defer { Darwin.close(jobFD) }
        try clone(cipherFD, parent: jobFD, name: "image.dmg", mode: 0o400)
        guard Darwin.mkdirat(jobFD, "view", 0o700) == 0, Darwin.mkdirat(jobFD, "snapshot-view", 0o700) == 0 else { throw Self.failure("Independent targets unavailable.") }
        let privateImage = job.appendingPathComponent("image.dmg").path
        knownImages.insert(privateImage)
        let pinnedPrivate = try openLeaf(jobFD, "image.dmg"); defer { Darwin.close(pinnedPrivate) }
        let pinnedState = try AESFileState(pinnedPrivate)
        let pinnedHash = try Self.digest(pinnedPrivate, size: pinnedState.size)
        guard pinnedState.size == cipherBytes, pinnedHash == cipherSHA else { throw Self.failure("Independent encrypted copy mismatch.") }
        knownBindings[privateImage] = (pinnedState, pinnedHash)
        oraclePrivatePath = privateImage
        oracleViewPath = try Self.fdPath(jobFD) + "/view"
        oracleSnapshotPath = try Self.fdPath(jobFD) + "/snapshot-view"
        _ = try run("/usr/bin/hdiutil", ["attach", "-readonly", "-nomount", "-noautofsck", "-noverify", "-nobrowse", "-noautoopen", "-plist", "-stdinpass", privateImage], secret: true, daemon: true)
        let scope = try ownedScope(privateImage)
        let fsck = try run("/sbin/fsck_apfs", ["-n", scope.physical.replacingOccurrences(of: "/dev/disk", with: "/dev/rdisk")])
        let text = String(decoding: fsck.stdout, as: UTF8.self).lowercased()
        guard fsck.stderrBytes == 0, text.contains("appears to be ok"), !["warning:", "error:", "invalid "].contains(where: text.contains) else { throw Self.failure("Independent complete Apple fsck was not clean.") }
        let view = try Self.fdPath(jobFD) + "/view", historical = try Self.fdPath(jobFD) + "/snapshot-view"
        _ = try run("/usr/sbin/diskutil", ["mount", "readOnly", "nobrowse", "-mountOptions", "noexec,nosuid,nodev", "-mountPoint", view, scope.volume], daemon: true)
        _ = try run("/sbin/mount_apfs", ["-o", "rdonly,nobrowse,noexec,nosuid,nodev,nofollow", "-s", Self.snapshot.name, view, historical], daemon: true)
        try mountedOracle(scratch: oracleScratch, snapshot: true, metadataOnly: false)
        _ = try run("/sbin/umount", [historical], daemon: true)
        _ = try run("/sbin/umount", [view], daemon: true)
        try detach(imagePath: privateImage)
        oraclePrivatePath = nil; oracleViewPath = nil; oracleSnapshotPath = nil
        try requireSourcesPreserved()
        // Remove only verified unmounted empty dirs and the exact owned private
        // leaf after positive detach; retained selected cipher source remains.
        let privateFD = try openLeaf(jobFD, "image.dmg"); let state = try AESFileState(privateFD); Darwin.close(privateFD)
        guard state == pinnedState, state.isRegular, state.size == cipherBytes,
              try AESFileState(pinnedPrivate) == pinnedState,
              try Self.digest(pinnedPrivate, size: cipherBytes) == cipherSHA,
              try AESFileState(pinnedPrivate) == pinnedState,
              try AESFileState(jobFD, "image.dmg") == state else { throw Self.failure("Independent private cleanup binding failed.") }
        guard Darwin.unlinkat(jobFD, "image.dmg", 0) == 0,
              Darwin.unlinkat(jobFD, "snapshot-view", AT_REMOVEDIR) == 0, Darwin.unlinkat(jobFD, "view", AT_REMOVEDIR) == 0,
              Darwin.unlinkat(scratchFD, name, AT_REMOVEDIR) == 0 else { throw Self.failure("Independent owned leaf cleanup failed.") }
    }

    private func mountedOracle(scratch: URL, snapshot: Bool, metadataOnly: Bool) throws {
        try requireSourcesPreserved()
        let scratchFD = try Self.openDirectory(scratch.path); defer { Darwin.close(scratchFD) }
        let scratchState = try AESFileState(scratchFD)
        let state = rootState!
        let result = try run("/usr/bin/python3", ["-c", Self.pythonMountedOracle,
            try Self.fdPath(scratchFD), metadataOnly ? "metadata" : (snapshot ? "snapshot" : "current"), try Self.fdPath(rootFD),
            String(state.device), String(state.inode), String(scratchState.device), String(scratchState.inode),
            String(cipherBytes), cipherSHA], timeout: 90, enforceConstructionBudget: false)
        guard result.stdout.count <= 65_536,
              let body = try JSONSerialization.jsonObject(with: result.stdout) as? [String: Any], body["ok"] as? Bool == true,
              body["privateSHA256"] as? String == cipherSHA,
              body["baseUUID"] as? String == Self.baseUUID.uuidString else { throw Self.failure("Independent mounted oracle rejected owned state.") }
        if snapshot {
            guard body["snapshotUUID"] as? String == Self.snapshot.uuid.uuidString,
                  body["transactionID"] as? Int == 1 else { throw Self.failure("Independent snapshot tuple mismatch.") }
        }
        if !metadataOnly {
            guard body["currentSHA256"] as? String == Self.laterSHA,
                  !snapshot || (body["historySHA256"] as? String) == Self.earlierSHA else { throw Self.failure("Independent current/history byte mismatch.") }
        }
        try requireSourcesPreserved()
    }
    private func recordFailure(_ label: String) { lock.withLock { if failures.count < 8 { failures.append(label) } } }
    private func requireRejectedAttachMapping() throws {
        try requireSourcesPreserved()
        let parent = try Self.openDirectory(scratch.path); defer { Darwin.close(parent) }
        let names = try FileManager.default.contentsOfDirectory(atPath: scratch.path)
        guard names.count == 1, names[0].range(of: #"^\.native-apfs-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"#, options: .regularExpression) != nil else { throw Self.failure("Wrong-key scratch ownership envelope invalid.") }
        let job = Darwin.openat(parent, names[0], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard job >= 0 else { throw Self.failure("Wrong-key owned job unavailable.") }; defer { Darwin.close(job) }
        let jobState = try AESFileState(job)
        guard jobState.uid == geteuid(), jobState.device == rootState!.device, jobState.mode & 0o7777 == 0o700,
              try AESFileState(parent, names[0]) == jobState else { throw Self.failure("Wrong-key owned job changed.") }
        let source = try openLeaf(job, "image.dmg"); defer { Darwin.close(source) }
        let sourceState = try AESFileState(source)
        guard sourceState.uid == geteuid(), sourceState.links == 1, sourceState.mode & 0o7777 == 0o400,
              sourceState.size == cipherBytes, try AESFileState(job, "image.dmg") == sourceState,
              try Self.digest(source, size: cipherBytes) == cipherSHA,
              try AESFileState(source) == sourceState else { throw Self.failure("Wrong-key private cipher binding failed.") }
        let expected = try Self.fdPath(job) + "/image.dmg"
        let body = try plist("/usr/bin/hdiutil", ["info", "-plist"])
        guard let rows = body["images"] as? [[String: Any]], rows.count <= 4_096 else { throw Self.failure("Wrong-key image inventory invalid.") }
        for row in rows {
            guard let path = row["image-path"] as? String, path.hasPrefix("/"), !path.utf8.contains(0) else { throw Self.failure("Wrong-key image inventory path invalid.") }
            let url = URL(fileURLWithPath: path)
            if path == expected || (url.lastPathComponent == "image.dmg" && url.deletingLastPathComponent().lastPathComponent == names[0]) {
                throw Self.failure("Wrong-key attach had an owned device mapping at terminal.")
            }
        }
        guard try AESFileState(job) == jobState, try AESFileState(parent, names[0]) == jobState,
              try AESFileState(source) == sourceState, try AESFileState(job, "image.dmg") == sourceState else { throw Self.failure("Wrong-key private state changed during inventory.") }
        try requireSourcesPreserved()
    }

    private func ownedScope(_ imagePath: String) throws -> (volume: String, physical: String) {
        guard let row = try ownedImage(imagePath), let entities = row["system-entities"] as? [[String: Any]] else { throw Self.failure("Owned attachment missing.") }
        let nodes = try deviceNodes(entities)
        var volumes: [[String: Any]] = []
        for node in nodes.sorted() {
            let info = try plist("/usr/sbin/diskutil", ["info", "-plist", node])
            if info["FilesystemType"] as? String == "apfs", info["VolumeUUID"] as? String == Self.baseUUID.uuidString { volumes.append(info) }
        }
        guard volumes.count == 1, let volume = volumes[0]["DeviceNode"] as? String, nodes.contains(volume),
              volumes[0]["Encryption"] as? Bool == false, volumes[0]["FileVault"] as? Bool == false,
              volumes[0]["Locked"] as? Bool == false, volumes[0]["WritableMedia"] as? Bool == false,
              let stores = volumes[0]["APFSPhysicalStores"] as? [[String: Any]], stores.count == 1,
              let identifier = stores[0]["APFSPhysicalStore"] as? String, nodes.contains("/dev/" + identifier) else { throw Self.failure("Independent plaintext volume/store binding failed.") }
        return (volume, "/dev/" + identifier)
    }
    private func deviceNodes(_ entities: [[String: Any]]) throws -> Set<String> {
        guard !entities.isEmpty, entities.count <= 64 else { throw Self.failure("Device inventory bound failed.") }
        let nodes = entities.compactMap { $0["dev-entry"] as? String }
        guard nodes.count == entities.count, Set(nodes).count == nodes.count,
              nodes.allSatisfy({ $0.range(of: #"^/dev/disk[0-9]+(?:s[0-9]+)*$"#, options: .regularExpression) != nil }) else { throw Self.failure("Owned device grammar failed.") }
        return Set(nodes)
    }
    private func ownedImage(_ path: String) throws -> [String: Any]? {
        guard knownImages.contains(path) else { throw Self.failure("Unowned image path rejected.") }
        let body = try plist("/usr/bin/hdiutil", ["info", "-plist"])
        guard let rows = body["images"] as? [[String: Any]], rows.count <= 4_096 else { throw Self.failure("Image inventory envelope invalid.") }
        let matches = rows.filter { $0["image-path"] as? String == path }
        guard matches.count <= 1 else { throw Self.failure("Owned image inventory ambiguous.") }
        if let row = matches.first {
            let parent = try Self.openDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path); defer { Darwin.close(parent) }
            let name = URL(fileURLWithPath: path).lastPathComponent
            let fd = try openLeaf(parent, name); defer { Darwin.close(fd) }
            let state = try AESFileState(fd)
            guard let pinned = knownBindings[path], state == pinned.state,
                  state.isRegular, state.uid == geteuid(), state.links == 1, state.size > 0, state.size <= Self.outputCap,
                  try AESFileState(parent, name) == state,
                  try Self.digest(fd, size: state.size) == pinned.sha256,
                  try AESFileState(fd) == state,
                  try AESFileState(parent, name) == state else { throw Self.failure("Owned backing binding failed.") }
            return row
        }
        return nil
    }
    private func detach(imagePath: String) throws {
        guard !uncertain else { throw Self.failure("Uncertain daemon keeps backing quarantined.") }
        guard let row = try ownedImage(imagePath), let entries = row["system-entities"] as? [[String: Any]] else { return }
        let nodes = try deviceNodes(entries)
        let roots = nodes.filter { $0.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil }
        let candidates = entries.compactMap { e -> String? in
            guard let node = e["dev-entry"] as? String, roots.contains(node), let hint = e["content-hint"] as? String,
                  ["", "GUID_partition_scheme", "Apple_APFS", "7C3457EF-0000-11AA-AA11-00306543ECAC"].contains(hint) else { return nil }; return node
        }
        guard candidates.count == 1 else { throw Self.failure("Owned detach root ambiguous.") }
        _ = try run("/usr/bin/hdiutil", ["detach", candidates[0]], daemon: true)
        guard try ownedImage(imagePath) == nil else { throw Self.failure("Owned detach not confirmed.") }
    }
    private func requireAllKnownImagesAbsent() throws {
        for path in knownImages.sorted() { guard try ownedImage(path) == nil else { throw Self.failure("Construction daemon attachment remains.") } }
    }
    private func drainKnownImages() throws {
        guard !uncertain else { throw Self.failure("Uncertain native command retained its backing.") }
        cleanup = true; cleanupDeadline = ContinuousClock().now + .seconds(40)
        defer { cleanup = false; cleanupDeadline = nil }
        do {
            if let path = oraclePrivatePath, try ownedImage(path) != nil {
                let scope = try ownedScope(path)
                try unmountOracleTarget(oracleSnapshotPath, source: Self.snapshot.name + "@" + scope.volume, historical: true)
                try unmountOracleTarget(oracleViewPath, source: scope.volume, historical: false)
            }
            for path in knownImages.sorted() { try detach(imagePath: path) }
            try requireAllKnownImagesAbsent()
        } catch { uncertain = true; throw error }
    }
    private func unmountOracleTarget(_ path: String?, source: String, historical: Bool) throws {
        guard let path else { return }
        let parentURL = URL(fileURLWithPath: path).deletingLastPathComponent()
        guard parentURL.deletingLastPathComponent().lastPathComponent == "oracle-scratch",
              parentURL.lastPathComponent.hasPrefix(".native-apfs-") else { throw Self.failure("Oracle target scope invalid.") }
        let parent = try Self.openDirectory(parentURL.path); defer { Darwin.close(parent) }
        let parentState = try AESFileState(parent)
        guard parentState.device == rootState!.device, parentState.uid == geteuid(),
              parentState.mode & 0o7777 == 0o700 else { throw Self.failure("Oracle target parent changed.") }
        let name = URL(fileURLWithPath: path).lastPathComponent
        guard name == (historical ? "snapshot-view" : "view") else { throw Self.failure("Oracle target leaf invalid.") }
        let fd = try Self.openDirectory(path)
        var mounted = statfs(), host = statfs()
        do {
            let held = try AESFileState(fd)
            guard try AESFileState(parent, name) == held, Darwin.fstatfs(fd, &mounted) == 0,
                  Darwin.fstatfs(rootFD, &host) == 0 else { throw Self.failure("Oracle mount cleanup identity failed.") }
            if held.device == rootState!.device {
                guard held.uid == geteuid(), held.mode & 0o7777 == 0o700,
                      Self.fsid(mounted) == Self.fsid(host) else { throw Self.failure("Oracle underlying target changed.") }
                Darwin.close(fd); return
            }
            guard Self.tupleString(mounted.f_fstypename) == "apfs",
                  Self.tupleString(mounted.f_mntonname) == path,
                  Self.tupleString(mounted.f_mntfromname) == source,
                  mounted.f_flags & UInt32(MNT_RDONLY) != 0,
                  (mounted.f_flags & 0x40000000 != 0) == historical,
                  Self.fsid(mounted) != Self.fsid(host) else { throw Self.failure("Oracle mounted target ownership failed.") }
            Darwin.close(fd)
        } catch { Darwin.close(fd); throw error }
        _ = try run("/sbin/umount", [path], daemon: true)
        let after = try Self.openDirectory(path); defer { Darwin.close(after) }
        let afterState = try AESFileState(after)
        var kernel = statfs()
        guard afterState.device == rootState!.device, afterState.uid == geteuid(), afterState.mode & 0o7777 == 0o700,
              try AESFileState(parent, name) == afterState, Darwin.fstatfs(after, &kernel) == 0,
              Self.fsid(kernel) == Self.fsid(host) else { throw Self.failure("Oracle unmount not independently confirmed.") }
    }
    private func plist(_ tool: String, _ args: [String]) throws -> [String: Any] {
        let output = try run(tool, args)
        guard let parsed = try PropertyListSerialization.propertyList(from: output.stdout, format: nil) as? [String: Any] else { throw Self.failure("Native plist shape invalid.") }; return parsed
    }
    private func run(_ tool: String, _ args: [String], secret: Bool = false, daemon: Bool = false,
                     timeout: Double = 60, enforceConstructionBudget: Bool = true) throws -> AESNativeOutcome {
        let leakedArgument = lock.withLock { !key.isEmpty && args.contains { Data($0.utf8).range(of: key) != nil } }
        guard !leakedArgument else { throw Self.failure("Credential argument refused.") }
        var inputFD: Int32 = -1, inputParent: Int32 = -1
        var inputName: String?, inputParentPath: String?, inputState: AESFileState?, inputParentState: AESFileState?, inputSHA: String?
        defer { if inputFD >= 0 { Darwin.close(inputFD) }; if inputParent >= 0 { Darwin.close(inputParent) } }
        if secret {
            guard tool == "/usr/bin/hdiutil", let operation = args.first, ["convert", "attach"].contains(operation) else { throw Self.failure("Secret input operation invalid.") }
            let path = operation == "convert" ? (args.count > 1 ? args[1] : "") : (args.last ?? "")
            guard knownImages.contains(path), let binding = knownBindings[path] else { throw Self.failure("Unbound native image input refused.") }
            let url = URL(fileURLWithPath: path)
            inputName = url.lastPathComponent; inputParentPath = url.deletingLastPathComponent().path
            inputParent = try Self.openDirectory(inputParentPath!)
            inputParentState = try AESFileState(inputParent)
            inputFD = try openLeaf(inputParent, inputName!)
            inputState = binding.state; inputSHA = binding.sha256
            guard try AESFileState(inputFD) == binding.state,
                  try AESFileState(inputParent, inputName!) == binding.state,
                  try Self.digest(inputFD, size: binding.state.size) == binding.sha256,
                  try AESFileState(inputFD) == binding.state else { throw Self.failure("Native input bytes or identity changed before spawn.") }
        }
        func validateNativeInput() throws {
            guard let inputState, let inputName, let inputParentPath, let inputParentState else { return }
            guard try AESFileState(inputFD) == inputState,
                  try AESFileState(inputParent, inputName) == inputState,
                  try AESFileState(inputParent).sameDirectory(inputParentState) else { throw Self.failure("Held native input changed.") }
            let parent = try Self.openDirectory(inputParentPath); defer { Darwin.close(parent) }
            guard try AESFileState(parent).sameDirectory(inputParentState) else { throw Self.failure("Native input parent replaced.") }
            try Self.requireMainFork(inputFD)
        }
        var input: [UInt8]
        if secret { input = try keyInput() } else { input = [] }
        defer { _ = input.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        do {
            let outcome = try AESNativeRunner.run(tool: tool, arguments: args, input: &input, secret: secret,
                timeout: timeout, validate: { [self] in
                    try ownedRootGuard()
                    try validateNativeInput()
                    if !cleanup { try constructionBudget(enabled: enforceConstructionBudget) }
                    else if let cleanupDeadline, ContinuousClock().now >= cleanupDeadline { throw Self.failure("Owned cleanup deadline expired.") }
                    if !cleanup { try sourceIdentityGuard() }
                }, uncertain: { [self] in if daemon { uncertain = true } })
            if let inputState, let inputSHA {
                try validateNativeInput()
                guard try Self.digest(inputFD, size: inputState.size) == inputSHA else { throw Self.failure("Complete native input bytes changed after terminal.") }
                try validateNativeInput()
            }
            if secret {
                guard outcome.stdout.isEmpty else { throw Self.failure("Secret command content was retained.") }
                secretCommands.append((args[0], outcome.rawStatus, outcome.stdoutBytes, outcome.stderrBytes))
            }
            return outcome
        } catch { throw error }
    }
    private func constructionBudget(enabled: Bool) throws {
        if enabled && !constructed && ContinuousClock().now >= began + .seconds(480) { throw Self.failure("Construction job deadline expired.") }
        try requireFreeSpace(Self.reserve)
        let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        var total: Int64 = 0
        while let url = enumerator?.nextObject() as? URL {
            var state = stat(); guard Darwin.lstat(url.path, &state) == 0,
                  state.st_mode & S_IFMT == S_IFREG || state.st_mode & S_IFMT == S_IFDIR else { throw Self.failure("Owned corpus entry invalid.") }
            if state.st_dev != rootState!.device {
                guard state.st_mode & S_IFMT == S_IFDIR, ["view", "snapshot-view"].contains(url.lastPathComponent),
                      url.deletingLastPathComponent().lastPathComponent.hasPrefix(".native-apfs-"),
                      ["adapter-scratch", "oracle-scratch"].contains(url.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent) else { throw Self.failure("Unowned mount inside corpus refused.") }
                enumerator?.skipDescendants(); continue
            }
            guard state.st_uid == geteuid() else { throw Self.failure("Owned corpus entry owner changed.") }
            if state.st_mode & S_IFMT == S_IFREG {
                guard state.st_size >= 0, state.st_size <= 2 * 1_024 * 1_024 * 1_024 - total else { throw Self.failure("Owned corpus bound exceeded.") }; total += state.st_size
                if url.pathExtension == "dmg", state.st_size > Self.outputCap { throw Self.failure("Disk-image output bound exceeded.") }
            }
        }
    }
    private func requireFreeSpace(_ required: UInt64) throws {
        var value = statvfs()
        guard Darwin.fstatvfs(rootFD, &value) == 0, value.f_frsize > 0 else { throw Self.failure("Free-space observation failed.") }
        let blocks = UInt64(value.f_bavail), width = UInt64(value.f_frsize)
        let requiredBlocks = required / width + (required % width == 0 ? 0 : 1)
        guard blocks >= requiredBlocks else { throw Self.failure("Free-space reserve exhausted.") }
    }
    private func ownedRootGuard() throws {
        guard rootFD >= 0, let rootState, try AESFileState(rootFD).sameDirectory(rootState) else { throw Self.failure("Owned root FD changed.") }
        let named = try Self.openDirectory(root.path); defer { Darwin.close(named) }
        guard try AESFileState(named).sameDirectory(rootState) else { throw Self.failure("Owned root named path changed.") }
        if let stagingState {
            guard try AESFileState(stagingFD).sameDirectory(stagingState),
                  try AESFileState(rootFD, "convert-staging").sameDirectory(stagingState) else { throw Self.failure("Held conversion staging changed.") }
        }
    }
    private func sourceIdentityGuard() throws {
        guard let originalState, try AESFileState(originalFD) == originalState,
              try AESFileState(originalParentFD, originalURL.lastPathComponent) == originalState else { throw Self.failure("Original source changed during native job.") }
        try Self.requireMainFork(originalFD)
        if let cipherState {
            guard try AESFileState(cipherFD) == cipherState,
                  try AESFileState(rootFD, "encrypted-source.dmg") == cipherState else { throw Self.failure("Encrypted selected source changed during native job.") }
            try Self.requireMainFork(cipherFD)
        }
    }
    private func makeDirectory(_ name: String) throws { guard Darwin.mkdirat(rootFD, name, 0o700) == 0, Darwin.fsync(rootFD) == 0 else { throw Self.failure("Owned directory creation failed.") } }
    private func openLeaf(_ parent: Int32, _ name: String) throws -> Int32 {
        let fd = Darwin.openat(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Self.failure("Owned leaf unavailable.") }
        do { guard try AESFileState(fd).isRegular else { throw Self.failure("Owned leaf is not regular.") }; try Self.requireMainFork(fd); return fd }
        catch { Darwin.close(fd); throw error }
    }
    private func clone(_ source: Int32, parent: Int32, name: String, mode: mode_t) throws {
        try ownedRootGuard(); try Self.requireMainFork(source)
        guard fclonefileat(source, parent, name, UInt32(CLONE_NOFOLLOW)) == 0 else { throw Self.failure("Exclusive COW clone unavailable.") }
        let fd = try openLeaf(parent, name); defer { Darwin.close(fd) }
        guard Darwin.fchmod(fd, mode) == 0, Darwin.fsync(fd) == 0, Darwin.fsync(parent) == 0 else { throw Self.failure("Owned clone freeze failed.") }
    }
    private func keyInput() throws -> [UInt8] {
        try lock.withLock {
            guard !key.isEmpty else { throw APFSReadError.credentialConsumed }
            var input = key.withUnsafeBytes { Array($0) }; input.append(0); return input
        }
    }
    private func eraseKey() { lock.withLock { key.resetBytes(in: 0..<key.count); key.removeAll() } }
    private func closeDescriptors() { for fd in [cipherFD, stagingFD, originalFD, originalParentFD, rootFD] where fd >= 0 { Darwin.close(fd) }; cipherFD = -1; stagingFD = -1; originalFD = -1; originalParentFD = -1; rootFD = -1 }
    private static func randomKey() -> Data {
        var random = [UInt8](repeating: 0, count: 32), result = Data(count: 64)
        random.withUnsafeMutableBytes { arc4random_buf($0.baseAddress!, $0.count) }
        let alphabet = Array("0123456789abcdef".utf8)
        for (i, byte) in random.enumerated() { result[i * 2] = alphabet[Int(byte >> 4)]; result[i * 2 + 1] = alphabet[Int(byte & 15)] }
        _ = random.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }; return result
    }
    private static func literal(_ prefix: String, _ pattern: String) -> Data { Data((prefix + String(repeating: pattern, count: 16_384 / pattern.utf8.count + 2)).utf8.prefix(16_384)) }
    private static func failure(_ label: String) -> ForensicsError { .io(label) }
    private static func requireMainFork(_ fd: Int32) throws { let n = Darwin.fgetxattr(fd, "com.apple.ResourceFork", nil, 0, 0, 0); guard n == 0 || (n == -1 && errno == ENOATTR) else { throw failure("Unbound resource fork refused.") } }
    private static func openDirectory(_ path: String) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { throw failure("Absolute directory required.") }
        var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw failure("Directory root unavailable.") }
        do { for part in path.split(separator: "/") { guard part != ".", part != ".." else { throw failure("Directory traversal refused.") }; let next = Darwin.openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); guard next >= 0 else { throw failure("Directory component unavailable.") }; Darwin.close(fd); fd = next }; return fd }
        catch { Darwin.close(fd); throw error }
    }
    private static func fdPath(_ fd: Int32) throws -> String {
        var chars = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = chars.withUnsafeMutableBufferPointer { Darwin.fcntl(fd, F_GETPATH, $0.baseAddress!) }
        guard result == 0 else { throw failure("Owned FD path unavailable.") }
        return chars.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }
    private static func tupleString<T>(_ value: T) -> String {
        withUnsafeBytes(of: value) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
    }
    private static func fsid(_ value: statfs) -> Data { withUnsafeBytes(of: value.f_fsid) { Data($0) } }
    private static func bytes(_ fd: Int32, offset: Int64, count: Int) throws -> Data {
        var data = Data(count: count), consumed = 0
        try data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
            while consumed < count { let n = Darwin.pread(fd, buffer.baseAddress!.advanced(by: consumed), count - consumed, off_t(offset + Int64(consumed))); if n < 0 && errno == EINTR { continue }; guard n > 0 else { throw failure("Short independent source read.") }; consumed += n }
        }; return data
    }
    private static func digest(_ fd: Int32, size: Int64) throws -> String {
        var value = SHA256(), offset: Int64 = 0
        while offset < size { let data = try bytes(fd, offset: offset, count: Int(min(1_048_576, size - offset))); value.update(data: data); offset += Int64(data.count) }
        return value.finalize().map { String(format: "%02x", $0) }.joined()
    }
    // Independent public-SDK/stdlib oracle inserted below in this staged file.
    private static let pythonMountedOracle = #"""
import ctypes,errno,hashlib,json,os,plistlib,re,selectors,signal,stat,struct,subprocess,sys,time,uuid
from pathlib import Path
stage='arguments'
opened=[]
deadline=time.monotonic()+75
image_hash=None
image_bytes=None
base_uuid='3322234B-EE3F-467B-9D1E-D1E430DF8F5B'
container_uuid='98CF6C75-0405-4B89-B29C-14817D758C7F'
snapshot_uuid='3222234B-EE3F-467B-9D1E-D1E430DF8F5B'
snapshot_name='nf-before'
last_command=None
last_inventory=None

def check(condition,label):
 global stage
 stage=label
 if not condition: raise RuntimeError(label)

def fd_open(name,flags,parent=None):
 descriptor=os.open(name,flags|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
 opened.append(descriptor)
 return descriptor

def directory_path(path):
 path=Path(path)
 check(path.is_absolute() and not any(p in ('.','..') for p in path.parts[1:]),'scratch-path')
 # Parent aliases such as /tmp -> /private/tmp are legitimate. Resolve only
 # the parent, then open the controlled leaf with O_NOFOLLOW and bind its
 # descriptor to the independent Swift-held creation identity below.
 parent=path.parent.resolve(strict=True)
 descriptor=fd_open('/',os.O_RDONLY|os.O_DIRECTORY)
 for component in parent.parts[1:]:
  check(True,'directory-component')
  descriptor=fd_open(component,os.O_RDONLY|os.O_DIRECTORY,descriptor)
 check(True,'directory-component')
 return fd_open(path.name,os.O_RDONLY|os.O_DIRECTORY,descriptor)

def stable_stat(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_size,value.st_uid,value.st_gid,
         value.st_nlink,value.st_flags,value.st_mtime_ns,value.st_ctime_ns)

def held_state(descriptor): return stable_stat(os.fstat(descriptor))

def named_same(name,parent,descriptor):
 check(stable_stat(os.stat(name,dir_fd=parent,follow_symlinks=False))==held_state(descriptor),'identities')

def parse_command(tool,args):
 global last_command
 check(time.monotonic()<deadline,'inventory-command-job-deadline')
 last_command={'tool':tool,'arguments':args,'startedMonotonic':time.monotonic(),
               'exit':None,'naturalTerminal':False,'stdoutBytes':0,'stderrBytes':0}
 check(True,'inventory-command-start')
 process=subprocess.Popen([tool,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  start_new_session=True,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'})
 selector=selectors.DefaultSelector(); buffers=[bytearray(),bytearray()]
 for index,pipe in enumerate((process.stdout,process.stderr)):
  os.set_blocking(pipe.fileno(),False); selector.register(pipe,selectors.EVENT_READ,index)
 until=min(deadline,time.monotonic()+15)
 try:
  while selector.get_map() or process.poll() is None:
   check(time.monotonic()<until,'inventory-command-deadline')
   for key,_ in selector.select(0.05):
    try: body=os.read(key.fileobj.fileno(),65536)
    except BlockingIOError: continue
    if not body: selector.unregister(key.fileobj); continue
    buffers[key.data].extend(body)
    check(len(buffers[key.data])<=(2*1024**2 if key.data==0 else 65536),'inventory-command-output-limit')
  result=process.wait()
  last_command.update({'exit':result,'naturalTerminal':result>=0})
  check(result==0,'inventory-command-exit')
  check(True,'inventory-command-plist')
  return plistlib.loads(bytes(buffers[0]))
 finally:
  last_command.update({'elapsedSeconds':time.monotonic()-last_command['startedMonotonic'],
   'stdoutBytes':len(buffers[0]),'stderrBytes':len(buffers[1]),
   'stdoutSHA256':hashlib.sha256(buffers[0]).hexdigest(),'stderrSHA256':hashlib.sha256(buffers[1]).hexdigest()})
  if process.poll() is None:
   try: os.killpg(process.pid,signal.SIGTERM)
   except ProcessLookupError: pass
   try: process.wait(timeout=0.5)
   except subprocess.TimeoutExpired:
    try: os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait(timeout=1)
  selector.close(); process.stdout.close(); process.stderr.close()

class KernelFS(ctypes.Structure):
 _fields_=[('block_size',ctypes.c_uint32),('io_size',ctypes.c_int32),('blocks',ctypes.c_uint64),
  ('free',ctypes.c_uint64),('available',ctypes.c_uint64),('files',ctypes.c_uint64),('free_files',ctypes.c_uint64),
  ('identifier',ctypes.c_int32*2),('owner',ctypes.c_uint32),('type',ctypes.c_uint32),('flags',ctypes.c_uint32),
  ('subtype',ctypes.c_uint32),('type_name',ctypes.c_char*16),('mount_path',ctypes.c_char*1024),
  ('source_name',ctypes.c_char*1024),('extended_flags',ctypes.c_uint32),('reserved',ctypes.c_uint32*7)]

class Attributes(ctypes.Structure):
 _fields_=[('groups',ctypes.c_uint16),('reserved',ctypes.c_uint16),('common',ctypes.c_uint32),
  ('volume',ctypes.c_uint32),('directory',ctypes.c_uint32),('file',ctypes.c_uint32),('fork',ctypes.c_uint32)]

def kernel(descriptor):
 value=KernelFS()
 check(library.fstatfs(descriptor,ctypes.byref(value))==0,'base-kernel')
 independent=os.fstatvfs(descriptor)
 check(value.block_size==independent.f_frsize and value.blocks==independent.f_blocks,'sdk-abi')
 return {'fsid':tuple(value.identifier),'flags':value.flags,'type':bytes(value.type_name).decode(),
         'mount':bytes(value.mount_path).decode(),'source':bytes(value.source_name).decode()}

def native_uuid(descriptor,label):
 request=Attributes(5,0,0,0x80040000,0,0,0)
 result=ctypes.create_string_buffer(20)
 check(library.fgetattrlist(descriptor,ctypes.byref(request),result,len(result),0)==0,label)
 check(struct.unpack_from('<I',result.raw,0)[0]==20,label)
 return str(uuid.UUID(bytes=result.raw[4:20])).upper()

def literal(prefix,pattern): return (prefix+pattern*((16384//len(pattern))+2))[:16384].encode('ascii')

def file_bytes(parent,name,expected,label):
 descriptor=fd_open(name,os.O_RDONLY,parent); before=held_state(descriptor)
 check(stat.S_ISREG(before[2]) and before[3]==len(expected) and before[0]==os.fstat(parent).st_dev,label)
 check(kernel(descriptor)['fsid']==kernel(parent)['fsid'],label)
 data=os.pread(descriptor,len(expected)+1,0)
 check(data==expected,label)
 check(held_state(descriptor)==before,label); named_same(name,parent,descriptor)
 return hashlib.sha256(data).hexdigest()

def hash_file(descriptor,size):
 before=held_state(descriptor)
 check(stat.S_ISREG(before[2]) and before[3]==size and 0<size<=512*1024**2,'image-hash-bound')
 n=library.fgetxattr(descriptor,b'com.apple.ResourceFork',None,0,0,0)
 check(n==0 or (n==-1 and ctypes.get_errno()==errno.ENOATTR),'image-main-fork')
 value=hashlib.sha256(); offset=0
 while offset<size:
  check(time.monotonic()<deadline,'image-hash-deadline')
  length=min(1024**2,size-offset); data=os.pread(descriptor,length,offset)
  check(len(data)==length,'image-hash-short-read'); value.update(data); offset+=length
 check(os.pread(descriptor,1,size)==b'' and held_state(descriptor)==before,'image-hash-identity')
 return value.hexdigest()

def exact_alias(reported,expected,descriptor,parent,is_directory):
 check(isinstance(reported,str) and reported.startswith('/') and '\x00' not in reported,'image-alias')
 reported_path=Path(reported)
 check(reported_path.resolve(strict=True)==expected,'image-alias')
 reported_parent=directory_path(reported_path.parent)
 check(held_state(reported_parent)==held_state(parent),'image-alias')
 alias=fd_open(reported_path.name,os.O_RDONLY|(os.O_DIRECTORY if is_directory else 0),reported_parent)
 check(held_state(alias)==held_state(descriptor),'image-alias')
 named_same(reported_path.name,reported_parent,alias)

def owned_image(required=()):
 global last_inventory
 body=parse_command('/usr/bin/hdiutil',['info','-plist'])
 check(isinstance(body,dict) and isinstance(body.get('images'),list),'inventory-envelope')
 images=body['images']
 last_inventory={'imageCount':len(images),'candidateCount':0,'ownedMatchCount':0,
                 'unrelatedCount':len(images),'ownedRows':[]}
 matches=[]
 for row in images:
  check(isinstance(row,dict),'inventory-row-type')
  path=row.get('image-path')
  # Unrelated host/user image paths are neither resolved nor opened.
  if isinstance(path,str) and Path(path).name=='image.dmg' and Path(path).parent.name==job_name:
   last_inventory['candidateCount']+=1
   last_inventory['unrelatedCount']-=1
   check(True,'inventory-candidate-path')
   if Path(path).resolve(strict=True)==image_path:
    matches.append(row); last_inventory['ownedMatchCount']=len(matches)
 check(len(matches)>0,'inventory-owned-missing')
 check(len(matches)==1,'inventory-owned-ambiguous')
 exact_alias(matches[0]['image-path'],image_path,image_fd,job_fd,False)
 entries=matches[0]['system-entities']
 check(isinstance(entries,list) and 0<len(entries)<=64,'devices')
 # Only an exact pathname plus independently checked held/named full identity
 # reaches this record. Unrelated rows contribute counts, never host paths,
 # resolved files, content or mount locations.
 last_inventory['ownedRows']=[{'privateImageIdentity':list(held_state(image_fd)),
  'expectedPrivateSHA256':image_hash,'entityCount':len(entries),
  'entities':[{'device':e.get('dev-entry') if isinstance(e.get('dev-entry'),str) and len(e['dev-entry'])<=64 else None,
               'contentHint':e.get('content-hint') if isinstance(e.get('content-hint'),str) and len(e['content-hint'].encode())<=128 else None,
               'hasMountPoint':'mount-point' in e} for e in entries if isinstance(e,dict)]}]
 mapped={entry.get('dev-entry') for entry in entries}
 check(all(isinstance(d,str) and re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*',d) for d in mapped),'devices')
 check(all(device in mapped for device in required),'devices')
 return entries,mapped

def native_snapshot(device):
 owned_image([device])
 rows=parse_command('/usr/sbin/diskutil',['apfs','listSnapshots','-plist',device])['Snapshots']
 check(isinstance(rows,list) and len(rows)==1,'snapshot-inventory')
 value=rows[0]
 check(value.get('SnapshotName')==snapshot_name and str(uuid.UUID(value['SnapshotUUID'])).upper()==snapshot_uuid
       and type(value.get('SnapshotXID')) is int and value['SnapshotXID']==1,'snapshot-inventory')
 return (value['SnapshotName'],str(uuid.UUID(value['SnapshotUUID'])).upper(),value['SnapshotXID'])

try:
 check(len(sys.argv)==10 and sys.argv[2] in ('current','snapshot','metadata'),'arguments')
 image_bytes=int(sys.argv[8]); image_hash=sys.argv[9]
 check(0<image_bytes<=512*1024**2 and re.fullmatch(r'[0-9a-f]{64}',image_hash),'arguments')
 mode=sys.argv[2]; scratch=Path(sys.argv[1])
 check(os.uname().machine=='arm64' and ctypes.sizeof(KernelFS)==2168 and ctypes.sizeof(Attributes)==24,'sdk-abi')
 library=ctypes.CDLL(None,use_errno=True)
 library.fstatfs.argtypes=[ctypes.c_int,ctypes.POINTER(KernelFS)]; library.fstatfs.restype=ctypes.c_int
 library.fgetattrlist.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_ulong]
 library.fgetattrlist.restype=ctypes.c_int
 library.fgetxattr.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_int]
 library.fgetxattr.restype=ctypes.c_ssize_t
 root_path=Path(sys.argv[3]); root_fd=directory_path(root_path)
 root_state=os.fstat(root_fd)
 check((root_state.st_dev,root_state.st_ino)==(int(sys.argv[4]),int(sys.argv[5]))
       and root_state.st_uid==os.getuid() and stat.S_IMODE(root_state.st_mode)==0o700,'scratch-anchor')
 check(scratch.name in ('adapter-scratch','oracle-scratch') and scratch.parent.resolve(strict=True)==root_path.resolve(strict=True),'scratch-path')
 scratch_fd=fd_open(scratch.name,os.O_RDONLY|os.O_DIRECTORY,root_fd); scratch=scratch.resolve(strict=True)
 check((os.fstat(scratch_fd).st_dev,os.fstat(scratch_fd).st_ino)==(int(sys.argv[6]),int(sys.argv[7])),'scratch-anchor')
 scratch_before=held_state(scratch_fd)
 check(os.fstat(scratch_fd).st_uid==os.getuid(),'scratch-owner')
 check(stat.S_IMODE(os.fstat(scratch_fd).st_mode)==0o700,'scratch-permissions')
 names=os.listdir(scratch_fd)
 check(len(names)==1 and re.fullmatch(r'\.native-apfs-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}',names[0]),'private-job')
 job_name=names[0]; job_fd=fd_open(job_name,os.O_RDONLY|os.O_DIRECTORY,scratch_fd)
 job_before=held_state(job_fd)
 check(os.fstat(job_fd).st_uid==os.getuid() and stat.S_IMODE(os.fstat(job_fd).st_mode)==0o700,'private-job')
 job_path=scratch/job_name; image_path=job_path/'image.dmg'
 image_fd=fd_open('image.dmg',os.O_RDONLY,job_fd); image_before=held_state(image_fd)
 check(stat.S_ISREG(image_before[2]) and image_before[3]==image_bytes and image_before[4]==os.getuid()
       and image_before[6]==1 and stat.S_IMODE(image_before[2])==0o400,'image')
 private_hash=hash_file(image_fd,image_bytes)
 check(private_hash==image_hash and os.pread(image_fd,12,0)==b'encrcdsa\x00\x00\x00\x02','image')
 encryption=parse_command('/usr/bin/hdiutil',['isencrypted','-plist',str(image_path)])
 check(encryption.get('encrypted') is True,'encrypted-wrapper')
 check(held_state(image_fd)==image_before,'identities')
 base_fd=fd_open('view',os.O_RDONLY|os.O_DIRECTORY,job_fd); base_before=held_state(base_fd)
 base_path=job_path/'view'
 entries,mapped=owned_image()
 physicals=[e['dev-entry'] for e in entries if e.get('content-hint') in ('Apple_APFS','7C3457EF-0000-11AA-AA11-00306543ECAC')]
 if not physicals:
  physicals=[e['dev-entry'] for e in entries if e.get('content-hint')=='' and re.fullmatch(r'/dev/disk[0-9]+',e['dev-entry'])]
 check(len(physicals)==1,'physical'); physical=physicals[0]
 owned_image([physical])
 physical_info=parse_command('/usr/sbin/diskutil',['info','-plist',physical])
 check(physical_info['DeviceNode']==physical,'physical')
 reference=physical_info['APFSContainerReference']
 check(re.fullmatch(r'disk[0-9]+',reference) and '/dev/'+reference in mapped,'container')
 owned_image([physical,'/dev/'+reference])
 containers=parse_command('/usr/sbin/diskutil',['apfs','list','/dev/'+reference,'-plist'])['Containers']
 check(len(containers)==1,'container'); container=containers[0]
 check(container['ContainerReference']==reference and container['APFSContainerUUID'].upper()==container_uuid
       and {p['DeviceIdentifier'] for p in container['PhysicalStores']}=={physical[5:]},'container')
 volumes=container['Volumes']
 check(len(volumes)==1 and volumes[0]['APFSVolumeUUID'].upper()==base_uuid,'volume')
 volume_device='/dev/'+volumes[0]['DeviceIdentifier']
 owned_image([physical,'/dev/'+reference,volume_device])
 volume=parse_command('/usr/sbin/diskutil',['info','-plist',volume_device])
 check(volume['DeviceNode']==volume_device and volume['VolumeUUID'].upper()==base_uuid
       and volume['APFSContainerReference']==reference and volume['ParentWholeDisk']==reference
       and {p['APFSPhysicalStore'] for p in volume['APFSPhysicalStores']}=={physical[5:]},'volume')
 check(volume['FilesystemType']=='apfs' and volume['WritableMedia'] is False and volume['WritableVolume'] is False
       and volume.get('Encryption') is False and volume.get('FileVault') is False and volume.get('Locked') is False,'base-kernel')
 exact_alias(volume['MountPoint'],base_path,base_fd,job_fd,True)
 base_kernel=kernel(base_fd)
 check(base_kernel['type']=='apfs' and base_kernel['source']==volume_device and base_kernel['mount']==str(base_path)
       and base_kernel['flags']&0x1d==0x1d and base_kernel['flags']&0x40000000==0,'base-kernel')
 check(native_uuid(base_fd,'base-uuid')==base_uuid,'base-uuid')
 earlier=literal('NATIVE FORENSICS BEFORE SNAPSHOT\n','earlier-known-block;0123456789abcdef\n')
 later=literal('NATIVE FORENSICS AFTER SNAPSHOT\n','later-known-block!!;fedcba9876543210\n')
 current_hash=None if mode=='metadata' else file_bytes(base_fd,'history.bin',later,'base-bytes')
 tuple_before=native_snapshot(volume_device)
 history_hash=None; chosen_uuid=None; chosen_xid=None; snapshot_fd=None
 if mode in ('snapshot','metadata'):
  snapshot_fd=fd_open('snapshot-view',os.O_RDONLY|os.O_DIRECTORY,job_fd)
  snapshot_before=held_state(snapshot_fd); snapshot_path=job_path/'snapshot-view'
  snapshot_kernel=kernel(snapshot_fd)
  check(snapshot_kernel['type']=='apfs' and snapshot_kernel['mount']==str(snapshot_path)
        and snapshot_kernel['source']==snapshot_name+'@'+volume_device
        and snapshot_kernel['flags']&0x4000001d==0x4000001d
        and snapshot_kernel['fsid']!=base_kernel['fsid'],'snapshot-kernel')
  check(native_uuid(snapshot_fd,'snapshot-uuid')==snapshot_uuid,'snapshot-uuid')
  history_hash=None if mode=='metadata' else file_bytes(snapshot_fd,'history.bin',earlier,'snapshot-bytes')
  check(held_state(snapshot_fd)==snapshot_before and kernel(snapshot_fd)==snapshot_kernel,'identities')
  named_same('snapshot-view',job_fd,snapshot_fd)
  chosen_uuid=snapshot_uuid; chosen_xid=1
 else:
  check('snapshot-view' not in os.listdir(job_fd),'current-only')
 check(native_snapshot(volume_device)==tuple_before,'snapshot-inventory')
 owned_image([physical,'/dev/'+reference,volume_device])
 check(held_state(scratch_fd)==scratch_before and held_state(job_fd)==job_before
       and held_state(image_fd)==image_before and held_state(base_fd)==base_before,'identities')
 named_same(job_name,scratch_fd,job_fd); named_same('image.dmg',job_fd,image_fd); named_same('view',job_fd,base_fd)
 check(kernel(base_fd)==base_kernel and native_uuid(base_fd,'base-uuid')==base_uuid,'identities')
 check(hash_file(image_fd,image_bytes)==image_hash and held_state(image_fd)==image_before,'identities')
 print(json.dumps({'ok':True,'stage':'complete','mode':mode,'privateSHA256':private_hash,'baseUUID':base_uuid,
                   'currentSHA256':current_hash,'snapshotUUID':chosen_uuid,'transactionID':chosen_xid,'historySHA256':history_hash}))
except BaseException:
 print(json.dumps({'ok':False,'stage':stage,'lastCommand':last_command,'lastOwnedInventory':last_inventory}))
finally:
 for descriptor in reversed(opened): os.close(descriptor)
"""#
}

struct AESFileState: Equatable {
    let device: dev_t, inode: ino_t, mode: mode_t, size: Int64, uid: uid_t, gid: gid_t, links: nlink_t, flags: UInt32
    let modificationSeconds: Int, modificationNanoseconds: Int, changeSeconds: Int, changeNanoseconds: Int
    var isRegular: Bool { mode & S_IFMT == S_IFREG }
    init(_ fd: Int32) throws { var s = stat(); guard Darwin.fstat(fd, &s) == 0 else { throw ForensicsError.io("Independent fstat failed.") }; self.init(s) }
    init(_ parent: Int32, _ name: String) throws { var s = stat(); guard Darwin.fstatat(parent, name, &s, AT_SYMLINK_NOFOLLOW) == 0 else { throw ForensicsError.io("Independent named stat failed.") }; self.init(s) }
    private init(_ s: stat) { device = s.st_dev; inode = s.st_ino; mode = s.st_mode; size = s.st_size; uid = s.st_uid; gid = s.st_gid; links = s.st_nlink; flags = s.st_flags; modificationSeconds = s.st_mtimespec.tv_sec; modificationNanoseconds = s.st_mtimespec.tv_nsec; changeSeconds = s.st_ctimespec.tv_sec; changeNanoseconds = s.st_ctimespec.tv_nsec }
    func sameDirectory(_ v: Self) -> Bool { device == v.device && inode == v.inode && mode == v.mode && uid == v.uid && gid == v.gid && flags == v.flags && mode & S_IFMT == S_IFDIR }
    func equalExceptCTime(_ v: Self) -> Bool { device == v.device && inode == v.inode && mode == v.mode && size == v.size && uid == v.uid && gid == v.gid && links == v.links && flags == v.flags && modificationSeconds == v.modificationSeconds && modificationNanoseconds == v.modificationNanoseconds }
}

final class AESDefaultExportFence: @unchecked Sendable {
    let descriptor: Int32, state: AESFileState, canonical: String, requested: String
    let names: Set<String>, attachments: Set<String>
    init(descriptor: Int32, state: AESFileState, canonical: String, requested: String,
         names: Set<String>, attachments: Set<String>) {
        self.descriptor = descriptor; self.state = state; self.canonical = canonical; self.requested = requested
        self.names = names; self.attachments = attachments
    }
    deinit { Darwin.close(descriptor) }
}

private struct AESNativeOutcome { let stdout: Data, rawStatus: Int32, stdoutBytes: Int, stderrBytes: Int }

/// Separate from the production runner. Secret command output is never a file
/// or log/hash; nonsecret metadata stdout is bounded and returned in memory.
private enum AESNativeRunner {
    static func run(tool: String, arguments: [String], input: inout [UInt8], secret: Bool, timeout: Double,
                    validate: () throws -> Void, uncertain: () -> Void) throws -> AESNativeOutcome {
        guard ["/usr/bin/hdiutil", "/usr/sbin/diskutil", "/sbin/fsck_apfs", "/sbin/mount_apfs", "/sbin/umount", "/usr/bin/python3"].contains(tool),
              timeout.isFinite, timeout > 0, timeout <= 90, input.count <= 1_025,
              !arguments.contains(where: { ["-passphrase", "-agentpass", "-recover", "-pubkey", "-certificate"].contains($0) }) else { throw ForensicsError.io("Independent command scope invalid.") }
        if secret {
            guard tool == "/usr/bin/hdiutil", ["convert", "attach"].contains(arguments.first ?? ""),
                  arguments.contains("-stdinpass"), input.last == 0,
                  !input.dropLast().contains(0) else { throw ForensicsError.io("Secret command scope invalid.") }
        }
        try validate()
        var channels = [[Int32](repeating: -1, count: 2), [Int32](repeating: -1, count: 2), [Int32](repeating: -1, count: 2)]
        defer { for pair in channels { for fd in pair where fd >= 0 { Darwin.close(fd) } } }
        for index in channels.indices {
            var pair = [Int32](repeating: -1, count: 2)
            guard Darwin.pipe(&pair) == 0 else { throw ForensicsError.io("Independent pipe unavailable.") }
            channels[index] = pair
            for fd in pair { guard Darwin.fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw ForensicsError.io("Independent pipe inheritance failed.") } }
        }
        guard Darwin.fcntl(channels[0][1], F_SETNOSIGPIPE, 1) == 0 else { throw ForensicsError.io("Independent stdin signal fence failed.") }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw ForensicsError.io("Independent spawn actions unavailable.") }; defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw ForensicsError.io("Independent spawn attributes unavailable.") }; defer { posix_spawnattr_destroy(&attributes) }
        for (fd, target) in [(channels[0][0], STDIN_FILENO), (channels[1][1], STDOUT_FILENO), (channels[2][1], STDERR_FILENO)] { guard posix_spawn_file_actions_adddup2(&actions, fd, target) == 0 else { throw ForensicsError.io("Independent spawn redirection failed.") } }
        for fd in channels.flatMap({ $0 }) { guard posix_spawn_file_actions_addclose(&actions, fd) == 0 else { throw ForensicsError.io("Independent child descriptor fence failed.") } }
        var mask = sigset_t(), defaults = sigset_t(); sigemptyset(&mask); sigemptyset(&defaults)
        for value in [SIGTERM, SIGINT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, value) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0, posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0 else { throw ForensicsError.io("Independent child process ownership failed.") }
        let argumentStrings: [String] = [tool] + arguments
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"]
        let pointers: [UnsafeMutablePointer<CChar>?] = argumentStrings.map { value in
            value.withCString { Darwin.strdup($0) }
        }
        let environments: [UnsafeMutablePointer<CChar>?] = environmentStrings.map { value in
            value.withCString { Darwin.strdup($0) }
        }
        defer { for p in pointers + environments { free(p) } }
        guard pointers.allSatisfy({ $0 != nil }), environments.allSatisfy({ $0 != nil }) else {
            throw ForensicsError.io("Independent native argument allocation failed.")
        }
        var args = pointers + [nil], env = environments + [nil], pid: pid_t = 0
        let error = args.withUnsafeMutableBufferPointer { a in env.withUnsafeMutableBufferPointer { e in posix_spawn(&pid, tool, &actions, &attributes, a.baseAddress!, e.baseAddress!) } }
        guard error == 0, pid > 0 else { throw ForensicsError.io("Independent native spawn failed.") }
        var reaped = false, natural = false
        defer {
            if !reaped {
                uncertain(); Darwin.kill(-pid, SIGTERM)
                let until = ContinuousClock().now + .seconds(1); var state: Int32 = 0
                while ContinuousClock().now < until { if Darwin.waitpid(pid, &state, WNOHANG) == pid { reaped = true; break }; usleep(10_000) }
                if !reaped {
                    Darwin.kill(-pid, SIGKILL)
                    let killedUntil = ContinuousClock().now + .seconds(1)
                    while ContinuousClock().now < killedUntil {
                        let result = Darwin.waitpid(pid, &state, WNOHANG)
                        if result == pid { reaped = true; break }
                        if result < 0 && errno != EINTR { break }
                        usleep(10_000)
                    }
                    // An unconfirmed reap never grants cleanup ownership.
                    // Return within the bound and retain native backing.
                }
            } else if !natural { uncertain() }
        }
        func closeEnd(_ pair: Int, _ end: Int) { let fd = channels[pair][end]; if fd >= 0 { Darwin.close(fd); channels[pair][end] = -1 } }
        closeEnd(0, 0); closeEnd(1, 1); closeEnd(2, 1)
        for fd in [channels[0][1], channels[1][0], channels[2][0]] { let flags = Darwin.fcntl(fd, F_GETFL); guard flags >= 0, Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw ForensicsError.io("Independent nonblocking pipe failed.") } }
        var sent = 0, stdout = Data(), counts = [0, 0], eof = [false, false]
        var buffer = [UInt8](repeating: 0, count: 32_768)
        defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        let deadline = ContinuousClock().now + .seconds(timeout)
        while true {
            try validate(); guard ContinuousClock().now < deadline else { throw ForensicsError.io("Independent command deadline expired.") }
            if sent == input.count { closeEnd(0, 1) }
            var events = [pollfd(fd: eof[0] ? -1 : channels[1][0], events: Int16(POLLIN), revents: 0), pollfd(fd: eof[1] ? -1 : channels[2][0], events: Int16(POLLIN), revents: 0), pollfd(fd: channels[0][1], events: Int16(POLLOUT), revents: 0)]
            let polled = Darwin.poll(&events, 3, 20); if polled < 0 { if errno == EINTR { continue }; throw ForensicsError.io("Independent poll failed.") }
            for index in 0..<2 where events[index].revents != 0 {
                for _ in 0..<8 {
                    let n = buffer.withUnsafeMutableBytes { Darwin.read(channels[index + 1][0], $0.baseAddress!, $0.count) }
                    if n > 0 { guard n <= (index == 0 ? 2 * 1_024 * 1_024 : 128 * 1_024) - counts[index] else { throw ForensicsError.io("Independent output bound exceeded.") }; counts[index] += n; if index == 0 && !secret { stdout.append(contentsOf: buffer.prefix(n)) } }
                    else if n == 0 { eof[index] = true; break }
                    else if errno == EINTR { continue }
                    else if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    else { throw ForensicsError.io("Independent pipe read failed.") }
                }
            }
            if channels[0][1] >= 0, events[2].revents != 0 {
                guard events[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else { throw ForensicsError.io("Independent stdin closed early.") }
                let remaining = input.count - sent
                let n = input.withUnsafeBytes { Darwin.write(channels[0][1], $0.baseAddress!.advanced(by: sent), remaining) }
                if n > 0 { sent += n } else if n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw ForensicsError.io("Independent stdin write failed.") }
            }
            if eof.allSatisfy({ $0 }) {
                var info = siginfo_t(); let observed = Darwin.waitid(P_PID, id_t(pid), &info, WEXITED | WNOHANG | WNOWAIT)
                if observed < 0 { if errno == EINTR { continue }; throw ForensicsError.io("Independent terminal observation failed.") }
                if info.si_pid != pid { continue }
                var status: Int32 = 0
                if Darwin.waitpid(pid, &status, WNOHANG) == pid {
                    reaped = true; natural = info.si_code == CLD_EXITED
                    guard natural, status == 0, sent == input.count else { throw ForensicsError.io("Independent native command did not exit successfully.") }
                    return AESNativeOutcome(stdout: stdout, rawStatus: status, stdoutBytes: counts[0], stderrBytes: counts[1])
                }
            }
        }
    }
}
