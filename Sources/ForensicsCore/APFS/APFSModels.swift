import Foundation

/// A system-mounted allocated-files view, never a direct APFS block parser.
public struct APFSReadOptions: Codable, Sendable, Equatable {
    public let maximumEntries: Int
    public let maximumFileBytes: Int64
    public let maximumContainerBytes: Int64
    public let commandTimeoutSeconds: Double
    public let maximumDepth: Int
    public let maximumMetadataBytes: Int
    public let maximumAggregateFileBytes: Int64
    public let jobTimeoutSeconds: Double
    /// Nil preserves the current single-volume default. Images with several
    /// APFS volumes require an exact UUID; no implicit first-volume selection.
    public let selectedVolumeUUID: UUID?
    /// Nil selects the current view of the selected base volume. An explicit
    /// UUID requests an exact snapshot from that volume's observed inventory.
    public let selectedSnapshotUUID: UUID?

    public init(maximumEntries: Int = 50_000, maximumFileBytes: Int64 = 128 * 1_024 * 1_024,
                maximumContainerBytes: Int64 = 64 * 1_024 * 1_024 * 1_024,
                commandTimeoutSeconds: Double = 60, maximumDepth: Int = 128,
                maximumMetadataBytes: Int = 64 * 1_024 * 1_024,
                maximumAggregateFileBytes: Int64 = 4 * 1_024 * 1_024 * 1_024, jobTimeoutSeconds: Double = 600,
                selectedVolumeUUID: UUID? = nil, selectedSnapshotUUID: UUID? = nil) {
        self.maximumEntries = maximumEntries; self.maximumFileBytes = maximumFileBytes
        self.maximumContainerBytes = maximumContainerBytes; self.commandTimeoutSeconds = commandTimeoutSeconds
        self.maximumDepth = maximumDepth
        self.maximumMetadataBytes = maximumMetadataBytes; self.maximumAggregateFileBytes = maximumAggregateFileBytes
        self.jobTimeoutSeconds = jobTimeoutSeconds
        self.selectedVolumeUUID = selectedVolumeUUID
        self.selectedSnapshotUUID = selectedSnapshotUUID
    }

    func validate() throws {
        guard (1...50_000).contains(maximumEntries), (1...128 * 1_024 * 1_024).contains(maximumFileBytes),
              (1...64 * 1_024 * 1_024 * 1_024).contains(maximumContainerBytes),
              commandTimeoutSeconds.isFinite, (1...60).contains(commandTimeoutSeconds),
              (1...128).contains(maximumDepth), (1...64 * 1_024 * 1_024).contains(maximumMetadataBytes),
              (1...4 * 1_024 * 1_024 * 1_024).contains(maximumAggregateFileBytes),
              jobTimeoutSeconds.isFinite, (1...600).contains(jobTimeoutSeconds) else { throw APFSReadError.invalidOptions }
    }
}

public enum APFSFileKind: String, Codable, Sendable { case regular, directory, symbolicLink, other }

public struct APFSFileEntry: Codable, Sendable, Equatable {
    public let relativePath: String
    public let kind: APFSFileKind
    public let inode: UInt64
    public let byteCount: Int64
    /// Present only for complete bounded regular-file reads from this view.
    public let sha256: String?
    public let modifiedSeconds: Int64
    public let modifiedNanoseconds: Int

    public init(relativePath: String, kind: APFSFileKind, inode: UInt64, byteCount: Int64,
                sha256: String?, modifiedSeconds: Int64, modifiedNanoseconds: Int) {
        self.relativePath = relativePath; self.kind = kind; self.inode = inode; self.byteCount = byteCount
        self.sha256 = sha256; self.modifiedSeconds = modifiedSeconds; self.modifiedNanoseconds = modifiedNanoseconds
    }
}

public struct APFSSnapshotInventoryEntry: Codable, Sendable, Equatable {
    public let uuid: UUID
    public let name: String
    public let transactionID: UInt64
    public init(uuid: UUID, name: String, transactionID: UInt64) { self.uuid = uuid; self.name = name; self.transactionID = transactionID }
}

public enum APFSContainerEncryption: String, Codable, Sendable {
    case none
    /// Disk image container encryption. This does not mean APFS/FileVault encryption.
    case encryptedDiskImage
}

public enum APFSReadCoverage: String, Codable, Sendable { case completeAllocatedView, partialAllocatedView }
public enum APFSVolumeEncryption: String, Codable, Sendable {
    case none
    /// The observed encrypted APFS image volume unlocked with its Disk crypto
    /// user. This does not assert boot FileVault/hardware-bound-key support.
    case diskUserAPFS
}

public struct APFSInspectionResult: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let evidenceID: UUID
    public let containerSHA256: String
    public let containerByteCount: Int64
    public let hashScope: String
    public let driver: String
    public let driverVersion: String
    public let options: APFSReadOptions
    public let volumeUUID: UUID
    public let containerEncryption: APFSContainerEncryption
    public let volumeEncryption: APFSVolumeEncryption
    public let entries: [APFSFileEntry]
    public let snapshots: [APFSSnapshotInventoryEntry]
    public let snapshotInventoryAvailable: Bool
    public let coverage: APFSReadCoverage
    public let warnings: [String]
    /// The exact observed snapshot tuple for this view; nil means current.
    /// volumeUUID continues to identify the base volume in either case.
    public let selectedSnapshot: APFSSnapshotInventoryEntry?
    public init(schemaVersion: Int = 1, evidenceID: UUID, containerSHA256: String, containerByteCount: Int64,
                hashScope: String = FileHashScope.selectedFileBytes, driver: String = "apple-system-readonly-apfs-v1",
                driverVersion: String, options: APFSReadOptions = .init(), volumeUUID: UUID,
                containerEncryption: APFSContainerEncryption, volumeEncryption: APFSVolumeEncryption,
                entries: [APFSFileEntry], snapshots: [APFSSnapshotInventoryEntry], snapshotInventoryAvailable: Bool,
                coverage: APFSReadCoverage, warnings: [String], selectedSnapshot: APFSSnapshotInventoryEntry? = nil) {
        self.schemaVersion = schemaVersion; self.evidenceID = evidenceID; self.containerSHA256 = containerSHA256
        self.containerByteCount = containerByteCount; self.hashScope = hashScope; self.driver = driver
        self.driverVersion = driverVersion; self.options = options; self.volumeUUID = volumeUUID
        self.containerEncryption = containerEncryption; self.volumeEncryption = volumeEncryption
        self.entries = entries; self.snapshots = snapshots; self.snapshotInventoryAvailable = snapshotInventoryAvailable
        self.coverage = coverage; self.warnings = warnings
        self.selectedSnapshot = selectedSnapshot
    }
}

public struct APFSVerifiedFile: Sendable {
    public let data: Data
    public let sha256: String
    public let containerSHA256: String
    public let volumeUUID: UUID
    public let relativePath: String
    /// The verified view's observed tuple; nil means the base volume's current view.
    public let selectedSnapshot: APFSSnapshotInventoryEntry?
    public init(data: Data, sha256: String, containerSHA256: String, volumeUUID: UUID, relativePath: String,
                selectedSnapshot: APFSSnapshotInventoryEntry? = nil) {
        self.data = data; self.sha256 = sha256; self.containerSHA256 = containerSHA256
        self.volumeUUID = volumeUUID; self.relativePath = relativePath
        self.selectedSnapshot = selectedSnapshot
    }
}

/// A single-use, memory-held credential. It is deliberately not Codable or
/// printable. A caller must supply a new credential for a subsequent job.
/// Swift/Foundation and system components may copy memory; this is not a claim
/// of hardware-backed secret storage or provable erasure of every copy.
public final class APFSPassphrase: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: Data?
    public init(_ utf8Bytes: Data) throws {
        guard !utf8Bytes.isEmpty, utf8Bytes.count <= 1_024,
              !utf8Bytes.contains(0), !utf8Bytes.contains(10), !utf8Bytes.contains(13),
              String(data: utf8Bytes, encoding: .utf8) != nil else { throw APFSReadError.invalidCredential }
        bytes = utf8Bytes
    }
    func consume(terminator: UInt8 = 0) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard var value = bytes else { throw APFSReadError.credentialConsumed }
        let count = bytes?.count ?? 0
        bytes?.resetBytes(in: 0..<count); bytes = nil
        value.append(terminator) // NUL for hdiutil, newline for diskutil.
        return value
    }
    deinit { let count = bytes?.count ?? 0; bytes?.resetBytes(in: 0..<count) }
}

public enum APFSReadError: Error, LocalizedError, Sendable, Equatable {
    case invalidOptions, invalidCredential, credentialConsumed, invalidEvidence, invalidResult
    case sourceChanged, unsafeMount, unsupported(String), timeout, outputLimit, commandFailed(Int32)
    case cleanupIncomplete, fileUnavailable
    public var errorDescription: String? {
        switch self {
        case .invalidOptions: "The APFS read limits are invalid."
        case .invalidCredential: "The disk-image credential is invalid."
        case .credentialConsumed: "This credential was already used. Enter it again for another job."
        case .invalidEvidence: "Select a bounded regular source with a selected-file SHA-256 receipt."
        case .invalidResult: "The APFS result does not match the selected source or read contract."
        case .sourceChanged: "The selected source or private image changed during the read."
        case .unsafeMount: "The mounted view was not a verified read-only APFS volume."
        case .unsupported(let reason): "This APFS combination is unavailable: \(reason)"
        case .timeout: "The system disk-image operation exceeded its time limit."
        case .outputLimit: "The system disk-image response exceeded its byte limit."
        case .commandFailed(let status): "The system disk-image operation failed (status \(status)); no unverified result was accepted."
        case .cleanupIncomplete: "The owned read-only disk image could not be fully detached. Its private backing copy was retained."
        case .fileUnavailable: "This file was not completely verified in the recorded allocated view."
        }
    }
}
