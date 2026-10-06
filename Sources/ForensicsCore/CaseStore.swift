import Darwin
import Foundation

// The SDK also exports the `flock` record type, hiding the C function from
// Swift name lookup. Bind the system function without changing its ABI.
@_silgen_name("flock")
private func systemFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

public enum CaseStore {
    public static let bundleExtension = "nativecase"
    private static let manifestName = "manifest.json"
    private static let lockName = ".case.lock"
    private static let maximumManifestBytes = 16 * 1_048_576

    /// Publishes a complete new bundle with an exclusive atomic rename. An
    /// existing destination is never overwritten, even when two creators race.
    public static func create(name: String, in parent: URL) throws -> ForensicCase {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        try validateName(cleanName)
        let directory = try FileAccess.localURL(parent)
        try validateDirectory(directory)
        let parentDescriptor = try openCaseDirectory(directory)
        defer { Darwin.close(parentDescriptor) }
        let destination = directory.appendingPathComponent(cleanName).appendingPathExtension(bundleExtension)
        let stagingName = ".nativecase-\(UUID().uuidString).tmp"
        guard Darwin.mkdirat(parentDescriptor, stagingName, mode_t(0o700)) == 0 else {
            throw FileAccess.posixError("Cannot create case staging directory")
        }
        var createdStaging = stat()
        guard Darwin.fstatat(parentDescriptor, stagingName, &createdStaging, AT_SYMLINK_NOFOLLOW) == 0,
              createdStaging.st_mode & S_IFMT == S_IFDIR else {
            throw ForensicsError.invalidCase("The newly created case staging directory changed.")
        }
        let staging = Darwin.openat(parentDescriptor, stagingName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard staging >= 0 else {
            let error = FileAccess.posixError("Cannot open case staging directory")
            var current = stat()
            if Darwin.fstatat(parentDescriptor, stagingName, &current, AT_SYMLINK_NOFOLLOW) == 0,
               current.st_mode & S_IFMT == S_IFDIR,
               current.st_dev == createdStaging.st_dev, current.st_ino == createdStaging.st_ino {
                _ = Darwin.unlinkat(parentDescriptor, stagingName, AT_REMOVEDIR)
            }
            throw error
        }
        var openedStaging = stat()
        guard Darwin.fstat(staging, &openedStaging) == 0,
              openedStaging.st_dev == createdStaging.st_dev, openedStaging.st_ino == createdStaging.st_ino else {
            Darwin.close(staging)
            throw ForensicsError.invalidCase("The case staging directory changed while being opened.")
        }
        var wasPublished = false
        defer {
            if !wasPublished {
                _ = Darwin.unlinkat(staging, manifestName, 0)
                _ = Darwin.unlinkat(staging, lockName, 0)
                if directoryReferenceMatches(stagingName, in: parentDescriptor, descriptor: staging) {
                    _ = Darwin.unlinkat(parentDescriptor, stagingName, AT_REMOVEDIR)
                }
            }
            Darwin.close(staging)
        }

        let manifest = try canonicalManifest(CaseManifest(name: cleanName))
        try writeNewFile(try encode(manifest), named: manifestName, in: staging)
        try writeNewFile(Data(), named: lockName, in: staging)
        guard Darwin.fsync(staging) == 0 else { throw FileAccess.posixError("Cannot flush case staging directory") }
        try validateDirectoryReference(directory, descriptor: parentDescriptor)
        guard directoryReferenceMatches(stagingName, in: parentDescriptor, descriptor: staging) else {
            throw ForensicsError.invalidCase("The case staging directory changed before publication.")
        }
        let published = Darwin.renameatx_np(parentDescriptor, stagingName, parentDescriptor, destination.lastPathComponent, UInt32(RENAME_EXCL))
        guard published == 0 else {
            if errno == EEXIST { throw ForensicsError.caseAlreadyExists }
            throw FileAccess.posixError("Cannot create case")
        }
        wasPublished = true
        guard Darwin.fsync(parentDescriptor) == 0 else { throw FileAccess.posixError("Cannot flush case parent directory") }
        try validateDirectoryReference(directory, descriptor: parentDescriptor)
        return ForensicCase(bundleURL: destination, manifest: manifest)
    }

    /// Opens the manifest without modifying the bundle or opening its evidence.
    public static func open(at url: URL) throws -> ForensicCase {
        let bundle = try caseURL(url)
        let directory = try openCaseDirectory(bundle)
        defer { Darwin.close(directory) }
        let (manifest, _) = try readManifest(in: bundle, directory: directory)
        try validateDirectoryReference(bundle, descriptor: directory)
        return ForensicCase(bundleURL: bundle, manifest: manifest)
    }

    /// Records a fresh inspection without copying or writing its source file.
    /// A saved/decoded DTO needs reinspection because local identity provenance
    /// is not serialized. The case lock makes compare-and-write one transaction.
    public static func adding(image: InspectedImage, to forensicCase: ForensicCase) throws -> ForensicCase {
        let bundle = try caseURL(forensicCase.bundleURL)
        let directory = try openCaseDirectory(bundle)
        defer { Darwin.close(directory) }
        guard image.hashScope == FileHashScope.selectedFileBytes,
              validHash(image.sha256), image.byteCount >= 0,
              let original = image.sourceIdentity else {
            throw ForensicsError.invalidInspection("Use a fresh result from ImageInspector; saved or manually created results require reinspection.")
        }
        let source = try FileAccess.localURL(image.sourceURL)
        guard !FileAccess.isInside(source, directory: bundle) else {
            throw ForensicsError.invalidInspection("Evidence must be outside the case bundle.")
        }
        guard (try? FileAccess.identity(at: source)) == original,
              image.byteCount == original.size else { throw ForensicsError.sourceChanged }

        let lock = Darwin.openat(directory, lockName, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard lock >= 0 else { throw ForensicsError.invalidCase("The case lock is missing or inaccessible.") }
        defer { Darwin.close(lock) }
        let lockIdentity = try FileAccess.identity(of: lock)
        while systemFlock(lock, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            throw FileAccess.posixError("Cannot lock case")
        }
        defer { _ = systemFlock(lock, LOCK_UN) }

        try validateDirectoryReference(bundle, descriptor: directory)
        guard (try? FileAccess.identity(at: lockName, in: directory)) == lockIdentity else {
            throw ForensicsError.invalidCase("The case lock changed while the transaction was waiting.")
        }
        let (current, manifestIdentity) = try readManifest(in: bundle, directory: directory)
        guard current == forensicCase.manifest else { throw ForensicsError.staleCase }
        guard !current.evidence.contains(where: { $0.sourcePath == source.path }) else {
            throw ForensicsError.duplicateEvidence
        }
        // Revalidate after waiting for the lock; another process may have edited
        // the source while this transaction was queued.
        guard (try? FileAccess.identity(at: source)) == original else { throw ForensicsError.sourceChanged }
        let evidence = EvidenceRecord(
            sourcePath: source.path,
            byteCount: image.byteCount,
            sha256: image.sha256,
            container: image.container,
            filesystemHint: image.filesystemHint
        )
        let updated = try canonicalManifest(CaseManifest(
            id: current.id,
            name: current.name,
            createdAt: current.createdAt,
            evidence: current.evidence + [evidence]
        ))
        // Serialization can take time for a large case. Recheck immediately
        // before publication as well as after acquiring the transaction lock.
        let data = try encode(updated)
        try replaceManifest(data, directory: directory) {
            guard (try? FileAccess.identity(at: source)) == original else { throw ForensicsError.sourceChanged }
            try validateDirectoryReference(bundle, descriptor: directory)
            guard (try? FileAccess.identity(at: lockName, in: directory)) == lockIdentity else {
                throw ForensicsError.invalidCase("The case lock changed during the transaction.")
            }
            guard (try? FileAccess.identity(at: manifestName, in: directory)) == manifestIdentity else {
                throw ForensicsError.staleCase
            }
        }
        return ForensicCase(bundleURL: bundle, manifest: updated)
    }

    private static func validateName(_ name: String) throws {
        guard !name.isEmpty, name.count <= 100, name.utf8.count <= 240, name != ".", name != "..",
              !name.contains("/"), !name.contains("\\"), !name.contains(":"),
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !name.hasSuffix(".") else { throw ForensicsError.invalidCaseName }
    }

    private static func validateDirectory(_ url: URL) throws {
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR else {
            throw ForensicsError.invalidCase("Choose an existing directory.")
        }
    }

    private static func caseURL(_ url: URL) throws -> URL {
        guard url.isFileURL else { throw ForensicsError.invalidFileURL }
        var metadata = stat()
        guard Darwin.lstat(url.standardizedFileURL.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR else {
            throw ForensicsError.invalidCase("A case must be a directory, not a file or symbolic link.")
        }
        let canonical = try FileAccess.localURL(url)
        guard canonical.pathExtension == bundleExtension else {
            throw ForensicsError.invalidCase("Choose a .\(bundleExtension) bundle.")
        }
        return canonical
    }

    private static func validHash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func validateManifest(_ manifest: CaseManifest, bundle: URL? = nil) throws {
        guard manifest.schemaVersion == 1 else {
            throw ForensicsError.invalidCase("This case schema version is unsupported; the original manifest was preserved.")
        }
        try validateName(manifest.name)
        var identifiers = Set<UUID>()
        var paths = Set<String>()
        for record in manifest.evidence {
            guard identifiers.insert(record.id).inserted, paths.insert(record.sourcePath).inserted,
                  record.sourcePath.hasPrefix("/"), !record.sourcePath.utf8.contains(0),
                  record.sourcePath != "/",
                  record.sourcePath == URL(fileURLWithPath: record.sourcePath).standardizedFileURL.path,
                  record.byteCount >= 0, validHash(record.sha256),
                  record.hashScope == FileHashScope.selectedFileBytes else {
                throw ForensicsError.invalidCase("The evidence manifest has invalid or duplicate records.")
            }
            if let bundle, FileAccess.isInside(URL(fileURLWithPath: record.sourcePath), directory: bundle) {
                throw ForensicsError.invalidCase("Evidence sources in a manifest must be outside the case bundle.")
            }
        }
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private static func encode(_ manifest: CaseManifest) throws -> Data {
        try validateManifest(manifest)
        let data = try encoder().encode(manifest)
        guard data.count <= maximumManifestBytes else {
            throw ForensicsError.invalidCase("The manifest exceeds the Phase 0 size limit (16 MiB).")
        }
        return data
    }

    private static func canonicalManifest(_ manifest: CaseManifest) throws -> CaseManifest {
        // ISO8601 stores second precision. Return the persisted form so stale
        // detection does not fail merely because a Date had fractional seconds.
        try decoder().decode(CaseManifest.self, from: encode(manifest))
    }

    private static func readManifest(in bundle: URL, directory: Int32) throws -> (CaseManifest, SourceIdentity) {
        let descriptor: Int32
        do { descriptor = try FileAccess.openReadOnly(manifestName, in: directory) }
        catch { throw ForensicsError.invalidCase("A readable, regular manifest.json is required.") }
        defer { Darwin.close(descriptor) }
        let before = try FileAccess.identity(of: descriptor)
        guard before.size <= maximumManifestBytes else { throw ForensicsError.invalidCase("The manifest is too large.") }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while data.count < before.size {
            let requested = Int(min(Int64(buffer.count), before.size - Int64(data.count)))
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: requested) }
            guard count > 0 else { throw ForensicsError.invalidCase("The manifest changed while being opened.") }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard try FileAccess.identity(of: descriptor) == before,
              (try? FileAccess.identity(at: manifestName, in: directory)) == before else {
            throw ForensicsError.invalidCase("The manifest changed while being opened.")
        }
        let manifest: CaseManifest
        do { manifest = try decoder().decode(CaseManifest.self, from: data) }
        catch { throw ForensicsError.invalidCase("manifest.json is not a supported case manifest.") }
        try validateManifest(manifest, bundle: bundle)
        return (manifest, before)
    }

    private static func writeNewFile(_ data: Data, named name: String, in directory: Int32) throws {
        let descriptor = Darwin.openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot create case file") }
        defer { Darwin.close(descriptor) }
        try writeAndSync(data, descriptor: descriptor)
    }

    private static func writeAndSync(_ data: Data, descriptor: Int32) throws {
        try data.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                let count = Darwin.write(descriptor, buffer.baseAddress?.advanced(by: written), buffer.count - written)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write case file") }
                written += count
            }
        }
        guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush case file") }
    }

    private static func replaceManifest(_ data: Data, directory: Int32, validateBeforePublish: () throws -> Void) throws {
        let temporary = ".manifest-\(UUID().uuidString).tmp"
        let descriptor = Darwin.openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot create case file") }
        defer {
            if referenceMatches(temporary, in: directory, descriptor: descriptor, kind: S_IFREG) {
                _ = Darwin.unlinkat(directory, temporary, 0)
            }
            Darwin.close(descriptor)
        }
        try writeAndSync(data, descriptor: descriptor)
        try validateBeforePublish()
        guard referenceMatches(temporary, in: directory, descriptor: descriptor, kind: S_IFREG) else {
            throw ForensicsError.invalidCase("The staged case manifest changed before publication.")
        }
        guard Darwin.renameat(directory, temporary, directory, manifestName) == 0 else {
            throw FileAccess.posixError("Cannot save case manifest")
        }
        guard Darwin.fsync(directory) == 0 else { throw FileAccess.posixError("Cannot flush case directory") }
    }

    private static func openCaseDirectory(_ bundle: URL) throws -> Int32 {
        let descriptor = Darwin.open(bundle.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ForensicsError.invalidCase("The case directory is inaccessible or has changed.") }
        do { try validateDirectoryReference(bundle, descriptor: descriptor) }
        catch { Darwin.close(descriptor); throw error }
        return descriptor
    }

    private static func validateDirectoryReference(_ url: URL, descriptor: Int32) throws {
        var opened = stat()
        var current = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Darwin.lstat(url.path, &current) == 0,
              current.st_mode & S_IFMT == S_IFDIR,
              opened.st_dev == current.st_dev, opened.st_ino == current.st_ino else {
            throw ForensicsError.invalidCase("The case directory changed during the operation; reopen the case.")
        }
    }

    private static func directoryReferenceMatches(_ name: String, in parent: Int32, descriptor: Int32) -> Bool {
        referenceMatches(name, in: parent, descriptor: descriptor, kind: S_IFDIR)
    }

    private static func referenceMatches(_ name: String, in parent: Int32, descriptor: Int32, kind: mode_t) -> Bool {
        var opened = stat()
        var current = stat()
        return Darwin.fstat(descriptor, &opened) == 0
            && Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0
            && current.st_mode & S_IFMT == kind
            && opened.st_dev == current.st_dev && opened.st_ino == current.st_ino
    }

}
