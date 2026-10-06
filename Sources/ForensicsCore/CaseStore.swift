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
        let destination = directory.appendingPathComponent(cleanName).appendingPathExtension(bundleExtension)
        let staging = directory.appendingPathComponent(".nativecase-\(UUID().uuidString).tmp", isDirectory: true)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: staging) }

        let manifest = try canonicalManifest(CaseManifest(name: cleanName))
        try writeNewFile(try encode(manifest), at: staging.appendingPathComponent(manifestName))
        try writeNewFile(Data(), at: staging.appendingPathComponent(lockName))
        try syncDirectory(staging)
        let published = Darwin.renameatx_np(AT_FDCWD, staging.path, AT_FDCWD, destination.path, UInt32(RENAME_EXCL))
        guard published == 0 else {
            if errno == EEXIST { throw ForensicsError.caseAlreadyExists }
            throw FileAccess.posixError("Cannot create case")
        }
        try syncDirectory(directory)
        return ForensicCase(bundleURL: destination, manifest: manifest)
    }

    /// Opens the manifest without modifying the bundle or opening its evidence.
    public static func open(at url: URL) throws -> ForensicCase {
        let bundle = try caseURL(url)
        let manifest = try readManifest(in: bundle)
        return ForensicCase(bundleURL: bundle, manifest: manifest)
    }

    /// Records a fresh inspection without copying or writing its source file.
    /// A saved/decoded DTO needs reinspection because local identity provenance
    /// is not serialized. The case lock makes compare-and-write one transaction.
    public static func adding(image: InspectedImage, to forensicCase: ForensicCase) throws -> ForensicCase {
        let bundle = try caseURL(forensicCase.bundleURL)
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

        let lockURL = bundle.appendingPathComponent(lockName)
        let lock = Darwin.open(lockURL.path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard lock >= 0 else { throw ForensicsError.invalidCase("The case lock is missing or inaccessible.") }
        defer { Darwin.close(lock) }
        _ = try FileAccess.identity(of: lock)
        while systemFlock(lock, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            throw FileAccess.posixError("Cannot lock case")
        }
        defer { _ = systemFlock(lock, LOCK_UN) }

        let current = try readManifest(in: bundle)
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
        try replaceManifest(updated, in: bundle)
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

    private static func validateManifest(_ manifest: CaseManifest) throws {
        guard manifest.schemaVersion == 1 else {
            throw ForensicsError.invalidCase("This case schema version is unsupported; the original manifest was preserved.")
        }
        try validateName(manifest.name)
        var identifiers = Set<UUID>()
        var paths = Set<String>()
        for record in manifest.evidence {
            guard identifiers.insert(record.id).inserted, paths.insert(record.sourcePath).inserted,
                  record.sourcePath.hasPrefix("/"), !record.sourcePath.utf8.contains(0),
                  record.byteCount >= 0, validHash(record.sha256),
                  record.hashScope == FileHashScope.selectedFileBytes else {
                throw ForensicsError.invalidCase("The evidence manifest has invalid or duplicate records.")
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

    private static func readManifest(in bundle: URL) throws -> CaseManifest {
        let url = bundle.appendingPathComponent(manifestName)
        let descriptor: Int32
        do { descriptor = try FileAccess.openReadOnly(url) }
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
        guard try FileAccess.identity(of: descriptor) == before else {
            throw ForensicsError.invalidCase("The manifest changed while being opened.")
        }
        let manifest: CaseManifest
        do { manifest = try decoder().decode(CaseManifest.self, from: data) }
        catch { throw ForensicsError.invalidCase("manifest.json is not a supported case manifest.") }
        try validateManifest(manifest)
        return manifest
    }

    private static func writeNewFile(_ data: Data, at url: URL) throws {
        let descriptor = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot create case file") }
        defer { Darwin.close(descriptor) }
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

    private static func replaceManifest(_ manifest: CaseManifest, in bundle: URL) throws {
        let temporary = bundle.appendingPathComponent(".manifest-\(UUID().uuidString).tmp")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try writeNewFile(try encode(manifest), at: temporary)
        guard Darwin.rename(temporary.path, bundle.appendingPathComponent(manifestName).path) == 0 else {
            throw FileAccess.posixError("Cannot save case manifest")
        }
        try syncDirectory(bundle)
    }

    private static func syncDirectory(_ url: URL) throws {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot open case directory") }
        defer { Darwin.close(descriptor) }
        guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush case directory") }
    }
}
