import CryptoKit
import Darwin
import Foundation

/// A derived logical-file collection for an Autopsy import. This does not add
/// UDF support to TSK or turn host filesystem dates into evidence timestamps.
public struct UDFLogicalFilesExport: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let status: String
    public let destinationPath: String
    public let sourceSHA256: String
    public let sourceByteCount: Int64
    public let caseID: UUID
    public let jobID: UUID
    public let parserVersion: String
    public let profile: String
    public let exportedAt: Date
    public let entries: [Entry]
    public let historyReportSHA256: String
    public let historyJSONSHA256: String
    public let limitations: [String]

    public struct Entry: Codable, Sendable, Equatable {
        public let entryID: String
        public let originalPath: String
        public let outputRelativePath: String
        public let pathMapping: String
        public let state: UDFEntryState
        public let snapshotIDs: [String]
        public let byteCount: Int64
        public let sha256: String
    }
}

public enum UDFLogicalFilesExporter {
    /// Creates one *new* directory. A failed or interrupted run never publishes
    /// its destination; its private stage is retained for diagnosis, not imported.
    /// Raw source metadata stays in Reports rather than being replaced by dates
    /// from the Mac's derived output filesystem.
    public static func export(sourceURL: URL, to destination: URL,
        progress: @escaping @Sendable (UDFInspectionProgress) -> Void = { _ in }) async throws -> UDFLogicalFilesExport {
        try await export(sourceURL: sourceURL, to: destination, progress: progress, beforePublication: {})
    }

    /// Case workflows must bind a fresh export to the examiner's saved source
    /// receipt. Reject changed bytes before creating any staging directories.
    public static func export(evidence: EvidenceRecord, to destination: URL,
        progress: @escaping @Sendable (UDFInspectionProgress) -> Void = { _ in }) async throws -> UDFLogicalFilesExport {
        guard evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.byteCount > 0, evidence.byteCount <= UDFInspectionOptions().maximumSourceBytes,
              EngineValidation.validHash(evidence.sha256) else { throw UDFError.invalidOptions }
        return try await export(sourceURL: URL(fileURLWithPath: evidence.sourcePath), to: destination,
            progress: progress, beforePublication: {}, expectedEvidence: evidence)
    }

    static func export(sourceURL: URL, to destination: URL,
        progress: @escaping @Sendable (UDFInspectionProgress) -> Void = { _ in },
        beforePublication: @escaping @Sendable () throws -> Void,
        timeoutSeconds: Double = 600,
        expectedEvidence: EvidenceRecord? = nil) async throws -> UDFLogicalFilesExport {
        guard timeoutSeconds.isFinite, timeoutSeconds > 0, timeoutSeconds <= 600 else { throw UDFError.invalidOptions }
        let deadline = ProcessInfo.processInfo.systemUptime + timeoutSeconds
        let worker = Task.detached(priority: .userInitiated) {
            try await performExport(sourceURL: sourceURL, to: destination, progress: progress,
                beforePublication: beforePublication, deadline: deadline, expectedEvidence: expectedEvidence)
        }
        let timeout = Task.detached {
            do {
                try await Task.sleep(for: .seconds(timeoutSeconds))
                worker.cancel()
            } catch { /* The completed caller cancels this watchdog. */ }
        }
        defer { timeout.cancel() }
        return try await withTaskCancellationHandler {
            do { return try await worker.value }
            catch is CancellationError {
                if ProcessInfo.processInfo.systemUptime >= deadline { throw UDFError.timeout }
                throw CancellationError()
            }
        } onCancel: { worker.cancel() }
    }

    private static func performExport(sourceURL: URL, to destination: URL,
        progress: @escaping @Sendable (UDFInspectionProgress) -> Void,
        beforePublication: @Sendable () throws -> Void, deadline: TimeInterval,
        expectedEvidence: EvidenceRecord?) async throws -> UDFLogicalFilesExport {
        let check: @Sendable () throws -> Void = {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw UDFError.timeout }
            try Task.checkCancellation()
        }
        let reportProgress: @Sendable (UDFInspectionProgress) -> Void = { value in
            if ProcessInfo.processInfo.systemUptime >= deadline { withUnsafeCurrentTask { $0?.cancel() } }
            progress(value)
        }
        try check()
        let source = sourceURL.standardizedFileURL
        let output = destination.standardizedFileURL
        guard source.isFileURL, output.isFileURL, !source.path.utf8.contains(0), !output.path.utf8.contains(0),
              !output.lastPathComponent.isEmpty, output.path != "/",
              !FileAccess.isInside(source, directory: output) else {
            throw UDFError.invalidResult("Choose a new export directory outside the source image.")
        }
        // Reject user symlinks, including an image leaf, before ImageInspector's
        // canonicalization. Apple /var and /tmp aliases remain supported.
        let sourceParent = try EvidenceViewFiles.openDirectory(source.deletingLastPathComponent(), searchOnly: true)
        defer { Darwin.close(sourceParent) }
        let sourceDescriptor = try FileAccess.openReadOnly(source.lastPathComponent, in: sourceParent)
        defer { Darwin.close(sourceDescriptor) }
        let originalIdentity = try FileAccess.identity(of: sourceDescriptor)
        guard originalIdentity.size > 0, originalIdentity.size <= UDFInspectionOptions().maximumSourceBytes else {
            throw UDFError.limitExceeded("Only raw source images up to 32 GiB are accepted")
        }
        let image = try await ImageInspector.inspect(url: source, progress: { value in
            reportProgress(.init(stage: "Hashing original image", completedBytes: value.bytesRead, totalBytes: value.totalBytes))
        })
        guard image.container == .raw, image.byteCount <= UDFInspectionOptions().maximumSourceBytes,
              image.sourceIdentity == originalIdentity else {
            throw UDFError.unsupported("Select a regular raw .dd, .img or .raw UDF image within 32 GiB.")
        }
        if let expectedEvidence {
            guard image.sha256 == expectedEvidence.sha256, image.byteCount == expectedEvidence.byteCount else {
                throw ForensicsError.sourceChanged
            }
        }
        try check()
        let transaction = try UDFLogicalExportDirectory(destination: output, deadline: deadline)
        let work = transaction.stagedURL
        _ = try transaction.directory("LogicalFiles")
        let reports = try transaction.directory("Reports")
        var forensicCase = try CaseStore.create(name: "UDF Source Receipt", in: reports)
        forensicCase = try CaseStore.adding(image: image, to: forensicCase)
        let evidence = forensicCase.manifest.evidence[0]
        let result = try await UDFInspector.inspect(evidence: evidence, in: forensicCase, progress: reportProgress)
        var records: [UDFLogicalFilesExport.Entry] = []
        for (index, entry) in result.entries.sorted(by: { $0.id < $1.id }).enumerated() {
            try check(); try transaction.validate()
            progress(.init(stage: "Exporting verified file \(index + 1)/\(result.entries.count)",
                completedBytes: Int64(index), totalBytes: Int64(result.entries.count), files: index))
            let mapped = try relativePath(for: entry)
            let target = work.appendingPathComponent(mapped.path)
            try transaction.createParents(for: mapped.path)
            let receipt = try await UDFInspector.export(entryID: entry.id, from: result, in: forensicCase, to: target)
            try check()
            guard receipt.byteCount == entry.byteCount, receipt.sha256 == entry.sha256 else {
                throw UDFError.invalidResult("A derived payload differs from the UDF receipt.")
            }
            records.append(.init(entryID: entry.id, originalPath: entry.originalPath,
                outputRelativePath: mapped.path, pathMapping: mapped.note, state: entry.state,
                snapshotIDs: entry.snapshotIDs, byteCount: receipt.byteCount, sha256: receipt.sha256))
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // Default numeric Date coding retains subsecond values used by the
        // immutable core receipt. Raw 12-byte UDF timestamp fields are also kept.
        let historyBytes = try encoder.encode(result)
        try transaction.write(historyBytes, relativePath: "Reports/udf-history.json")
        let reportURL = reports.appendingPathComponent("udf-history.md")
        try UDFReportBuilder.exportMarkdown(result: result, in: forensicCase, to: reportURL)
        let reportBytes = try Data(contentsOf: reportURL)
        let exported = UDFLogicalFilesExport(schemaVersion: 1, status: "completed", destinationPath: output.path,
            sourceSHA256: result.sourceSHA256, sourceByteCount: result.sourceByteCount,
            caseID: result.caseID, jobID: result.jobID, parserVersion: result.parserVersion, profile: result.profile,
            exportedAt: Date(), entries: records, historyReportSHA256: UDFCoding.hash(reportBytes),
            historyJSONSHA256: UDFCoding.hash(historyBytes), limitations: result.limitations + [
                "Derived logical-file import: Autopsy/TSK does not parse the original UDF filesystem through this adapter.",
                "Host output creation/modification/access dates are export dates, not original UDF evidence times. Read Reports/udf-history.json or .md for source timestamps, raw fields, offsets and timezone.",
                "A unique entry directory separates different versions and case-sensitive source names. Original paths, alias paths and all VAT memberships remain in the history receipt.",
                "No original content extension is guessed or renamed. Enable Autopsy File Type Identification and Extension Mismatch Detector when analyzing disguised filenames.",
                "Only the supported bounded raw-2048 UDF 2.01 physical/virtual/VAT profile is accepted; a 600-second overall watchdog cancels incomplete work, and failures do not publish partial output.",
                "The private nativecase receipt records a local source path. Keep Reports private when it contains personal source metadata."
            ])
        try transaction.write(try encoder.encode(exported), relativePath: "Reports/manifest.json")
        try transaction.write(Data(importGuide.utf8), relativePath: "READ-ME-FIRST.txt")
        try check()
        let after = try await ImageInspector.inspect(url: source, progress: { value in
            reportProgress(.init(stage: "Final source verification", completedBytes: value.bytesRead, totalBytes: value.totalBytes))
        })
        try EvidenceViewFiles.validateDirectory(source.deletingLastPathComponent(), descriptor: sourceParent, searchOnly: true)
        guard after.sha256 == image.sha256, after.byteCount == image.byteCount,
              after.sourceIdentity == originalIdentity,
              try FileAccess.identity(of: sourceDescriptor) == originalIdentity,
              try FileAccess.identity(at: source.lastPathComponent, in: sourceParent) == originalIdentity else {
            throw ForensicsError.sourceChanged
        }
        try beforePublication()
        try check()
        // Rehash every final derived file through no-follow directory handles.
        // This also protects the completed manifest from publication-time edits.
        for record in records {
            try transaction.verify(relativePath: record.outputRelativePath, count: record.byteCount, hash: record.sha256)
        }
        try transaction.verify(relativePath: "Reports/udf-history.json", count: Int64(historyBytes.count), hash: exported.historyJSONSHA256)
        try transaction.verify(relativePath: "Reports/udf-history.md", count: Int64(reportBytes.count), hash: exported.historyReportSHA256)
        let manifestBytes = try encoder.encode(exported)
        try transaction.verify(relativePath: "Reports/manifest.json", count: Int64(manifestBytes.count), hash: UDFCoding.hash(manifestBytes))
        try transaction.verify(relativePath: "READ-ME-FIRST.txt", count: Int64(importGuide.utf8.count), hash: UDFCoding.hash(Data(importGuide.utf8)))
        try transaction.validatePayloadTree(expectedPaths: records.map(\.outputRelativePath))
        guard try UDFInspector.loadLatest(in: forensicCase, evidenceID: evidence.id) == result,
              try FileAccess.identity(of: sourceDescriptor) == originalIdentity,
              try FileAccess.identity(at: source.lastPathComponent, in: sourceParent) == originalIdentity else {
            throw ForensicsError.sourceChanged
        }
        try EvidenceViewFiles.validateDirectory(source.deletingLastPathComponent(), descriptor: sourceParent, searchOnly: true)
        try check()
        try transaction.publish()
        progress(.init(stage: "Complete: add LogicalFiles to Autopsy", completedBytes: Int64(records.count),
            totalBytes: Int64(records.count), files: records.count))
        return exported
    }

    /// Preserve readable leaf names/tree where macOS can represent them. The
    /// per-entry wrapper prevents case-folding collisions and historical-version
    /// overwrite. Unrepresentable/long names have an explicit receipt mapping.
    static func relativePath(for entry: UDFFileEntry) throws -> (path: String, note: String) {
        guard entry.id.count == 64, entry.id.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
              entry.originalPath.hasPrefix("/"), !entry.originalPath.utf8.contains(0) else {
            throw UDFError.invalidResult("An optical entry has an unsafe identifier or path.")
        }
        let components = entry.originalPath.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(String.init)
        guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw UDFError.invalidResult("An optical namespace contains unsafe traversal components.")
        }
        let encoded = components.map(hostComponent)
        let prefix = "LogicalFiles/\(entry.state.rawValue)/\(entry.id)/"
        let tree = prefix + encoded.joined(separator: "/")
        if tree.utf8.count <= 600 {
            return (tree, components == encoded ? "original namespace beneath unique entry wrapper" : "escaped or shortened host names; original namespace remains in history receipt")
        }
        return (prefix + encoded.last!, "long namespace stored in history receipt; output keeps mapped leaf beneath unique entry wrapper")
    }

    private static func hostComponent(_ value: String) -> String {
        var encoded = ""
        for scalar in value.unicodeScalars {
            if scalar.value < 32 || scalar.value == 127 || [37, 58, 92].contains(scalar.value) {
                for byte in String(scalar).utf8 { encoded += String(format: "%%%02X", byte) }
            } else { encoded.unicodeScalars.append(scalar) }
        }
        if encoded.utf8.count <= 180 { return encoded }
        let suffix = "~" + UDFCoding.hash(Data(value.utf8)).prefix(24)
        var shortened = ""
        for scalar in encoded.unicodeScalars {
            let part = String(scalar)
            if shortened.utf8.count + part.utf8.count > 120 { break }
            shortened += part
        }
        return shortened + suffix
    }

    public static let importGuide = """
    UDF files for Autopsy / วิธีเปิดไฟล์ UDF ใน Autopsy

    1. Open Autopsy, create/open your own case, then choose Add Data Source.
    2. Select Logical Files -> Local files and folders. Click Add -> choose this folder's LogicalFiles directory only. Leave all import timestamp checkboxes OFF.
    3. Enable File Type Identification and Extension Mismatch Detector. Enable other modules you need, then Finish.
    4. Source filenames may intentionally disguise Office files as pictures/text. Use detected file type, not extension alone.
    5. Read Reports/manifest.json and udf-history.md/json alongside Autopsy. They bind each exported file to source SHA-256, exact byte count, original UDF path, source extents, source times and VAT history.
    6. Keep the exported folder at this location: Autopsy Logical Files references these absolute host paths rather than copying payloads into the case.

    ภาษาไทย: เปิด Autopsy > Add Data Source > Logical Files > Local files and folders > Add และเลือกเฉพาะโฟลเดอร์ LogicalFiles > ไม่ติ๊กช่องนำเข้าวันเวลา > เปิด File Type Identification และ Extension Mismatch Detector > Finish. เก็บโฟลเดอร์ส่งออกไว้ที่เดิม เพราะ Autopsy อ้างอิงไฟล์ที่ตำแหน่งนี้.
    ไฟล์ที่นำเข้าเป็นสำเนาที่ดึงจาก metadata UDF ไม่ใช่การเพิ่มความสามารถอ่าน UDF ให้ TSK. โฟลเดอร์ชื่อ entry ID ป้องกันไฟล์ต่างเวอร์ชัน/ตัวพิมพ์เล็กใหญ่ทับกัน; อ่านเส้นทางเดิมและประวัติ VAT จาก Reports.
    วันที่ไฟล์ที่ Autopsy เห็นจาก Mac เป็นเวลาส่งออก ห้ามใช้แทนวันเวลาในหลักฐาน. เวลาต้นฉบับและ timezone/raw fields อยู่ใน udf-history.md/json.
    historicalDeletedAncestor หมายถึงไฟล์จากประวัติ VAT ภายใต้โฟลเดอร์บรรพบุรุษที่ลบ ไม่ได้ยืนยันว่าบิต deleted ของไฟล์ลูกถูกตั้ง.
    รักษา image ต้นฉบับและ SHA-256 ไว้. เก็บ Reports ส่วนตัวหากมีชื่อหรือเส้นทางส่วนตัว. ไม่แก้ไขหรือซ่อม image ต้นฉบับ.

    Supported profile: raw 2048-byte UDF 2.01 physical + virtual partition with linked VAT history. Other UDF profiles are rejected with a diagnostic.
    The exporter publishes a new folder only after every file and report verifies. A failed/cancelled run may retain a hidden private .udf-logical-import-*.tmp diagnostic stage; do not import it.
    """
}

/// New output has one atomic publication boundary. Descriptor-relative mkdir,
/// exclusive writes and no-follow reads never trust names from UDF as paths.
/// Private failures are deliberately retained: recursive deletion must not adopt
/// files from a concurrently replaced stage or destroy an examiner's diagnostic.
private final class UDFLogicalExportDirectory {
    let stagedURL: URL
    private let destination: URL
    private let name: String
    private let parent: Int32
    private let root: Int32
    private let deadline: TimeInterval
    private var published = false
    private var verifiedIdentities: [String: SourceIdentity] = [:]

    init(destination: URL, deadline: TimeInterval) throws {
        self.destination = destination
        self.deadline = deadline
        name = ".udf-logical-import-\(UUID().uuidString.lowercased()).tmp"
        stagedURL = destination.deletingLastPathComponent().appendingPathComponent(name, isDirectory: true)
        parent = try EvidenceViewFiles.openDirectory(destination.deletingLastPathComponent())
        var existing = stat()
        guard Darwin.fstatat(parent, destination.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
            Darwin.close(parent); throw UDFError.invalidResult("The export directory already exists. Choose a new name.")
        }
        guard Darwin.mkdirat(parent, name, mode_t(0o700)) == 0 else {
            let error = FileAccess.posixError("Cannot create UDF import stage"); Darwin.close(parent); throw error
        }
        root = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else {
            let error = FileAccess.posixError("Cannot pin UDF import stage"); Darwin.close(parent); throw error
        }
    }
    deinit { Darwin.close(root); Darwin.close(parent) }

    func validate(enforceDeadline: Bool = true) throws {
        if enforceDeadline { try checkDeadline() }
        try EvidenceViewFiles.validateDirectory(destination.deletingLastPathComponent(), descriptor: parent)
        var named = stat(), opened = stat()
        guard Darwin.fstatat(parent, published ? destination.lastPathComponent : name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              Darwin.fstat(root, &opened) == 0, named.st_mode & S_IFMT == S_IFDIR,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino else { throw ForensicsError.sourceChanged }
    }

    func directory(_ relative: String) throws -> URL {
        let descriptor = try openDirectory(relative: relative, create: true)
        defer { Darwin.close(descriptor) }
        return stagedURL.appendingPathComponent(relative, isDirectory: true)
    }

    func createParents(for relative: String) throws {
        let parts = try components(relative)
        let descriptor = try openDirectory(relative: parts.dropLast().joined(separator: "/"), create: true)
        Darwin.close(descriptor)
    }

    func write(_ bytes: Data, relativePath: String) throws {
        guard bytes.count <= 64 * 1_048_576 else { throw UDFError.limitExceeded("Logical import report size") }
        let parts = try components(relativePath)
        let directory = try openDirectory(relative: parts.dropLast().joined(separator: "/"), create: false)
        defer { Darwin.close(directory) }
        let output = Darwin.openat(directory, parts.last!, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard output >= 0 else { throw FileAccess.posixError("Cannot write UDF import report") }
        defer { Darwin.close(output) }
        try bytes.withUnsafeBytes { buffer in
            var copied = 0
            while copied < buffer.count {
                try checkDeadline()
                let count = Darwin.write(output, buffer.baseAddress!.advanced(by: copied), buffer.count - copied)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw FileAccess.posixError("Cannot write UDF import report") }
                copied += count
            }
        }
        guard Darwin.fsync(output) == 0, Darwin.fsync(directory) == 0 else {
            throw FileAccess.posixError("Cannot flush UDF import report")
        }
        try validate()
    }

    func verify(relativePath: String, count: Int64, hash: String) throws {
        let parts = try components(relativePath)
        let directory = try openDirectory(relative: parts.dropLast().joined(separator: "/"), create: false)
        defer { Darwin.close(directory) }
        let input = try FileAccess.openReadOnly(parts.last!, in: directory)
        defer { Darwin.close(input) }
        let before = try FileAccess.identity(of: input)
        var metadata = stat()
        guard before.size == count, Darwin.fstat(input, &metadata) == 0, metadata.st_nlink == 1 else {
            throw UDFError.invalidResult("A derived logical-file output changed before publication.")
        }
        var digest = SHA256(), offset: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while offset < count {
            try checkDeadline()
            let amount = try buffer.withUnsafeMutableBytes { try FileAccess.read(input, into: $0, count: Int(min(Int64($0.count), count - offset))) }
            guard amount > 0 else { throw ForensicsError.sourceChanged }
            digest.update(data: Data(buffer.prefix(amount))); offset += Int64(amount)
        }
        guard UDFCoding.hex(digest.finalize()) == hash, try FileAccess.identity(of: input) == before,
              try FileAccess.identity(at: parts.last!, in: directory) == before else { throw ForensicsError.sourceChanged }
        guard Darwin.fsync(input) == 0, Darwin.fsync(directory) == 0 else { throw FileAccess.posixError("Cannot flush verified logical files") }
        verifiedIdentities[relativePath] = before
        try validate()
    }

    func publish() throws {
        try checkDeadline(); try validate()
        for (path, identity) in verifiedIdentities {
            let parts = try components(path)
            let directory = try openDirectory(relative: parts.dropLast().joined(separator: "/"), create: false)
            defer { Darwin.close(directory) }
            guard try FileAccess.identity(at: parts.last!, in: directory) == identity else { throw ForensicsError.sourceChanged }
        }
        guard Darwin.fsync(root) == 0 else { throw FileAccess.posixError("Cannot flush UDF import folder") }
        try checkDeadline()
        guard Darwin.renameatx_np(parent, name, parent, destination.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            throw FileAccess.posixError("Cannot publish UDF import folder without overwriting")
        }
        published = true // Cancellation after the commit must not hide success.
        guard Darwin.fsync(parent) == 0 else { throw FileAccess.posixError("Cannot flush UDF import destination") }
        try validate(enforceDeadline: false)
    }

    func validatePayloadTree(expectedPaths: [String]) throws {
        let expectedFiles = Set(expectedPaths)
        var expectedDirectories: Set<String> = ["LogicalFiles"]
        for path in expectedPaths {
            let parts = try components(path)
            for count in 1..<parts.count { expectedDirectories.insert(parts.prefix(count).joined(separator: "/")) }
        }
        var foundFiles = Set<String>(), foundDirectories: Set<String> = ["LogicalFiles"]
        func visit(_ relative: String) throws {
            try checkDeadline()
            let descriptor = try openDirectory(relative: relative, create: false)
            defer { Darwin.close(descriptor) }
            let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
            guard duplicate >= 0 else { throw FileAccess.posixError("Cannot inspect logical payload folder") }
            guard let stream = Darwin.fdopendir(duplicate) else {
                Darwin.close(duplicate); throw FileAccess.posixError("Cannot inspect logical payload folder")
            }
            defer { Darwin.closedir(stream) }
            while let entry = Darwin.readdir(stream) {
                let name = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
                }
                if name == "." || name == ".." { continue }
                let path = relative + "/" + name
                var metadata = stat()
                guard Darwin.fstatat(descriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else { throw ForensicsError.sourceChanged }
                if metadata.st_mode & S_IFMT == S_IFDIR {
                    guard expectedDirectories.contains(path), foundDirectories.insert(path).inserted else {
                        throw UDFError.invalidResult("The import folder contains an unexpected directory.")
                    }
                    try visit(path)
                } else {
                    guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_nlink == 1,
                          expectedFiles.contains(path), foundFiles.insert(path).inserted,
                          verifiedIdentities[path] == SourceIdentity(metadata) else {
                        throw UDFError.invalidResult("The import folder contains an unexpected file or link.")
                    }
                }
            }
            guard Darwin.fsync(descriptor) == 0 else { throw FileAccess.posixError("Cannot flush logical payload tree") }
        }
        try visit("LogicalFiles")
        guard foundFiles == expectedFiles, foundDirectories == expectedDirectories else {
            throw UDFError.invalidResult("The import payload tree differs from its completed manifest.")
        }
        try validate()
    }

    private func components(_ value: String) throws -> [String] {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw UDFError.invalidResult("A derived output path is unsafe.")
        }
        return parts
    }

    private func checkDeadline() throws {
        guard ProcessInfo.processInfo.systemUptime < deadline else { throw UDFError.timeout }
        try Task.checkCancellation()
    }

    private func openDirectory(relative: String, create: Bool) throws -> Int32 {
        try validate()
        var directory = Darwin.fcntl(root, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw FileAccess.posixError("Cannot pin UDF import directory") }
        do {
            if !relative.isEmpty {
                for part in try components(relative) {
                    if create && Darwin.mkdirat(directory, part, mode_t(0o700)) != 0 && errno != EEXIST {
                        throw FileAccess.posixError("Cannot create UDF namespace folder")
                    }
                    let child = Darwin.openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard child >= 0 else { throw FileAccess.posixError("Cannot open UDF namespace folder without following links") }
                    Darwin.close(directory); directory = child
                }
            }
            try validate(); return directory
        } catch { Darwin.close(directory); throw error }
    }
}
