import Darwin
import Foundation

public struct BrowserTimelineResult: Sendable {
    public let events: [TimelineEvent]
    public let receipts: [TimelineArtifactReceipt]
    public let binding: TimelineSourceBinding
    public init(events: [TimelineEvent], receipts: [TimelineArtifactReceipt], binding: TimelineSourceBinding) {
        self.events = events; self.receipts = receipts; self.binding = binding
    }
}

/// Extracts the exact selected History and every recorded sibling WAL/SHM from
/// one complete listing. SQLite never opens the original evidence or export.
public struct FilesystemBrowserTimelineService: Sendable {
    public let engine: EngineClient
    public init(engine: EngineClient) { self.engine = engine }
    public func parse(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry) async throws -> BrowserTimelineResult {
        try VerifiedContentService.validateSelection(evidence: evidence, result: result, file: file)
        guard result.status == .completed else { throw TimelineError.unsupported("Browser artifacts require a complete filesystem listing so recorded WAL/SHM siblings cannot be silently omitted.") }
        guard !file.isDirectory, !file.isDeleted, file.size > 0, file.size <= 64 * 1_048_576 else { throw TimelineError.unsupported("Select an allocated Chromium History database up to 64 MiB.") }
        let binding = try TimelineSourceBinding.make(caseID: caseID, evidence: evidence, result: result, historical: false)
        let names = [file.path, file.path + "-wal", file.path + "-shm"]
        var selection: [FilesystemEntry] = []
        for path in names {
            let matching = result.files.filter { $0.path == path && $0.fsOffsetBytes == file.fsOffsetBytes }
            guard matching.count <= 1 else { throw TimelineError.inconsistentSnapshot("The listing has ambiguous History or sidecar paths. Select an unambiguous snapshot.") }
            if let sibling = matching.first {
                guard !sibling.isDirectory, !sibling.isDeleted, sibling.attributeType == nil || sibling.attributeType == file.attributeType,
                      sibling.size >= 0, sibling.size <= (path == file.path ? 64 : 16) * 1_048_576 else {
                    throw TimelineError.inconsistentSnapshot("The recorded History sidecar is deleted, unsupported or exceeds its byte cap.")
                }
                selection.append(sibling)
            }
        }
        guard selection.first == file else { throw TimelineError.sourceChanged }
        let scratch = try TimelineExtractScratch()
        defer { scratch.cleanup() }
        var outputs: [String: VerifiedArtifactFile] = [:]
        var options = result.options; options.hashLogicalImage = false
        for (index, entry) in selection.enumerated() {
            try Task.checkCancellation()
            let leaf = "artifact-\(index)"
            let url = scratch.url(leaf)
            let owned = try await engine.extractOwned(imagePaths: result.sourcePaths.map { URL(fileURLWithPath: $0) }, file: entry,
                outputURL: url, options: options, expectedSourceHashes: result.sourceFileHashes)
            try scratch.claim(leaf, output: owned.receipt, identity: owned.identity)
            guard owned.receipt.byteCount == entry.size else { throw TimelineError.sourceChanged }
            outputs[entry.path] = VerifiedArtifactFile(url: url, fileID: entry.id, evidencePath: entry.path,
                byteCount: owned.receipt.byteCount, sha256: owned.receipt.sha256)
        }
        guard let main = outputs[file.path] else { throw TimelineError.sourceChanged }
        let input = VerifiedBrowserArtifact(binding: binding, database: main, wal: outputs[file.path + "-wal"], shm: outputs[file.path + "-shm"],
            expectedWAL: selection.contains { $0.path == file.path + "-wal" }, expectedSHM: selection.contains { $0.path == file.path + "-shm" })
        let events = try await ChromiumHistoryParser.parse(input: input)
        try scratch.validate()
        // Every extraction verifies source bytes. A final verification prevents
        // a different source state during the parser interval being presented.
        var identities: [(URL, SourceIdentity)] = []
        for path in result.sourcePaths {
            let verified = try await ImageInspector.inspect(url: URL(fileURLWithPath: path), progress: { _ in })
            guard verified.sha256 == result.sourceFileHashes[path], let identity = verified.sourceIdentity else { throw TimelineError.sourceChanged }
            identities.append((verified.sourceURL, identity))
        }
        guard identities.allSatisfy({ (try? FileAccess.identity(at: $0.0)) == $0.1 }) else { throw TimelineError.sourceChanged }
        try scratch.validate(); try Task.checkCancellation()
        // Optional sidecars remain explicitly listed even when empty.
        return BrowserTimelineResult(events: events,
            receipts: [TimelineArtifactReceipt(file: main, role: "database")]
                + (input.wal.map { [TimelineArtifactReceipt(file: $0, role: "wal")] } ?? [])
                + (input.shm.map { [TimelineArtifactReceipt(file: $0, role: "shm")] } ?? []), binding: binding)
    }
}

private final class TimelineExtractScratch {
    let rootURL: URL
    private let parentURL: URL
    private let name = ".native-timeline-extract-\(UUID().uuidString.lowercased())"
    private let parent: Int32
    private let root: Int32
    private var owned: [String: SourceIdentity] = [:]
    private var cleaned = false
    init() throws {
        parentURL = try FileAccess.localURL(FileManager.default.temporaryDirectory)
        parent = try EvidenceViewFiles.openDirectory(parentURL)
        rootURL = parentURL.appendingPathComponent(name, isDirectory: true)
        guard Darwin.mkdirat(parent, name, 0o700) == 0 else { let error = FileAccess.posixError("Create timeline scratch"); Darwin.close(parent); throw error }
        let descriptor = Darwin.openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { let error = FileAccess.posixError("Open timeline scratch"); Darwin.close(parent); throw error }
        root = descriptor
    }
    func url(_ name: String) -> URL { rootURL.appendingPathComponent(name) }
    func claim(_ name: String, output: ExtractionResult, identity: SourceIdentity) throws {
        owned[name] = identity
        guard output.outputPath == url(name).path, output.byteCount == identity.size else { throw TimelineError.sourceChanged }
        try validate()
    }
    func validate() throws {
        try EvidenceViewFiles.validateDirectory(parentURL, descriptor: parent)
        try EvidenceViewFiles.validateDirectory(rootURL, descriptor: root)
        for (name, identity) in owned { guard (try? FileAccess.identity(at: name, in: root)) == identity else { throw TimelineError.sourceChanged } }
    }
    func cleanup() {
        guard !cleaned else { return }; cleaned = true
        for (name, identity) in owned where (try? FileAccess.identity(at: name, in: root)) == identity { _ = Darwin.unlinkat(root, name, 0) }
        if (try? EvidenceViewFiles.validateDirectory(rootURL, descriptor: root)) != nil { _ = Darwin.unlinkat(parent, name, AT_REMOVEDIR) }
        Darwin.close(root); Darwin.close(parent)
    }
    deinit { cleanup() }
}
