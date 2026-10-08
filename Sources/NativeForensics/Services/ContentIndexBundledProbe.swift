import CryptoKit
import Darwin
import Foundation
import ForensicsCore

/// Explicit synthetic acceptance through the real bundled host and production
/// Core/XPC factories. Normal workbench launch never enters this diagnostic.
enum ContentIndexBundledProbe {
    struct Arguments: Equatable {
        let fixture: URL
        let output: URL
        static func parse(_ arguments: [String]) throws -> Self {
            guard arguments.count == 4 else { throw Failure.arguments }
            var values: [String: String] = [:]
            for index in stride(from: 0, to: arguments.count, by: 2) {
                guard ["--fixture", "--output"].contains(arguments[index]), values[arguments[index]] == nil,
                      arguments[index + 1].hasPrefix("/"), !arguments[index + 1].utf8.contains(0) else { throw Failure.arguments }
                values[arguments[index]] = arguments[index + 1]
            }
            guard let fixture = values["--fixture"], let output = values["--output"] else { throw Failure.arguments }
            let source = URL(fileURLWithPath: fixture, isDirectory: true).standardizedFileURL
            let destination = URL(fileURLWithPath: output, isDirectory: true).standardizedFileURL
            guard source.path == fixture, destination.path == output,
                  source.lastPathComponent.hasPrefix("nf-index-fixture-"), source.pathExtension == "noindex",
                  destination.lastPathComponent.hasPrefix("nf-index-run-"), destination.pathExtension == "noindex",
                  source.deletingLastPathComponent() == destination.deletingLastPathComponent(), source != destination else {
                throw Failure.arguments
            }
            return Self(fixture: source, output: destination)
        }
    }

    static func run(_ arguments: [String]) async -> Int32 {
        do {
            guard Bundle.main.bundleURL.pathExtension == "app" else { throw Failure.bundle }
            let options = try Arguments.parse(arguments)
            try await session(options)
            return 0
        } catch {
            FileHandle.standardError.write(Data("Content index probe failed: \(String(describing: type(of: error)))\n".utf8))
            return 64
        }
    }

    private static func session(_ arguments: Arguments) async throws {
        let fixture = try OwnedDirectory.open(arguments.fixture)
        defer { fixture.close() }
        let parent = try OwnedDirectory.open(arguments.output.deletingLastPathComponent())
        defer { parent.close() }
        let output = try parent.create(arguments.output.lastPathComponent)
        defer { output.close() } // Failed candidates are retained, never pathname-cleaned.
        let marker: Marker = try fixture.read("fixture.json", maximumBytes: 4_096)
        guard marker.schemaVersion == 1, marker.syntheticOnly,
              marker.fixtureKind == "nf-content-index-pipeline-v1" else { throw Failure.fixture }
        let engineURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFTSKEngine")
        let decoderURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder")
        let engine = EngineClient(helperURL: engineURL)
        let ledger = Ledger()
        let cancellation = CancellationControl()
        let service = CaseContentIndexService(engineHelperURL: engineURL, documentHelperURL: decoderURL,
            decoderLifecycle: { event in
                ledger.decoder(event)
                if case .started(let pid, let backend) = event {
                    guard backend == .appSandboxXPC, waitForAcknowledgement(pid: pid) else {
                        ledger.failObservation(); cancellation.request(); return
                    }
                    if ledger.stage == "cancel" { cancellation.request() }
                }
            })
        var scopes: [String: Scope] = [:]
        for label in ["stable", "original", "replacement"] {
            let oracle: Oracle = try fixture.read(label + "/oracle.json", maximumBytes: 16 * 1_048_576)
            guard oracle.schemaVersion == 1, oracle.syntheticOnly, oracle.imageByteCount >= 256 * 1_048_576 else {
                throw Failure.fixture
            }
            let url = arguments.fixture.appendingPathComponent(label + "/workload-fat32.raw")
            let identity = try FileState.inspect(url)
            let inspection = try await ImageInspector.inspect(url: url, progress: { _ in })
            guard inspection.sha256 == oracle.imageSHA256, inspection.byteCount == oracle.imageByteCount else { throw Failure.fixture }
            let listing = try await engine.enumerate(imageURL: url, options: .init(timezone: "UTC", hashLogicalImage: false))
            let regular = listing.files.filter { !$0.isDirectory }
            guard listing.status == .completed, Set(regular.map(\.path)) == Set(oracle.files.keys),
                  regular.allSatisfy({ !$0.isDeleted && $0.size == oracle.files[$0.path]?.byteCount }) else { throw Failure.fixture }
            guard try FileState.inspect(url) == identity else { throw Failure.fixture }
            scopes[label] = Scope(label: label, inspection: inspection, listing: listing, oracle: oracle, fileState: identity)
        }
        guard var stable = scopes["stable"], var original = scopes["original"], var replacement = scopes["replacement"],
              original.inspection.sha256 != replacement.inspection.sha256 else { throw Failure.fixture }
        var forensicCase = try CaseStore.create(name: "Content Index Probe", in: arguments.output)
        forensicCase = try CaseStore.adding(image: stable.inspection, to: forensicCase)
        forensicCase = try CaseStore.adding(image: original.inspection, to: forensicCase)
        stable.evidence = forensicCase.manifest.evidence[0]
        original.evidence = forensicCase.manifest.evidence[1]
        var replacementCase = try CaseStore.create(name: "Replacement Source Record", in: arguments.output)
        replacementCase = try CaseStore.adding(image: replacement.inspection, to: replacementCase)
        replacement.evidence = replacementCase.manifest.evidence[0]
        let caseID = forensicCase.manifest.id
        let manifestBefore = try output.readBytes("Content Index Probe.nativecase/manifest.json", maximumBytes: 16 * 1_048_576)
        let replacementManifestBefore = try output.readBytes("Replacement Source Record.nativecase/manifest.json", maximumBytes: 16 * 1_048_576)
        let inputs = try [stable, original].map { try $0.input() }
        let changedInputs = try [stable, replacement].map { try $0.input() }
        for scope in [stable, original] {
            try EngineResultStore.save(result: scope.listing, evidenceID: scope.record.id, in: forensicCase.bundleURL)
            guard try EngineResultStore.load(evidenceID: scope.record.id, in: forensicCase.bundleURL) == scope.listing else { throw Failure.persistence }
        }
        let scratchBefore = try scratchNames()
        var stages: [Stage] = []
        var searches: [String: [String: [Hit]]] = [:]
        ledger.begin("rebuild")
        var start = DispatchTime.now().uptimeNanoseconds
        let rebuilt = try await service.rebuild(caseID: caseID, inputs: inputs, progress: ledger.progress)
        let rebuildDuration = DispatchTime.now().uptimeNanoseconds - start
        try validate(rebuilt, scopes: [stable, original])
        try ledger.validate(reused: 0, rebuilt: 18)
        try CaseContentIndexStore.save(rebuilt, expectedSnapshotID: nil, in: forensicCase.bundleURL)
        guard try CaseContentIndexStore.load(in: forensicCase.bundleURL) == rebuilt else { throw Failure.persistence }
        try output.write(rebuilt, named: "rebuild-index.json")
        searches["rebuild"] = try search(rebuilt, scopes: [stable, original])
        stages.append(Stage(snapshot: rebuilt, stage: "rebuild", duration: rebuildDuration, progress: ledger.latest,
                            filename: "rebuild-index.json"))
        ledger.end()

        ledger.begin("unchanged")
        start = DispatchTime.now().uptimeNanoseconds
        let unchanged = try await service.update(caseID: caseID, inputs: inputs, previous: rebuilt,
                                                  progress: ledger.progress)
        let unchangedDuration = DispatchTime.now().uptimeNanoseconds - start
        guard unchanged.id != rebuilt.id, unchanged.documents == rebuilt.documents,
              unchanged.sources == rebuilt.sources else { throw Failure.oracle }
        try validate(unchanged, scopes: [stable, original]); try ledger.validate(reused: 8, rebuilt: 10)
        try CaseContentIndexStore.save(unchanged, expectedSnapshotID: rebuilt.id, in: forensicCase.bundleURL)
        guard try CaseContentIndexStore.load(in: forensicCase.bundleURL) == unchanged else { throw Failure.persistence }
        try output.write(unchanged, named: "unchanged-index.json")
        searches["unchanged"] = try search(unchanged, scopes: [stable, original])
        try oldReferenceDoesNotResolve(from: rebuilt, in: unchanged)
        stages.append(Stage(snapshot: unchanged, stage: "unchanged", duration: unchangedDuration, progress: ledger.latest,
                            filename: "unchanged-index.json"))
        ledger.end()
        let persistedBefore = try output.readBytes("Content Index Probe.nativecase/" + CaseContentIndexStore.filename,
                                                  maximumBytes: ContentIndexLimits.maximumSerializedBytes)

        ledger.begin("changed")
        start = DispatchTime.now().uptimeNanoseconds
        let changed = try await service.update(caseID: caseID, inputs: changedInputs, previous: unchanged,
                                                progress: ledger.progress)
        let changedDuration = DispatchTime.now().uptimeNanoseconds - start
        try validate(changed, scopes: [stable, replacement]); try ledger.validate(reused: 4, rebuilt: 14)
        guard changed.documents.filter({ $0.evidenceID == stable.record.id && $0.status == .indexed })
                == unchanged.documents.filter({ $0.evidenceID == stable.record.id && $0.status == .indexed }),
              replacement.record.id != original.record.id, changed.id != unchanged.id else { throw Failure.oracle }
        var publicationRefused = false
        do { try CaseContentIndexStore.save(changed, expectedSnapshotID: unchanged.id, in: forensicCase.bundleURL) }
        catch ContentIndexError.sourceChanged { publicationRefused = true }
        guard publicationRefused else { throw Failure.persistence }
        try output.write(changed, named: "changed-index.json")
        searches["changed"] = try search(changed, scopes: [stable, replacement])
        try oldReferenceDoesNotResolve(from: unchanged, in: changed)
        stages.append(Stage(snapshot: changed, stage: "changed", duration: changedDuration, progress: ledger.latest,
                            filename: "changed-index.json"))
        ledger.end()

        ledger.begin("cancel")
        start = DispatchTime.now().uptimeNanoseconds
        let task = Task { try await service.update(caseID: caseID, inputs: changedInputs,
                                                   previous: unchanged, progress: ledger.progress) }
        cancellation.attach { task.cancel() }
        var cancelled = false
        do { _ = try await task.value }
        catch is CancellationError { cancelled = true }
        let cancellationReturnedAt = DispatchTime.now().uptimeNanoseconds
        cancellation.detach()
        guard cancelled, cancellation.requested, ledger.observationSucceeded, ledger.startedCount > 0,
              ledger.startedPIDs == ledger.exitedPIDs else { throw Failure.cancellation }
        let cancelDuration = cancellationReturnedAt - start
        guard let cancellationRequestedAt = cancellation.requestedAt,
              cancellationReturnedAt >= cancellationRequestedAt else { throw Failure.cancellation }
        ledger.end()

        ledger.begin("recovery")
        start = DispatchTime.now().uptimeNanoseconds
        let recovery = try await service.update(caseID: caseID, inputs: changedInputs, previous: unchanged,
                                                 progress: ledger.progress)
        let recoveryDuration = DispatchTime.now().uptimeNanoseconds - start
        try validate(recovery, scopes: [stable, replacement]); try ledger.validate(reused: 4, rebuilt: 14)
        try output.write(recovery, named: "recovery-index.json")
        searches["recovery"] = try search(recovery, scopes: [stable, replacement])
        stages.append(Stage(snapshot: recovery, stage: "recovery", duration: recoveryDuration, progress: ledger.latest,
                            filename: "recovery-index.json"))
        ledger.end()
        guard try output.readBytes("Content Index Probe.nativecase/manifest.json", maximumBytes: 16 * 1_048_576) == manifestBefore,
              try output.readBytes("Replacement Source Record.nativecase/manifest.json", maximumBytes: 16 * 1_048_576) == replacementManifestBefore,
              try output.readBytes("Content Index Probe.nativecase/" + CaseContentIndexStore.filename,
                                    maximumBytes: ContentIndexLimits.maximumSerializedBytes) == persistedBefore,
              try CaseContentIndexStore.load(in: forensicCase.bundleURL) == unchanged else { throw Failure.persistence }
        for scope in [stable, original, replacement] {
            let fresh = try await ImageInspector.inspect(url: scope.inspection.sourceURL, progress: { _ in })
            guard fresh.sha256 == scope.inspection.sha256, try FileState.inspect(scope.inspection.sourceURL) == scope.fileState else { throw Failure.fixture }
        }
        let remaining = try scratchNames().subtracting(scratchBefore).count
        guard remaining == 0 else { throw Failure.cancellation }
        try fixture.check(); try output.check()
        let report = Report(schemaVersion: 1, syntheticOnly: true, backend: "actual-bundled-app-sandbox-xpc",
            providerExecuted: false, guiMeasured: false, sources: [stable, original, replacement].map(SourceReceipt.init),
            stages: stages, searchHits: searches, publicationRefused: publicationRefused,
            cancellationRequested: cancellation.requested, cancellationReturned: cancelled,
            cancellationDurationNanoseconds: cancelDuration, priorGenerationUnchanged: true, newScratchRemaining: remaining,
            cancellationRequestedUptimeNanoseconds: cancellationRequestedAt,
            cancellationReturnedUptimeNanoseconds: cancellationReturnedAt,
            cancellationDrainNanoseconds: cancellationReturnedAt - cancellationRequestedAt,
            measurementScope: "Explicit bundled Main diagnostic calling the production Core service directly; no workbench scheduler or GUI. Process RSS includes three bounded expected-text oracles, retained snapshots and setup/verification; stage timers isolate Core API calls.",
            cancellationScope: "After a trusted accepted worker and observer ACK; parser-body execution need not have started. Core task and existing lifecycle exits awaited; external driver must separately prove kernel physical exit.",
            observationSynchronization: "Per accepted worker: stdout event then exact stdin ACK PID within 3 seconds; instrumentation overhead is included.")
        try output.write(report, named: "receipt.json")
        Ledger.emit(Event(kind: "complete", stage: "", processIdentifier: nil, receipt: "receipt.json"))
    }

    private static func validate(_ snapshot: CaseContentIndexSnapshot, scopes: [Scope]) throws {
        guard snapshot.limits == ContentIndexLimits(), snapshot.indexedCount == 8, snapshot.skippedCount == 12,
              snapshot.failedCount == 0, snapshot.pendingCount == 0, snapshot.missingListingCount == 0,
              snapshot.documents.count == 20, snapshot.isPartial,
              snapshot.decoderIdentity?.isolation == .appSandboxXPC else { throw Failure.oracle }
        for scope in scopes {
            let documents = snapshot.documents.filter { $0.evidenceID == scope.record.id }
            guard Set(documents.map { $0.file.path }) == Set(scope.oracle.files.keys) else { throw Failure.oracle }
            for document in documents {
                guard let expected = scope.oracle.files[document.file.path], document.status.rawValue == expected.indexStatus,
                      document.reason == expected.indexReason, document.textIsComplete == expected.textIsComplete else { throw Failure.oracle }
                if document.status == .indexed {
                    guard document.contentSHA256 == expected.sha256, document.textPages.count == 1,
                          document.textPages[0].text == expected.text,
                          document.decoderProvenance?.isolation == .appSandboxXPC,
                          let provenance = document.decoderProvenance, snapshot.decoderIdentity?.matches(provenance) == true else { throw Failure.oracle }
                }
            }
        }
    }

    private static func search(_ snapshot: CaseContentIndexSnapshot, scopes: [Scope]) throws -> [String: [Hit]] {
        let queries = Set(scopes.flatMap { $0.oracle.queries.keys })
        var output: [String: [Hit]] = [:]
        for query in queries.sorted() {
            let found = try CaseContentIndexSearch.search(query, in: snapshot, caseSensitive: true)
            guard !found.hitLimitReached, found.coverageIsPartial else { throw Failure.oracle }
            let actual = try found.hits.map { hit -> Hit in
                guard let scope = scopes.first(where: { $0.record.id == hit.reference.evidenceID }),
                      let page = CaseContentIndexSearch.resolve(hit.reference, in: snapshot),
                      (page.text as NSString).substring(with: NSRange(location: hit.reference.utf16Offset,
                       length: hit.reference.utf16Length)) == query else { throw Failure.oracle }
                return Hit(label: scope.label, path: hit.reference.file.path, utf16Offset: hit.reference.utf16Offset,
                    utf16Length: hit.reference.utf16Length, contentSHA256: hit.reference.contentSHA256,
                    orderedContainerSHA256: hit.reference.orderedContainerSHA256)
            }.sorted()
            var expected: [Hit] = []
            for scope in scopes {
                for reference in scope.oracle.queries[query] ?? [] {
                    guard let file = scope.oracle.files[reference.path] else { throw Failure.oracle }
                    expected.append(Hit(label: scope.label, path: reference.path, utf16Offset: reference.utf16Offset,
                        utf16Length: reference.utf16Length, contentSHA256: file.sha256,
                        orderedContainerSHA256: [scope.inspection.sha256]))
                }
            }
            guard actual == expected.sorted() else { throw Failure.oracle }
            output[query] = actual
        }
        return output
    }

    private static func oldReferenceDoesNotResolve(from old: CaseContentIndexSnapshot, in current: CaseContentIndexSnapshot) throws {
        if let hit = try CaseContentIndexSearch.search("needleOnlyInPayload", in: old, caseSensitive: true).hits.first {
            guard CaseContentIndexSearch.resolve(hit.reference, in: current) == nil else { throw Failure.oracle }
        } else { throw Failure.oracle }
    }

    static func waitForAcknowledgement(pid: Int32, descriptor: Int32 = STDIN_FILENO) -> Bool {
        guard pid > 0 else { return false }
        let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
        var bytes = Data()
        while bytes.count < 64, DispatchTime.now().uptimeNanoseconds < deadline {
            var item = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
            let result = Darwin.poll(&item, 1, 50)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { return false }
            if result == 0 { continue }
            var byte: UInt8 = 0
            let count = Darwin.read(descriptor, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            guard count == 1 else { return false }
            bytes.append(byte)
            if byte == 10 { return bytes == Data("ACK \(pid)\n".utf8) }
        }
        return false
    }

    private static func scratchNames() throws -> Set<String> {
        Set(try FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
            .filter { $0.hasPrefix(".native-document-") })
    }
    enum Failure: Error, Equatable { case arguments, bundle, fixture, destination, persistence, oracle, cancellation, observation }
    private struct Marker: Decodable { let schemaVersion: Int; let syntheticOnly: Bool; let fixtureKind: String }
    private struct Oracle: Decodable {
        let schemaVersion: Int; let syntheticOnly: Bool; let imageByteCount: Int64; let imageSHA256: String
        let files: [String: ExpectedFile]; let queries: [String: [ExpectedHit]]
    }
    private struct ExpectedFile: Decodable {
        let byteCount: Int64; let sha256: String; let text: String?; let indexStatus: String
        let indexReason: String?; let textIsComplete: Bool
    }
    private struct ExpectedHit: Decodable { let path: String; let utf16Offset: Int; let utf16Length: Int }
    private struct Scope {
        let label: String; let inspection: InspectedImage; let listing: EnumerationResult; let oracle: Oracle; let fileState: FileState
        var evidence: EvidenceRecord?
        var record: EvidenceRecord { evidence! } // Assigned only from normal fresh CaseStore recording above.
        func input() throws -> ContentIndexInput {
            guard let evidence else { throw Failure.fixture }
            return ContentIndexInput(evidence: evidence, result: listing)
        }
    }
    private struct SourceReceipt: Encodable {
        let label: String; let evidenceID: UUID; let path: String; let sha256: String; let byteCount: Int64
        init(_ source: Scope) {
            label = source.label; evidenceID = source.record.id; path = source.record.sourcePath
            sha256 = source.record.sha256; byteCount = source.record.byteCount
        }
    }
    private struct Stage: Encodable {
        let stage: String; let durationNanoseconds: UInt64; let previewCount: Int; let reusedFiles: Int; let rebuiltFiles: Int
        let sourceIDs: [UUID]; let snapshotID: UUID; let serializedFilename: String
        init(snapshot: CaseContentIndexSnapshot, stage: String, duration: UInt64, progress: ContentIndexProgress?, filename: String) {
            self.stage = stage; durationNanoseconds = duration; previewCount = progress?.rebuiltFiles ?? -1
            reusedFiles = progress?.reusedFiles ?? -1; rebuiltFiles = progress?.rebuiltFiles ?? -1
            sourceIDs = snapshot.sources.map(\.evidenceID); snapshotID = snapshot.id; serializedFilename = filename
        }
    }
    private struct Hit: Encodable, Equatable, Comparable {
        let label: String; let path: String; let utf16Offset: Int; let utf16Length: Int
        let contentSHA256: String; let orderedContainerSHA256: [String]
        static func < (lhs: Self, rhs: Self) -> Bool {
            if lhs.label != rhs.label { return lhs.label < rhs.label }
            if lhs.path != rhs.path { return lhs.path < rhs.path }
            return lhs.utf16Offset < rhs.utf16Offset
        }
    }
    private struct Report: Encodable {
        let schemaVersion: Int; let syntheticOnly: Bool; let backend: String; let providerExecuted: Bool; let guiMeasured: Bool
        let sources: [SourceReceipt]; let stages: [Stage]; let searchHits: [String: [String: [Hit]]]
        let publicationRefused: Bool; let cancellationRequested: Bool; let cancellationReturned: Bool
        let cancellationDurationNanoseconds: UInt64; let priorGenerationUnchanged: Bool; let newScratchRemaining: Int
        let cancellationRequestedUptimeNanoseconds: UInt64; let cancellationReturnedUptimeNanoseconds: UInt64
        let cancellationDrainNanoseconds: UInt64; let measurementScope: String; let cancellationScope: String
        let observationSynchronization: String
    }
    private struct Event: Encodable {
        let schemaVersion = 1; let kind: String; let stage: String; let processIdentifier: Int32?; let receipt: String?
        let uptimeNanoseconds = DispatchTime.now().uptimeNanoseconds
        init(kind: String, stage: String, processIdentifier: Int32? = nil, receipt: String? = nil) {
            self.kind = kind; self.stage = stage; self.processIdentifier = processIdentifier; self.receipt = receipt
        }
    }
    private final class Ledger: @unchecked Sendable {
        private let lock = NSLock()
        private var current = "", observed = true, progressValue: ContentIndexProgress?
        private var started: [Int32] = [], exited: [Int32] = []
        var stage: String { lock.withLock { current } }
        var latest: ContentIndexProgress? { lock.withLock { progressValue } }
        var startedPIDs: [Int32] { lock.withLock { started } }
        var exitedPIDs: [Int32] { lock.withLock { exited } }
        var startedCount: Int { lock.withLock { started.count } }
        var observationSucceeded: Bool { lock.withLock { observed } }
        func begin(_ name: String) {
            lock.withLock { current = name; progressValue = nil; started = []; exited = [] }
            Self.emit(Event(kind: "stageStarted", stage: name))
        }
        func end() { Self.emit(Event(kind: "stageCompleted", stage: stage)) }
        func progress(_ value: ContentIndexProgress) { lock.withLock { progressValue = value } }
        func failObservation() { lock.withLock { observed = false } }
        func decoder(_ event: DocumentDecoderLifecycleEvent) {
            let value = lock.withLock { () -> Event in
                switch event {
                case .started(let pid, _): started.append(pid); return Event(kind: "decoderStarted", stage: current, processIdentifier: pid)
                case .exited(let pid): exited.append(pid); return Event(kind: "decoderExited", stage: current, processIdentifier: pid)
                }
            }
            Self.emit(value)
        }
        func validate(reused: Int, rebuilt: Int) throws {
            guard observationSucceeded, startedPIDs == exitedPIDs, startedCount == rebuilt,
                  latest?.reusedFiles == reused, latest?.rebuiltFiles == rebuilt,
                  latest?.finishedFiles == 20, latest?.plannedFiles == 20 else { throw Failure.observation }
        }
        static func emit(_ value: Event) {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            if var data = try? encoder.encode(value) {
                data.append(10); FileHandle.standardOutput.write(data)
            }
        }
    }
    private final class CancellationControl: @unchecked Sendable {
        private let lock = NSLock()
        private var action: (@Sendable () -> Void)?, wasRequested = false, requestTimestamp: UInt64?
        var requested: Bool { lock.withLock { wasRequested } }
        var requestedAt: UInt64? { lock.withLock { requestTimestamp } }
        func attach(_ action: @escaping @Sendable () -> Void) {
            let already = lock.withLock { self.action = action; return wasRequested }
            if already { action() }
        }
        func request() {
            let pending = lock.withLock {
                wasRequested = true
                if requestTimestamp == nil { requestTimestamp = DispatchTime.now().uptimeNanoseconds }
                return action
            }
            pending?()
        }
        func detach() { lock.withLock { action = nil } }
    }
    final class OwnedDirectory {
        let url: URL
        private let descriptor: Int32
        private let device: dev_t, inode: ino_t
        private var closed = false
        private init(url: URL, descriptor: Int32, metadata: stat) {
            self.url = url; self.descriptor = descriptor; device = metadata.st_dev; inode = metadata.st_ino
        }
        static func open(_ url: URL) throws -> OwnedDirectory {
            guard url == url.resolvingSymlinksInPath() else { throw Failure.destination }
            let fd = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.destination }
            var metadata = stat()
            guard Darwin.fstat(fd, &metadata) == 0, metadata.st_uid == Darwin.getuid(),
                  metadata.st_mode & 0o777 == 0o700 else { Darwin.close(fd); throw Failure.destination }
            let value = OwnedDirectory(url: url, descriptor: fd, metadata: metadata)
            do { try value.check(); return value } catch { value.close(); throw error }
        }
        func check() throws {
            var held = stat(), named = stat()
            guard !closed, Darwin.fstat(descriptor, &held) == 0, Darwin.lstat(url.path, &named) == 0,
                  named.st_mode & S_IFMT == S_IFDIR, named.st_dev == device, named.st_ino == inode,
                  held.st_dev == device, held.st_ino == inode, named.st_uid == Darwin.getuid(),
                  named.st_mode & 0o777 == 0o700, url == url.resolvingSymlinksInPath() else { throw Failure.destination }
        }
        func create(_ name: String) throws -> OwnedDirectory {
            try check()
            guard !name.contains("/"), Darwin.mkdirat(descriptor, name, 0o700) == 0 else { throw Failure.destination }
            let value = try Self.open(url.appendingPathComponent(name, isDirectory: true))
            try check(); return value
        }
        func read<T: Decodable>(_ name: String, maximumBytes: Int) throws -> T {
            try JSONDecoder().decode(T.self, from: readBytes(name, maximumBytes: maximumBytes))
        }
        func readBytes(_ name: String, maximumBytes: Int) throws -> Data {
            try check()
            let file = url.appendingPathComponent(name).standardizedFileURL
            guard file.path.hasPrefix(url.path + "/"), file == file.resolvingSymlinksInPath() else { throw Failure.destination }
            let fd = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.destination }
            defer { Darwin.close(fd) }
            var before = stat(), after = stat(), named = stat()
            guard Darwin.fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
                  before.st_uid == Darwin.getuid(), before.st_nlink == 1,
                  before.st_size >= 0, before.st_size <= maximumBytes else { throw Failure.fixture }
            var data = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
            while data.count < before.st_size {
                let requested = min(buffer.count, Int(before.st_size) - data.count)
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, requested) }
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Failure.fixture }
                data.append(contentsOf: buffer.prefix(count))
            }
            guard Darwin.fstat(fd, &after) == 0, Darwin.lstat(file.path, &named) == 0,
                  before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
                  before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                  before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
                  before.st_dev == named.st_dev, before.st_ino == named.st_ino,
                  before.st_size == named.st_size, before.st_mtimespec.tv_sec == named.st_mtimespec.tv_sec,
                  before.st_mtimespec.tv_nsec == named.st_mtimespec.tv_nsec,
                  before.st_ctimespec.tv_sec == named.st_ctimespec.tv_sec,
                  before.st_ctimespec.tv_nsec == named.st_ctimespec.tv_nsec,
                  file == file.resolvingSymlinksInPath() else { throw Failure.fixture }
            try check(); return data
        }
        func write<T: Encodable>(_ value: T, named name: String) throws {
            try check()
            guard !name.contains("/"), name.hasSuffix(".json") else { throw Failure.destination }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let bytes = try encoder.encode(value)
            guard bytes.count <= ContentIndexLimits.maximumSerializedBytes else { throw Failure.persistence }
            let fd = Darwin.openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw Failure.destination }
            defer { Darwin.close(fd) }
            try bytes.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(fd, buffer.baseAddress?.advanced(by: offset), min(65_536, buffer.count - offset))
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw Failure.persistence }
                    offset += count
                }
            }
            guard Darwin.fsync(fd) == 0 else { throw Failure.persistence }
            var held = stat(), named = stat()
            guard Darwin.fstat(fd, &held) == 0, Darwin.fstatat(descriptor, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_size == bytes.count,
                  named.st_mode & S_IFMT == S_IFREG, named.st_nlink == 1, named.st_uid == Darwin.getuid(),
                  Darwin.fsync(descriptor) == 0 else { throw Failure.persistence }
            try check()
        }
        func close() { if !closed { closed = true; Darwin.close(descriptor) } }
        deinit { close() }
    }
    private struct FileState: Equatable {
        let device: dev_t; let inode: ino_t; let bytes: Int64
        let modifiedSeconds: Int; let modifiedNanoseconds: Int; let changedSeconds: Int; let changedNanoseconds: Int
        static func inspect(_ url: URL) throws -> Self {
            guard url == url.resolvingSymlinksInPath() else { throw Failure.fixture }
            let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw Failure.fixture }
            defer { Darwin.close(fd) }
            var held = stat(), named = stat()
            guard Darwin.fstat(fd, &held) == 0, Darwin.lstat(url.path, &named) == 0,
                  held.st_mode & S_IFMT == S_IFREG, held.st_uid == Darwin.getuid(), held.st_nlink == 1,
                  held.st_dev == named.st_dev, held.st_ino == named.st_ino,
                  held.st_size == named.st_size, held.st_mtimespec.tv_sec == named.st_mtimespec.tv_sec,
                  held.st_mtimespec.tv_nsec == named.st_mtimespec.tv_nsec,
                  held.st_ctimespec.tv_sec == named.st_ctimespec.tv_sec,
                  held.st_ctimespec.tv_nsec == named.st_ctimespec.tv_nsec else { throw Failure.fixture }
            return Self(device: held.st_dev, inode: held.st_ino, bytes: held.st_size,
                modifiedSeconds: held.st_mtimespec.tv_sec, modifiedNanoseconds: held.st_mtimespec.tv_nsec,
                changedSeconds: held.st_ctimespec.tv_sec, changedNanoseconds: held.st_ctimespec.tv_nsec)
        }
    }
}
