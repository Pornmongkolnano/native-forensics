import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("ForensicsCoreTests")
struct ForensicsCoreTests {
    @Test("SHA-256 of known bytes and empty files")
    func knownHashes() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let abc = try directory.write("sample.dd", bytes: Data("abc".utf8))
        let empty = try directory.write("empty.img", bytes: Data())
        let inspectedABC = try await ImageInspector.inspect(url: abc, progress: { _ in })
        let inspectedEmpty = try await ImageInspector.inspect(url: empty, progress: { _ in })
        #expect(inspectedABC.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(inspectedABC.byteCount == 3)
        #expect(inspectedEmpty.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        #expect(inspectedEmpty.byteCount == 0)
        #expect(inspectedABC.hashScope == "selected-file-bytes")
    }

    @Test("Streaming crosses chunk boundaries and leaves source unchanged")
    func largeFileAndReadOnly() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        var bytes = Data()
        let pattern = Data((0...255).map(UInt8.init))
        for _ in 0..<12_288 { bytes.append(pattern) }
        bytes.append(contentsOf: (0..<17).map(UInt8.init))
        let source = try directory.write("large raw image.dd", bytes: bytes)
        let before = try FileAccess.identity(at: source)
        let progress = ProgressRecorder()
        let result = try await ImageInspector.inspect(url: source, progress: { progress.append($0) })
        #expect(result.byteCount == 3_145_745)
        #expect(result.sha256 == "69112280f593fd44684d97d3fe42cdcb84da4ae495d8e1db649f06c3596a7ce6")
        #expect(try Data(contentsOf: source) == bytes)
        #expect(try FileAccess.identity(at: source) == before)
        let updates = progress.values
        #expect(updates.first?.bytesRead == 0)
        #expect(updates.last?.bytesRead == result.byteCount)
        #expect(updates.last?.fraction == 1)
        #expect(updates.allSatisfy { $0.totalBytes == result.byteCount && (0...1).contains($0.fraction) })
        #expect(zip(updates, updates.dropFirst()).allSatisfy { $0.bytesRead <= $1.bytesRead })
    }

    @Test("EWF hash explicitly covers only the selected container file")
    func containerScopeAndSignatures() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        var ewf = Data([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00])
        ewf.append(Data("synthetic EWF header; not a valid disk image".utf8))
        let first = try directory.write("disk.E01", bytes: ewf)
        let second = try directory.write("disk.E02", bytes: Data("another segment".utf8))
        let inspected = try await ImageInspector.inspect(url: first, progress: { _ in })
        #expect(inspected.container == .ewf)
        #expect(inspected.byteCount == ewf.count)
        #expect(inspected.filesystemHint == nil)
        #expect(inspected.hashScope == FileHashScope.selectedFileBytes)
        #expect(try Data(contentsOf: second) == Data("another segment".utf8))
        let badExtension = try directory.write("not-ewf.E01", bytes: Data("abc".utf8))
        let unknown = try await ImageInspector.inspect(url: badExtension, progress: { _ in })
        #expect(unknown.container == .unknown)
        var fat = Data(repeating: 0, count: 512)
        fat.replaceSubrange(54..<62, with: Data("FAT16   ".utf8))
        let hinted = try directory.write("signature.bin", bytes: fat)
        let hintedResult = try await ImageInspector.inspect(url: hinted, progress: { _ in })
        #expect(hintedResult.container == .raw)
        #expect(hintedResult.filesystemHint == "FAT16 boot-sector signature")
    }

    @Test("Only regular local files are inspected")
    func invalidSources() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        await #expect(throws: ForensicsError.invalidFileURL) {
            try await ImageInspector.inspect(url: URL(string: "https://example.invalid/disk.dd")!, progress: { _ in })
        }
        await #expect(throws: ForensicsError.invalidFileURL) {
            try await ImageInspector.inspect(url: URL(string: "file://remote.invalid/disk.dd")!, progress: { _ in })
        }
        await #expect(throws: ForensicsError.self) {
            try await ImageInspector.inspect(url: directory.url, progress: { _ in })
        }
        await #expect(throws: ForensicsError.self) {
            try await ImageInspector.inspect(url: directory.url.appendingPathComponent("missing.dd"), progress: { _ in })
        }
        let fifo = directory.url.appendingPathComponent("pipe.dd")
        #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
        await #expect(throws: ForensicsError.self) {
            try await ImageInspector.inspect(url: fifo, progress: { _ in })
        }
    }

    @Test("Source symlinks resolve to one canonical source path")
    func canonicalSource() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("actual.dd", bytes: Data("abc".utf8))
        let alias = directory.url.appendingPathComponent("alias.dd")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: source)
        let image = try await ImageInspector.inspect(url: alias, progress: { _ in })
        #expect(image.sourceURL == source.resolvingSymlinksInPath())
    }

    @Test("File mutation during hashing rejects the result")
    func mutationDuringHashing() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("changing.dd", bytes: Data(repeating: 42, count: 2048))
        await #expect(throws: ForensicsError.sourceChanged) {
            try await ImageInspector.inspect(url: source, progress: { update in
                if update.bytesRead == 0 {
                    let handle = try? FileHandle(forWritingTo: source)
                    _ = try? handle?.seekToEnd()
                    try? handle?.write(contentsOf: Data([99]))
                    try? handle?.close()
                }
            })
        }
    }

    @Test("Replacing the source path during hashing rejects the result")
    func replacedSourceDuringHashing() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("replaced.dd", bytes: Data(repeating: 17, count: 2048))
        let backup = directory.url.appendingPathComponent("original.dd")
        await #expect(throws: ForensicsError.sourceChanged) {
            try await ImageInspector.inspect(url: source, progress: { update in
                if update.bytesRead > 0 {
                    try? FileManager.default.moveItem(at: source, to: backup)
                    try? Data(repeating: 23, count: 2048).write(to: source)
                }
            })
        }
        #expect(try Data(contentsOf: backup) == Data(repeating: 17, count: 2048))
    }

    @Test("Cancellation before inspection propagates")
    func cancellationBeforeInspection() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("cancel.dd", bytes: Data("abc".utf8))
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await ImageInspector.inspect(url: source, progress: { _ in })
        }
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("Cancellation while the worker is reading propagates")
    func cancellationDuringInspection() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("cancel active.dd", bytes: Data(repeating: 0x55, count: 2_100_000))
        let reachedProgress = DispatchSemaphore(value: 0)
        let resume = DispatchSemaphore(value: 0)
        let task = Task {
            try await ImageInspector.inspect(url: source, progress: { update in
                if update.bytesRead > 0 {
                    reachedProgress.signal()
                    _ = resume.wait(timeout: .now() + 10)
                }
            })
        }
        let reached = await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                continuation.resume(returning: reachedProgress.wait(timeout: .now() + 10) == .success)
            }
        }
        #expect(reached)
        task.cancel()
        resume.signal()
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("Case JSON roundtrip and evidence persistence")
    func roundtrip() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("source.dd", bytes: Data("abc".utf8))
        let sourceBefore = try FileAccess.identity(at: source)
        let original = try CaseStore.create(name: "Investigation 01", in: directory.url)
        #expect(original.bundleURL.lastPathComponent == "Investigation 01.nativecase")
        #expect(original.manifest.evidence.isEmpty)
        #expect(try CaseStore.open(at: original.bundleURL).manifest == original.manifest)
        let image = try await ImageInspector.inspect(url: source, progress: { _ in })
        let updated = try CaseStore.adding(image: image, to: original)
        let reopened = try CaseStore.open(at: updated.bundleURL)
        #expect(reopened.manifest == updated.manifest)
        let caseDTO = try JSONDecoder().decode(ForensicCase.self, from: JSONEncoder().encode(updated))
        #expect(caseDTO.bundleURL == updated.bundleURL)
        #expect(caseDTO.manifest == updated.manifest)
        #expect(reopened.manifest.id == original.manifest.id)
        #expect(reopened.manifest.createdAt == original.manifest.createdAt)
        let record = try #require(reopened.manifest.evidence.first)
        #expect(record.sourcePath == source.resolvingSymlinksInPath().path)
        #expect(record.sha256 == image.sha256)
        #expect(record.hashScope == FileHashScope.selectedFileBytes)
        #expect(record.byteCount == 3)
        #expect(try FileAccess.identity(at: source) == sourceBefore)
        #expect(try Data(contentsOf: source) == Data("abc".utf8))
        let manifestData = try Data(contentsOf: updated.bundleURL.appendingPathComponent("manifest.json"))
        let json = try #require(JSONSerialization.jsonObject(with: manifestData) as? [String: Any])
        #expect(json["createdAt"] is String)
        #expect(json["schemaVersion"] as? Int == 1)
        let files = try FileManager.default.contentsOfDirectory(atPath: updated.bundleURL.path)
        #expect(Set(files) == ["manifest.json", ".case.lock"])
    }

    @Test("Invalid names and existing destinations cannot overwrite data")
    func nameAndOverwriteValidation() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        for name in ["", " ", ".", "..", "../escaped", "a/b", "a\\b", "bad:name", "line\nbreak", "last.", String(repeating: "x", count: 101)] {
            #expect(throws: ForensicsError.invalidCaseName) { try CaseStore.create(name: name, in: directory.url) }
        }
        let forensicCase = try CaseStore.create(name: "Original", in: directory.url)
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let before = try Data(contentsOf: manifestURL)
        #expect(throws: ForensicsError.caseAlreadyExists) { try CaseStore.create(name: "Original", in: directory.url) }
        #expect(try Data(contentsOf: manifestURL) == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path) == ["Original.nativecase"])
        #expect(throws: ForensicsError.self) {
            try CaseStore.create(name: "Valid", in: URL(string: "https://example.invalid/")!)
        }
    }

    @Test("Duplicate paths and stale snapshots cannot drop evidence")
    func duplicateAndStaleUpdate() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source1 = try directory.write("one.dd", bytes: Data("one".utf8))
        let source2 = try directory.write("two.dd", bytes: Data("two".utf8))
        let image1 = try await ImageInspector.inspect(url: source1, progress: { _ in })
        let image2 = try await ImageInspector.inspect(url: source2, progress: { _ in })
        let original = try CaseStore.create(name: "Transactions", in: directory.url)
        let updated = try CaseStore.adding(image: image1, to: original)
        #expect(throws: ForensicsError.duplicateEvidence) { try CaseStore.adding(image: image1, to: updated) }
        #expect(throws: ForensicsError.staleCase) { try CaseStore.adding(image: image2, to: original) }
        let final = try CaseStore.adding(image: image2, to: updated)
        #expect(final.manifest.evidence.count == 2)
        #expect(try CaseStore.open(at: original.bundleURL).manifest == final.manifest)
    }

    @Test("Same-sized source edits after hashing cannot be recorded")
    func sourceChangedBeforeSave() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("source.dd", bytes: Data("abc".utf8))
        let image = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.create(name: "Changes", in: directory.url)
        try Data("def".utf8).write(to: source)
        #expect(throws: ForensicsError.sourceChanged) { try CaseStore.adding(image: image, to: forensicCase) }
        #expect(try CaseStore.open(at: forensicCase.bundleURL).manifest.evidence.isEmpty)
    }

    @Test("Decoded or manually constructed inspection DTOs require reinspection")
    func inspectionProvenance() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let source = try directory.write("source.dd", bytes: Data("abc".utf8))
        let image = try await ImageInspector.inspect(url: source, progress: { _ in })
        let decoded = try JSONDecoder().decode(InspectedImage.self, from: JSONEncoder().encode(image))
        #expect(decoded.sha256 == image.sha256)
        #expect(decoded.sourceURL == image.sourceURL)
        let forensicCase = try CaseStore.create(name: "Provenance", in: directory.url)
        #expect(throws: ForensicsError.self) { try CaseStore.adding(image: decoded, to: forensicCase) }
        let manual = InspectedImage(sourceURL: source, byteCount: 3, sha256: image.sha256, container: .raw, filesystemHint: nil)
        #expect(throws: ForensicsError.self) { try CaseStore.adding(image: manual, to: forensicCase) }
        let reinspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        #expect(try CaseStore.adding(image: reinspected, to: forensicCase).manifest.evidence.count == 1)
    }

    @Test("Evidence inside the output case is rejected")
    func outputBoundary() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let forensicCase = try CaseStore.create(name: "Boundary", in: directory.url)
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let manifestBefore = try Data(contentsOf: manifestURL)
        let image = try await ImageInspector.inspect(url: manifestURL, progress: { _ in })
        #expect(throws: ForensicsError.self) { try CaseStore.adding(image: image, to: forensicCase) }
        #expect(try Data(contentsOf: manifestURL) == manifestBefore)
    }

    @Test("Case open rejects corrupted or symlinked manifests")
    func corruptedCase() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let forensicCase = try CaseStore.create(name: "Corruption", in: directory.url)
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        try Data("{}".utf8).write(to: manifestURL)
        #expect(throws: ForensicsError.self) { try CaseStore.open(at: forensicCase.bundleURL) }
        try FileManager.default.removeItem(at: manifestURL)
        let external = try directory.write("outside.json", bytes: Data("{}".utf8))
        try FileManager.default.createSymbolicLink(at: manifestURL, withDestinationURL: external)
        #expect(throws: ForensicsError.self) { try CaseStore.open(at: forensicCase.bundleURL) }
        #expect(try Data(contentsOf: external) == Data("{}".utf8))
        let caseAlias = directory.url.appendingPathComponent("alias.nativecase")
        try FileManager.default.createSymbolicLink(at: caseAlias, withDestinationURL: forensicCase.bundleURL)
        #expect(throws: ForensicsError.self) { try CaseStore.open(at: caseAlias) }
    }

    @Test("Concurrent writers serialize and one stale update is rejected")
    func concurrentUpdates() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let first = try directory.write("one.dd", bytes: Data("one".utf8))
        let second = try directory.write("two.dd", bytes: Data("two".utf8))
        let image1 = try await ImageInspector.inspect(url: first, progress: { _ in })
        let image2 = try await ImageInspector.inspect(url: second, progress: { _ in })
        let original = try CaseStore.create(name: "Concurrency", in: directory.url)
        let firstUpdate = Task.detached { Result { try CaseStore.adding(image: image1, to: original) } }
        let secondUpdate = Task.detached { Result { try CaseStore.adding(image: image2, to: original) } }
        let results = await [firstUpdate.value, secondUpdate.value]
        let successes = results.compactMap { try? $0.get() }
        let errors = results.compactMap { result -> ForensicsError? in
            if case .failure(let error) = result { return error as? ForensicsError }
            return nil
        }
        #expect(successes.count == 1)
        #expect(errors == [.staleCase])
        #expect(try CaseStore.open(at: original.bundleURL).manifest.evidence.count == 1)
    }

    @Test("Unknown case schema versions are refused without modification")
    func unknownSchema() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let forensicCase = try CaseStore.create(name: "Future", in: directory.url)
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        var json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any])
        json["schemaVersion"] = 999
        let unsupported = try JSONSerialization.data(withJSONObject: json)
        try unsupported.write(to: manifestURL)
        #expect(throws: ForensicsError.self) { try CaseStore.open(at: forensicCase.bundleURL) }
        #expect(try Data(contentsOf: manifestURL) == unsupported)
    }

    @Test("Concurrent creation publishes one complete bundle without overwrite")
    func concurrentCreation() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let first = Task.detached { Result { try CaseStore.create(name: "Race", in: directory.url) } }
        let second = Task.detached { Result { try CaseStore.create(name: "Race", in: directory.url) } }
        let results = await [first.value, second.value]
        let successes = results.compactMap { try? $0.get() }
        let errors = results.compactMap { result -> ForensicsError? in
            if case .failure(let error) = result { return error as? ForensicsError }
            return nil
        }
        #expect(successes.count == 1)
        #expect(errors == [.caseAlreadyExists])
        let actual = try CaseStore.open(at: directory.url.appendingPathComponent("Race.nativecase"))
        #expect(actual.manifest == successes.first?.manifest)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path) == ["Race.nativecase"])
    }
}

private struct TemporaryDirectory: Sendable {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("NativeForensicsTests-\(UUID().uuidString)", isDirectory: true)
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    }

    func write(_ name: String, bytes: Data) throws -> URL {
        let result = url.appendingPathComponent(name)
        try bytes.write(to: result, options: .withoutOverwriting)
        return result
    }

    func remove() { try? FileManager.default.removeItem(at: url) }
}

private final class ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var updates: [InspectionProgress] = []

    func append(_ value: InspectionProgress) {
        lock.lock()
        defer { lock.unlock() }
        updates.append(value)
    }

    var values: [InspectionProgress] {
        lock.lock()
        defer { lock.unlock() }
        return updates
    }
}
