import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Verified transactional batch extraction")
struct BatchExtractionTests {
    @Test("Colliding names, deleted entries and named streams retain exact verified bytes")
    func completeExport() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files = [
            fixture.file(id: "first", path: "/one/หลักฐาน.txt", payload: Data("first ภาษาไทย\n".utf8)),
            fixture.file(id: "second", path: "/two/หลักฐาน.txt", payload: Data([0, 0xff, 0x41]), deleted: true),
            fixture.file(id: "stream", path: "/folder:directory-note", payload: Data("stream".utf8), attributeType: 128, attributeID: 3),
            fixture.file(id: "empty", path: "/empty", payload: Data())
        ]
        let payloads = Dictionary(uniqueKeysWithValues: zip(files.map(\.id), [
            Data("first ภาษาไทย\n".utf8), Data([0, 0xff, 0x41]), Data("stream".utf8), Data()
        ]))
        let analysis = fixture.analysis(files: files, hashLogicalImage: true)
        let calls = BatchExtractionCalls()
        let service = FilesystemBatchExportService(extract: { paths, file, output, options, hashes in
            await calls.record(file.id)
            #expect(paths.map(\.path) == analysis.sourcePaths)
            #expect(hashes == analysis.sourceFileHashes)
            #expect(options.timezone == analysis.options.timezone)
            #expect(!options.hashLogicalImage)
            let permissions = try FileManager.default.attributesOfItem(atPath: output.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber
            #expect(permissions?.intValue == 0o700)
            return try BatchExtractionFixture.write(try #require(payloads[file.id]), to: output)
        })
        let exported = try await service.export(analysis: analysis, files: files, to: fixture.destination, caseURL: nil, progress: { _ in })
        #expect(exported.status == .completed)
        #expect(exported.requestedCount == 4 && exported.successfulCount == 4 && exported.failedCount == 0)
        #expect(exported.entries.map(\.sourceFile) == files)
        #expect(exported.destinationPath == fixture.destination.path)
        let names = try exported.entries.map { try #require($0.outputFilename) }
        #expect(Set(names).count == 4)
        for (entry, name) in zip(exported.entries, names) {
            #expect(name == URL(fileURLWithPath: name).lastPathComponent)
            #expect(!name.contains("/") && !name.contains("\\") && name != "." && name != "..")
            let payload = try #require(payloads[entry.sourceFile.id])
            #expect(try Data(contentsOf: fixture.destination.appendingPathComponent(name)) == payload)
            #expect(entry.byteCount == Int64(payload.count))
            #expect(entry.sha256 == BatchExtractionFixture.hash(payload))
            #expect(entry.errorMessage == nil)
        }
        let manifestURL = URL(fileURLWithPath: exported.manifestPath)
        #expect(manifestURL.deletingLastPathComponent() == fixture.destination)
        let manifest = try JSONDecoder().decode(FilesystemBatchExportResult.self, from: Data(contentsOf: manifestURL))
        #expect(manifest.status == .completed)
        #expect(manifest.entries.map(\.sourceFile) == files)
        #expect(manifest.entries.map(\.sha256) == exported.entries.map(\.sha256))
        #expect(manifest.schemaVersion == 1)
        #expect(manifest.sourcePaths == analysis.sourcePaths)
        #expect(manifest.sourceFileHashes == analysis.sourceFileHashes)
        #expect(manifest.engineVersion == analysis.engineVersion)
        #expect(manifest.patchDigest == analysis.patchDigest)
        #expect(manifest.analysisSavedAt == analysis.savedAt)
        #expect(manifest.evidenceTimezone == analysis.options.timezone)
        #expect(manifest.extractionHelperSha256 == nil)
        let wire = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any])
        #expect(wire["analysisEngineVersion"] as? String == analysis.engineVersion)
        #expect(wire["analysisPatchDigest"] as? String == analysis.patchDigest)
        #expect(wire["engineVersion"] == nil && wire["patchDigest"] == nil)
        #expect(await calls.ids == files.map(\.id))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try fixture.childNames() == ["export", "synthetic.dd"])
    }

    @Test("A recoverable unavailable file produces a partial manifest and later files still extract")
    func partialExport() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files = (1...3).map { fixture.file(id: "file-\($0)", path: "/\($0).txt") }
        let calls = BatchExtractionCalls()
        let service = FilesystemBatchExportService(extract: { _, file, output, _, _ in
            await calls.record(file.id)
            if file.id == "file-2" { throw EngineError.helperFailed("synthetic unavailable") }
            return try BatchExtractionFixture.write(Data("abc".utf8), to: output)
        })
        let exported = try await service.export(analysis: fixture.analysis(files: files), files: files,
            to: fixture.destination, caseURL: nil, progress: { _ in })
        #expect(exported.status == .partial)
        #expect(exported.requestedCount == 3 && exported.successfulCount == 2 && exported.failedCount == 1)
        #expect(await calls.ids == files.map(\.id))
        let failed = try #require(exported.entries.first { $0.sourceFile.id == "file-2" })
        #expect(failed.outputFilename == nil && failed.sha256 == nil && failed.byteCount == nil)
        #expect(failed.errorMessage?.contains("synthetic unavailable") == true)
        let manifest = try JSONDecoder().decode(FilesystemBatchExportResult.self,
            from: Data(contentsOf: URL(fileURLWithPath: exported.manifestPath)))
        #expect(manifest.status == .partial && manifest.failedCount == 1)
        #expect(manifest.entries.count == 3)
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.destination.path).count == 3)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Existing directories, files and dangling symlinks are never overwritten", arguments: ["directory", "file", "symlink"])
    func existingDestination(_ mode: String) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        if mode == "directory" {
            try FileManager.default.createDirectory(at: fixture.destination, withIntermediateDirectories: false)
            try Data("keep".utf8).write(to: fixture.destination.appendingPathComponent("keep"))
        } else if mode == "file" {
            try Data("keep".utf8).write(to: fixture.destination)
        } else {
            try FileManager.default.createSymbolicLink(at: fixture.destination,
                withDestinationURL: fixture.directory.appendingPathComponent("absent"))
        }
        let calls = BatchExtractionCalls()
        let service = fixture.service(calls: calls)
        let file = fixture.file()
        await #expect(throws: EngineError.self) {
            try await service.export(analysis: fixture.analysis(files: [file]), files: [file],
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        if mode == "directory" {
            #expect(try Data(contentsOf: fixture.destination.appendingPathComponent("keep")) == Data("keep".utf8))
        } else if mode == "file" {
            #expect(try Data(contentsOf: fixture.destination) == Data("keep".utf8))
        } else {
            #expect(try FileManager.default.destinationOfSymbolicLink(atPath: fixture.destination.path) == fixture.directory.appendingPathComponent("absent").path)
        }
        #expect(try fixture.childNames() == ["export", "synthetic.dd"])
    }

    @Test("A destination inside a case is rejected even through a directory alias", arguments: [false, true])
    func caseNamespace(_ alias: Bool) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let caseURL = fixture.directory.appendingPathComponent("Synthetic.nfcase", isDirectory: true)
        try FileManager.default.createDirectory(at: caseURL, withIntermediateDirectories: false)
        let marker = caseURL.appendingPathComponent("manifest.json")
        try Data("original case".utf8).write(to: marker)
        var parent = caseURL
        if alias {
            parent = fixture.directory.appendingPathComponent("case-alias")
            try FileManager.default.createSymbolicLink(at: parent, withDestinationURL: caseURL)
        }
        let destination = parent.appendingPathComponent("export", isDirectory: true)
        let file = fixture.file()
        let calls = BatchExtractionCalls()
        await #expect(throws: (any Error).self) {
            try await fixture.service(calls: calls).export(analysis: fixture.analysis(files: [file]), files: [file],
                to: destination, caseURL: caseURL, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try FileManager.default.contentsOfDirectory(atPath: caseURL.path) == ["manifest.json"])
        #expect(try Data(contentsOf: marker) == Data("original case".utf8))
    }

    @Test("A symlink destination parent cannot redirect publication")
    func symlinkParent() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let real = fixture.directory.appendingPathComponent("actual", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false)
        let alias = fixture.directory.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
        let file = fixture.file()
        let calls = BatchExtractionCalls()
        await #expect(throws: ForensicsError.self) {
            try await fixture.service(calls: calls).export(analysis: fixture.analysis(files: [file]), files: [file],
                to: alias.appendingPathComponent("export"), caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try FileManager.default.contentsOfDirectory(atPath: real.path).isEmpty)
    }

    @Test("A forged locator with a real identifier cannot escape the analysis snapshot")
    func forgedMembership() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let original = fixture.file()
        let forged = fixture.file(id: original.id, path: "/different-location.txt", metaAddress: 999)
        let calls = BatchExtractionCalls()
        await #expect(throws: EngineError.self) {
            try await fixture.service(calls: calls).export(analysis: fixture.analysis(files: [original]), files: [forged],
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try fixture.childNames() == ["synthetic.dd"])
    }

    @Test("Empty, repeated and directory selections are rejected before helper launch", arguments: ["empty", "duplicate", "directory"])
    func invalidSelections(_ mode: String) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let file = fixture.file(directory: mode == "directory")
        let selected = mode == "empty" ? [] : mode == "duplicate" ? [file, file] : [file]
        let calls = BatchExtractionCalls()
        await #expect(throws: EngineError.self) {
            try await fixture.service(calls: calls).export(analysis: fixture.analysis(files: [file]), files: selected,
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try fixture.childNames() == ["synthetic.dd"])
    }

    @Test("Count, per-file and aggregate size bounds fail without allocating outputs", arguments: ["count", "file-bytes", "total-bytes"])
    func limits(_ mode: String) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files: [FilesystemEntry]
        if mode == "count" {
            files = (0...FilesystemBatchExportService.maxFiles).map {
                fixture.file(id: "file-\($0)", path: "/\($0).txt")
            }
        } else if mode == "file-bytes" {
            files = [fixture.file(size: FilesystemBatchExportService.maxFileBytes + 1)]
        } else {
            files = (0..<4).map {
                fixture.file(id: "large-\($0)", path: "/\($0).bin", size: FilesystemBatchExportService.maxFileBytes)
            } + [fixture.file(id: "extra", path: "/extra.bin", size: 1)]
        }
        let calls = BatchExtractionCalls()
        await #expect(throws: EngineError.self) {
            try await fixture.service(calls: calls).export(analysis: fixture.analysis(files: files), files: files,
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try fixture.childNames() == ["synthetic.dd"])
    }

    @Test("Ordered multi-segment inputs and the complete hash scope reach every extraction")
    func orderedSourceScope() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let second = fixture.directory.appendingPathComponent("synthetic.dd.002")
        let secondBytes = Data("second segment".utf8)
        try secondBytes.write(to: second)
        let sources = [second, fixture.source]
        let hashes = [second.path: BatchExtractionFixture.hash(secondBytes), fixture.source.path: BatchExtractionFixture.hash(fixture.sourceBytes)]
        let file = fixture.file()
        let analysis = fixture.analysis(files: [file], sources: sources, hashes: hashes)
        let service = FilesystemBatchExportService(extract: { paths, _, output, _, expected in
            #expect(paths == sources)
            #expect(expected == hashes)
            return try BatchExtractionFixture.write(Data("abc".utf8), to: output)
        })
        let exported = try await service.export(analysis: analysis, files: [file], to: fixture.destination, caseURL: nil, progress: { _ in })
        #expect(exported.status == .completed)
        #expect(try Data(contentsOf: second) == secondBytes)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Incomplete, extra or invalid source hashes fail closed", arguments: ["missing", "extra", "malformed"])
    func invalidSourceHashScope(_ mode: String) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        var hashes = [fixture.source.path: BatchExtractionFixture.hash(fixture.sourceBytes)]
        if mode == "missing" { hashes = [:] }
        else if mode == "extra" { hashes[fixture.directory.appendingPathComponent("unselected.dd").path] = String(repeating: "a", count: 64) }
        else { hashes[fixture.source.path] = "not-a-sha256" }
        let file = fixture.file()
        let calls = BatchExtractionCalls()
        await #expect(throws: EngineError.self) {
            try await fixture.service(calls: calls).export(analysis: fixture.analysis(files: [file], hashes: hashes), files: [file],
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try fixture.childNames() == ["synthetic.dd"])
    }

    @Test("Changed source bytes are rejected before any helper call")
    func sourceChangedBeforeExport() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let file = fixture.file()
        let analysis = fixture.analysis(files: [file])
        try Data("different".utf8).write(to: fixture.source)
        let calls = BatchExtractionCalls()
        await #expect(throws: EngineError.sourceChanged) {
            try await fixture.service(calls: calls).export(analysis: analysis, files: [file],
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(await calls.ids.isEmpty)
        #expect(try fixture.childNames() == ["synthetic.dd"])
        #expect(try Data(contentsOf: fixture.source) == Data("different".utf8))
    }

    @Test("Source mutation during extraction discards a previously successful file")
    func sourceChangedDuringExport() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files = [fixture.file(id: "first"), fixture.file(id: "second", path: "/second.txt")]
        let analysis = fixture.analysis(files: files)
        let service = FilesystemBatchExportService(extract: { _, file, output, _, _ in
            let receipt = try BatchExtractionFixture.write(Data("abc".utf8), to: output)
            if file.id == "second" { try Data("changed in mock".utf8).write(to: fixture.source) }
            return receipt
        })
        await #expect(throws: EngineError.sourceChanged) {
            try await service.export(analysis: analysis, files: files, to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        #expect(try fixture.childNames() == ["synthetic.dd"])
        #expect(try Data(contentsOf: fixture.source) == Data("changed in mock".utf8))
    }

    @Test("Source mutation after one verified file prevents the next helper invocation")
    func sourceChangedBetweenExtractions() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files = [fixture.file(id: "first"), fixture.file(id: "second", path: "/second.txt")]
        let calls = BatchExtractionCalls()
        let analysis = fixture.analysis(files: files)
        await #expect(throws: EngineError.sourceChanged) {
            try await fixture.service(calls: calls).export(analysis: analysis, files: files,
                to: fixture.destination, caseURL: nil, progress: { progress in
                    if progress.completedFiles == 1 {
                        try? Data("different".utf8).write(to: fixture.source)
                    }
                })
        }
        #expect(await calls.ids == ["first"])
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        #expect(try fixture.childNames() == ["synthetic.dd"])
        #expect(try Data(contentsOf: fixture.source) == Data("different".utf8))
    }

    @Test("Receipt path, size, digest and helper output symlink mismatches abort the entire export", arguments: ["path", "size", "hash", "symlink"])
    func receiptMismatch(_ mode: String) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files = [fixture.file(id: "first"), fixture.file(id: "second", path: "/second.txt")]
        let service = FilesystemBatchExportService(extract: { _, file, output, _, _ in
            if file.id == "first" { return try BatchExtractionFixture.write(Data("abc".utf8), to: output) }
            if mode == "symlink" {
                try FileManager.default.createSymbolicLink(at: output, withDestinationURL: fixture.source)
            } else {
                try Data("abc".utf8).write(to: output, options: .withoutOverwriting)
            }
            return ExtractionResult(outputPath: mode == "path" ? fixture.source.path : output.path,
                byteCount: mode == "size" ? 2 : 3,
                sha256: mode == "hash" ? String(repeating: "0", count: 64) : BatchExtractionFixture.hash(Data("abc".utf8)))
        })
        await #expect(throws: (any Error).self) {
            try await service.export(analysis: fixture.analysis(files: files), files: files,
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        // An unclaimed symbolic-link leaf may be retained for ownership safety,
        // but a completed file from this job cannot remain as a final export.
        if mode != "symlink" { #expect(try fixture.childNames() == ["synthetic.dd"]) }
    }

    @Test("Cancellation cleans owned successes and never publishes a manifest")
    func cancellationCleanup() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let files = [fixture.file(id: "first"), fixture.file(id: "second", path: "/second.txt")]
        let calls = BatchExtractionCalls()
        let service = FilesystemBatchExportService(extract: { _, file, output, _, _ in
            await calls.record(file.id)
            if file.id == "second" { try await Task.sleep(for: .seconds(30)) }
            return try BatchExtractionFixture.write(Data("abc".utf8), to: output)
        })
        let task = Task {
            do {
                let result = try await service.export(analysis: fixture.analysis(files: files), files: files,
                    to: fixture.destination, caseURL: nil, progress: { _ in })
                await calls.finished()
                return result
            } catch {
                await calls.finished()
                throw error
            }
        }
        #expect(await calls.waitForCall("second"))
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        #expect(try fixture.childNames() == ["synthetic.dd"])
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("An unrelated stage leaf survives fatal cleanup")
    func preserveUnknownStageContent() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let file = fixture.file()
        let captured = BatchExtractionPath()
        let service = FilesystemBatchExportService(extract: { _, _, output, _, _ in
            let unrelated = output.deletingLastPathComponent().appendingPathComponent("unrelated-content")
            try Data("preserve unrelated".utf8).write(to: unrelated)
            await captured.record(unrelated)
            throw EngineError.protocolViolation("synthetic malformed receipt")
        })
        await #expect(throws: EngineError.self) {
            try await service.export(analysis: fixture.analysis(files: [file]), files: [file],
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        let unrelated = try #require(await captured.url)
        #expect(try Data(contentsOf: unrelated) == Data("preserve unrelated".utf8))
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Publication cannot replace a directory created after extraction begins")
    func lateDestinationCollision() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let file = fixture.file()
        let marker = fixture.destination.appendingPathComponent("keep")
        let service = FilesystemBatchExportService(extract: { _, _, output, _, _ in
            let receipt = try BatchExtractionFixture.write(Data("abc".utf8), to: output)
            try FileManager.default.createDirectory(at: fixture.destination, withIntermediateDirectories: false)
            try Data("created by another owner".utf8).write(to: marker)
            return receipt
        })
        await #expect(throws: EngineError.self) {
            try await service.export(analysis: fixture.analysis(files: [file]), files: [file],
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(try Data(contentsOf: marker) == Data("created by another owner".utf8))
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.destination.path) == ["keep"])
        #expect(try fixture.childNames() == ["export", "synthetic.dd"])
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Replacing a stage or destination parent cannot publish or delete the replacement", arguments: ["stage", "parent"])
    func directoryReplacement(_ mode: String) async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let parent = fixture.directory.appendingPathComponent("export-parent", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        let destination = parent.appendingPathComponent("export", isDirectory: true)
        let originalParentMarker = parent.appendingPathComponent("unrelated-parent-marker")
        try Data("preserve original parent".utf8).write(to: originalParentMarker)
        let replacementMarker = BatchExtractionPath()
        let heldDirectory = BatchExtractionPath()
        let files = [fixture.file(id: "first"), fixture.file(id: "second", path: "/second.txt")]
        let service = FilesystemBatchExportService(extract: { _, file, output, _, _ in
            let receipt = try BatchExtractionFixture.write(Data("abc".utf8), to: output)
            if file.id == "second" {
                let original = mode == "stage" ? output.deletingLastPathComponent() : parent
                let held = original.appendingPathExtension("held")
                try FileManager.default.moveItem(at: original, to: held)
                await heldDirectory.record(held)
                try FileManager.default.createDirectory(at: original, withIntermediateDirectories: false)
                let marker = original.appendingPathComponent("unrelated-replacement-marker")
                try Data("preserve replacement".utf8).write(to: marker)
                await replacementMarker.record(marker)
            }
            return receipt
        })
        await #expect(throws: (any Error).self) {
            try await service.export(analysis: fixture.analysis(files: files), files: files,
                to: destination, caseURL: nil, progress: { _ in })
        }
        let marker = try #require(await replacementMarker.url)
        let held = try #require(await heldDirectory.url)
        #expect(try Data(contentsOf: marker) == Data("preserve replacement".utf8))
        #expect(!FileManager.default.fileExists(atPath: destination.path))
        if mode == "parent" {
            #expect(try Data(contentsOf: held.appendingPathComponent("unrelated-parent-marker")) == Data("preserve original parent".utf8))
            #expect(!FileManager.default.fileExists(atPath: held.appendingPathComponent("export").path))
        } else {
            #expect(try Data(contentsOf: originalParentMarker) == Data("preserve original parent".utf8))
        }
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Changing an earlier extracted file before publication invalidates the whole batch")
    func earlierOutputMutation() async throws {
        let fixture = try BatchExtractionFixture()
        defer { fixture.remove() }
        let firstOutput = BatchExtractionPath()
        let files = [fixture.file(id: "first"), fixture.file(id: "second", path: "/second.txt")]
        let service = FilesystemBatchExportService(extract: { _, file, output, _, _ in
            let receipt = try BatchExtractionFixture.write(Data("abc".utf8), to: output)
            if file.id == "first" { await firstOutput.record(output) }
            else {
                let first = try #require(await firstOutput.url)
                // Same byte length makes a size-only recheck insufficient.
                try Data("xyz".utf8).write(to: first)
            }
            return receipt
        })
        await #expect(throws: (any Error).self) {
            try await service.export(analysis: fixture.analysis(files: files), files: files,
                to: fixture.destination, caseURL: nil, progress: { _ in })
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }
}

private actor BatchExtractionCalls {
    private(set) var ids: [String] = []
    private var waiters: [String: [CheckedContinuation<Bool, Never>]] = [:]
    private var hasFinished = false

    func record(_ id: String) {
        ids.append(id)
        for waiter in waiters.removeValue(forKey: id) ?? [] { waiter.resume(returning: true) }
    }

    func waitForCall(_ id: String) async -> Bool {
        if ids.contains(id) { return true }
        if hasFinished { return false }
        return await withCheckedContinuation { continuation in
            waiters[id, default: []].append(continuation)
        }
    }

    func finished() {
        hasFinished = true
        let pending = waiters.values.flatMap { $0 }
        waiters.removeAll()
        for waiter in pending { waiter.resume(returning: false) }
    }
}

private actor BatchExtractionPath {
    private(set) var url: URL?
    func record(_ url: URL) { self.url = url }
}

private struct BatchExtractionFixture: Sendable {
    let directory: URL
    let source: URL
    let sourceBytes = Data("abc".utf8)
    var destination: URL { directory.appendingPathComponent("export", isDirectory: true) }

    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("BatchExtractionTests-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        source = directory.appendingPathComponent("synthetic.dd")
        try sourceBytes.write(to: source)
    }

    func file(id: String = "first", path: String = "/HELLO.TXT", payload: Data? = nil, size: Int64? = nil,
        deleted: Bool = false, directory: Bool = false, metaAddress: UInt64 = 1,
        attributeType: Int32? = nil, attributeID: Int32? = nil) -> FilesystemEntry {
        FilesystemEntry(id: id, path: path, name: URL(fileURLWithPath: path).lastPathComponent,
            fsOffsetBytes: 0, metaAddress: metaAddress, attributeType: attributeType, attributeID: attributeID,
            size: size ?? Int64(payload?.count ?? 3), isDirectory: directory, isDeleted: deleted,
            modifiedEpoch: 1_700_000_000)
    }

    func analysis(files: [FilesystemEntry], sources: [URL]? = nil, hashes: [String: String]? = nil,
        hashLogicalImage: Bool = false) -> EnumerationResult {
        let sources = sources ?? [source]
        return EnumerationResult(engineVersion: "synthetic-batch", patchDigest: "synthetic-only",
            sourcePaths: sources.map(\.path), sourceFileHashes: hashes ?? [source.path: Self.hash(sourceBytes)],
            options: EngineOptions(timezone: "Asia/Bangkok", hashLogicalImage: hashLogicalImage),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512,
                logicalSha256: hashLogicalImage ? Self.hash(sourceBytes) : nil, imagePaths: sources.map(\.path)),
            volumes: [], files: files, warnings: [], status: .completed)
    }

    func service(calls: BatchExtractionCalls) -> FilesystemBatchExportService {
        FilesystemBatchExportService(extract: { _, file, output, _, _ in
            await calls.record(file.id)
            return try Self.write(Data("abc".utf8), to: output)
        })
    }

    func childNames() throws -> [String] { try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    static func write(_ payload: Data, to output: URL) throws -> ExtractionResult {
        try payload.write(to: output, options: .withoutOverwriting)
        return ExtractionResult(outputPath: output.path, byteCount: Int64(payload.count), sha256: hash(payload))
    }
}
