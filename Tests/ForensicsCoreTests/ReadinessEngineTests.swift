import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Engine readiness regressions")
struct ReadinessEngineTests {
    @Test("Live metadata must state every ordered source path", arguments: ["missing", "reversed"])
    func requiredLiveSourceScope(_ mode: String) async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let second = fixture.directory.appendingPathComponent("segment.002")
        try Data("def".utf8).write(to: second)
        let helper = try fixture.helper(body: """
        image = dict(imageType='raw', logicalSize=6, sectorSize=512, logicalSha256='\(ReadinessEngineFixture.abcHash)')
        if '\(mode)' == 'reversed':
            image['imagePaths'] = list(reversed(request['imagePaths']))
        emit('image', **image)
        emit('completed', fileCount=0)
        """)
        await #expect(throws: EngineError.self) {
            _ = try await EngineClient(helperURL: helper).enumerate(imagePaths: [fixture.source, second])
        }
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
        #expect(try Data(contentsOf: second) == Data("def".utf8))
    }

    @Test("Deadline requests cooperative cancellation before PID fallback")
    func deadlineCancellation() async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let marker = fixture.directory.appendingPathComponent("cooperative-cancel.txt")
        let helper = try fixture.helper(body: """
        emit('image', imageType='raw', logicalSize=3, sectorSize=512,
            imagePaths=request['imagePaths'], logicalSha256='\(ReadinessEngineFixture.abcHash)')
        cancel = json.loads(sys.stdin.readline())
        if cancel.get('operation') == 'cancel' and cancel.get('jobID') == request['jobID']:
            with open(\(ReadinessEngineFixture.literal(marker.path)), 'x') as output:
                output.write('cancel acknowledged')
        emit('cancelled', fileCount=0)
        sys.exit(2)
        """)
        let timeouts = EngineTimeouts(startup: 5, inactivity: 0.2, cancellationGrace: 1, terminationGrace: 0.1)
        await #expect(throws: EngineError.timeout("The native engine stopped reporting activity before its stage deadline.")) {
            _ = try await EngineClient(helperURL: helper, timeouts: timeouts).enumerate(imageURL: fixture.source)
        }
        #expect(FileManager.default.fileExists(atPath: marker.path))
    }

    @Test("Corrupted cache cannot remove a requested logical-image hash")
    func requiredCachedLogicalHash() async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let forensicCase = try await fixture.makeCase()
        let evidenceID = try #require(forensicCase.manifest.evidence.first?.id)
        let result = try fixture.result(hashLogicalImage: true, logicalHash: nil)
        #expect(throws: EngineError.self) {
            try EngineResultStore.save(result: result, evidenceID: evidenceID, in: forensicCase.bundleURL)
        }
        let valid = try fixture.result(hashLogicalImage: true, logicalHash: ReadinessEngineFixture.abcHash)
        try EngineResultStore.save(result: valid, evidenceID: evidenceID, in: forensicCase.bundleURL)
        let cache = forensicCase.bundleURL.appendingPathComponent("filesystem")
            .appendingPathComponent(evidenceID.uuidString.lowercased() + ".json")
        var json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: cache)) as? [String: Any])
        var image = try #require(json["image"] as? [String: Any])
        image.removeValue(forKey: "logicalSha256")
        json["image"] = image
        try JSONSerialization.data(withJSONObject: json).write(to: cache)
        #expect(throws: EngineError.self) {
            _ = try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL)
        }
    }

    @Test("Historic optional image-path metadata and explicitly skipped logical hashing remain readable")
    func legacyCacheScope() async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let forensicCase = try await fixture.makeCase()
        let evidenceID = try #require(forensicCase.manifest.evidence.first?.id)
        let result = try fixture.result(hashLogicalImage: false, logicalHash: nil)
        try EngineResultStore.save(result: result, evidenceID: evidenceID, in: forensicCase.bundleURL)
        let loaded = try #require(try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL))
        #expect(loaded.image.imagePaths == nil)
        #expect(loaded.image.logicalSha256 == nil)
        #expect(loaded.options.hashLogicalImage == false)
        #expect(loaded.sourceFileHashes[fixture.source.path] == ReadinessEngineFixture.abcHash)
    }

    @Test("Cache structural bounds apply even when bypassing the helper", arguments: ["volumes", "modified-nanoseconds", "changed-nanoseconds"])
    func cacheStructuralBounds(_ mode: String) async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let forensicCase = try await fixture.makeCase()
        let evidenceID = try #require(forensicCase.manifest.evidence.first?.id)
        let valid = try fixture.result(hashLogicalImage: true, logicalHash: ReadinessEngineFixture.abcHash)
        try EngineResultStore.save(result: valid, evidenceID: evidenceID, in: forensicCase.bundleURL)
        let cache = forensicCase.bundleURL.appendingPathComponent("filesystem")
            .appendingPathComponent(evidenceID.uuidString.lowercased() + ".json")
        var json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: cache)) as? [String: Any])
        if mode == "volumes" {
            json["volumes"] = (0..<4_097).map {
                ["id": "v\($0)", "offsetBytes": 0, "filesystem": "synthetic", "blockSize": 512, "blockCount": 1] as [String: Any]
            }
        } else {
            var identities = try #require(json["sourceIdentities"] as? [[String: Any]])
            identities[0][mode == "modified-nanoseconds" ? "modifiedNanoseconds" : "changedNanoseconds"] = mode == "modified-nanoseconds" ? -1 : 1_000_000_000
            json["sourceIdentities"] = identities
        }
        try JSONSerialization.data(withJSONObject: json).write(to: cache)
        #expect(throws: EngineError.self) {
            _ = try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL)
        }
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Two segment names cannot alias the same underlying file")
    func hardLinkedSources() async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let alias = fixture.directory.appendingPathComponent("alias.002")
        #expect(Darwin.link(fixture.source.path, alias.path) == 0)
        let marker = fixture.directory.appendingPathComponent("helper-ran.txt")
        let helper = try fixture.helper(body: """
        with open(\(ReadinessEngineFixture.literal(marker.path)), 'x') as output:
            output.write('unexpected launch')
        emit('image', imageType='raw', logicalSize=6, sectorSize=512,
            imagePaths=request['imagePaths'], logicalSha256='\(ReadinessEngineFixture.abcHash)')
        emit('completed', fileCount=0)
        """)
        await #expect(throws: EngineError.self) {
            _ = try await EngineClient(helperURL: helper).inspect(imagePaths: [fixture.source, alias])
        }
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    @Test("Cancellation and deadline reap extraction helper and remove staged bytes", arguments: [false, true])
    func abortedExtraction(_ deadline: Bool) async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let pidFile = fixture.directory.appendingPathComponent("owned-helper.pid")
        let output = fixture.directory.appendingPathComponent("must-not-publish.bin")
        let helper = try fixture.helper(body: """
        import os
        emit('image', imageType='raw', logicalSize=3, sectorSize=512,
            imagePaths=request['imagePaths'], logicalSha256='\(ReadinessEngineFixture.abcHash)')
        with open(request['outputPath'], 'xb') as staging:
            staging.write(b'abc')
        with open(\(ReadinessEngineFixture.literal(pidFile.path)), 'x') as marker:
            marker.write(str(os.getpid()))
        emit('progress', stage='waiting-for-cancel', completed=0, unit='files')
        cancel = json.loads(sys.stdin.readline())
        if cancel.get('operation') != 'cancel' or cancel.get('jobID') != request['jobID']:
            sys.exit(9)
        emit('cancelled', fileCount=0)
        sys.exit(2)
        """)
        let receivedProgress = ReadinessProgressFlag()
        let timeouts = EngineTimeouts(startup: 5, inactivity: deadline ? 0.3 : 5, cancellationGrace: 1, terminationGrace: 0.1)
        let task = Task {
            try await EngineClient(helperURL: helper, timeouts: timeouts).extract(
                imageURL: fixture.source,
                file: FilesystemEntry(id: "synthetic-file", path: "/file", name: "file", fsOffsetBytes: 0, metaAddress: 1, size: 3, isDirectory: false, isDeleted: false),
                outputURL: output,
                progress: { if $0.stage == "waiting-for-cancel" { receivedProgress.mark() } })
        }
        if deadline {
            await #expect(throws: EngineError.timeout("The native engine stopped reporting activity before its stage deadline.")) {
                _ = try await task.value
            }
        } else {
            for _ in 0..<500 where !receivedProgress.value { try await Task.sleep(for: .milliseconds(10)) }
            #expect(receivedProgress.value)
            task.cancel()
            await #expect(throws: CancellationError.self) { _ = try await task.value }
        }
        let pid = try #require(Int32(try String(contentsOf: pidFile, encoding: .utf8)))
        #expect(Darwin.kill(pid, 0) == -1)
        #expect(errno == ESRCH)
        #expect(!FileManager.default.fileExists(atPath: output.path))
        #expect(!(try FileManager.default.contentsOfDirectory(atPath: fixture.directory.path)).contains(where: { $0.hasPrefix(".native-extract-") }))
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Malformed shutdown output cannot turn an explicit user cancellation into failure")
    func cancellationErrorPrecedence() async throws {
        let fixture = try ReadinessEngineFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        emit('image', imageType='raw', logicalSize=3, sectorSize=512,
            imagePaths=request['imagePaths'], logicalSha256='\(ReadinessEngineFixture.abcHash)')
        emit('progress', stage='waiting-for-cancel', completed=0, unit='files')
        json.loads(sys.stdin.readline())
        sys.stdout.write('{malformed}\\n')
        sys.stdout.flush()
        """)
        let receivedProgress = ReadinessProgressFlag()
        let task = Task {
            try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source,
                progress: { if $0.stage == "waiting-for-cancel" { receivedProgress.mark() } })
        }
        for _ in 0..<500 where !receivedProgress.value { try await Task.sleep(for: .milliseconds(10)) }
        #expect(receivedProgress.value)
        task.cancel()
        await #expect(throws: CancellationError.self) { _ = try await task.value }
    }
}

private final class ReadinessProgressFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var received = false
    func mark() { lock.lock(); received = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return received }
}

private struct ReadinessEngineFixture {
    static let abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    let directory: URL
    let source: URL

    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("ReadinessEngine-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        source = directory.appendingPathComponent("synthetic.dd")
        try Data("abc".utf8).write(to: source, options: .withoutOverwriting)
    }

    func helper(body: String) throws -> URL {
        let helper = directory.appendingPathComponent("synthetic-helper.py")
        let script = """
        #!/usr/bin/python3
        import json, sys
        request = json.loads(sys.stdin.readline())
        sequence = 0
        def emit(kind, **values):
            global sequence
            frame = dict(protocolVersion=1, jobID=request['jobID'], sequence=sequence, type=kind)
            frame.update(values)
            sequence += 1
            print(json.dumps(frame), flush=True)
        emit('hello', engineVersion='readiness-test', patchDigest='synthetic-only', capabilities=['raw'])
        \(body)
        """
        try Data(script.utf8).write(to: helper, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        return helper
    }

    func result(hashLogicalImage: Bool, logicalHash: String?) throws -> EnumerationResult {
        EnumerationResult(engineVersion: "readiness-test", patchDigest: "synthetic-only",
            sourcePaths: [source.path],
            sourceIdentities: [EngineSourceIdentity(path: source.path, identity: try FileAccess.identity(at: source))],
            sourceFileHashes: [source.path: Self.abcHash],
            options: EngineOptions(hashLogicalImage: hashLogicalImage),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512, logicalSha256: logicalHash),
            volumes: [], files: [], warnings: [], status: .completed)
    }

    func makeCase() async throws -> ForensicCase {
        let forensicCase = try CaseStore.create(name: "Readiness synthetic", in: directory)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        return try CaseStore.adding(image: inspected, to: forensicCase)
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }

    static func literal(_ value: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: try! encoder.encode(value), as: UTF8.self)
    }
}
