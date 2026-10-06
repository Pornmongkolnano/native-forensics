import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Native engine protocol and cache")
struct EngineProtocolTests {
    @Test("Valid framed enumeration preserves exact integer timestamps and source scope")
    func successfulEnumeration() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        emit("volume", volume={"id":"v0","offsetBytes":0,"filesystem":"fat16","blockSize":512,"blockCount":32})
        emit("fileBatch", files=[entry])
        emit("progress", stage="enumeration", completed=1, total=1, unit="files")
        emit("completed", fileCount=1)
        """)
        let recorded = EngineProgressRecorder()
        let result = try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source, progress: { recorded.append($0) })
        #expect(result.status == .completed)
        #expect(result.sourcePaths == [fixture.source.path])
        #expect(result.sourceFileHashes[fixture.source.path] == EngineTestFixture.abcHash)
        #expect(result.sourceIdentities.count == 1)
        #expect(result.image.hashScope == "logical-image-bytes")
        #expect(result.files.first?.metaAddress == UInt64.max)
        #expect(result.files.first?.modifiedEpoch == 1_700_000_001)
        #expect(result.files.first?.modifiedNanoseconds == 987_654_321)
        #expect(result.files.first?.createdNanoseconds == 0)
        #expect(recorded.values.last?.stage == "enumeration")
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Explicit partial results retain files and diagnostics")
    func partialResult() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        emit("fileBatch", files=[entry])
        emit("error", code="DAMAGED_VOLUME", message="One volume could not be read.")
        emit("partial", fileCount=1)
        """)
        let result = try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source)
        #expect(result.status == .partial)
        #expect(result.files.count == 1)
        #expect(result.warnings.contains(where: { $0.contains("DAMAGED_VOLUME") }))
    }

    @Test("Version, job, sequence, hello, terminal and duplicate invariants are strict", arguments: [
        "wrong-version", "wrong-job", "sequence-gap", "duplicate-hello", "duplicate-file", "duplicate-volume",
        "duplicate-terminal", "after-terminal", "bad-count", "unknown-type", "missing-terminal", "malformed", "truncated",
        "no-hello", "no-image", "missing-hash", "error-completed", "wrong-image-scope", "negative-progress", "bad-nanoseconds"
    ])
    func rejectedFrames(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let body: String
        let setup: String
        switch mode {
        case "wrong-version": body = "emit('completed', fileCount=0, protocolVersion=99)"; setup = ""
        case "wrong-job": body = "emit('completed', fileCount=0, jobID='foreign-job')"; setup = ""
        case "sequence-gap": body = "sequence += 1\nemit('completed', fileCount=0)"; setup = ""
        case "duplicate-hello": body = "hello()\nemit('completed', fileCount=0)"; setup = ""
        case "duplicate-file": body = "emit('fileBatch', files=[entry, entry])\nemit('completed', fileCount=2)"; setup = ""
        case "duplicate-volume": body = "v={'id':'v','offsetBytes':0,'filesystem':'fat','blockSize':512,'blockCount':1}\nemit('volume', volume=v)\nemit('volume', volume=v)\nemit('completed', fileCount=0)"; setup = ""
        case "duplicate-terminal": body = "emit('completed', fileCount=0)\nemit('completed', fileCount=0)"; setup = ""
        case "after-terminal": body = "emit('completed', fileCount=0)\nemit('progress', stage='late', completed=0, unit='files')"; setup = ""
        case "bad-count": body = "emit('completed', fileCount=1)"; setup = ""
        case "unknown-type": body = "emit('surprise')"; setup = ""
        case "missing-terminal": body = "pass"; setup = ""
        case "malformed": body = "sys.stdout.write('{not json}\\n'); sys.stdout.flush()"; setup = ""
        case "truncated": body = "sys.stdout.write('{\\\"type\\\":'); sys.stdout.flush()"; setup = ""
        case "no-hello": body = "emit('completed', fileCount=0)"; setup = "skip_hello = True"
        case "no-image": body = "emit('completed', fileCount=0)"; setup = "skip_image = True"
        case "missing-hash": body = "emit('completed', fileCount=0)"; setup = "missing_hash = True"
        case "error-completed": body = "emit('error', code='BROKEN', message='Unreadable filesystem')\nemit('completed', fileCount=0)"; setup = ""
        case "wrong-image-scope": body = "emit('completed', fileCount=0)"; setup = "wrong_image_scope = True"
        case "negative-progress": body = "emit('progress', stage='bad', completed=-1, unit='files')"; setup = ""
        default: body = "entry['modifiedNanoseconds']=1000000000\nemit('fileBatch', files=[entry])\nemit('completed', fileCount=1)"; setup = ""
        }
        let helper = try fixture.helper(setup: setup, body: body)
        await #expect(throws: EngineError.self) { try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source) }
    }

    @Test("Oversized NDJSON frames and oversized batches are bounded", arguments: ["frame", "batch", "file-limit"])
    func responseLimits(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let body: String
        if mode == "frame" { body = "sys.stdout.write('x' * 1048577); sys.stdout.flush()" }
        else if mode == "batch" { body = "emit('fileBatch', files=[dict(entry, id=str(i)) for i in range(129)])" }
        else { body = "emit('fileBatch', files=[dict(entry, id=str(i)) for i in range(2)])" }
        let helper = try fixture.helper(body: body)
        await #expect(throws: EngineError.self) {
            try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source, options: EngineOptions(maxFiles: mode == "file-limit" ? 1 : 50_000))
        }
    }

    @Test("Both pipes drain when stderr exceeds its retained diagnostic budget")
    func stderrSaturation() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        sys.stderr.write("diagnostic " * 200000)
        sys.stderr.flush()
        emit("fileBatch", files=[entry])
        emit("completed", fileCount=1)
        """)
        let result = try await EngineClient(helperURL: helper, timeouts: shortTimeouts).enumerate(imageURL: fixture.source)
        #expect(result.status == .completed)
        #expect(result.files.count == 1)
    }

    @Test("Crash and nonzero exits cannot masquerade as completed results", arguments: ["crash", "nonzero", "failed"])
    func unsuccessfulExit(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let body = mode == "crash" ? "os.kill(os.getpid(), signal.SIGKILL)" :
            mode == "failed" ? "emit('error', code='OPEN_FAILED', message='Unreadable image')\nemit('failed', fileCount=0)\nsys.exit(1)" :
            "emit('completed', fileCount=0)\nsys.exit(7)"
        let helper = try fixture.helper(body: body)
        await #expect(throws: EngineError.self) { try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source) }
    }

    @Test("Startup and inactivity deadlines terminate only the owned helper", arguments: ["startup", "stage", "partial-bytes"])
    func deadlines(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let body = mode == "partial-bytes" ? "for _ in range(100):\n    sys.stdout.write('{'); sys.stdout.flush(); time.sleep(0.1)" : "time.sleep(5)"
        let helper = try fixture.helper(setup: mode == "startup" ? "time.sleep(5)" : "", body: body)
        let client = EngineClient(helperURL: helper, timeouts: EngineTimeouts(startup: mode == "startup" ? 0.2 : 10, inactivity: 0.2, cancellationGrace: 0.1, terminationGrace: 0.1))
        let error: EngineError = mode == "startup" ? .timeout("The native engine did not send hello before its startup deadline.") : .timeout("The native engine stopped reporting activity before its stage deadline.")
        await #expect(throws: error) { try await client.enumerate(imageURL: fixture.source) }
    }

    @Test("Progress heartbeats refresh the inactivity deadline")
    func heartbeats() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        for i in range(6):
            emit('progress', stage='hashing', completed=i, total=6, unit='bytes')
            time.sleep(0.08)
        emit('completed', fileCount=0)
        """)
        let result = try await EngineClient(helperURL: helper, timeouts: EngineTimeouts(startup: 2, inactivity: 0.25)).enumerate(imageURL: fixture.source)
        #expect(result.status == .completed)
    }

    @Test("Cancellation sends the protocol request before owned-PID fallback", arguments: [false, true])
    func cancellation(_ ignoreCancel: Bool) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let marker = fixture.url.appendingPathComponent("cancel-received")
        let body = ignoreCancel ? "signal.signal(signal.SIGTERM, signal.SIG_IGN)\nemit('progress', stage='waiting', completed=0, unit='files')\ntime.sleep(10)" : """
        emit('progress', stage='waiting', completed=0, unit='files')
        cancel = json.loads(sys.stdin.readline())
        if cancel['operation'] == 'cancel' and cancel['jobID'] == request['jobID']:
            open(\(pythonString(marker.path)), 'w').write('cancelled')
        emit('cancelled', fileCount=0)
        sys.exit(2)
        """
        let helper = try fixture.helper(body: body)
        let client = EngineClient(helperURL: helper, timeouts: EngineTimeouts(startup: 10, inactivity: 10, cancellationGrace: 0.2, terminationGrace: 0.1))
        let updates = EngineProgressRecorder()
        let task = Task { try await client.enumerate(imageURL: fixture.source, progress: { updates.append($0) }) }
        for _ in 0..<600 {
            if updates.values.contains(where: { $0.stage == "waiting" }) { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(updates.values.contains(where: { $0.stage == "waiting" }))
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        if !ignoreCancel { #expect(FileManager.default.fileExists(atPath: marker.path)) }
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Identity changes during a job reject the entire result")
    func sourceMutation() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: "open(request['imagePaths'][0], 'ab').write(b'changed')\nemit('completed', fileCount=0)")
        await #expect(throws: EngineError.sourceChanged) { try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source) }
    }

    @Test("Only regular local paths are accepted and duplicate inputs are rejected")
    func sourceValidation() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: "emit('completed', fileCount=0)")
        let client = EngineClient(helperURL: helper)
        await #expect(throws: ForensicsError.invalidFileURL) { try await client.enumerate(imageURL: URL(string: "https://example.invalid/image")!) }
        await #expect(throws: ForensicsError.invalidFileURL) { try await client.enumerate(imageURL: URL(string: "file://remote.invalid/image")!) }
        await #expect(throws: EngineError.self) { try await client.enumerate(imagePaths: [fixture.source, fixture.source]) }
        await #expect(throws: ForensicsError.self) { try await client.enumerate(imageURL: fixture.url) }
        let fifo = fixture.url.appendingPathComponent("fifo.dd")
        #expect(Darwin.mkfifo(fifo.path, mode_t(0o600)) == 0)
        await #expect(throws: ForensicsError.self) { try await client.enumerate(imageURL: fifo) }
    }

    @Test("Extraction validates bytes, publishes once and preserves existing destinations")
    func extraction() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        payload = b'abc'
        with open(request['outputPath'], 'xb') as output:
            output.write(payload)
        emit('extracted', outputPath=request['outputPath'], byteCount=3, sha256=hashlib.sha256(payload).hexdigest())
        emit('completed', fileCount=0)
        """)
        let client = EngineClient(helperURL: helper)
        let output = fixture.url.appendingPathComponent("Recovered file.txt")
        let receipt = try await client.extract(imageURL: fixture.source, file: fixture.file, outputURL: output, expectedSourceHashes: [fixture.source.path: EngineTestFixture.abcHash])
        #expect(receipt.outputPath == output.path)
        #expect(receipt.byteCount == 3)
        #expect(receipt.sha256 == EngineTestFixture.abcHash)
        #expect(receipt.hashScope == "extracted-file-bytes")
        #expect(try Data(contentsOf: output) == Data("abc".utf8))
        await #expect(throws: EngineError.self) { try await client.extract(imageURL: fixture.source, file: fixture.file, outputURL: output) }
        await #expect(throws: EngineError.self) { try await client.extract(imageURL: fixture.source, file: fixture.file, outputURL: fixture.source) }
        #expect(!((try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)).contains(where: { $0.hasPrefix(".native-extract-") })))
    }

    @Test("Wrong extraction hash or byte count never publishes an output", arguments: ["hash", "count", "source", "failed", "cancelled"])
    func invalidExtraction(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let body = """
        open(request['outputPath'], 'xb').write(b'abc')
        \(mode == "source" ? "open(request['imagePaths'][0], 'ab').write(b'edit')" : "")
        emit('extracted', outputPath=request['outputPath'], byteCount=\(mode == "count" ? 2 : 3), sha256=\(pythonString(mode == "hash" ? String(repeating: "0", count: 64) : EngineTestFixture.abcHash)))
        emit('\(mode == "failed" || mode == "cancelled" ? mode : "completed")', fileCount=0)
        \(mode == "failed" ? "sys.exit(1)" : mode == "cancelled" ? "sys.exit(2)" : "")
        """
        let helper = try fixture.helper(body: body)
        let output = fixture.url.appendingPathComponent("must-not-exist.txt")
        do {
            _ = try await EngineClient(helperURL: helper).extract(imageURL: fixture.source, file: fixture.file, outputURL: output)
            Issue.record("An invalid extraction unexpectedly succeeded.")
        } catch { }
        #expect(!FileManager.default.fileExists(atPath: output.path))
        #expect(!((try FileManager.default.contentsOfDirectory(atPath: fixture.url.path)).contains(where: { $0.hasPrefix(".native-extract-") })))
    }

    @Test("Historic hashes cover every ordered segment before extraction")
    func expectedHashScope() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let second = fixture.url.appendingPathComponent("image.E02")
        try Data("def".utf8).write(to: second)
        let helper = try fixture.helper(body: "raise Exception('must not execute')")
        let client = EngineClient(helperURL: helper)
        let output = fixture.url.appendingPathComponent("output.txt")
        await #expect(throws: EngineError.self) {
            try await client.extract(imagePaths: [fixture.source, second], file: fixture.file, outputURL: output, expectedSourceHashes: [fixture.source.path: EngineTestFixture.abcHash])
        }
        await #expect(throws: EngineError.sourceChanged) {
            try await client.extract(imageURL: fixture.source, file: fixture.file, outputURL: output, expectedSourceHashes: [fixture.source.path: String(repeating: "0", count: 64)])
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    @Test("Destination created mid-extraction is preserved by exclusive publication")
    func extractionRace() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let output = fixture.url.appendingPathComponent("raced.txt")
        let helper = try fixture.helper(body: """
        open(request['outputPath'], 'xb').write(b'abc')
        open(\(pythonString(output.path)), 'xb').write(b'keep me')
        emit('extracted', outputPath=request['outputPath'], byteCount=3, sha256=\(pythonString(EngineTestFixture.abcHash)))
        emit('completed', fileCount=0)
        """)
        do {
            _ = try await EngineClient(helperURL: helper).extract(imageURL: fixture.source, file: fixture.file, outputURL: output)
            Issue.record("The raced destination was unexpectedly overwritten.")
        } catch EngineError.invalidRequest { }
        #expect(try Data(contentsOf: output) == Data("keep me".utf8))
    }

    @Test("Replacing output directories cannot redirect publication or cleanup", arguments: ["parent", "staging"])
    func extractionDirectoryReplacement(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let chosen = fixture.url.appendingPathComponent("chosen-output", isDirectory: true)
        try FileManager.default.createDirectory(at: chosen, withIntermediateDirectories: false)
        let output = chosen.appendingPathComponent("final.txt")
        let marker = fixture.url.appendingPathComponent("replacement-path.txt")
        let helper = try fixture.helper(body: """
        open(request['outputPath'], 'xb').write(b'abc')
        stage = os.path.dirname(request['outputPath'])
        replaced = os.path.dirname(stage) if \(mode == "parent" ? "True" : "False") else stage
        os.rename(replaced, replaced + '-moved')
        os.mkdir(replaced)
        open(os.path.join(replaced, 'sentinel.txt'), 'wb').write(b'preserve replacement')
        if \(mode == "parent" ? "True" : "False"):
            os.mkdir(stage)
            open(request['outputPath'], 'xb').write(b'abc')
        open(\(pythonString(marker.path)), 'w').write(replaced)
        emit('extracted', outputPath=request['outputPath'], byteCount=3, sha256=\(pythonString(EngineTestFixture.abcHash)))
        emit('completed', fileCount=0)
        """)
        do {
            _ = try await EngineClient(helperURL: helper).extract(imageURL: fixture.source, file: fixture.file, outputURL: output)
            Issue.record("A replaced directory unexpectedly received a published extraction.")
        } catch { }
        let replacement = URL(fileURLWithPath: try String(contentsOf: marker, encoding: .utf8))
        #expect(try Data(contentsOf: replacement.appendingPathComponent("sentinel.txt")) == Data("preserve replacement".utf8))
        #expect(!FileManager.default.fileExists(atPath: output.path))
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Filesystem cache survives reopen without altering the Phase 0 manifest")
    func cacheRoundtrip() async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: "emit('fileBatch', files=[entry])\nemit('completed', fileCount=1)")
        let result = try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source)
        let forensicCase = try await fixture.makeCase()
        let evidenceID = try #require(forensicCase.manifest.evidence.first?.id)
        let manifest = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let before = try Data(contentsOf: manifest)
        #expect(try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL) == nil)
        try EngineResultStore.save(result: result, evidenceID: evidenceID, in: forensicCase.bundleURL)
        let loaded = try #require(try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL))
        #expect(loaded.files == result.files)
        #expect(loaded.sourceFileHashes == result.sourceFileHashes)
        #expect(loaded.sourceIdentities == result.sourceIdentities)
        #expect(loaded.options == result.options)
        #expect(loaded.status == .completed)
        #expect(loaded.files.first?.modifiedNanoseconds == 987_654_321)
        #expect(try Data(contentsOf: manifest) == before)
        #expect(try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest)
    }

    @Test("Cache versions, source scope, identifiers and symbolic links are rejected", arguments: ["version", "id", "source", "directory-link", "file-link", "oversized"])
    func invalidCache(_ mode: String) async throws {
        let fixture = try EngineTestFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: "emit('completed', fileCount=0)")
        let result = try await EngineClient(helperURL: helper).enumerate(imageURL: fixture.source)
        let forensicCase = try await fixture.makeCase()
        let evidenceID = try #require(forensicCase.manifest.evidence.first?.id)
        let directory = forensicCase.bundleURL.appendingPathComponent("filesystem", isDirectory: true)
        if mode == "directory-link" {
            try FileManager.default.createSymbolicLink(at: directory, withDestinationURL: fixture.url)
            #expect(throws: EngineError.self) { try EngineResultStore.save(result: result, evidenceID: evidenceID, in: forensicCase.bundleURL) }
            #expect(!FileManager.default.fileExists(atPath: fixture.url.appendingPathComponent(evidenceID.uuidString.lowercased() + ".json").path))
            return
        }
        if mode == "id" {
            #expect(throws: EngineError.self) { try EngineResultStore.save(result: result, evidenceID: UUID(), in: forensicCase.bundleURL) }
            return
        }
        try EngineResultStore.save(result: result, evidenceID: evidenceID, in: forensicCase.bundleURL)
        let cache = directory.appendingPathComponent(evidenceID.uuidString.lowercased() + ".json")
        if mode == "file-link" {
            try FileManager.default.removeItem(at: cache)
            try FileManager.default.createSymbolicLink(at: cache, withDestinationURL: fixture.source)
        } else if mode == "oversized" {
            let handle = try FileHandle(forWritingTo: cache)
            try handle.truncate(atOffset: UInt64(EngineValidation.resultLimit + 1))
            try handle.close()
        } else {
            var json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: cache)) as? [String: Any])
            if mode == "version" { json["schemaVersion"] = 99 }
            else { json["sourcePaths"] = ["/invalid-scope.dd"] }
            try JSONSerialization.data(withJSONObject: json).write(to: cache)
        }
        #expect(throws: (any Error).self) { try EngineResultStore.load(evidenceID: evidenceID, in: forensicCase.bundleURL) }
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    private var shortTimeouts: EngineTimeouts { EngineTimeouts(startup: 3, inactivity: 3, cancellationGrace: 0.2, terminationGrace: 0.2) }
}

private struct EngineTestFixture: Sendable {
    static let abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    let url: URL
    let source: URL
    var file: FilesystemEntry {
        FilesystemEntry(id: "v0-file", path: "/hello.txt", name: "hello.txt", fsOffsetBytes: 0, metaAddress: 1, size: 3, isDirectory: false, isDeleted: false)
    }

    init() throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("EngineTests \(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        source = url.appendingPathComponent("synthetic image.dd")
        try Data("abc".utf8).write(to: source, options: .withoutOverwriting)
    }

    func helper(setup: String = "", body: String) throws -> URL {
        let helper = url.appendingPathComponent("helper ' $ no-shell.py")
        let script = """
        #!/usr/bin/python3
        import sys, json, os, time, signal, hashlib
        request = json.loads(sys.stdin.readline())
        sequence = 0
        skip_hello = False
        skip_image = False
        missing_hash = False
        wrong_image_scope = False
        def emit(kind, **values):
            global sequence
            event = dict(protocolVersion=1, jobID=request['jobID'], sequence=sequence, type=kind)
            event.update(values)
            sequence += 1
            sys.stdout.write(json.dumps(event) + '\\n')
            sys.stdout.flush()
        def hello():
            emit('hello', engineVersion='synthetic-1', patchDigest='synthetic-only', capabilities=['raw'])
        \(setup)
        if not skip_hello:
            hello()
        if not skip_image:
            image = dict(imageType='raw', logicalSize=3, sectorSize=512, imagePaths=request['imagePaths'])
            if not missing_hash:
                image['logicalSha256'] = '\(Self.abcHash)'
            if wrong_image_scope:
                image['imagePaths'] = ['/unlisted/image.dd']
            emit('image', **image)
        entry = dict(id='v0-file', path='/hello.txt', name='hello.txt', fsOffsetBytes=0,
            metaAddress=18446744073709551615, size=3, isDirectory=False, isDeleted=False,
            modifiedEpoch=1700000001, modifiedNanoseconds=987654321)
        \(body)
        """
        try Data(script.utf8).write(to: helper, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        return helper
    }

    func makeCase() async throws -> ForensicCase {
        let original = try CaseStore.create(name: "Synthetic", in: url)
        let image = try await ImageInspector.inspect(url: source, progress: { _ in })
        return try CaseStore.adding(image: image, to: original)
    }

    func remove() { try? FileManager.default.removeItem(at: url) }
}

private func pythonString(_ value: String) -> String {
    // A JSON string is also a Python string literal for these ASCII temp paths;
    // it is written into a file, never interpolated into a shell command.
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let data = try! encoder.encode(value)
    return String(decoding: data, as: UTF8.self)
}

private final class EngineProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var updates: [EngineProgress] = []
    func append(_ progress: EngineProgress) { lock.lock(); updates.append(progress); lock.unlock() }
    var values: [EngineProgress] { lock.lock(); defer { lock.unlock() }; return updates }
}
