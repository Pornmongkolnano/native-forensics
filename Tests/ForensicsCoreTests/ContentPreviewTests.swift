import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Bounded verified local content")
struct ContentPreviewTests {
    @Test("Thai UTF-8, CRLF lines, long fragments and partial/deleted limits remain exact")
    func textRowsAndScope() throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let payload = Data(("ภาษาไทย\r\n" + String(repeating: "ก", count: 200) + "\nlast").utf8)
        let preview = try fixture.preview(payload: payload, deleted: true, partial: true)
        #expect(preview.text == String(decoding: payload, as: UTF8.self))
        #expect(preview.textFragments.first?.lineNumber == 1)
        #expect(preview.textFragments.first?.text == "ภาษาไทย")
        #expect(preview.textFragments.filter { $0.lineNumber == 2 }.count == 3)
        #expect(preview.textFragments.filter { $0.lineNumber == 2 }.map(\.text).joined() == String(repeating: "ก", count: 200))
        #expect(preview.textFragments.allSatisfy { $0.text.utf8.count <= ContentPreviewBuilder.maximumTextFragmentBytes })
        #expect(preview.textFragments.last?.lineNumber == 3)
        #expect(preview.textFragments.last?.byteOffset == payload.count - 4)
        #expect(preview.receipt.sha256 == ContentFixture.hash(payload))
        #expect(preview.receipt.hashScope == "extracted-file-bytes")
        #expect(preview.receipt.containerHashScope == "selected-file-bytes")
        #expect(!preview.receipt.metadataWasRefreshed)
        #expect(!preview.receipt.logicalImageHashWasRefreshed)
        #expect(preview.warnings.contains { $0.contains("partial") })
        #expect(preview.warnings.contains { $0.contains("reused") })
        #expect(preview.warnings.contains { $0.contains("Asia/Bangkok") })
        let json = String(decoding: try JSONEncoder().encode(preview.receipt), as: UTF8.self)
        #expect(!json.contains(fixture.directory.path))
    }

    @Test("Binary, invalid UTF-8 and terminal control bytes render exact hex", arguments: [Data([0x00, 0x1b, 0xff, 0x41]), Data([0xc3]), Data([0x7f, 0x80])])
    func binaryHex(_ payload: Data) throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let preview = try fixture.preview(payload: payload)
        #expect(!preview.supportsText)
        #expect(preview.textFragments.isEmpty)
        #expect(preview.hexRows.first?.byteOffset == 0)
        #expect(preview.hexRows.first?.hexadecimal == payload.map { String(format: "%02X", $0) }.joined(separator: " "))
        #expect(preview.hexRows.first?.ascii.utf8.allSatisfy { (32...126).contains($0) } == true)
        #expect(preview.receipt.sha256 == ContentFixture.hash(payload))
    }

    @Test("Empty bytes preserve a complete digest and an empty first derived line")
    func emptyFile() throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let preview = try fixture.preview(payload: Data())
        #expect(preview.supportsText)
        #expect(preview.text == "")
        #expect(preview.textFragments.count == 1)
        #expect(preview.hexRows.isEmpty)
        #expect(!preview.textIsTruncated && !preview.hexIsTruncated)
        #expect(preview.receipt.sha256 == ContentFixture.hash(Data()))
    }

    @Test("UTF-8 and hex prefixes have independent exact bounds while digest covers the complete file")
    func prefixBounds() throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let payload = Data((String(repeating: "a", count: 32_766) + "🕵️tail").utf8)
        let preview = try fixture.preview(payload: payload)
        #expect(preview.textIncludedByteCount == 32_766)
        #expect(preview.text == String(repeating: "a", count: 32_766))
        #expect(preview.hexIncludedByteCount == 32_768)
        #expect(preview.hexRows.count == 2048)
        #expect(preview.hexRows.last?.byteOffset == 32_752)
        #expect(preview.textIsTruncated && preview.hexIsTruncated)
        #expect(preview.receipt.sha256 == ContentFixture.hash(payload))
        #expect(preview.receipt.sha256 != ContentFixture.hash(Data(try #require(preview.text).utf8)))
    }

    @Test("Independent verification rejects receipt hash, size and over-limit bytes", arguments: ["hash", "receipt-size", "expected-size", "limit"])
    func invalidReceipt(_ mode: String) throws {
        let payload = mode == "limit" ? Data(repeating: 0x61, count: Int(VerifiedContentService.maximumFileBytes) + 1) : Data("abc".utf8)
        let receipt = ExtractionResult(outputPath: "/unused", byteCount: Int64(payload.count) + (mode == "receipt-size" ? 1 : 0),
            sha256: mode == "hash" ? String(repeating: "0", count: 64) : ContentFixture.hash(payload))
        #expect(throws: VerifiedContentError.extractedContentMismatch) {
            try VerifiedContentService.verify(bytes: payload, receipt: receipt,
                expectedSize: Int64(payload.count) + (mode == "expected-size" ? 1 : 0))
        }
    }

    @Test("Fresh service verifies extraction independently and removes descriptor-owned scratch")
    func freshExtraction() async throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let payload = Data("hello หลักฐาน\n".utf8)
        let file = fixture.file(size: Int64(payload.count))
        let helper = try fixture.helper(payload: payload)
        let preview = try await ContentPreviewBuilder.load(evidence: fixture.evidence, result: fixture.result(file),
            file: file, engine: EngineClient(helperURL: helper))
        #expect(preview.text == String(decoding: payload, as: UTF8.self))
        #expect(preview.receipt.sha256 == ContentFixture.hash(payload))
        #expect(preview.receipt.orderedContainerSHA256 == [fixture.evidence.sha256])
        let directory = try fixture.scratchDirectory()
        #expect(!FileManager.default.fileExists(atPath: directory.path))
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Changed source fails before helper launch or local preview")
    func changedSource() async throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let file = fixture.file(size: 3)
        let result = fixture.result(file)
        let helper = try fixture.helper(payload: Data("abc".utf8))
        try Data("changed".utf8).write(to: fixture.source)
        await #expect(throws: EngineError.sourceChanged) {
            try await ContentPreviewBuilder.load(evidence: fixture.evidence, result: result, file: file,
                engine: EngineClient(helperURL: helper))
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.marker.path))
    }

    @Test("Canceled extraction drains helper and only owned temporary bytes")
    func canceledExtraction() async throws {
        let fixture = try ContentFixture()
        defer { fixture.remove() }
        let file = fixture.file(size: 3)
        let helper = try fixture.helper(payload: Data("abc".utf8), waits: true)
        let flag = ContentProgressFlag()
        let task = Task {
            try await ContentPreviewBuilder.load(evidence: fixture.evidence, result: fixture.result(file), file: file,
                engine: EngineClient(helperURL: helper), progress: { if $0.stage == "await-cancel" { flag.mark() } })
        }
        for _ in 0..<500 where !flag.value { try await Task.sleep(for: .milliseconds(10)) }
        #expect(flag.value)
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(!FileManager.default.fileExists(atPath: try fixture.scratchDirectory().path))
        let pid = try #require(Int32(String(contentsOf: fixture.pid, encoding: .utf8)))
        #expect(Darwin.kill(pid, 0) == -1)
        #expect(errno == ESRCH)
        #expect(try Data(contentsOf: fixture.source) == Data("abc".utf8))
    }

    @Test("Known leaf cleanup preserves replacements and unknown scratch contents")
    func scratchOwnership() throws {
        let scratch = try ContentScratch()
        let output = scratch.outputURL
        let owned = Data("owned".utf8)
        try owned.write(to: output)
        try scratch.claimPublished(receipt: ExtractionResult(outputPath: output.path, byteCount: 5, sha256: ContentFixture.hash(owned)),
                                   identity: FileAccess.identity(at: output))
        let held = output.deletingLastPathComponent().appendingPathComponent("original")
        try FileManager.default.moveItem(at: output, to: held)
        try Data("replacement".utf8).write(to: output)
        let unknown = output.deletingLastPathComponent().appendingPathComponent("unknown")
        try Data("keep".utf8).write(to: unknown)
        scratch.cleanup()
        #expect(try Data(contentsOf: output) == Data("replacement".utf8))
        #expect(try Data(contentsOf: unknown) == Data("keep".utf8))
        #expect(try Data(contentsOf: held) == owned)
        try FileManager.default.removeItem(at: output.deletingLastPathComponent())
    }

    @Test("Replacement before claim is never adopted or removed", arguments: ["regular", "symlink", "directory"])
    func replacementBeforeClaim(_ mode: String) throws {
        let scratch = try ContentScratch()
        let output = scratch.outputURL
        let originalDirectory = output.deletingLastPathComponent()
        let original = Data("owned".utf8)
        try original.write(to: output)
        let identity = try FileAccess.identity(at: output)
        let receipt = ExtractionResult(outputPath: output.path, byteCount: 5, sha256: ContentFixture.hash(original))
        let heldDirectory = originalDirectory.appendingPathExtension("held")
        if mode == "directory" {
            try FileManager.default.moveItem(at: originalDirectory, to: heldDirectory)
            try FileManager.default.createDirectory(at: originalDirectory, withIntermediateDirectories: false)
            try Data("replacement".utf8).write(to: output)
        } else {
            try FileManager.default.moveItem(at: output, to: originalDirectory.appendingPathComponent("held"))
            if mode == "regular" { try Data("replacement".utf8).write(to: output) }
            else { try FileManager.default.createSymbolicLink(at: output, withDestinationURL: originalDirectory.appendingPathComponent("held")) }
        }
        #expect(throws: VerifiedContentError.extractedContentMismatch) {
            try scratch.claimPublished(receipt: receipt, identity: identity)
        }
        scratch.cleanup()
        if mode == "directory" {
            #expect(try Data(contentsOf: output) == Data("replacement".utf8))
            #expect(!FileManager.default.fileExists(atPath: heldDirectory.appendingPathComponent("selected-file").path))
            try FileManager.default.removeItem(at: heldDirectory)
        } else if mode == "regular" {
            #expect(try Data(contentsOf: output) == Data("replacement".utf8))
            #expect(try Data(contentsOf: originalDirectory.appendingPathComponent("held")) == original)
        } else {
            #expect(try FileManager.default.destinationOfSymbolicLink(atPath: output.path) == originalDirectory.appendingPathComponent("held").path)
            #expect(try Data(contentsOf: output) == original)
        }
        try FileManager.default.removeItem(at: originalDirectory)
    }
}

private final class ContentProgressFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var marked = false
    var value: Bool { lock.withLock { marked } }
    func mark() { lock.withLock { marked = true } }
}

private struct ContentFixture {
    let directory: URL
    let source: URL
    let marker: URL
    let pid: URL
    let evidence: EvidenceRecord

    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("ContentFixture-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        source = directory.appendingPathComponent("synthetic.dd")
        marker = directory.appendingPathComponent("output.marker")
        pid = directory.appendingPathComponent("pid.marker")
        try Data("abc".utf8).write(to: source)
        evidence = EvidenceRecord(sourcePath: source.path, byteCount: 3, sha256: Self.hash(Data("abc".utf8)), container: .raw, filesystemHint: nil)
    }

    func file(size: Int64, deleted: Bool = false) -> FilesystemEntry {
        FilesystemEntry(id: "content-1", path: "/content.txt", name: "content.txt", fsOffsetBytes: 0, metaAddress: 1,
            size: size, isDirectory: false, isDeleted: deleted)
    }

    func result(_ file: FilesystemEntry, partial: Bool = false) -> EnumerationResult {
        EnumerationResult(engineVersion: "content-fixture", patchDigest: "synthetic-only", sourcePaths: [source.path],
            sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(timezone: "Asia/Bangkok", hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 3, sectorSize: 512), volumes: [], files: [file],
            warnings: [], status: partial ? .partial : .completed)
    }

    func preview(payload: Data, deleted: Bool = false, partial: Bool = false) throws -> LocalContentPreview {
        let file = file(size: Int64(payload.count), deleted: deleted)
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result(file, partial: partial), file: file)
        let content = VerifiedContent(bytes: payload, receipt: VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id,
            byteCount: Int64(payload.count), sha256: Self.hash(payload), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]))
        return ContentPreviewBuilder.render(content: content, context: context)
    }

    func helper(payload: Data, waits: Bool = false) throws -> URL {
        let url = directory.appendingPathComponent("helper.py")
        let script = """
        #!/usr/bin/python3
        import json, sys, hashlib, os
        request = json.loads(sys.stdin.readline())
        assert request['operation'] == 'extract'
        assert request['hashLogicalImage'] is False
        sequence = 0
        def emit(kind, **values):
            global sequence
            frame = dict(protocolVersion=1, jobID=request['jobID'], sequence=sequence, type=kind)
            frame.update(values)
            sequence += 1
            print(json.dumps(frame), flush=True)
        emit('hello', engineVersion='content-fixture', patchDigest='synthetic-only', capabilities=['raw'])
        emit('image', imageType='raw', logicalSize=3, sectorSize=512, imagePaths=request['imagePaths'])
        payload = bytes.fromhex('\(payload.map { String(format: "%02x", $0) }.joined())')
        with open(request['outputPath'], 'xb') as output: output.write(payload)
        with open(\(Self.literal(marker.path)), 'x') as marker: marker.write(request['outputPath'])
        with open(\(Self.literal(pid.path)), 'x') as marker: marker.write(str(os.getpid()))
        \(waits ? "emit('progress', stage='await-cancel', completed=0, unit='files')\ncancel = json.loads(sys.stdin.readline())\nemit('cancelled', fileCount=0)\nsys.exit(2)" : "emit('extracted', outputPath=request['outputPath'], byteCount=len(payload), sha256=hashlib.sha256(payload).hexdigest())\nemit('completed', fileCount=0)")
        """
        try Data(script.utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }

    func scratchDirectory() throws -> URL {
        URL(fileURLWithPath: try String(contentsOf: marker, encoding: .utf8)).deletingLastPathComponent().deletingLastPathComponent()
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    static func literal(_ value: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: try! encoder.encode(value), as: UTF8.self)
    }
}
