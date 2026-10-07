import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("RAW signature recovery correctness")
struct RecoveryServiceTests {
    @Test("Reported allocation padding is clipped only after exact source-byte verification")
    func paddedMapping() async throws {
        let fixture = try await RecoveryServiceFixture.make()
        defer { fixture.remove() }
        let result = try await fixture.service(mode: "valid").recover(evidence: fixture.evidence, in: fixture.forensicCase)
        let artifact = try #require(result.artifacts.first)
        #expect(result.status == .completed && result.artifacts.count == 1)
        #expect(artifact.reportedByteRuns == [RecoveryByteRun(outputOffset: 0, sourceOffset: 512, length: 512)])
        #expect(artifact.verifiedByteRuns == [RecoveryByteRun(outputOffset: 0, sourceOffset: 512, length: 3)])
        #expect(artifact.validationStatus == .sourceBytesVerified && artifact.deletionStatus == "unknown")
        #expect(artifact.byteCount == 3 && artifact.sha256 == RecoveryServiceFixture.hash(Data("ABC".utf8)))
        #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
            in: fixture.forensicCase.bundleURL, maximumBytes: 3) == Data("ABC".utf8))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.forensicCase.bundleURL) == result)
        let serialized = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
        #expect(!serialized.contains(fixture.root.path))
    }

    @Test("Fragmented output is mapped in declared output order without fabricating a contiguous span")
    func fragmentedMapping() async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        let result = try await fixture.service(mode: "fragmented").recover(evidence: fixture.evidence, in: fixture.forensicCase)
        let artifact = try #require(result.artifacts.first)
        #expect(artifact.verifiedByteRuns == [RecoveryByteRun(outputOffset: 0, sourceOffset: 512, length: 3),
            RecoveryByteRun(outputOffset: 3, sourceOffset: 1_536, length: 3)])
        #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
            in: fixture.forensicCase.bundleURL, maximumBytes: 6) == Data("ABCDEF".utf8))
    }

    @Test("Only documented unreported JPEG thumbnails are excluded with an explicit primary-listing warning")
    func thumbnailSideProducts() async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        let result = try await fixture.service(mode: "thumbnail").recover(evidence: fixture.evidence, in: fixture.forensicCase)
        #expect(result.artifacts.count == 1 && result.artifacts[0].filename == "f0000001.jpg")
        #expect(result.warnings.contains { $0.contains("1 unreported JPEG thumbnail") })
    }

    @Test("Mapping mismatches remain explicit unverified candidates", arguments: ["mismatch", "gap"])
    func unverifiedMapping(_ mode: String) async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        let result = try await fixture.service(mode: mode).recover(evidence: fixture.evidence, in: fixture.forensicCase)
        let artifact = try #require(result.artifacts.first)
        #expect(artifact.validationStatus == .unverified && artifact.verifiedByteRuns.isEmpty)
        #expect(!artifact.warnings.isEmpty && artifact.deletionStatus == "unknown")
    }

    @Test("Malformed reports and output symlinks never publish", arguments: ["path", "entity", "overflow", "symlink", "omitted"])
    func rejectedReport(_ mode: String) async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        await #expect(throws: RecoveryError.invalidReport) {
            try await fixture.service(mode: mode).recover(evidence: fixture.evidence, in: fixture.forensicCase)
        }
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.forensicCase.bundleURL) == nil)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: fixture.sentinel) == Data("untouched".utf8))
    }

    @Test("Changed source fails before scanner work and source mutation during a scan vetoes publication", arguments: ["changed-before", "changed-during"])
    func changedSource(_ mode: String) async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        if mode == "changed-before" {
            var data = fixture.sourceBytes; data[0] = 0x41; try data.write(to: fixture.source)
        }
        await #expect(throws: RecoveryError.sourceChanged) {
            try await fixture.service(mode: mode).recover(evidence: fixture.evidence, in: fixture.forensicCase)
        }
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.forensicCase.bundleURL) == nil)
        if mode == "changed-before" { #expect(!FileManager.default.fileExists(atPath: fixture.marker.path)) }
    }

    @Test("Tool failure and byte limits preserve the complete previous immutable generation", arguments: ["failure", "limit"])
    func preservePrevious(_ mode: String) async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        let prior = try await fixture.service(mode: "valid").recover(evidence: fixture.evidence, in: fixture.forensicCase)
        var options = RecoveryOptions()
        if mode == "limit" { options.maximumOutputBytes = 2; options.maximumArtifactBytes = 2 }
        do {
            _ = try await fixture.service(mode: mode).recover(evidence: fixture.evidence, in: fixture.forensicCase, options: options)
            Issue.record("Failure was accepted")
        } catch {
            #expect(error as? RecoveryError == (mode == "failure" ? .toolFailed(7) : .outputLimit))
        }
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.forensicCase.bundleURL) == prior)
        let artifact = try #require(prior.artifacts.first)
        #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: prior,
            in: fixture.forensicCase.bundleURL, maximumBytes: 3) == Data("ABC".utf8))
    }

    @Test("Cancellation drains owned child and leaves the existing case unchanged")
    func cancellation() async throws {
        let fixture = try await RecoveryServiceFixture.make(); defer { fixture.remove() }
        let signal = RecoveryServiceSignal()
        let task = Task {
            try await fixture.service(mode: "wait").recover(evidence: fixture.evidence, in: fixture.forensicCase) {
                if $0.stage == "Recovering signature candidates" { signal.mark() }
            }
        }
        for _ in 0..<500 where !signal.value { try await Task.sleep(for: .milliseconds(10)) }
        #expect(signal.value); task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.forensicCase.bundleURL) == nil)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Installed PhotoRec recovers a generated PNG with independent exact bytes and source mapping",
          .enabled(if: FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/photorec")))
    func actualPhotoRec() async throws {
        let png = try #require(Data(base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j6GkAAAAASUVORK5CYII="))
        var image = Data(repeating: 0, count: 8 * 1_048_576)
        image.replaceSubrange(512..<512 + png.count, with: png)
        let fixture = try await RecoveryServiceFixture.make(bytes: image); defer { fixture.remove() }
        let result = try await PhotoRecRecoveryService(executableURL: URL(fileURLWithPath: "/opt/homebrew/bin/photorec"))
            .recover(evidence: fixture.evidence, in: fixture.forensicCase, options: RecoveryOptions(timeout: 60))
        let artifact = try #require(result.artifacts.first(where: { $0.formatHint == "png" }))
        #expect(artifact.sha256 == RecoveryServiceFixture.hash(png))
        #expect(artifact.validationStatus == .sourceBytesVerified)
        #expect(artifact.verifiedByteRuns.first?.sourceOffset == 512)
        #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
            in: fixture.forensicCase.bundleURL, maximumBytes: 1_024) == png)
        #expect(try Data(contentsOf: fixture.source) == image)
    }

    @Test("XML limits, entities, duplicates, nested scalars and out-of-bounds extents are rejected", arguments: ["entity", "duplicate", "range", "size", "depth", "nested"])
    func parserControls(_ mode: String) throws {
        let field = mode == "duplicate" ? "<filename>x</filename><filename>y</filename>" : "<filename>x</filename>"
        let run = mode == "range" ? "<byte_run offset='0' img_offset='4095' len='2'/>" : "<byte_run offset='0' img_offset='512' len='512'/>"
        var xml = "<dfxml><source><image_size>\(mode == "size" ? 4095 : 4096)</image_size></source><fileobject>\(field)<filesize>3</filesize><byte_runs>\(run)</byte_runs></fileobject></dfxml>"
        if mode == "entity" { xml = "<!DOCTYPE dfxml [<!ENTITY a 'ABC'>]>" + xml }
        if mode == "depth" { xml = "<dfxml>" + String(repeating: "<x>", count: 35) + String(repeating: "</x>", count: 35) + "</dfxml>" }
        if mode == "nested" { xml = xml.replacingOccurrences(of: "<filesize>3</filesize>", with: "<filesize><x>wrong</x>3</filesize>") }
        #expect(throws: mode == "depth" ? RecoveryError.outputLimit : RecoveryError.invalidReport) {
            try RecoveryReportParser.parse(Data(xml.utf8), sourceSize: 4_096, maximumFiles: 5_000)
        }
    }

    @Test("A persisted verified range must be exactly clipped from the reported mapping")
    func inconsistentMapping() throws {
        let id = UUID()
        let artifact = CarvedArtifact(id: id, filename: "candidate.txt", relativePath: "files/\(id.uuidString.lowercased())",
            formatHint: "txt", byteCount: 3, sha256: RecoveryServiceFixture.hash(Data("ABC".utf8)),
            reportedByteRuns: [RecoveryByteRun(outputOffset: 0, sourceOffset: 512, length: 512)],
            verifiedByteRuns: [RecoveryByteRun(outputOffset: 0, sourceOffset: 1_536, length: 3)], validationStatus: .sourceBytesVerified)
        #expect(throws: RecoveryError.invalidResult) { try artifact.validate(sourceSize: 4_096, options: RecoveryOptions()) }
    }

    @Test("Recovery cleanup preserves a replacement inode and safely removes later over-quota owned files")
    func cleanupOwnershipAndQuota() throws {
        let scratch = try RecoveryScratch()
        let directory = scratch.url.appendingPathComponent("recovered.1")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let file = directory.appendingPathComponent("f1.txt")
        try Data("owned".utf8).write(to: file)
        _ = try scratch.inventory(options: RecoveryOptions())
        try FileManager.default.moveItem(at: file, to: directory.appendingPathComponent("original-owned"))
        try Data("replacement".utf8).write(to: file)
        #expect(throws: RecoveryError.storageChanged) { try scratch.inventory(options: RecoveryOptions()) }
        #expect(!scratch.cleanup())
        #expect(try Data(contentsOf: file) == Data("replacement".utf8))
        try FileManager.default.removeItem(at: scratch.url)

        let limited = try RecoveryScratch()
        let outputs = limited.url.appendingPathComponent("recovered.1")
        try FileManager.default.createDirectory(at: outputs, withIntermediateDirectories: false)
        for index in 0..<3 { try Data("ABC".utf8).write(to: outputs.appendingPathComponent("f\(index).txt")) }
        #expect(throws: RecoveryError.outputLimit) {
            try limited.inventory(options: RecoveryOptions(maximumOutputBytes: 2, maximumArtifactBytes: 2))
        }
        #expect(limited.cleanup())
        #expect(!FileManager.default.fileExists(atPath: limited.url.path))
    }
}

private struct RecoveryServiceFixture: Sendable {
    let root: URL, source: URL, sentinel: URL, marker: URL
    let sourceBytes: Data
    let forensicCase: ForensicCase
    var evidence: EvidenceRecord { forensicCase.manifest.evidence[0] }

    static func make(bytes: Data? = nil) async throws -> Self {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("recovery-ไทย-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let source = root.appendingPathComponent("หลักฐาน ' RAW.dd")
        var data = bytes ?? Data(repeating: 0, count: 4_096)
        if bytes == nil {
            data.replaceSubrange(512..<515, with: Data("ABC".utf8))
            data.replaceSubrange(1_536..<1_539, with: Data("DEF".utf8))
        }
        try data.write(to: source)
        let sentinel = root.appendingPathComponent("untouched")
        try Data("untouched".utf8).write(to: sentinel)
        let created = try CaseStore.create(name: "Synthetic recovery", in: root)
        let inspection = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspection, to: created)
        return Self(root: root, source: source, sentinel: sentinel, marker: root.appendingPathComponent("scanner-started"),
            sourceBytes: data, forensicCase: forensicCase)
    }

    func service(mode: String) throws -> PhotoRecRecoveryService {
        let url = root.appendingPathComponent("photorec-\(mode).sh")
        let payload: String
        switch mode {
        case "fragmented": payload = "/bin/dd if=input.raw bs=1 skip=512 count=3 2>/dev/null > recovered.1/f0000001.txt\n/bin/dd if=input.raw bs=1 skip=1536 count=3 2>/dev/null >> recovered.1/f0000001.txt"
        case "mismatch": payload = "printf XBC > recovered.1/f0000001.txt"
        case "symlink": payload = "/bin/ln -s \(Self.quote(sentinel.path)) recovered.1/f0000001.txt"
        default: payload = "/bin/dd if=input.raw of=recovered.1/f0000001.txt bs=1 skip=512 count=3 2>/dev/null"
        }
        let filename = mode == "path" ? "../../untouched" : mode == "thumbnail" ? "f0000001.jpg" : "f0000001.txt"
        let files = mode == "omitted" ? "" : "<fileobject><filename>\(filename)</filename><filesize>\(mode == "fragmented" ? 6 : 3)</filesize><byte_runs><byte_run offset='\(mode == "gap" ? 1 : 0)' img_offset='\(mode == "overflow" ? "9223372036854775807" : "512")' len='\(mode == "fragmented" ? 3 : 512)'/>\(mode == "fragmented" ? "<byte_run offset='3' img_offset='1536' len='512'/>" : "")</byte_runs></fileobject>"
        let xml = (mode == "entity" ? "<!DOCTYPE dfxml [<!ENTITY a 'ABC'>]>" : "") + "<dfxml><source><image_size>\(sourceBytes.count)</image_size></source>\(files)</dfxml>"
        let script = """
        #!/bin/sh
        if [ "$1" = /version ]; then printf 'PhotoRec 7.2 synthetic fixture\\n'; exit 0; fi
        printf started > \(Self.quote(marker.path))
        \(mode == "failure" ? "exit 7" : "")
        \(mode == "wait" ? "/bin/sleep 30" : "")
        /bin/mkdir recovered.1
        \(payload)
        \(mode == "thumbnail" ? "/bin/mv recovered.1/f0000001.txt recovered.1/f0000001.jpg\nprintf '\\377\\330\\377thumbnail\\377\\331' > recovered.1/t0000001.jpg" : "")
        printf '%s' \(Self.quote(xml)) > recovered.1/report.xml
        \(mode == "changed-during" ? "printf changed >> " + Self.quote(source.path) : "")
        exit 0
        """
        try Data(script.utf8).write(to: url)
        guard Darwin.chmod(url.path, 0o700) == 0 else { throw RecoveryError.unavailable }
        return PhotoRecRecoveryService(executableURL: url)
    }
    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }
    func remove() { try? FileManager.default.removeItem(at: root) }
}

private final class RecoveryServiceSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var marked = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return marked }
    func mark() { lock.lock(); marked = true; lock.unlock() }
}
