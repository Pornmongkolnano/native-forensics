import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// Fixed bytes follow the primary DMGFooter framing offsets, independently of
/// ImageInspector. These prove wrapper recognition, not UDIF decompression.
@Suite("UDIF wrapper classification and legacy RAW recovery rejection", .serialized)
struct ImageInspectorUDIFTests {
    private static let wrappedSHA256 = "bc37f91edb2f9420f97a3512e98651f81f17260d3c1b7dd8c6e03e66322e0b2a"
    private static let rawSHA256 = "0f24b3a6690a8cffd25fa06153b239b6f8067a045f106aa4bf0fc9fa60d052e4"

    @Test("The same NXSB signature is RAW without framing but a small stored UDIF wrapper has distinct logical size")
    func independentFraming() throws {
        let raw = Self.rawBytes(), wrapped = Self.wrappedBytes()
        #expect(Self.hash(raw) == Self.rawSHA256 && Self.hash(wrapped) == Self.wrappedSHA256)
        #expect(Data(raw[32..<36]) == Data(wrapped[32..<36]))
        let trueRaw = Self.classify(raw, named: "plain.bin")
        #expect(trueRaw.container == .raw && trueRaw.hint == "APFS container signature")
        for name in ["stored.dmg", "renamed.dd", "renamed.raw", "renamed.img", "renamed.bin"] {
            let result = Self.classify(wrapped, named: name)
            #expect(result.container == .unknown)
            let hint = try #require(result.hint)
            #expect(hint.lowercased().contains("udif"))
            #expect(hint.contains("2048") && hint.contains("268435456"))
        }
    }

    @Test("Framed out-of-bounds ranges, wrapped arithmetic and invalid sector counts cannot fall back to RAW")
    func malformedFramedFooter() throws {
        let malformedFields: [(Int, UInt64)] = [
            (24, 1_537), (32, 1_537), (24, UInt64.max), (32, UInt64.max),
            (216, 1_537), (224, 513), (216, UInt64.max), (224, UInt64.max),
            (492, 0), (492, UInt64.max)
        ]
        for (offset, value) in malformedFields {
            var footer = Self.validFooter(); Self.setBigEndian(value, at: offset, in: &footer)
            let result = Self.classify(Self.bodyBytes() + footer, named: "misleading.dd")
            #expect(result.container == .unknown)
            let hint = try #require(result.hint)
            #expect(hint.lowercased().contains("udif") && hint.lowercased().contains("malformed"))
        }
    }

    @Test("Short footer, wrong signature, version or header size preserve genuine RAW signature/extension behavior")
    func nonFramedFooter() {
        var invalidFooters = [Data(Self.validFooter().dropLast())]
        var wrongSignature = Self.validFooter(); wrongSignature[0] = 0x78; invalidFooters.append(wrongSignature)
        for (offset, bytes) in [(4, [UInt8](arrayLiteral: 0, 0, 0, 3)),
                                (4, [UInt8](arrayLiteral: 0, 0, 0, 5)),
                                (8, [UInt8](arrayLiteral: 0, 0, 1, 255)),
                                (8, [UInt8](arrayLiteral: 0, 0, 2, 1))] {
            var footer = Self.validFooter(); footer.replaceSubrange(offset..<(offset + 4), with: bytes)
            invalidFooters.append(footer)
        }
        for footer in invalidFooters {
            let result = ImageInspector.classify(header: Self.bodyBytes(), footer: footer, byteCount: Int64(1_536 + footer.count),
                url: URL(fileURLWithPath: "/synthetic/plain.bin"))
            #expect(result.container == .raw && result.hint == "APFS container signature")
            let extensionOnly = ImageInspector.classify(header: Data(repeating: 0, count: 1_536),
                footer: footer, byteCount: Int64(1_536 + footer.count), url: URL(fileURLWithPath: "/synthetic/plain.dd"))
            #expect(extensionOnly.container == .raw && extensionOnly.hint == nil)
        }
    }

    @Test("All existing EWF magics retain precedence over embedded NXSB and a framed UDIF-shaped trailer")
    func ewfPrecedence() {
        let signatures: [[UInt8]] = [
            [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00],
            [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00],
            [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00],
            [0x4c, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]
        ]
        for signature in signatures {
            var bytes = Self.wrappedBytes(); bytes.replaceSubrange(0..<8, with: signature)
            let result = Self.classify(bytes, named: "ambiguous.dd")
            #expect(result.container == .ewf && result.hint == nil)
        }
    }

    @Test("Actual inspection hashes every stored byte once and carries a footer across small real reads without changing the source")
    func realMultiReadInspection() async throws {
        let fixture = try UDIFInspectionTestFixture(bytes: Self.wrappedBytes(), name: "renamed.dd")
        defer { fixture.removeOwnedRoot() }
        let before = try FileAccess.identity(at: fixture.source), probe = UDIFInspectionReadProbe()
        let image = try await ImageInspector.inspect(url: fixture.source, progress: { probe.progress($0) },
            readForTesting: { descriptor, buffer, requested in
                let offset = Darwin.lseek(descriptor, 0, SEEK_CUR)
                let count = try FileAccess.read(descriptor, into: buffer, count: min(requested, 73))
                probe.read(descriptor: descriptor, offset: offset, count: count, buffer: buffer)
                return count
            }, descriptorClosedForTesting: { probe.closed($0, $1) })
        #expect(image.container == .unknown && image.byteCount == 2_048)
        #expect(image.sha256 == Self.wrappedSHA256 && image.hashScope == FileHashScope.selectedFileBytes)
        let afterIdentity = try FileAccess.identity(at: fixture.source)
        #expect(image.sourceIdentity == before && afterIdentity == before)
        let hint = try #require(image.filesystemHint)
        #expect(hint.lowercased().contains("udif") && hint.contains("2048") && hint.contains("268435456"))
        let reads = probe.reads
        #expect(reads.first?.offset == 0 && reads.reduce(0) { $0 + $1.count } == 2_048)
        #expect(reads.allSatisfy { $0.count > 0 && $0.count <= 73 && $0.flags & O_ACCMODE == O_RDONLY })
        #expect(zip(reads, reads.dropFirst()).allSatisfy { $0.offset + off_t($0.count) == $1.offset })
        #expect(reads.filter { $0.offset + off_t($0.count) > 1_536 }.count > 1)
        let last = try #require(reads.last)
        #expect(last.offset + off_t(last.count) == 2_048)
        #expect(probe.bytes == fixture.bytes && probe.closes.count == 1 && probe.closes.first?.status == 0)
        #expect(probe.closes.first?.descriptor == reads.first?.descriptor)
        #expect(probe.updates.last?.bytesRead == 2_048 && probe.updates.last?.totalBytes == 2_048 && probe.updates.last?.fraction == 1)
        #expect(try Data(contentsOf: fixture.source) == fixture.bytes)

        let rawFixture = try UDIFInspectionTestFixture(bytes: Self.rawBytes(), name: "plain.bin")
        defer { rawFixture.removeOwnedRoot() }
        let rawBefore = try FileAccess.identity(at: rawFixture.source)
        let raw = try await ImageInspector.inspect(url: rawFixture.source, progress: { _ in })
        #expect(raw.container == .raw && raw.filesystemHint == "APFS container signature")
        #expect(raw.byteCount == 4_096 && raw.sha256 == Self.rawSHA256 && raw.sourceIdentity == rawBefore)
        #expect(try FileAccess.identity(at: rawFixture.source) == rawBefore)
    }

    @Test("A legacy RAW case entry containing framed UDIF rejects before an absent PhotoRec executable or recovery publication")
    func legacyRawRecoveryPreflight() async throws {
        let fixture = try UDIFInspectionTestFixture(bytes: Self.wrappedBytes(), name: "OLD.raw")
        defer { fixture.removeOwnedRoot() }
        let inspected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        #expect(inspected.container == .unknown)
        var legacy = InspectedImage(sourceURL: inspected.sourceURL, byteCount: inspected.byteCount,
            sha256: inspected.sha256, container: .raw, filesystemHint: "APFS container signature")
        legacy.sourceIdentity = inspected.sourceIdentity
        let created = try CaseStore.create(name: "Legacy RAW UDIF", in: fixture.root)
        let forensicCase = try CaseStore.adding(image: legacy, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        #expect(evidence.container == .raw && evidence.sha256 == Self.wrappedSHA256)
        let before = try FileAccess.identity(at: fixture.source)
        let manifestURL = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let manifestBefore = try Data(contentsOf: manifestURL)
        let caseLeaves = try FileManager.default.contentsOfDirectory(atPath: forensicCase.bundleURL.path).sorted()
        let rootLeaves = try FileManager.default.contentsOfDirectory(atPath: fixture.root.path).sorted()
        let missingTool = fixture.root.appendingPathComponent("nonexistent-photorec")
        #expect(!FileManager.default.fileExists(atPath: missingTool.path))
        let progress = UDIFRecoveryProgressProbe()
        await #expect(throws: RecoveryError.unsupportedSource) {
            _ = try await PhotoRecRecoveryService(executableURL: missingTool).recover(evidence: evidence,
                in: forensicCase, progress: { _ in progress.record() })
        }
        #expect(progress.count == 0)
        #expect(try Data(contentsOf: manifestURL) == manifestBefore)
        #expect(try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest)
        #expect(try FileManager.default.contentsOfDirectory(atPath: forensicCase.bundleURL.path).sorted() == caseLeaves)
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.root.path).sorted() == rootLeaves)
        #expect(!FileManager.default.fileExists(atPath: forensicCase.bundleURL.appendingPathComponent("recovery").path))
        #expect(try FileAccess.identity(at: fixture.source) == before)
        let after = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        #expect(after.sha256 == Self.wrappedSHA256 && after.sourceIdentity == before && after.container == .unknown)
        #expect(try Data(contentsOf: fixture.source) == fixture.bytes)
    }

    private static func classify(_ bytes: Data, named name: String) -> (container: ImageContainer, hint: String?) {
        ImageInspector.classify(header: Data(bytes.prefix(4_096)), footer: Data(bytes.suffix(512)),
            byteCount: Int64(bytes.count), url: URL(fileURLWithPath: "/synthetic/" + name))
    }
    private static func rawBytes() -> Data {
        var bytes = Data((0..<4_096).map { UInt8($0 % 256) })
        bytes.replaceSubrange(32..<36, with: Data("NXSB".utf8)); return bytes
    }
    private static func bodyBytes() -> Data {
        var bytes = Data((0..<1_536).map { UInt8($0 % 256) })
        bytes.replaceSubrange(32..<36, with: Data("NXSB".utf8)); return bytes
    }
    private static func validFooter() -> Data {
        var footer = Data(repeating: 0, count: 512)
        footer.replaceSubrange(0..<4, with: Data("koly".utf8))
        footer.replaceSubrange(4..<8, with: [0, 0, 0, 4] as [UInt8])
        footer.replaceSubrange(8..<12, with: [0, 0, 2, 0] as [UInt8])
        for (offset, value) in [(24, UInt64(0)), (32, UInt64(1_024)), (216, UInt64(1_024)),
                                (224, UInt64(512)), (492, UInt64(524_288))] {
            setBigEndian(value, at: offset, in: &footer)
        }
        return footer
    }
    private static func setBigEndian(_ value: UInt64, at offset: Int, in data: inout Data) {
        for byte in 0..<8 { data[offset + byte] = UInt8(truncatingIfNeeded: value >> ((7 - byte) * 8)) }
    }
    private static func wrappedBytes() -> Data { bodyBytes() + validFooter() }
    private static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}

private struct UDIFInspectionTestFixture {
    let root: URL
    let source: URL
    let bytes: Data
    private let rootIdentity: (dev_t, ino_t)
    init(bytes: Data, name: String) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("NF-UDIF-inspection-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        source = root.appendingPathComponent(name); self.bytes = bytes
        try bytes.write(to: source, options: .withoutOverwriting)
        try #require(Darwin.chmod(source.path, 0o400) == 0)
        var metadata = stat(); try #require(Darwin.lstat(root.path, &metadata) == 0)
        rootIdentity = (metadata.st_dev, metadata.st_ino)
    }
    func removeOwnedRoot() {
        var metadata = stat()
        guard Darwin.lstat(root.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_dev == rootIdentity.0, metadata.st_ino == rootIdentity.1 else { return }
        try? FileManager.default.removeItem(at: root)
    }
}

private final class UDIFInspectionReadProbe: @unchecked Sendable {
    struct Read: Sendable { let descriptor: Int32; let offset: off_t; let count: Int; let flags: Int32 }
    struct Close: Sendable { let descriptor: Int32; let status: Int32 }
    private let lock = NSLock()
    private var readValues: [Read] = [], closeValues: [Close] = [], updateValues: [InspectionProgress] = []
    private var observedBytes = Data()
    func read(descriptor: Int32, offset: off_t, count: Int, buffer: UnsafeMutableRawBufferPointer) {
        lock.withLock {
            readValues.append(.init(descriptor: descriptor, offset: offset, count: count, flags: Darwin.fcntl(descriptor, F_GETFL)))
            observedBytes.append(contentsOf: buffer.bindMemory(to: UInt8.self).prefix(count))
        }
    }
    func closed(_ descriptor: Int32, _ status: Int32) { lock.withLock { closeValues.append(.init(descriptor: descriptor, status: status)) } }
    func progress(_ value: InspectionProgress) { lock.withLock { updateValues.append(value) } }
    var reads: [Read] { lock.withLock { readValues } }
    var closes: [Close] { lock.withLock { closeValues } }
    var updates: [InspectionProgress] { lock.withLock { updateValues } }
    var bytes: Data { lock.withLock { observedBytes } }
}
private final class UDIFRecoveryProgressProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func record() { lock.withLock { value += 1 } }
    var count: Int { lock.withLock { value } }
}
