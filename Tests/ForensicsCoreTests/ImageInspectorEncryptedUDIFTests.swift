import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// Independently fixed public framing bytes. No key, encryption algorithm or
/// decryption is inferred from this synthetic stored-byte classification.
@Suite("Encrypted UDIF framing and legacy RAW admission", .serialized)
struct ImageInspectorEncryptedUDIFTests {
    private static let storedSHA256 = "efa2ab883cbf7aa697ec3faa9739853a7196456d35294626e872133d3339f15b"

    @Test("Known encrypted v2 public framing precedes RAW suffixes and a conflicting NXSB-looking prefix")
    func renamedEncryptedFraming() throws {
        let bytes = Self.storedBytes()
        #expect(Self.hash(bytes) == Self.storedSHA256)
        #expect(bytes.prefix(8) == Data("encrcdsa".utf8) && bytes[32..<36] == Data("NXSB".utf8))
        for name in ["stored.dmg", "renamed.dd", "renamed.img", "renamed.raw", "renamed.bin"] {
            let result = Self.classify(bytes, named: name)
            #expect(result.container == .unknown)
            let hint = try #require(result.hint)
            #expect(hint.contains("Encrypted UDIF") && hint.contains("version 2") && hint.contains("2048 stored bytes"))
            #expect(hint.contains("stored encrypted container bytes") && hint.contains("plaintext media offsets are unavailable"))
        }
    }

    @Test("A complete encrypted magic with incomplete or unsupported version stays conservatively unknown")
    func incompleteOrUnsupportedVersion() throws {
        for count in 8..<12 {
            let result = Self.classify(Data(Self.storedBytes().prefix(count)), named: "short.dd")
            #expect(result.container == .unknown)
            #expect(try #require(result.hint).contains("incomplete or unsupported"))
        }
        for version in [UInt32(0), 1, 3, UInt32.max] {
            var bytes = Self.storedBytes()
            for index in 0..<4 { bytes[8 + index] = UInt8(truncatingIfNeeded: version >> ((3 - index) * 8)) }
            let result = Self.classify(bytes, named: "misleading.raw")
            #expect(result.container == .unknown)
            #expect(try #require(result.hint).contains("incomplete or unsupported"))
        }
        let full = Self.storedBytes()
        let inconsistentSize = ImageInspector.classify(header: full, footer: Data(), byteCount: 11,
            url: URL(fileURLWithPath: "/synthetic/incomplete.img"))
        #expect(inconsistentSize.container == .unknown)
        #expect(try #require(inconsistentSize.hint).contains("incomplete or unsupported"))
    }

    @Test("Partial magic alone does not infer an encrypted wrapper and existing EWF precedence remains")
    func nonFramingAndEWF() {
        let short = Data("encrcds".utf8)
        #expect(Self.classify(short, named: "plain.dd").container == .raw)
        #expect(Self.classify(short, named: "plain.bin").container == .unknown)
        var ewf = Self.storedBytes()
        ewf.replaceSubrange(0..<8, with: [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00] as [UInt8])
        let result = Self.classify(ewf, named: "conflicting.raw")
        #expect(result.container == .ewf && result.hint == nil)
    }

    @Test("Actual stored-byte inspection preserves the full source identity and independently fixed hash")
    func actualInspection() async throws {
        let fixture = try EncryptedUDIFFramingFixture(bytes: Self.storedBytes(), name: "renamed.dd")
        defer { fixture.removeOwnedRoot() }
        let original = try FileAccess.identity(at: fixture.source)
        let inspected = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        #expect(inspected.container == .unknown && inspected.byteCount == 2_048)
        #expect(inspected.sha256 == Self.storedSHA256 && inspected.hashScope == FileHashScope.selectedFileBytes)
        let endingIdentity = try FileAccess.identity(at: fixture.source)
        #expect(inspected.sourceIdentity == original && endingIdentity == original)
        #expect(try Data(contentsOf: fixture.source) == Self.storedBytes())
    }

    @Test("OLD.raw encrypted wrapper refuses before an absent scanner and creates no recovery output")
    func legacyRawRecoveryRefused() async throws {
        let fixture = try EncryptedUDIFFramingFixture(bytes: Self.storedBytes(), name: "OLD.raw")
        defer { fixture.removeOwnedRoot() }
        let before = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        #expect(before.container == .unknown && before.sha256 == Self.storedSHA256)
        var stale = InspectedImage(sourceURL: before.sourceURL, byteCount: before.byteCount,
            sha256: before.sha256, container: .raw, filesystemHint: "APFS container signature")
        stale.sourceIdentity = before.sourceIdentity
        let forensicCase = try CaseStore.adding(image: stale, to: CaseStore.create(name: "Legacy encrypted wrapper", in: fixture.root))
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let sourceIdentity = try FileAccess.identity(at: fixture.source)
        let manifest = forensicCase.bundleURL.appendingPathComponent("manifest.json")
        let manifestBytes = try Data(contentsOf: manifest)
        let rootLeaves = try FileManager.default.contentsOfDirectory(atPath: fixture.root.path).sorted()
        let caseLeaves = try FileManager.default.contentsOfDirectory(atPath: forensicCase.bundleURL.path).sorted()
        let missingTool = fixture.root.appendingPathComponent("nonexistent-photorec")
        #expect(!FileManager.default.fileExists(atPath: missingTool.path))
        let probe = EncryptedUDIFRecoveryProgressProbe()
        await #expect(throws: RecoveryError.unsupportedSource) {
            _ = try await PhotoRecRecoveryService(executableURL: missingTool).recover(evidence: evidence,
                in: forensicCase, progress: { _ in probe.record() })
        }
        #expect(probe.count == 0)
        #expect(try Data(contentsOf: manifest) == manifestBytes)
        #expect(try CaseStore.open(at: forensicCase.bundleURL).manifest == forensicCase.manifest)
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.root.path).sorted() == rootLeaves)
        #expect(try FileManager.default.contentsOfDirectory(atPath: forensicCase.bundleURL.path).sorted() == caseLeaves)
        #expect(!FileManager.default.fileExists(atPath: forensicCase.bundleURL.appendingPathComponent("recovery").path))
        #expect(try FileAccess.identity(at: fixture.source) == sourceIdentity)
        let after = try await ImageInspector.inspect(url: fixture.source, progress: { _ in })
        #expect(after.sha256 == Self.storedSHA256 && after.sourceIdentity == before.sourceIdentity && after.container == .unknown)
    }

    private static func storedBytes() -> Data {
        var bytes = Data((0..<2_048).map { UInt8($0 % 256) })
        bytes.replaceSubrange(0..<8, with: Data("encrcdsa".utf8))
        bytes.replaceSubrange(8..<12, with: [0, 0, 0, 2] as [UInt8])
        bytes.replaceSubrange(32..<36, with: Data("NXSB".utf8))
        return bytes
    }
    private static func classify(_ bytes: Data, named name: String) -> (container: ImageContainer, hint: String?) {
        ImageInspector.classify(header: Data(bytes.prefix(4_096)), footer: Data(bytes.suffix(512)),
            byteCount: Int64(bytes.count), url: URL(fileURLWithPath: "/synthetic/" + name))
    }
    private static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}

private struct EncryptedUDIFFramingFixture {
    let root: URL
    let source: URL
    private let rootIdentity: (dev_t, ino_t)
    init(bytes: Data, name: String) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("NF-encrypted-UDIF-framing-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        source = root.appendingPathComponent(name)
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

private final class EncryptedUDIFRecoveryProgressProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func record() { lock.withLock { value += 1 } }
    var count: Int { lock.withLock { value } }
}
