import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Immutable APFS historical result store")
struct APFSResultStoreTests {
    @Test("Generation roundtrip is source-bound, immutable and opens offline")
    func roundtrip() async throws {
        let (root, source, forensicCase) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let result = make(evidence)
        let receipt = try APFSResultStore.save(result, in: forensicCase)
        #expect(receipt.caseID == forensicCase.manifest.id)
        #expect(receipt.evidenceID == evidence.id)
        let output = forensicCase.bundleURL.appendingPathComponent(receipt.relativePath)
        let bytes = try Data(contentsOf: output)
        #expect(receipt.resultSHA256 == hash(bytes))
        #expect(receipt.serializedByteCount == bytes.count)
        #expect(try APFSResultStore.loadLatest(in: forensicCase, evidenceID: evidence.id) == result)
        let second = try APFSResultStore.save(result, in: forensicCase)
        #expect(second.generationID != receipt.generationID)
        #expect(try Data(contentsOf: output) == bytes)
        try FileManager.default.removeItem(at: source)
        #expect(try APFSResultStore.loadLatest(in: forensicCase, evidenceID: evidence.id) == result)
        let job = try APFSResultStore.jobProvenance(result: result, receipt: second, startedAt: Date(timeIntervalSinceNow: -2))
        #expect(job.artifactRelativePath == second.relativePath)
        #expect(job.artifactSHA256 == second.resultSHA256)
        #expect(job.sourceHashes.first?.sha256 == evidence.sha256)
        #expect(!job.optionsJSON.contains(source.path))
    }

    @Test("Interrupted pre-publication save preserves the previous generation and pointer")
    func cancelledPublication() async throws {
        let (root, _, forensicCase) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let evidence = try #require(forensicCase.manifest.evidence.first), result = make(evidence)
        let receipt = try APFSResultStore.save(result, in: forensicCase)
        #expect(throws: CancellationError.self) {
            _ = try APFSResultStore.save(result, in: forensicCase, prePublicationValidation: { throw CancellationError() })
        }
        let latest = try #require(try APFSResultStore.loadLatestRecord(in: forensicCase, evidenceID: evidence.id))
        #expect(latest.receipt == receipt && latest.result == result)
        let generations = forensicCase.bundleURL.appendingPathComponent("apfs/\(evidence.id.uuidString.lowercased())/generations")
        #expect(try FileManager.default.contentsOfDirectory(atPath: generations.path) == [receipt.generationID.uuidString.lowercased()])
    }

    @Test("Corrupt latest metadata cannot be silently replaced; changed results fail their digest")
    func corruption() async throws {
        let (root, _, forensicCase) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let evidence = try #require(forensicCase.manifest.evidence.first), result = make(evidence)
        let receipt = try APFSResultStore.save(result, in: forensicCase)
        let generation = forensicCase.bundleURL.appendingPathComponent(receipt.relativePath)
        let original = try Data(contentsOf: generation)
        try Data("{}".utf8).write(to: generation)
        #expect(throws: (any Error).self) { _ = try APFSResultStore.loadLatest(in: forensicCase, evidenceID: evidence.id) }
        #expect(throws: (any Error).self) { _ = try APFSResultStore.save(result, in: forensicCase) }
        #expect(try Data(contentsOf: generation) == Data("{}".utf8))
        try original.write(to: generation)
        let pointer = forensicCase.bundleURL.appendingPathComponent("apfs/\(evidence.id.uuidString.lowercased())/latest.json")
        try Data("{\"schemaVersion\":999}".utf8).write(to: pointer)
        #expect(throws: (any Error).self) { _ = try APFSResultStore.save(result, in: forensicCase) }
        #expect(try Data(contentsOf: pointer) == Data("{\"schemaVersion\":999}".utf8))
    }

    @Test("An APFS cache symlink cannot redirect publication outside the case")
    func symlinkDestination() async throws {
        let (root, _, forensicCase) = try await fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let other = root.appendingPathComponent("other")
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(atPath: forensicCase.bundleURL.appendingPathComponent("apfs").path, withDestinationPath: other.path)
        #expect(throws: (any Error).self) { _ = try APFSResultStore.save(make(evidence), in: forensicCase) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: other.path).isEmpty)
    }

    private func fixture() async throws -> (URL, URL, ForensicCase) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NativeForensics-APFS-store-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let source = root.appendingPathComponent("synthetic.img"), bytes = Data("owned synthetic store source".utf8)
        try bytes.write(to: source, options: .withoutOverwriting)
        let created = try CaseStore.create(name: "APFS Cache", in: root)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        return (root, source, try CaseStore.adding(image: inspected, to: created))
    }
    private func make(_ evidence: EvidenceRecord) -> APFSInspectionResult {
        .init(evidenceID: evidence.id, containerSHA256: evidence.sha256, containerByteCount: evidence.byteCount,
              driverVersion: "synthetic-test-contract", volumeUUID: UUID(), containerEncryption: .none, volumeEncryption: .none,
              entries: [], snapshots: [], snapshotInventoryAvailable: true, coverage: .completeAllocatedView, warnings: [])
    }
    private func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}
