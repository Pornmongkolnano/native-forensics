import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Extraction interpretation and awaited immutable history")
struct ExtractionHistoryPublicationTests {
    @Test("EFS history retains public provenance, raw bindings and unauthenticated limitation after reopen", arguments: [1, 2])
    func publicDecryptionReceipt(_ schemaVersion: Int) async throws {
        let fixture = try await ExtractionHistoryFixture.make(schemaVersion: schemaVersion)
        defer { fixture.remove() }
        let beforeSource = try Data(contentsOf: fixture.source)
        let beforeManifest = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        let id = UUID(), instant = Date(timeIntervalSinceReferenceDate: 813_457_690.125)
        let outcome = await ExtractionHistoryPublication.publish(receipt: fixture.decryptedReceipt,
            caseID: fixture.forensicCase.manifest.id, evidence: fixture.evidence, result: fixture.result,
            file: fixture.file, in: fixture.caseURL, id: id, verifiedAt: instant)
        let record = try #require(outcome.record)
        #expect(outcome.historyIsConfirmed)
        #expect(record.id == id && record.createdAt == instant)
        #expect(record.contentStatus == "decrypted-content")
        #expect(record.warnings == [ExtractionDecryptionReceipt.unauthenticatedPlaintextWarning])
        #expect(record.decryption == fixture.decryptedReceipt.decryption)
        #expect(record.decryption?.authenticatedPlaintext == false)
        #expect(record.outputHash.sha256 == ExtractionHistoryFixture.plaintextSHA256)
        #expect(record.outputHash.scope == "extracted-file-bytes")
        #expect(record.binding.snapshotSHA256 == fixture.binding.snapshotSHA256)
        #expect(record.binding.options == fixture.result.options)
        #expect(record.binding.engineVersion == "efs-history-synthetic")
        #expect(record.binding.patchDigest == "synthetic-original-component")
        #expect(record.binding.selectedContainerHash.scope == "selected-file-bytes")
        #expect(record.binding.selectedContainerHash.sha256 == fixture.evidence.sha256)
        #expect(record.binding.logicalImageHash?.scope == "logical-image-bytes")
        #expect(record.binding.logicalImageHash?.sha256 != record.outputHash.sha256)
        let saved = try #require(try CaseWorkStore.loadExtraction(id: id, in: fixture.caseURL))
        #expect(saved == record)
        let bytes = try Data(contentsOf: fixture.recordURL(id))
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(!text.contains(fixture.source.path))
        #expect(!text.contains(fixture.output.path))
        #expect(!text.contains("privateKey"))
        #expect(!text.contains("certificate.der"))
        // The signed bytes include all interpretation fields. This signature is
        // a test trust anchor, not a claim that every case is automatically signed.
        let key = Curve25519.Signing.PrivateKey()
        let signature = try key.signature(for: bytes)
        #expect(key.publicKey.isValidSignature(signature, for: bytes))
        let edited = try fixture.edit(bytes) { object in
            var decryption = try #require(object["decryption"] as? [String: Any])
            decryption["authenticatedPlaintext"] = true
            object["decryption"] = decryption
        }
        #expect(!key.publicKey.isValidSignature(signature, for: edited))
        let audit = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(audit.checks.contains { $0.relativePath == "extractions/\(id.uuidString.lowercased()).json" && $0.code == "metadata.valid" })
        #expect(!audit.sourceRehashed)
        #expect(try Data(contentsOf: fixture.source) == beforeSource)
        #expect(try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json")) == beforeManifest)
    }

    @Test("Legacy nil receipts decode and serialize to the exact original v1 field set")
    func legacyBytes() async throws {
        let fixture = try await ExtractionHistoryFixture.make(encrypted: false)
        defer { fixture.remove() }
        let record = try ExtractionRecord.make(binding: fixture.binding,
            receipt: ExtractionResult(outputPath: fixture.output.path, byteCount: 3,
                sha256: ExtractionHistoryFixture.plaintextSHA256))
        let legacy = LegacyExtractionRecord(schemaVersion: record.schemaVersion, id: record.id,
            createdAt: record.createdAt, binding: record.binding, outputHash: record.outputHash,
            outputByteCount: record.outputByteCount, verificationDescription: record.verificationDescription)
        let bytes = try CaseWorkCoding.encode(legacy)
        #expect(try CaseWorkCoding.encode(record) == bytes)
        let decoded = try CaseWorkCoding.decode(ExtractionRecord.self, bytes)
        try decoded.validate()
        #expect(decoded.contentStatus == nil && decoded.warnings == nil && decoded.decryption == nil)
        try CaseWorkStore.saveExtraction(decoded, in: fixture.caseURL)
        #expect(try CaseWorkStore.loadExtraction(id: record.id, in: fixture.caseURL) == record)
        #expect(try Data(contentsOf: fixture.recordURL(record.id)) == bytes)
    }

    @Test("Ordinary and deleted history keep their distinct interpretation without a decryption claim", arguments: [false, true])
    func ordinaryInterpretation(_ deleted: Bool) async throws {
        let fixture = try await ExtractionHistoryFixture.make(encrypted: false, deleted: deleted)
        defer { fixture.remove() }
        let warnings = deleted ? [ExtractionRecord.recoveryContentWarning, ExtractionRecord.allocatedClusterWarning] : nil
        let receipt = ExtractionResult(outputPath: fixture.output.path, byteCount: 3,
            sha256: ExtractionHistoryFixture.plaintextSHA256,
            contentStatus: deleted ? "recovery-candidate" : "logical-content", warnings: warnings)
        let outcome = await ExtractionHistoryPublication.publish(receipt: receipt, binding: fixture.binding,
            in: fixture.caseURL)
        let record = try #require(outcome.record)
        #expect(outcome.historyIsConfirmed)
        #expect(record.contentStatus == receipt.contentStatus && record.warnings == warnings)
        #expect(record.decryption == nil)
        #expect(try CaseWorkStore.loadExtraction(id: record.id, in: fixture.caseURL) == record)
    }

    @Test("Historical decoding rejects inconsistent, altered or path-bearing interpretation", arguments: [
        "authenticated", "profile", "metadataHash", "certificate", "ciphertextHash", "ciphertextBytes", "unitBytes",
        "recipientRole", "missingDecryption", "missingStatus", "wrongStatus", "missingWarning", "unknownWarning", "privatePathWarning"
    ])
    func rejectsFalseInterpretation(_ mutation: String) async throws {
        let fixture = try await ExtractionHistoryFixture.make()
        defer { fixture.remove() }
        let record = try ExtractionRecord.make(binding: fixture.binding, receipt: fixture.decryptedReceipt)
        try CaseWorkStore.saveExtraction(record, in: fixture.caseURL)
        let beforeSource = try Data(contentsOf: fixture.source)
        let edited = try fixture.edit(Data(contentsOf: fixture.recordURL(record.id))) { object in
            var decryption = try #require(object["decryption"] as? [String: Any])
            switch mutation {
            case "authenticated": decryption["authenticatedPlaintext"] = true
            case "profile": decryption["profile"] = "unrecognized-profile"
            case "metadataHash": decryption["metadataSHA256"] = String(repeating: "A", count: 64)
            case "certificate": decryption["certificateSHA1"] = String(repeating: "c", count: 64)
            case "ciphertextHash": decryption["ciphertextSHA256"] = "short"
            case "ciphertextBytes": decryption["ciphertextBytes"] = 3
            case "unitBytes": decryption["unitBytes"] = 16
            case "recipientRole": decryption["recipientRole"] = "owner"
            case "missingDecryption": object.removeValue(forKey: "decryption")
            case "missingStatus": object.removeValue(forKey: "contentStatus")
            case "wrongStatus": object["contentStatus"] = "logical-content"
            case "missingWarning": object.removeValue(forKey: "warnings")
            case "unknownWarning": object["warnings"] = ["This plaintext is authenticated."]
            case "privatePathWarning": object["warnings"] = [fixture.output.path]
            default: break
            }
            if mutation != "missingDecryption" { object["decryption"] = decryption }
        }
        try edited.write(to: fixture.recordURL(record.id))
        #expect(throws: CaseWorkError.invalidRecord) {
            try CaseWorkStore.loadExtraction(id: record.id, in: fixture.caseURL)
        }
        let audit = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        #expect(audit.checks.contains { $0.relativePath == "extractions/\(record.id.uuidString.lowercased()).json" && $0.code == "metadata.invalid" })
        #expect(try Data(contentsOf: fixture.recordURL(record.id)) == edited)
        #expect(try Data(contentsOf: fixture.source) == beforeSource)
    }

    @Test("Decryption history requires explicit allocated EFS unnamed DATA provenance")
    func encryptedSelectionRequired() async throws {
        let fixture = try await ExtractionHistoryFixture.make(encrypted: false)
        defer { fixture.remove() }
        #expect(throws: CaseWorkError.invalidRecord) {
            try ExtractionRecord.make(binding: fixture.binding, receipt: fixture.decryptedReceipt)
        }
        let outcome = await ExtractionHistoryPublication.publish(receipt: fixture.decryptedReceipt,
            binding: fixture.binding, in: fixture.caseURL)
        #expect(outcome == .failed(recordID: outcome.recordID, reason: .invalidRecord))
        #expect(outcome.record == nil && !outcome.historyIsConfirmed)
        #expect(try CaseWorkStore.loadExtraction(id: outcome.recordID, in: fixture.caseURL) == nil)
    }

    @Test("Publication attempts once and distinguishes precommit disk errors from committed history uncertainty",
        arguments: CasePersistenceCheckpoint.allCases)
    func persistenceOutcomes(_ checkpoint: CasePersistenceCheckpoint) async throws {
        let fixture = try await ExtractionHistoryFixture.make()
        defer { fixture.remove() }
        let old = try ExtractionRecord.make(binding: fixture.binding, receipt: fixture.decryptedReceipt)
        try CaseWorkStore.saveExtraction(old, in: fixture.caseURL)
        let oldBytes = try Data(contentsOf: fixture.recordURL(old.id))
        let sourceBytes = try Data(contentsOf: fixture.source), outputBytes = try Data(contentsOf: fixture.output)
        let manifestBytes = try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json"))
        let id = UUID(), attempts = ExtractionHistoryAttempts()
        let outcome = await ExtractionHistoryPublication.publishForTesting(receipt: fixture.decryptedReceipt,
            binding: fixture.binding, in: fixture.caseURL, id: id) { boundary, _ in
                if boundary == .beforeWrite { attempts.increment() }
                if boundary == checkpoint { throw POSIXError(.ENOSPC) }
            }
        #expect(attempts.count == 1)
        let committed = [.afterRename, .beforeDirectoryFlush, .afterDirectoryFlush].contains(checkpoint)
        if committed {
            guard case .publishedButDurabilityUnconfirmed(let record) = outcome else {
                Issue.record("An already-committed immutable record must report history uncertainty"); return
            }
            #expect(record.id == id && !outcome.historyIsConfirmed)
            #expect(try CaseWorkStore.loadExtraction(id: id, in: fixture.caseURL) == record)
        } else {
            #expect(outcome == .failed(recordID: id, reason: .storageFailure))
            #expect(outcome.record == nil)
            #expect(try CaseWorkStore.loadExtraction(id: id, in: fixture.caseURL) == nil)
        }
        #expect(try Data(contentsOf: fixture.recordURL(old.id)) == oldBytes)
        #expect(try Data(contentsOf: fixture.source) == sourceBytes)
        #expect(try Data(contentsOf: fixture.output) == outputBytes)
        #expect(try Data(contentsOf: fixture.caseURL.appendingPathComponent("manifest.json")) == manifestBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.caseURL.appendingPathComponent("extractions").path)
            .allSatisfy { !$0.hasSuffix(".tmp") })
    }

    @Test("A late cancellation drains accepted history under the same admission and keeps the published output")
    func lateCancellation() async throws {
        let fixture = try await ExtractionHistoryFixture.make()
        defer { fixture.remove() }
        let gate = ExtractionHistoryGate(), scheduler = ForensicWorkScheduler()
        let permit = try await scheduler.acquireImmediately(.extraction)
        let id = UUID()
        let task = Task {
            try await permit.runToCompletion {
                await ExtractionHistoryPublication.publishForTesting(receipt: fixture.decryptedReceipt,
                    binding: fixture.binding, in: fixture.caseURL, id: id) { boundary, _ in
                        if boundary == .beforeRename { try gate.pause() }
                    }
            }
        }
        #expect(await gate.waitUntilEntered())
        let before = await scheduler.state()
        #expect(before.active?.id == permit.admission.id)
        task.cancel()
        #expect(await scheduler.state().active?.id == permit.admission.id)
        gate.release()
        let outcome = try await task.value
        #expect(outcome.historyIsConfirmed)
        #expect(outcome.recordID == id)
        #expect(try CaseWorkStore.loadExtraction(id: id, in: fixture.caseURL) == outcome.record)
        #expect(try Data(contentsOf: fixture.output) == Data("abc".utf8))
        #expect(try Data(contentsOf: fixture.source) == ExtractionHistoryFixture.sourceBytes)
        #expect(await permit.release())
        #expect(await scheduler.state().active == nil)
    }

    @Test("An existing UUID is never retried, replaced or assigned a second history record")
    func immutableDuplicate() async throws {
        let fixture = try await ExtractionHistoryFixture.make()
        defer { fixture.remove() }
        let id = UUID(), instant = Date(timeIntervalSinceReferenceDate: 813_457_690.25)
        let first = await ExtractionHistoryPublication.publish(receipt: fixture.decryptedReceipt,
            binding: fixture.binding, in: fixture.caseURL, id: id, verifiedAt: instant)
        #expect(first.historyIsConfirmed)
        let before = try Data(contentsOf: fixture.recordURL(id))
        let second = await ExtractionHistoryPublication.publish(receipt: fixture.decryptedReceipt,
            binding: fixture.binding, in: fixture.caseURL, id: id, verifiedAt: instant)
        #expect(second == .failed(recordID: id, reason: .recordAlreadyExists))
        #expect(try Data(contentsOf: fixture.recordURL(id)) == before)
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.caseURL.appendingPathComponent("extractions").path)
            == [id.uuidString.lowercased() + ".json"])
    }
}

private struct LegacyExtractionRecord: Encodable {
    let schemaVersion: Int; let id: UUID; let createdAt: Date; let binding: CaseWorkBinding
    let outputHash: AssistantScopedHash; let outputByteCount: Int64; let verificationDescription: String
}

private struct ExtractionHistoryFixture: Sendable {
    static let sourceBytes = Data("synthetic immutable container".utf8)
    // Independent standard SHA-256 vector for the exact published abc bytes.
    static let plaintextSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    let directory: URL; let source: URL; let output: URL; let forensicCase: ForensicCase
    let evidence: EvidenceRecord; let file: FilesystemEntry; let result: EnumerationResult; let binding: CaseWorkBinding
    var caseURL: URL { forensicCase.bundleURL }
    var decryptedReceipt: ExtractionResult {
        ExtractionResult(outputPath: output.path, byteCount: 3, sha256: Self.plaintextSHA256,
            contentStatus: "decrypted-content", warnings: [ExtractionDecryptionReceipt.unauthenticatedPlaintextWarning],
            decryption: ExtractionDecryptionReceipt(profile: "ntfs-efs-rsa-pkcs1-aes256-der", recipientRole: .drf,
                metadataSHA256: String(repeating: "a", count: 64), certificateSHA1: String(repeating: "b", count: 40),
                ciphertextSHA256: String(repeating: "c", count: 64), ciphertextBytes: 512, unitBytes: 512,
                authenticatedPlaintext: false))
    }
    static func make(schemaVersion: Int = 1, encrypted: Bool = true, deleted: Bool = false) async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ExtractionHistoryTests-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            let source = directory.appendingPathComponent("private-source.dd"), output = directory.appendingPathComponent("private-user-export")
            try sourceBytes.write(to: source); try Data("abc".utf8).write(to: output)
            let created = try CaseStore.create(name: "Synthetic Extraction", in: directory)
            let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
            var forensicCase = try CaseStore.adding(image: inspected, to: created)
            if schemaVersion == 2 { forensicCase = try CaseStore.migrateToSchema2(forensicCase) }
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let file = FilesystemEntry(id: "0:24:128:0", path: "/encrypted.txt", name: "encrypted.txt",
                fsOffsetBytes: 0, metaAddress: 24, attributeType: 128, attributeID: 0, size: 3,
                isDirectory: false, isDeleted: deleted,
                encryptionStatus: encrypted ? .ntfsEFSEncrypted : nil, attributeName: "")
            let result = EnumerationResult(engineVersion: "efs-history-synthetic", patchDigest: "synthetic-original-component",
                sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256],
                options: EngineOptions(timezone: "Asia/Bangkok"),
                image: EngineImageMetadata(imageType: "raw", logicalSize: Int64(sourceBytes.count), sectorSize: 512,
                    logicalSha256: String(repeating: "d", count: 64)), volumes: [], files: [file], warnings: [],
                status: .completed, savedAt: Date(timeIntervalSinceReferenceDate: 813_457_680.25))
            let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: file)
            return Self(directory: directory, source: source, output: output, forensicCase: forensicCase,
                evidence: evidence, file: file, result: result, binding: binding)
        } catch { try? FileManager.default.removeItem(at: directory); throw error }
    }
    func recordURL(_ id: UUID) -> URL {
        caseURL.appendingPathComponent("extractions").appendingPathComponent(id.uuidString.lowercased() + ".json")
    }
    func edit(_ data: Data, mutation: (inout [String: Any]) throws -> Void) throws -> Data {
        var object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        try mutation(&object)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
}

private final class ExtractionHistoryAttempts: @unchecked Sendable {
    private let lock = NSLock(); private var value = 0
    func increment() { lock.lock(); defer { lock.unlock() }; value += 1 }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

private final class ExtractionHistoryGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false, released = false
    func pause() throws {
        condition.lock(); defer { condition.unlock() }
        entered = true
        let deadline = Date().addingTimeInterval(5)
        while !released {
            guard condition.wait(until: deadline) else { throw POSIXError(.ETIMEDOUT) }
        }
    }
    private var hasEntered: Bool { condition.lock(); defer { condition.unlock() }; return entered }
    func waitUntilEntered() async -> Bool {
        for _ in 0..<500 {
            if hasEntered { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return false
    }
    func release() { condition.lock(); released = true; condition.broadcast(); condition.unlock() }
}
