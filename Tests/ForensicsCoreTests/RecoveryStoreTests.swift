import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@_silgen_name("flock")
private func recoveryTestFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

struct RecoveryStoreTests {
    @Test("Immutable recovery generations survive source-offline reopen and preserve exact bytes")
    func roundTripAndOfflineReopen() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let before = try Data(contentsOf: fixture.manifestURL)
        let result = fixture.result(date: Date(timeIntervalSinceReferenceDate: 812_345_678.1234567))
        try fixture.save(result)
        #expect(try RecoveryResultStore.load(jobID: result.jobID, evidenceID: fixture.evidence.id,
            in: fixture.caseURL) == result)
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.caseURL) == result)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: fixture.manifestURL) == before)
        try FileManager.default.removeItem(at: fixture.source)
        let reopened = try CaseStore.open(at: fixture.caseURL)
        let artifact = try #require(result.artifacts.first)
        #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
            in: reopened.bundleURL, maximumBytes: 1_024) == fixture.payloadBytes)
        let url = try RecoveryResultStore.artifactURL(artifact: artifact, result: result, in: reopened.bundleURL)
        #expect(try FileAccess.identity(at: url) == FileAccess.identity(at: fixture.payloadURL(result)))
        #expect(try Data(contentsOf: url) == fixture.payloadBytes)
        let json = String(decoding: try Data(contentsOf: fixture.resultURL(result)), as: UTF8.self)
        #expect(!json.contains(fixture.source.path))
        #expect(!json.contains(fixture.caseURL.path))
        #expect(artifact.hashScope == "recovered-file-bytes")
        #expect(artifact.deletionStatus == "unknown")
    }

    @Test("Export verifies recovered bytes and exclusively publishes a new file")
    func verifiedExport() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(); try fixture.save(result)
        let artifact = try #require(result.artifacts.first)
        let destination = fixture.root.appendingPathComponent("examiner-export.png")
        let receipt = try RecoveryResultStore.export(artifact: artifact, result: result, in: fixture.caseURL, to: destination)
        #expect(receipt.byteCount == Int64(fixture.payloadBytes.count))
        #expect(receipt.sha256 == RecoveryStoreFixture.hash(fixture.payloadBytes))
        #expect(try Data(contentsOf: destination) == fixture.payloadBytes)
        #expect(throws: RecoveryError.destinationExists) {
            try RecoveryResultStore.export(artifact: artifact, result: result, in: fixture.caseURL, to: destination)
        }
        #expect(try Data(contentsOf: destination) == fixture.payloadBytes)
        #expect(throws: RecoveryError.scopeMismatch) {
            try RecoveryResultStore.export(artifact: artifact, result: result, in: fixture.caseURL, to: fixture.source)
        }
        #expect(throws: RecoveryError.scopeMismatch) {
            try RecoveryResultStore.export(artifact: artifact, result: result, in: fixture.caseURL,
                to: fixture.caseURL.appendingPathComponent("unsafe-export"))
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.caseURL.appendingPathComponent("unsafe-export").path))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Saved case payloads cannot become inputs to another recovery generation")
    func caseInternalCandidateRefused() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let original = fixture.result(); try fixture.save(original)
        let next = fixture.result()
        #expect(throws: RecoveryError.scopeMismatch) {
            try RecoveryResultStore.save(result: next, artifactFiles: [fixture.artifactID: fixture.payloadURL(original)],
                in: fixture.forensicCase)
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.generationURL(next).path))
        #expect(try Data(contentsOf: fixture.payloadURL(original)) == fixture.payloadBytes)
    }

    @Test("Verified macOS /var system alias works for temporary case, candidate and export paths")
    func systemTemporaryAlias() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        func alias(_ url: URL) -> URL {
            let path = url.path.hasPrefix("/private/var/") ? String(url.path.dropFirst("/private".count)) : url.path
            return URL(fileURLWithPath: path, isDirectory: url.hasDirectoryPath)
        }
        let aliasedCase = ForensicCase(bundleURL: alias(fixture.caseURL), manifest: fixture.forensicCase.manifest)
        let result = fixture.result()
        try RecoveryResultStore.save(result: result, artifactFiles: [fixture.artifactID: alias(fixture.input)], in: aliasedCase)
        #expect(try RecoveryResultStore.load(jobID: result.jobID, evidenceID: fixture.evidence.id,
            in: aliasedCase.bundleURL) == result)
        let artifact = try #require(result.artifacts.first)
        #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
            in: aliasedCase.bundleURL, maximumBytes: 1_024) == fixture.payloadBytes)
        let destination = alias(fixture.root.appendingPathComponent("alias-export.png"))
        let receipt = try RecoveryResultStore.export(artifact: artifact, result: result, in: aliasedCase.bundleURL, to: destination)
        #expect(try Data(contentsOf: URL(fileURLWithPath: receipt.outputPath)) == fixture.payloadBytes)
    }

    @Test("Publishing the same job UUID preserves the first complete generation")
    func duplicateGeneration() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(); try fixture.save(result)
        let first = try Data(contentsOf: fixture.resultURL(result))
        #expect(throws: RecoveryError.destinationExists) { try fixture.save(result) }
        #expect(try Data(contentsOf: fixture.resultURL(result)) == first)
        #expect(try Data(contentsOf: fixture.payloadURL(result)) == fixture.payloadBytes)
        #expect(try fixture.generationNames() == [result.jobID.uuidString.lowercased()])
    }

    @Test("Cancellation exactly after export rename returns its committed receipt and preserves bytes")
    func exportCancellationAfterCommit() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(); try fixture.save(result)
        let artifact = try #require(result.artifacts.first)
        let destination = fixture.root.appendingPathComponent("committed-export.png")
        let worker = Task.detached {
            let receipt = try RecoveryResultStore.export(artifact: artifact, result: result,
                in: fixture.caseURL, to: destination, afterPublication: {
                    withUnsafeCurrentTask { task in task?.cancel() }
                })
            return (receipt, Task.isCancelled)
        }
        let (receipt, cancelled) = try await worker.value
        #expect(cancelled)
        #expect(try FileAccess.identity(at: URL(fileURLWithPath: receipt.outputPath)) == FileAccess.identity(at: destination))
        #expect(receipt.sha256 == RecoveryStoreFixture.hash(fixture.payloadBytes))
        #expect(try Data(contentsOf: destination) == fixture.payloadBytes)
        #expect(try Data(contentsOf: fixture.payloadURL(result)) == fixture.payloadBytes)
    }

    @Test("Candidate bytes are checked before publication; a failed copy leaves no complete generation")
    func wrongInputBytes() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        try Data(repeating: 0x41, count: fixture.payloadBytes.count).write(to: fixture.input)
        #expect(throws: RecoveryError.artifactChanged) { try fixture.save(result) }
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.caseURL) == nil)
        #expect(try fixture.generationNames().isEmpty)
    }

    @Test("Untrusted input symlinks are refused without modifying their targets", arguments: [false, true])
    func symlinkInput(_ intermediate: Bool) async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        let alias = fixture.root.appendingPathComponent(intermediate ? "input-directory-alias" : "input-leaf-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: intermediate ? fixture.root : fixture.input)
        let supplied = intermediate ? alias.appendingPathComponent(fixture.input.lastPathComponent) : alias
        #expect(throws: RecoveryError.storageChanged) {
            try RecoveryResultStore.save(result: result, artifactFiles: [fixture.artifactID: supplied], in: fixture.forensicCase)
        }
        #expect(try Data(contentsOf: fixture.input) == fixture.payloadBytes)
        #expect(try fixture.generationNames().isEmpty)
    }

    @Test("Recovery directory symlinks do not redirect writes outside the case")
    func symlinkStorage() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent("keep")
        try Data("preserved".utf8).write(to: sentinel)
        try FileManager.default.createSymbolicLink(at: fixture.caseURL.appendingPathComponent("recovery"), withDestinationURL: outside)
        #expect(throws: RecoveryError.storageChanged) { try fixture.save(fixture.result()) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path) == ["keep"])
        #expect(try Data(contentsOf: sentinel) == Data("preserved".utf8))
    }

    @Test("Same-size stored-byte tampering fails every byte access route", arguments: ["read", "url", "export"])
    func storedTampering(_ mode: String) async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(); try fixture.save(result)
        let artifact = try #require(result.artifacts.first)
        try Data(repeating: 0x55, count: fixture.payloadBytes.count).write(to: fixture.payloadURL(result))
        #expect(throws: RecoveryError.artifactChanged) {
            switch mode {
            case "url":
                _ = try RecoveryResultStore.artifactURL(artifact: artifact, result: result, in: fixture.caseURL)
            case "export":
                _ = try RecoveryResultStore.export(artifact: artifact, result: result, in: fixture.caseURL,
                    to: fixture.root.appendingPathComponent("rejected-export"))
            default:
                _ = try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
                    in: fixture.caseURL, maximumBytes: 1_024)
            }
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("rejected-export").path))
    }

    @Test("Missing, symlinked, extra and resized stored payloads are diagnostic errors", arguments: ["missing", "symlink", "extra", "resized"])
    func unsafeStoredPayload(_ mode: String) async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(); try fixture.save(result)
        let url = fixture.payloadURL(result)
        switch mode {
        case "missing": try FileManager.default.removeItem(at: url)
        case "symlink":
            try FileManager.default.removeItem(at: url)
            try FileManager.default.createSymbolicLink(at: url, withDestinationURL: fixture.input)
        case "extra": try Data("unknown".utf8).write(to: url.deletingLastPathComponent().appendingPathComponent("unexpected"))
        default: try Data("short".utf8).write(to: url)
        }
        #expect(throws: (any Error).self) {
            _ = try RecoveryResultStore.load(jobID: result.jobID, evidenceID: fixture.evidence.id, in: fixture.caseURL)
        }
        #expect(throws: (any Error).self) {
            _ = try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.caseURL)
        }
        #expect(try Data(contentsOf: fixture.input) == fixture.payloadBytes)
    }

    @Test("A corrupt newest generation is reported rather than silently falling back")
    func corruptLatest() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let older = fixture.result(date: Date(timeIntervalSince1970: 100)); try fixture.save(older)
        let newer = fixture.result(date: Date(timeIntervalSince1970: 200)); try fixture.save(newer)
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.caseURL) == newer)
        try Data("{ broken JSON".utf8).write(to: fixture.resultURL(newer))
        #expect(throws: RecoveryError.invalidResult) {
            _ = try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.caseURL)
        }
        #expect(try RecoveryResultStore.load(jobID: older.jobID, evidenceID: fixture.evidence.id,
            in: fixture.caseURL) == older)
    }

    @Test("Metadata or manifest evidence binding mismatches cannot access historical bytes")
    func provenanceMismatch() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(); try fixture.save(result)
        let mismatched = fixture.result(jobID: result.jobID, sourceHash: String(repeating: "f", count: 64))
        #expect(throws: RecoveryError.scopeMismatch) { try fixture.save(mismatched) }
        let artifact = try #require(result.artifacts.first)
        #expect(throws: RecoveryError.scopeMismatch) {
            _ = try RecoveryResultStore.readArtifact(artifact: artifact, result: mismatched,
                in: fixture.caseURL, maximumBytes: 1_024)
        }
        let different = CarvedArtifact(id: artifact.id, filename: "changed.png", relativePath: artifact.relativePath,
            formatHint: artifact.formatHint, byteCount: artifact.byteCount, sha256: artifact.sha256,
            reportedByteRuns: artifact.reportedByteRuns, verifiedByteRuns: artifact.verifiedByteRuns,
            validationStatus: artifact.validationStatus)
        #expect(throws: RecoveryError.scopeMismatch) {
            _ = try RecoveryResultStore.artifactURL(artifact: different, result: result, in: fixture.caseURL)
        }
    }

    @Test("Explicit read bounds and complete artifact-file mappings are enforced")
    func limitsAndMappings() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        #expect(throws: RecoveryError.scopeMismatch) {
            try RecoveryResultStore.save(result: result, artifactFiles: [:], in: fixture.forensicCase)
        }
        try fixture.save(result)
        let artifact = try #require(result.artifacts.first)
        #expect(throws: RecoveryError.outputLimit) {
            _ = try RecoveryResultStore.readArtifact(artifact: artifact, result: result, in: fixture.caseURL,
                maximumBytes: artifact.byteCount - 1)
        }
        #expect(throws: RecoveryError.outputLimit) {
            _ = try RecoveryResultStore.readArtifact(artifact: artifact, result: result, in: fixture.caseURL, maximumBytes: -1)
        }
    }

    @Test("Cancellation leaves a busy shared case lock promptly without publishing recovery")
    func cancellationAtCaseLock() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let descriptor = Darwin.open(fixture.caseURL.appendingPathComponent(".case.lock").path, O_RDONLY | O_CLOEXEC)
        #expect(descriptor >= 0)
        guard descriptor >= 0 else { return }
        defer { _ = recoveryTestFlock(descriptor, LOCK_UN); Darwin.close(descriptor) }
        #expect(recoveryTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
        let result = fixture.result()
        let worker = Task.detached { try fixture.save(result) }
        worker.cancel()
        do { try await worker.value; Issue.record("Cancelled save unexpectedly published a generation") }
        catch { #expect(error is CancellationError) }
        #expect(!FileManager.default.fileExists(atPath: fixture.generationURL(result).path))
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Live source validation runs after candidate copying and can refuse atomic publication")
    func publicationValidationBoundary() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        let marker = fixture.root.appendingPathComponent("publication-validated")
        #expect(throws: RecoveryError.sourceChanged) {
            try RecoveryResultStore.save(result: result, artifactFiles: [fixture.artifactID: fixture.input],
                in: fixture.forensicCase, prePublicationValidation: {
                    let names = try fixture.generationNames()
                    guard names.count == 1, let staging = names.first, staging.hasPrefix(".recovery-"),
                          staging.hasSuffix(".tmp") else { throw RecoveryError.invalidResult }
                    let directory = fixture.generationURL(result).deletingLastPathComponent().appendingPathComponent(staging)
                    guard try Data(contentsOf: directory.appendingPathComponent("files")
                        .appendingPathComponent(fixture.artifactID.uuidString.lowercased())) == fixture.payloadBytes,
                          FileManager.default.fileExists(atPath: directory.appendingPathComponent("result.json").path) else {
                        throw RecoveryError.invalidResult
                    }
                    try Data("checked complete staged generation".utf8).write(to: marker)
                    throw RecoveryError.sourceChanged
                })
        }
        #expect(try Data(contentsOf: marker) == Data("checked complete staged generation".utf8))
        #expect(try fixture.generationNames().isEmpty)
        #expect(try RecoveryResultStore.latest(evidenceID: fixture.evidence.id, in: fixture.caseURL) == nil)
    }

    @Test("Source mutation while queued on the case lock is caught by publication revalidation")
    func sourceMutationWhileQueued() async throws {
        let fixture = try await RecoveryStoreFixture.make()
        defer { fixture.remove() }
        let descriptor = Darwin.open(fixture.caseURL.appendingPathComponent(".case.lock").path, O_RDONLY | O_CLOEXEC)
        #expect(descriptor >= 0)
        guard descriptor >= 0 else { return }
        defer { _ = recoveryTestFlock(descriptor, LOCK_UN); Darwin.close(descriptor) }
        #expect(recoveryTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
        let result = fixture.result()
        let worker = Task.detached {
            try RecoveryResultStore.save(result: result, artifactFiles: [fixture.artifactID: fixture.input],
                in: fixture.forensicCase, prePublicationValidation: {
                    guard RecoveryStoreFixture.hash(try Data(contentsOf: fixture.source)) == result.sourceSHA256 else {
                        throw RecoveryError.sourceChanged
                    }
                })
        }
        try Data(repeating: 0x42, count: fixture.sourceBytes.count).write(to: fixture.source)
        #expect(recoveryTestFlock(descriptor, LOCK_UN) == 0)
        do { try await worker.value; Issue.record("Changed evidence was unexpectedly published") }
        catch { #expect((error as? RecoveryError) == .sourceChanged) }
        #expect(try fixture.generationNames().isEmpty)
    }
}

private struct RecoveryStoreFixture: Sendable {
    let root: URL
    let source: URL
    let sourceBytes: Data
    let input: URL
    let payloadBytes: Data
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let artifactID: UUID
    var caseURL: URL { forensicCase.bundleURL }
    var manifestURL: URL { caseURL.appendingPathComponent("manifest.json") }

    static func make() async throws -> Self {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("RecoveryStoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            let source = root.appendingPathComponent("synthetic.dd")
            let sourceBytes = Data(repeating: 0x32, count: 8_192)
            try sourceBytes.write(to: source)
            let image = try await ImageInspector.inspect(url: source) { _ in }
            let created = try CaseStore.create(name: "Recovery", in: root)
            let forensicCase = try CaseStore.adding(image: image, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let input = root.appendingPathComponent("input-candidate")
            let payloadBytes = Data("PNG candidate\nIndependent logical recovered bytes\n".utf8)
            try payloadBytes.write(to: input)
            return Self(root: root, source: source, sourceBytes: sourceBytes, input: input,
                payloadBytes: payloadBytes, forensicCase: forensicCase, evidence: evidence, artifactID: UUID())
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }

    func result(jobID: UUID = UUID(), date: Date = Date(), sourceHash: String? = nil) -> CarvingResult {
        let artifact = CarvedArtifact(id: artifactID, filename: "recovered.png",
            relativePath: "files/\(artifactID.uuidString.lowercased())", formatHint: "png",
            byteCount: Int64(payloadBytes.count), sha256: Self.hash(payloadBytes), reportedByteRuns: [],
            verifiedByteRuns: [], validationStatus: .unverified, warnings: ["Source extents unavailable"])
        return CarvingResult(caseID: forensicCase.manifest.id, sourceEvidenceID: evidence.id,
            sourceSHA256: sourceHash ?? evidence.sha256, sourceByteCount: evidence.byteCount,
            jobID: jobID, status: .completed, artifacts: [artifact], warnings: [], photoRecVersion: "synthetic-test",
            executableSHA256: String(repeating: "a", count: 64), options: RecoveryOptions(), savedAt: date)
    }

    func save(_ result: CarvingResult) throws {
        try RecoveryResultStore.save(result: result, artifactFiles: [artifactID: input], in: forensicCase)
    }
    func generationURL(_ result: CarvingResult) -> URL {
        caseURL.appendingPathComponent("recovery").appendingPathComponent(evidence.id.uuidString.lowercased())
            .appendingPathComponent(result.jobID.uuidString.lowercased())
    }
    func resultURL(_ result: CarvingResult) -> URL { generationURL(result).appendingPathComponent("result.json") }
    func payloadURL(_ result: CarvingResult) -> URL { generationURL(result).appendingPathComponent("files").appendingPathComponent(artifactID.uuidString.lowercased()) }
    func generationNames() throws -> [String] {
        let directory = caseURL.appendingPathComponent("recovery").appendingPathComponent(evidence.id.uuidString.lowercased())
        if !FileManager.default.fileExists(atPath: directory.path) { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
