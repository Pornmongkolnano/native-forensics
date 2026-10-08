import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@_silgen_name("flock")
private func legacyCacheTestFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

struct EngineLegacyCacheRecoveryTests {
    @Test("Exact latest legacy projection restores its historical binding without opening offline sources",
        arguments: [813_150_755.456666, -0.25, 813_150_756.0.nextDown])
    func exactLegacyBindingWithOfflineSources(_ referenceSeconds: Double) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let original = fixture.result(referenceSeconds: referenceSeconds,
            status: referenceSeconds < 0 ? .partial : .completed)
        let jobID = UUID()
        _ = try fixture.save(original, id: jobID)
        let cacheBytes = try fixture.installLegacyCache(original)
        let binding = try fixture.binding(original)
        let history = try ExtractionRecord.make(binding: binding,
            receipt: .init(outputPath: "synthetic-export-only", byteCount: 3,
                sha256: LegacyCacheFixture.sourceSHA256, contentStatus: "logical-content"))
        try CaseWorkStore.saveExtraction(history, in: fixture.caseURL)
        try FileManager.default.removeItem(at: fixture.source)
        try FileManager.default.removeItem(at: fixture.segment)
        let before = try fixture.snapshot()
        let observations = LegacyCacheReadObservations()

        let loaded = try #require(try EngineResultStore.loadForTesting(
            evidenceID: fixture.evidence.id, in: fixture.caseURL,
            checkpoint: { observations.record($0) }))

        #expect(loaded == original)
        #expect(loaded.savedAt.timeIntervalSinceReferenceDate == referenceSeconds)
        #expect(try fixture.binding(loaded) == binding)
        #expect(try fixture.binding(loaded).snapshotSHA256 == binding.snapshotSHA256)
        #expect(observations.contains(.didReadArtifact))
        #expect(observations.contains(.beforeReturn))
        #expect(try fixture.snapshot() == before)
        #expect(try Data(contentsOf: fixture.cacheURL) == cacheBytes)
        #expect(!FileManager.default.fileExists(atPath: fixture.source.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.segment.path))
        #expect(try CaseWorkStore.loadExtraction(id: history.id, in: fixture.caseURL) == history)
    }

    @Test("Unavailable or mismatching complete job proof preserves the valid legacy projection",
        arguments: [
            "schema1", "noJob", "artifactMetadataAbsent", "artifactAbsent", "artifactDirectoryAbsent",
            "artifactSizeUnknown", "artifactSizeChanged", "artifactHashChanged", "invalidArtifact",
            "componentIdentifier", "componentVersion", "componentBuild", "options", "warnings",
            "sourceOrdinal", "orderedSourceHash", "status", "completedAt", "producerPath"
        ])
    func missingOrMismatchingProof(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make(migrate: mode != "schema1")
        defer { fixture.remove() }
        let original = fixture.result()
        let id = UUID()
        if mode == "schema1" || mode == "noJob" {
            try EngineResultStore.save(result: original, evidenceID: fixture.evidence.id, in: fixture.caseURL)
        } else {
            _ = try fixture.save(original, id: id)
        }
        let cacheBytes = try fixture.installLegacyCache(original)
        switch mode {
        case "artifactAbsent":
            try FileManager.default.removeItem(at: fixture.artifactURL(id))
        case "artifactDirectoryAbsent":
            try FileManager.default.removeItem(at: fixture.jobsURL)
        case "invalidArtifact":
            let invalid = Data("synthetic incomplete listing".utf8)
            try invalid.write(to: fixture.artifactURL(id))
            try fixture.editLastJob { job in
                job["artifactSHA256"] = LegacyCacheFixture.hash(invalid)
                job["artifactByteCount"] = invalid.count
            }
        case "producerPath":
            let otherID = UUID()
            try FileManager.default.copyItem(at: fixture.artifactURL(id), to: fixture.artifactURL(otherID))
            try fixture.editLastJob { $0["artifactRelativePath"] = fixture.artifactPath(otherID) }
        case "schema1", "noJob":
            break
        default:
            try fixture.editLastJob { job in
                switch mode {
                case "artifactMetadataAbsent":
                    job.removeValue(forKey: "artifactRelativePath")
                    job.removeValue(forKey: "artifactSHA256")
                    job.removeValue(forKey: "artifactByteCount")
                case "artifactSizeUnknown":
                    job.removeValue(forKey: "artifactByteCount")
                case "artifactSizeChanged":
                    job["artifactByteCount"] = (try #require(job["artifactByteCount"] as? Int)) + 1
                case "artifactHashChanged":
                    job["artifactSHA256"] = String(repeating: "a", count: 64)
                case "componentIdentifier", "componentVersion", "componentBuild":
                    var component = try #require(job["component"] as? [String: Any])
                    let key = mode == "componentIdentifier" ? "identifier" :
                        (mode == "componentVersion" ? "version" : "buildDigest")
                    component[key] = "different-synthetic-component"
                    job["component"] = component
                case "options":
                    let string = try #require(job["optionsJSON"] as? String)
                    var options = try LegacyCacheFixture.object(Data(string.utf8))
                    options["maxFiles"] = 32
                    let bytes = try LegacyCacheFixture.canonicalJSON(options)
                    job["optionsJSON"] = String(decoding: bytes, as: UTF8.self)
                    job["optionsSHA256"] = LegacyCacheFixture.hash(bytes)
                case "warnings":
                    job["warnings"] = ["A different synthetic warning."]
                case "sourceOrdinal":
                    // Both synthetic inputs contain the independently known
                    // same bytes, keeping the manifest valid while changing order.
                    job["selectedSourceOrdinal"] = 1
                case "orderedSourceHash":
                    var hashes = try #require(job["sourceHashes"] as? [[String: Any]])
                    hashes[1]["sha256"] = String(repeating: "a", count: 64)
                    job["sourceHashes"] = hashes
                case "status":
                    job["status"] = "partial"
                case "completedAt":
                    job["completedAt"] = original.savedAt.timeIntervalSinceReferenceDate + 0.125
                default:
                    throw LegacyCacheTestFailure.unsupportedMode
                }
            }
        }
        // Establish that refusal tests concern optional recovery proof rather
        // than a corrupt case manifest.
        _ = try CaseStore.open(at: fixture.caseURL)
        let before = try fixture.snapshot()
        let loaded = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))

        #expect(loaded == (try fixture.decodeLegacy(cacheBytes)))
        #expect(loaded.savedAt != original.savedAt)
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourcesUnchanged()
    }

    @Test("The final matching enumeration cannot be bypassed by an older matching artifact",
        arguments: ["rows", "options", "artifactAbsent", "artifactSizeUnknown", "artifactMetadataAbsent", "reverseCompletionOrder"])
    func newerJobPreventsOlderFallback(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let original = fixture.result(referenceSeconds: 813_150_756.75)
        let oldID = UUID(), newID = UUID()
        _ = try fixture.save(original, id: oldID)
        var options = original.options
        if mode == "options" { options.maxFiles = 32 }
        let later = fixture.result(marker: mode == "options" ? "ONE" : "TWO",
            referenceSeconds: mode == "reverseCompletionOrder" ? 813_150_755.25 : 813_150_757.25,
            options: options)
        _ = try fixture.save(later, id: newID)
        let cacheBytes = try fixture.installLegacyCache(original)
        if mode == "artifactAbsent" {
            try FileManager.default.removeItem(at: fixture.artifactURL(newID))
        } else if mode == "artifactSizeUnknown" {
            try fixture.editLastJob { _ = $0.removeValue(forKey: "artifactByteCount") }
        } else if mode == "artifactMetadataAbsent" {
            try fixture.editLastJob { job in
                job.removeValue(forKey: "artifactRelativePath")
                job.removeValue(forKey: "artifactSHA256")
                job.removeValue(forKey: "artifactByteCount")
            }
        }
        let before = try fixture.snapshot()
        let loaded = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))

        #expect(loaded == (try fixture.decodeLegacy(cacheBytes)))
        #expect(loaded.savedAt != original.savedAt)
        #expect(loaded.files == original.files)
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Append order selects the final exact artifact even when fractional completion dates run backward")
    func finalJobWinsIdenticalLegacyProjection() async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let original = fixture.result(referenceSeconds: 813_150_755.875)
        let final = fixture.result(referenceSeconds: 813_150_755.125)
        _ = try fixture.save(original, id: UUID())
        _ = try fixture.save(final, id: UUID())
        let originalProjection = try fixture.legacyBytes(original)
        #expect(try fixture.legacyBytes(final) == originalProjection)
        try originalProjection.write(to: fixture.cacheURL)
        let before = try fixture.snapshot()

        let loaded = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))

        #expect(loaded == final)
        #expect(loaded.savedAt != original.savedAt)
        #expect(try fixture.binding(loaded) == fixture.binding(final))
        #expect(try fixture.snapshot() == before)
    }

    @Test("A later job for another evidence does not displace this evidence's final enumeration")
    func laterUnrelatedEvidenceJob() async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let original = fixture.result()
        _ = try fixture.save(original, id: UUID())
        _ = try fixture.save(fixture.result(marker: "OTHER", referenceSeconds: 813_150_760.5,
            selectedSourceFirst: false), id: UUID(), evidenceID: fixture.segmentEvidence.id)
        _ = try fixture.installLegacyCache(original)
        let before = try fixture.snapshot()

        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == original)
        #expect(try fixture.snapshot() == before)
    }

    @Test("Recovery requires all legacy cache bytes, including formatting and historical metadata",
        arguments: ["whitespace", "unknownMember", "sourceIdentity", "warning", "fileMetadata"])
    func fullLegacyBytesRequired(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let original = fixture.result()
        _ = try fixture.save(original, id: UUID())
        let originalBytes = try fixture.installLegacyCache(original)
        let modified: Data
        if mode == "whitespace" {
            modified = originalBytes + Data("\n".utf8)
        } else {
            var object = try LegacyCacheFixture.object(originalBytes)
            switch mode {
            case "unknownMember":
                object["unrecognizedSyntheticMember"] = "preserve these disk bytes"
            case "sourceIdentity":
                var identities = try #require(object["sourceIdentities"] as? [[String: Any]])
                let inode = try #require(identities[1]["inode"] as? NSNumber)
                identities[1]["inode"] = inode.uint64Value + 1
                object["sourceIdentities"] = identities
            case "warning":
                object["warnings"] = ["A changed recorded warning."]
            case "fileMetadata":
                var files = try #require(object["files"] as? [[String: Any]])
                files[0]["modifiedEpoch"] = 1_700_000_001
                object["files"] = files
            default:
                throw LegacyCacheTestFailure.unsupportedMode
            }
            modified = try LegacyCacheFixture.canonicalJSON(object)
        }
        try modified.write(to: fixture.cacheURL)
        let expected = try fixture.decodeLegacy(modified)
        let before = try fixture.snapshot()

        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == expected)
        #expect(try fixture.snapshot() == before)
        #expect(try Data(contentsOf: fixture.cacheURL) == modified)
    }

    @Test("Valid precision bypasses optional artifact recovery")
    func newPrecisionDoesNotInspectArtifact() async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        let id = UUID()
        _ = try fixture.save(result, id: id)
        try fixture.substitute(fixture.artifactURL(id), with: .symlink)
        let before = try fixture.snapshot()
        let observations = LegacyCacheReadObservations()

        #expect(try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id, in: fixture.caseURL,
            checkpoint: { observations.record($0) }) == result)
        #expect(!observations.contains(.didReadArtifact))
        #expect(try fixture.snapshot() == before)
    }

    @Test("A present invalid precision value is rejected without legacy recovery",
        arguments: ["null", "string", "differentSecond"])
    func invalidPresentPrecisionDoesNotRecover(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        _ = try fixture.save(result, id: UUID())
        var object = try LegacyCacheFixture.object(Data(contentsOf: fixture.cacheURL))
        switch mode {
        case "null": object["savedAtExactReferenceDate"] = NSNull()
        case "string": object["savedAtExactReferenceDate"] = "813150755.456666"
        default: object["savedAtExactReferenceDate"] = 813_150_756.456666
        }
        let bytes = try LegacyCacheFixture.canonicalJSON(object)
        try bytes.write(to: fixture.cacheURL)
        let before = try fixture.snapshot()
        let observations = LegacyCacheReadObservations()

        #expect(throws: (any Error).self) {
            try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id, in: fixture.caseURL,
                checkpoint: { observations.record($0) })
        }
        #expect(!observations.contains(.didReadArtifact))
        #expect(try fixture.snapshot() == before)
    }

    @Test("Unsafe metadata namespaces are errors rather than missing optional proof",
        arguments: [
            "artifact-symlink", "artifact-hardLink", "artifact-fifo", "artifact-directory",
            "jobs-symlink", "jobs-file", "cache-symlink", "cache-hardLink", "cache-fifo", "cache-directory",
            "cacheDirectory-symlink", "lock-symlink", "lock-hardLink", "lock-fifo", "lock-directory",
            "manifest-symlink", "manifest-hardLink", "manifest-fifo", "root-symlink"
        ])
    func unsafeNamespace(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        let id = UUID()
        _ = try fixture.save(result, id: id)
        _ = try fixture.installLegacyCache(result)
        let parts = mode.split(separator: "-", maxSplits: 1).map(String.init)
        let target = try fixture.target(parts[0], artifactID: id)
        let kind = try #require(LegacyCacheSubstitution(rawValue: parts[1]))
        try fixture.substitute(target, with: kind)
        let before = try fixture.snapshot()

        #expect(throws: (any Error).self) {
            try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL)
        }
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Pinned references detect same-byte replacements during the read transaction",
        arguments: [
            "manifestAfterManifest", "lockAfterManifest", "cacheAfterCache", "cacheDirectoryAfterCache",
            "rootAfterCache", "artifactAfterArtifact", "jobsAfterArtifact",
            "manifestBeforeReturn", "cacheBeforeReturn", "artifactBeforeReturn"
        ])
    func namespaceChangesDuringRead(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        let id = UUID()
        _ = try fixture.save(result, id: id)
        let cacheBytes = try fixture.installLegacyCache(result)
        let manifestBytes = try Data(contentsOf: fixture.manifestURL)
        let artifactBytes = try Data(contentsOf: fixture.artifactURL(id))
        let oneShot = LegacyCacheOneShot()

        #expect(throws: (any Error).self) {
            try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id, in: fixture.caseURL) { point in
                let matches: Bool
                switch point {
                case .didReadManifest: matches = mode.hasSuffix("AfterManifest")
                case .didReadCache: matches = mode.hasSuffix("AfterCache")
                case .didReadArtifact: matches = mode.hasSuffix("AfterArtifact")
                case .beforeReturn: matches = mode.hasSuffix("BeforeReturn")
                default: matches = false
                }
                guard matches, oneShot.claim() else { return }
                let target: String
                if mode.hasPrefix("manifest") { target = "manifest" }
                else if mode.hasPrefix("lock") { target = "lock" }
                else if mode.hasPrefix("cacheDirectory") { target = "cacheDirectory" }
                else if mode.hasPrefix("cache") { target = "cache" }
                else if mode.hasPrefix("artifact") { target = "artifact" }
                else if mode.hasPrefix("jobs") { target = "jobs" }
                else { target = "root" }
                try fixture.replaceWithSameBytes(try fixture.target(target, artifactID: id))
            }
        }

        #expect(oneShot.wasClaimed)
        #expect(try Data(contentsOf: fixture.manifestURL) == manifestBytes)
        #expect(try Data(contentsOf: fixture.cacheURL) == cacheBytes)
        #expect(try Data(contentsOf: fixture.artifactURL(id)) == artifactBytes)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Checkpoint cancellation and I/O failures propagate instead of becoming legacy fallback",
        arguments: ["cancel", "io"])
    func readFailuresPropagate(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        _ = try fixture.save(result, id: UUID())
        _ = try fixture.installLegacyCache(result)
        let before = try fixture.snapshot()
        let oneShot = LegacyCacheOneShot()
        var observed: (any Error)?
        do {
            _ = try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id, in: fixture.caseURL) { point in
                guard case .didReadArtifact = point, oneShot.claim() else { return }
                if mode == "cancel" { throw CancellationError() }
                throw LegacyCacheTestFailure.injectedReadFailure
            }
            Issue.record("A read checkpoint failure was swallowed.")
        } catch { observed = error }

        #expect(oneShot.wasClaimed)
        if mode == "cancel" { #expect(observed is CancellationError) }
        else { #expect(observed as? LegacyCacheTestFailure == .injectedReadFailure) }
        #expect(try fixture.snapshot() == before)
    }

    @Test("A cancelled reader drains while the owned case writer still holds exclusive admission")
    func cancellationWhileWaitingForCaseLock() async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        _ = try fixture.save(result, id: UUID())
        _ = try fixture.installLegacyCache(result)
        let before = try fixture.snapshot()
        let admission = try LegacyCacheExclusiveAdmission(fixture.lockURL)
        defer { admission.release() }
        let signal = LegacyCacheReadSignal()
        let observations = LegacyCacheReadObservations()
        let worker = Task.detached {
            try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id, in: fixture.caseURL) { point in
                observations.record(point)
                if case .waitingForCaseLock = point { signal.resolve(true) }
            }
        }
        // Failure guard releases owned admission so a broken cancellation path
        // cannot leave the test suite waiting on this test's descriptor.
        let guardTask = Task.detached {
            do { try await Task.sleep(for: .seconds(10)) }
            catch { return }
            admission.release()
            signal.resolve(false)
        }
        let observedAdmission = await signal.wait()
        worker.cancel()
        var observed: (any Error)?
        do {
            _ = try await worker.value
            Issue.record("A cancelled legacy reader returned a result.")
        } catch { observed = error }
        guardTask.cancel()
        await guardTask.value

        #expect(observedAdmission)
        #expect(observed is CancellationError)
        #expect(admission.isHeld)
        #expect(!observations.contains(.didReadManifest))
        #expect(!observations.contains(.didReadCache))
        admission.release()
        #expect(try fixture.snapshot() == before)
        // A subsequent call establishes that the cancelled reader released
        // its own resources without publishing any cache bytes.
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == result)
    }

    @Test("Optional artifact size mismatches preserve legacy precision without reading artifact bytes",
        arguments: ["differentCount", "oversizedActual", "oversizedDeclared"])
    func optionalArtifactSizeMismatchIsUnread(_ mode: String) async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        let id = UUID()
        _ = try fixture.save(result, id: id)
        let cacheBytes = try fixture.installLegacyCache(result)
        let artifact = fixture.artifactURL(id)
        if mode == "oversizedDeclared" {
            try fixture.editLastJob { $0["artifactByteCount"] = EngineValidation.resultLimit + 1 }
        } else {
            let originalSize = try FileAccess.identity(at: artifact).size
            let size = mode == "oversizedActual" ? Int64(EngineValidation.resultLimit) + 1 : originalSize + 1
            #expect(Darwin.truncate(artifact.path, off_t(size)) == 0)
        }
        _ = try CaseStore.open(at: fixture.caseURL)
        let before = try fixture.snapshot()
        let observations = LegacyCacheReadObservations()

        let loaded = try #require(try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id,
            in: fixture.caseURL, checkpoint: { observations.record($0) }))

        #expect(loaded == (try fixture.decodeLegacy(cacheBytes)))
        #expect(!observations.contains(.didReadArtifact))
        #expect(try fixture.snapshot() == before)
    }

    @Test("An oversized current cache is rejected before parsing or artifact recovery")
    func oversizedCacheIsBounded() async throws {
        let fixture = try await LegacyCacheFixture.make()
        defer { fixture.remove() }
        let result = fixture.result()
        _ = try fixture.save(result, id: UUID())
        _ = try fixture.installLegacyCache(result)
        let oversized = Int64(EngineValidation.resultLimit) + 1
        #expect(Darwin.truncate(fixture.cacheURL.path, off_t(oversized)) == 0)
        let identity = try FileAccess.identity(at: fixture.cacheURL)
        let observations = LegacyCacheReadObservations()

        #expect(throws: (any Error).self) {
            try EngineResultStore.loadForTesting(evidenceID: fixture.evidence.id, in: fixture.caseURL,
                checkpoint: { observations.record($0) })
        }
        #expect(!observations.contains(.didReadArtifact))
        #expect(try FileAccess.identity(at: fixture.cacheURL) == identity)
        #expect(identity.size == oversized)
        try fixture.expectSourcesUnchanged()
    }
}

private enum LegacyCacheTestFailure: Error, Equatable {
    case unsupportedMode, injectedReadFailure, cannotLockSyntheticCase
}

private enum LegacyCacheSubstitution: String {
    case symlink, hardLink, fifo, directory, file
}

private struct LegacyCacheSnapshotItem: Equatable {
    let type: mode_t
    let size: Int64
    let bytes: Data?
    let linkTarget: String?
    let identity: SourceIdentity?
    let links: Int
}

private struct LegacyCacheFixture: Sendable {
    static let sourceBytes = Data("abc".utf8)
    static let sourceSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    let root: URL
    let source: URL
    let segment: URL
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let segmentEvidence: EvidenceRecord
    let identities: [EngineSourceIdentity]
    var caseURL: URL { forensicCase.bundleURL }
    var manifestURL: URL { caseURL.appendingPathComponent("manifest.json") }
    var lockURL: URL { caseURL.appendingPathComponent(".case.lock") }
    var jobsURL: URL { caseURL.appendingPathComponent("filesystem-jobs", isDirectory: true) }
    var cacheDirectory: URL { caseURL.appendingPathComponent("filesystem", isDirectory: true) }
    var cacheURL: URL { cacheDirectory.appendingPathComponent(evidence.id.uuidString.lowercased() + ".json") }

    static func make(migrate: Bool = true) async throws -> Self {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("LegacyCacheRecovery-\(UUID().uuidString)", isDirectory: true)
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        do {
            let source = root.appendingPathComponent("selected-synthetic.dd")
            let segment = root.appendingPathComponent("other-synthetic.dd")
            try sourceBytes.write(to: source)
            try sourceBytes.write(to: segment)
            let inspected = try await ImageInspector.inspect(url: source) { _ in }
            let other = try await ImageInspector.inspect(url: segment) { _ in }
            #expect(inspected.sha256 == sourceSHA256)
            #expect(other.sha256 == sourceSHA256)
            let initial = try CaseStore.create(name: "Synthetic legacy cache recovery", in: root)
            let selected = try CaseStore.adding(image: inspected, to: initial)
            let withBoth = try CaseStore.adding(image: other, to: selected)
            let current = try migrate ? CaseStore.migrateToSchema2(withBoth) : withBoth
            let evidence = try #require(current.manifest.evidence.first)
            let segmentEvidence = try #require(current.manifest.evidence.last)
            let identities = try [source, segment].map {
                EngineSourceIdentity(path: $0.path, identity: try FileAccess.identity(at: $0))
            }
            return Self(root: root, source: source, segment: segment, forensicCase: current,
                evidence: evidence, segmentEvidence: segmentEvidence, identities: identities)
        } catch {
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func result(marker: String = "ONE", referenceSeconds: Double = 813_150_755.456666,
        status: EngineTerminalStatus = .completed, options: EngineOptions? = nil,
        selectedSourceFirst: Bool = true) -> EnumerationResult {
        let paths = selectedSourceFirst ? [source.path, segment.path] : [segment.path, source.path]
        return EnumerationResult(engineVersion: "synthetic-engine.v2", patchDigest: "synthetic-patch.v3",
            sourcePaths: paths, sourceIdentities: selectedSourceFirst ? identities : Array(identities.reversed()),
            sourceFileHashes: [source.path: Self.sourceSHA256, segment.path: Self.sourceSHA256],
            options: options ?? .init(imageType: "raw", sectorSize: 512, timezone: "Asia/Bangkok",
                maxFiles: 17, hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 6, sectorSize: 512, imagePaths: paths),
            volumes: [.init(id: "synthetic-volume", offsetBytes: 0, filesystem: "FAT32", blockSize: 512, blockCount: 1)],
            files: [.init(id: "0:42", path: "/\(marker).TXT", name: "\(marker).TXT",
                fsOffsetBytes: 0, metaAddress: 42, size: 3, isDirectory: false, isDeleted: false,
                modifiedEpoch: 1_700_000_000)],
            warnings: status == .partial ? ["Synthetic partial enumeration."] : [],
            status: status, savedAt: Date(timeIntervalSinceReferenceDate: referenceSeconds))
    }

    func save(_ result: EnumerationResult, id: UUID, evidenceID: UUID? = nil) throws -> EngineJobSaveReceipt {
        try EngineResultStore.saveWithJobProvenance(result: result, evidenceID: evidenceID ?? evidence.id,
            in: caseURL, jobID: id, startedAt: result.savedAt.addingTimeInterval(-1),
            executableSHA256: String(repeating: "b", count: 64))
    }

    func binding(_ result: EnumerationResult) throws -> CaseWorkBinding {
        try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result,
            file: try #require(result.files.first))
    }

    func legacyBytes(_ result: EnumerationResult) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(result)
        #expect(bytes.count <= EngineValidation.resultLimit)
        return bytes
    }

    func installLegacyCache(_ result: EnumerationResult) throws -> Data {
        let bytes = try legacyBytes(result)
        try bytes.write(to: cacheURL)
        return bytes
    }

    func decodeLegacy(_ bytes: Data) throws -> EnumerationResult {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(EnumerationResult.self, from: bytes)
    }

    func artifactPath(_ id: UUID) -> String { "filesystem-jobs/" + id.uuidString.lowercased() + ".json" }
    func artifactURL(_ id: UUID) -> URL { caseURL.appendingPathComponent(artifactPath(id)) }

    func editLastJob(_ edit: (inout [String: Any]) throws -> Void) throws {
        var manifest = try Self.object(Data(contentsOf: manifestURL))
        var provenance = try #require(manifest["provenance"] as? [String: Any])
        var jobs = try #require(provenance["jobs"] as? [[String: Any]])
        var job = try #require(jobs.last)
        try edit(&job)
        jobs[jobs.count - 1] = job
        provenance["jobs"] = jobs
        manifest["provenance"] = provenance
        try Self.canonicalJSON(manifest).write(to: manifestURL)
    }

    func target(_ name: String, artifactID: UUID) throws -> URL {
        switch name {
        case "root": return caseURL
        case "manifest": return manifestURL
        case "lock": return lockURL
        case "cache": return cacheURL
        case "cacheDirectory": return cacheDirectory
        case "artifact": return artifactURL(artifactID)
        case "jobs": return jobsURL
        default: throw LegacyCacheTestFailure.unsupportedMode
        }
    }

    func substitute(_ target: URL, with kind: LegacyCacheSubstitution) throws {
        let detached = root.appendingPathComponent("detached-\(UUID().uuidString)")
        try FileManager.default.moveItem(at: target, to: detached)
        switch kind {
        case .symlink:
            try FileManager.default.createSymbolicLink(at: target, withDestinationURL: detached)
        case .hardLink:
            guard Darwin.link(detached.path, target.path) == 0 else {
                throw FileAccess.posixError("Cannot create synthetic hard link")
            }
        case .fifo:
            guard Darwin.mkfifo(target.path, mode_t(0o600)) == 0 else {
                throw FileAccess.posixError("Cannot create synthetic FIFO")
            }
        case .directory:
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        case .file:
            try Data("Synthetic replacement for a directory.".utf8).write(to: target)
        }
    }

    func replaceWithSameBytes(_ target: URL) throws {
        let detached = root.appendingPathComponent("same-byte-original-\(UUID().uuidString)")
        try FileManager.default.moveItem(at: target, to: detached)
        try FileManager.default.copyItem(at: detached, to: target)
    }

    func snapshot() throws -> [String: LegacyCacheSnapshotItem] {
        var items: [String: LegacyCacheSnapshotItem] = [:]
        func visit(_ directory: URL, prefix: String) throws {
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() {
                let url = directory.appendingPathComponent(name)
                var metadata = stat()
                guard Darwin.lstat(url.path, &metadata) == 0 else {
                    throw FileAccess.posixError("Cannot snapshot synthetic legacy cache")
                }
                let type = metadata.st_mode & S_IFMT
                let regular = type == S_IFREG
                let key = prefix + name
                items[key] = .init(type: type, size: Int64(metadata.st_size),
                    bytes: regular && metadata.st_size <= 1_048_576 ? try Data(contentsOf: url) : nil,
                    linkTarget: type == S_IFLNK ? try FileManager.default.destinationOfSymbolicLink(atPath: url.path) : nil,
                    identity: regular ? SourceIdentity(metadata) : nil, links: Int(metadata.st_nlink))
                if type == S_IFDIR { try visit(url, prefix: key + "/") }
            }
        }
        try visit(root, prefix: "")
        return items
    }

    func expectSourcesUnchanged() throws {
        #expect(try Data(contentsOf: source) == Self.sourceBytes)
        #expect(try Data(contentsOf: segment) == Self.sourceBytes)
    }

    static func object(_ bytes: Data) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    }

    static func canonicalJSON(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    static func hash(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}

private final class LegacyCacheReadObservations: @unchecked Sendable {
    private let lock = NSLock()
    private var points = Set<String>()
    func record(_ point: EngineFilesystemCacheReadCheckpoint) {
        lock.lock(); defer { lock.unlock() }
        points.insert(String(describing: point))
    }
    func contains(_ point: EngineFilesystemCacheReadCheckpoint) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return points.contains(String(describing: point))
    }
}

private final class LegacyCacheOneShot: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    var wasClaimed: Bool {
        lock.lock(); defer { lock.unlock() }
        return claimed
    }
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !claimed else { return false }
        claimed = true
        return true
    }
}

private final class LegacyCacheExclusiveAdmission: @unchecked Sendable {
    private let stateLock = NSLock()
    private let descriptor: Int32
    private var held = true
    init(_ url: URL) throws {
        let opened = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard opened >= 0 else { throw FileAccess.posixError("Cannot open synthetic case lock") }
        guard legacyCacheTestFlock(opened, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(opened)
            throw LegacyCacheTestFailure.cannotLockSyntheticCase
        }
        descriptor = opened
    }
    var isHeld: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return held
    }
    func release() {
        stateLock.lock(); defer { stateLock.unlock() }
        guard held else { return }
        held = false
        _ = legacyCacheTestFlock(descriptor, LOCK_UN)
    }
    deinit { release(); Darwin.close(descriptor) }
}

private final class LegacyCacheReadSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Bool?
    private var continuation: CheckedContinuation<Bool, Never>?
    func resolve(_ result: Bool) {
        lock.lock()
        guard self.result == nil else { lock.unlock(); return }
        self.result = result
        let waiting = continuation
        continuation = nil
        lock.unlock()
        waiting?.resume(returning: result)
    }
    func wait() async -> Bool {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(returning: result)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }
}
