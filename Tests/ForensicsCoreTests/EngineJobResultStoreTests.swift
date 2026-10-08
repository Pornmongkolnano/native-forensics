import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

struct EngineJobResultStoreTests {
    @Test("Recording an engine job requires an explicit case migration and preserves schema 1 bytes")
    func migrationIsExplicit() async throws {
        let fixture = try await EngineJobFixture.make(migrate: false)
        defer { fixture.remove() }
        let before = try fixture.snapshot()
        #expect(throws: CaseProvenanceError.migrationRequired) {
            try fixture.save(result: fixture.result(), jobID: UUID())
        }
        #expect(try fixture.snapshot() == before)
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.schemaVersion == 1)
        #expect(!FileManager.default.fileExists(atPath: fixture.jobsURL.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.cacheURL.path))
        try fixture.expectSourcesUnchanged()
    }

    @Test("A recorded partial job binds exact artifact bytes, reconstructible options and ordered source hashes")
    func independentArtifactAndProvenance() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(status: .partial)
        let id = UUID()
        let receipt = try fixture.save(result: result, jobID: id)
        let bytes = try Data(contentsOf: fixture.artifactURL(id))
        let object = try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let job = receipt.job
        #expect(!receipt.wasAlreadyRecorded)
        #expect(receipt.latestCacheUpdated)
        #expect(receipt.artifactSHA256 == EngineJobFixture.hash(bytes))
        #expect(receipt.artifactByteCount == bytes.count)
        #expect(job.id == id)
        #expect(job.evidenceID == fixture.evidence.id)
        #expect(job.kind == "filesystem.enumeration")
        #expect(job.startedAt == fixture.startedAt)
        #expect(job.completedAt == result.savedAt)
        #expect(job.status == .partial)
        #expect(job.isPartial)
        #expect(job.component.identifier == "NFTSKEngine")
        #expect(job.component.version == "fixture-engine.v2")
        #expect(job.component.buildDigest == "independent-fixture-patch.v3")
        #expect(job.component.executableSHA256 == EngineJobFixture.executableHash)
        #expect(job.optionsJSON == #"{"hashLogicalImage":false,"imageType":"raw","maxFiles":17,"sectorSize":512,"timezone":"Asia/Bangkok"}"#)
        #expect(job.optionsSHA256 == EngineJobFixture.hash(Data(job.optionsJSON.utf8)))
        #expect(job.selectedSourceOrdinal == 1)
        #expect(job.sourceHashes.map(\.ordinal) == [0, 1])
        #expect(job.sourceHashes.map(\.scope) == ["selected-file-bytes", "selected-file-bytes"])
        // Constants were independently checked with Python hashlib, so these
        // source expectations do not derive from the store's digest helper.
        #expect(job.sourceHashes.map(\.sha256) == ["3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"])
        #expect(job.sourceHashes.map(\.byteCount) == [3, 3])
        #expect(job.warnings == ["Synthetic warning for [selected-source-0] and [selected-source-1].", "A deliberately partial listing."])
        #expect(job.artifactRelativePath == fixture.artifactRelativePath(id))
        #expect(job.artifactSHA256 == EngineJobFixture.hash(bytes))
        #expect(job.artifactByteCount == bytes.count)
        #expect(object["sourcePaths"] as? [String] == [fixture.segment.path, fixture.source.path])
        #expect(object["sourceFileHashes"] as? [String: String] == [fixture.segment.path: EngineJobFixture.hash(fixture.segmentBytes), fixture.source.path: EngineJobFixture.hash(fixture.sourceBytes)])
        #expect(object["warnings"] as? [String] == result.warnings)
        #expect(object["status"] as? String == "partial")
        #expect((object["files"] as? [[String: Any]])?.first?["path"] as? String == "/SELECTED.TXT")
        let storedJobBytes = try JSONEncoder().encode(job)
        #expect(!String(decoding: storedJobBytes, as: UTF8.self).contains(fixture.source.path))
        #expect(!String(decoding: storedJobBytes, as: UTF8.self).contains(fixture.segment.path))
        let reopened = try CaseStore.open(at: fixture.caseURL)
        #expect(reopened.manifest == receipt.forensicCase.manifest)
        #expect(reopened.manifest.provenance?.jobs == [job])
        #expect(try Data(contentsOf: fixture.originalManifestBackup(reopened)) == fixture.originalManifest)
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == result)
        try fixture.expectSourcesUnchanged()
    }

    @Test("A newer mutable cache cannot overwrite the immutable bytes of earlier jobs")
    func historicalJobsSurviveNewLatestCache() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let firstID = UUID(), secondID = UUID()
        let first = try fixture.save(result: fixture.result(), jobID: firstID)
        let originalArtifact = try Data(contentsOf: fixture.artifactURL(firstID))
        let later = fixture.result(status: .partial, marker: "second", savedAt: fixture.completedAt.addingTimeInterval(2))
        let second = try fixture.save(result: later, jobID: secondID)
        #expect(!second.wasAlreadyRecorded)
        #expect(try Data(contentsOf: fixture.artifactURL(firstID)) == originalArtifact)
        #expect(first.artifactSHA256 == EngineJobFixture.hash(originalArtifact))
        #expect(second.artifactSHA256 != first.artifactSHA256)
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == later)
        let reopened = try CaseStore.open(at: fixture.caseURL)
        #expect(reopened.manifest.provenance?.jobs.map(\.id) == [firstID, secondID])
        let beforeRetry = try fixture.snapshot()
        let historicalRetry = try fixture.save(result: fixture.result(), jobID: firstID)
        #expect(historicalRetry.wasAlreadyRecorded)
        #expect(!historicalRetry.latestCacheUpdated)
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == later)
        #expect(try fixture.snapshot() == beforeRetry)
        let beforeAudit = try fixture.snapshot()
        let audit = try await CaseIntegrityAuditor.audit(forensicCase: reopened)
        #expect(!audit.hasFailures)
        #expect(!audit.isPartial)
        for receipt in [first, second] {
            let path = try #require(receipt.job.artifactRelativePath)
            #expect(audit.checks.contains { $0.relativePath == path && $0.code == "job.listing.valid" && $0.status == .pass })
            #expect(audit.checks.contains { $0.relativePath == path && $0.code == "job.artifact.verified" && $0.status == .pass && $0.sha256 == receipt.artifactSHA256 })
        }
        #expect(try fixture.snapshot() == beforeAudit)
        try fixture.expectSourcesUnchanged()
    }

    @Test("An exact duplicate job is idempotent and leaves all saved byte records untouched")
    func exactDuplicateIsReadOnly() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID(), result = fixture.result()
        let first = try fixture.save(result: result, jobID: id)
        let before = try fixture.snapshot()
        let duplicate = try fixture.save(result: result, jobID: id)
        #expect(duplicate.wasAlreadyRecorded)
        #expect(!duplicate.latestCacheUpdated)
        #expect(duplicate.job == first.job)
        #expect(duplicate.artifactSHA256 == first.artifactSHA256)
        #expect(duplicate.artifactByteCount == first.artifactByteCount)
        #expect(duplicate.forensicCase.manifest == first.forensicCase.manifest)
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Immutable artifact, job and latest cache preserve the exact fractional instant and binding")
    func fractionalArtifactCompletion() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let precise = Date(timeIntervalSinceReferenceDate: 813_457_693.9876543)
        let result = fixture.result(savedAt: precise, selectedSourceFirst: true)
        let id = UUID()
        let receipt = try fixture.save(result: result, jobID: id,
            startedAt: precise.addingTimeInterval(-1.1234567))
        #expect(receipt.job.completedAt == precise)
        #expect(try fixture.decodeArtifact(id) == result)
        let object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: fixture.artifactURL(id))) as? [String: Any])
        #expect((object["savedAt"] as? NSNumber)?.doubleValue == precise.timeIntervalSinceReferenceDate)
        let reopened = try CaseStore.open(at: fixture.caseURL)
        #expect(reopened.manifest.provenance?.jobs.first?.completedAt == precise)
        #expect(reopened.manifest.provenance?.jobs.first?.startedAt == receipt.job.startedAt)
        let cache = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))
        #expect(cache == result)
        #expect(cache.savedAt == receipt.job.completedAt)
        let originalBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: result, file: try #require(result.files.first))
        let cacheBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: cache, file: try #require(cache.files.first))
        #expect(cacheBinding == originalBinding)
        #expect(cacheBinding.snapshotSHA256 == originalBinding.snapshotSHA256)
        #expect(object["savedAtExactReferenceDate"] == nil)
        let beforeDuplicate = try fixture.snapshot()
        let duplicate = try fixture.save(result: result, jobID: id, startedAt: receipt.job.startedAt)
        #expect(duplicate.wasAlreadyRecorded)
        #expect(!duplicate.latestCacheUpdated)
        #expect(try fixture.snapshot() == beforeDuplicate)
        try fixture.expectSourcesUnchanged()
    }


    @Test("Direct filesystem cache saves preserve the full result and exact CaseWork binding", arguments: [
        813_150_755.456666, 813_150_755.0.nextDown, 813_150_755.0,
        813_150_755.0.nextUp, 813_150_756.0.nextDown,
        -0.1, (-1.0).nextDown, (-1.0).nextUp, Double.zero.nextDown, 0.0, Double.zero.nextUp,
        0.75, (-978_307_200.0).nextDown, -978_307_200.0, (-978_307_200.0).nextUp, -978_307_200.25
    ])
    func directCachePreservesExactBinding(_ referenceSeconds: Double) async throws {
        let fixture = try await EngineJobFixture.make(migrate: false)
        defer { fixture.remove() }
        let result = fixture.result(savedAt: Date(timeIntervalSinceReferenceDate: referenceSeconds), selectedSourceFirst: true)
        let manifestBefore = try Data(contentsOf: fixture.manifestURL)
        let originalBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: result, file: try #require(result.files.first))
        try EngineResultStore.save(result: result, evidenceID: fixture.evidence.id, in: fixture.caseURL)
        let loaded = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))
        #expect(loaded == result)
        #expect(loaded.savedAt.timeIntervalSinceReferenceDate == referenceSeconds)
        let loadedBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: loaded, file: try #require(loaded.files.first))
        #expect(loadedBinding == originalBinding)
        #expect(loadedBinding.snapshotSHA256 == originalBinding.snapshotSHA256)
        let cacheBytes = try Data(contentsOf: fixture.cacheURL)
        let object = try #require(try JSONSerialization.jsonObject(with: cacheBytes) as? [String: Any])
        #expect(object["savedAt"] is String)
        #expect((object["savedAtExactReferenceDate"] as? NSNumber)?.doubleValue == referenceSeconds)
        let legacyDecoder = JSONDecoder(); legacyDecoder.dateDecodingStrategy = .iso8601
        let projected = try legacyDecoder.decode(EnumerationResult.self, from: cacheBytes)
        #expect(projected.savedAt.timeIntervalSinceReferenceDate == referenceSeconds.rounded(.down))
        #expect(try Data(contentsOf: fixture.manifestURL) == manifestBefore)
        #expect(!FileManager.default.fileExists(atPath: fixture.jobsURL.path))
        try fixture.expectSourcesUnchanged()
    }

    @Test("ISO-only caches with incomplete latest-job proof preserve unknown fractions and old hashes")
    func legacyCachePreservesOldRecords() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let precise = Date(timeIntervalSinceReferenceDate: 813_150_755.456666)
        let result = fixture.result(savedAt: precise, selectedSourceFirst: true)
        let oldArtifactBytes = try fixture.encodeResult(result)
        let originalBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: result, file: try #require(result.files.first))
        let id = UUID()
        let receipt = try fixture.save(result: result, jobID: id, startedAt: precise.addingTimeInterval(-1))
        #expect(try Data(contentsOf: fixture.artifactURL(id)) == oldArtifactBytes)
        #expect(receipt.artifactSHA256 == EngineJobFixture.hash(oldArtifactBytes))
        let oldEncoder = JSONEncoder(); oldEncoder.dateEncodingStrategy = .iso8601
        oldEncoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let oldCacheBytes = try oldEncoder.encode(result)
        try oldCacheBytes.write(to: fixture.cacheURL)
        // A valid legacy job may retain its artifact SHA without declaring the
        // artifact byte count. That incomplete proof cannot restore cache time.
        let legacyJob = receipt.job.preservingUnknownArtifactSize()
        var manifest = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: fixture.manifestURL)) as? [String: Any])
        var provenance = try #require(manifest["provenance"] as? [String: Any])
        var jobs = try #require(provenance["jobs"] as? [[String: Any]])
        try #require(jobs.count == 1)
        jobs[0].removeValue(forKey: "artifactByteCount")
        provenance["jobs"] = jobs; manifest["provenance"] = provenance
        try JSONSerialization.data(withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]).write(to: fixture.manifestURL)
        try #require(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs == [legacyJob])
        let beforeRead = try fixture.snapshot()
        let oldDecoder = JSONDecoder(); oldDecoder.dateDecodingStrategy = .iso8601
        let oldResult = try oldDecoder.decode(EnumerationResult.self, from: oldCacheBytes)
        let loaded = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))
        #expect(loaded == oldResult)
        #expect(loaded.savedAt.timeIntervalSinceReferenceDate == precise.timeIntervalSinceReferenceDate.rounded(.down))
        #expect(loaded.savedAt != precise)
        let loadedBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: loaded, file: try #require(loaded.files.first))
        // Without complete declared job proof, old ISO-only cache fractions
        // remain unknown. History identity is never weakened to hide this limit.
        #expect(loadedBinding.snapshotSHA256 != originalBinding.snapshotSHA256)
        let decodedArtifact = try fixture.decodeArtifact(id)
        let artifactBinding = try CaseWorkBinding.make(caseID: fixture.forensicCase.manifest.id,
            evidence: fixture.evidence, result: decodedArtifact, file: try #require(decodedArtifact.files.first))
        #expect(artifactBinding == originalBinding)
        let reopened = try CaseStore.open(at: fixture.caseURL)
        #expect(reopened.manifest.provenance?.jobs == [legacyJob])
        #expect(reopened.manifest.provenance?.jobs.first?.artifactByteCount == nil)
        #expect(reopened.manifest.provenance?.jobs.first?.artifactSHA256 == receipt.artifactSHA256)
        let report = try await CaseIntegrityAuditor.audit(forensicCase: reopened)
        #expect(!report.hasFailures)
        #expect(report.checks.contains {
            $0.relativePath == receipt.artifactRelativePath && $0.code == "job.artifact.verified"
                && $0.status == .pass && $0.sha256 == receipt.artifactSHA256
        })
        #expect(try fixture.snapshot() == beforeRead)
        #expect(try Data(contentsOf: fixture.cacheURL) == oldCacheBytes)
        #expect(try Data(contentsOf: fixture.artifactURL(id)) == oldArtifactBytes)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Invalid optional cache precision is rejected by both load and integrity audit", arguments: [
        "differentSecond", "null", "string", "boolean", "array", "overflow"
    ])
    func invalidCachePrecisionIsPreserved(_ mode: String) async throws {
        let fixture = try await EngineJobFixture.make(migrate: false)
        defer { fixture.remove() }
        let result = fixture.result(savedAt: Date(timeIntervalSinceReferenceDate: 813_150_755.456666))
        try EngineResultStore.save(result: result, evidenceID: fixture.evidence.id, in: fixture.caseURL)
        var object = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: fixture.cacheURL)) as? [String: Any])
        switch mode {
        case "differentSecond": object["savedAtExactReferenceDate"] = 813_150_756.456666
        case "null": object["savedAtExactReferenceDate"] = NSNull()
        case "string": object["savedAtExactReferenceDate"] = "813150755.456666"
        case "boolean": object["savedAtExactReferenceDate"] = true
        case "array": object["savedAtExactReferenceDate"] = [813_150_755.456666]
        default: object["savedAtExactReferenceDate"] = "PRECISION_OVERFLOW"
        }
        var corrupt = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        if mode == "overflow" {
            let raw = String(decoding: corrupt, as: UTF8.self).replacingOccurrences(
                of: "\"savedAtExactReferenceDate\":\"PRECISION_OVERFLOW\"",
                with: "\"savedAtExactReferenceDate\":1e999")
            corrupt = Data(raw.utf8)
            #expect(!raw.contains("PRECISION_OVERFLOW"))
        }
        try corrupt.write(to: fixture.cacheURL)
        let beforeRead = try fixture.snapshot()
        #expect(throws: EngineError.self) {
            try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL)
        }
        let report = try await CaseIntegrityAuditor.audit(forensicCase: CaseStore.open(at: fixture.caseURL))
        let relativePath = "filesystem/" + fixture.evidence.id.uuidString.lowercased() + ".json"
        #expect(report.checks.contains { $0.relativePath == relativePath && $0.status == .fail })
        #expect(try fixture.snapshot() == beforeRead)
        #expect(try Data(contentsOf: fixture.cacheURL) == corrupt)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Nonfinite cache saved timestamps cannot publish a result")
    func nonfiniteCacheTimestampCannotPublish() async throws {
        let fixture = try await EngineJobFixture.make(migrate: false)
        defer { fixture.remove() }
        let before = try fixture.snapshot()
        for raw in [Double.nan, Double.infinity, -Double.infinity] {
            let result = fixture.result(savedAt: Date(timeIntervalSinceReferenceDate: raw))
            #expect(throws: (any Error).self) {
                try EngineResultStore.save(result: result, evidenceID: fixture.evidence.id, in: fixture.caseURL)
            }
            #expect(try fixture.snapshot() == before)
        }
        try fixture.expectSourcesUnchanged()
    }

    @Test("Reusing a job UUID with changed bytes, options, time or executable identity is refused", arguments: ["result", "options", "warning", "startedAt", "executable"])
    func conflictingIdentityIsRefused(_ mode: String) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID(), original = fixture.result()
        _ = try fixture.save(result: original, jobID: id)
        let before = try fixture.snapshot()
        let changed: EnumerationResult
        if mode == "result" { changed = fixture.result(marker: "different file") }
        else if mode == "options" { changed = fixture.result(options: EngineOptions(imageType: "raw", sectorSize: 512, timezone: "UTC", maxFiles: 17, hashLogicalImage: false)) }
        else if mode == "warning" { changed = fixture.result(extraWarning: "Additional warning") }
        else { changed = original }
        #expect(throws: (any Error).self) {
            try fixture.save(result: changed, jobID: id,
                startedAt: mode == "startedAt" ? fixture.startedAt.addingTimeInterval(0.25) : fixture.startedAt,
                executableHash: mode == "executable" ? String(repeating: "c", count: 64) : EngineJobFixture.executableHash)
        }
        #expect(try fixture.snapshot() == before)
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs.count == 1)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Invalid evidence scope, executable hash and chronology cannot publish any job bytes", arguments: ["evidenceID", "selectedHash", "invalidBinary", "reversedDates"])
    func invalidJobCannotPublish(_ mode: String) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let before = try fixture.snapshot()
        let result = fixture.result(selectedHash: mode == "selectedHash" ? String(repeating: "a", count: 64) : nil)
        #expect(throws: (any Error).self) {
            try EngineResultStore.saveWithJobProvenance(result: result,
                evidenceID: mode == "evidenceID" ? UUID() : fixture.evidence.id, in: fixture.caseURL,
                jobID: UUID(), startedAt: mode == "reversedDates" ? fixture.completedAt.addingTimeInterval(1) : fixture.startedAt,
                executableSHA256: mode == "invalidBinary" ? "a version label is not a binary hash" : EngineJobFixture.executableHash)
        }
        #expect(try fixture.snapshot() == before)
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs.isEmpty == true)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Concurrent identical publications commit exactly one job and report all other calls as idempotent")
    func concurrentIdenticalJobs() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID(), result = fixture.result()
        let gate = EngineJobStartGate(participants: 8)
        let outcomes = await withTaskGroup(of: EngineJobOutcome.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    await gate.wait()
                    do {
                        let receipt = try fixture.save(result: result, jobID: id)
                        return .saved(id: receipt.job.id, alreadyRecorded: receipt.wasAlreadyRecorded)
                    } catch { return .failure(String(describing: error)) }
                }
            }
            var values: [EngineJobOutcome] = []
            for await value in group { values.append(value) }
            return values
        }
        #expect(outcomes.filter { $0 == .saved(id: id, alreadyRecorded: false) }.count == 1)
        #expect(outcomes.filter { $0 == .saved(id: id, alreadyRecorded: true) }.count == 7)
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs.map(\.id) == [id])
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.jobsURL.path) == [id.uuidString.lowercased() + ".json"])
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == result)
        try fixture.expectSourcesUnchanged()
    }

    @Test("A concurrent same-UUID conflict keeps only the winner's exact result and provenance")
    func concurrentConflictingJobs() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID()
        let candidates = [fixture.result(marker: "first candidate"), fixture.result(marker: "second candidate")]
        let gate = EngineJobStartGate(participants: 2)
        let outcomes = await withTaskGroup(of: EngineJobOutcome.self) { group in
            for candidate in candidates {
                group.addTask {
                    await gate.wait()
                    do {
                        let receipt = try fixture.save(result: candidate, jobID: id)
                        return .saved(id: receipt.job.id, alreadyRecorded: receipt.wasAlreadyRecorded)
                    } catch { return .failure(String(describing: error)) }
                }
            }
            var values: [EngineJobOutcome] = []
            for await value in group { values.append(value) }
            return values
        }
        #expect(outcomes.filter { $0 == .saved(id: id, alreadyRecorded: false) }.count == 1)
        #expect(outcomes.filter { if case .failure = $0 { return true }; return false }.count == 1)
        let current = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))
        #expect(candidates.contains(current))
        let immutable = try fixture.decodeArtifact(id)
        #expect(immutable == current)
        let reopened = try CaseStore.open(at: fixture.caseURL)
        #expect(reopened.manifest.provenance?.jobs.count == 1)
        #expect(reopened.manifest.provenance?.jobs.first?.artifactSHA256 == EngineJobFixture.hash(try Data(contentsOf: fixture.artifactURL(id))))
        try fixture.expectSourcesUnchanged()
    }

    @Test("Concurrent distinct jobs cannot lose a manifest entry or rewrite either immutable artifact")
    func concurrentDistinctJobs() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let firstID = UUID(), secondID = UUID()
        let candidates = [(firstID, fixture.result(marker: "first distinct")), (secondID, fixture.result(marker: "second distinct"))]
        let gate = EngineJobStartGate(participants: 2)
        let outcomes = await withTaskGroup(of: EngineJobOutcome.self) { group in
            for (id, candidate) in candidates {
                group.addTask {
                    await gate.wait()
                    do {
                        let receipt = try fixture.save(result: candidate, jobID: id)
                        return .saved(id: receipt.job.id, alreadyRecorded: receipt.wasAlreadyRecorded)
                    } catch { return .failure(String(describing: error)) }
                }
            }
            var values: [EngineJobOutcome] = []
            for await value in group { values.append(value) }
            return values
        }
        #expect(Set(outcomes) == Set([.saved(id: firstID, alreadyRecorded: false), .saved(id: secondID, alreadyRecorded: false)]))
        for (id, candidate) in candidates { #expect(try fixture.decodeArtifact(id) == candidate) }
        let reopened = try CaseStore.open(at: fixture.caseURL)
        #expect(Set(reopened.manifest.provenance?.jobs.map(\.id) ?? []) == Set([firstID, secondID]))
        let current = try #require(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL))
        #expect(candidates.contains { $0.1 == current })
        let report = try await CaseIntegrityAuditor.audit(forensicCase: reopened)
        #expect(!report.hasFailures)
        #expect(report.checks.filter { $0.code == "job.artifact.verified" && $0.status == .pass }.count == 2)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Immutable storage refuses links and nonregular destinations without touching outside targets", arguments: ["directoryLink", "fileLink", "hardLink", "fifo"])
    func unsafeArtifactDestinations(_ mode: String) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID()
        let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent("sentinel.json")
        let privateBytes = Data("OUTSIDE_TARGET_MUST_NOT_BE_READ_OR_MODIFIED".utf8)
        try privateBytes.write(to: sentinel)
        try FileManager.default.createDirectory(at: fixture.cacheURL.deletingLastPathComponent(), withIntermediateDirectories: false)
        if mode == "directoryLink" {
            try FileManager.default.createSymbolicLink(at: fixture.jobsURL, withDestinationURL: outside)
        } else {
            try FileManager.default.createDirectory(at: fixture.jobsURL, withIntermediateDirectories: false)
            if mode == "fileLink" { try FileManager.default.createSymbolicLink(at: fixture.artifactURL(id), withDestinationURL: sentinel) }
            else if mode == "hardLink" { #expect(Darwin.link(sentinel.path, fixture.artifactURL(id).path) == 0) }
            else { #expect(Darwin.mkfifo(fixture.artifactURL(id).path, mode_t(0o600)) == 0) }
        }
        let before = try fixture.snapshot()
        #expect(throws: (any Error).self) { try fixture.save(result: fixture.result(), jobID: id) }
        #expect(try fixture.snapshot() == before)
        #expect(try Data(contentsOf: sentinel) == privateBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path) == ["sentinel.json"])
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs.isEmpty == true)
        try fixture.expectSourcesUnchanged()
    }

    @Test("A substituted immutable artifact cannot make a duplicate save succeed or repair it silently")
    func substitutedExistingArtifact() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID(), result = fixture.result()
        _ = try fixture.save(result: result, jobID: id)
        let replacement = try fixture.encodeResult(fixture.result(marker: "substituted"))
        try replacement.write(to: fixture.artifactURL(id))
        let before = try fixture.snapshot()
        #expect(throws: (any Error).self) { try fixture.save(result: result, jobID: id) }
        #expect(try fixture.snapshot() == before)
        #expect(try Data(contentsOf: fixture.artifactURL(id)) == replacement)
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == result)
        try fixture.expectSourcesUnchanged()
    }

    @Test("A directory substitution at publication cannot redirect writes and exposes already committed bytes", arguments: ["beforeCommit", "afterCommit"])
    func artifactDirectorySwap(_ mode: String) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let existingID = UUID(), attemptedID = UUID()
        _ = try fixture.save(result: fixture.result(), jobID: existingID)
        let oldManifest = try Data(contentsOf: fixture.manifestURL)
        let oldCache = try Data(contentsOf: fixture.cacheURL)
        let oldArtifact = try Data(contentsOf: fixture.artifactURL(existingID))
        let detached = fixture.root.appendingPathComponent("detached-jobs", isDirectory: true)
        let outside = fixture.root.appendingPathComponent("outside-publication-target", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent(attemptedID.uuidString.lowercased() + ".json")
        let privateBytes = Data("NO_PUBLICATION_OUTSIDE_THE_HELD_DIRECTORY".utf8)
        try privateBytes.write(to: sentinel)
        var swapped = false
        var observed: (any Error)?
        let attempted = fixture.result(marker: "directory swap")
        do {
            _ = try EngineResultStore.saveWithJobProvenanceForTesting(result: attempted,
                evidenceID: fixture.evidence.id, in: fixture.caseURL, jobID: attemptedID,
                startedAt: fixture.startedAt, executableSHA256: EngineJobFixture.executableHash) { checkpoint, _ in
                    if checkpoint == (mode == "beforeCommit" ? .beforeArtifactRename : .afterArtifactRename) {
                        try FileManager.default.moveItem(at: fixture.jobsURL, to: detached)
                        try FileManager.default.createSymbolicLink(at: fixture.jobsURL, withDestinationURL: outside)
                        swapped = true
                    }
                }
            Issue.record("A substituted job directory was accepted.")
        } catch { observed = error }
        #expect(swapped)
        let error = try #require(observed)
        if mode == "afterCommit" {
            #expect(error as? EngineJobSaveError == .publishedButIncomplete(jobID: attemptedID,
                artifactSHA256: EngineJobFixture.hash(try fixture.encodeResult(attempted)),
                artifactState: .uncertain, manifestState: .notCommitted, latestCacheState: .notCommitted))
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .deferredToDate
            #expect(try decoder.decode(EnumerationResult.self, from: Data(contentsOf: detached.appendingPathComponent(attemptedID.uuidString.lowercased() + ".json"))) == attempted)
        } else {
            #expect(error as? EngineJobSaveError == nil)
        }
        #expect(try Data(contentsOf: fixture.manifestURL) == oldManifest)
        #expect(try Data(contentsOf: fixture.cacheURL) == oldCache)
        #expect(try Data(contentsOf: detached.appendingPathComponent(existingID.uuidString.lowercased() + ".json")) == oldArtifact)
        let expectedNames = mode == "beforeCommit" ? [existingID] : [existingID, attemptedID]
        #expect(Set(try FileManager.default.contentsOfDirectory(atPath: detached.path)) == Set(expectedNames.map { $0.uuidString.lowercased() + ".json" }))
        #expect(try Data(contentsOf: sentinel) == privateBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path) == [attemptedID.uuidString.lowercased() + ".json"])
        try fixture.expectSourcesUnchanged()
    }

    @Test("Integrity auditing detects a validly encoded changed immutable artifact by its exact named binding")
    func auditDetectsArtifactByteDrift() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID()
        let receipt = try fixture.save(result: fixture.result(), jobID: id)
        let editedBytes = try fixture.encodeResult(fixture.result(extraWarning: "Changed historical diagnostic"))
        try editedBytes.write(to: fixture.artifactURL(id))
        let before = try fixture.snapshot()
        let reopened = try CaseStore.open(at: fixture.caseURL)
        let report = try await CaseIntegrityAuditor.audit(forensicCase: reopened)
        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == "job.artifact.changed" && $0.status == .fail && $0.sha256 == EngineJobFixture.hash(editedBytes) })
        #expect(!report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == "job.artifact.verified" && $0.sha256 == receipt.artifactSHA256 })
        #expect(try fixture.snapshot() == before)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Audit classification distinguishes observed invalid artifacts, unsupported schemas, size receipts and genuine absence", arguments: ["malformedMatchingReceipt", "unsupportedMatchingReceipt", "unsupportedChanged", "symlink", "fifo", "absent", "legacyUnknownCount", "wrongDeclaredCount"])
    func artifactAuditClassification(_ mode: String) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let id = UUID()
        _ = try fixture.save(result: fixture.result(), jobID: id)
        let artifact = fixture.artifactURL(id)
        let outside = fixture.root.appendingPathComponent("unrelated-target.json")
        let outsideBytes = Data("UNRELATED_TARGET_MUST_NOT_BE_READ_OR_CHANGED".utf8)
        var editedBytes: Data?
        if mode == "legacyUnknownCount" || mode == "wrongDeclaredCount" {
            var manifest = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: fixture.manifestURL)) as? [String: Any])
            var provenance = try #require(manifest["provenance"] as? [String: Any])
            var jobs = try #require(provenance["jobs"] as? [[String: Any]])
            if mode == "legacyUnknownCount" { jobs[0].removeValue(forKey: "artifactByteCount") }
            else { jobs[0]["artifactByteCount"] = try Data(contentsOf: artifact).count + 1 }
            provenance["jobs"] = jobs; manifest["provenance"] = provenance
            try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: fixture.manifestURL)
        } else if mode == "absent" { try FileManager.default.removeItem(at: artifact) }
        else if mode == "fifo" {
            try FileManager.default.removeItem(at: artifact)
            #expect(Darwin.mkfifo(artifact.path, mode_t(0o600)) == 0)
        } else if mode == "symlink" {
            try outsideBytes.write(to: outside)
            try FileManager.default.removeItem(at: artifact)
            try FileManager.default.createSymbolicLink(at: artifact, withDestinationURL: outside)
        } else {
            var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: artifact)) as? [String: Any])
            if mode == "malformedMatchingReceipt" { object = ["schemaVersion": 1] }
            else { object["schemaVersion"] = 999 }
            let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
            try bytes.write(to: artifact); editedBytes = bytes
            if mode.hasSuffix("MatchingReceipt") {
                // A coordinated unsigned hash rewrite must still require a
                // supported, valid artifact schema rather than claim absence.
                var manifest = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: fixture.manifestURL)) as? [String: Any])
                var provenance = try #require(manifest["provenance"] as? [String: Any])
                var jobs = try #require(provenance["jobs"] as? [[String: Any]])
                jobs[0]["artifactSHA256"] = EngineJobFixture.hash(bytes)
                jobs[0]["artifactByteCount"] = bytes.count
                provenance["jobs"] = jobs; manifest["provenance"] = provenance
                try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: fixture.manifestURL)
            }
        }
        let opened = try CaseStore.open(at: fixture.caseURL)
        let before = try fixture.snapshot()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: opened)
        let expected = mode == "legacyUnknownCount" ? "job.artifact.verified" : mode == "absent" ? "job.artifact.missing" : mode == "unsupportedMatchingReceipt" ? "job.artifact.unavailable" : mode == "unsupportedChanged" ? "job.artifact.changed" : mode == "wrongDeclaredCount" ? "job.artifact.sizeChanged" : "job.artifact.invalid"
        let expectedStatus: CaseIntegrityStatus = mode == "legacyUnknownCount" ? .pass : mode == "unsupportedMatchingReceipt" ? .unavailable : .fail
        #expect(report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == expected && $0.status == expectedStatus })
        if mode != "absent" { #expect(!report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == "job.artifact.missing" }) }
        if mode.hasPrefix("unsupported") { #expect(report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == "metadata.schema.unsupported" && $0.status == .unavailable }) }
        if mode == "unsupportedChanged", let editedBytes {
            #expect(report.checks.contains { $0.code == "job.artifact.changed" && $0.sha256 == EngineJobFixture.hash(editedBytes) })
        }
        if mode == "legacyUnknownCount" {
            #expect(opened.manifest.provenance?.jobs.first?.artifactByteCount == nil)
            #expect(report.isPartial)
            #expect(report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == "job.artifact.sizeUnavailable" && $0.status == .unavailable })
            let retry = try fixture.save(result: fixture.result(), jobID: id)
            #expect(retry.wasAlreadyRecorded)
            #expect(retry.job.artifactByteCount == nil)
        }
        else { #expect(!report.checks.contains { $0.relativePath == fixture.artifactRelativePath(id) && $0.code == "job.artifact.verified" }) }
        #expect(try fixture.snapshot() == before)
        if mode == "symlink" {
            #expect(try Data(contentsOf: outside) == outsideBytes)
            #expect(!report.checks.contains { $0.sha256 == EngineJobFixture.hash(outsideBytes) })
        }
        try fixture.expectSourcesUnchanged()
    }

    @Test("Faults at every exposed engine save checkpoint retain prior work and truthfully report each committed phase", arguments: EngineJobSaveCheckpoint.allCases)
    func persistenceBoundaryFaults(_ point: EngineJobSaveCheckpoint) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let oldID = UUID(), newID = UUID()
        let original = fixture.result()
        _ = try fixture.save(result: original, jobID: oldID)
        let oldArtifact = try Data(contentsOf: fixture.artifactURL(oldID))
        let oldManifest = try Data(contentsOf: fixture.manifestURL)
        let oldCache = try Data(contentsOf: fixture.cacheURL)
        let before = try fixture.snapshot()
        // This exceeds one 64 KiB write chunk while retaining the production
        // per-warning and total result budgets. The first-chunk fault therefore
        // interrupts a genuinely incomplete staged write.
        let attempted = fixture.result(status: .partial, marker: "faulted job",
            extraWarning: String(repeating: "S", count: 65_536))
        let attemptedBytes = try fixture.encodeResult(attempted)
        #expect(attemptedBytes.count > 65_536)
        var reached = false
        var observed: (any Error)?
        do {
            _ = try EngineResultStore.saveWithJobProvenanceForTesting(result: attempted,
                evidenceID: fixture.evidence.id, in: fixture.caseURL, jobID: newID,
                startedAt: fixture.startedAt, executableSHA256: EngineJobFixture.executableHash) { checkpoint, written in
                    if checkpoint == point {
                        reached = true
                        if checkpoint == .afterArtifactWriteChunk || checkpoint == .afterLatestWriteChunk {
                            #expect(written > 0 && written <= 65_536 && written < attemptedBytes.count)
                        }
                        throw EngineJobInjectedFault.interrupted(point)
                    }
                }
            Issue.record("The selected persistence fault was swallowed.")
        } catch { observed = error }
        #expect(reached)
        let error = try #require(observed)
        let expected = EngineJobBoundaryExpectation.forCheckpoint(point)
        if expected.artifact == .notCommitted {
            #expect(error as? EngineJobInjectedFault == .interrupted(point))
            #expect(!FileManager.default.fileExists(atPath: fixture.artifactURL(newID).path))
            #expect(try fixture.snapshot() == before)
        } else {
            let typed = try #require(error as? EngineJobSaveError)
            guard case let .publishedButIncomplete(jobID, artifactSHA256, artifactState, manifestState, cacheState) = typed else {
                Issue.record("A published save must expose its incomplete commit receipt.")
                return
            }
            #expect(jobID == newID)
            #expect(artifactSHA256 == EngineJobFixture.hash(attemptedBytes))
            #expect(artifactState == expected.artifact)
            #expect(manifestState == expected.manifest)
            #expect(cacheState == expected.latest)
            #expect(try Data(contentsOf: fixture.artifactURL(newID)) == attemptedBytes)
        }
        #expect(try Data(contentsOf: fixture.artifactURL(oldID)) == oldArtifact)
        let interrupted = try CaseStore.open(at: fixture.caseURL)
        if expected.manifest == .notCommitted {
            #expect(try Data(contentsOf: fixture.manifestURL) == oldManifest)
            #expect(interrupted.manifest.provenance?.jobs.map(\.id) == [oldID])
        } else {
            #expect(interrupted.manifest.provenance?.jobs.map(\.id) == [oldID, newID])
            #expect(interrupted.manifest.provenance?.jobs.last?.artifactSHA256 == EngineJobFixture.hash(attemptedBytes))
        }
        if expected.latest == .notCommitted {
            #expect(try Data(contentsOf: fixture.cacheURL) == oldCache)
            #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == original)
        } else {
            #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == attempted)
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.jobsURL.path).allSatisfy { !$0.hasPrefix(".") })
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.cacheURL.deletingLastPathComponent().path).allSatisfy { !$0.hasPrefix(".") })
        try fixture.expectSourcesUnchanged()

        // Reconciliation retries exact bytes; it never substitutes a different
        // job or silently removes a committed orphan artifact.
        let retry = try fixture.save(result: attempted, jobID: newID)
        #expect(retry.wasAlreadyRecorded == (expected.manifest != .notCommitted))
        #expect(retry.job.artifactSHA256 == EngineJobFixture.hash(attemptedBytes))
        #expect(try fixture.decodeArtifact(newID) == attempted)
        #expect(try Data(contentsOf: fixture.artifactURL(oldID)) == oldArtifact)
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs.map(\.id) == [oldID, newID])
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == attempted)
        let reconciledSnapshot = try fixture.snapshot()
        let audit = try await CaseIntegrityAuditor.audit(forensicCase: retry.forensicCase)
        #expect(!audit.hasFailures)
        #expect(audit.checks.filter { $0.code == "job.artifact.verified" && $0.status == .pass }.count == 2)
        #expect(try fixture.snapshot() == reconciledSnapshot)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Manifest publication faults distinguish an unrecorded orphan from an uncertain committed manifest", arguments: CasePersistenceCheckpoint.allCases)
    func nestedManifestBoundaryFaults(_ point: CasePersistenceCheckpoint) async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let oldID = UUID(), newID = UUID()
        let original = fixture.result()
        _ = try fixture.save(result: original, jobID: oldID)
        let oldArtifact = try Data(contentsOf: fixture.artifactURL(oldID))
        let oldManifest = try Data(contentsOf: fixture.manifestURL)
        let oldCache = try Data(contentsOf: fixture.cacheURL)
        let attempted = fixture.result(status: .partial, marker: "nested manifest fault",
            extraWarning: String(repeating: "M", count: 65_536))
        let attemptedBytes = try fixture.encodeResult(attempted)
        var reached = false
        var observed: (any Error)?
        do {
            _ = try EngineResultStore.saveWithJobProvenanceForTesting(result: attempted,
                evidenceID: fixture.evidence.id, in: fixture.caseURL, jobID: newID,
                startedAt: fixture.startedAt, executableSHA256: EngineJobFixture.executableHash,
                manifestCheckpoint: { checkpoint, written in
                    if checkpoint == point {
                        reached = true
                        if checkpoint == .afterWriteChunk { #expect(written > 0 && written <= 65_536) }
                        throw EngineJobManifestInjectedFault.interrupted(point)
                    }
                }, checkpoint: { _, _ in })
            Issue.record("The nested manifest fault was swallowed.")
        } catch { observed = error }
        #expect(reached)
        let error = try #require(observed as? EngineJobSaveError)
        let wasManifestPublished: Bool
        switch point {
        case .beforeWrite, .afterWriteChunk, .beforeFileFlush, .afterFileFlush, .beforeRename:
            wasManifestPublished = false
        case .afterRename, .beforeDirectoryFlush, .afterDirectoryFlush:
            wasManifestPublished = true
        }
        #expect(error == .publishedButIncomplete(jobID: newID,
            artifactSHA256: EngineJobFixture.hash(attemptedBytes), artifactState: .confirmed,
            manifestState: wasManifestPublished ? .uncertain : .notCommitted, latestCacheState: .notCommitted))
        #expect(try Data(contentsOf: fixture.artifactURL(oldID)) == oldArtifact)
        #expect(try Data(contentsOf: fixture.artifactURL(newID)) == attemptedBytes)
        #expect(try Data(contentsOf: fixture.cacheURL) == oldCache)
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == original)
        let interrupted = try CaseStore.open(at: fixture.caseURL)
        if wasManifestPublished {
            #expect(interrupted.manifest.provenance?.jobs.map(\.id) == [oldID, newID])
            #expect(interrupted.manifest.provenance?.jobs.last?.artifactSHA256 == EngineJobFixture.hash(attemptedBytes))
        } else {
            #expect(try Data(contentsOf: fixture.manifestURL) == oldManifest)
            #expect(interrupted.manifest.provenance?.jobs.map(\.id) == [oldID])
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.caseURL.path).allSatisfy { !$0.hasPrefix(".manifest-") })
        try fixture.expectSourcesUnchanged()
        let retry = try fixture.save(result: attempted, jobID: newID)
        #expect(retry.wasAlreadyRecorded == wasManifestPublished)
        #expect(retry.latestCacheUpdated)
        #expect(try fixture.decodeArtifact(newID) == attempted)
        #expect(try CaseStore.open(at: fixture.caseURL).manifest.provenance?.jobs.map(\.id) == [oldID, newID])
        #expect(try EngineResultStore.load(evidenceID: fixture.evidence.id, in: fixture.caseURL) == attempted)
        let report = try await CaseIntegrityAuditor.audit(forensicCase: retry.forensicCase)
        #expect(!report.hasFailures)
        #expect(report.checks.filter { $0.code == "job.artifact.verified" && $0.status == .pass }.count == 2)
        try fixture.expectSourcesUnchanged()
    }

    @Test("Historical job recording does not open offline evidence or mistake saved hashes for fresh verification")
    func offlineSourceIsHistorical() async throws {
        let fixture = try await EngineJobFixture.make()
        defer { fixture.remove() }
        let result = fixture.result(), id = UUID()
        try FileManager.default.removeItem(at: fixture.source)
        #expect(Darwin.mkfifo(fixture.source.path, mode_t(0o600)) == 0)
        let receipt = try fixture.save(result: result, jobID: id)
        #expect(receipt.job.sourceHashes[receipt.job.selectedSourceOrdinal].sha256 == EngineJobFixture.hash(fixture.sourceBytes))
        let audit = try await CaseIntegrityAuditor.audit(forensicCase: receipt.forensicCase)
        #expect(!audit.sourceRehashed)
        #expect(audit.verifiedSourceCount == 0)
        #expect(audit.checks.contains { $0.code == "source.historical" && $0.status == .historical })
        var metadata = stat()
        #expect(Darwin.lstat(fixture.source.path, &metadata) == 0)
        #expect(metadata.st_mode & S_IFMT == S_IFIFO)
        #expect(try Data(contentsOf: fixture.segment) == fixture.segmentBytes)
    }
}

private enum EngineJobOutcome: Sendable, Hashable {
    case saved(id: UUID, alreadyRecorded: Bool)
    case failure(String)
}

private enum EngineJobInjectedFault: Error, Equatable {
    case interrupted(EngineJobSaveCheckpoint)
}

private enum EngineJobManifestInjectedFault: Error, Equatable {
    case interrupted(CasePersistenceCheckpoint)
}

private struct EngineJobBoundaryExpectation {
    let artifact: EngineJobCommitState
    let manifest: EngineJobCommitState
    let latest: EngineJobCommitState
    static func forCheckpoint(_ point: EngineJobSaveCheckpoint) -> Self {
        switch point {
        case .beforeArtifactWrite, .afterArtifactWriteChunk, .beforeArtifactFileFlush, .afterArtifactFileFlush, .beforeArtifactRename:
            .init(artifact: .notCommitted, manifest: .notCommitted, latest: .notCommitted)
        case .afterArtifactRename, .beforeArtifactDirectoryFlush, .afterArtifactDirectoryFlush:
            .init(artifact: .uncertain, manifest: .notCommitted, latest: .notCommitted)
        case .beforeManifestRecord:
            .init(artifact: .confirmed, manifest: .notCommitted, latest: .notCommitted)
        case .afterManifestRecord, .beforeLatestWrite, .afterLatestWriteChunk, .beforeLatestFileFlush, .afterLatestFileFlush, .beforeLatestRename:
            .init(artifact: .confirmed, manifest: .confirmed, latest: .notCommitted)
        case .afterLatestRename, .beforeLatestDirectoryFlush, .afterLatestDirectoryFlush:
            .init(artifact: .confirmed, manifest: .confirmed, latest: .uncertain)
        case .complete:
            .init(artifact: .confirmed, manifest: .confirmed, latest: .confirmed)
        }
    }
}

private actor EngineJobStartGate {
    private let participants: Int
    private var waiting: [CheckedContinuation<Void, Never>] = []
    init(participants: Int) { self.participants = participants }
    func wait() async {
        await withCheckedContinuation { continuation in
            waiting.append(continuation)
            if waiting.count == participants {
                let ready = waiting
                waiting.removeAll()
                for item in ready { item.resume() }
            }
        }
    }
}

private struct EngineJobSnapshotItem: Equatable {
    let type: mode_t
    let bytes: Data?
    let linkTarget: String?
    let identity: SourceIdentity?
    let permissions: mode_t?
    let linkCount: Int?
}

private struct EngineJobFixture: Sendable {
    static let executableHash = String(repeating: "b", count: 64)
    let root: URL
    let source: URL
    let segment: URL
    let sourceBytes: Data
    let segmentBytes: Data
    let evidence: EvidenceRecord
    let forensicCase: ForensicCase
    let originalManifest: Data
    let identities: [EngineSourceIdentity]
    let startedAt = Date(timeIntervalSince1970: 1_800_000_000.125)
    let completedAt = Date(timeIntervalSince1970: 1_800_000_005)
    var caseURL: URL { forensicCase.bundleURL }
    var manifestURL: URL { caseURL.appendingPathComponent("manifest.json") }
    var jobsURL: URL { caseURL.appendingPathComponent("filesystem-jobs", isDirectory: true) }
    var cacheURL: URL { caseURL.appendingPathComponent("filesystem").appendingPathComponent(evidence.id.uuidString.lowercased() + ".json") }

    static func make(migrate: Bool = true) async throws -> Self {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EngineJobStore-\(UUID().uuidString)", isDirectory: true).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            let source = root.appendingPathComponent("selected-synthetic.dd")
            let segment = root.appendingPathComponent("first-synthetic.dd")
            let sourceBytes = Data("abc".utf8), segmentBytes = Data("xyz".utf8)
            try sourceBytes.write(to: source); try segmentBytes.write(to: segment)
            let freshImage = try await ImageInspector.inspect(url: source) { _ in }
            let initial = try CaseStore.create(name: "Synthetic engine jobs", in: root)
            let withEvidence = try CaseStore.adding(image: freshImage, to: initial)
            let originalManifest = try Data(contentsOf: withEvidence.bundleURL.appendingPathComponent("manifest.json"))
            let current = try migrate ? CaseStore.migrateToSchema2(withEvidence) : withEvidence
            let evidence = try #require(current.manifest.evidence.first)
            let identities = try [segment, source].map { EngineSourceIdentity(path: $0.path, identity: try FileAccess.identity(at: $0)) }
            return Self(root: root, source: source, segment: segment, sourceBytes: sourceBytes,
                segmentBytes: segmentBytes, evidence: evidence, forensicCase: current,
                originalManifest: originalManifest, identities: identities)
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }

    func result(status: EngineTerminalStatus = .completed, marker: String = "first",
                options: EngineOptions? = nil, savedAt: Date? = nil, extraWarning: String? = nil,
                selectedHash: String? = nil, selectedSourceFirst: Bool = false) -> EnumerationResult {
        var warnings = ["Synthetic warning for \(segment.path) and \(source.path)."]
        if status == .partial { warnings.append("A deliberately partial listing.") }
        if let extraWarning { warnings.append(extraWarning) }
        // CaseWork metadata selects the first input. Existing job-only tests
        // retain the non-first selected ordinal unless explicitly opted in.
        let orderedPaths = selectedSourceFirst ? [source.path, segment.path] : [segment.path, source.path]
        let orderedIdentities = selectedSourceFirst ? Array(identities.reversed()) : identities
        return EnumerationResult(engineVersion: "fixture-engine.v2", patchDigest: "independent-fixture-patch.v3",
            sourcePaths: orderedPaths, sourceIdentities: orderedIdentities,
            sourceFileHashes: [segment.path: Self.hash(segmentBytes), source.path: selectedHash ?? Self.hash(sourceBytes)],
            options: options ?? EngineOptions(imageType: "raw", sectorSize: 512, timezone: "Asia/Bangkok", maxFiles: 17, hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 6, sectorSize: 512, imagePaths: orderedPaths),
            volumes: [.init(id: "volume-0", offsetBytes: 0, filesystem: "FAT32", blockSize: 512, blockCount: 1)],
            files: [.init(id: "0:42", path: "/SELECTED.TXT", name: "SELECTED.TXT", fsOffsetBytes: 0,
                metaAddress: 42, size: 3, isDirectory: false, isDeleted: false,
                modifiedEpoch: 1_700_000_000 + Int64(marker.utf8.reduce(0) { $0 + Int($1) }))],
            warnings: warnings, status: status, savedAt: savedAt ?? completedAt)
    }

    @discardableResult
    func save(result: EnumerationResult, jobID: UUID, startedAt: Date? = nil,
              executableHash: String? = Self.executableHash) throws -> EngineJobSaveReceipt {
        try EngineResultStore.saveWithJobProvenance(result: result, evidenceID: evidence.id, in: caseURL,
            jobID: jobID, startedAt: startedAt ?? self.startedAt, executableSHA256: executableHash)
    }

    func artifactRelativePath(_ id: UUID) -> String { "filesystem-jobs/" + id.uuidString.lowercased() + ".json" }
    func artifactURL(_ id: UUID) -> URL { caseURL.appendingPathComponent(artifactRelativePath(id)) }
    func encodeResult(_ result: EnumerationResult) throws -> Data {
        // Immutable artifacts preserve exact reference-date values. The
        // separate latest cache retains ISO8601 plus an exact precision field.
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .deferredToDate
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(result)
    }
    func decodeArtifact(_ id: UUID) throws -> EnumerationResult {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .deferredToDate
        return try decoder.decode(EnumerationResult.self, from: Data(contentsOf: artifactURL(id)))
    }
    func originalManifestBackup(_ current: ForensicCase) throws -> URL {
        let name = try #require(current.manifest.provenance?.migration.backupFilename)
        return caseURL.appendingPathComponent("migrations").appendingPathComponent(name)
    }
    func expectSourcesUnchanged() throws {
        #expect(try Data(contentsOf: source) == sourceBytes)
        #expect(try Data(contentsOf: segment) == segmentBytes)
    }
    func snapshot() throws -> [String: EngineJobSnapshotItem] {
        var result: [String: EngineJobSnapshotItem] = [:]
        func visit(_ directory: URL, prefix: String) throws {
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() {
                let url = directory.appendingPathComponent(name)
                var metadata = stat()
                guard Darwin.lstat(url.path, &metadata) == 0 else { throw FileAccess.posixError("Cannot snapshot synthetic engine job store") }
                let type = metadata.st_mode & S_IFMT
                let path = prefix + name
                result[path] = .init(type: type,
                    bytes: type == S_IFREG ? try Data(contentsOf: url) : nil,
                    linkTarget: type == S_IFLNK ? try FileManager.default.destinationOfSymbolicLink(atPath: url.path) : nil,
                    identity: type == S_IFREG ? SourceIdentity(metadata) : nil,
                    permissions: type == S_IFREG ? metadata.st_mode : nil,
                    linkCount: type == S_IFREG ? Int(metadata.st_nlink) : nil)
                if type == S_IFDIR { try visit(url, prefix: path + "/") }
            }
        }
        try visit(caseURL, prefix: "")
        return result
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
