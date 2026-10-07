import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

struct CaseIntegrityTests {
    @Test("A historical audit reopens caches and receipts without opening an offline FIFO source")
    func historicalAuditNeverOpensEvidence() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let before = try fixture.snapshotCase()
        let manifest = try Data(contentsOf: fixture.manifestURL)
        try FileManager.default.removeItem(at: fixture.source)
        #expect(Darwin.mkfifo(fixture.source.path, mode_t(0o600)) == 0)

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(!report.sourceRehashed)
        #expect(!report.isPartial)
        #expect(!report.hasFailures)
        #expect(report.verifiedSourceCount == 0)
        #expect(report.caseID == fixture.forensicCase.manifest.id)
        #expect(report.manifestSHA256 == CaseIntegrityFixture.hash(manifest))
        #expect(report.checks.contains { $0.code == "manifest.valid" && $0.status == .pass })
        #expect(report.checks.contains { $0.code == "source.historical" && $0.status == .historical })
        #expect(report.checks.contains { $0.relativePath == fixture.cacheRelativePath && $0.code == "metadata.valid" })
        #expect(report.checks.contains { $0.relativePath == fixture.findingRelativePath && $0.code == "metadata.valid" })
        #expect(try fixture.snapshotCase() == before)
        var metadata = stat()
        #expect(Darwin.lstat(fixture.source.path, &metadata) == 0)
        #expect(metadata.st_mode & S_IFMT == S_IFIFO)
    }

    @Test("Fresh verification distinguishes unchanged, same-size drift, resized and offline sources", arguments: ["unchanged", "sameSize", "resized", "offline"])
    func freshSourceVerification(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        if mode == "sameSize" { try Data(repeating: 0x57, count: fixture.sourceBytes.count).write(to: fixture.source) }
        if mode == "resized" { try Data("shortened source".utf8).write(to: fixture.source) }
        if mode == "offline" { try FileManager.default.removeItem(at: fixture.source) }
        let before = try fixture.snapshotCase()
        let sourceBefore: Data? = try mode == "offline" ? nil : Data(contentsOf: fixture.source)

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase,
            options: CaseIntegrityAuditOptions(freshEvidenceRehash: true))

        #expect(report.sourceRehashed)
        let code = mode == "unchanged" ? "source.verified" : mode == "offline" ? "source.offline" : "source.changed"
        let check = try #require(report.checks.first { $0.code == code })
        #expect(check.evidenceID == fixture.evidence.id)
        if mode == "unchanged" {
            #expect(check.status == .pass)
            #expect(check.byteCount == fixture.evidence.byteCount)
            #expect(check.sha256 == fixture.evidence.sha256)
            #expect(report.verifiedSourceCount == 1)
            #expect(!report.hasFailures)
        } else if mode == "offline" {
            #expect(check.status == .offline)
            #expect(report.verifiedSourceCount == 0)
        } else {
            #expect(check.status == .fail)
            #expect(report.hasFailures)
            #expect(report.verifiedSourceCount == 0)
        }
        #expect(try fixture.snapshotCase() == before)
        if let sourceBefore { #expect(try Data(contentsOf: fixture.source) == sourceBefore) }
        else { #expect(!FileManager.default.fileExists(atPath: fixture.source.path)) }
    }

    @Test("Malformed and unsupported filesystem caches and sidecars are diagnosed without repair", arguments: ["cacheMalformed", "cacheVersion", "findingMalformed", "findingVersion"])
    func malformedOrUnsupportedMetadata(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let relative = mode.hasPrefix("cache") ? fixture.cacheRelativePath : fixture.findingRelativePath
        let file = fixture.caseURL.appendingPathComponent(relative)
        if mode.hasSuffix("Malformed") { try Data("{\"schemaVersion\":1,".utf8).write(to: file) }
        else {
            var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
            object["schemaVersion"] = 999
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: file)
        }
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        let code = mode.hasSuffix("Version") ? "metadata.schema.unsupported" : "metadata.invalid"
        let check = try #require(report.checks.first { $0.relativePath == relative && $0.code == code })
        #expect(check.status == .fail || check.status == .unavailable)
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Validly encoded metadata cannot claim a different selected-file hash or byte count", arguments: ["cacheHash", "findingSize"])
    func sourceBindingMismatch(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let relative = mode == "cacheHash" ? fixture.cacheRelativePath : fixture.findingRelativePath
        let file = fixture.caseURL.appendingPathComponent(relative)
        var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        if mode == "cacheHash" {
            var hashes = try #require(object["sourceFileHashes"] as? [String: String])
            hashes[fixture.source.path] = String(repeating: "a", count: 64)
            object["sourceFileHashes"] = hashes
        } else {
            var binding = try #require(object["binding"] as? [String: Any])
            binding["selectedContainerByteCount"] = fixture.evidence.byteCount + 1
            object["binding"] = binding
        }
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: file)
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.checks.contains { $0.relativePath == relative && $0.code == "metadata.invalid" && $0.status == .fail })
        #expect(report.hasFailures)
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Auditing a stale opened case fails instead of silently adopting a changed manifest")
    func staleManifestPreserved() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let secondSource = fixture.root.appendingPathComponent("second-synthetic.dd")
        let bytes = Data("Additional synthetic source".utf8)
        try bytes.write(to: secondSource)
        let image = try await ImageInspector.inspect(url: secondSource) { _ in }
        _ = try CaseStore.adding(image: image, to: fixture.forensicCase)
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.checks.contains { $0.code == "storage.changed" && $0.status == .fail })
        #expect(report.isPartial)
        #expect(report.verifiedSourceCount == 0)
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: secondSource) == bytes)
    }

    @Test("An unknown manifest schema stays unavailable and is never migrated by auditing")
    func unsupportedManifestPreserved() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: fixture.manifestURL)) as? [String: Any])
        object["schemaVersion"] = 999
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: fixture.manifestURL)
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.isPartial)
        #expect(report.checks.contains { $0.code == "metadata.schema.unsupported" && $0.status == .unavailable && $0.relativePath == "manifest.json" })
        #expect(!report.checks.contains { $0.code == "manifest.valid" })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Symlink case roots, cache directories and cache files cannot redirect an audit", arguments: ["root", "directory", "file"])
    func symlinkStorageRefused(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent("sentinel.json")
        let privateBytes = Data("PRIVATE_OUTSIDE_TARGET_MUST_NOT_BE_READ_OR_CHANGED".utf8)
        try privateBytes.write(to: sentinel)
        var supplied = fixture.forensicCase
        if mode == "root" {
            let alias = fixture.root.appendingPathComponent("alias.nativecase", isDirectory: true)
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture.caseURL)
            supplied = ForensicCase(bundleURL: alias, manifest: fixture.forensicCase.manifest)
        } else if mode == "directory" {
            let cacheDirectory = fixture.caseURL.appendingPathComponent("filesystem", isDirectory: true)
            try FileManager.default.removeItem(at: cacheDirectory)
            try FileManager.default.createSymbolicLink(at: cacheDirectory, withDestinationURL: outside)
        } else {
            try FileManager.default.removeItem(at: fixture.cacheURL)
            try FileManager.default.createSymbolicLink(at: fixture.cacheURL, withDestinationURL: sentinel)
        }
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: supplied)

        #expect(report.hasFailures)
        #expect(report.checks.contains { $0.code == "storage.unsafe" && $0.status == .fail })
        #expect(!report.checks.contains { $0.sha256 == CaseIntegrityFixture.hash(privateBytes) })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: sentinel) == privateBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path) == ["sentinel.json"])
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Fresh evidence verification refuses a substituted source symlink without following its target")
    func sourceSymlinkRefused() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let target = fixture.root.appendingPathComponent("replacement.dd")
        let bytes = Data(repeating: 0x4e, count: fixture.sourceBytes.count)
        try bytes.write(to: target)
        try FileManager.default.removeItem(at: fixture.source)
        try FileManager.default.createSymbolicLink(at: fixture.source, withDestinationURL: target)
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase,
            options: CaseIntegrityAuditOptions(freshEvidenceRehash: true))

        #expect(report.checks.contains { $0.code == "source.unsafe" && $0.status == .fail })
        #expect(report.verifiedSourceCount == 0)
        #expect(!report.checks.contains { $0.sha256 == CaseIntegrityFixture.hash(bytes) })
        #expect(try Data(contentsOf: target) == bytes)
        #expect(try fixture.snapshotCase() == before)
    }

    @Test("Fresh verification refuses a substituted evidence parent-directory symlink")
    func sourceParentSymlinkRefused() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let parent = fixture.root.appendingPathComponent("original-source-parent", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
        let secondSource = parent.appendingPathComponent("second.dd")
        let bytes = Data("Second synthetic source for parent-link rejection".utf8)
        try bytes.write(to: secondSource)
        let image = try await ImageInspector.inspect(url: secondSource) { _ in }
        let updatedCase = try CaseStore.adding(image: image, to: fixture.forensicCase)
        let evidence = try #require(updatedCase.manifest.evidence.last)
        let relocatedParent = fixture.root.appendingPathComponent("relocated-source-parent", isDirectory: true)
        try FileManager.default.moveItem(at: parent, to: relocatedParent)
        try FileManager.default.createSymbolicLink(at: parent, withDestinationURL: relocatedParent)
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: updatedCase,
            options: CaseIntegrityAuditOptions(freshEvidenceRehash: true))

        #expect(report.checks.contains { $0.code == "source.unsafe" && $0.status == .fail && $0.evidenceID == evidence.id })
        #expect(!report.checks.contains { $0.code == "source.verified" && $0.evidenceID == evidence.id })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: relocatedParent.appendingPathComponent("second.dd")) == bytes)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("A source parent replaced after its held hash cannot produce a fresh verification pass")
    func sourceParentReplacementAfterHash() async throws {
        let fixture = try await CaseIntegrityFixture.make(nestedSource: true)
        defer { fixture.remove() }
        let originalParent = fixture.source.deletingLastPathComponent()
        let movedParent = fixture.root.appendingPathComponent("held-source-parent", isDirectory: true)
        let movedSource = movedParent.appendingPathComponent(fixture.source.lastPathComponent)
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.auditForTesting(forensicCase: fixture.forensicCase,
            options: CaseIntegrityAuditOptions(freshEvidenceRehash: true), afterSourceRead: { _ in
                // Replace the pathname at the precise held-descriptor boundary;
                // both old and new source files retain the same name and bytes.
                try FileManager.default.moveItem(at: originalParent, to: movedParent)
                try FileManager.default.createDirectory(at: originalParent, withIntermediateDirectories: false)
                try fixture.sourceBytes.write(to: fixture.source)
            })

        #expect(report.checks.contains { $0.code == "source.changed" && $0.status == .fail && $0.evidenceID == fixture.evidence.id })
        #expect(!report.checks.contains { $0.code == "source.verified" })
        #expect(report.verifiedSourceCount == 0)
        #expect(report.hasFailures)
        #expect(try Data(contentsOf: movedSource) == fixture.sourceBytes)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try fixture.snapshotCase() == before)
        var movedMetadata = stat(), replacementMetadata = stat()
        #expect(Darwin.lstat(movedParent.path, &movedMetadata) == 0)
        #expect(Darwin.lstat(originalParent.path, &replacementMetadata) == 0)
        #expect(movedMetadata.st_dev != replacementMetadata.st_dev || movedMetadata.st_ino != replacementMetadata.st_ino)
    }

    @Test("File and metadata audit budgets disclose partial coverage without changing stored bytes", arguments: ["files", "metadata", "source"])
    func coverageLimits(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let before = try fixture.snapshotCase()
        let options: CaseIntegrityAuditOptions
        switch mode {
        case "files": options = CaseIntegrityAuditOptions(maximumFiles: 1)
        case "metadata": options = CaseIntegrityAuditOptions(maximumMetadataBytes: 16)
        default: options = CaseIntegrityAuditOptions(freshEvidenceRehash: true, maximumSourceBytes: 16)
        }

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase, options: options)

        #expect(report.isPartial)
        let code = mode == "source" ? "source.unavailable" : "coverage.limit"
        #expect(report.checks.contains { $0.status == .unavailable && $0.code == code })
        #expect(report.verifiedSourceCount == 0)
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Recovery audit independently hashes stored payloads and identifies same-size corruption or deletion", arguments: ["valid", "changed", "missing"])
    func recoveryPayloadVerification(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let recovery = try fixture.saveRecovery()
        if mode == "changed" { try Data(repeating: 0x58, count: recovery.bytes.count).write(to: recovery.payload) }
        if mode == "missing" { try FileManager.default.removeItem(at: recovery.payload) }
        let before = try fixture.snapshotCase()
        try FileManager.default.removeItem(at: fixture.source)

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        let code = mode == "valid" ? "payload.verified" : mode == "changed" ? "payload.changed" : "payload.missing"
        let check = try #require(report.checks.first { $0.code == code && $0.relativePath == recovery.relativePath })
        #expect(check.status == (mode == "valid" ? .pass : .fail))
        if mode == "valid" {
            #expect(check.byteCount == Int64(recovery.bytes.count))
            #expect(check.sha256 == CaseIntegrityFixture.hash(recovery.bytes))
        }
        #expect(report.hasFailures == (mode != "valid"))
        #expect(!report.sourceRehashed)
        #expect(report.verifiedSourceCount == 0)
        #expect(try fixture.snapshotCase() == before)
        #expect(!FileManager.default.fileExists(atPath: fixture.source.path))
    }

    @Test("UDF checksums and latest pointers are verified independently of valid result schemas", arguments: ["valid", "resultBytes", "checksum", "latest"])
    func udfGenerationReceipts(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let paths = try fixture.saveUDF()
        if mode != "valid" {
            let relative = mode == "resultBytes" ? paths.result : mode == "checksum" ? paths.checksum : paths.latest
            let url = fixture.caseURL.appendingPathComponent(relative)
            var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            if mode == "resultBytes" { object["volumeIdentifier"] = "ALTERED_SYNTHETIC_VOLUME" }
            else { object["resultSHA256"] = String(repeating: "a", count: 64) }
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
        }
        let before = try fixture.snapshotCase()
        try FileManager.default.removeItem(at: fixture.source)

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        if mode == "valid" {
            #expect(report.checks.contains { $0.code == "optical.checksum.valid" && $0.status == .pass && $0.relativePath == paths.result })
            #expect(report.checks.contains { $0.code == "optical.pointer.valid" && $0.status == .pass && $0.relativePath == paths.latest })
            #expect(!report.hasFailures)
        } else {
            let code = mode == "latest" ? "optical.pointer.invalid" : "optical.checksum.invalid"
            #expect(report.checks.contains { $0.code == code && $0.status == .fail })
            #expect(report.hasFailures)
        }
        #expect(!report.sourceRehashed)
        #expect(report.verifiedSourceCount == 0)
        #expect(try fixture.snapshotCase() == before)
        #expect(!FileManager.default.fileExists(atPath: fixture.source.path))
    }

    @Test("An orphan UDF checksum cannot pass even when its pointer schema is valid")
    func orphanUDFChecksum() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let paths = try fixture.saveUDF()
        try FileManager.default.removeItem(at: fixture.caseURL.appendingPathComponent(paths.result))
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.checks.contains { $0.code == "optical.checksum.invalid" && $0.status == .fail && $0.relativePath == paths.checksum })
        #expect(report.hasFailures)
        #expect(!report.checks.contains { $0.code == "optical.checksum.valid" })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Unknown stores are preserved and disclosed as unavailable", arguments: ["unknownDirectory", "unknownFile"])
    func unknownStoresPreserved(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let privateBytes = Data("PRIVATE_DERIVED_CONTENT_MUST_NOT_BE_AUDITED".utf8)
        if mode == "unknownDirectory" {
            let directory = fixture.caseURL.appendingPathComponent("PRIVATE_UNKNOWN_STORE", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            try privateBytes.write(to: directory.appendingPathComponent("private-content.json"))
        } else {
            try privateBytes.write(to: fixture.caseURL.appendingPathComponent("unknown-derived-index.json"))
        }
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.isPartial)
        #expect(report.checks.contains { $0.code == "storage.unrecognized" && $0.status == .unavailable })
        #expect(!report.hasFailures)
        #expect(!report.checks.contains { $0.sha256 == CaseIntegrityFixture.hash(privateBytes) })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        let json = String(decoding: try CaseIntegrityReportRenderer.json(report), as: UTF8.self)
        #expect(!json.contains("PRIVATE_UNKNOWN_STORE"))
        #expect(!json.contains("PRIVATE_DERIVED_CONTENT"))
    }

    @Test("Malformed and future content-index schemas are diagnosed without rewriting their bytes", arguments: ["malformed", "futureSchema"])
    func derivedIndexSchema(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let bytes = mode == "malformed" ? Data("{not-json".utf8) : Data("{\"schemaVersion\":999}".utf8)
        try bytes.write(to: fixture.caseURL.appendingPathComponent(CaseContentIndexStore.filename))
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        let code = mode == "malformed" ? "metadata.invalid" : "metadata.schema.unsupported"
        let check = try #require(report.checks.first { $0.code == code && $0.relativePath == CaseContentIndexStore.filename })
        #expect(check.status == (mode == "malformed" ? .fail : .unavailable))
        #expect(!report.checks.contains { $0.code == "derived.index.valid" })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Finding revision gaps and changed finding identities cannot pass complete-chain checks", arguments: ["missingParent", "differentFinding"])
    func findingRevisionChain(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let first = try #require(try CaseWorkStore.loadFinding(id: fixture.findingID, in: fixture.caseURL))
        let second = try first.revised(note: "Second synthetic examiner note", bookmarked: false,
            tags: [], reviewStatus: .unreviewed, reviewReason: "")
        try CaseWorkStore.saveFinding(second, expectedLatestRevisionID: first.id, in: fixture.caseURL)
        if mode == "missingParent" { try FileManager.default.removeItem(at: fixture.caseURL.appendingPathComponent(fixture.findingRelativePath)) }
        else {
            let url = fixture.caseURL.appendingPathComponent("findings/\(second.id.uuidString.lowercased()).json")
            var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
            object["findingID"] = UUID().uuidString
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
        }
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)

        #expect(report.checks.contains { $0.code == "finding.chain.invalid" && $0.status == .fail })
        #expect(report.hasFailures)
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Payload-byte limits retain an unavailable check instead of claiming successful verification")
    func payloadLimit() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        _ = try fixture.saveRecovery()
        let before = try fixture.snapshotCase()

        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase,
            options: CaseIntegrityAuditOptions(maximumPayloadBytes: 1))

        #expect(report.isPartial)
        #expect(report.checks.contains { $0.code == "coverage.limit" && $0.status == .unavailable })
        #expect(!report.checks.contains { $0.code == "payload.verified" })
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("JSON and Markdown audit exports redact host paths by default and permit explicit private-path inclusion")
    func reportRedaction() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let before = try fixture.snapshotCase()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase,
            options: CaseIntegrityAuditOptions(freshEvidenceRehash: true))
        let defaultJSON = try CaseIntegrityReportRenderer.json(report)
        let defaultMarkdown = try CaseIntegrityReportRenderer.markdown(report)
        for data in [defaultJSON, defaultMarkdown] {
            let text = String(decoding: data, as: UTF8.self)
            #expect(!text.contains(fixture.root.path))
            #expect(!text.contains(fixture.caseURL.path))
            #expect(!text.contains(fixture.source.path))
            #expect(text.contains(fixture.evidence.sha256))
            #expect(text.contains(fixture.cacheRelativePath))
        }
        let object = try #require(try JSONSerialization.jsonObject(with: defaultJSON) as? [String: Any])
        #expect(object["casePath"] == nil || object["casePath"] is NSNull)
        for data in [try CaseIntegrityReportRenderer.json(report, includePrivatePaths: true),
                     try CaseIntegrityReportRenderer.markdown(report, includePrivatePaths: true)] {
            let text = String(decoding: data, as: UTF8.self)
            #expect(text.contains(fixture.caseURL.path))
            #expect(text.contains(fixture.source.path))
        }
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }

    @Test("Report exports verify exact bytes and never overwrite an existing publication", arguments: CaseIntegrityReportFormat.allCases)
    func exclusiveReportExport(_ format: CaseIntegrityReportFormat) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let before = try fixture.snapshotCase()
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        let destination = fixture.root.appendingPathComponent("audit.\(format == .json ? "json" : "md")")
        let expected = try format == .json ? CaseIntegrityReportRenderer.json(report) : CaseIntegrityReportRenderer.markdown(report)

        let output = try await CaseIntegrityReportExporter.export(report: report, forensicCase: fixture.forensicCase,
            format: format, to: destination)

        #expect(output == destination)
        #expect(try Data(contentsOf: destination) == expected)
        await #expect(throws: ForensicsError.caseAlreadyExists) {
            try await CaseIntegrityReportExporter.export(report: report, forensicCase: fixture.forensicCase,
                format: format, to: destination)
        }
        #expect(try Data(contentsOf: destination) == expected)
        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(!(try FileManager.default.contentsOfDirectory(atPath: fixture.root.path))
            .contains { $0.hasPrefix(".integrity-report-") })
    }

    @Test("Report publication refuses evidence, case storage and symbolic-link destinations", arguments: ["source", "case", "parentAlias", "leafAlias"])
    func unsafeReportDestinations(_ mode: String) async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let report = try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase)
        let outside = fixture.root.appendingPathComponent("export-parent", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let target = outside.appendingPathComponent("keep.json")
        let sentinel = Data("Preserved private export target".utf8)
        try sentinel.write(to: target)
        let destination: URL
        switch mode {
        case "source": destination = fixture.source
        case "case": destination = fixture.caseURL.appendingPathComponent("audit.json")
        case "parentAlias":
            let alias = fixture.root.appendingPathComponent("export-parent-alias", isDirectory: true)
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: outside)
            destination = alias.appendingPathComponent("audit.json")
        default:
            let alias = fixture.root.appendingPathComponent("export-leaf-alias.json")
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: target)
            destination = alias
        }
        let before = try fixture.snapshotCase()

        await #expect(throws: (any Error).self) {
            try await CaseIntegrityReportExporter.export(report: report, forensicCase: fixture.forensicCase,
                format: .json, to: destination)
        }

        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: target) == sentinel)
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path) == ["keep.json"])
        #expect(!(try FileManager.default.contentsOfDirectory(atPath: fixture.root.path))
            .contains { $0.hasPrefix(".integrity-report-") })
    }

    @Test("Cancellation at the first audit progress boundary preserves the whole case and source")
    func cancellationPreservesCase() async throws {
        let fixture = try await CaseIntegrityFixture.make()
        defer { fixture.remove() }
        let before = try fixture.snapshotCase()
        let worker = Task.detached {
            try await CaseIntegrityAuditor.audit(forensicCase: fixture.forensicCase,
                options: CaseIntegrityAuditOptions(freshEvidenceRehash: true), progress: { _ in
                    withUnsafeCurrentTask { $0?.cancel() }
                })
        }

        await #expect(throws: CancellationError.self) { try await worker.value }

        #expect(try fixture.snapshotCase() == before)
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
    }
}

private struct CaseIntegrityFixture: Sendable {
    let root: URL
    let source: URL
    let sourceBytes: Data
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let findingID: UUID
    var caseURL: URL { forensicCase.bundleURL }
    var manifestURL: URL { caseURL.appendingPathComponent("manifest.json") }
    var cacheRelativePath: String { "filesystem/\(evidence.id.uuidString.lowercased()).json" }
    var cacheURL: URL { caseURL.appendingPathComponent(cacheRelativePath) }
    var findingRelativePath: String { "findings/\(findingID.uuidString.lowercased()).json" }

    static func make(nestedSource: Bool = false) async throws -> Self {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("CaseIntegrityTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            let sourceParent = nestedSource ? root.appendingPathComponent("original-source-parent", isDirectory: true) : root
            if nestedSource { try FileManager.default.createDirectory(at: sourceParent, withIntermediateDirectories: false) }
            let source = sourceParent.appendingPathComponent("synthetic-private-source.dd")
            let sourceBytes = Data(repeating: 0x32, count: 8_192)
            try sourceBytes.write(to: source)
            let created = try CaseStore.create(name: "Synthetic Integrity", in: root)
            let image = try await ImageInspector.inspect(url: source) { _ in }
            let forensicCase = try CaseStore.adding(image: image, to: created)
            let evidence = try #require(forensicCase.manifest.evidence.first)
            let file = FilesystemEntry(id: "0:1", path: "/HELLO.TXT", name: "HELLO.TXT", fsOffsetBytes: 0,
                metaAddress: 1, size: 3, isDirectory: false, isDeleted: false, modifiedEpoch: 1_700_000_000)
            let result = EnumerationResult(engineVersion: "integrity-synthetic", patchDigest: "synthetic-only",
                sourcePaths: [source.path], sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(),
                image: EngineImageMetadata(imageType: "raw", logicalSize: evidence.byteCount, sectorSize: 512,
                    logicalSha256: String(repeating: "e", count: 64)), volumes: [], files: [file],
                warnings: ["Synthetic diagnostic \(source.path)"], status: .completed)
            try EngineResultStore.save(result: result, evidenceID: evidence.id, in: forensicCase.bundleURL)
            let binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: file)
            let finding = try FindingRecord.create(binding: binding, note: "Synthetic examiner note", bookmarked: true)
            try CaseWorkStore.saveFinding(finding, expectedLatestRevisionID: nil, in: forensicCase.bundleURL)
            return Self(root: root, source: source, sourceBytes: sourceBytes, forensicCase: forensicCase,
                evidence: evidence, findingID: finding.id)
        } catch {
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func saveRecovery() throws -> (payload: URL, relativePath: String, bytes: Data) {
        let bytes = Data("Synthetic recovered payload\n".utf8)
        let input = root.appendingPathComponent("recovery-input")
        try bytes.write(to: input)
        let artifactID = UUID()
        let artifact = CarvedArtifact(id: artifactID, filename: "candidate.txt",
            relativePath: "files/\(artifactID.uuidString.lowercased())", formatHint: "txt",
            byteCount: Int64(bytes.count), sha256: Self.hash(bytes), reportedByteRuns: [], verifiedByteRuns: [],
            validationStatus: .unverified, warnings: ["Source extents unavailable"])
        let result = CarvingResult(caseID: forensicCase.manifest.id, sourceEvidenceID: evidence.id,
            sourceSHA256: evidence.sha256, sourceByteCount: evidence.byteCount, status: .completed,
            artifacts: [artifact], warnings: [], photoRecVersion: "synthetic-test",
            executableSHA256: String(repeating: "a", count: 64), options: RecoveryOptions())
        try RecoveryResultStore.save(result: result, artifactFiles: [artifactID: input], in: forensicCase)
        let relative = "recovery/\(evidence.id.uuidString.lowercased())/\(result.jobID.uuidString.lowercased())/\(artifact.relativePath)"
        return (caseURL.appendingPathComponent(relative), relative, bytes)
    }

    func saveUDF() throws -> (result: String, checksum: String, latest: String) {
        let timestamp = UDFTimestamp(rawHex: "0010e7070b0e160d14000000", sourceOffset: 64,
            type: 1, timezoneMinutes: 0, utcDate: Date(timeIntervalSince1970: 1_700_000_000), microsecond: 0)
        let snapshot = UDFSnapshot(id: "synthetic-vat", vatICBSourceOffset: 128,
            previousVATLogicalBlock: nil, mappedBlockCount: 0, namespaceFileCount: 0, modification: timestamp)
        // This is a synthetic model receipt, not a claim that the source was parsed as UDF.
        let result = UDFInspectionResult(caseID: forensicCase.manifest.id, sourceEvidenceID: evidence.id,
            sourceSHA256: evidence.sha256, sourceByteCount: evidence.byteCount, parserVersion: "integrity-model-fixture",
            volumeIdentifier: "SYNTHETIC", udfRevision: "2.01", latestSnapshotID: snapshot.id,
            snapshots: [snapshot], entries: [], deletedAncestors: [],
            limitations: ["Synthetic metadata integrity fixture; no parser outcome claimed."], options: UDFInspectionOptions())
        _ = try UDFResultStore.save(result, in: forensicCase)
        let evidencePath = "optical/\(evidence.id.uuidString.lowercased())"
        let generation = evidencePath + "/generations/\(result.jobID.uuidString.lowercased())"
        return (generation + "/result.json", generation + "/checksum.json", evidencePath + "/latest.json")
    }

    /// Captures names, kinds, regular bytes and link text without following links.
    /// This deliberately does not use source hashing or the auditor under test.
    func snapshotCase() throws -> [String: CaseIntegritySnapshotEntry] {
        var entries: [String: CaseIntegritySnapshotEntry] = [:]
        func walk(_ directory: URL, prefix: String) throws {
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() {
                let url = directory.appendingPathComponent(name)
                let relative = prefix.isEmpty ? name : "\(prefix)/\(name)"
                var metadata = stat()
                guard Darwin.lstat(url.path, &metadata) == 0 else { throw FileAccess.posixError("Cannot snapshot synthetic case") }
                switch metadata.st_mode & S_IFMT {
                case S_IFDIR: entries[relative] = .directory; try walk(url, prefix: relative)
                case S_IFREG: entries[relative] = .file(try Data(contentsOf: url))
                case S_IFLNK: entries[relative] = .link(try FileManager.default.destinationOfSymbolicLink(atPath: url.path))
                default: entries[relative] = .other
                }
            }
        }
        try walk(caseURL, prefix: "")
        return entries
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

private enum CaseIntegritySnapshotEntry: Equatable {
    case file(Data), directory, link(String), other
}
