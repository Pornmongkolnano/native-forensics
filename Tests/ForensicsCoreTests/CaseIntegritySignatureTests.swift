import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

struct CaseIntegritySignatureTests {
    @Test("A full signed report verifies with an independently supplied trusted key and preserves fractional dates")
    func trustedRoundTrip() throws {
        let key = try fixtureKey(1)
        let report = fixtureReport()
        let envelope = try CaseIntegritySignature.sign(report: report, using: key)
        let canonical = try CaseIntegritySignature.canonicalReportJSON(report)
        let bytes = try CaseIntegritySignature.json(envelope)

        #expect(envelope.reportSHA256 == digest(canonical))
        #expect(envelope.signerPublicKey == key.publicKey.rawRepresentation)
        #expect(envelope.signature.count == 64)
        #expect(try CaseIntegritySignature.verify(envelope, trustedPublicKey: key.publicKey) == report)
        #expect(try CaseIntegritySignature.decodeAndVerify(bytes, trustedPublicKey: key.publicKey) == report)
        // CryptoKit randomizes Ed25519 signatures for side-channel protection.
        // Repeated signing preserves the report, digest and key; both resulting
        // signatures must independently verify rather than be byte-identical.
        let repeated = try CaseIntegritySignature.sign(report: report, using: key)
        #expect(repeated.report == report)
        #expect(repeated.reportSHA256 == envelope.reportSHA256)
        #expect(repeated.signerPublicKey == envelope.signerPublicKey)
        #expect(try CaseIntegritySignature.canonicalReportJSON(repeated.report) == canonical)
        #expect(try CaseIntegritySignature.verify(repeated, trustedPublicKey: key.publicKey) == report)
        #expect(try CaseIntegritySignature.decodeAndVerify(CaseIntegritySignature.json(repeated),
            trustedPublicKey: key.publicKey) == report)
        #expect(String(decoding: bytes, as: UTF8.self).contains(report.casePath))
        #expect(String(decoding: canonical, as: UTF8.self).contains(try #require(report.checks[0].privatePath)))
        #expect(report.startedAt.timeIntervalSinceReferenceDate == 780_000_000.1234567)
        #expect(try CaseIntegritySignature.json(envelope) == bytes)
    }

    @Test("Version 1 canonical report bytes match an explicit fixture and independently computed SHA-256")
    func canonicalReportVector() throws {
        let expected = #"""
        {"caseID":"AAAAAAAA-0000-0000-0000-000000000002",
        "casePath":"/synthetic/private/case.nativecase",
        "checks":[
        {"code":"source.receipt","evidenceID":"AAAAAAAA-0000-0000-0000-000000000003","id":"AAAAAAAA-0000-0000-0000-000000000005","message":"Historical synthetic receipt; bytes not reopened","privatePath":"/synthetic/private/source.dd","recordedByteCount":4096,"recordedSHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","relativePath":"manifest.json","status":"historical"},
        {"code":"coverage.unavailable","id":"AAAAAAAA-0000-0000-0000-000000000006","message":"Synthetic unavailable source","status":"unavailable"}
        ],
        "completedAt":780000001.7654321,
        "id":"AAAAAAAA-0000-0000-0000-000000000001",
        "isPartial":true,
        "manifestSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "schemaVersion":1,"sourceRehashed":false,"startedAt":780000000.1234567}
        """#.replacingOccurrences(of: "\n", with: "")
        // Computed independently with Python hashlib.sha256 over the explicit
        // UTF-8 fixture above, not derived from the production report codec.
        let expectedSHA256 = "8eab330ab5efd0342450e3f57c45c99e5885c991d5dbc419deabb6bdc31e0056"
        let report = fixtureReport()
        #expect(try CaseIntegritySignature.canonicalReportJSON(report) == Data(expected.utf8))
        #expect(digest(Data(expected.utf8)) == expectedSHA256)
        #expect(try CaseIntegritySignature.sign(report: report, using: fixtureKey(1)).reportSHA256 == expectedSHA256)
    }

    @Test("An embedded attacker key cannot replace an external trusted key")
    func embeddedKeyIsNotTrust() throws {
        let trusted = try fixtureKey(1), attacker = try fixtureKey(2)
        let attackerEnvelope = try CaseIntegritySignature.sign(report: fixtureReport(), using: attacker)
        #expect(throws: CaseIntegritySignatureError.untrustedSigner) {
            try CaseIntegritySignature.verify(attackerEnvelope, trustedPublicKey: trusted.publicKey)
        }
        #expect(throws: CaseIntegritySignatureError.untrustedSigner) {
            try CaseIntegritySignature.decodeAndVerify(CaseIntegritySignature.json(attackerEnvelope),
                trustedPublicKey: trusted.publicKey)
        }
    }

    @Test("Any full-report change invalidates its digest", arguments: ["caseID", "privatePath", "time", "order", "optional", "mode"])
    func changedFullReport(_ field: String) throws {
        let key = try fixtureKey(1), original = fixtureReport()
        let envelope = try CaseIntegritySignature.sign(report: original, using: key)
        var checks = original.checks
        var caseID = original.caseID, startedAt = original.startedAt, rehashed = original.sourceRehashed
        switch field {
        case "caseID": caseID = UUID(uuidString: "aaaaaaaa-0000-0000-0000-000000000004")!
        case "privatePath":
            let check = checks[0]
            checks[0] = CaseIntegrityCheck(id: check.id, status: check.status, code: check.code,
                relativePath: check.relativePath, evidenceID: check.evidenceID, privatePath: "/synthetic/private/changed.dd",
                byteCount: check.byteCount, sha256: check.sha256, recordedByteCount: check.recordedByteCount,
                recordedSHA256: check.recordedSHA256, message: check.message)
        case "time": startedAt = Date(timeIntervalSinceReferenceDate: 780_000_000.1234568)
        case "order": checks.reverse()
        case "optional":
            let check = checks[1]
            checks[1] = CaseIntegrityCheck(id: check.id, status: check.status, code: check.code,
                relativePath: "", privatePath: check.privatePath, message: check.message)
        default: rehashed.toggle()
        }
        let changed = CaseIntegrityReport(id: original.id, caseID: caseID, casePath: original.casePath,
            manifestSHA256: original.manifestSHA256, startedAt: startedAt, completedAt: original.completedAt,
            sourceRehashed: rehashed, isPartial: original.isPartial, checks: checks)
        #expect(throws: CaseIntegritySignatureError.reportHashMismatch) {
            try CaseIntegritySignature.verify(copy(envelope, report: changed), trustedPublicKey: key.publicKey)
        }
    }

    @Test("Rewriting the full report and its hash still requires a new trusted signature")
    func coordinatedReportAndHashRewrite() throws {
        let key = try fixtureKey(1), envelope = try CaseIntegritySignature.sign(report: fixtureReport(), using: key)
        let rewritten = fixtureReport(casePath: "/synthetic/private/rewritten.nativecase")
        let substituted = copy(envelope, reportSHA256: digest(try CaseIntegritySignature.canonicalReportJSON(rewritten)),
            report: rewritten)
        #expect(throws: CaseIntegritySignatureError.invalidSignature) {
            try CaseIntegritySignature.verify(substituted, trustedPublicKey: key.publicKey)
        }
    }

    @Test("Swapped signer keys and signatures fail", arguments: ["key", "keyWithMatchingTrust", "signature", "signatureBit"])
    func swappedKeyOrSignature(_ field: String) throws {
        let trusted = try fixtureKey(1), other = try fixtureKey(2)
        let first = try CaseIntegritySignature.sign(report: fixtureReport(), using: trusted)
        let second = try CaseIntegritySignature.sign(report: fixtureReport(), using: other)
        var signature = first.signature
        signature[signature.startIndex] ^= 1
        let edited: CaseIntegritySignedEnvelope
        switch field {
        case "key", "keyWithMatchingTrust": edited = copy(first, signerPublicKey: second.signerPublicKey)
        case "signature": edited = copy(first, signature: second.signature)
        default: edited = copy(first, signature: signature)
        }
        #expect(throws: field == "key" ? CaseIntegritySignatureError.untrustedSigner : .invalidSignature) {
            try CaseIntegritySignature.verify(edited, trustedPublicKey: field == "keyWithMatchingTrust" ? other.publicKey : trusted.publicKey)
        }
    }

    @Test("Envelope framing and malformed cryptographic fields fail closed", arguments: ["version", "algorithm", "canonicalization", "hash", "hashCase", "keySize", "signatureSize"])
    func invalidMetadata(_ field: String) throws {
        let key = try fixtureKey(1), envelope = try CaseIntegritySignature.sign(report: fixtureReport(), using: key)
        let edited: CaseIntegritySignedEnvelope
        let error: CaseIntegritySignatureError
        switch field {
        case "version": edited = copy(envelope, schemaVersion: 2); error = .unsupportedVersion
        case "algorithm": edited = copy(envelope, algorithm: "Curve25519"); error = .unsupportedAlgorithm
        case "canonicalization": edited = copy(envelope, canonicalization: "unknown-json"); error = .unsupportedCanonicalization
        case "hash": edited = copy(envelope, reportSHA256: String(repeating: "0", count: 64)); error = .reportHashMismatch
        case "hashCase": edited = copy(envelope, reportSHA256: String(repeating: "A", count: 64)); error = .invalidEnvelope
        case "keySize": edited = copy(envelope, signerPublicKey: Data(repeating: 1, count: 31)); error = .invalidEnvelope
        default: edited = copy(envelope, signature: Data(repeating: 1, count: 63)); error = .invalidEnvelope
        }
        #expect(throws: error) { try CaseIntegritySignature.verify(edited, trustedPublicKey: key.publicKey) }
    }

    @Test("Canonical envelope parsing rejects unknown, duplicate and alternate JSON bytes", arguments: ["unknown", "duplicate", "whitespace", "trailing", "malformed"])
    func strictWireParsing(_ field: String) throws {
        let key = try fixtureKey(1), envelope = try CaseIntegritySignature.sign(report: fixtureReport(), using: key)
        let bytes = try CaseIntegritySignature.json(envelope)
        let text = String(decoding: bytes, as: UTF8.self)
        let edited: Data
        let error: CaseIntegritySignatureError
        switch field {
        case "unknown": edited = Data(("{\"untrustedExtra\":true," + text.dropFirst()).utf8); error = .nonCanonicalEnvelope
        case "duplicate": edited = Data(("{\"schemaVersion\":1," + text.dropFirst()).utf8); error = .nonCanonicalEnvelope
        case "whitespace": edited = Data((text + "\n").utf8); error = .nonCanonicalEnvelope
        case "trailing": edited = Data((text + "{}").utf8); error = .invalidEnvelope
        default: edited = Data("{broken-json".utf8); error = .invalidEnvelope
        }
        #expect(throws: error) {
            try CaseIntegritySignature.decodeAndVerify(edited, trustedPublicKey: key.publicKey)
        }
    }

    @Test("Invalid options cannot remove hard report, envelope or diagnostic limits", arguments: ["reportZero", "reportLarge", "envelopeNegative", "envelopeLarge", "checksNegative", "checksLarge", "intMax"])
    func invalidOptions(_ field: String) throws {
        let key = try fixtureKey(1)
        let options: CaseIntegritySignatureOptions
        switch field {
        case "reportZero": options = .init(maximumReportBytes: 0)
        case "reportLarge": options = .init(maximumReportBytes: 16 * 1_048_576 + 1)
        case "envelopeNegative": options = .init(maximumEnvelopeBytes: -1)
        case "envelopeLarge": options = .init(maximumEnvelopeBytes: 17 * 1_048_576 + 1)
        case "checksNegative": options = .init(maximumChecks: -1)
        case "checksLarge": options = .init(maximumChecks: 20_002)
        default: options = .init(maximumReportBytes: Int.max)
        }
        #expect(throws: CaseIntegritySignatureError.invalidOptions) {
            try CaseIntegritySignature.sign(report: fixtureReport(), using: key, options: options)
        }
    }

    @Test("Narrow caller budgets bound in-memory reports and untrusted envelope parsing")
    func narrowedLimits() throws {
        let key = try fixtureKey(1), report = fixtureReport()
        let envelope = try CaseIntegritySignature.sign(report: report, using: key)
        let bytes = try CaseIntegritySignature.json(envelope)
        #expect(throws: CaseIntegritySignatureError.reportLimit) {
            try CaseIntegritySignature.sign(report: report, using: key, options: .init(maximumReportBytes: 1))
        }
        #expect(throws: CaseIntegritySignatureError.reportLimit) {
            try CaseIntegritySignature.sign(report: report, using: key, options: .init(maximumChecks: 1))
        }
        #expect(throws: CaseIntegritySignatureError.envelopeLimit) {
            try CaseIntegritySignature.verify(envelope, trustedPublicKey: key.publicKey,
                options: .init(maximumEnvelopeBytes: bytes.count - 1))
        }
        #expect(throws: CaseIntegritySignatureError.envelopeLimit) {
            try CaseIntegritySignature.decodeAndVerify(bytes, trustedPublicKey: key.publicKey,
                options: .init(maximumEnvelopeBytes: bytes.count - 1))
        }
        #expect(try CaseIntegritySignature.decodeAndVerify(bytes, trustedPublicKey: key.publicKey,
            options: .init(maximumEnvelopeBytes: bytes.count)) == report)
    }

    @Test("Aggregate private strings are bounded before report JSON allocation")
    func aggregateStringLimit() throws {
        let key = try fixtureKey(1), base = fixtureReport()
        let check = CaseIntegrityCheck(status: .historical, code: "historical",
            privatePath: String(repeating: "p", count: 32_768), message: "Synthetic historical receipt")
        let report = CaseIntegrityReport(caseID: base.caseID, casePath: base.casePath, manifestSHA256: nil,
            sourceRehashed: false, isPartial: false, checks: Array(repeating: check, count: 513))
        #expect(throws: CaseIntegritySignatureError.reportLimit) {
            try CaseIntegritySignature.sign(report: report, using: key)
        }
    }

    @Test("Malformed reports are never signed", arguments: ["schema", "date", "digest", "field", "negativeBytes"])
    func invalidReports(_ field: String) throws {
        let key = try fixtureKey(1), base = fixtureReport()
        var checks = base.checks
        if field == "field" { checks = [.init(status: .pass, code: "synthetic", message: String(repeating: "x", count: 4_097))] }
        if field == "negativeBytes" { checks = [.init(status: .pass, code: "synthetic", byteCount: -1, message: "Synthetic")] }
        let report = CaseIntegrityReport(schemaVersion: field == "schema" ? 2 : 1, id: base.id,
            caseID: base.caseID, casePath: base.casePath, manifestSHA256: field == "digest" ? "bad" : base.manifestSHA256,
            startedAt: field == "date" ? Date(timeIntervalSinceReferenceDate: .infinity) : base.startedAt,
            completedAt: base.completedAt, sourceRehashed: base.sourceRehashed, isPartial: base.isPartial, checks: checks)
        #expect(throws: CaseIntegritySignatureError.invalidReport) {
            try CaseIntegritySignature.sign(report: report, using: key)
        }
    }

    private func fixtureKey(_ byte: UInt8) throws -> Curve25519.Signing.PrivateKey {
        try .init(rawRepresentation: Data(repeating: byte, count: 32))
    }

    private func fixtureReport(casePath: String = "/synthetic/private/case.nativecase") -> CaseIntegrityReport {
        let evidenceID = UUID(uuidString: "aaaaaaaa-0000-0000-0000-000000000003")!
        return CaseIntegrityReport(id: UUID(uuidString: "aaaaaaaa-0000-0000-0000-000000000001")!,
            caseID: UUID(uuidString: "aaaaaaaa-0000-0000-0000-000000000002")!, casePath: casePath,
            manifestSHA256: String(repeating: "a", count: 64),
            startedAt: Date(timeIntervalSinceReferenceDate: 780_000_000.1234567),
            completedAt: Date(timeIntervalSinceReferenceDate: 780_000_001.7654321), sourceRehashed: false,
            isPartial: true, checks: [
                .init(id: UUID(uuidString: "aaaaaaaa-0000-0000-0000-000000000005")!, status: .historical,
                    code: "source.receipt", relativePath: "manifest.json", evidenceID: evidenceID,
                    privatePath: "/synthetic/private/source.dd", recordedByteCount: 4_096,
                    recordedSHA256: String(repeating: "b", count: 64), message: "Historical synthetic receipt; bytes not reopened"),
                .init(id: UUID(uuidString: "aaaaaaaa-0000-0000-0000-000000000006")!, status: .unavailable,
                    code: "coverage.unavailable", message: "Synthetic unavailable source")
            ])
    }

    private func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func copy(_ envelope: CaseIntegritySignedEnvelope, schemaVersion: Int? = nil, algorithm: String? = nil,
                      canonicalization: String? = nil, reportSHA256: String? = nil, signerPublicKey: Data? = nil,
                      signature: Data? = nil, report: CaseIntegrityReport? = nil) -> CaseIntegritySignedEnvelope {
        CaseIntegritySignedEnvelope(schemaVersion: schemaVersion ?? envelope.schemaVersion,
            algorithm: algorithm ?? envelope.algorithm, canonicalization: canonicalization ?? envelope.canonicalization,
            reportSHA256: reportSHA256 ?? envelope.reportSHA256, signerPublicKey: signerPublicKey ?? envelope.signerPublicKey,
            signature: signature ?? envelope.signature, report: report ?? envelope.report)
    }
}
