import CryptoKit
import Foundation

/// Local, memory-only limits. Callers may narrow these bounds, never enlarge them.
public struct CaseIntegritySignatureOptions: Sendable, Equatable {
    public let maximumReportBytes: Int
    public let maximumEnvelopeBytes: Int
    public let maximumChecks: Int

    public init(maximumReportBytes: Int = 16 * 1_048_576,
                maximumEnvelopeBytes: Int = 17 * 1_048_576, maximumChecks: Int = 20_001) {
        self.maximumReportBytes = maximumReportBytes
        self.maximumEnvelopeBytes = maximumEnvelopeBytes
        self.maximumChecks = maximumChecks
    }
}

/// A separate envelope around the unchanged, complete report schema. Its paths
/// are private local data. Possessing this envelope does not establish trust in
/// its embedded key; verification always needs an independently trusted key.
public struct CaseIntegritySignedEnvelope: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let algorithm: String
    public let canonicalization: String
    public let reportSHA256: String
    public let signerPublicKey: Data
    public let signature: Data
    public let report: CaseIntegrityReport

    public init(schemaVersion: Int = 1, algorithm: String = "Ed25519",
                canonicalization: String = "nativeforensics.case-integrity-report-json-v1",
                reportSHA256: String, signerPublicKey: Data, signature: Data, report: CaseIntegrityReport) {
        self.schemaVersion = schemaVersion
        self.algorithm = algorithm
        self.canonicalization = canonicalization
        self.reportSHA256 = reportSHA256
        self.signerPublicKey = signerPublicKey
        self.signature = signature
        self.report = report
    }
}

public enum CaseIntegritySignatureError: Error, Sendable, Equatable {
    case invalidOptions, invalidReport, invalidEnvelope
    case unsupportedVersion, unsupportedAlgorithm, unsupportedCanonicalization
    case reportLimit, envelopeLimit, reportHashMismatch, untrustedSigner, invalidSignature
    case nonCanonicalEnvelope
}

/// Signs and verifies local values only. This API never generates or persists
/// keys, opens evidence, writes files, contacts services or publishes reports.
public enum CaseIntegritySignature {
    private static let canonicalization = "nativeforensics.case-integrity-report-json-v1"
    private static let domain = Data("NativeForensics/CaseIntegritySignedEnvelope/v1\u{0}".utf8)

    /// The caller supplies and controls the private key. Any external key
    /// anchoring, examiner identity or custody policy is outside this API.
    /// CryptoKit can produce different valid Ed25519 signature bytes for the
    /// same key and report; canonical report bytes and their digest stay stable.
    public static func sign(report: CaseIntegrityReport, using privateKey: Curve25519.Signing.PrivateKey,
                            options: CaseIntegritySignatureOptions = .init()) throws -> CaseIntegritySignedEnvelope {
        let digest = hash(try canonicalReportJSON(report, options: options))
        let publicKey = privateKey.publicKey.rawRepresentation
        let metadata = SignedMetadata(reportSHA256: digest, signerPublicKey: publicKey)
        let signature = try privateKey.signature(for: transcript(metadata))
        let envelope = CaseIntegritySignedEnvelope(reportSHA256: digest, signerPublicKey: publicKey,
            signature: signature, report: report)
        _ = try encodedEnvelope(envelope, options: options)
        return envelope
    }

    /// Returns only the authenticated typed report. The embedded public key is
    /// compared with this mandatory external trust input, never used as trust.
    public static func verify(_ envelope: CaseIntegritySignedEnvelope,
                              trustedPublicKey: Curve25519.Signing.PublicKey,
                              options: CaseIntegritySignatureOptions = .init()) throws -> CaseIntegrityReport {
        _ = try json(envelope, options: options)
        return try verifyValidated(envelope, trustedPublicKey: trustedPublicKey)
    }

    /// Encodes the complete local envelope, including private paths. Encoding
    /// validates structure and its report digest; it does not establish trust.
    public static func json(_ envelope: CaseIntegritySignedEnvelope,
                            options: CaseIntegritySignatureOptions = .init()) throws -> Data {
        try validate(options)
        try validateMetadata(envelope)
        guard hash(try canonicalReportJSON(envelope.report, options: options)) == envelope.reportSHA256 else {
            throw CaseIntegritySignatureError.reportHashMismatch
        }
        return try encodedEnvelope(envelope, options: options)
    }

    /// Accepts only the canonical bytes emitted by `json`. Exact re-encoding
    /// rejects duplicate/unknown keys and alternative JSON representations.
    /// The byte bound is enforced before parsing untrusted input.
    public static func decodeAndVerify(_ data: Data, trustedPublicKey: Curve25519.Signing.PublicKey,
                                       options: CaseIntegritySignatureOptions = .init()) throws -> CaseIntegrityReport {
        try validate(options)
        guard data.count <= options.maximumEnvelopeBytes else { throw CaseIntegritySignatureError.envelopeLimit }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .deferredToDate
        let envelope: CaseIntegritySignedEnvelope
        do { envelope = try decoder.decode(CaseIntegritySignedEnvelope.self, from: data) }
        catch { throw CaseIntegritySignatureError.invalidEnvelope }
        guard try json(envelope, options: options) == data else { throw CaseIntegritySignatureError.nonCanonicalEnvelope }
        return try verifyValidated(envelope, trustedPublicKey: trustedPublicKey)
    }

    /// App-specific versioned JSON, not RFC 8785. It preserves all report
    /// fields, check order, optional-value presence and numeric Date precision.
    public static func canonicalReportJSON(_ report: CaseIntegrityReport,
                                           options: CaseIntegritySignatureOptions = .init()) throws -> Data {
        try validate(options)
        try validateReport(report, options: options)
        let bytes = try encoder().encode(report)
        guard bytes.count <= options.maximumReportBytes else { throw CaseIntegritySignatureError.reportLimit }
        return bytes
    }

    private static func verifyValidated(_ envelope: CaseIntegritySignedEnvelope,
                                        trustedPublicKey: Curve25519.Signing.PublicKey) throws -> CaseIntegrityReport {
        guard envelope.signerPublicKey == trustedPublicKey.rawRepresentation else {
            throw CaseIntegritySignatureError.untrustedSigner
        }
        guard trustedPublicKey.isValidSignature(envelope.signature, for: try transcript(SignedMetadata(envelope))) else {
            throw CaseIntegritySignatureError.invalidSignature
        }
        return envelope.report
    }

    private static func encodedEnvelope(_ envelope: CaseIntegritySignedEnvelope,
                                        options: CaseIntegritySignatureOptions) throws -> Data {
        let bytes = try encoder().encode(envelope)
        guard bytes.count <= options.maximumEnvelopeBytes else { throw CaseIntegritySignatureError.envelopeLimit }
        return bytes
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .deferredToDate
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func validate(_ options: CaseIntegritySignatureOptions) throws {
        guard (1...16 * 1_048_576).contains(options.maximumReportBytes),
              (1...17 * 1_048_576).contains(options.maximumEnvelopeBytes),
              (0...20_001).contains(options.maximumChecks) else {
            throw CaseIntegritySignatureError.invalidOptions
        }
    }

    private static func validateMetadata(_ envelope: CaseIntegritySignedEnvelope) throws {
        guard envelope.schemaVersion == 1 else { throw CaseIntegritySignatureError.unsupportedVersion }
        guard envelope.algorithm == "Ed25519" else { throw CaseIntegritySignatureError.unsupportedAlgorithm }
        guard envelope.canonicalization == canonicalization else { throw CaseIntegritySignatureError.unsupportedCanonicalization }
        guard EngineValidation.validHash(envelope.reportSHA256), envelope.signerPublicKey.count == 32,
              envelope.signature.count == 64 else { throw CaseIntegritySignatureError.invalidEnvelope }
    }

    private static func validateReport(_ report: CaseIntegrityReport, options: CaseIntegritySignatureOptions) throws {
        guard report.checks.count <= options.maximumChecks else { throw CaseIntegritySignatureError.reportLimit }
        guard report.schemaVersion == 1, report.casePath.utf8.count <= 32_768,
              report.startedAt.timeIntervalSinceReferenceDate.isFinite,
              report.completedAt.timeIntervalSinceReferenceDate.isFinite,
              report.manifestSHA256.map(EngineValidation.validHash) ?? true else {
            throw CaseIntegritySignatureError.invalidReport
        }
        // Account for escaped strings before allocating encoded JSON. Per-field
        // limits alone would allow hundreds of MiB across 20,001 checks. The
        // decrementing budget avoids overflow even with adversarial options.
        var remaining = options.maximumReportBytes
        try charge(report.casePath, remaining: &remaining)
        if let digest = report.manifestSHA256 { try charge(digest, remaining: &remaining) }
        for check in report.checks {
            guard check.message.utf8.count <= 4_096, check.code.utf8.count <= 256,
                  (check.relativePath?.utf8.count ?? 0) <= 4_096,
                  (check.privatePath?.utf8.count ?? 0) <= 32_768,
                  check.sha256.map(EngineValidation.validHash) ?? true,
                  check.recordedSHA256.map(EngineValidation.validHash) ?? true,
                  check.byteCount.map({ $0 >= 0 }) ?? true,
                  check.recordedByteCount.map({ $0 >= 0 }) ?? true else {
                throw CaseIntegritySignatureError.invalidReport
            }
            for text in [check.code, check.message] { try charge(text, remaining: &remaining) }
            for text in [check.relativePath, check.privatePath, check.sha256, check.recordedSHA256].compactMap({ $0 }) {
                try charge(text, remaining: &remaining)
            }
        }
    }

    private static func charge(_ text: String, remaining: inout Int) throws {
        for byte in text.utf8 {
            // A control character may use six JSON bytes (\u00xx). Quotes and
            // backslashes use two; slashes stay unescaped in this codec.
            let cost = byte < 0x20 ? 6 : (byte == 0x22 || byte == 0x5c ? 2 : 1)
            guard remaining >= cost else { throw CaseIntegritySignatureError.reportLimit }
            remaining -= cost
        }
    }

    private static func hash(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func transcript(_ metadata: SignedMetadata) throws -> Data {
        var data = domain
        data.append(try encoder().encode(metadata))
        return data
    }

    private struct SignedMetadata: Encodable {
        let schemaVersion: Int
        let algorithm: String
        let canonicalization: String
        let reportSHA256: String
        let signerPublicKey: Data

        init(reportSHA256: String, signerPublicKey: Data) {
            schemaVersion = 1
            algorithm = "Ed25519"
            canonicalization = CaseIntegritySignature.canonicalization
            self.reportSHA256 = reportSHA256
            self.signerPublicKey = signerPublicKey
        }

        init(_ envelope: CaseIntegritySignedEnvelope) {
            schemaVersion = envelope.schemaVersion
            algorithm = envelope.algorithm
            canonicalization = envelope.canonicalization
            reportSHA256 = envelope.reportSHA256
            signerPublicKey = envelope.signerPublicKey
        }
    }
}
