import CryptoKit
import Darwin
import Foundation

/// Parser contract versions are separate from the workbench release version.
/// Changes to format interpretation or limits require a new contract version.
public enum DocumentDecoderContract {
    public static let identifier = "NativeForensics.document-decoder"
    public static let version = "2.1.0"
}

public enum DocumentDecodeIsolation: String, Codable, Sendable {
    case appSandboxXPC, requiredDevelopmentSeatbelt, testFixture
}

/// The actual fixed interpretation/output policy used for this result. These
/// are receipts, not switches that can grant a helper more privileges.
public struct DocumentDecodeOptions: Codable, Sendable, Equatable {
    public let timeoutSeconds: Double
    public let maximumInputBytes: Int64
    public let maximumResponseBytes: Int
    public let maximumTextBytes: Int
    public let maximumThumbnailBytes: Int
    public let maximumImagePixels: Int64
    public let maximumPages: Int
    public let maximumMetadataItems: Int
    public let maximumArchiveMembers: Int
    public let maximumMetadataValueBytes: Int
    public let allowInferredWindows1252: Bool
    public let previewedImageFrame: Int
    public let previewedPDFPage: Int
    public let includesOCR: Bool
    public let evaluatesOfficeFormulasOrMacros: Bool
    public let fetchesExternalResources: Bool

    public init(timeoutSeconds: Double) {
        self.timeoutSeconds = timeoutSeconds
        self.maximumInputBytes = DocumentLimits.maximumInputBytes
        self.maximumResponseBytes = DocumentLimits.maximumResponseBytes
        self.maximumTextBytes = DocumentLimits.maximumTextBytes
        self.maximumThumbnailBytes = DocumentLimits.maximumThumbnailBytes
        self.maximumImagePixels = DocumentLimits.maximumImagePixels
        self.maximumPages = DocumentLimits.maximumPages
        self.maximumMetadataItems = DocumentLimits.maximumMetadataItems
        self.maximumArchiveMembers = DocumentLimits.maximumArchiveMembers
        self.maximumMetadataValueBytes = DocumentLimits.maximumMetadataValueBytes
        self.allowInferredWindows1252 = true
        self.previewedImageFrame = 1; self.previewedPDFPage = 1
        self.includesOCR = false; self.evaluatesOfficeFormulasOrMacros = false
        self.fetchesExternalResources = false
    }

    var isCurrentPolicy: Bool {
        timeoutSeconds.isFinite && timeoutSeconds > 0 && timeoutSeconds <= 120
            && self == DocumentDecodeOptions(timeoutSeconds: timeoutSeconds)
    }
}

/// Host-generated provenance for a receipt-validated result. Historical v1
/// analyses do not have this field and are kept explicitly unprovenanced.
public struct DocumentDecodeProvenance: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let decoderIdentifier: String
    public let decoderVersion: String
    public let decoderExecutableSHA256: String
    public let decoderCodeSigningCDHash: String?
    public let brokerExecutableSHA256: String?
    public let brokerCodeSigningCDHash: String?
    public let isolation: DocumentDecodeIsolation
    public let options: DocumentDecodeOptions
    public let optionsSHA256: String
    /// Canonical sorted JSON of every final DocumentTextPage, including source
    /// unit references and truncation flags; agrees with content-index receipts.
    public let derivedTextSHA256: String

    init(executableSHA256: String, codeSigningCDHash: String?, isolation: DocumentDecodeIsolation,
         timeout: TimeInterval, pages: [DocumentTextPage],
         brokerExecutableSHA256: String? = nil, brokerCodeSigningCDHash: String? = nil) throws {
        self.schemaVersion = 1
        self.decoderIdentifier = DocumentDecoderContract.identifier
        self.decoderVersion = DocumentDecoderContract.version
        self.decoderExecutableSHA256 = executableSHA256
        self.decoderCodeSigningCDHash = codeSigningCDHash
        self.brokerExecutableSHA256 = brokerExecutableSHA256
        self.brokerCodeSigningCDHash = brokerCodeSigningCDHash
        self.isolation = isolation
        self.options = DocumentDecodeOptions(timeoutSeconds: timeout)
        self.optionsSHA256 = try CaseWorkCoding.digest(options)
        self.derivedTextSHA256 = try CaseWorkCoding.digest(pages)
    }

    func validate(pages: [DocumentTextPage]) throws {
        try validateMetadata()
        guard derivedTextSHA256 == (try CaseWorkCoding.digest(pages)) else { throw DocumentAnalysisError.invalidResponse }
    }

    /// Validates shape/policy without inventing omitted historical page text.
    func validateMetadata() throws {
        try DocumentDecoderMetadataValidation.validate(schemaVersion: schemaVersion,
            decoderIdentifier: decoderIdentifier, decoderVersion: decoderVersion,
            executableSHA256: decoderExecutableSHA256, codeSigningCDHash: decoderCodeSigningCDHash,
            brokerExecutableSHA256: brokerExecutableSHA256, brokerCodeSigningCDHash: brokerCodeSigningCDHash,
            isolation: isolation, options: options, optionsSHA256: optionsSHA256)
        guard EngineValidation.validHash(derivedTextSHA256) else { throw DocumentAnalysisError.invalidResponse }
    }
}

struct DocumentDecoderExecutableReceipt: Sendable {
    let url: URL
    let identity: SourceIdentity
    let sha256: String

    static func inspect(_ url: URL, cancellation: DocumentCancellation) throws -> Self {
        let descriptor: Int32
        do { descriptor = try FileAccess.openReadOnly(url) }
        catch { throw DocumentAnalysisError.unavailable }
        defer { Darwin.close(descriptor) }
        let identity = try FileAccess.identity(of: descriptor)
        guard identity.size > 0, identity.size <= 256 * 1_024 * 1_024 else { throw DocumentAnalysisError.unavailable }
        var hasher = SHA256(), byteCount: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 128 * 1_024)
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: $0.count) }
            if count == 0 { break }
            byteCount += Int64(count)
            guard byteCount <= identity.size else { throw DocumentAnalysisError.sourceChanged }
            hasher.update(data: Data(buffer.prefix(count)))
        }
        guard byteCount == identity.size, (try? FileAccess.identity(of: descriptor)) == identity,
              (try? FileAccess.identity(at: url)) == identity else { throw DocumentAnalysisError.sourceChanged }
        return Self(url: url, identity: identity, sha256: CaseWorkCoding.hex(hasher.finalize()))
    }

    func verify(cancellation: DocumentCancellation) throws {
        let current = try Self.inspect(url, cancellation: cancellation)
        guard current.identity == identity, current.sha256 == sha256 else { throw DocumentAnalysisError.sourceChanged }
    }
}
