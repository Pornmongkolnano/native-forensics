import Foundation

/// Fresh backend metadata used to bind an index to the complete decoder.
/// This value excludes result-derived text; decoding a persisted value does
/// not inspect installed code. Obtain live identity from the analysis client.
public struct DocumentDecoderIdentity: Codable, Sendable, Equatable {
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
    public let ipcProtocolVersion: Int?

    init(executableSHA256: String, codeSigningCDHash: String? = nil,
         isolation: DocumentDecodeIsolation, timeout: TimeInterval,
         brokerExecutableSHA256: String? = nil, brokerCodeSigningCDHash: String? = nil,
         ipcProtocolVersion: Int? = nil) throws {
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
        self.ipcProtocolVersion = ipcProtocolVersion
        try validateMetadata()
    }

    /// Shape/current-contract validation. It does not replace fresh code
    /// inspection or recompute text omitted from a persisted result.
    public func validateMetadata() throws {
        try DocumentDecoderMetadataValidation.validate(schemaVersion: schemaVersion,
            decoderIdentifier: decoderIdentifier, decoderVersion: decoderVersion,
            executableSHA256: decoderExecutableSHA256, codeSigningCDHash: decoderCodeSigningCDHash,
            brokerExecutableSHA256: brokerExecutableSHA256, brokerCodeSigningCDHash: brokerCodeSigningCDHash,
            isolation: isolation, options: options, optionsSHA256: optionsSHA256)
        if isolation == .appSandboxXPC {
            guard ipcProtocolVersion == DocumentXPCWire.protocolVersion else { throw DocumentAnalysisError.invalidResponse }
        } else if ipcProtocolVersion != nil { throw DocumentAnalysisError.invalidResponse }
    }

    /// Fail closed on malformed metadata and bind every backend policy field.
    /// Contract 2.1.0 identifies the current version-2 broker/worker protocol;
    /// historical provenance remains unchanged and is not upgraded here.
    public func matches(_ provenance: DocumentDecodeProvenance) -> Bool {
        guard (try? validateMetadata()) != nil, (try? provenance.validateMetadata()) != nil else { return false }
        return decoderIdentifier == provenance.decoderIdentifier && decoderVersion == provenance.decoderVersion
            && decoderExecutableSHA256 == provenance.decoderExecutableSHA256
            && decoderCodeSigningCDHash == provenance.decoderCodeSigningCDHash
            && brokerExecutableSHA256 == provenance.brokerExecutableSHA256
            && brokerCodeSigningCDHash == provenance.brokerCodeSigningCDHash
            && isolation == provenance.isolation && options == provenance.options
            && optionsSHA256 == provenance.optionsSHA256
    }
}

/// Shared receipt metadata checks; no fabricated derived-text digest is used
/// to validate a backend identity that has no document result.
enum DocumentDecoderMetadataValidation {
    static func validate(schemaVersion: Int, decoderIdentifier: String, decoderVersion: String,
                         executableSHA256: String, codeSigningCDHash: String?,
                         brokerExecutableSHA256: String?, brokerCodeSigningCDHash: String?,
                         isolation: DocumentDecodeIsolation, options: DocumentDecodeOptions,
                         optionsSHA256: String) throws {
        guard schemaVersion == 1, decoderIdentifier == DocumentDecoderContract.identifier,
              decoderVersion == DocumentDecoderContract.version, EngineValidation.validHash(executableSHA256),
              options.isCurrentPolicy, EngineValidation.validHash(optionsSHA256),
              optionsSHA256 == (try CaseWorkCoding.digest(options)) else { throw DocumentAnalysisError.invalidResponse }
        if let codeSigningCDHash {
            guard validCDHash(codeSigningCDHash) else { throw DocumentAnalysisError.invalidResponse }
        }
        if isolation == .appSandboxXPC {
            guard codeSigningCDHash != nil, let brokerExecutableSHA256,
                  EngineValidation.validHash(brokerExecutableSHA256), let brokerCodeSigningCDHash,
                  validCDHash(brokerCodeSigningCDHash) else { throw DocumentAnalysisError.invalidResponse }
        } else if brokerExecutableSHA256 != nil || brokerCodeSigningCDHash != nil {
            throw DocumentAnalysisError.invalidResponse
        }
    }

    private static func validCDHash(_ value: String) -> Bool {
        [40, 64].contains(value.utf8.count)
            && value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    }
}
