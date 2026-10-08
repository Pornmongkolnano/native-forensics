import Foundation

/// The latest filesystem cache retains its legacy ISO8601 date representation
/// and adds exact Foundation reference-date seconds. Immutable job artifacts
/// continue to use EnumerationResult's unchanged Codable representation.
enum EngineFilesystemCacheCoding {
    static func encode(_ result: EnumerationResult) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(CacheDTO(result: result))
    }

    static func decode(_ data: Data) throws -> EnumerationResult {
        try decodeWithReceipt(data).result
    }

    struct DecodeReceipt {
        let result: EnumerationResult
        let containsExactReferenceDate: Bool
    }

    static func decodeWithReceipt(_ data: Data) throws -> DecodeReceipt {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let value = try decoder.decode(CacheDTO.self, from: data)
        return DecodeReceipt(result: value.result, containsExactReferenceDate: value.containsExactReferenceDate)
    }

    private struct CacheDTO: Codable {
        private enum PrecisionKeys: String, CodingKey {
            case savedAtExactReferenceDate
        }

        let result: EnumerationResult
        let containsExactReferenceDate: Bool

        init(result: EnumerationResult) {
            self.result = result
            containsExactReferenceDate = true
        }

        func encode(to encoder: Encoder) throws {
            let exact = result.savedAt.timeIntervalSinceReferenceDate
            guard exact.isFinite else {
                throw EncodingError.invalidValue(exact, .init(
                    codingPath: encoder.codingPath,
                    debugDescription: "The filesystem cache saved timestamp must be finite."
                ))
            }
            // Encode an explicit whole reference-date second, avoiding any
            // formatter conversion of a fractional instant near a second edge.
            try Self.replacingSavedAt(in: result,
                with: Date(timeIntervalSinceReferenceDate: exact.rounded(.down))).encode(to: encoder)
            var precision = encoder.container(keyedBy: PrecisionKeys.self)
            try precision.encode(exact, forKey: .savedAtExactReferenceDate)
        }

        init(from decoder: Decoder) throws {
            let legacy = try EnumerationResult(from: decoder)
            let precision = try decoder.container(keyedBy: PrecisionKeys.self)
            guard precision.contains(.savedAtExactReferenceDate) else {
                // The codec alone cannot infer a missing fraction. The store
                // may recover a verified latest immutable job only after exact
                // complete-byte equality with its former ISO cache encoding.
                result = legacy
                containsExactReferenceDate = false
                return
            }
            // A present null or wrong type is invalid, never a legacy fallback.
            let exact = try precision.decode(Double.self, forKey: .savedAtExactReferenceDate)
            let whole = legacy.savedAt.timeIntervalSinceReferenceDate
            guard exact.isFinite, whole.isFinite, whole == exact.rounded(.down) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .savedAtExactReferenceDate, in: precision,
                    debugDescription: "The exact filesystem cache timestamp does not match its ISO8601 whole second."
                )
            }
            // These are historical metadata values, not a verification of source
            // bytes or of the fraction against an old immutable job artifact.
            result = Self.replacingSavedAt(in: legacy,
                with: Date(timeIntervalSinceReferenceDate: exact))
            containsExactReferenceDate = true
        }

        private static func replacingSavedAt(in value: EnumerationResult, with savedAt: Date) -> EnumerationResult {
            EnumerationResult(
                schemaVersion: value.schemaVersion, engineVersion: value.engineVersion,
                patchDigest: value.patchDigest, sourcePaths: value.sourcePaths,
                sourceIdentities: value.sourceIdentities, sourceFileHashes: value.sourceFileHashes,
                options: value.options, image: value.image, volumes: value.volumes,
                files: value.files, warnings: value.warnings, status: value.status,
                savedAt: savedAt
            )
        }
    }
}
