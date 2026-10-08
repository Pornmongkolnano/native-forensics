import Foundation

/// Logical UTF-8 payload of the actual String fields retained by a listing.
/// This excludes enum raw values, numeric fields, allocator overhead and any
/// encoded representation. It is a retention budget, not a process RSS limit.
public struct FilesystemListingStringCost: Sendable, Equatable {
    public let rawUTF8Bytes: Int

    public init(rawUTF8Bytes: Int) throws {
        guard rawUTF8Bytes >= 0 else {
            throw EngineError.invalidCache("A filesystem listing string cost cannot be negative.")
        }
        self.rawUTF8Bytes = rawUTF8Bytes
    }

    /// Perform this validating scan on a worker before publishing the result.
    /// No JSON encoding, decoding or serialization is performed.
    public static func measure(_ result: EnumerationResult) throws -> Self {
        try measure(result, checkCancellation: { try Task.checkCancellation() })
    }

    static func measure(_ result: EnumerationResult, checkCancellation: () throws -> Void) throws -> Self {
        try checkCancellation()
        guard result.files.count <= 50_000, result.files.count <= result.options.maxFiles,
              result.sourcePaths.count <= 1_024, result.sourceIdentities.count <= 1_024,
              result.sourceFileHashes.count <= 1_024, (result.image.imagePaths?.count ?? 0) <= 1_024,
              result.volumes.count <= 4_096, result.warnings.count <= 1_024 else {
            throw EngineError.invalidCache("A filesystem listing exceeds its record count limits.")
        }

        // Validate the bounded header with the shared protocol rules. Passing
        // an empty file array avoids a second traversal of the large listing.
        let header = EnumerationResult(schemaVersion: result.schemaVersion, engineVersion: result.engineVersion,
            patchDigest: result.patchDigest, sourcePaths: result.sourcePaths, sourceIdentities: result.sourceIdentities,
            sourceFileHashes: result.sourceFileHashes, options: result.options, image: result.image,
            volumes: result.volumes, files: [], warnings: result.warnings, status: result.status, savedAt: result.savedAt)
        try EngineValidation.result(header)
        try checkCancellation()

        var bytes = 0
        var fieldsSinceCancellation = 0
        func add(_ value: String) throws {
            if fieldsSinceCancellation == 128 {
                try checkCancellation()
                fieldsSinceCancellation = 0
            }
            bytes = try checkedTotal(bytes, adding: value.utf8.count)
            guard bytes <= FilesystemListingRetention.defaultMaximumStringBytes else {
                throw EngineError.limitExceeded("The filesystem listing String payload exceeds 64 MiB.")
            }
            fieldsSinceCancellation += 1
        }
        func addScopedPath(_ path: String) throws {
            // Swift String equality accepts canonically equivalent spellings.
            // Scope equality with sourcePaths does not bound the actual UTF-8
            // payload of a separately stored decomposed path.
            guard path.hasPrefix("/"), EngineValidation.text(path) else {
                throw EngineError.invalidCache("A stored filesystem source path exceeds its UTF-8 bounds.")
            }
            try add(path)
        }
        func addOptionalString(_ value: String?) throws {
            if let value { try add(value) }
        }
        func addTimestamp(_ timestamp: FilesystemCivilTimestamp?) throws {
            guard let timestamp else { return }
            try addOptionalString(timestamp.civil)
            try addOptionalString(timestamp.timezone)
        }

        try add(result.engineVersion)
        try add(result.patchDigest)
        for path in result.sourcePaths { try add(path) }
        for identity in result.sourceIdentities { try addScopedPath(identity.path) }
        for (path, hash) in result.sourceFileHashes { try addScopedPath(path); try add(hash) }
        try add(result.options.imageType)
        try add(result.options.timezone)
        try add(result.image.imageType)
        try addOptionalString(result.image.logicalSha256)
        for path in result.image.imagePaths ?? [] { try addScopedPath(path) }
        for volume in result.volumes { try add(volume.id); try add(volume.filesystem) }
        for warning in result.warnings { try add(warning) }

        var identifiers = Set<String>()
        identifiers.reserveCapacity(result.files.count)
        for (index, file) in result.files.enumerated() {
            if index.isMultiple(of: 128) { try checkCancellation() }
            try EngineValidation.file(file)
            guard identifiers.insert(file.id).inserted else {
                throw EngineError.invalidCache("A filesystem listing contains duplicate entry identifiers.")
            }
            try add(file.id)
            try add(file.path)
            try add(file.name)
            try addOptionalString(file.attributeName)
            try addOptionalString(file.recoveryStatus)
            for warning in file.recoveryWarnings ?? [] { try add(warning) }
            try addTimestamp(file.timestampProvenance?.created)
            try addTimestamp(file.timestampProvenance?.modified)
            try addTimestamp(file.timestampProvenance?.accessed)
        }
        try checkCancellation()
        return try Self(rawUTF8Bytes: bytes)
    }

    static func checkedTotal(_ current: Int, adding next: Int) throws -> Int {
        guard current >= 0, next >= 0 else {
            throw EngineError.invalidCache("A filesystem listing string cost cannot be negative.")
        }
        let (total, overflow) = current.addingReportingOverflow(next)
        guard !overflow else {
            throw EngineError.limitExceeded("The filesystem listing string cost overflowed its byte counter.")
        }
        return total
    }
}
