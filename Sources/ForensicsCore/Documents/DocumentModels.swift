import Foundation

/// Decoders receive only an independently recovered regular file, never an image
/// container address. SHA-256 is over every byte of that recovered file.
public struct DocumentInput: Codable, Sendable, Equatable {
    public let fileURL: URL
    public let expectedSHA256: String
    public let expectedByteCount: Int64

    public init(fileURL: URL, expectedSHA256: String, expectedByteCount: Int64) {
        self.fileURL = fileURL
        self.expectedSHA256 = expectedSHA256
        self.expectedByteCount = expectedByteCount
    }
}

public enum DocumentContentKind: String, Codable, Sendable {
    case image, pdf, text, archive, office, audio, video, unknown
}

public enum DocumentValidationStatus: String, Codable, Sendable {
    case decoded, unsupported, failed
}

public enum DocumentOfficeFormat: String, Codable, Sendable {
    case docx, pptx, xlsx, doc, ppt, xls
}

public enum DocumentStructureValidation: String, Codable, Sendable {
    case validated, signatureOnly
}

public enum DocumentTextReferenceKind: String, Codable, Sendable {
    case page, slide, sheet, document, archiveMember
}

/// A raw metadata value is evidence supplied by the file, not a interpreted
/// forensic timestamp. In particular EXIF dates without offsets stay unzoned.
public struct DocumentRawMetadata: Codable, Sendable, Equatable, Identifiable {
    public let name: String
    public let value: String
    public var id: String { name }
    public init(name: String, value: String) { self.name = name; self.value = value }
}

public struct DocumentTextPage: Codable, Sendable, Equatable, Identifiable {
    /// One-based source unit index: PDF page, slide, worksheet, or document body.
    /// A DOCX body is not represented as a fabricated page layout.
    public let pageNumber: Int
    public let text: String
    public let isTruncated: Bool
    public let referenceLabel: String?
    public let referenceKind: DocumentTextReferenceKind?
    public var id: Int { pageNumber }
    public init(pageNumber: Int, text: String, isTruncated: Bool = false,
                referenceLabel: String? = nil, referenceKind: DocumentTextReferenceKind? = nil) {
        self.pageNumber = pageNumber; self.text = text; self.isTruncated = isTruncated
        self.referenceLabel = referenceLabel; self.referenceKind = referenceKind
    }
}

public struct DocumentAnalysis: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let contentKind: DocumentContentKind
    public let mimeType: String
    public let status: DocumentValidationStatus
    public let sourceSHA256: String
    public let sourceByteCount: Int64
    public let title: String?
    public let pixelWidth: Int?
    public let pixelHeight: Int?
    public let pageCount: Int?
    public let officeFormat: DocumentOfficeFormat?
    public let contentUnitCount: Int?
    /// Container validation does not assert legacy Office body readability.
    public let structuralValidation: DocumentStructureValidation?
    public let textPages: [DocumentTextPage]
    /// A re-encoded bounded thumbnail. Original JPEG/PDF bytes never reach UI decoders.
    public let thumbnailPNG: Data?
    public let rawMetadata: [DocumentRawMetadata]
    public let warnings: [String]
    public let failureCode: String?
    /// Absent on historical schema 1; required for current client schema 2.
    public let provenance: DocumentDecodeProvenance?

    public init(schemaVersion: Int = 1, contentKind: DocumentContentKind, mimeType: String, status: DocumentValidationStatus,
                sourceSHA256: String, sourceByteCount: Int64, title: String? = nil,
                pixelWidth: Int? = nil, pixelHeight: Int? = nil, pageCount: Int? = nil,
                officeFormat: DocumentOfficeFormat? = nil, contentUnitCount: Int? = nil,
                structuralValidation: DocumentStructureValidation? = nil,
                textPages: [DocumentTextPage] = [], thumbnailPNG: Data? = nil,
                rawMetadata: [DocumentRawMetadata] = [], warnings: [String] = [], failureCode: String? = nil,
                provenance: DocumentDecodeProvenance? = nil) {
        self.schemaVersion = schemaVersion; self.contentKind = contentKind; self.mimeType = mimeType
        self.status = status; self.sourceSHA256 = sourceSHA256; self.sourceByteCount = sourceByteCount
        self.title = title; self.pixelWidth = pixelWidth; self.pixelHeight = pixelHeight
        self.pageCount = pageCount; self.textPages = textPages; self.thumbnailPNG = thumbnailPNG
        self.officeFormat = officeFormat; self.contentUnitCount = contentUnitCount
        self.structuralValidation = structuralValidation
        self.rawMetadata = rawMetadata; self.warnings = warnings; self.failureCode = failureCode
        self.provenance = provenance
    }

    func attachingProvenance(executableSHA256: String, codeSigningCDHash: String?,
                             isolation: DocumentDecodeIsolation, timeout: TimeInterval,
                             brokerExecutableSHA256: String? = nil, brokerCodeSigningCDHash: String? = nil) throws -> DocumentAnalysis {
        let receipt = try DocumentDecodeProvenance(executableSHA256: executableSHA256,
            codeSigningCDHash: codeSigningCDHash, isolation: isolation, timeout: timeout, pages: textPages,
            brokerExecutableSHA256: brokerExecutableSHA256, brokerCodeSigningCDHash: brokerCodeSigningCDHash)
        let result = DocumentAnalysis(schemaVersion: 2, contentKind: contentKind, mimeType: mimeType, status: status,
            sourceSHA256: sourceSHA256, sourceByteCount: sourceByteCount, title: title,
            pixelWidth: pixelWidth, pixelHeight: pixelHeight, pageCount: pageCount,
            officeFormat: officeFormat, contentUnitCount: contentUnitCount, structuralValidation: structuralValidation,
            textPages: textPages, thumbnailPNG: thumbnailPNG, rawMetadata: rawMetadata, warnings: warnings,
            failureCode: failureCode, provenance: receipt)
        try receipt.validate(pages: textPages)
        return result
    }

    public var textIsComplete: Bool {
        status == .decoded && (contentKind == .pdf || contentKind == .text || contentKind == .office || contentKind == .archive)
            && !textPages.isEmpty && !textPages.contains(where: { $0.isTruncated || $0.text.isEmpty })
            && (contentKind != .pdf || pageCount == textPages.count)
            && ((contentKind != .office && contentKind != .archive) || contentUnitCount == textPages.count)
    }
}

public enum DocumentLimits {
    public static let maximumInputBytes: Int64 = 128 * 1_024 * 1_024
    public static let maximumResponseBytes = 2 * 1_024 * 1_024
    public static let maximumTextBytes = 1_024 * 1_024
    public static let maximumThumbnailBytes = 512 * 1_024
    public static let maximumImagePixels: Int64 = 100_000_000
    public static let maximumPages = 200
    public static let maximumMetadataItems = 128
    public static let maximumArchiveMembers = 128
    public static let maximumMetadataValueBytes = 4_096
    public static let timeout: TimeInterval = 12
}

public enum DocumentAnalysisError: Error, LocalizedError, Sendable, Equatable {
    case invalidInput, integrityMismatch, sourceChanged, unavailable, sandboxUnavailable, launchFailed, timeout, outputLimit, invalidResponse, cleanupFailed
    public var errorDescription: String? {
        switch self {
        case .invalidInput: "Document inspection requires a regular recovered file within the 128 MiB size limit and its size/hash receipt."
        case .integrityMismatch: "The recovered file does not match its size/hash receipt."
        case .sourceChanged: "The recovered file changed during document inspection."
        case .unavailable: "The isolated document decoder is unavailable."
        case .sandboxUnavailable: "The required isolated document sandbox or service identity could not be verified. Inspection stopped without an unrestricted fallback."
        case .launchFailed: "The isolated document decoder could not start."
        case .timeout: "Document inspection reached its time limit."
        case .outputLimit: "Document inspection exceeded the bounded response limit."
        case .invalidResponse: "The document decoder did not return a valid, bounded result."
        case .cleanupFailed: "The isolated document job could not be confirmed stopped. Further XPC inspection is disabled for this app session."
        }
    }
}
