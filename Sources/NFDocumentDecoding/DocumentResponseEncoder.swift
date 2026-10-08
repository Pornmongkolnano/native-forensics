import Foundation
import ForensicsCore

/// Preserves coverage/truncation semantics while bounding serialized derived data.
public enum DocumentResponseEncoder {
    public static func encode(_ analysis: DocumentAnalysis, maximumBytes: Int = DocumentLimits.maximumResponseBytes) throws -> Data {
        try bounded(analysis, maximumBytes: maximumBytes) { try encoder().encode($0) }
    }

    public static func encodeXPC(_ analysis: DocumentAnalysis, request: DocumentXPCDecodeRequest) throws -> Data {
        try bounded(analysis, maximumBytes: DocumentLimits.maximumResponseBytes) {
            try encoder().encode(DocumentXPCDecodeResponse(request: request, analysis: $0))
        }
    }

    private static func encoder() -> JSONEncoder {
        let value = JSONEncoder()
        value.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return value
    }

    private static func bounded(_ analysis: DocumentAnalysis, maximumBytes: Int,
                                encode: (DocumentAnalysis) throws -> Data) throws -> Data {
        var current = analysis
        var encoded = try encode(current)
        if encoded.count + 1 > maximumBytes, current.thumbnailPNG != nil {
            current = copy(current, thumbnail: nil, pages: current.textPages,
                           warnings: current.warnings + ["Thumbnail omitted to preserve the bounded document response."])
            encoded = try encode(current)
        }
        var budget = current.textPages.reduce(0) { $0 + $1.text.utf8.count }
        for _ in 0..<8 where encoded.count + 1 > maximumBytes {
            budget /= 2
            var remaining = budget
            let pages = current.textPages.map { page in
                let limited = DocumentDecoder.limitedUTF8(page.text, maximumBytes: remaining)
                remaining -= limited.value.utf8.count
                return DocumentTextPage(pageNumber: page.pageNumber, text: limited.value,
                                        isTruncated: page.isTruncated || limited.truncated,
                                        referenceLabel: page.referenceLabel, referenceKind: page.referenceKind)
            }
            let warning = "Extracted text was shortened to preserve the bounded JSON response."
            current = copy(current, thumbnail: current.thumbnailPNG, pages: pages,
                           warnings: current.warnings.contains(warning) ? current.warnings : current.warnings + [warning])
            encoded = try encode(current)
        }
        guard encoded.count + 1 <= maximumBytes else { throw DocumentAnalysisError.outputLimit }
        return encoded
    }

    private static func copy(_ analysis: DocumentAnalysis, thumbnail: Data?, pages: [DocumentTextPage], warnings: [String]) -> DocumentAnalysis {
        DocumentAnalysis(schemaVersion: analysis.schemaVersion, contentKind: analysis.contentKind, mimeType: analysis.mimeType, status: analysis.status,
                         sourceSHA256: analysis.sourceSHA256, sourceByteCount: analysis.sourceByteCount,
                         title: analysis.title, pixelWidth: analysis.pixelWidth, pixelHeight: analysis.pixelHeight,
                         pageCount: analysis.pageCount, officeFormat: analysis.officeFormat,
                         contentUnitCount: analysis.contentUnitCount, structuralValidation: analysis.structuralValidation,
                         textPages: pages, thumbnailPNG: thumbnail,
                         rawMetadata: analysis.rawMetadata, warnings: warnings, failureCode: analysis.failureCode, provenance: analysis.provenance)
    }

}
