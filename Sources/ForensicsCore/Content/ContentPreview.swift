import Foundation

public struct ContentTextFragment: Sendable, Equatable, Identifiable {
    public let id: Int
    public let lineNumber: Int
    public let fragmentNumber: Int
    /// Offset in the extracted UTF-8 bytes, not a filesystem or image address.
    public let byteOffset: Int
    public let text: String
}

public struct ContentHexRow: Sendable, Equatable, Identifiable {
    public let byteOffset: Int
    public let hexadecimal: String
    public let ascii: String
    public var id: Int { byteOffset }
}

public struct LocalContentPreview: Sendable, Equatable {
    public let receipt: VerifiedContentReceipt
    public let text: String?
    public let textFragments: [ContentTextFragment]
    public let textIncludedByteCount: Int?
    public let hexRows: [ContentHexRow]
    public let hexIncludedByteCount: Int
    public let warnings: [String]
    public var supportsText: Bool { text != nil }
    public var textIsTruncated: Bool { textIncludedByteCount.map { Int64($0) < receipt.byteCount } ?? false }
    public var hexIsTruncated: Bool { Int64(hexIncludedByteCount) < receipt.byteCount }
}

public enum ContentPreviewBuilder {
    public static let maximumTextFragmentBytes = 256
    public static let bytesPerHexRow = 16

    public static func load(evidence: EvidenceRecord, result: EnumerationResult, file: FilesystemEntry,
                            engine: EngineClient,
                            progress: @escaping @Sendable (EngineProgress) -> Void = { _ in }) async throws -> LocalContentPreview {
        let context = try AssistantContextBuilder.metadata(evidence: evidence, result: result, file: file)
        let content = try await VerifiedContentService.extract(evidence: evidence, result: result, file: file,
                                                              engine: engine, progress: progress)
        try Task.checkCancellation()
        return render(content: content, context: context)
    }

    static func render(content: VerifiedContent, context: EvidenceAnalysisContext) -> LocalContentPreview {
        let textPrefix = ContentTextDecoder.prefix(bytes: content.bytes)
        let hexBytes = Array(content.bytes.prefix(VerifiedContentService.maximumPreviewBytes))
        let hexRows = stride(from: 0, to: hexBytes.count, by: bytesPerHexRow).map { offset in
            let row = hexBytes[offset..<min(offset + bytesPerHexRow, hexBytes.count)]
            return ContentHexRow(byteOffset: offset,
                hexadecimal: row.map { String(format: "%02X", $0) }.joined(separator: " "),
                ascii: String(row.map { (32...126).contains($0) ? Character(UnicodeScalar($0)) : "." }))
        }
        var warnings = ["Container hashes and all selected extracted bytes were verified for this local preview. Recorded metadata, timestamps and the logical-image hash were not refreshed."]
        warnings.append(contentsOf: context.warnings.dropFirst())
        warnings.append("Recorded timestamps retain the analysis timezone (\(context.analysis.timezone)); preview does not reinterpret or refresh them.")
        if Int64(hexBytes.count) < content.receipt.byteCount {
            warnings.append("Only a byte-bounded prefix is displayed. The extracted-file SHA-256 covers all extracted bytes, not just the displayed prefix.")
        }
        if textPrefix == nil {
            warnings.append("These bytes are binary, contain control characters, or use an unsupported text encoding. Hex preserves their byte values; no document parser is run.")
        }
        return LocalContentPreview(receipt: content.receipt, text: textPrefix?.text,
            textFragments: textPrefix.map { textFragments($0.text) } ?? [],
            textIncludedByteCount: textPrefix?.byteCount,
            hexRows: hexRows, hexIncludedByteCount: hexBytes.count, warnings: warnings)
    }

    private static func textFragments(_ text: String) -> [ContentTextFragment] {
        var rows: [ContentTextFragment] = []
        var fragment = "", fragmentBytes = 0, offset = 0, start = 0
        var line = 1, fragmentNumber = 1, previousWasCR = false
        func append() {
            rows.append(ContentTextFragment(id: rows.count, lineNumber: line,
                fragmentNumber: fragmentNumber, byteOffset: start, text: fragment))
            fragment = ""
            fragmentBytes = 0
        }
        for scalar in text.unicodeScalars {
            let width = scalar.utf8.count
            if scalar.value == 10 && previousWasCR {
                offset += width
                start = offset
                previousWasCR = false
                continue
            }
            previousWasCR = scalar.value == 13
            if scalar.value == 10 || scalar.value == 13 {
                append()
                offset += width
                start = offset
                line += 1
                fragmentNumber = 1
                continue
            }
            if fragmentBytes + width > maximumTextFragmentBytes {
                append()
                start = offset
                fragmentNumber += 1
            }
            fragment.unicodeScalars.append(scalar)
            fragmentBytes += width
            offset += width
        }
        append()
        return rows
    }
}

/// Mirrors assistant disclosure: complete valid UTF-8, printable scalars plus
/// tabs/newlines, then a prefix that never splits a Unicode scalar.
enum ContentTextDecoder {
    static func prefix(bytes: Data) -> (text: String, byteCount: Int)? {
        guard let text = String(data: bytes, encoding: .utf8),
              text.unicodeScalars.allSatisfy({ scalar in
                  [9, 10, 13].contains(scalar.value)
                    || (scalar.value >= 32 && scalar.value != 127 && !(128...159).contains(scalar.value))
              }) else { return nil }
        var included = 0
        var end = text.unicodeScalars.startIndex
        for scalar in text.unicodeScalars {
            let width = scalar.utf8.count
            guard included + width <= VerifiedContentService.maximumPreviewBytes else { break }
            included += width
            end = text.unicodeScalars.index(after: end)
        }
        return (String(text[..<end]), included)
    }
}
