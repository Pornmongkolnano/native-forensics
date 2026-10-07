import Foundation

public struct DocumentSearchHit: Sendable, Equatable, Identifiable {
    public let id: Int
    public let pageNumber: Int
    public let snippet: String
    /// Zero-based UTF-16 offset within extracted page text, not a source byte offset.
    public let utf16Offset: Int
    public let referenceLabel: String?
    public let referenceKind: DocumentTextReferenceKind?
}

public struct DocumentSearchOutcome: Sendable, Equatable {
    public let query: String
    public let hits: [DocumentSearchHit]
    public let searchedTextIsComplete: Bool
    public let hitLimitReached: Bool
}

/// Literal substring search over locally decoded text. No regex, OCR, web
/// service, or AI interpretation is implied by a positive or negative result.
public enum DocumentContentSearch {
    public static func search(_ query: String, in analysis: DocumentAnalysis,
                              caseSensitive: Bool = false, maximumHits: Int = 200) -> DocumentSearchOutcome {
        let limit = min(max(maximumHits, 1), 1_000)
        guard !query.isEmpty, query.utf8.count <= 4_096 else {
            return DocumentSearchOutcome(query: query, hits: [], searchedTextIsComplete: false, hitLimitReached: false)
        }
        var hits: [DocumentSearchHit] = []
        let options: NSString.CompareOptions = caseSensitive ? [.literal] : [.literal, .caseInsensitive]
        for page in analysis.textPages {
            let text = page.text as NSString
            var offset = 0
            while offset < text.length {
                let range = text.range(of: query, options: options, range: NSRange(location: offset, length: text.length - offset))
                guard range.location != NSNotFound else { break }
                if hits.count == limit {
                    return DocumentSearchOutcome(query: query, hits: hits,
                        searchedTextIsComplete: analysis.textIsComplete, hitLimitReached: true)
                }
                var lower = max(range.location - 100, 0), upper = min(NSMaxRange(range) + 100, text.length)
                // Retain complete Unicode scalars. A grapheme can contain an
                // unbounded number of combining marks, so expanding to whole
                // composed characters would defeat this snippet's size budget.
                if lower > 0, lower < text.length, (0xDC00...0xDFFF).contains(text.character(at: lower)),
                   (0xD800...0xDBFF).contains(text.character(at: lower - 1)) { lower -= 1 }
                if upper > 0, upper < text.length, (0xD800...0xDBFF).contains(text.character(at: upper - 1)),
                   (0xDC00...0xDFFF).contains(text.character(at: upper)) { upper += 1 }
                let snippetRange = NSRange(location: lower, length: upper - lower)
                hits.append(DocumentSearchHit(id: hits.count, pageNumber: page.pageNumber,
                    snippet: text.substring(with: snippetRange), utf16Offset: range.location,
                    referenceLabel: page.referenceLabel, referenceKind: page.referenceKind))
                offset = NSMaxRange(range)
            }
        }
        return DocumentSearchOutcome(query: query, hits: hits,
            searchedTextIsComplete: analysis.textIsComplete, hitLimitReached: false)
    }
}
