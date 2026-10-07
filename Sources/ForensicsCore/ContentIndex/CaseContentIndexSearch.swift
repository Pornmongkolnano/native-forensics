import Foundation

public enum CaseContentIndexSearch {
    /// Whole query is a literal substring, with no token/regex/FTS interpretation
    /// and no normalization. Thai and 1–2 scalar queries follow the same rule.
    public static func search(_ query: String, in snapshot: CaseContentIndexSnapshot,
                              caseSensitive: Bool = false, maximumHits: Int = ContentIndexLimits.maximumHits) throws -> CaseContentSearchOutcome {
        try Task.checkCancellation()
        guard !query.isEmpty, query.utf8.count <= ContentIndexLimits.maximumQueryBytes else {
            return CaseContentSearchOutcome(query: query, hits: [], hitLimitReached: false, coverageIsPartial: true)
        }
        let limit = min(max(maximumHits, 1), ContentIndexLimits.maximumHits)
        let options: NSString.CompareOptions = caseSensitive ? [.literal] : [.literal, .caseInsensitive]
        var hits: [CaseContentSearchHit] = []
        for document in snapshot.documents where document.status == .indexed {
            try Task.checkCancellation()
            guard let contentHash = document.contentSHA256, let textHash = document.derivedTextSHA256,
                  let source = snapshot.sources.first(where: { $0.evidenceID == document.evidenceID }),
                  let listingHash = source.listingSHA256 else { throw ContentIndexError.invalidSnapshot }
            for page in document.textPages {
                try Task.checkCancellation()
                let text = page.text as NSString
                var offset = 0
                while offset < text.length {
                    try Task.checkCancellation()
                    let range = text.range(of: query, options: options, range: NSRange(location: offset, length: text.length - offset))
                    guard range.location != NSNotFound, range.length > 0 else { break }
                    if hits.count == limit {
                        return CaseContentSearchOutcome(query: query, hits: hits, hitLimitReached: true, coverageIsPartial: snapshot.isPartial)
                    }
                    var lower = max(range.location - 80, 0), upper = min(NSMaxRange(range) + 80, text.length)
                    // Bound scalars, not entire graphemes (a malicious grapheme
                    // can contain arbitrarily many combining marks).
                    if lower > 0, lower < text.length, (0xDC00...0xDFFF).contains(text.character(at: lower)),
                       (0xD800...0xDBFF).contains(text.character(at: lower - 1)) { lower -= 1 }
                    if upper > 0, upper < text.length, (0xD800...0xDBFF).contains(text.character(at: upper - 1)),
                       (0xDC00...0xDFFF).contains(text.character(at: upper)) { upper += 1 }
                    hits.append(CaseContentSearchHit(id: hits.count, reference: ContentIndexReference(snapshotID: snapshot.id,
                        evidenceID: document.evidenceID, listingSHA256: listingHash, file: document.file, locatorSHA256: document.locatorSHA256,
                        orderedContainerSHA256: source.orderedContainerSHA256, contentSHA256: contentHash,
                        derivedTextSHA256: textHash, decoderBinarySHA256: snapshot.decoderBinarySHA256,
                        pageNumber: page.pageNumber, utf16Offset: range.location,
                        utf16Length: range.length, referenceLabel: page.referenceLabel, referenceKind: page.referenceKind),
                        snippet: text.substring(with: NSRange(location: lower, length: upper - lower))))
                    offset = NSMaxRange(range)
                }
            }
        }
        try Task.checkCancellation()
        return CaseContentSearchOutcome(query: query, hits: hits, hitLimitReached: false, coverageIsPartial: snapshot.isPartial)
    }

    /// Resolves only exact references from this immutable derived generation.
    /// This does not reopen evidence or assert that source bytes are fresh.
    public static func resolve(_ reference: ContentIndexReference, in snapshot: CaseContentIndexSnapshot) -> DocumentTextPage? {
        guard reference.snapshotID == snapshot.id, reference.decoderBinarySHA256 == snapshot.decoderBinarySHA256,
              reference.utf16Offset >= 0, reference.utf16Length > 0,
              let source = snapshot.sources.first(where: { $0.evidenceID == reference.evidenceID }),
              source.listingSHA256 == reference.listingSHA256, source.orderedContainerSHA256 == reference.orderedContainerSHA256,
              let document = snapshot.documents.first(where: { $0.evidenceID == reference.evidenceID && $0.file == reference.file }),
              document.status == .indexed, document.locatorSHA256 == reference.locatorSHA256,
              document.contentSHA256 == reference.contentSHA256, document.derivedTextSHA256 == reference.derivedTextSHA256,
              let page = document.textPages.first(where: { $0.pageNumber == reference.pageNumber }),
              page.referenceLabel == reference.referenceLabel, page.referenceKind == reference.referenceKind,
              reference.utf16Offset <= page.text.utf16.count,
              reference.utf16Length <= page.text.utf16.count - reference.utf16Offset else { return nil }
        return page
    }
}
