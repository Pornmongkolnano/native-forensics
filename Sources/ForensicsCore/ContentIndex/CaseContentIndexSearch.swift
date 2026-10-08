import Foundation
import NaturalLanguage

public enum CaseContentIndexSearch {
    /// Compatibility entry point: the whole query remains a literal substring.
    /// Thai and 1–2 scalar queries never acquire token or wildcard semantics.
    public static func search(_ query: String, in snapshot: CaseContentIndexSnapshot,
                              caseSensitive: Bool = false, maximumHits: Int = ContentIndexLimits.maximumHits) throws -> CaseContentSearchOutcome {
        let result = try search(ContentIndexQueryRequest(query: query, caseSensitive: caseSensitive),
                                in: snapshot, maximumHits: maximumHits)
        return CaseContentSearchOutcome(query: query, hits: result.hits.map {
            CaseContentSearchHit(id: $0.id, reference: $0.reference.indexReference, snippet: $0.snippet)
        }, hitLimitReached: result.hitLimitReached, coverageIsPartial: result.coverageIsPartial)
    }

    public static func search(_ query: String, in snapshot: CaseContentIndexSnapshot,
                              mode: ContentIndexSearchMode, caseSensitive: Bool = false,
                              maximumHits: Int = ContentIndexLimits.maximumHits) throws -> CaseContentQueryOutcome {
        try search(ContentIndexQueryRequest(query: query, mode: mode, caseSensitive: caseSensitive),
                   in: snapshot, maximumHits: maximumHits)
    }

    /// Phrase compares adjacent whole word tokens. Thai-only phrases also
    /// compare complete Thai tokens with internal whitespace omitted. Prefix
    /// compares the literal beginning of one token; all ranges retain raw text.
    public static func search(_ request: ContentIndexQueryRequest, in snapshot: CaseContentIndexSnapshot,
                              maximumHits: Int = ContentIndexLimits.maximumHits) throws -> CaseContentQueryOutcome {
        try Task.checkCancellation()
        let plan = try QueryPlan(request)
        guard plan.issue == nil else {
            return CaseContentQueryOutcome(request: request, queryTokens: plan.tokens, queryIssue: plan.issue,
                hits: [], hitLimitReached: false, coverageIsPartial: true)
        }
        let limit = min(max(maximumHits, 1), ContentIndexLimits.maximumHits)
        var hits: [CaseContentQueryHit] = []
        for document in snapshot.documents where document.status == .indexed {
            try Task.checkCancellation()
            guard let contentHash = document.contentSHA256, let textHash = document.derivedTextSHA256,
                  let source = snapshot.sources.first(where: { $0.evidenceID == document.evidenceID }),
                  let listingHash = source.listingSHA256 else { throw ContentIndexError.invalidSnapshot }
            let decoderProvenanceHash = try boundProvenanceDigest(document, in: snapshot)
            for page in document.textPages {
                try Task.checkCancellation()
                let text = page.text as NSString
                var additionalMatch = false
                try enumerateMatches(plan, in: text) { range in
                    if hits.count == limit { additionalMatch = true; return false }
                    let reference = ContentIndexReference(snapshotID: snapshot.id,
                        evidenceID: document.evidenceID, listingSHA256: listingHash, file: document.file, locatorSHA256: document.locatorSHA256,
                        orderedContainerSHA256: source.orderedContainerSHA256, contentSHA256: contentHash,
                        derivedTextSHA256: textHash, decoderBinarySHA256: snapshot.decoderBinarySHA256,
                        pageNumber: page.pageNumber, utf16Offset: range.location,
                        utf16Length: range.length, referenceLabel: page.referenceLabel, referenceKind: page.referenceKind,
                        decoderProvenanceSHA256: decoderProvenanceHash)
                    hits.append(CaseContentQueryHit(id: hits.count,
                        reference: ContentIndexQueryReference(caseID: snapshot.caseID, request: request, indexReference: reference),
                        snippet: snippet(text, around: range)))
                    return true
                }
                if additionalMatch {
                    return CaseContentQueryOutcome(request: request, queryTokens: plan.tokens, queryIssue: nil,
                        hits: hits, hitLimitReached: true, coverageIsPartial: snapshot.isPartial)
                }
            }
        }
        try Task.checkCancellation()
        return CaseContentQueryOutcome(request: request, queryTokens: plan.tokens, queryIssue: nil,
            hits: hits, hitLimitReached: false, coverageIsPartial: snapshot.isPartial)
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
        do {
            guard try boundProvenanceDigest(document, in: snapshot) == reference.decoderProvenanceSHA256 else { return nil }
        } catch { return nil }
        return page
    }

    /// Bind both the retained document proof and its generation's full decoder
    /// identity. Header-only mutations cannot reuse an otherwise unchanged hit.
    private static func boundProvenanceDigest(_ document: ContentIndexDocument,
                                             in snapshot: CaseContentIndexSnapshot) throws -> String? {
        guard let identity = snapshot.decoderIdentity else {
            guard snapshot.decoderContract == "NFDocumentDecoder.document-analysis.v1",
                  document.decoderProvenance == nil else { throw ContentIndexError.invalidSnapshot }
            return nil
        }
        do { try identity.validateMetadata() }
        catch { throw ContentIndexError.invalidSnapshot }
        guard snapshot.decoderContract == identity.decoderIdentifier + "@" + identity.decoderVersion,
              snapshot.decoderBinarySHA256 == identity.decoderExecutableSHA256,
              let provenance = document.decoderProvenance, identity.matches(provenance),
              provenance.derivedTextSHA256 == document.derivedTextSHA256 else { throw ContentIndexError.invalidSnapshot }
        // Public callers can decode an in-memory snapshot without accepting it
        // through the store validator. Bind the proof to its actual raw pages,
        // rather than trusting two equal but stale persisted hash fields.
        do { try provenance.validate(pages: document.textPages) }
        catch { throw ContentIndexError.invalidSnapshot }
        return try CaseWorkCoding.digest(provenance)
    }

    /// A query reference additionally proves that its exact range is a match of
    /// the recorded mode and raw query. Unrelated query/range context is rejected;
    /// expectedRequest additionally checks the caller's original request binding.
    public static func resolve(_ reference: ContentIndexQueryReference, in snapshot: CaseContentIndexSnapshot,
                               expectedRequest: ContentIndexQueryRequest? = nil) -> DocumentTextPage? {
        guard reference.caseID == snapshot.caseID,
              expectedRequest == nil || expectedRequest == reference.request,
              let page = resolve(reference.indexReference, in: snapshot) else { return nil }
        do {
            let plan = try QueryPlan(reference.request)
            guard plan.issue == nil else { return nil }
            let expected = NSRange(location: reference.indexReference.utf16Offset, length: reference.indexReference.utf16Length)
            var found = false
            try enumerateMatches(plan, in: page.text as NSString) { range in
                if range == expected { found = true; return false }
                return range.location <= expected.location
            }
            return found ? page : nil
        } catch { return nil }
    }

    private struct QueryPlan {
        let request: ContentIndexQueryRequest
        var tokens: [ContentIndexQueryToken] = []
        var issue: ContentIndexQueryIssue?
        var failure: [Int] = []
        var thaiPhrase: ThaiPhrasePlan?
        var options: NSString.CompareOptions { request.caseSensitive ? [.literal] : [.literal, .caseInsensitive] }

        init(_ request: ContentIndexQueryRequest) throws {
            self.request = request
            guard !request.query.isEmpty else { issue = .emptyQuery; return }
            guard request.query.utf8.count <= ContentIndexLimits.maximumQueryBytes else { issue = .queryTooLong; return }
            guard request.mode != .literal else { return }
            let text = request.query as NSString
            try CaseContentIndexSearch.enumerateWords(text) { range in
                tokens.append(ContentIndexQueryToken(text: text.substring(with: range), utf16Offset: range.location, utf16Length: range.length))
                return true
            }
            guard !tokens.isEmpty else { issue = .noWordTokens; return }
            if request.mode == .tokenPrefix {
                guard tokens.count == 1, tokens[0].utf16Offset == 0, tokens[0].utf16Length == text.length else {
                    issue = .prefixRequiresSingleToken; return
                }
                return
            }
            // Never silently discard raw quotes, '*', brackets or punctuation
            // from the query. Phrase spacing is the only ignored query text.
            var end = 0
            for token in tokens {
                guard Self.onlyWhitespace(text, NSRange(location: end, length: token.utf16Offset - end)) else {
                    issue = .phraseContainsNonWordText; return
                }
                end = token.utf16Offset + token.utf16Length
            }
            guard Self.onlyWhitespace(text, NSRange(location: end, length: text.length - end)) else {
                issue = .phraseContainsNonWordText; return
            }
            if tokens.allSatisfy({ token in
                let word = token.text as NSString
                return CaseContentIndexSearch.isThaiWord(word, range: NSRange(location: 0, length: word.length))
            }) {
                thaiPhrase = try ThaiPhrasePlan(tokens: tokens)
                return
            }
            failure = Array(repeating: 0, count: tokens.count)
            var matched = 0
            if tokens.count > 1 {
                for index in 1..<tokens.count {
                    try Task.checkCancellation()
                    while matched > 0, !tokenEquals(tokens[index].text, tokens[matched].text) { matched = failure[matched - 1] }
                    if tokenEquals(tokens[index].text, tokens[matched].text) { matched += 1 }
                    failure[index] = matched
                }
            }
        }

        func tokenEquals(_ left: String, _ right: String) -> Bool {
            (left as NSString).compare(right, options: options) == .orderedSame
        }
        private static func onlyWhitespace(_ text: NSString, _ range: NSRange) -> Bool {
            text.substring(with: range).unicodeScalars.allSatisfy { $0.properties.isWhitespace }
        }
    }

    /// Thai dictionary compounds need not expose their component words. This
    /// plan compares raw Thai units across whitespace while retaining the
    /// existing platform token boundaries as the only permitted match edges.
    private struct ThaiPhrasePlan {
        let units: [UInt16]
        let failure: [Int]

        init(tokens: [ContentIndexQueryToken]) throws {
            units = tokens.flatMap { Array($0.text.utf16) }
            var table = Array(repeating: 0, count: units.count), matched = 0
            if units.count > 1 {
                for index in 1..<units.count {
                    try Task.checkCancellation()
                    while matched > 0, units[index] != units[matched] { matched = table[matched - 1] }
                    if units[index] == units[matched] { matched += 1 }
                    table[index] = matched
                }
            }
            failure = table
        }
    }

    /// Streaming KMP over words keeps only query-sized state, including for
    /// repeated/overlapping phrases. No per-document token array is retained.
    private static func enumerateMatches(_ plan: QueryPlan, in text: NSString, visit: (NSRange) -> Bool) throws {
        switch plan.request.mode {
        case .literal:
            var offset = 0
            while offset < text.length {
                try Task.checkCancellation()
                let range = text.range(of: plan.request.query, options: plan.options,
                    range: NSRange(location: offset, length: text.length - offset))
                guard range.location != NSNotFound, range.length > 0 else { return }
                guard visit(range) else { return }
                offset = NSMaxRange(range)
            }
        case .tokenPrefix:
            try enumerateWords(text) { token in
                let range = text.range(of: plan.request.query, options: plan.options.union(.anchored), range: token)
                guard range.location == token.location, range.length > 0 else { return true }
                return visit(range)
            }
        case .phrase:
            if let thaiPhrase = plan.thaiPhrase {
                try enumerateThaiPhrase(thaiPhrase, in: text, visit: visit)
                return
            }
            var matched = 0, tokenCount = 0
            var recent = Array(repeating: NSRange(location: 0, length: 0), count: plan.tokens.count)
            try enumerateWords(text) { range in
                recent[tokenCount % recent.count] = range; tokenCount += 1
                func equals(_ index: Int) -> Bool {
                    text.compare(plan.tokens[index].text, options: plan.options, range: range) == .orderedSame
                }
                while matched > 0, !equals(matched) { matched = plan.failure[matched - 1] }
                if equals(matched) { matched += 1 }
                guard matched == plan.tokens.count else { return true }
                let start = recent[(tokenCount - recent.count) % recent.count].location
                matched = plan.failure[matched - 1]
                return visit(NSRange(location: start, length: NSMaxRange(range) - start))
            }
        }
    }

    private static func isThaiWord(_ text: NSString, range: NSRange) -> Bool {
        guard range.length > 0 else { return false }
        return (range.location..<NSMaxRange(range)).allSatisfy { offset in
            let unit = text.character(at: offset)
            guard (0x0E00...0x0E7F).contains(unit), let scalar = UnicodeScalar(UInt32(unit)) else { return false }
            return CharacterSet.letters.contains(scalar) || CharacterSet.nonBaseCharacters.contains(scalar)
        }
    }

    /// KMP over unchanged Thai UTF-16 units. The ring remembers original
    /// positions and token starts, so ignored whitespace stays in hit ranges
    /// without making an interior character a valid word edge.
    private static func enumerateThaiPhrase(_ plan: ThaiPhrasePlan, in text: NSString, visit: (NSRange) -> Bool) throws {
        var matched = 0, unitCount = 0, previousEnd: Int?
        var recent = Array(repeating: (offset: 0, wordStart: false), count: plan.units.count)
        try enumerateWords(text) { range in
            guard isThaiWord(text, range: range) else {
                matched = 0; unitCount = 0; previousEnd = nil
                return true
            }
            if let previousEnd {
                let gap = NSRange(location: previousEnd, length: range.location - previousEnd)
                if !text.substring(with: gap).unicodeScalars.allSatisfy({ $0.properties.isWhitespace }) {
                    matched = 0; unitCount = 0
                }
            }
            previousEnd = NSMaxRange(range)
            for offset in range.location..<NSMaxRange(range) {
                if Task.isCancelled { return false }
                recent[unitCount % recent.count] = (offset: offset, wordStart: offset == range.location)
                unitCount += 1
                let unit = text.character(at: offset)
                while matched > 0, unit != plan.units[matched] { matched = plan.failure[matched - 1] }
                if unit == plan.units[matched] { matched += 1 }
                guard matched == plan.units.count else { continue }
                let start = recent[(unitCount - recent.count) % recent.count]
                matched = plan.failure[matched - 1]
                guard start.wordStart, offset + 1 == NSMaxRange(range) else { continue }
                if !visit(NSRange(location: start.offset, length: offset + 1 - start.offset)) { return false }
            }
            return true
        }
    }

    private static func enumerateWords(_ text: NSString, visit: (NSRange) -> Bool) throws {
        try Task.checkCancellation()
        var canceled = false, invalidTokenRange = false
        var thaiTokenizer: NLTokenizer?
        // Foundation declares an escaping block but completes it synchronously.
        // Keep our visitor nonescaping, including mutating query-plan builders.
        withoutActuallyEscaping(visit) { visitor in
            text.enumerateSubstrings(in: NSRange(location: 0, length: text.length), options: [.byWords, .substringNotRequired]) { _, range, _, stop in
                if Task.isCancelled { canceled = true; stop.pointee = true; return }
                // Foundation's default word break can retain an entire Thai
                // run. Refine only Thai-bearing spans with an explicit Thai
                // tokenizer, independent of the user's current locale.
                let containsThai = (range.location..<NSMaxRange(range)).contains {
                    (0x0E00...0x0E7F).contains(text.character(at: $0))
                }
                guard containsThai else {
                    if !visitor(range) { stop.pointee = true }
                    return
                }
                let span = text.substring(with: range)
                let tokenizer = thaiTokenizer ?? NLTokenizer(unit: .word)
                thaiTokenizer = tokenizer
                tokenizer.string = span; tokenizer.setLanguage(.thai)
                var emitted = false, continueVisit = true, previousEnd = 0
                tokenizer.enumerateTokens(in: span.startIndex..<span.endIndex) { tokenRange, _ in
                    if Task.isCancelled { canceled = true; continueVisit = false; return false }
                    let token = NSRange(tokenRange, in: span)
                    guard token.location >= previousEnd, token.location <= range.length, token.length > 0,
                          token.length <= range.length - token.location else {
                        invalidTokenRange = true; continueVisit = false; return false
                    }
                    previousEnd = NSMaxRange(token); emitted = true
                    continueVisit = visitor(NSRange(location: range.location + token.location, length: token.length))
                    return continueVisit
                }
                if !continueVisit { stop.pointee = true }
                else if !emitted, !visitor(range) {
                    // Retain an existing word span when the dictionary has no
                    // tokens, including short/unknown Thai. Never invent
                    // character boundaries or skip the original word silently.
                    stop.pointee = true
                }
            }
        }
        if canceled { throw CancellationError() }
        if invalidTokenRange { throw ContentIndexError.invalidSnapshot }
        try Task.checkCancellation()
    }

    private static func snippet(_ text: NSString, around range: NSRange) -> String {
        // A large phrase may span arbitrary punctuation. Keep the excerpt
        // bounded independently of its full match length.
        var lower = max(range.location - 80, 0), upper = min(text.length, range.location + 80)
        if lower > 0, lower < text.length, (0xDC00...0xDFFF).contains(text.character(at: lower)),
           (0xD800...0xDBFF).contains(text.character(at: lower - 1)) { lower -= 1 }
        if upper > 0, upper < text.length, (0xD800...0xDBFF).contains(text.character(at: upper - 1)),
           (0xDC00...0xDFFF).contains(text.character(at: upper)) { upper += 1 }
        return text.substring(with: NSRange(location: lower, length: upper - lower))
    }
}
