import Foundation

public enum MultiEvidencePDFLimits {
    public static let maximumPDFExcerptBytes = 16_384
    public static let maximumPDFAggregateBytes = 32_768
    public static let maximumSelectedPages = 16
}

/// Half-open UTF-16 positions in untouched decoder page text, never PDF bytes.
public struct MultiEvidencePDFRange: Codable, Equatable, Sendable {
    public let pageNumber: Int
    public let range: MultiEvidenceRange

    public init(pageNumber: Int, start: Int, end: Int) {
        self.pageNumber = pageNumber
        self.range = MultiEvidenceRange(start: start, end: end)
    }
}

/// A bounded historical receipt; omitted raw page text is not retained here.
public struct MultiEvidencePDFPageReceipt: Codable, Equatable, Sendable {
    public let pageNumber: Int
    public let utf16Count: Int
    public let byteCount: Int
    public let rawTextSHA256: String
    public let isTruncated: Bool

    public init(pageNumber: Int, utf16Count: Int, byteCount: Int, rawTextSHA256: String, isTruncated: Bool) {
        self.pageNumber = pageNumber; self.utf16Count = utf16Count; self.byteCount = byteCount
        self.rawTextSHA256 = rawTextSHA256; self.isTruncated = isTruncated
    }
}

public struct MultiEvidencePDFDisclosure: Codable, Equatable, Sendable {
    public let provenance: DocumentDecodeProvenance
    public let pageCount: Int
    public let pages: [MultiEvidencePDFPageReceipt]
    public let selectedRanges: [MultiEvidencePDFRange]
    public let redactedRanges: [MultiEvidencePDFRange]
    public let rawDerivedByteCount: Int
    public let omittedDerivedByteCount: Int
    public let textIsComplete: Bool

    public init(provenance: DocumentDecodeProvenance, pageCount: Int, pages: [MultiEvidencePDFPageReceipt],
                selectedRanges: [MultiEvidencePDFRange], redactedRanges: [MultiEvidencePDFRange],
                rawDerivedByteCount: Int, omittedDerivedByteCount: Int, textIsComplete: Bool) {
        self.provenance = provenance; self.pageCount = pageCount; self.pages = pages
        self.selectedRanges = selectedRanges; self.redactedRanges = redactedRanges
        self.rawDerivedByteCount = rawDerivedByteCount; self.omittedDerivedByteCount = omittedDerivedByteCount
        self.textIsComplete = textIsComplete
    }
}

/// Created only from a fresh owned extraction and receipt-validated decoder result.
/// File kind is established by the decoder; this wrapper has no original PDF bytes.
public struct MultiEvidenceVerifiedPDF: Sendable {
    public let analysis: DocumentAnalysis
    public let provenance: DocumentDecodeProvenance
    public let pageReceipts: [MultiEvidencePDFPageReceipt]

    public init(binding: CaseWorkBinding, preview: FilesystemDocumentPreview) throws {
        try binding.validate()
        let receipt = preview.receipt, analysis = preview.analysis
        guard !binding.selectedEntry.isDirectory,
              (0...DocumentLimits.maximumInputBytes).contains(binding.selectedEntry.size),
              preview.file == binding.selectedEntry,
              receipt.evidenceID == binding.evidenceID, receipt.fileID == binding.selectedEntry.id,
              receipt.byteCount == binding.selectedEntry.size,
              receipt.orderedContainerSHA256 == binding.containerHashes.map(\.sha256),
              receipt.verifiedAt.timeIntervalSince1970.isFinite, EngineValidation.validHash(receipt.sha256),
              analysis.schemaVersion == 2, analysis.contentKind == .pdf, analysis.status == .decoded,
              analysis.mimeType == "application/pdf", analysis.sourceSHA256 == receipt.sha256,
              analysis.sourceByteCount == receipt.byteCount, let provenance = analysis.provenance,
              provenance.isolation != .testFixture else { throw MultiEvidenceError.invalidContent }
        // The sentinel path is validation metadata only; this call never opens it.
        try DocumentAnalysisClient.validate(analysis, for: DocumentInput(fileURL: URL(fileURLWithPath: "/derived-pdf-validation"),
            expectedSHA256: receipt.sha256, expectedByteCount: receipt.byteCount))
        try provenance.validate(pages: analysis.textPages)
        self.analysis = analysis; self.provenance = provenance
        pageReceipts = analysis.textPages.map(MultiEvidencePDFText.receipt)
    }
}

/// Historical shape/policy validation only. Full-retention segment text is checked
/// by the owning context validator; neither retention mode retains omitted text
/// from which this method could recompute the complete derived-text digest.
func validatePDFDisclosure(_ disclosure: MultiEvidencePDFDisclosure, disclosedByteCount: Int, requireText: Bool) throws {
    _ = requireText
    try validatePDFProvenanceMetadata(disclosure.provenance)
    try MultiEvidencePDFText.validatePageReceipts(disclosure.pages)
    guard (1...1_000_000).contains(disclosure.pageCount),
          disclosure.pages.allSatisfy({ $0.pageNumber <= disclosure.pageCount }),
          (0...DocumentLimits.maximumTextBytes).contains(disclosure.rawDerivedByteCount),
          disclosure.rawDerivedByteCount == disclosure.pages.reduce(0, { $0 + $1.byteCount }),
          (0...MultiEvidencePDFLimits.maximumPDFExcerptBytes).contains(disclosedByteCount),
          disclosedByteCount <= disclosure.rawDerivedByteCount,
          disclosure.omittedDerivedByteCount == disclosure.rawDerivedByteCount - disclosedByteCount,
          disclosure.textIsComplete == (!disclosure.pages.isEmpty && disclosure.pages.count == disclosure.pageCount
              && disclosure.pages.allSatisfy({ !$0.isTruncated && $0.byteCount > 0 })) else {
        throw MultiEvidenceError.invalidContent
    }
    try MultiEvidencePDFText.validateRanges(disclosure.selectedRanges, pageReceipts: disclosure.pages)
    try MultiEvidencePDFText.validateRanges(disclosure.redactedRanges, pageReceipts: disclosure.pages)
    let visible = MultiEvidencePDFText.subtract(selected: disclosure.selectedRanges, redacted: disclosure.redactedRanges)
    guard visible.count <= 64 else { throw MultiEvidenceError.budgetExceeded }
    let visibleUTF16Count = visible.reduce(0) { $0 + $1.range.count }
    // Each valid Unicode scalar uses at least one UTF-8 byte per UTF-16 unit
    // and at most three. Exact UTF-8 bytes/digests require the disclosed segments.
    guard disclosedByteCount >= visibleUTF16Count, disclosedByteCount <= visibleUTF16Count * 3 else {
        throw MultiEvidenceError.invalidContent
    }
}

private func validatePDFProvenanceMetadata(_ value: DocumentDecodeProvenance) throws {
    guard value.isolation != .testFixture else { throw MultiEvidenceError.invalidContent }
    // Historical receipts omit raw page text, so validate the centralized
    // broker/worker metadata contract without pretending to recompute it.
    do { try value.validateMetadata() }
    catch { throw MultiEvidenceError.invalidContent }
}

enum MultiEvidencePDFText {
    static func slice(_ text: String, range: MultiEvidenceRange) throws -> String {
        guard range.start >= 0, range.end > range.start, range.end <= text.utf16.count else {
            throw MultiEvidenceError.invalidRange
        }
        let units = Array(text.utf16)
        // String.Index(_:within: String) requires a Character boundary, which
        // would reject a valid cut between e and a following combining scalar.
        // Swift strings are valid Unicode; a UTF-16 cut is a scalar boundary
        // exactly when it does not start at the trailing half of a surrogate.
        guard utf16ScalarBoundary(range.start, units: units), utf16ScalarBoundary(range.end, units: units) else {
            throw MultiEvidenceError.invalidRange
        }
        return String(decoding: units[range.start..<range.end], as: UTF16.self)
    }

    static func utf16Offset(in text: String, utf8Offset: Int) throws -> Int {
        guard utf8Offset >= 0, utf8Offset <= text.utf8.count else { throw MultiEvidenceError.invalidRange }
        let bytes = Array(text.utf8)
        // An interior UTF-8 position is a scalar boundary only when the next
        // byte is not a continuation. Decode only this proven-valid prefix;
        // counting UTF-16 units preserves untouched combining scalars.
        guard utf8Offset == bytes.count || !(0x80...0xbf).contains(bytes[utf8Offset]) else {
            throw MultiEvidenceError.invalidRange
        }
        return String(decoding: bytes.prefix(utf8Offset), as: UTF8.self).utf16.count
    }

    private static func utf16ScalarBoundary(_ offset: Int, units: [UInt16]) -> Bool {
        offset == units.count || !(0xdc00...0xdfff).contains(units[offset])
    }

    static func defaultSelection(_ pdf: MultiEvidenceVerifiedPDF) -> [MultiEvidencePDFRange] {
        var remaining = MultiEvidencePDFLimits.maximumPDFExcerptBytes
        var ranges: [MultiEvidencePDFRange] = []
        for page in pdf.analysis.textPages {
            guard remaining > 0, ranges.count < MultiEvidencePDFLimits.maximumSelectedPages else { break }
            var end = 0
            // Admit whole Unicode scalars, measuring actual UTF-8 bytes rather
            // than assuming UTF-16 counts or graphemes are a disclosure budget.
            for scalar in page.text.unicodeScalars {
                let value = scalar.value
                let byteCount = value <= 0x7f ? 1 : value <= 0x7ff ? 2 : value <= 0xffff ? 3 : 4
                guard byteCount <= remaining else { break }
                remaining -= byteCount
                end += value <= 0xffff ? 1 : 2
            }
            if end > 0 { ranges.append(.init(pageNumber: page.pageNumber, start: 0, end: end)) }
        }
        return ranges
    }

    static func visibleRanges(selected: [MultiEvidencePDFRange], redacted: [MultiEvidencePDFRange],
                              pages: [DocumentTextPage]) throws -> [MultiEvidencePDFRange] {
        let receipts = pages.map(receipt)
        try validateRanges(selected, pageReceipts: receipts)
        try validateRanges(redacted, pageReceipts: receipts)
        let byPage = Dictionary(uniqueKeysWithValues: pages.map { ($0.pageNumber, $0.text) })
        for span in selected + redacted {
            guard let text = byPage[span.pageNumber] else { throw MultiEvidenceError.invalidRange }
            _ = try slice(text, range: span.range)
        }
        let result = subtract(selected: selected, redacted: redacted)
        guard result.count <= 64 else { throw MultiEvidenceError.budgetExceeded }
        return result
    }

    static func validateRanges(_ ranges: [MultiEvidencePDFRange], pageReceipts: [MultiEvidencePDFPageReceipt]) throws {
        try validatePageReceipts(pageReceipts)
        guard ranges.count <= 32, Set(ranges.map(\.pageNumber)).count <= MultiEvidencePDFLimits.maximumSelectedPages else {
            throw MultiEvidenceError.budgetExceeded
        }
        let byPage = Dictionary(uniqueKeysWithValues: pageReceipts.map { ($0.pageNumber, $0) })
        var lastPage = 0, lastEnd = 0
        for span in ranges {
            guard let page = byPage[span.pageNumber], span.pageNumber >= lastPage,
                  span.range.start >= 0, span.range.end > span.range.start, span.range.end <= page.utf16Count,
                  span.pageNumber != lastPage || span.range.start >= lastEnd else { throw MultiEvidenceError.invalidRange }
            lastPage = span.pageNumber; lastEnd = span.range.end
        }
    }

    static func receipt(_ page: DocumentTextPage) -> MultiEvidencePDFPageReceipt {
        .init(pageNumber: page.pageNumber, utf16Count: page.text.utf16.count, byteCount: page.text.utf8.count,
              rawTextSHA256: MultiEvidenceCoding.digest(Data(page.text.utf8)), isTruncated: page.isTruncated)
    }

    static func validatePageReceipts(_ pages: [MultiEvidencePDFPageReceipt]) throws {
        guard pages.count <= DocumentLimits.maximumPages else { throw MultiEvidenceError.budgetExceeded }
        var lastPage = 0, total = 0
        for page in pages {
            guard page.pageNumber > lastPage, page.pageNumber <= 1_000_000,
                  (0...DocumentLimits.maximumTextBytes).contains(page.byteCount),
                  page.utf16Count >= 0, page.utf16Count <= page.byteCount,
                  page.byteCount <= page.utf16Count * 3,
                  EngineValidation.validHash(page.rawTextSHA256),
                  page.byteCount != 0 || page.rawTextSHA256 == MultiEvidenceCoding.digest(Data()) else {
                throw MultiEvidenceError.invalidContent
            }
            total += page.byteCount
            guard total <= DocumentLimits.maximumTextBytes else { throw MultiEvidenceError.budgetExceeded }
            lastPage = page.pageNumber
        }
    }

    static func subtract(selected: [MultiEvidencePDFRange], redacted: [MultiEvidencePDFRange]) -> [MultiEvidencePDFRange] {
        var spans = selected
        for hidden in redacted {
            spans = spans.flatMap { span in
                guard span.pageNumber == hidden.pageNumber, hidden.range.start < span.range.end,
                      hidden.range.end > span.range.start else { return [span] }
                var remaining: [MultiEvidencePDFRange] = []
                if span.range.start < hidden.range.start {
                    remaining.append(.init(pageNumber: span.pageNumber, start: span.range.start, end: hidden.range.start))
                }
                if hidden.range.end < span.range.end {
                    remaining.append(.init(pageNumber: span.pageNumber, start: hidden.range.end, end: span.range.end))
                }
                return remaining
            }
        }
        return spans
    }
}
