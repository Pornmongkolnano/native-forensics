import Foundation

extension MultiEvidenceContext {
    static let pdfTransformationVersion = "utf8-bytes-and-pdf-page-utf16-minus-redactions.v2"

    static func makePDFDisclosure(file: MultiEvidenceVerifiedFile, selection: MultiEvidenceSelection,
                                  index: Int) throws -> MultiEvidenceDisclosure {
        guard let pdf = file.pdf, selection.ranges.isEmpty, selection.redactions.isEmpty else {
            throw MultiEvidenceError.invalidSelection
        }
        let spans = try MultiEvidencePDFText.visibleRanges(selected: selection.pdfRanges,
            redacted: selection.pdfRedactions, pages: pdf.analysis.textPages)
        guard spans.count <= 64 else { throw MultiEvidenceError.budgetExceeded }
        let segments = try spans.enumerated().map { offset, span -> MultiEvidenceSegment in
            guard let page = pdf.analysis.textPages.first(where: { $0.pageNumber == span.pageNumber }) else {
                throw MultiEvidenceError.invalidRange
            }
            let text = try MultiEvidencePDFText.slice(page.text, range: span.range)
            let bytes = Data(text.utf8)
            guard !bytes.contains(0), !bytes.isEmpty else { throw MultiEvidenceError.invalidContent }
            return MultiEvidenceSegment(id: "\(index == 0 ? "A" : "B")\(offset + 1)", sourceRange: nil,
                disclosedSHA256: MultiEvidenceCoding.digest(bytes), byteCount: bytes.count, text: text, pdfRange: span)
        }
        let total = segments.reduce(0) { $0 + $1.byteCount }
        guard total <= MultiEvidencePDFLimits.maximumPDFExcerptBytes else { throw MultiEvidenceError.budgetExceeded }
        let rawBytes = pdf.pageReceipts.reduce(0) { $0 + $1.byteCount }
        let receipt = MultiEvidencePDFDisclosure(provenance: pdf.provenance,
            pageCount: pdf.analysis.pageCount ?? 0, pages: pdf.pageReceipts,
            selectedRanges: selection.pdfRanges, redactedRanges: selection.pdfRedactions,
            rawDerivedByteCount: rawBytes, omittedDerivedByteCount: rawBytes - total,
            textIsComplete: pdf.analysis.textIsComplete)
        return MultiEvidenceDisclosure(binding: file.binding, contentSHA256: file.receipt.sha256,
            verifiedAt: file.receipt.verifiedAt, selectedRanges: [], redactedRanges: [], segments: segments,
            disclosedByteCount: total, omittedByteCount: rawBytes - total, pdf: receipt)
    }

    static func validatePDFFile(_ file: MultiEvidenceDisclosure, index: Int, requireText: Bool) throws {
        guard let pdf = file.pdf, file.selectedRanges.isEmpty, file.redactedRanges.isEmpty,
              file.omittedByteCount == pdf.omittedDerivedByteCount else { throw MultiEvidenceError.invalidContent }
        try validatePDFDisclosure(pdf, disclosedByteCount: file.disclosedByteCount, requireText: requireText)
        let expected = MultiEvidencePDFText.subtract(selected: pdf.selectedRanges, redacted: pdf.redactedRanges)
        guard file.segments.compactMap(\.pdfRange) == expected else { throw MultiEvidenceError.invalidContent }
        var total = 0
        for (offset, segment) in file.segments.enumerated() {
            guard segment.id == "\(index == 0 ? "A" : "B")\(offset + 1)", segment.sourceRange == nil,
                  let span = segment.pdfRange, let page = pdf.pages.first(where: { $0.pageNumber == span.pageNumber }),
                  span.range.start >= 0, span.range.end > span.range.start, span.range.end <= page.utf16Count,
                  (1...MultiEvidencePDFLimits.maximumPDFExcerptBytes).contains(segment.byteCount),
                  EngineValidation.validHash(segment.disclosedSHA256) else { throw MultiEvidenceError.invalidContent }
            total += segment.byteCount
            if requireText {
                guard let text = segment.text, text.utf8.count == segment.byteCount,
                      text.utf16.count == span.range.count, !text.utf8.contains(0),
                      MultiEvidenceCoding.digest(Data(text.utf8)) == segment.disclosedSHA256 else { throw MultiEvidenceError.invalidContent }
            } else if segment.text != nil { throw MultiEvidenceError.invalidContent }
        }
        guard total == file.disclosedByteCount else { throw MultiEvidenceError.invalidContent }
    }

    /// Identity excludes fresh verification timestamps and retained text, but
    /// includes every source/decoder/page/span/redaction/segment binding.
    public func hasSameDisclosure(as other: Self) -> Bool {
        guard schemaVersion == other.schemaVersion, transformation == other.transformation,
              files.count == other.files.count else { return false }
        return zip(files, other.files).allSatisfy { first, second in
            first.binding == second.binding && first.contentSHA256 == second.contentSHA256
                && first.selectedRanges == second.selectedRanges && first.redactedRanges == second.redactedRanges
                && first.pdf == second.pdf && first.disclosedByteCount == second.disclosedByteCount
                && first.omittedByteCount == second.omittedByteCount
                && first.segments.map { $0.withoutText() } == second.segments.map { $0.withoutText() }
        }
    }
}

extension MultiEvidenceSegment {
    func withoutText() -> Self {
        Self(id: id, sourceRange: sourceRange, disclosedSHA256: disclosedSHA256, byteCount: byteCount,
             text: nil, pdfRange: pdfRange)
    }
}
