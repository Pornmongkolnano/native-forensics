import Foundation

extension MultiEvidenceReferences {
    static func openPDF(_ reference: MultiEvidenceReference, disclosure: MultiEvidenceDisclosure,
                        segment: MultiEvidenceSegment, fresh: MultiEvidenceVerifiedFile) throws -> String {
        guard let receipt = disclosure.pdf, let pdf = fresh.pdf,
              pdf.provenance == receipt.provenance, pdf.pageReceipts == receipt.pages,
              pdf.analysis.pageCount == receipt.pageCount, pdf.analysis.textIsComplete == receipt.textIsComplete,
              reference.sourceRange == nil, segment.sourceRange == nil,
              let raw = segment.pdfRange, let located = reference.pdfRange, let disclosed = reference.disclosedRange,
              let page = pdf.analysis.textPages.first(where: { $0.pageNumber == raw.pageNumber }),
              let text = try? MultiEvidencePDFText.slice(page.text, range: raw.range) else { throw MultiEvidenceError.staleReference }
        let bytes = Data(text.utf8)
        guard bytes.count == segment.byteCount, MultiEvidenceCoding.digest(bytes) == segment.disclosedSHA256,
              let start = try? MultiEvidencePDFText.utf16Offset(in: text, utf8Offset: disclosed.start),
              let end = try? MultiEvidencePDFText.utf16Offset(in: text, utf8Offset: disclosed.end),
              located == MultiEvidencePDFRange(pageNumber: raw.pageNumber, start: raw.range.start + start, end: raw.range.start + end),
              let span = String(data: bytes.subdata(in: disclosed.start..<disclosed.end), encoding: .utf8) else {
            throw MultiEvidenceError.staleReference
        }
        return span
    }
}
