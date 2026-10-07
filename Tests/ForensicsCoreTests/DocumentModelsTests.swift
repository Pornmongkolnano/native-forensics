import Foundation
import Testing
@testable import ForensicsCore

struct DocumentModelsTests {
    private func pdf(_ pages: [DocumentTextPage], count: Int? = nil) -> DocumentAnalysis {
        DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: String(repeating: "a", count: 64), sourceByteCount: 12,
            pageCount: count ?? pages.count, textPages: pages)
    }

    @Test func literalSearchReportsExactPageAndSnippet() {
        let analysis = pdf([DocumentTextPage(pageNumber: 1, text: "Unrelated content."),
                            DocumentTextPage(pageNumber: 2, text: "The diary of Jack contains [literal].")])
        let result = DocumentContentSearch.search("DIARY of Jack", in: analysis)
        #expect(result.hits.count == 1)
        #expect(result.hits.first?.pageNumber == 2)
        #expect(result.hits.first?.snippet.contains("diary of Jack") == true)
        #expect(result.hits.first?.utf16Offset == 4)
        #expect(result.searchedTextIsComplete)
        #expect(DocumentContentSearch.search("[literal]", in: analysis).hits.count == 1)
        #expect(DocumentContentSearch.search(".*", in: analysis).hits.isEmpty)
    }

    @Test func partialAndImageSearchDoNotClaimAbsenceProof() {
        #expect(!DocumentContentSearch.search("missing", in: pdf([DocumentTextPage(pageNumber: 1, text: "partial", isTruncated: true)])).searchedTextIsComplete)
        #expect(!DocumentContentSearch.search("missing", in: pdf([DocumentTextPage(pageNumber: 1, text: "some text")], count: 201)).searchedTextIsComplete)
        #expect(!DocumentContentSearch.search("missing", in: pdf([DocumentTextPage(pageNumber: 1, text: "")])).searchedTextIsComplete)
        let image = DocumentAnalysis(contentKind: .image, mimeType: "image/png", status: .decoded,
            sourceSHA256: String(repeating: "a", count: 64), sourceByteCount: 12, pixelWidth: 1, pixelHeight: 1)
        #expect(!DocumentContentSearch.search("missing", in: image).searchedTextIsComplete)
    }

    @Test func hitLimitAndUnicodeSnippetAreExplicit() {
        let result = DocumentContentSearch.search("needle", in: pdf([DocumentTextPage(pageNumber: 1,
            text: String(repeating: "😀 needle ", count: 30))]), maximumHits: 2)
        #expect(result.hits.count == 2)
        #expect(result.hitLimitReached)
        #expect(result.hits.first?.snippet.contains("😀") == true)
        #expect(DocumentContentSearch.search("", in: pdf([DocumentTextPage(pageNumber: 1, text: "data")])).hits.isEmpty)
    }

    @Test func rawUnzonedExifSurvivesCodableExactly() throws {
        let date = "2001:01:06 11:12:30"
        let result = DocumentAnalysis(contentKind: .image, mimeType: "image/jpeg", status: .decoded,
            sourceSHA256: String(repeating: "a", count: 64), sourceByteCount: 12, pixelWidth: 1, pixelHeight: 1,
            rawMetadata: [DocumentRawMetadata(name: "EXIF.DateTimeOriginal", value: date)],
            warnings: ["The file does not supply an EXIF timezone offset."])
        let decoded = try JSONDecoder().decode(DocumentAnalysis.self, from: JSONEncoder().encode(result))
        #expect(decoded == result)
        #expect(decoded.rawMetadata.first?.value == date)
        #expect(decoded.rawMetadata.count == 1)
    }

    @Test func pathologicalGraphemeDoesNotExpandSnippetBudget() {
        let text = "needle A" + String(repeating: "\u{0301}", count: 10_000)
        let result = DocumentContentSearch.search("needle", in: pdf([DocumentTextPage(pageNumber: 1, text: text)]))
        #expect(result.hits.count == 1)
        #expect((result.hits.first?.snippet.utf16.count ?? Int.max) <= 208)
    }

    @Test func protocolRejectsUnboundedOrFalseReadableResults() throws {
        let input = DocumentInput(fileURL: URL(fileURLWithPath: "/unused"), expectedSHA256: String(repeating: "a", count: 64), expectedByteCount: 12)
        let unsupportedReadable = DocumentAnalysis(contentKind: .office, mimeType: "application/msword", status: .unsupported,
            sourceSHA256: input.expectedSHA256, sourceByteCount: 12,
            textPages: [DocumentTextPage(pageNumber: 1, text: "fabricated")])
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(unsupportedReadable, for: input) }
        let huge = pdf([DocumentTextPage(pageNumber: 1, text: String(repeating: "a", count: DocumentLimits.maximumTextBytes + 1))])
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(huge, for: input) }
        let duplicate = pdf([DocumentTextPage(pageNumber: 1, text: "first"), DocumentTextPage(pageNumber: 1, text: "second")])
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(duplicate, for: input) }
    }
}
