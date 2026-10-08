import Foundation
import Testing
@testable import ForensicsCore

struct MultiEvidencePDFUnitTests {
    @Test("PDF coordinates preserve Thai, emoji and untouched combining scalars")
    func scalarUTF16Slices() throws {
        let text = "A😀กe\u{301}Z"
        #expect(try MultiEvidencePDFText.slice(text, range: .init(start: 1, end: 3)) == "😀")
        #expect(try MultiEvidencePDFText.slice(text, range: .init(start: 3, end: 4)) == "ก")
        #expect(try MultiEvidencePDFText.slice(text, range: .init(start: 4, end: 5)) == "e")
        #expect(try MultiEvidencePDFText.slice(text, range: .init(start: 5, end: 6)) == "\u{301}")
        let combining = try MultiEvidencePDFText.slice(text, range: .init(start: 4, end: 6))
        #expect(Data(combining.utf8) == Data([0x65, 0xcc, 0x81]))
        #expect(throws: MultiEvidenceError.invalidRange) { try MultiEvidencePDFText.slice(text, range: .init(start: 1, end: 2)) }
        #expect(throws: MultiEvidenceError.invalidRange) { try MultiEvidencePDFText.slice(text, range: .init(start: 2, end: 3)) }
        for range in [MultiEvidenceRange(start: -1, end: 1), .init(start: 0, end: Int.max),
                      .init(start: Int.min, end: Int.max), .init(start: 1, end: 1)] {
            #expect(throws: MultiEvidenceError.invalidRange) { try MultiEvidencePDFText.slice(text, range: range) }
        }
    }

    @Test("Citation byte offsets map to raw page UTF-16 without replacement or normalization")
    func utf8ToUTF16Offsets() throws {
        let text = "A😀กe\u{301}Z"
        for (bytes, units) in [(0, 0), (1, 1), (5, 3), (8, 4), (9, 5), (11, 6), (12, 7)] {
            #expect(try MultiEvidencePDFText.utf16Offset(in: text, utf8Offset: bytes) == units)
        }
        for bytes in [-1, 2, 3, 4, 6, 7, 10, 13, Int.max] {
            #expect(throws: MultiEvidenceError.invalidRange) {
                try MultiEvidencePDFText.utf16Offset(in: text, utf8Offset: bytes)
            }
        }
    }

    @Test("Redactions split page-local spans and never merge pages")
    func redactionsRemainPageLocal() throws {
        let pages = [page(1, "A😀กB"), page(2, "second")]
        let selected = [MultiEvidencePDFRange(pageNumber: 1, start: 0, end: 5),
                        .init(pageNumber: 2, start: 0, end: 6)]
        let redacted = [MultiEvidencePDFRange(pageNumber: 1, start: 1, end: 3),
                        .init(pageNumber: 2, start: 0, end: 2)]
        let visible = try MultiEvidencePDFText.visibleRanges(selected: selected, redacted: redacted, pages: pages)
        #expect(visible == [.init(pageNumber: 1, start: 0, end: 1), .init(pageNumber: 1, start: 3, end: 5),
                            .init(pageNumber: 2, start: 2, end: 6)])
        let text = try visible.map { span in
            try MultiEvidencePDFText.slice(pages[span.pageNumber - 1].text, range: span.range)
        }
        #expect(text == ["A", "กB", "cond"])
        #expect(throws: MultiEvidenceError.invalidRange) {
            try MultiEvidencePDFText.visibleRanges(selected: selected,
                redacted: [.init(pageNumber: 1, start: 1, end: 2)], pages: pages)
        }
    }

    @Test("PDF selections reject missing pages, overlaps and unordered ranges")
    func rangeMetadataValidation() throws {
        let receipts = [page(1, "abcdef"), page(2, "abcdef")].map(MultiEvidencePDFText.receipt)
        try MultiEvidencePDFText.validateRanges([.init(pageNumber: 1, start: 0, end: 2),
                                                .init(pageNumber: 1, start: 2, end: 4),
                                                .init(pageNumber: 2, start: 0, end: 6)], pageReceipts: receipts)
        let invalid: [[MultiEvidencePDFRange]] = [
            [.init(pageNumber: 3, start: 0, end: 1)],
            [.init(pageNumber: 1, start: 0, end: 7)],
            [.init(pageNumber: 1, start: 0, end: 3), .init(pageNumber: 1, start: 2, end: 4)],
            [.init(pageNumber: 2, start: 0, end: 1), .init(pageNumber: 1, start: 0, end: 1)],
            [.init(pageNumber: 1, start: Int.min, end: Int.max)]
        ]
        for ranges in invalid {
            #expect(throws: MultiEvidenceError.invalidRange) { try MultiEvidencePDFText.validateRanges(ranges, pageReceipts: receipts) }
        }
        let tooMany = (0..<33).map { MultiEvidencePDFRange(pageNumber: 1, start: $0, end: $0 + 1) }
        #expect(throws: MultiEvidenceError.budgetExceeded) { try MultiEvidencePDFText.validateRanges(tooMany, pageReceipts: receipts) }
    }

    @Test("Default selection measures 16 KiB of UTF-8 across Thai and emoji page boundaries")
    func measuredDefaultSelectionBudget() throws {
        let pages = [page(1, String(repeating: "😀", count: 3_000)),
                     page(2, String(repeating: "ก", count: 3_000)), page(3, String(repeating: "z", count: 100))]
        let (binding, preview) = try fixture(pages: pages)
        let pdf = try MultiEvidenceVerifiedPDF(binding: binding, preview: preview)
        let ranges = MultiEvidencePDFText.defaultSelection(pdf)
        let texts = try ranges.map { try MultiEvidencePDFText.slice(pages[$0.pageNumber - 1].text, range: $0.range) }
        let disclosed = texts.reduce(0) { $0 + $1.utf8.count }
        #expect(disclosed == 16_384)
        #expect(disclosed <= MultiEvidencePDFLimits.maximumPDFExcerptBytes)
        #expect(ranges == [.init(pageNumber: 1, start: 0, end: 6_000),
                           .init(pageNumber: 2, start: 0, end: 1_461), .init(pageNumber: 3, start: 0, end: 1)])
        #expect(texts[0].utf8.count == 12_000 && texts[1].utf8.count == 4_383 && texts[2].utf8.count == 1)
    }

    @Test("Default selection limits selected pages independently from its byte cap")
    func defaultSelectionPageBudget() throws {
        let pages = (1...18).map { page($0, "A") }
        let (binding, preview) = try fixture(pages: pages)
        let ranges = MultiEvidencePDFText.defaultSelection(try MultiEvidenceVerifiedPDF(binding: binding, preview: preview))
        #expect(ranges.count == MultiEvidencePDFLimits.maximumSelectedPages)
        #expect(ranges.map(\.pageNumber) == Array(1...16))
        #expect(throws: MultiEvidenceError.budgetExceeded) {
            try MultiEvidencePDFText.validateRanges((1...17).map { .init(pageNumber: $0, start: 0, end: 1) },
                pageReceipts: pages.map(MultiEvidencePDFText.receipt))
        }
    }

    @Test("Verified PDF binds schema-2 derivation to exact extraction and supports 128 MiB sources")
    func verifiedPDFSourceBinding() throws {
        let pages = [page(1, "derived text")]
        let (binding, preview) = try fixture(pages: pages, sourceBytes: DocumentLimits.maximumInputBytes)
        let pdf = try MultiEvidenceVerifiedPDF(binding: binding, preview: preview)
        #expect(pdf.analysis == preview.analysis)
        #expect(pdf.provenance.derivedTextSHA256 == (try CaseWorkCoding.digest(pages)))
        #expect(pdf.pageReceipts == pages.map(MultiEvidencePDFText.receipt))
        let badReceipt = VerifiedContentReceipt(evidenceID: UUID(), fileID: preview.file.id,
            byteCount: preview.receipt.byteCount, sha256: preview.receipt.sha256,
            verifiedAt: preview.receipt.verifiedAt, orderedContainerSHA256: preview.receipt.orderedContainerSHA256)
        #expect(throws: MultiEvidenceError.invalidContent) {
            try MultiEvidenceVerifiedPDF(binding: binding,
                preview: .init(file: preview.file, receipt: badReceipt, analysis: preview.analysis))
        }
        let (oversizedBinding, oversizedPreview) = try fixture(pages: pages, sourceBytes: DocumentLimits.maximumInputBytes + 1)
        #expect(throws: MultiEvidenceError.invalidContent) { try MultiEvidenceVerifiedPDF(binding: oversizedBinding, preview: oversizedPreview) }
    }

    @Test("Unprovenanced historical results and fixture isolation cannot become PDF comparison evidence")
    func provenanceIsRequired() throws {
        let pages = [page(1, "derived text")]
        let (binding, preview) = try fixture(pages: pages)
        let historical = DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: preview.receipt.sha256, sourceByteCount: preview.receipt.byteCount, pageCount: 1, textPages: pages)
        #expect(throws: MultiEvidenceError.invalidContent) {
            try MultiEvidenceVerifiedPDF(binding: binding, preview: .init(file: preview.file, receipt: preview.receipt, analysis: historical))
        }
        let fixtureAnalysis = try historical.attachingProvenance(executableSHA256: String(repeating: "d", count: 64),
            codeSigningCDHash: nil, isolation: .testFixture, timeout: 12)
        #expect(throws: MultiEvidenceError.invalidContent) {
            try MultiEvidenceVerifiedPDF(binding: binding, preview: .init(file: preview.file, receipt: preview.receipt, analysis: fixtureAnalysis))
        }
    }

    @Test("PDF disclosure retains only receipts and exact selected/redacted locations")
    func boundedHistoricalDisclosure() throws {
        let pages = [page(1, "public private")]
        let (value, disclosed) = try disclosure(pages: pages,
            selected: [.init(pageNumber: 1, start: 0, end: 14)], redacted: [.init(pageNumber: 1, start: 7, end: 14)])
        try validatePDFDisclosure(value, disclosedByteCount: disclosed, requireText: true)
        try validatePDFDisclosure(value, disclosedByteCount: disclosed, requireText: false)
        #expect(value.omittedDerivedByteCount == 7)
        let data = try JSONEncoder().encode(value)
        #expect(!String(decoding: data, as: UTF8.self).contains("public private"))
        #expect(try JSONDecoder().decode(MultiEvidencePDFDisclosure.self, from: data) == value)
        let changed = MultiEvidencePDFDisclosure(provenance: value.provenance, pageCount: value.pageCount,
            pages: value.pages, selectedRanges: value.selectedRanges, redactedRanges: value.redactedRanges,
            rawDerivedByteCount: value.rawDerivedByteCount, omittedDerivedByteCount: 0, textIsComplete: value.textIsComplete)
        #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(changed, disclosedByteCount: disclosed, requireText: false) }
    }

    @Test("Historical receipts reject forged executable/options metadata and completeness")
    func disclosureProvenanceTampering() throws {
        let (value, count) = try disclosure(pages: [page(1, "content")], selected: [.init(pageNumber: 1, start: 0, end: 7)])
        for field in ["decoderVersion", "decoderExecutableSHA256", "optionsSHA256", "derivedTextSHA256", "isolation"] {
            let changed = try mutate(value) { root in
                var provenance = root["provenance"] as! [String: Any]
                provenance[field] = field == "isolation" ? "testFixture" : "invalid"
                root["provenance"] = provenance
            }
            #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(changed, disclosedByteCount: count, requireText: false) }
        }
        let changedOptions = try mutate(value) { root in
            var provenance = root["provenance"] as! [String: Any]
            var options = provenance["options"] as! [String: Any]
            options["includesOCR"] = true; provenance["options"] = options; root["provenance"] = provenance
        }
        #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(changedOptions, disclosedByteCount: count, requireText: true) }
        let falseComplete = try mutate(value) { $0["textIsComplete"] = false }
        #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(falseComplete, disclosedByteCount: count, requireText: false) }
    }

    @Test("Truncation and raw-text limits remain explicit historical coverage")
    func receiptCoverageAndBounds() throws {
        let (value, count) = try disclosure(pages: [page(1, "prefix", truncated: true)],
            selected: [.init(pageNumber: 1, start: 0, end: 6)], pageCount: 3)
        #expect(!value.textIsComplete && value.pages[0].isTruncated && value.pageCount == 3)
        try validatePDFDisclosure(value, disclosedByteCount: count, requireText: false)
        let badReceipts = [
            MultiEvidencePDFPageReceipt(pageNumber: 1, utf16Count: Int.max, byteCount: Int.max, rawTextSHA256: String(repeating: "a", count: 64), isTruncated: false),
            .init(pageNumber: 1, utf16Count: 0, byteCount: 1, rawTextSHA256: String(repeating: "a", count: 64), isTruncated: false),
            .init(pageNumber: 1, utf16Count: 1, byteCount: 1, rawTextSHA256: "bad", isTruncated: false)
        ]
        for receipt in badReceipts {
            #expect(throws: MultiEvidenceError.invalidContent) { try MultiEvidencePDFText.validateRanges([], pageReceipts: [receipt]) }
        }
        #expect(throws: MultiEvidenceError.invalidContent) {
            try MultiEvidencePDFText.validateRanges([], pageReceipts: [value.pages[0], value.pages[0]])
        }
    }

    @Test("Historical PDF receipts validate both parser and broker identities through the shared provenance contract")
    func brokerWorkerMetadataBinding() throws {
        let (value, count) = try disclosure(pages: [page(1, "content")], selected: [.init(pageNumber: 1, start: 0, end: 7)])
        let sandboxed = try mutate(value) { root in
            var provenance = root["provenance"] as! [String: Any]
            provenance["isolation"] = "appSandboxXPC"
            provenance["decoderCodeSigningCDHash"] = String(repeating: "c", count: 40)
            provenance["brokerExecutableSHA256"] = String(repeating: "b", count: 64)
            provenance["brokerCodeSigningCDHash"] = String(repeating: "a", count: 40)
            root["provenance"] = provenance
        }
        try validatePDFDisclosure(sandboxed, disclosedByteCount: count, requireText: false)
        for field in ["brokerExecutableSHA256", "brokerCodeSigningCDHash", "decoderCodeSigningCDHash"] {
            let missing = try mutate(sandboxed) { root in
                var provenance = root["provenance"] as! [String: Any]
                provenance.removeValue(forKey: field); root["provenance"] = provenance
            }
            #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(missing, disclosedByteCount: count, requireText: false) }
            let malformed = try mutate(sandboxed) { root in
                var provenance = root["provenance"] as! [String: Any]
                provenance[field] = "invalid"; root["provenance"] = provenance
            }
            #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(malformed, disclosedByteCount: count, requireText: false) }
        }
        let wrongMode = try mutate(sandboxed) { root in
            var provenance = root["provenance"] as! [String: Any]
            provenance["isolation"] = "requiredDevelopmentSeatbelt"; root["provenance"] = provenance
        }
        #expect(throws: MultiEvidenceError.invalidContent) { try validatePDFDisclosure(wrongMode, disclosedByteCount: count, requireText: false) }
    }

    private func page(_ number: Int, _ text: String, truncated: Bool = false) -> DocumentTextPage {
        .init(pageNumber: number, text: text, isTruncated: truncated, referenceLabel: "Page \(number)", referenceKind: .page)
    }

    private func fixture(pages: [DocumentTextPage], sourceBytes: Int64 = 24, pageCount: Int? = nil) throws
        -> (CaseWorkBinding, FilesystemDocumentPreview) {
        let sourcePath = "/synthetic-comparison-container.dd", containerHash = String(repeating: "a", count: 64)
        let evidence = EvidenceRecord(sourcePath: sourcePath, byteCount: 128, sha256: containerHash, container: .raw, filesystemHint: nil)
        let file = FilesystemEntry(id: "0:1", path: "/SYNTHETIC.PDF", name: "SYNTHETIC.PDF", fsOffsetBytes: 0,
            metaAddress: 1, size: sourceBytes, isDirectory: false, isDeleted: false)
        let result = EnumerationResult(engineVersion: "synthetic-pdf-comparison", patchDigest: "synthetic-only",
            sourcePaths: [sourcePath], sourceFileHashes: [sourcePath: containerHash], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 128, sectorSize: 512), volumes: [], files: [file], warnings: [], status: .partial)
        let binding = try CaseWorkBinding.make(caseID: UUID(), evidence: evidence, result: result, file: file)
        let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id, byteCount: sourceBytes,
            sha256: String(repeating: "b", count: 64), verifiedAt: Date(), orderedContainerSHA256: [containerHash])
        let historical = DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: receipt.sha256, sourceByteCount: receipt.byteCount,
            pageCount: pageCount ?? max(pages.map(\.pageNumber).max() ?? 1, 1), textPages: pages)
        let analysis = try historical.attachingProvenance(executableSHA256: String(repeating: "d", count: 64),
            codeSigningCDHash: nil, isolation: .requiredDevelopmentSeatbelt, timeout: 12)
        return (binding, .init(file: file, receipt: receipt, analysis: analysis))
    }

    private func disclosure(pages: [DocumentTextPage], selected: [MultiEvidencePDFRange],
                            redacted: [MultiEvidencePDFRange] = [], pageCount: Int? = nil) throws -> (MultiEvidencePDFDisclosure, Int) {
        let (binding, preview) = try fixture(pages: pages, pageCount: pageCount)
        let pdf = try MultiEvidenceVerifiedPDF(binding: binding, preview: preview)
        let visible = try MultiEvidencePDFText.visibleRanges(selected: selected, redacted: redacted, pages: pages)
        let byPage = Dictionary(uniqueKeysWithValues: pages.map { ($0.pageNumber, $0.text) })
        let disclosed = try visible.reduce(0) { total, span in
            total + (try MultiEvidencePDFText.slice(byPage[span.pageNumber]!, range: span.range)).utf8.count
        }
        let raw = pages.reduce(0) { $0 + $1.text.utf8.count }
        return (.init(provenance: pdf.provenance, pageCount: preview.analysis.pageCount!, pages: pdf.pageReceipts,
            selectedRanges: selected, redactedRanges: redacted, rawDerivedByteCount: raw,
            omittedDerivedByteCount: raw - disclosed, textIsComplete: preview.analysis.textIsComplete), disclosed)
    }

    private func mutate(_ value: MultiEvidencePDFDisclosure, change: (inout [String: Any]) -> Void) throws -> MultiEvidencePDFDisclosure {
        var root = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
        change(&root)
        return try JSONDecoder().decode(MultiEvidencePDFDisclosure.self, from: JSONSerialization.data(withJSONObject: root))
    }
}
