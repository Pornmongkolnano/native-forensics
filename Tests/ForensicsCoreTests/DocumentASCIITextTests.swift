import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NFDocumentDecoding

struct DocumentASCIITextTests {
    private let limit = DocumentLimits.maximumTextBytes
    private let bom = Data([0xef, 0xbb, 0xbf])
    private let limitWarning = "Text reached the 1 MiB inspection limit."
    private let inferredWarning = "Windows-1252 display encoding was inferred. Original source bytes and hash remain unchanged."

    private func decode(_ bytes: Data) throws -> DocumentAnalysis {
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let source = try VerifiedDocument(data: bytes, expectedSHA256: digest, expectedByteCount: Int64(bytes.count))
        let analysis = DocumentDecoder.decode(source)
        #expect(analysis.sourceSHA256 == digest)
        #expect(analysis.sourceByteCount == Int64(bytes.count))
        #expect(source.data == bytes)
        return analysis
    }

    private func expectText(_ analysis: DocumentAnalysis, value: String, truncated: Bool,
                            encoding: String = "UTF-8", inferred: Bool = false) {
        #expect(analysis.contentKind == .text && analysis.status == .decoded)
        #expect(analysis.mimeType == "text/plain; charset=" + encoding.lowercased())
        #expect(analysis.textPages == [DocumentTextPage(pageNumber: 1, text: value, isTruncated: truncated,
                                                      referenceLabel: "Text document", referenceKind: .document)])
        #expect(analysis.textPages.first?.text.utf8.elementsEqual(value.utf8) == true)
        #expect(analysis.rawMetadata == [DocumentRawMetadata(name: "Text.Encoding", value: encoding + (inferred ? " (inferred)" : ""))])
        #expect(analysis.warnings == (truncated ? [limitWarning] : []) + (inferred ? [inferredWarning] : []))
        #expect(analysis.textIsComplete == (!truncated && !value.isEmpty))
    }

    @Test func fastPathClassifiesTheWholeByteAlphabetEvenBeyondItsRetainedPrefix() throws {
        // A zero-byte output budget still has to classify the complete source.
        // Independent literal acceptance sets cover every possible final byte.
        let accepted = Set([9, 10, 13] + Array(32...126))
        for value in 0...255 {
            let bytes = Data("already outside the output budget".utf8) + Data([UInt8(value)])
            let result = BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: 0)
            if accepted.contains(value) {
                let result = try #require(result)
                #expect(result.value.isEmpty && result.truncated)
            } else {
                #expect(result == nil)
            }
        }
    }

    @Test(arguments: [(-1, false), (0, false), (1, true)])
    func asciiLengthBoundaryRetainsExactCoverage(extraBytes: Int, truncated: Bool) throws {
        let bytes = Data(repeating: 65, count: limit + extraBytes)
        let analysis = try decode(bytes)
        expectText(analysis, value: String(repeating: "A", count: min(bytes.count, limit)), truncated: truncated)
        #expect(DocumentContentSearch.search("tail-only-marker", in: analysis).searchedTextIsComplete == !truncated)
    }

    @Test func pinnedReleaseWorkloadPrefixKeepsItsOriginalDerivedTextDigest() throws {
        // Recipe and digest were recorded by the immutable pre-change release
        // runtime, independently of this new fast path's implementation.
        let marker = "NF_RUNTIME_ASCII_ORACLE_20261008\n"
        let chunk = Data(String(repeating: marker, count: limit / marker.utf8.count + 1).utf8).prefix(limit)
        let analysis = try decode(chunk + chunk)
        expectText(analysis, value: String(decoding: chunk, as: UTF8.self), truncated: true)
        #expect(try CaseWorkCoding.digest(analysis.textPages) == "4041c492c18318b210f80c8a22abec47ef9bf4bf17e2dc8236deffc899c2ca56")
    }

    @Test(arguments: [UInt8(0), UInt8(1), UInt8(0x7f), UInt8(0x81)])
    func disallowedFinalByteAfterTheDisplayCapRejectsTheWholeDocument(byte: UInt8) throws {
        let bytes = Data(repeating: 65, count: limit) + Data([byte])
        #expect(BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: limit) == nil)
        let analysis = try decode(bytes)
        #expect(analysis.status == .unsupported && analysis.contentKind == .unknown)
        #expect(analysis.textPages.isEmpty && analysis.rawMetadata.isEmpty && !analysis.textIsComplete)
    }

    @Test func invalidUTF8TailStillSelectsInferredLegacyEncoding() throws {
        let bytes = Data(repeating: 65, count: limit) + Data([0xff])
        #expect(BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: limit) == nil)
        expectText(try decode(bytes), value: String(repeating: "A", count: limit), truncated: true,
                   encoding: "Windows-1252", inferred: true)
    }

    @Test func legacyFallbackUsesTheOriginalBOMBytes() throws {
        let bytes = bom + Data(repeating: 65, count: limit) + Data([0xff])
        #expect(BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: limit) == nil)
        expectText(try decode(bytes), value: "ï»¿" + String(repeating: "A", count: limit - 6), truncated: true,
                   encoding: "Windows-1252", inferred: true)
    }

    @Test func nonASCIIFinalScalarOutsideTheCapKeepsUTF8Interpretation() throws {
        let bytes = Data(repeating: 65, count: limit) + Data("ก😀é".utf8)
        #expect(BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: limit) == nil)
        expectText(try decode(bytes), value: String(repeating: "A", count: limit), truncated: true)
    }

    @Test(arguments: ["é", "ก", "😀"])
    func unicodeFallbackStopsBeforeAnOverflowingScalarAndDoesNotResumeForASCII(scalar: String) throws {
        let prefix = String(repeating: "A", count: limit - scalar.utf8.count + 1)
        let bytes = Data((prefix + scalar + "Z").utf8)
        #expect(BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: limit) == nil)
        expectText(try decode(bytes), value: prefix, truncated: true)
    }

    @Test func combiningSequenceKeepsExistingScalarRatherThanGraphemeBoundary() throws {
        let prefix = String(repeating: "A", count: limit - 1)
        let bytes = Data((prefix + "\u{0301}Z").utf8)
        expectText(try decode(bytes), value: prefix, truncated: true)
        let exact = Data((String(repeating: "A", count: limit - 2) + "\u{0301}").utf8)
        expectText(try decode(exact), value: String(decoding: exact, as: UTF8.self), truncated: false)
    }

    @Test func rawNewlinesAndASCIIBOMHaveIdenticalDisplayedBytes() throws {
        let raw = "A\r\nB\rC\n\tZ"
        for bytes in [Data(raw.utf8), bom + Data(raw.utf8)] {
            expectText(try decode(bytes), value: raw, truncated: false)
        }
        let full = bom + Data(repeating: 65, count: limit)
        expectText(try decode(full), value: String(repeating: "A", count: limit), truncated: false)
        expectText(try decode(full + Data([65])), value: String(repeating: "A", count: limit), truncated: true)
    }

    @Test func emptyAndBOMOnlyKeepTheirOriginalEmptyCoverageMeaning() throws {
        for bytes in [Data(), bom] {
            expectText(try decode(bytes), value: "", truncated: false)
        }
    }

    @Test func dataSlicesWithNonzeroIndexesDoNotLoseTheBOMOrBody() throws {
        let raw = "A\r\nB\tC"
        let bytes = (Data("discard".utf8) + bom + Data(raw.utf8)).dropFirst(7)
        #expect(bytes.startIndex > 0)
        expectText(try decode(bytes), value: raw, truncated: false)
    }

    @Test func embeddedAndRepeatedBOMRemainOutsideTheASCIIFastPath() {
        for bytes in [Data("A".utf8) + bom, bom + bom + Data("A".utf8)] {
            #expect(BoundedTextDecoder.decodePrintableASCIIPrefix(bytes, maximumBytes: limit) == nil)
        }
    }
}
