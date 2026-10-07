import CoreGraphics
import CoreText
import CryptoKit
import Darwin
import Foundation
import ImageIO
import Testing
@testable import ForensicsCore

/// The fixtures are generated locally from independent trusted primitives;
/// ImageIO/PDFKit inspection of recovered inputs remains helper-only in the app.
struct DocumentDecoderTests {
    private func helper() throws -> URL {
        // The Xcode SwiftPM build system runs tests from a system runner, so
        // argv[0] need not point into the package's products directory.
        let bundled = Bundle(for: DocumentDecoderTestAnchor.self).bundleURL
            .deletingLastPathComponent().appendingPathComponent("NFDocumentDecoder")
        if Darwin.access(bundled.path, X_OK) == 0 { return bundled }
        let testExecutable = URL(fileURLWithPath: CommandLine.arguments[0])
        var directory = testExecutable.deletingLastPathComponent()
        // SwiftPM's XCTest bundle lives beside executable products.
        for _ in 0..<5 {
            let candidate = directory.appendingPathComponent("NFDocumentDecoder")
            if Darwin.access(candidate.path, X_OK) == 0 { return candidate }
            directory.deleteLastPathComponent()
        }
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        for configuration in ["debug", "release"] {
            let candidate = repo.appendingPathComponent(".build/\(configuration)/NFDocumentDecoder")
            if Darwin.access(candidate.path, X_OK) == 0 { return candidate }
        }
        throw DocumentAnalysisError.unavailable
    }

    private func inspect(_ data: Data, name: String = "input") async throws -> DocumentAnalysis {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("nf-document-decoder-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent(name)
        try data.write(to: url)
        let hash = digest(data)
        let analysis = try await DocumentAnalysisClient(helperURL: helper()).analyze(
            DocumentInput(fileURL: url, expectedSHA256: hash, expectedByteCount: Int64(data.count)))
        #expect(try digest(Data(contentsOf: url)) == hash)
        #expect(analysis.sourceSHA256 == hash)
        #expect(analysis.sourceByteCount == Int64(data.count))
        return analysis
    }

    @Test func independentPDFsDecodeTitleTextAndPageReferences() async throws {
        let first = try pdf(title: "Independent fixture A", pages: ["The diary of Jack.", "Second page findings."])
        let second = try pdf(title: "Independent fixture B", pages: ["A separate forensic exercise."])
        #expect(digest(first) != digest(second))
        let a = try await inspect(first, name: "misleading.jpg")
        let b = try await inspect(second, name: "separate.pdf")
        #expect(a.contentKind == .pdf && a.status == .decoded)
        #expect(a.pageCount == 2 && a.textPages.count == 2)
        #expect(a.title == "Independent fixture A")
        #expect(a.thumbnailPNG != nil)
        #expect(DocumentContentSearch.search("diary of Jack", in: a).hits.first?.pageNumber == 1)
        #expect(DocumentContentSearch.search("Second page", in: a).hits.first?.pageNumber == 2)
        #expect(b.title == "Independent fixture B")
        #expect(DocumentContentSearch.search("diary of Jack", in: b).hits.isEmpty)
        #expect(DocumentContentSearch.search("separate forensic", in: b).hits.first?.pageNumber == 1)
    }

    @Test func jpegPNGAndExifUseContentAndRetainUnzonedOriginal() async throws {
        let png = try image(type: "public.png", metadata: [:])
        let jpeg = try image(type: "public.jpeg", metadata: [
            kCGImagePropertyExifDictionary: [kCGImagePropertyExifDateTimeOriginal: "2001:01:06 11:12:30"],
            kCGImagePropertyTIFFDictionary: [kCGImagePropertyTIFFMake: "Synthetic Camera", kCGImagePropertyTIFFModel: "Fixture"]
        ])
        let p = try await inspect(png, name: "fake.pdf")
        let j = try await inspect(jpeg, name: "photo.bin")
        #expect(p.contentKind == .image && p.mimeType == "image/png" && p.status == .decoded)
        #expect(j.contentKind == .image && j.mimeType == "image/jpeg" && j.status == .decoded)
        #expect(p.pixelWidth == 8 && p.pixelHeight == 4)
        #expect(j.pixelWidth == 8 && j.pixelHeight == 4)
        #expect(j.rawMetadata.contains(where: { $0.value == "2001:01:06 11:12:30" }))
        #expect(!j.rawMetadata.contains(where: { $0.name.contains("OffsetTime") }))
        #expect(j.thumbnailPNG != nil && p.thumbnailPNG != nil)
        #expect(!j.textIsComplete)
    }

    @Test func TIFFAndGIFDecodeOnlyBoundedFirstImage() async throws {
        for type in ["public.tiff", "com.compuserve.gif"] {
            let analysis = try await inspect(image(type: type, metadata: [:]))
            #expect(analysis.status == .decoded && analysis.contentKind == .image)
            #expect(analysis.pixelWidth == 8 && analysis.pixelHeight == 4)
            #expect(analysis.thumbnailPNG?.count ?? 0 <= DocumentLimits.maximumThumbnailBytes)
        }
    }

    @Test func textSearchAndUnsupportedContainersAreExplicit() async throws {
        let text = try await inspect(Data("Local 😀 text\nThe diary of Jack".utf8))
        #expect(text.status == .decoded && text.contentKind == .text)
        #expect(DocumentContentSearch.search("diary", in: text).hits.count == 1)
        let ole = Data([0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]) + Data(repeating: 0, count: 504)
        let office = try await inspect(ole, name: "legacy.doc")
        #expect(office.contentKind == .office && office.status != .decoded)
        #expect(office.textPages.isEmpty && office.thumbnailPNG == nil)
        #expect(!office.textIsComplete)
        let binary = try await inspect(Data([0, 1, 2, 0xff]))
        #expect(binary.status == .unsupported)
        #expect(binary.textPages.isEmpty)
    }

    @Test func malformedSupportedFilesFailWithoutReadableContent() async throws {
        for bytes in [Data("%PDF-1.7\nnot a PDF body".utf8), Data([0xff,0xd8,0xff,0xe0,0,16,0,0])] {
            let analysis = try await inspect(bytes)
            #expect(analysis.status == .failed)
            #expect(analysis.failureCode != nil)
            #expect(analysis.thumbnailPNG == nil && analysis.textPages.isEmpty)
        }
    }

    @Test func textAndPDFPageBudgetsReportIncompleteSearchCoverage() async throws {
        let bytes = Data((String(repeating: "A", count: DocumentLimits.maximumTextBytes) + " tail-needle").utf8)
        let text = try await inspect(bytes)
        #expect(text.status == .decoded)
        #expect(text.textPages.first?.text.utf8.count == DocumentLimits.maximumTextBytes)
        #expect(text.textPages.first?.isTruncated == true)
        let missed = DocumentContentSearch.search("tail-needle", in: text)
        #expect(missed.hits.isEmpty && !missed.searchedTextIsComplete)
        let manyPages = try await inspect(pdf(title: "Page budget fixture", pages: (1...201).map { "Page \($0) fixture" }))
        #expect(manyPages.status == .decoded && manyPages.pageCount == 201)
        #expect(manyPages.textPages.count == DocumentLimits.maximumPages)
        #expect(!manyPages.textIsComplete)
        #expect(manyPages.warnings.contains(where: { $0.contains("200") }))
    }

    @Test func mediaContainerRecognitionDoesNotClaimPlaybackOrSearch() async throws {
        var asf = Data([0x30,0x26,0xb2,0x75,0x8e,0x66,0xcf,0x11,0xa6,0xd9,0x00,0xaa,0x00,0x62,0xce,0x6c])
        asf.append(contentsOf: [30,0,0,0,0,0,0,0,0,0,0,0,1,2])
        let a = try await inspect(asf)
        #expect(a.contentKind == .video && a.status == .unsupported)
        #expect(a.mimeType == "video/x-ms-asf")
        let quicktime = Data([0,0,0,8]) + Data("moov".utf8)
        let q = try await inspect(quicktime)
        #expect(q.contentKind == .video && q.status == .unsupported)
        #expect(q.mimeType == "video/quicktime")
        #expect(!a.textIsComplete && !q.textIsComplete)
        #expect(a.thumbnailPNG == nil && q.textPages.isEmpty)
    }

    private func pdf(title: String, pages: [String]) throws -> Data {
        let output = NSMutableData()
        var box = CGRect(x: 0, y: 0, width: 320, height: 240)
        guard let consumer = CGDataConsumer(data: output),
              let context = CGContext(consumer: consumer, mediaBox: &box,
                [kCGPDFContextTitle: title, kCGPDFContextCreator: "Synthetic regression fixture"] as CFDictionary) else {
            throw DocumentAnalysisError.launchFailed
        }
        for text in pages {
            context.beginPDFPage(nil)
            context.textPosition = CGPoint(x: 20, y: 180)
            let attributes = [NSAttributedString.Key(kCTFontAttributeName as String): CTFontCreateWithName("Helvetica" as CFString, 12, nil)]
            let line = CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: attributes))
            CTLineDraw(line, context)
            context.endPDFPage()
        }
        context.closePDF()
        return output as Data
    }

    private func image(type: String, metadata: [CFString: Any]) throws -> Data {
        guard let context = CGContext(data: nil, width: 8, height: 4, bitsPerComponent: 8, bytesPerRow: 32,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { throw DocumentAnalysisError.launchFailed }
        context.setFillColor(CGColor(red: 0.8, green: 0.2, blue: 0.1, alpha: 1)); context.fill(CGRect(x: 0, y: 0, width: 8, height: 4))
        guard let image = context.makeImage() else { throw DocumentAnalysisError.launchFailed }
        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(output, type as CFString, 1, nil) else { throw DocumentAnalysisError.launchFailed }
        CGImageDestinationAddImage(destination, image, metadata as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { throw DocumentAnalysisError.launchFailed }
        return output as Data
    }

    private func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}

private final class DocumentDecoderTestAnchor: NSObject {}
