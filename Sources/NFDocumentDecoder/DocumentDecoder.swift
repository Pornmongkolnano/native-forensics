import CoreGraphics
import Foundation
import ForensicsCore
import ImageIO
import PDFKit

enum DocumentDecoder {
    static func decode(_ source: VerifiedDocument) -> DocumentAnalysis {
        let format = DetectedDocumentFormat.detect(source.data)
        if format == .unknown, source.data.starts(with: Data("%PDF-".utf8)) {
            return failed(source, kind: .pdf, mime: "application/pdf", code: "MALFORMED_PDF")
        }
        return switch format {
        case .jpeg: image(source, mimeType: "image/jpeg", expectedType: "public.jpeg")
        case .png: image(source, mimeType: "image/png", expectedType: "public.png")
        case .gif: image(source, mimeType: "image/gif", expectedType: "com.compuserve.gif")
        case .tiff: image(source, mimeType: "image/tiff", expectedType: "public.tiff")
        case .pdf: pdf(source)
        case .zip: zip(source)
        case .ole: legacyOffice(source)
        case .mp4: unsupported(source, kind: .video, mime: "video/mp4", warning: "ISO base-media container signature detected. Media content decoding is not supported; its brand may identify a non-video format.")
        case .asf: unsupported(source, kind: .video, mime: "video/x-ms-asf", warning: "ASF container header detected. Windows Media content decoding and playback are not supported.")
        case .quicktime: unsupported(source, kind: .video, mime: "video/quicktime", warning: "QuickTime atom structure detected. Media content decoding and playback are not supported.")
        case .riff: riff(source)
        case .mpeg: mpeg(source)
        case .unknown: textOrUnknown(source)
        }
    }

    private static func image(_ source: VerifiedDocument, mimeType: String, expectedType: String) -> DocumentAnalysis {
        guard let imageSource = CGImageSourceCreateWithData(source.data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              let type = CGImageSourceGetType(imageSource), type as String == expectedType,
              CGImageSourceGetCount(imageSource) > 0,
              CGImageSourceGetStatus(imageSource) == .statusComplete,
              CGImageSourceGetStatusAtIndex(imageSource, 0) == .statusComplete,
              let properties = CGImageSourceCopyPropertiesAtIndex(imageSource, 0, nil) as? [String: Any],
              let widthValue = properties[kCGImagePropertyPixelWidth as String] as? NSNumber,
              let heightValue = properties[kCGImagePropertyPixelHeight as String] as? NSNumber else {
            return failed(source, kind: .image, mime: mimeType, code: "MALFORMED_IMAGE")
        }
        let width = widthValue.int64Value
        let height = heightValue.int64Value
        guard width > 0, height > 0, width <= DocumentLimits.maximumImagePixels,
              height <= DocumentLimits.maximumImagePixels,
              width * height <= DocumentLimits.maximumImagePixels else {
            return failed(source, kind: .image, mime: mimeType, code: "IMAGE_PIXEL_LIMIT")
        }
        var thumbnail: Data?
        for size in [512, 256, 128] {
            let options: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: size,
                kCGImageSourceShouldCache: false
            ]
            guard let image = CGImageSourceCreateThumbnailAtIndex(imageSource, 0, options as CFDictionary) else {
                return failed(source, kind: .image, mime: mimeType, code: "MALFORMED_IMAGE")
            }
            if let encoded = encodePNG(image), encoded.count <= DocumentLimits.maximumThumbnailBytes {
                thumbnail = encoded
                break
            }
        }
        var warnings: [String] = []
        if CGImageSourceGetCount(imageSource) > 1 { warnings.append("Only image frame 1 was decoded and previewed.") }
        if thumbnail == nil { warnings.append("Thumbnail exceeded the bounded preview size.") }
        let metadata = boundedMetadata(properties)
        if metadata.truncated { warnings.append("Raw image metadata was truncated to the inspection limits.") }
        if metadata.items.contains(where: { $0.name.contains("DateTime") }) {
            warnings.append("Raw image dates are file-supplied values. Dates without an explicit offset have no assumed time zone.")
        }
        return DocumentAnalysis(contentKind: .image, mimeType: mimeType, status: .decoded,
                                sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                pixelWidth: Int(width), pixelHeight: Int(height), thumbnailPNG: thumbnail,
                                rawMetadata: metadata.items, warnings: warnings)
    }

    private static func pdf(_ source: VerifiedDocument) -> DocumentAnalysis {
        guard let document = PDFDocument(data: source.data) else {
            return failed(source, kind: .pdf, mime: "application/pdf", code: "MALFORMED_PDF")
        }
        guard !document.isLocked else { return failed(source, kind: .pdf, mime: "application/pdf", code: "LOCKED_PDF") }
        guard document.pageCount > 0 else { return failed(source, kind: .pdf, mime: "application/pdf", code: "MALFORMED_PDF") }
        let pageCount = document.pageCount
        var pages: [DocumentTextPage] = []
        var remaining = DocumentLimits.maximumTextBytes
        var warnings: [String] = []
        for index in 0..<min(pageCount, DocumentLimits.maximumPages) {
            guard let page = document.page(at: index) else {
                return failed(source, kind: .pdf, mime: "application/pdf", code: "MALFORMED_PDF")
            }
            let raw = page.string ?? ""
            let text = limitedUTF8(raw, maximumBytes: remaining)
            pages.append(DocumentTextPage(pageNumber: index + 1, text: text.value, isTruncated: text.truncated,
                                          referenceLabel: "Page \(index + 1)", referenceKind: .page))
            remaining -= text.value.utf8.count
            if text.truncated || remaining == 0 {
                warnings.append("PDF extracted text reached the 1 MiB inspection limit.")
                break
            }
        }
        if pageCount > DocumentLimits.maximumPages { warnings.append("Only the first 200 PDF pages were inspected.") }
        if pages.count < min(pageCount, DocumentLimits.maximumPages), !warnings.contains(where: { $0.contains("1 MiB") }) {
            warnings.append("Not all PDF pages were inspected.")
        }
        if !pages.contains(where: { !$0.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) {
            warnings.append("No extractable PDF text was found. Optical character recognition is not included.")
        }
        let metadata = pdfMetadata(document)
        let thumbnail = pdfThumbnail(source.data)
        if thumbnail == nil { warnings.append("The first PDF page could not produce a bounded thumbnail.") }
        return DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
                                sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                title: metadata.first(where: { $0.name == "PDF.Title" })?.value,
                                pageCount: pageCount, textPages: pages, thumbnailPNG: thumbnail,
                                rawMetadata: metadata, warnings: warnings)
    }

    private static func pdfThumbnail(_ data: Data) -> Data? {
        guard let provider = CGDataProvider(data: data as CFData), let document = CGPDFDocument(provider),
              !document.isEncrypted || document.isUnlocked,
              let page = document.page(at: 1) else { return nil }
        let box = page.getBoxRect(.cropBox)
        guard box.width.isFinite, box.height.isFinite, box.width > 0, box.height > 0,
              box.width < 10_000_000, box.height < 10_000_000 else { return nil }
        for maximumSize in [512.0, 256.0, 128.0] {
            let scale = min(maximumSize / box.width, maximumSize / box.height)
            let width = max(1, Int(ceil(box.width * scale)))
            let height = max(1, Int(ceil(box.height * scale)))
            guard let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8,
                                          bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
                                          bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
            context.setFillColor(CGColor(gray: 1, alpha: 1))
            context.fill(CGRect(x: 0, y: 0, width: width, height: height))
            context.concatenate(page.getDrawingTransform(.cropBox, rect: CGRect(x: 0, y: 0, width: width, height: height), rotate: 0, preserveAspectRatio: true))
            context.drawPDFPage(page)
            if let image = context.makeImage(), let encoded = encodePNG(image), encoded.count <= DocumentLimits.maximumThumbnailBytes { return encoded }
        }
        return nil
    }

    private static func pdfMetadata(_ document: PDFDocument) -> [DocumentRawMetadata] {
        let attributes = document.documentAttributes ?? [:]
        let keys: [(PDFDocumentAttribute, String)] = [(.titleAttribute, "Title"), (.authorAttribute, "Author"),
                                                     (.subjectAttribute, "Subject"), (.creatorAttribute, "Creator"),
                                                     (.producerAttribute, "Producer"), (.keywordsAttribute, "Keywords")]
        return keys.compactMap { key, name in
            guard let value = attributes[key] else { return nil }
            let raw = (value as? String) ?? (value as? [String])?.joined(separator: ", ")
            guard let raw else { return nil }
            return DocumentRawMetadata(name: "PDF." + name, value: limitedUTF8(raw, maximumBytes: DocumentLimits.maximumMetadataValueBytes).value)
        }
    }

    private static func boundedMetadata(_ properties: [String: Any]) -> (items: [DocumentRawMetadata], truncated: Bool) {
        var items: [DocumentRawMetadata] = []
        var names = Set<String>()
        var totalBytes = 0
        var truncated = false
        func visit(_ dictionary: [String: Any], prefix: String, depth: Int) {
            guard depth <= 4 else { truncated = true; return }
            for key in dictionary.keys.sorted() {
                guard items.count < DocumentLimits.maximumMetadataItems, totalBytes < 64 * 1_024 else { truncated = true; return }
                guard let value = dictionary[key] else { continue }
                let normalized = key.trimmingCharacters(in: CharacterSet(charactersIn: "{}"))
                let name = limitedUTF8(prefix.isEmpty ? normalized : prefix + "." + normalized, maximumBytes: 128).value
                if let nested = value as? [String: Any] { visit(nested, prefix: name, depth: depth + 1); continue }
                let raw: String
                if let string = value as? String { raw = string }
                else if let number = value as? NSNumber { raw = number.stringValue }
                else if let array = value as? [NSNumber] { raw = array.prefix(32).map(\.stringValue).joined(separator: ", "); if array.count > 32 { truncated = true } }
                else if let array = value as? [String] { raw = array.prefix(32).joined(separator: ", "); if array.count > 32 { truncated = true } }
                else { continue }
                guard names.insert(name).inserted else { truncated = true; continue }
                let limited = limitedUTF8(raw, maximumBytes: min(DocumentLimits.maximumMetadataValueBytes, 64 * 1_024 - totalBytes))
                truncated = truncated || limited.truncated
                totalBytes += limited.value.utf8.count
                items.append(DocumentRawMetadata(name: name, value: limited.value))
            }
        }
        visit(properties, prefix: "", depth: 0)
        return (items, truncated)
    }

    private static func riff(_ source: VerifiedDocument) -> DocumentAnalysis {
        let kind: DocumentContentKind
        let mime: String
        let identifier = String(data: source.data.subdata(in: 8..<12), encoding: .ascii)
        switch identifier {
        case "WAVE": kind = .audio; mime = "audio/wav"
        case "AVI ": kind = .video; mime = "video/x-msvideo"
        case "WEBP": kind = .image; mime = "image/webp"
        default: kind = .unknown; mime = "application/octet-stream"
        }
        return unsupported(source, kind: kind, mime: mime, warning: "RIFF container signature detected. Its contents have not been decoded or validated.")
    }

    private static func zip(_ source: VerifiedDocument) -> DocumentAnalysis {
        let archive: BoundedZIPArchive
        do { archive = try BoundedZIPReader.read(source.data) }
        catch ZIPReaderError.limitExceeded { return failed(source, kind: .archive, mime: "application/zip", code: "ZIP_INSPECTION_LIMIT") }
        catch ZIPReaderError.unsupported {
            return DocumentAnalysis(contentKind: .archive, mimeType: "application/zip", status: .unsupported,
                                    sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                    structuralValidation: .signatureOnly,
                                    warnings: ["This ZIP container uses unsupported encryption, compression, splitting, or ZIP64 features. Its structure and contents were not fully validated."])
        }
        catch { return failed(source, kind: .archive, mime: "application/zip", code: "MALFORMED_ZIP") }
        do {
            if let office = try OfficeOpenXMLReader.read(archive) {
                guard office.contentUnitCount > 0 else {
                    return DocumentAnalysis(contentKind: .office, mimeType: office.mimeType, status: .unsupported,
                                            sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                            title: office.title, officeFormat: office.format, structuralValidation: .validated,
                                            rawMetadata: office.rawMetadata,
                                            warnings: office.warnings + ["The Office package contains no document text units to inspect."])
                }
                return DocumentAnalysis(contentKind: .office, mimeType: office.mimeType, status: .decoded,
                                        sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                        title: office.title, officeFormat: office.format,
                                        contentUnitCount: office.contentUnitCount, structuralValidation: .validated,
                                        textPages: office.units, rawMetadata: office.rawMetadata,
                                        warnings: office.warnings)
            }
            return archiveText(source, archive: archive)
        } catch OOXMLReaderError.unsupported {
            return DocumentAnalysis(contentKind: .office, mimeType: "application/zip", status: .unsupported,
                                    sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                    structuralValidation: .validated,
                                    warnings: ["ZIP structure and CRC values were validated. This Office package uses document encodings or content features that this decoder does not support; no document text was decoded."])
        } catch OOXMLReaderError.limitExceeded {
            return failed(source, kind: .office, mime: "application/zip", code: "OFFICE_INSPECTION_LIMIT")
        } catch {
            return failed(source, kind: .office, mime: "application/zip", code: "MALFORMED_OFFICE_PACKAGE")
        }
    }

    private static func archiveText(_ source: VerifiedDocument, archive: BoundedZIPArchive) -> DocumentAnalysis {
        let members = archive.entries.filter { !$0.name.hasSuffix("/") }
        let suffixes: Set<String> = ["txt", "csv", "log", "json", "xml"]
        var pages: [DocumentTextPage] = []
        var remaining = DocumentLimits.maximumTextBytes
        var eligibleCount = 0
        var clippedLabels = false
        var inferredEncoding = false
        var memberEncodings: [DocumentRawMetadata] = []
        for (index, member) in members.enumerated() {
            guard let dot = member.name.lastIndex(of: "."),
                  suffixes.contains(member.name[member.name.index(after: dot)...].lowercased()),
                  !member.isDataOmitted, !member.data.isEmpty || member.originalByteCount == 0 else { continue }
            // XML parts may be retained for Office parsing up to 16 MiB. Archive
            // presentation still decodes only a bounded prefix after text fills.
            guard remaining > 0, pages.count < DocumentLimits.maximumArchiveMembers else { eligibleCount += 1; continue }
            let prefixCount = min(member.data.count, remaining + 4)
            let prefixTruncated = member.isDataTruncated || prefixCount < member.data.count
            guard let decoded = BoundedTextDecoder.decode(Data(member.data.prefix(prefixCount)), allowLegacyEncoding: true,
                                                           prefixMayBeTruncated: prefixTruncated) else { continue }
            eligibleCount += 1
            let text = limitedUTF8(decoded.value, maximumBytes: remaining)
            let label = limitedUTF8(member.name, maximumBytes: 4_096)
            clippedLabels = clippedLabels || label.truncated
            inferredEncoding = inferredEncoding || decoded.encodingWasInferred
            if decoded.encodingWasInferred, memberEncodings.count < DocumentLimits.maximumMetadataItems - 3 {
                memberEncodings.append(DocumentRawMetadata(name: "ZIP.MemberEncoding.\(index + 1)", value: decoded.encoding + " (inferred)"))
            }
            pages.append(DocumentTextPage(pageNumber: index + 1, text: text.value,
                                          isTruncated: text.truncated || prefixTruncated,
                                          referenceLabel: label.value, referenceKind: .archiveMember))
            remaining -= text.value.utf8.count
        }
        let skipped = members.count - pages.count
        var warnings = ["ZIP entry bounds, complete decompression and CRC values were validated. Preview shows bounded printable .txt, .csv, .log, .json and .xml member text without writing or recursively opening archive contents."]
        if skipped > 0 { warnings.append("\(skipped) regular archive members were not previewed; binary and unsupported member types remain outside text-search coverage.") }
        if eligibleCount > DocumentLimits.maximumArchiveMembers { warnings.append("Only the first 128 eligible text members were previewed.") }
        if pages.contains(where: \.isTruncated) { warnings.append("Archive text preview reached the 1 MiB inspection limit.") }
        if clippedLabels { warnings.append("Long archive-member reference labels were limited to 4 KiB UTF-8; source member indexes are retained.") }
        if inferredEncoding { warnings.append("Windows-1252 display encoding was inferred for some archive members. Original member bytes and the source ZIP hash remain unchanged.") }
        if pages.isEmpty { warnings.append("No supported printable text member was available within the preview limits.") }
        return DocumentAnalysis(contentKind: .archive, mimeType: "application/zip",
                                status: pages.isEmpty ? .unsupported : .decoded,
                                sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                contentUnitCount: members.isEmpty ? nil : members.count,
                                structuralValidation: .validated, textPages: pages,
                                rawMetadata: [DocumentRawMetadata(name: "ZIP.EntryCount", value: String(archive.entries.count)),
                                              DocumentRawMetadata(name: "ZIP.PreviewedMemberCount", value: String(pages.count)),
                                              DocumentRawMetadata(name: "ZIP.SkippedMemberCount", value: String(skipped))] + memberEncodings,
                                warnings: warnings)
    }

    private static func legacyOffice(_ source: VerifiedDocument) -> DocumentAnalysis {
        let recognition = LegacyOfficeRecognizer.inspect(source.data)
        return DocumentAnalysis(contentKind: .office, mimeType: recognition.mimeType,
                                status: recognition.isStructurallyValid ? .unsupported : .failed,
                                sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                officeFormat: recognition.format,
                                structuralValidation: recognition.isStructurallyValid ? .validated : .signatureOnly,
                                warnings: recognition.warnings,
                                failureCode: recognition.isStructurallyValid ? nil : "MALFORMED_OLE_CONTAINER")
    }

    private static func mpeg(_ source: VerifiedDocument) -> DocumentAnalysis {
        let video = source.data.starts(with: Data([0x00, 0x00, 0x01, 0xBA]))
            || source.data.starts(with: Data([0x00, 0x00, 0x01, 0xB3]))
        return unsupported(source, kind: video ? .video : .audio, mime: video ? "video/mpeg" : "audio/mpeg",
                           warning: "MPEG or ID3 signature detected. Media content decoding is not supported.")
    }

    private static func textOrUnknown(_ source: VerifiedDocument) -> DocumentAnalysis {
        guard let decoded = BoundedTextDecoder.decode(source.data, allowLegacyEncoding: true) else {
            return unsupported(source, kind: .unknown, mime: "application/octet-stream", warning: "No supported readable document signature was detected. The filename extension was not used as proof of content type.")
        }
        let text = limitedUTF8(decoded.value, maximumBytes: DocumentLimits.maximumTextBytes)
        var warnings = text.truncated ? ["Text reached the 1 MiB inspection limit."] : []
        if decoded.encodingWasInferred { warnings.append("Windows-1252 display encoding was inferred. Original source bytes and hash remain unchanged.") }
        return DocumentAnalysis(contentKind: .text, mimeType: "text/plain; charset=" + decoded.encoding.lowercased(), status: .decoded,
                                sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount,
                                textPages: [DocumentTextPage(pageNumber: 1, text: text.value, isTruncated: text.truncated,
                                                             referenceLabel: "Text document", referenceKind: .document)],
                                rawMetadata: [DocumentRawMetadata(name: "Text.Encoding", value: decoded.encoding + (decoded.encodingWasInferred ? " (inferred)" : ""))],
                                warnings: warnings)
    }

    private static func unsupported(_ source: VerifiedDocument, kind: DocumentContentKind, mime: String, warning: String) -> DocumentAnalysis {
        DocumentAnalysis(contentKind: kind, mimeType: mime, status: .unsupported,
                         sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount, warnings: [warning])
    }

    private static func failed(_ source: VerifiedDocument, kind: DocumentContentKind, mime: String, code: String) -> DocumentAnalysis {
        DocumentAnalysis(contentKind: kind, mimeType: mime, status: .failed,
                         sourceSHA256: source.sha256, sourceByteCount: source.input.expectedByteCount, failureCode: code)
    }

    private static func encodePNG(_ image: CGImage) -> Data? {
        // Decode and color-convert file-supplied profiles only in this helper.
        // UI receives fresh DeviceRGB pixels without the original ICC/metadata.
        guard image.width > 0, image.height > 0, image.width <= 1_024, image.height <= 1_024,
              let context = CGContext(data: nil, width: image.width, height: image.height,
                                      bitsPerComponent: 8, bytesPerRow: image.width * 4,
                                      space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        guard let normalized = context.makeImage() else { return nil }
        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(output as CFMutableData, "public.png" as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, normalized, nil)
        return CGImageDestinationFinalize(destination) ? output as Data : nil
    }

    static func limitedUTF8(_ string: String, maximumBytes: Int) -> (value: String, truncated: Bool) {
        var count = 0
        var boundary = string.unicodeScalars.startIndex
        for scalar in string.unicodeScalars {
            let bytes = scalar.utf8.count
            guard count + bytes <= maximumBytes else { return (String(string[..<boundary]), true) }
            count += bytes
            boundary = string.unicodeScalars.index(after: boundary)
        }
        return (string, false)
    }
}
