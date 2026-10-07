import CryptoKit
import Darwin
import Foundation
import Testing
import zlib
@testable import ForensicsCore

struct DocumentOfficeTests {
    @Test func OOXMLDocumentsSearchByDocumentSlideAndSheet() async throws {
        let docx = try await inspect(office("docx"), name: "fake.jpg")
        #expect(docx.contentKind == .office && docx.officeFormat == .docx && docx.status == .decoded)
        #expect(docx.structuralValidation == .validated)
        #expect(docx.pageCount == nil && docx.contentUnitCount == 1)
        #expect(docx.title == "Synthetic case notes")
        let wordHit = DocumentContentSearch.search("diary of Jack", in: docx).hits.first
        #expect(wordHit?.referenceKind == .document)
        #expect(wordHit?.referenceLabel == "Document body")

        let pptx = try await inspect(office("pptx"))
        #expect(pptx.officeFormat == .pptx && pptx.status == .decoded)
        #expect(pptx.contentUnitCount == 2 && pptx.textPages.count == 2)
        let slide = DocumentContentSearch.search("Second slide finding", in: pptx).hits.first
        #expect(slide?.pageNumber == 2 && slide?.referenceKind == .slide)

        let xlsx = try await inspect(office("xlsx"))
        #expect(xlsx.officeFormat == .xlsx && xlsx.status == .decoded)
        let sheet = DocumentContentSearch.search("shared evidence", in: xlsx).hits.first
        #expect(sheet?.referenceKind == .sheet)
        #expect(sheet?.referenceLabel?.contains("Evidence") == true)
        #expect(xlsx.textPages.first?.text.contains("42") == true)
        #expect(xlsx.textPages.first?.text.contains("inline finding") == true)
    }

    @Test func XMLExternalEntitiesAndCRCChangesAreRejected() async throws {
        let dangerous = office("docx", maliciousXML: true)
        let entity = try await inspect(dangerous)
        #expect(entity.status == .failed)
        #expect(entity.textPages.isEmpty && entity.thumbnailPNG == nil)
        var corrupted = office("docx")
        // Mutate a stored member while retaining the central/local CRC receipt.
        let needle = Data("The diary of Jack".utf8)
        if let range = corrupted.range(of: needle) { corrupted[range.lowerBound] ^= 1 }
        let damaged = try await inspect(corrupted)
        #expect(damaged.status == .failed)
        #expect(damaged.structuralValidation != .validated)
        #expect(damaged.textPages.isEmpty)
    }

    @Test func DeflatedOfficeMembersUseBoundedCRCVerifiedDecompression() async throws {
        for format in ["docx", "pptx", "xlsx"] {
            let result = try await inspect(office(format, deflated: true))
            #expect(result.status == .decoded && result.officeFormat?.rawValue == format)
            #expect(result.structuralValidation == .validated)
            #expect(!result.textPages.isEmpty)
        }
    }

    @Test func ZIPTraversalDuplicateAndEncryptionAreNotReadableDocuments() async throws {
        for archive in [zip([("../word/document.xml", Data("unsafe".utf8))]),
                        zip([("word/document.xml", Data("one".utf8)), ("word/document.xml", Data("two".utf8))]),
                        zip([("word/document.xml", Data("encrypted".utf8))], flags: 0x0801)] {
            let result = try await inspect(archive)
            #expect(result.status != .decoded)
            #expect(result.structuralValidation != .validated)
            #expect(result.textPages.isEmpty)
        }
    }

    @Test func LegacyOfficeStreamNamesIdentifyFormatWithoutBodyClaims() async throws {
        for (name, format) in [("WordDocument", DocumentOfficeFormat.doc),
                               ("Workbook", .xls), ("PowerPoint Document", .ppt)] {
            let result = try await inspect(cfb(streamName: name), name: "camouflage.jpg")
            #expect(result.contentKind == .office && result.officeFormat == format)
            #expect(result.status == .unsupported && result.structuralValidation == .validated)
            #expect(result.textPages.isEmpty && result.thumbnailPNG == nil)
            #expect(!result.textIsComplete)
        }
        var malformed = cfb(streamName: "WordDocument")
        malformed[30] = 15 // Invalid sector shift.
        let rejected = try await inspect(malformed)
        #expect(rejected.status != .decoded)
        #expect(rejected.structuralValidation != .validated)
    }

    @Test func GenericZIPTextUsesRealMemberReferencesAndParentHashScope() async throws {
        let archive = zip([("notes/wword60.txt", Data("Local dictionary\nThe diary of Jack".utf8)),
                           ("opaque.bin", Data([0,0xff,1]))], deflated: true)
        let result = try await inspect(archive)
        #expect(result.contentKind == .archive && result.status == .decoded)
        #expect(result.structuralValidation == .validated && result.contentUnitCount == 2)
        #expect(result.textPages.count == 1)
        #expect(result.textPages.first?.referenceKind == .archiveMember)
        #expect(result.textPages.first?.referenceLabel == "notes/wword60.txt")
        #expect(!result.textIsComplete)
        let match = DocumentContentSearch.search("diary of Jack", in: result)
        #expect(match.hits.first?.referenceLabel == "notes/wword60.txt")
        #expect(!match.searchedTextIsComplete)
        #expect(result.sourceSHA256 == SHA256.hash(data: archive).map { String(format: "%02x", $0) }.joined())
        #expect(result.warnings.contains(where: { $0.localizedCaseInsensitiveContains("skip") || $0.localizedCaseInsensitiveContains("binary") }))
    }

    @Test func LegacyDictionaryEncodingIsAnExplicitDisplayInterpretation() async throws {
        let original = Data("Evidence ".utf8) + Data([0x92]) + Data("dictionary".utf8) + Data([0x94])
        let result = try await inspect(zip([("wword60.txt", original)], deflated: true))
        #expect(result.status == .decoded && result.contentKind == .archive)
        #expect(result.textPages.first?.text == "Evidence ’dictionary”")
        #expect(result.warnings.contains(where: { $0.contains("Windows-1252") && $0.localizedCaseInsensitiveContains("infer") }))
        #expect(result.textPages.first?.referenceLabel == "wword60.txt")
        let direct = try await inspect(original, name: "word-list.txt")
        #expect(direct.status == .decoded && direct.contentKind == .text)
        #expect(direct.textPages.first?.text == "Evidence ’dictionary”")
        #expect(direct.rawMetadata.contains(where: { $0.name == "Text.Encoding" && $0.value.contains("Windows-1252") }))
        let bom = try await inspect(Data([0xef,0xbb,0xbf]) + Data("BOM fixture".utf8), name: "bom.txt")
        #expect(bom.textPages.first?.text == "BOM fixture")
        #expect(bom.rawMetadata.contains(where: { $0.name == "Text.Encoding" && $0.value == "UTF-8" }))
    }

    @Test func LargeBinaryArchiveMembersAreCRCVerifiedWithoutBeingPreviewed() async throws {
        let large = Data(repeating: 7, count: 10 * 1_024 * 1_024)
        let archive = zip([("large.bin", large), ("notes.txt", Data("Bounded notes".utf8))])
        let result = try await inspect(archive)
        #expect(result.status == .decoded && result.textPages.count == 1)
        #expect(result.textPages.first?.pageNumber == 2)
        #expect(result.textPages.first?.referenceLabel == "notes.txt")
        #expect(!result.textIsComplete)
        var damaged = archive
        damaged[39] ^= 1 // Stored first payload; its unchanged CRC must fail.
        let rejected = try await inspect(damaged)
        #expect(rejected.status == .failed && rejected.failureCode == "MALFORMED_ZIP")
    }

    @Test func OpaqueOfficeDrawingAttributeIsNotTreatedAsBodyText() async throws {
        let drawing = String(repeating: "A", count: 20_000)
        let xml = "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:v=\"urn:schemas-microsoft-com:vml\" xmlns:o=\"urn:schemas-microsoft-com:office:office\"><w:body><w:p><w:r><w:t>Independent readable body</w:t></w:r></w:p><v:group o:gfxdata=\"\(drawing)\"/></w:body></w:document>"
        let result = try await inspect(office("docx", documentXML: xml))
        #expect(result.status == .decoded && result.officeFormat == .docx)
        #expect(result.textPages.first?.text == "Independent readable body")
        #expect(result.textPages.first?.text.contains(drawing) == false)
    }

    private func inspect(_ bytes: Data, name: String = "candidate") async throws -> DocumentAnalysis {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("nf-office-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent(name)
        try bytes.write(to: url)
        let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let helper = Bundle(for: DocumentOfficeTestAnchor.self).bundleURL.deletingLastPathComponent().appendingPathComponent("NFDocumentDecoder")
        let result = try await DocumentAnalysisClient(helperURL: helper).analyze(
            DocumentInput(fileURL: url, expectedSHA256: hash, expectedByteCount: Int64(bytes.count)))
        #expect(try Data(contentsOf: url) == bytes)
        return result
    }

    private func office(_ type: String, maliciousXML: Bool = false, deflated: Bool = false,
                        documentXML: String? = nil) -> Data {
        let relationshipNamespace = "http://schemas.openxmlformats.org/package/2006/relationships"
        let officeRelationship = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        var members: [(String, Data)] = []
        func add(_ name: String, _ text: String) { members.append((name, Data(text.utf8))) }
        func types(_ body: String) { add("[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\(body)</Types>") }
        func relationships(_ path: String, _ body: String) { add(path, "<Relationships xmlns=\"\(relationshipNamespace)\">\(body)</Relationships>") }
        let main: String
        switch type {
        case "docx":
            main = "word/document.xml"
            types("<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>")
            let prefix = maliciousXML ? "<!DOCTYPE document [<!ENTITY external SYSTEM \"file:///etc/passwd\">]>" : ""
            let content = maliciousXML ? "&external;" : "The diary of Jack"
            add(main, documentXML ?? (prefix + "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>\(content)</w:t></w:r></w:p><w:p><w:r><w:t>Independent notes.</w:t></w:r></w:p></w:body></w:document>"))
        case "pptx":
            main = "ppt/presentation.xml"
            types("<Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/><Override PartName=\"/ppt/slides/slide1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/><Override PartName=\"/ppt/slides/slide2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>")
            add(main, "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" xmlns:r=\"\(officeRelationship)\"><p:sldIdLst><p:sldId id=\"256\" r:id=\"rId1\"/><p:sldId id=\"257\" r:id=\"rId2\"/></p:sldIdLst></p:presentation>")
            relationships("ppt/_rels/presentation.xml.rels", "<Relationship Id=\"rId1\" Type=\"\(officeRelationship)/slide\" Target=\"slides/slide1.xml\"/><Relationship Id=\"rId2\" Type=\"\(officeRelationship)/slide\" Target=\"slides/slide2.xml\"/>")
            for (index, text) in ["First slide", "Second slide finding"].enumerated() {
                add("ppt/slides/slide\(index + 1).xml", "<p:sld xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>\(text)</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>")
            }
        default:
            main = "xl/workbook.xml"
            types("<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/>")
            add(main, "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"\(officeRelationship)\"><sheets><sheet name=\"Evidence\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>")
            relationships("xl/_rels/workbook.xml.rels", "<Relationship Id=\"rId1\" Type=\"\(officeRelationship)/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"\(officeRelationship)/sharedStrings\" Target=\"sharedStrings.xml\"/>")
            add("xl/sharedStrings.xml", "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><si><t>shared evidence</t></si></sst>")
            add("xl/worksheets/sheet1.xml", "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\" t=\"s\"><v>0</v></c><c r=\"B1\" t=\"n\"><v>42</v></c><c r=\"C1\" t=\"inlineStr\"><is><t>inline finding</t></is></c></row></sheetData></worksheet>")
        }
        relationships("_rels/.rels", "<Relationship Id=\"rId1\" Type=\"\(officeRelationship)/officeDocument\" Target=\"\(main)\"/><Relationship Id=\"rId2\" Type=\"\(relationshipNamespace)/metadata/core-properties\" Target=\"docProps/core.xml\"/>")
        add("docProps/core.xml", "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:title>Synthetic case notes</dc:title></cp:coreProperties>")
        return zip(members, deflated: deflated)
    }

    private func zip(_ entries: [(String, Data)], flags: UInt16 = 0x0800, deflated: Bool = false) -> Data {
        var output = Data(), central = Data()
        for (name, bytes) in entries {
            let offset = UInt32(output.count), filename = Data(name.utf8)
            let crc = bytes.withUnsafeBytes { crc32(0, $0.bindMemory(to: Bytef.self).baseAddress, uInt(bytes.count)) }
            let payload = deflated ? rawDeflate(bytes) : bytes
            let method: UInt16 = deflated ? 8 : 0
            output.append(le32(0x04034b50)); output.append(le16(20)); output.append(le16(flags)); output.append(le16(method))
            output.append(le16(0)); output.append(le16(0)); output.append(le32(UInt32(crc)))
            output.append(le32(UInt32(payload.count))); output.append(le32(UInt32(bytes.count)))
            output.append(le16(UInt16(filename.count))); output.append(le16(0)); output.append(filename); output.append(payload)
            central.append(le32(0x02014b50)); central.append(le16(20)); central.append(le16(20)); central.append(le16(flags)); central.append(le16(method))
            central.append(le16(0)); central.append(le16(0)); central.append(le32(UInt32(crc)))
            central.append(le32(UInt32(payload.count))); central.append(le32(UInt32(bytes.count)))
            central.append(le16(UInt16(filename.count))); central.append(le16(0)); central.append(le16(0)); central.append(le16(0)); central.append(le16(0))
            central.append(le32(0)); central.append(le32(offset)); central.append(filename)
        }
        let centralOffset = UInt32(output.count); output.append(central)
        output.append(le32(0x06054b50)); output.append(le16(0)); output.append(le16(0))
        output.append(le16(UInt16(entries.count))); output.append(le16(UInt16(entries.count)))
        output.append(le32(UInt32(central.count))); output.append(le32(centralOffset)); output.append(le16(0))
        return output
    }

    private func rawDeflate(_ bytes: Data) -> Data {
        var stream = z_stream()
        let setup = deflateInit2_(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                                 Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        precondition(setup == Z_OK, "Synthetic fixture compression failed.")
        defer { deflateEnd(&stream) }
        var output = Data(count: Int(compressBound(uLong(bytes.count))) + 16)
        let status = bytes.withUnsafeBytes { input in
            output.withUnsafeMutableBytes { target in
                stream.next_in = UnsafeMutablePointer(mutating: input.bindMemory(to: Bytef.self).baseAddress)
                stream.avail_in = uInt(input.count)
                stream.next_out = target.bindMemory(to: Bytef.self).baseAddress
                stream.avail_out = uInt(target.count)
                return deflate(&stream, Z_FINISH)
            }
        }
        precondition(status == Z_STREAM_END)
        return output.prefix(Int(stream.total_out))
    }

    private func cfb(streamName: String) -> Data {
        var header = Data(repeating: 0, count: 512), fat = Data(repeating: 0xff, count: 512), directory = Data(repeating: 0, count: 512)
        func put(_ target: inout Data, _ offset: Int, _ bytes: Data) { target.replaceSubrange(offset..<offset + bytes.count, with: bytes) }
        put(&header, 0, Data([0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1])); put(&header, 24, le16(0x003e)); put(&header, 26, le16(3))
        put(&header, 28, le16(0xfffe)); put(&header, 30, le16(9)); put(&header, 32, le16(6)); put(&header, 44, le32(1)); put(&header, 48, le32(1))
        put(&header, 56, le32(4096)); put(&header, 60, le32(0xfffffffe)); put(&header, 68, le32(0xfffffffe))
        for offset in stride(from: 76, to: 512, by: 4) { put(&header, offset, le32(0xffffffff)) }; put(&header, 76, le32(0))
        put(&fat, 0, le32(0xfffffffd)); put(&fat, 4, le32(0xfffffffe))
        for (index, name) in ["Root Entry", streamName].enumerated() {
            let base = index * 128, encoded = name.data(using: .utf16LittleEndian)! + Data([0,0])
            put(&directory, base, encoded); put(&directory, base + 64, le16(UInt16(encoded.count))); directory[base + 66] = index == 0 ? 5 : 2; directory[base + 67] = 1
            for offset in [68,72,76] { put(&directory, base + offset, le32(0xffffffff)) }
            put(&directory, base + 116, le32(0xfffffffe))
        }
        put(&directory, 76, le32(1))
        return header + fat + directory
    }
    private func le16(_ value: UInt16) -> Data { Data([UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8)]) }
    private func le32(_ value: UInt32) -> Data { Data((0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }) }
}

private final class DocumentOfficeTestAnchor: NSObject {}
