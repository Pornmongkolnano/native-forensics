import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif
import ForensicsCore

enum OOXMLReaderError: Error {
    case malformed, unsupported, limitExceeded
}

struct OfficeDecodedContent {
    let format: DocumentOfficeFormat
    let mimeType: String
    let title: String?
    let units: [DocumentTextPage]
    let contentUnitCount: Int
    let warnings: [String]
    let rawMetadata: [DocumentRawMetadata]
}

/// Reads only in-memory OPC parts that have already passed the bounded ZIP reader.
/// Stored text is not a rendering, a formula evaluation, or an Office application.
enum OfficeOpenXMLReader {
    static func read(_ archive: BoundedZIPArchive) throws -> OfficeDecodedContent? {
        guard archive.entries.contains(where: { $0.name == "[Content_Types].xml" }) else { return nil }
        let package = try OOXMLPackage(archive)
        guard let typeData = package.data("[Content_Types].xml") else { throw OOXMLReaderError.limitExceeded }
        let types = try OOXMLContentTypes(typeData)
        if types.hasMacros || package.names.contains(where: { $0.split(separator: "/").last?.lowercased() == "vbaproject.bin" }) {
            throw OOXMLReaderError.unsupported
        }
        guard let rootRels = package.data("_rels/.rels") else {
            if package.hasPart("_rels/.rels") { throw OOXMLReaderError.limitExceeded }
            if types.hasOfficeMainPart { throw OOXMLReaderError.malformed }
            return nil
        }
        let rootRelationships = try OOXMLRelationships(rootRels, sourcePart: "")
        let mainRelationships = rootRelationships.ofType("officeDocument")
        guard !mainRelationships.isEmpty else {
            if types.hasOfficeMainPart { throw OOXMLReaderError.malformed }
            return nil
        }
        guard mainRelationships.count == 1 else { throw OOXMLReaderError.malformed }
        let main = try mainRelationships[0].internalPart()
        guard let mainType = types.type(of: main), package.hasPart(main) else {
            throw OOXMLReaderError.malformed
        }
        let format: DocumentOfficeFormat
        switch mainType {
        case OOXMLNamespaces.docxType: format = .docx
        case OOXMLNamespaces.pptxType: format = .pptx
        case OOXMLNamespaces.xlsxType: format = .xlsx
        default: throw OOXMLReaderError.unsupported
        }
        var warnings = ["Stored Office text is shown without rendered layout, formatting, visibility rules, or optical character recognition. Embedded objects and macros are not executed."]
        if rootRelationships.hasExternalTargets {
            warnings.append("External package relationships were not followed.")
        }
        let properties = try coreProperties(package, relationships: rootRelationships, warnings: &warnings)
        guard let mainData = package.data(main) else {
            // A DOCX has one body unit by definition. Presentation/workbook
            // counts and ordering cannot be asserted without their main XML.
            guard format == .docx else { throw OOXMLReaderError.unsupported }
            warnings.append("The DOCX main XML part was omitted by the bounded ZIP retention limit. The document body was not parsed; verified ZIP bytes do not establish readable XML content.")
            return OfficeDecodedContent(format: .docx, mimeType: OOXMLNamespaces.docxMIME,
                                        title: properties.title,
                                        units: [DocumentTextPage(pageNumber: 1, text: "", isTruncated: true,
                                                                 referenceLabel: "Document body", referenceKind: .document)],
                                        contentUnitCount: 1, warnings: warnings, rawMetadata: properties.metadata)
        }
        switch format {
        case .docx:
            return try docx(mainData, title: properties.title, rawMetadata: properties.metadata, warnings: warnings)
        case .pptx:
            return try pptx(mainData, mainPart: main, package: package, types: types,
                            title: properties.title, rawMetadata: properties.metadata, warnings: warnings)
        case .xlsx:
            return try xlsx(mainData, mainPart: main, package: package, types: types,
                            title: properties.title, rawMetadata: properties.metadata, warnings: warnings)
        default:
            throw OOXMLReaderError.unsupported
        }
    }

    private static func coreProperties(_ package: OOXMLPackage, relationships: OOXMLRelationships,
                                       warnings: inout [String]) throws -> (title: String?, metadata: [DocumentRawMetadata]) {
        let matches = relationships.entries.filter { $0.type == OOXMLNamespaces.corePropertiesRelationship }
        guard matches.count <= 1 else { throw OOXMLReaderError.malformed }
        guard let relationship = matches.first else { return (nil, []) }
        let path = try relationship.internalPart()
        guard let data = package.data(path) else {
            if package.hasPart(path) {
                warnings.append("Office core properties exceeded the bounded XML retention limit and were not interpreted.")
                return (nil, [])
            }
            throw OOXMLReaderError.malformed
        }
        let document = try OOXMLTree.parse(data)
        guard document.isElement("coreProperties", in: [OOXMLNamespaces.coreProperties]) else {
            throw OOXMLReaderError.malformed
        }
        let titles = document.children.filter { $0.isElement("title", in: [OOXMLNamespaces.dublinCore]) }
        guard titles.count <= 1 else { throw OOXMLReaderError.malformed }
        var title: String?
        var clipped = false
        if let raw = titles.first?.text, !raw.isEmpty {
            var value = OOXMLTextBuffer(maximumBytes: 4_096)
            value.append(raw)
            clipped = value.isTruncated
            title = value.value
        }
        var metadata: [DocumentRawMetadata] = []
        for (element, namespace, label) in [("creator", OOXMLNamespaces.dublinCore, "Office.Creator"),
                                            ("created", OOXMLNamespaces.dublinCoreTerms, "Office.Created"),
                                            ("modified", OOXMLNamespaces.dublinCoreTerms, "Office.Modified")] {
            let matches = document.children.filter { $0.isElement(element, in: [namespace]) }
            guard matches.count <= 1 else { throw OOXMLReaderError.malformed }
            if let raw = matches.first?.text, !raw.isEmpty {
                var value = OOXMLTextBuffer(maximumBytes: 4_096)
                value.append(raw)
                clipped = clipped || value.isTruncated
                metadata.append(DocumentRawMetadata(name: label, value: value.value))
            }
        }
        if clipped { warnings.append("Long Office core-property values were limited to 4 KiB.") }
        if !metadata.isEmpty {
            warnings.append("Office core properties are raw values supplied by the file, separate from filesystem timestamps. Dates and missing time-zone offsets are not interpreted.")
        }
        return (title, metadata)
    }

    private static func docx(_ data: Data, title: String?, rawMetadata: [DocumentRawMetadata], warnings initial: [String]) throws -> OfficeDecodedContent {
        let decoded = try OOXMLWordBody.parse(data)
        var text = decoded.text
        var warnings = initial
        warnings.append("Only the DOCX main body was inspected. Headers, footers, comments, footnotes, images, and embedded objects are excluded; document pages are not inferred.")
        warnings.append("Stored field results are read without evaluating fields. Deleted revision text is excluded; revision visibility and hidden text formatting are not resolved.")
        if text.isTruncated { warnings.append(OOXMLNamespaces.textLimitWarning) }
        if decoded.hasSymbols {
            text.markTruncated()
            warnings.append("Font-specific DOCX symbols were not decoded; the extracted body text is incomplete.")
        }
        if decoded.hasCompatibility {
            text.markTruncated()
            warnings.append("DOCX markup-compatibility alternatives were omitted because rendered feature selection is unsupported. Choice/fallback content is not duplicated; body text is incomplete.")
        }
        if decoded.hasOpaqueDrawingData {
            warnings.append("Large Office drawing payload attributes were validated as XML strings but not retained or decoded; only body text was extracted.")
        }
        let unit = DocumentTextPage(pageNumber: 1, text: text.value, isTruncated: text.isTruncated,
                                    referenceLabel: "Document body", referenceKind: .document)
        return OfficeDecodedContent(format: .docx, mimeType: OOXMLNamespaces.docxMIME, title: title,
                                    units: [unit], contentUnitCount: 1, warnings: warnings, rawMetadata: rawMetadata)
    }

    private static func pptx(_ data: Data, mainPart: String, package: OOXMLPackage,
                             types: OOXMLContentTypes, title: String?, rawMetadata: [DocumentRawMetadata], warnings initial: [String]) throws -> OfficeDecodedContent {
        let root = try OOXMLTree.parse(data)
        guard root.isElement("presentation", in: OOXMLNamespaces.presentation) else { throw OOXMLReaderError.malformed }
        let lists = root.children.filter { $0.isElement("sldIdLst", in: OOXMLNamespaces.presentation) }
        guard lists.count <= 1 else { throw OOXMLReaderError.malformed }
        let listed = lists.first?.children ?? []
        guard listed.count <= 1_000_000 else { throw OOXMLReaderError.limitExceeded }
        let relationships = try package.relationships(for: mainPart)
        var targets: [String] = []
        var seenIDs = Set<String>()
        var seenParts = Set<String>()
        for slide in listed {
            guard slide.isElement("sldId", in: OOXMLNamespaces.presentation),
                  let id = slide.attribute("id"), !id.isEmpty, seenIDs.insert(id).inserted,
                  let relationshipID = slide.relationshipID else { throw OOXMLReaderError.malformed }
            let relationship = try relationships.required(relationshipID, ofType: "slide")
            let target = try relationship.internalPart()
            guard seenParts.insert(OOXMLPackage.key(target)).inserted,
                  types.type(of: target) == OOXMLNamespaces.slideType,
                  package.hasPart(target) else { throw OOXMLReaderError.malformed }
            targets.append(target)
        }
        var units: [DocumentTextPage] = []
        var remaining = DocumentLimits.maximumTextBytes
        var warnings = initial
        var compatibility = false
        var omittedSlide = false
        for (index, target) in targets.prefix(DocumentLimits.maximumPages).enumerated() {
            guard let part = package.data(target) else {
                omittedSlide = true
                units.append(DocumentTextPage(pageNumber: index + 1, text: "", isTruncated: true,
                                              referenceLabel: "Slide \(index + 1)", referenceKind: .slide))
                continue
            }
            let slide: OOXMLNode
            do { slide = try OOXMLTree.parse(part) }
            catch OOXMLReaderError.limitExceeded {
                omittedSlide = true
                units.append(DocumentTextPage(pageNumber: index + 1, text: "", isTruncated: true,
                                              referenceLabel: "Slide \(index + 1)", referenceKind: .slide))
                continue
            }
            guard slide.isElement("sld", in: OOXMLNamespaces.presentation) else { throw OOXMLReaderError.malformed }
            let common = slide.children.filter { $0.isElement("cSld", in: OOXMLNamespaces.presentation) }
            guard common.count == 1,
                  common[0].children.filter({ $0.isElement("spTree", in: OOXMLNamespaces.presentation) }).count == 1 else {
                throw OOXMLReaderError.malformed
            }
            var paragraphs: [OOXMLNode] = []
            collectParagraphs(common[0], namespaces: OOXMLNamespaces.drawing, into: &paragraphs, word: false)
            var text = OOXMLTextBuffer(maximumBytes: remaining)
            for (paragraphIndex, paragraph) in paragraphs.enumerated() {
                if paragraphIndex > 0 { text.append("\n") }
                paragraphText(paragraph, namespaces: OOXMLNamespaces.drawing, into: &text, word: false)
            }
            compatibility = compatibility || containsCompatibility(common[0])
            units.append(DocumentTextPage(pageNumber: index + 1, text: text.value, isTruncated: text.isTruncated,
                                          referenceLabel: "Slide \(index + 1)", referenceKind: .slide))
            remaining -= text.byteCount
            if text.isTruncated || (remaining == 0 && index + 1 < targets.count) {
                warnings.append(OOXMLNamespaces.textLimitWarning)
                break
            }
        }
        warnings.append("PPTX text follows presentation slide order. Speaker notes, masters, charts, images, and embedded objects are excluded; stored field text is not evaluated.")
        if targets.count > DocumentLimits.maximumPages { warnings.append("Only the first 200 presentation slides were inspected.") }
        if relationships.hasExternalTargets { warnings.append("External presentation relationships were not followed.") }
        if compatibility { warnings.append(OOXMLNamespaces.compatibilityWarning) }
        if omittedSlide { warnings.append("One or more listed slide XML parts exceeded bounded retention or XML parsing limits. Their slide references are retained, but their text and XML structures were not fully inspected.") }
        return OfficeDecodedContent(format: .pptx, mimeType: OOXMLNamespaces.pptxMIME, title: title,
                                    units: units, contentUnitCount: targets.count, warnings: warnings, rawMetadata: rawMetadata)
    }

    private static func xlsx(_ data: Data, mainPart: String, package: OOXMLPackage,
                             types: OOXMLContentTypes, title: String?, rawMetadata: [DocumentRawMetadata], warnings initial: [String]) throws -> OfficeDecodedContent {
        let root = try OOXMLTree.parse(data)
        guard root.isElement("workbook", in: OOXMLNamespaces.spreadsheet) else { throw OOXMLReaderError.malformed }
        let sheetLists = root.children.filter { $0.isElement("sheets", in: OOXMLNamespaces.spreadsheet) }
        guard sheetLists.count == 1 else { throw OOXMLReaderError.malformed }
        let listed = sheetLists[0].children
        guard listed.count <= 1_000_000 else { throw OOXMLReaderError.limitExceeded }
        let relationships = try package.relationships(for: mainPart)
        let sharedRelationships = relationships.ofType("sharedStrings")
        guard sharedRelationships.count <= 1 else { throw OOXMLReaderError.malformed }
        var shared: [String] = []
        var sharedUnavailable = false
        if let relationship = sharedRelationships.first {
            let target = try relationship.internalPart()
            guard types.type(of: target) == OOXMLNamespaces.sharedStringsType,
                  package.hasPart(target) else { throw OOXMLReaderError.malformed }
            if let sharedData = package.data(target) {
                do { shared = try sharedStrings(sharedData) }
                catch OOXMLReaderError.limitExceeded { sharedUnavailable = true }
            } else { sharedUnavailable = true }
        }
        var sheets: [(name: String, path: String)] = []
        var seenIDs = Set<String>()
        var seenNames = Set<String>()
        var seenParts = Set<String>()
        for sheet in listed {
            guard sheet.isElement("sheet", in: OOXMLNamespaces.spreadsheet),
                  let name = sheet.attribute("name"), !name.isEmpty,
                  let id = sheet.attribute("sheetId"), !id.isEmpty,
                  seenIDs.insert(id).inserted, seenNames.insert(name.lowercased()).inserted,
                  let relationshipID = sheet.relationshipID else { throw OOXMLReaderError.malformed }
            let relationship = try relationships.required(relationshipID, ofType: "worksheet")
            let target = try relationship.internalPart()
            guard types.type(of: target) == OOXMLNamespaces.worksheetType,
                  package.hasPart(target), seenParts.insert(OOXMLPackage.key(target)).inserted else {
                throw OOXMLReaderError.malformed
            }
            sheets.append((name, target))
        }
        var units: [DocumentTextPage] = []
        var remaining = DocumentLimits.maximumTextBytes
        var warnings = initial
        var hasFormula = false
        var clippedLabel = false
        var omittedWorksheet = false
        for (index, sheet) in sheets.prefix(DocumentLimits.maximumPages).enumerated() {
            var label = OOXMLTextBuffer(maximumBytes: 256)
            label.append(sheet.name)
            clippedLabel = clippedLabel || label.isTruncated
            guard let sheetData = package.data(sheet.path) else {
                omittedWorksheet = true
                units.append(DocumentTextPage(pageNumber: index + 1, text: "", isTruncated: true,
                                              referenceLabel: label.value, referenceKind: .sheet))
                continue
            }
            let decoded: (text: OOXMLTextBuffer, hasFormula: Bool, hasUnresolvedStrings: Bool)
            do {
                decoded = try worksheet(sheetData, shared: shared, sharedUnavailable: sharedUnavailable, maximumBytes: remaining)
            } catch OOXMLReaderError.limitExceeded {
                omittedWorksheet = true
                units.append(DocumentTextPage(pageNumber: index + 1, text: "", isTruncated: true,
                                              referenceLabel: label.value, referenceKind: .sheet))
                continue
            }
            units.append(DocumentTextPage(pageNumber: index + 1, text: decoded.text.value,
                                          isTruncated: decoded.text.isTruncated || decoded.hasUnresolvedStrings,
                                          referenceLabel: label.value, referenceKind: .sheet))
            remaining -= decoded.text.byteCount
            hasFormula = hasFormula || decoded.hasFormula
            if decoded.text.isTruncated || (remaining == 0 && index + 1 < sheets.count) {
                warnings.append(OOXMLNamespaces.textLimitWarning)
                break
            }
        }
        warnings.append("XLSX text follows workbook worksheet order. Cell addresses and stored values are retained; number/date styles, hidden rows/columns/sheets, charts, drawings, and displayed formatting are not resolved.")
        warnings.append("Spreadsheet _xHHHH_ escape sequences are retained as stored text without interpreting escaped control characters.")
        if hasFormula { warnings.append("Formulas are displayed as stored source plus any cached value. Formulas, shared-formula references, and external links are never evaluated.") }
        if sheets.count > DocumentLimits.maximumPages { warnings.append("Only the first 200 workbook worksheets were inspected.") }
        if relationships.hasExternalTargets { warnings.append("External workbook relationships were not followed.") }
        if clippedLabel { warnings.append("Long worksheet reference labels were limited to 256 UTF-8 bytes.") }
        if omittedWorksheet { warnings.append("One or more listed worksheet XML parts exceeded bounded retention or XML parsing limits. Their sheet references remain, with incomplete text; other bounded worksheets were inspected.") }
        if sharedUnavailable { warnings.append("Shared-string XML exceeded bounded retention or parsing limits. Affected cell indices are labeled unresolved; their values are not claimed as decoded.") }
        return OfficeDecodedContent(format: .xlsx, mimeType: OOXMLNamespaces.xlsxMIME, title: title,
                                    units: units, contentUnitCount: sheets.count, warnings: warnings, rawMetadata: rawMetadata)
    }

    private static func sharedStrings(_ data: Data) throws -> [String] {
        let root = try OOXMLTree.parse(data)
        guard root.isElement("sst", in: OOXMLNamespaces.spreadsheet) else { throw OOXMLReaderError.malformed }
        guard root.children.count <= 100_000 else { throw OOXMLReaderError.limitExceeded }
        var strings: [String] = []
        var total = 0
        for item in root.children {
            guard item.isElement("si", in: OOXMLNamespaces.spreadsheet) else { throw OOXMLReaderError.malformed }
            var value = OOXMLTextBuffer(maximumBytes: 8 * 1_024 * 1_024 - total)
            richString(item, into: &value)
            guard !value.isTruncated else { throw OOXMLReaderError.limitExceeded }
            total += value.byteCount
            strings.append(value.value)
        }
        return strings
    }

    private static func richString(_ root: OOXMLNode, into text: inout OOXMLTextBuffer) {
        for child in root.children {
            if child.isElement("t", in: OOXMLNamespaces.spreadsheet) { text.append(child.text) }
            else if child.isElement("r", in: OOXMLNamespaces.spreadsheet) {
                for run in child.children where run.isElement("t", in: OOXMLNamespaces.spreadsheet) { text.append(run.text) }
            }
            // Phonetic rPh text is not a second copy of the cell value.
        }
    }

    private static func worksheet(_ data: Data, shared: [String], sharedUnavailable: Bool,
                                  maximumBytes: Int) throws -> (text: OOXMLTextBuffer, hasFormula: Bool, hasUnresolvedStrings: Bool) {
        let root = try OOXMLTree.parse(data)
        guard root.isElement("worksheet", in: OOXMLNamespaces.spreadsheet) else { throw OOXMLReaderError.malformed }
        let bodies = root.children.filter { $0.isElement("sheetData", in: OOXMLNamespaces.spreadsheet) }
        guard bodies.count == 1 else { throw OOXMLReaderError.malformed }
        var text = OOXMLTextBuffer(maximumBytes: maximumBytes)
        var hasFormula = false
        var hasUnresolvedStrings = false
        var previousRow = 0
        var cellCount = 0
        for row in bodies[0].children {
            guard row.isElement("row", in: OOXMLNamespaces.spreadsheet) else { throw OOXMLReaderError.malformed }
            let rowNumber: Int
            if let stored = row.attribute("r") {
                guard let number = Int(stored), number > previousRow, number <= 1_048_576 else { throw OOXMLReaderError.malformed }
                rowNumber = number
            } else { rowNumber = previousRow + 1 }
            guard rowNumber <= 1_048_576 else { throw OOXMLReaderError.malformed }
            previousRow = rowNumber
            var previousColumn = 0
            for (index, cell) in row.children.enumerated() {
                guard cell.isElement("c", in: OOXMLNamespaces.spreadsheet) else { throw OOXMLReaderError.malformed }
                cellCount += 1
                guard cellCount <= 100_000 else { throw OOXMLReaderError.limitExceeded }
                let address: String
                let column: Int
                if let stored = cell.attribute("r") {
                    let parsed = try cellAddress(stored)
                    guard parsed.row == rowNumber, parsed.column > previousColumn else { throw OOXMLReaderError.malformed }
                    address = stored; column = parsed.column
                } else {
                    column = previousColumn + 1
                    guard column <= 16_384 else { throw OOXMLReaderError.malformed }
                    address = columnLabel(column) + String(rowNumber)
                }
                previousColumn = column
                if index > 0 { text.append("\t") }
                text.append(address + ": ")
                let values = cell.children.filter { $0.isElement("v", in: OOXMLNamespaces.spreadsheet) }
                let formulas = cell.children.filter { $0.isElement("f", in: OOXMLNamespaces.spreadsheet) }
                let inline = cell.children.filter { $0.isElement("is", in: OOXMLNamespaces.spreadsheet) }
                guard values.count <= 1, formulas.count <= 1, inline.count <= 1 else { throw OOXMLReaderError.malformed }
                let raw = values.first?.text ?? ""
                var value = OOXMLTextBuffer(maximumBytes: max(0, maximumBytes - text.byteCount))
                switch cell.attribute("t") ?? "n" {
                case "s":
                    guard let item = Int(raw), item >= 0, inline.isEmpty else { throw OOXMLReaderError.malformed }
                    if sharedUnavailable {
                        hasUnresolvedStrings = true
                        value.append("[unresolved shared-string index \(item)]")
                    } else {
                        guard item < shared.count else { throw OOXMLReaderError.malformed }
                        value.append(shared[item])
                    }
                case "inlineStr":
                    guard inline.count == 1, values.isEmpty, formulas.isEmpty else { throw OOXMLReaderError.malformed }
                    richString(inline[0], into: &value)
                case "b":
                    guard raw.isEmpty || raw == "0" || raw == "1", inline.isEmpty else { throw OOXMLReaderError.malformed }
                    value.append(raw.isEmpty ? "" : (raw == "1" ? "TRUE [stored 1]" : "FALSE [stored 0]"))
                case "n", "str", "e", "d":
                    guard inline.isEmpty else { throw OOXMLReaderError.malformed }
                    value.append(raw)
                default: throw OOXMLReaderError.unsupported
                }
                if let formula = formulas.first {
                    hasFormula = true
                    text.append("Formula: ")
                    if !formula.text.isEmpty { text.append("=" + formula.text) }
                    else if formula.attribute("t") == "shared" {
                        text.append("[shared reference " + (formula.attribute("si") ?? "unknown") + "]")
                    } else { text.append("[source absent]") }
                    text.append(" | cached: ")
                }
                text.append(value.value)
                if value.isTruncated { text.markTruncated() }
            }
            text.append("\n")
        }
        return (text, hasFormula, hasUnresolvedStrings)
    }

    private static func cellAddress(_ value: String) throws -> (column: Int, row: Int) {
        let bytes = Array(value.utf8)
        guard bytes.count <= 10 else { throw OOXMLReaderError.malformed }
        var position = 0
        var column = 0
        while position < bytes.count, (65...90).contains(bytes[position]) {
            column = column * 26 + Int(bytes[position] - 64)
            guard column <= 16_384 else { throw OOXMLReaderError.malformed }
            position += 1
        }
        guard column > 0, position < bytes.count, bytes[position] != 48,
              bytes[position...].allSatisfy({ (48...57).contains($0) }),
              let row = Int(String(decoding: bytes[position...], as: UTF8.self)), row > 0, row <= 1_048_576 else {
            throw OOXMLReaderError.malformed
        }
        return (column, row)
    }

    private static func columnLabel(_ number: Int) -> String {
        var number = number
        var result = ""
        while number > 0 {
            number -= 1
            result = String(UnicodeScalar(65 + number % 26)!) + result
            number /= 26
        }
        return result
    }

    private static func collectParagraphs(_ node: OOXMLNode, namespaces: Set<String>,
                                          into result: inout [OOXMLNode], word: Bool) {
        if word && node.namespaceURI.map(OOXMLNamespaces.word.contains) == true
            && ["del", "moveFrom"].contains(node.localName) { return }
        if node.isElement("p", in: namespaces) { result.append(node) }
        for child in node.textChildren { collectParagraphs(child, namespaces: namespaces, into: &result, word: word) }
    }

    private static func paragraphText(_ paragraph: OOXMLNode, namespaces: Set<String>,
                                      into text: inout OOXMLTextBuffer, word: Bool) {
        func visit(_ node: OOXMLNode) {
            if node !== paragraph, node.isElement("p", in: namespaces) { return }
            if word && node.namespaceURI.map(OOXMLNamespaces.word.contains) == true
                && ["del", "moveFrom"].contains(node.localName) { return }
            if node.isElement("t", in: namespaces) { text.append(node.text); return }
            if node.isElement("br", in: namespaces) || (word && node.isElement("cr", in: namespaces)) { text.append("\n") }
            if word && node.isElement("tab", in: namespaces) { text.append("\t") }
            if word && node.isElement("noBreakHyphen", in: namespaces) { text.append("\u{2011}") }
            if word && node.isElement("softHyphen", in: namespaces) { text.append("\u{00AD}") }
            for child in node.textChildren { visit(child) }
        }
        visit(paragraph)
    }

    private static func containsCompatibility(_ node: OOXMLNode) -> Bool {
        node.isElement("AlternateContent", in: [OOXMLNamespaces.compatibility])
            || node.children.contains(where: containsCompatibility)
    }

    private static func contains(_ node: OOXMLNode, element: String, namespaces: Set<String>) -> Bool {
        node.isElement(element, in: namespaces)
            || node.children.contains(where: { contains($0, element: element, namespaces: namespaces) })
    }
}

private enum OOXMLNamespaces {
    static let contentTypes = "http://schemas.openxmlformats.org/package/2006/content-types"
    static let packageRelationships = "http://schemas.openxmlformats.org/package/2006/relationships"
    static let officeRelationships: Set<String> = ["http://schemas.openxmlformats.org/officeDocument/2006/relationships", "http://purl.oclc.org/ooxml/officeDocument/relationships"]
    static let word: Set<String> = ["http://schemas.openxmlformats.org/wordprocessingml/2006/main", "http://purl.oclc.org/ooxml/wordprocessingml/main"]
    static let drawing: Set<String> = ["http://schemas.openxmlformats.org/drawingml/2006/main", "http://purl.oclc.org/ooxml/drawingml/main"]
    static let presentation: Set<String> = ["http://schemas.openxmlformats.org/presentationml/2006/main", "http://purl.oclc.org/ooxml/presentationml/main"]
    static let spreadsheet: Set<String> = ["http://schemas.openxmlformats.org/spreadsheetml/2006/main", "http://purl.oclc.org/ooxml/spreadsheetml/main"]
    static let compatibility = "http://schemas.openxmlformats.org/markup-compatibility/2006"
    static let coreProperties = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    static let dublinCore = "http://purl.org/dc/elements/1.1/"
    static let dublinCoreTerms = "http://purl.org/dc/terms/"
    static let corePropertiesRelationship = packageRelationships + "/metadata/core-properties"
    static let docxType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    static let pptxType = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
    static let xlsxType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    static let docxMIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    static let pptxMIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    static let xlsxMIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    static let slideType = "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"
    static let worksheetType = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
    static let sharedStringsType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml"
    static let textLimitWarning = "Office extracted text reached the 1 MiB inspection limit."
    static let compatibilityWarning = "Markup-compatibility alternatives use one stored branch (fallback when available); rendered layout and feature support are not resolved."
}

private struct OOXMLPackage {
    private let parts: [String: BoundedZIPEntry]
    let names: [String]

    init(_ archive: BoundedZIPArchive) throws {
        var parts: [String: BoundedZIPEntry] = [:]
        var names: [String] = []
        var seen = Set<String>()
        var total = 0
        for entry in archive.entries {
            total += entry.data.count
            guard total <= 64 * 1_024 * 1_024 else { throw OOXMLReaderError.limitExceeded }
            guard entry.originalByteCount >= 0, entry.data.count <= entry.originalByteCount,
                  !(entry.isDataOmitted && entry.isDataTruncated),
                  !entry.isDataOmitted || entry.data.isEmpty,
                  entry.isDataOmitted || entry.isDataTruncated || entry.data.count == entry.originalByteCount else {
                throw OOXMLReaderError.malformed
            }
            let directory = entry.name.hasSuffix("/")
            let raw = directory ? String(entry.name.dropLast()) : entry.name
            let path = try Self.resolve(raw, sourcePart: "", allowPackageRoot: false, allowParents: false)
            let key = Self.key(path)
            guard seen.insert(key).inserted else { throw OOXMLReaderError.malformed }
            if directory {
                guard entry.originalByteCount == 0, entry.data.isEmpty,
                      !entry.isDataOmitted, !entry.isDataTruncated else { throw OOXMLReaderError.malformed }
            } else {
                parts[key] = entry
                names.append(path)
            }
        }
        self.parts = parts; self.names = names
    }

    static func key(_ path: String) -> String { path.precomposedStringWithCanonicalMapping.lowercased() }
    func hasPart(_ path: String) -> Bool { parts[Self.key(path)] != nil }
    func data(_ path: String) -> Data? {
        guard let entry = parts[Self.key(path)], !entry.isDataOmitted, !entry.isDataTruncated else { return nil }
        return entry.data
    }

    func relationships(for source: String) throws -> OOXMLRelationships {
        let components = source.split(separator: "/").map(String.init)
        guard let last = components.last else { throw OOXMLReaderError.malformed }
        let directory = components.dropLast().joined(separator: "/")
        let relPath = (directory.isEmpty ? "" : directory + "/") + "_rels/" + last + ".rels"
        guard let data = data(relPath) else {
            if hasPart(relPath) { throw OOXMLReaderError.limitExceeded }
            throw OOXMLReaderError.malformed
        }
        return try OOXMLRelationships(data, sourcePart: source)
    }

    static func resolve(_ raw: String, sourcePart: String, allowPackageRoot: Bool = true,
                        allowParents: Bool = true) throws -> String {
        guard !raw.isEmpty, raw.utf8.count <= 4_096,
              !raw.contains("\\"), !raw.contains("?"), !raw.contains("#"), !raw.contains(":"),
              let decoded = raw.removingPercentEncoding,
              !decoded.contains("\\"), !decoded.contains("?"), !decoded.contains("#"), !decoded.contains(":"),
              !decoded.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !raw.lowercased().contains("%2f"), !raw.lowercased().contains("%5c") else {
            throw OOXMLReaderError.malformed
        }
        let rooted = decoded.hasPrefix("/")
        guard !rooted || allowPackageRoot else { throw OOXMLReaderError.malformed }
        var components = rooted ? [] : sourcePart.split(separator: "/").dropLast().map(String.init)
        let target = rooted ? String(decoded.dropFirst()) : decoded
        let segments = target.split(separator: "/", omittingEmptySubsequences: false)
        for segment in segments {
            guard !segment.isEmpty else { throw OOXMLReaderError.malformed }
            if segment == "." {
                guard allowParents else { throw OOXMLReaderError.malformed }
            } else if segment == ".." {
                guard allowParents, !components.isEmpty else { throw OOXMLReaderError.malformed }
                components.removeLast()
            } else { components.append(String(segment)) }
        }
        guard !components.isEmpty else { throw OOXMLReaderError.malformed }
        return components.joined(separator: "/").precomposedStringWithCanonicalMapping
    }
}

private struct OOXMLContentTypes {
    private let overrides: [String: String]
    private let defaults: [String: String]
    let hasMacros: Bool
    let hasOfficeMainPart: Bool

    init(_ data: Data) throws {
        let root = try OOXMLTree.parse(data)
        guard root.isElement("Types", in: [OOXMLNamespaces.contentTypes]) else { throw OOXMLReaderError.malformed }
        var overrides: [String: String] = [:]
        var defaults: [String: String] = [:]
        var macros = false
        var office = false
        for child in root.children {
            guard let type = child.attribute("ContentType"), !type.isEmpty, type.utf8.count <= 256 else {
                throw OOXMLReaderError.malformed
            }
            let normalized = type.lowercased()
            macros = macros || normalized.contains("macroenabled") || normalized.contains("vbaproject") || normalized.contains("macrosheet")
            office = office || [OOXMLNamespaces.docxType, OOXMLNamespaces.pptxType, OOXMLNamespaces.xlsxType].contains(normalized)
            if child.isElement("Override", in: [OOXMLNamespaces.contentTypes]) {
                guard let raw = child.attribute("PartName"), raw.hasPrefix("/") else { throw OOXMLReaderError.malformed }
                let part = try OOXMLPackage.resolve(raw, sourcePart: "", allowParents: false)
                guard overrides.updateValue(normalized, forKey: OOXMLPackage.key(part)) == nil else { throw OOXMLReaderError.malformed }
            } else if child.isElement("Default", in: [OOXMLNamespaces.contentTypes]) {
                guard let ext = child.attribute("Extension"), !ext.isEmpty, ext.utf8.count <= 64,
                      ext.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) }),
                      defaults.updateValue(normalized, forKey: ext.lowercased()) == nil else { throw OOXMLReaderError.malformed }
            } else { throw OOXMLReaderError.malformed }
        }
        self.overrides = overrides; self.defaults = defaults
        hasMacros = macros; hasOfficeMainPart = office
    }

    func type(of path: String) -> String? {
        if let override = overrides[OOXMLPackage.key(path)] { return override }
        guard let name = path.split(separator: "/").last, let dot = name.lastIndex(of: ".") else { return nil }
        return defaults[String(name[name.index(after: dot)...]).lowercased()]
    }
}

private struct OOXMLRelationship {
    let id: String
    let type: String
    let target: String
    let external: Bool
    let sourcePart: String
    func internalPart() throws -> String {
        guard !external else { throw OOXMLReaderError.unsupported }
        return try OOXMLPackage.resolve(target, sourcePart: sourcePart)
    }
}

private struct OOXMLRelationships {
    let entries: [OOXMLRelationship]
    private let byID: [String: OOXMLRelationship]
    var hasExternalTargets: Bool { entries.contains(where: { $0.external }) }

    init(_ data: Data, sourcePart: String) throws {
        let root = try OOXMLTree.parse(data)
        guard root.isElement("Relationships", in: [OOXMLNamespaces.packageRelationships]) else { throw OOXMLReaderError.malformed }
        var entries: [OOXMLRelationship] = []
        var byID: [String: OOXMLRelationship] = [:]
        var seen = Set<String>()
        for child in root.children {
            guard child.isElement("Relationship", in: [OOXMLNamespaces.packageRelationships]),
                  let id = child.attribute("Id"), !id.isEmpty, seen.insert(id).inserted,
                  let type = child.attribute("Type"), !type.isEmpty,
                  let target = child.attribute("Target"), !target.isEmpty else { throw OOXMLReaderError.malformed }
            let mode = child.attribute("TargetMode") ?? "Internal"
            guard mode == "Internal" || mode == "External" else { throw OOXMLReaderError.malformed }
            let entry = OOXMLRelationship(id: id, type: type, target: target,
                                          external: mode == "External", sourcePart: sourcePart)
            entries.append(entry)
            byID[id] = entry
        }
        self.entries = entries; self.byID = byID
    }

    func ofType(_ name: String) -> [OOXMLRelationship] {
        entries.filter { entry in OOXMLNamespaces.officeRelationships.contains(where: { entry.type == $0 + "/" + name }) }
    }

    func required(_ id: String, ofType name: String) throws -> OOXMLRelationship {
        guard let entry = byID[id] else { throw OOXMLReaderError.malformed }
        guard OOXMLNamespaces.officeRelationships.contains(where: { entry.type == $0 + "/" + name }) else {
            if name == "worksheet", ["chartsheet", "dialogsheet", "macrosheet", "intlMacrosheet"].contains(where: { kind in
                OOXMLNamespaces.officeRelationships.contains(where: { entry.type == $0 + "/" + kind })
            }) { throw OOXMLReaderError.unsupported }
            throw OOXMLReaderError.malformed
        }
        return entry
    }
}

private struct OOXMLAttributeName: Hashable {
    let namespaceURI: String
    let localName: String
}

private final class OOXMLNode {
    let localName: String
    let namespaceURI: String?
    let attributes: [OOXMLAttributeName: String]
    var children: [OOXMLNode] = []
    var text = ""

    init(localName: String, namespaceURI: String?, attributes: [OOXMLAttributeName: String]) {
        self.localName = localName; self.namespaceURI = namespaceURI; self.attributes = attributes
    }
    func isElement(_ name: String, in namespaces: Set<String>) -> Bool {
        localName == name && namespaceURI.map(namespaces.contains) == true
    }
    func attribute(_ name: String) -> String? { attributes[OOXMLAttributeName(namespaceURI: "", localName: name)] }
    var relationshipID: String? {
        let matches = OOXMLNamespaces.officeRelationships.compactMap {
            attributes[OOXMLAttributeName(namespaceURI: $0, localName: "id")]
        }
        return matches.count == 1 && !matches[0].isEmpty ? matches[0] : nil
    }
    var textChildren: [OOXMLNode] {
        guard isElement("AlternateContent", in: [OOXMLNamespaces.compatibility]) else { return children }
        if let fallback = children.first(where: { $0.isElement("Fallback", in: [OOXMLNamespaces.compatibility]) }) { return [fallback] }
        if let choice = children.first(where: { $0.isElement("Choice", in: [OOXMLNamespaces.compatibility]) }) { return [choice] }
        return []
    }
    var capturesText: Bool {
        if localName == "t", namespaceURI.map({ OOXMLNamespaces.word.contains($0) || OOXMLNamespaces.drawing.contains($0) || OOXMLNamespaces.spreadsheet.contains($0) }) == true { return true }
        if ["v", "f"].contains(localName), namespaceURI.map(OOXMLNamespaces.spreadsheet.contains) == true { return true }
        if ["title", "creator"].contains(localName), namespaceURI == OOXMLNamespaces.dublinCore { return true }
        return ["created", "modified"].contains(localName) && namespaceURI == OOXMLNamespaces.dublinCoreTerms
    }
}

/// Large DOCX bodies need only a bounded SAX context stack and output buffer,
/// not hundreds of thousands of retained run/formatting nodes.
private final class OOXMLWordBody: NSObject, XMLParserDelegate {
    private struct Frame {
        let localName: String
        let namespaceURI: String?
        let insideBody: Bool
        let suppressed: Bool
        let activeParagraph: Bool
        let textLeaf: Bool
        let capturesText: Bool
    }

    private var stack: [Frame] = []
    private var mappings: [String: [String]] = ["xml": ["http://www.w3.org/XML/1998/namespace"]]
    private var mappingCount = 1
    private var eventCount = 0
    private var attributeBytes = 0
    private var sawRoot = false
    private var bodyCount = 0
    private var paragraphCount = 0
    private var activeParagraphs = 0
    private var failure: OOXMLReaderError?
    private(set) var text = OOXMLTextBuffer(maximumBytes: DocumentLimits.maximumTextBytes)
    private(set) var hasSymbols = false
    private(set) var hasCompatibility = false
    private(set) var hasOpaqueDrawingData = false

    static func parse(_ data: Data) throws -> OOXMLWordBody {
        try OOXMLTree.preflight(data)
        let delegate = OOXMLWordBody()
        let parser = XMLParser(data: data)
        parser.shouldProcessNamespaces = true
        parser.shouldReportNamespacePrefixes = true
        parser.shouldResolveExternalEntities = false
        parser.externalEntityResolvingPolicy = .never
        parser.delegate = delegate
        guard parser.parse(), delegate.failure == nil, delegate.stack.isEmpty,
              delegate.sawRoot, delegate.bodyCount == 1, delegate.activeParagraphs == 0 else {
            throw delegate.failure ?? OOXMLReaderError.malformed
        }
        return delegate
    }

    private func reject(_ parser: XMLParser, _ error: OOXMLReaderError) {
        if failure == nil { failure = error }
        parser.abortParsing()
    }

    private func countEvent(_ parser: XMLParser) -> Bool {
        eventCount += 1
        guard eventCount <= 2_000_000 else { reject(parser, .limitExceeded); return false }
        return failure == nil
    }

    func parser(_ parser: XMLParser, didStartMappingPrefix prefix: String, toURI namespaceURI: String) {
        guard countEvent(parser) else { return }
        guard prefix.utf8.count <= 256, namespaceURI.utf8.count <= 4_096, mappingCount < 1_024 else {
            reject(parser, .limitExceeded); return
        }
        mappings[prefix, default: []].append(namespaceURI)
        mappingCount += 1
    }

    func parser(_ parser: XMLParser, didEndMappingPrefix prefix: String) {
        guard countEvent(parser) else { return }
        guard var current = mappings[prefix], !current.isEmpty else { reject(parser, .malformed); return }
        current.removeLast()
        mappingCount -= 1
        mappings[prefix] = current.isEmpty ? nil : current
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String]) {
        guard countEvent(parser) else { return }
        guard stack.count < 128, elementName.utf8.count <= 256,
              (namespaceURI?.utf8.count ?? 0) <= 4_096, attributeDict.count <= 64 else {
            reject(parser, .limitExceeded); return
        }
        guard stack.last?.textLeaf != true else { reject(parser, .malformed); return }
        var attributeNames = Set<OOXMLAttributeName>()
        for (qualified, value) in attributeDict {
            if qualified == "xmlns" || qualified.hasPrefix("xmlns:") { continue }
            let pieces = qualified.split(separator: ":", omittingEmptySubsequences: false)
            let key: OOXMLAttributeName
            if pieces.count == 1 { key = OOXMLAttributeName(namespaceURI: "", localName: qualified) }
            else if pieces.count == 2, let uri = mappings[String(pieces[0])]?.last, !pieces[1].isEmpty {
                key = OOXMLAttributeName(namespaceURI: uri, localName: String(pieces[1]))
            } else { reject(parser, .malformed); return }
            guard attributeNames.insert(key).inserted else { reject(parser, .malformed); return }
            let valueBytes = value.utf8.count
            attributeBytes += qualified.utf8.count + valueBytes
            let opaqueDrawing = key.namespaceURI == "urn:schemas-microsoft-com:office:office" && key.localName == "gfxdata"
            guard qualified.utf8.count <= 256,
                  valueBytes <= (opaqueDrawing ? 16 * 1_024 * 1_024 : 8_192),
                  attributeBytes <= 16 * 1_024 * 1_024 else { reject(parser, .limitExceeded); return }
            if opaqueDrawing && valueBytes > 8_192 { hasOpaqueDrawingData = true }
        }

        let word = namespaceURI.map(OOXMLNamespaces.word.contains) == true
        if stack.isEmpty {
            guard !sawRoot, word, elementName == "document" else { reject(parser, .malformed); return }
            sawRoot = true
        }
        let isBody = word && elementName == "body"
        if isBody {
            guard stack.count == 1, stack[0].localName == "document", bodyCount == 0 else {
                reject(parser, .malformed); return
            }
            bodyCount += 1
        }
        let insideBody = isBody || stack.last?.insideBody == true
        var suppressed = stack.last?.suppressed ?? false
        if insideBody, word, elementName == "altChunk" || elementName == "subDoc" {
            reject(parser, .unsupported); return
        }
        if insideBody, word, elementName == "del" || elementName == "moveFrom" { suppressed = true }
        if insideBody, namespaceURI == OOXMLNamespaces.compatibility, elementName == "AlternateContent" {
            // Selecting a rendered branch requires Office feature negotiation.
            // Suppress the entire region while continuing full XML validation.
            hasCompatibility = true
            suppressed = true
        }
        let activeParagraph = insideBody && word && elementName == "p" && !suppressed
        if activeParagraph {
            if paragraphCount > 0 { text.append("\n") }
            paragraphCount += 1
            activeParagraphs += 1
        }
        let textLeaf = word && elementName == "t"
        let capturesText = insideBody && textLeaf && !suppressed
        if capturesText, activeParagraphs == 0 { reject(parser, .malformed); return }
        if insideBody && word && !suppressed && activeParagraphs > 0 {
            switch elementName {
            case "tab": text.append("\t")
            case "br", "cr": text.append("\n")
            case "noBreakHyphen": text.append("\u{2011}")
            case "softHyphen": text.append("\u{00AD}")
            case "sym": hasSymbols = true
            default: break
            }
        }
        stack.append(Frame(localName: elementName, namespaceURI: namespaceURI,
                           insideBody: insideBody, suppressed: suppressed,
                           activeParagraph: activeParagraph, textLeaf: textLeaf, capturesText: capturesText))
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        guard countEvent(parser) else { return }
        guard let frame = stack.last, frame.localName == elementName, frame.namespaceURI == namespaceURI else {
            reject(parser, .malformed); return
        }
        if frame.activeParagraph { activeParagraphs -= 1 }
        stack.removeLast()
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard countEvent(parser) else { return }
        if stack.last?.capturesText == true { text.append(string) }
    }
    func parser(_ parser: XMLParser, foundIgnorableWhitespace whitespaceString: String) {
        guard countEvent(parser) else { return }
        if stack.last?.capturesText == true { text.append(whitespaceString) }
    }
    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        guard countEvent(parser) else { return }
        guard let string = String(data: CDATABlock, encoding: .utf8) else { reject(parser, .malformed); return }
        if stack.last?.capturesText == true { text.append(string) }
    }
    func parser(_ parser: XMLParser, foundComment comment: String) { _ = countEvent(parser) }
    func parser(_ parser: XMLParser, foundProcessingInstructionWithTarget target: String, data: String?) { _ = countEvent(parser) }
    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) { reject(parser, .malformed) }
    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) { reject(parser, .malformed) }
    func parser(_ parser: XMLParser, foundUnparsedEntityDeclarationWithName name: String, publicID: String?, systemID: String?, notationName: String?) { reject(parser, .malformed) }
    func parser(_ parser: XMLParser, resolveExternalEntityName name: String, systemID: String?) -> Data? { reject(parser, .malformed); return nil }
    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) { if failure == nil { failure = .malformed } }
    func parser(_ parser: XMLParser, validationErrorOccurred validationError: Error) { reject(parser, .malformed) }
}

/// Bounds the retained tree independently of output clipping. Only text-bearing
/// leaves retain SAX character data; indentation and arbitrary node text do not.
private final class OOXMLTree: NSObject, XMLParserDelegate {
    private var root: OOXMLNode?
    private var stack: [OOXMLNode] = []
    private var mappings: [String: [String]] = ["xml": ["http://www.w3.org/XML/1998/namespace"]]
    private var mappingCount = 1
    private var elementCount = 0
    private var attributeBytes = 0
    private var textBytes = 0
    private var failure: OOXMLReaderError?

    static func parse(_ data: Data) throws -> OOXMLNode {
        try preflight(data)
        let delegate = OOXMLTree()
        let parser = XMLParser(data: data)
        parser.shouldProcessNamespaces = true
        parser.shouldReportNamespacePrefixes = true
        parser.shouldResolveExternalEntities = false
        parser.externalEntityResolvingPolicy = .never
        parser.delegate = delegate
        guard parser.parse(), delegate.failure == nil, delegate.stack.isEmpty, let root = delegate.root else {
            throw delegate.failure ?? OOXMLReaderError.malformed
        }
        return root
    }

    static func preflight(_ data: Data) throws {
        guard !data.isEmpty else { throw OOXMLReaderError.malformed }
        guard data.count <= 16 * 1_024 * 1_024 else { throw OOXMLReaderError.limitExceeded }
        // The bounded reader deliberately supports UTF-8 XML only (including
        // its BOM). Reject UTF-16/32 before XMLParser can expand declarations.
        guard !data.contains(0), let utf8 = String(data: data, encoding: .utf8) else { throw OOXMLReaderError.unsupported }
        try validateEncodingDeclaration(utf8)
        guard !hasForbiddenDeclaration(data) else { throw OOXMLReaderError.malformed }
    }

    private static func validateEncodingDeclaration(_ string: String) throws {
        var xml = string[...]
        if xml.hasPrefix("\u{FEFF}") { xml = xml.dropFirst() }
        guard xml.hasPrefix("<?xml"), let next = xml.dropFirst(5).first,
              [" ", "\t", "\r", "\n"].contains(next) else { return }
        // The XML declaration must be short and only declare the byte encoding
        // already checked above; XMLParser must not reinterpret UTF-8 as another
        // charset after the DTD preflight has examined the original bytes.
        let prefix = String(xml.prefix(4_096))
        guard let end = prefix.range(of: "?>") else { throw OOXMLReaderError.limitExceeded }
        let declaration = String(prefix[..<end.upperBound])
        guard declaration.utf8.count <= 4_096 else { throw OOXMLReaderError.limitExceeded }
        let pattern = try NSRegularExpression(pattern: #"(?i)\bencoding\s*=\s*["']([^"']+)["']"#)
        if let match = pattern.firstMatch(in: declaration, range: NSRange(declaration.startIndex..., in: declaration)),
           let range = Range(match.range(at: 1), in: declaration),
           !["utf-8", "utf8"].contains(declaration[range].lowercased()) {
            throw OOXMLReaderError.unsupported
        }
    }

    private static func hasForbiddenDeclaration(_ data: Data) -> Bool {
        let patterns = [Array("<!DOCTYPE".utf8), Array("<!ENTITY".utf8)]
        var positions = [0, 0]
        for original in data {
            if original == 0 { continue }
            let byte = (97...122).contains(original) ? original - 32 : original
            for index in patterns.indices {
                if byte == patterns[index][positions[index]] { positions[index] += 1 }
                else { positions[index] = byte == patterns[index][0] ? 1 : 0 }
                if positions[index] == patterns[index].count { return true }
            }
        }
        return false
    }

    private func reject(_ parser: XMLParser, _ error: OOXMLReaderError) {
        if failure == nil { failure = error }
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, didStartMappingPrefix prefix: String, toURI namespaceURI: String) {
        guard prefix.utf8.count <= 256, namespaceURI.utf8.count <= 4_096,
              mappingCount < 1_024 else { reject(parser, .limitExceeded); return }
        mappings[prefix, default: []].append(namespaceURI)
        mappingCount += 1
    }
    func parser(_ parser: XMLParser, didEndMappingPrefix prefix: String) {
        guard var current = mappings[prefix], !current.isEmpty else { reject(parser, .malformed); return }
        current.removeLast()
        mappingCount -= 1
        mappings[prefix] = current.isEmpty ? nil : current
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String]) {
        elementCount += 1
        guard elementCount <= 200_000, stack.count < 128, elementName.utf8.count <= 256,
              (namespaceURI?.utf8.count ?? 0) <= 4_096, attributeDict.count <= 64 else { reject(parser, .limitExceeded); return }
        var attributes: [OOXMLAttributeName: String] = [:]
        for (qualified, value) in attributeDict {
            if qualified == "xmlns" || qualified.hasPrefix("xmlns:") { continue }
            attributeBytes += qualified.utf8.count + value.utf8.count
            guard qualified.utf8.count <= 256, value.utf8.count <= 8_192,
                  attributeBytes <= 4 * 1_024 * 1_024 else { reject(parser, .limitExceeded); return }
            let pieces = qualified.split(separator: ":", omittingEmptySubsequences: false)
            let key: OOXMLAttributeName
            if pieces.count == 1 { key = OOXMLAttributeName(namespaceURI: "", localName: qualified) }
            else if pieces.count == 2, let uri = mappings[String(pieces[0])]?.last, !pieces[1].isEmpty {
                key = OOXMLAttributeName(namespaceURI: uri, localName: String(pieces[1]))
            } else { reject(parser, .malformed); return }
            guard attributes.updateValue(value, forKey: key) == nil else { reject(parser, .malformed); return }
        }
        let node = OOXMLNode(localName: elementName, namespaceURI: namespaceURI, attributes: attributes)
        if let parent = stack.last {
            guard !parent.capturesText else { reject(parser, .malformed); return }
            parent.children.append(node)
        }
        else if root == nil { root = node }
        else { reject(parser, .malformed); return }
        stack.append(node)
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        guard let node = stack.last, node.localName == elementName, node.namespaceURI == namespaceURI else { reject(parser, .malformed); return }
        stack.removeLast()
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) { retain(string, parser: parser) }
    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        guard let string = String(data: CDATABlock, encoding: .utf8) else { reject(parser, .malformed); return }
        retain(string, parser: parser)
    }
    private func retain(_ string: String, parser: XMLParser) {
        guard let node = stack.last, node.capturesText else { return }
        textBytes += string.utf8.count
        guard textBytes <= 8 * 1_024 * 1_024 else { reject(parser, .limitExceeded); return }
        node.text.append(string)
    }

    func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) { reject(parser, .malformed) }
    func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) { reject(parser, .malformed) }
    func parser(_ parser: XMLParser, foundUnparsedEntityDeclarationWithName name: String, publicID: String?, systemID: String?, notationName: String?) { reject(parser, .malformed) }
    func parser(_ parser: XMLParser, resolveExternalEntityName name: String, systemID: String?) -> Data? { reject(parser, .malformed); return nil }
    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) { if failure == nil { failure = .malformed } }
    func parser(_ parser: XMLParser, validationErrorOccurred validationError: Error) { reject(parser, .malformed) }
}

private struct OOXMLTextBuffer {
    private let maximumBytes: Int
    private(set) var byteCount = 0
    private(set) var value = ""
    private(set) var isTruncated = false

    init(maximumBytes: Int) { self.maximumBytes = max(0, maximumBytes) }
    mutating func markTruncated() { isTruncated = true }
    mutating func append(_ string: String) {
        guard !string.isEmpty else { return }
        if isTruncated { return }
        let available = maximumBytes - byteCount
        guard available > 0 else { isTruncated = true; return }
        let count = string.utf8.count
        if count <= available { value.append(string); byteCount += count; return }
        var boundary = string.unicodeScalars.startIndex
        var copied = 0
        for scalar in string.unicodeScalars {
            let scalarBytes = scalar.utf8.count
            guard copied + scalarBytes <= available else { break }
            copied += scalarBytes
            boundary = string.unicodeScalars.index(after: boundary)
        }
        value.append(contentsOf: string[..<boundary])
        byteCount += copied
        isTruncated = true
    }
}
