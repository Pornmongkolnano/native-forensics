import Foundation

struct RecoveryReportedArtifact: Equatable {
    let filename: String
    let byteCount: Int64
    let byteRuns: [RecoveryByteRun]
}

/// Bounded SAX parsing. Recovery XML is tool output, not a trusted instruction
/// or filesystem path. No entity, DTD or external-resource resolution is used.
enum RecoveryReportParser {
    static let maximumReportBytes = 32 * 1_048_576
    static func parse(_ data: Data, sourceSize: Int64, maximumFiles: Int) throws -> [RecoveryReportedArtifact] {
        try Task.checkCancellation()
        guard data.count <= maximumReportBytes, let text = String(data: data, encoding: .utf8),
              !text.contains("<!DOCTYPE"), !text.contains("<!ENTITY") else { throw RecoveryError.invalidReport }
        let delegate = ReportDelegate(sourceSize: sourceSize, maximumFiles: maximumFiles)
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        let parsed = parser.parse()
        if delegate.cancelled { throw CancellationError() }
        try Task.checkCancellation()
        guard parsed, delegate.failure == nil, delegate.rootSeen,
              delegate.elements.isEmpty, delegate.sourceSize == sourceSize else { throw delegate.failure ?? RecoveryError.invalidReport }
        return delegate.artifacts
    }
}

private final class ReportDelegate: NSObject, XMLParserDelegate {
    let expectedSourceSize: Int64
    let maximumFiles: Int
    var sourceSize: Int64?
    var rootSeen = false
    var artifacts: [RecoveryReportedArtifact] = []
    var elements: [String] = []
    var failure: RecoveryError?
    var cancelled = false
    private var text = ""
    private var filename: String?
    private var byteCount: Int64?
    private var runs: [RecoveryByteRun] = []
    private var isFile = false
    private var totalElements = 0
    private var totalRuns = 0
    private var fileByteRunsSeen = false
    private var sourceSeen = false

    init(sourceSize: Int64, maximumFiles: Int) { expectedSourceSize = sourceSize; self.maximumFiles = maximumFiles }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        guard failure == nil else { return }
        totalElements += 1
        if totalElements.isMultiple(of: 128), Task.isCancelled { cancelled = true; parser.abortParsing(); return }
        guard elements.count < 32, totalElements <= 300_000 else { stop(parser, .outputLimit); return }
        guard !["filename", "filesize", "image_size"].contains(elements.last ?? "") else { stop(parser); return }
        if elements.isEmpty {
            guard !rootSeen, elementName == "dfxml" else { stop(parser); return }
            rootSeen = true
        }
        elements.append(elementName)
        text = ""
        if elementName == "source" {
            guard !sourceSeen, elements.elementsEqual(["dfxml", "source"]) else { stop(parser); return }
            sourceSeen = true
        }
        if elementName == "fileobject" {
            guard !isFile, elements.count == 2, artifacts.count < maximumFiles else { stop(parser, .outputLimit); return }
            isFile = true; filename = nil; byteCount = nil; runs = []; fileByteRunsSeen = false
        }
        if elementName == "byte_runs", isFile {
            guard !fileByteRunsSeen, elements.elementsEqual(["dfxml", "fileobject", "byte_runs"]) else { stop(parser); return }
            fileByteRunsSeen = true
        }
        if elementName == "byte_run", isFile {
            guard elements.suffix(3).elementsEqual(["fileobject", "byte_runs", "byte_run"]),
                  runs.count < 8_192, totalRuns < 50_000,
                  let output = integer(attributeDict["offset"]),
                  let source = integer(attributeDict["img_offset"]),
                  let length = integer(attributeDict["len"]), length > 0,
                  source <= expectedSourceSize, length <= expectedSourceSize - source,
                  output <= Int64.max - length else { stop(parser); return }
            runs.append(RecoveryByteRun(outputOffset: output, sourceOffset: source, length: length))
            totalRuns += 1
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard failure == nil else { return }
        if Task.isCancelled { cancelled = true; parser.abortParsing(); return }
        guard text.utf8.count + string.utf8.count <= 8_192 else { stop(parser, .outputLimit); return }
        text += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        guard failure == nil, elements.last == elementName else { stop(parser); return }
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if elements.elementsEqual(["dfxml", "source", "image_size"]) {
            guard sourceSize == nil, let number = integer(value) else { stop(parser); return }
            sourceSize = number
        }
        if isFile, elements.count == 3 {
            if elementName == "filename" {
                guard filename == nil, !value.isEmpty, value.utf8.count <= 4_096,
                      !value.utf8.contains(0) else { stop(parser); return }
                filename = value
            } else if elementName == "filesize" {
                guard byteCount == nil, let number = integer(value) else { stop(parser); return }
                byteCount = number
            }
        }
        if elementName == "fileobject" {
            guard let filename, let byteCount else { stop(parser); return }
            artifacts.append(RecoveryReportedArtifact(filename: filename, byteCount: byteCount, byteRuns: runs))
            isFile = false
        }
        elements.removeLast()
        text = ""
    }

    func parser(_ parser: XMLParser, resolveExternalEntityName name: String, systemID: String?) -> Data? {
        stop(parser); return nil
    }

    private func integer(_ value: String?) -> Int64? {
        guard let value, !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
        return Int64(value)
    }
    private func stop(_ parser: XMLParser, _ error: RecoveryError = .invalidReport) {
        failure = error; parser.abortParsing()
    }
}
