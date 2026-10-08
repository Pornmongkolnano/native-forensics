import CryptoKit
import Foundation

public struct MultiEvidenceRange: Codable, Equatable, Sendable {
    public let start: Int
    public let end: Int
    public init(start: Int, end: Int) { self.start = start; self.end = end }
    public var count: Int {
        let result = end.subtractingReportingOverflow(start)
        return result.overflow ? -1 : result.partialValue
    }
}

public struct MultiEvidenceSelection: Equatable, Sendable {
    public let ranges: [MultiEvidenceRange]
    public let redactions: [MultiEvidenceRange]
    public let pdfRanges: [MultiEvidencePDFRange]
    public let pdfRedactions: [MultiEvidencePDFRange]
    public init(ranges: [MultiEvidenceRange], redactions: [MultiEvidenceRange] = []) {
        self.ranges = ranges; self.redactions = redactions; self.pdfRanges = []; self.pdfRedactions = []
    }
    public init(pdfRanges: [MultiEvidencePDFRange], pdfRedactions: [MultiEvidencePDFRange] = []) {
        self.ranges = []; self.redactions = []; self.pdfRanges = pdfRanges; self.pdfRedactions = pdfRedactions
    }
}

/// Complete verified bytes stay local. Only explicitly selected non-redacted
/// segments are copied into an outbound request or a full-retention sidecar.
public struct MultiEvidenceVerifiedFile: Sendable {
    public let binding: CaseWorkBinding
    public let receipt: VerifiedContentReceipt
    public let bytes: Data
    public let pdf: MultiEvidenceVerifiedPDF?
    public init(binding: CaseWorkBinding, content: VerifiedContent) throws {
        try binding.validate()
        guard !binding.selectedEntry.isDirectory, content.bytes.count <= VerifiedContentService.maximumFileBytes,
              Int64(content.bytes.count) == binding.selectedEntry.size,
              content.receipt.byteCount == binding.selectedEntry.size,
              content.receipt.evidenceID == binding.evidenceID, content.receipt.fileID == binding.selectedEntry.id,
              content.receipt.orderedContainerSHA256 == binding.containerHashes.map(\.sha256),
              MultiEvidenceCoding.digest(content.bytes) == content.receipt.sha256,
              String(data: content.bytes, encoding: .utf8) != nil else { throw MultiEvidenceError.invalidContent }
        self.binding = binding; self.receipt = content.receipt; bytes = content.bytes; pdf = nil
    }
    public init(binding: CaseWorkBinding, preview: FilesystemDocumentPreview) throws {
        pdf = try MultiEvidenceVerifiedPDF(binding: binding, preview: preview)
        self.binding = binding; self.receipt = preview.receipt; bytes = Data()
    }
    public var isPDF: Bool { pdf != nil }
    public var text: String { String(decoding: bytes, as: UTF8.self) }
    public var previewByteCount: Int {
        guard let pdf else { return defaultSelection.ranges.first?.end ?? 0 }
        return defaultSelection.pdfRanges.reduce(0) { total, span in
            guard let page = pdf.analysis.textPages.first(where: { $0.pageNumber == span.pageNumber }),
                  let text = try? MultiEvidencePDFText.slice(page.text, range: span.range) else { return total }
            return total + text.utf8.count
        }
    }
    public var previewText: String {
        guard let pdf else { return String(decoding: bytes.prefix(previewByteCount), as: UTF8.self) }
        return defaultSelection.pdfRanges.compactMap { span in
            guard let page = pdf.analysis.textPages.first(where: { $0.pageNumber == span.pageNumber }),
                  let text = try? MultiEvidencePDFText.slice(page.text, range: span.range) else { return nil }
            return "[Page \(span.pageNumber), raw derived UTF-16 \(span.range.start):\(span.range.end)]\n\(text)"
        }.joined(separator: "\n\n")
    }
    public var defaultSelection: MultiEvidenceSelection {
        if let pdf { return .init(pdfRanges: MultiEvidencePDFText.defaultSelection(pdf)) }
        var end = min(bytes.count, MultiEvidenceContext.maximumExcerptBytes)
        while end > 0 && String(data: bytes.prefix(end), encoding: .utf8) == nil { end -= 1 }
        return MultiEvidenceSelection(ranges: end == 0 ? [] : [.init(start: 0, end: end)])
    }
}

public struct MultiEvidenceSegment: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    /// Present only for original UTF-8 source-file byte coordinates.
    public let sourceRange: MultiEvidenceRange?
    public let disclosedSHA256: String
    public let byteCount: Int
    public let text: String?
    /// PDF positions are page/raw-derived UTF-16; never original PDF bytes.
    public let pdfRange: MultiEvidencePDFRange?
    public init(id: String, sourceRange: MultiEvidenceRange?, disclosedSHA256: String, byteCount: Int,
                text: String?, pdfRange: MultiEvidencePDFRange? = nil) {
        self.id = id; self.sourceRange = sourceRange; self.disclosedSHA256 = disclosedSHA256
        self.byteCount = byteCount; self.text = text; self.pdfRange = pdfRange
    }
}

public struct MultiEvidenceDisclosure: Codable, Equatable, Sendable {
    public let binding: CaseWorkBinding
    public let contentSHA256: String
    public let verifiedAt: Date
    public let selectedRanges: [MultiEvidenceRange]
    public let redactedRanges: [MultiEvidenceRange]
    public let segments: [MultiEvidenceSegment]
    public let disclosedByteCount: Int
    public let omittedByteCount: Int
    public let pdf: MultiEvidencePDFDisclosure?
    public init(binding: CaseWorkBinding, contentSHA256: String, verifiedAt: Date,
                selectedRanges: [MultiEvidenceRange], redactedRanges: [MultiEvidenceRange],
                segments: [MultiEvidenceSegment], disclosedByteCount: Int, omittedByteCount: Int,
                pdf: MultiEvidencePDFDisclosure? = nil) {
        self.binding = binding; self.contentSHA256 = contentSHA256; self.verifiedAt = verifiedAt
        self.selectedRanges = selectedRanges; self.redactedRanges = redactedRanges; self.segments = segments
        self.disclosedByteCount = disclosedByteCount; self.omittedByteCount = omittedByteCount; self.pdf = pdf
    }
}

public struct MultiEvidenceContext: Codable, Equatable, Sendable {
    public static let maximumExcerptBytes = 32_768
    public static let maximumAggregateBytes = 65_536
    public static let maximumRequestBytes = 192 * 1_024
    public static let transformationVersion = "utf8-byte-ranges-minus-redactions.v1"
    public let schemaVersion: Int
    public let transformation: String
    public let files: [MultiEvidenceDisclosure]
    public let warnings: [String]

    public static func make(files: [MultiEvidenceVerifiedFile], selections: [MultiEvidenceSelection]) throws -> Self {
        guard files.count == 2, selections.count == 2,
              files[0].binding.caseID == files[1].binding.caseID,
              files[0].binding.evidenceID == files[1].binding.evidenceID,
              files[0].binding.snapshotSHA256 == files[1].binding.snapshotSHA256,
              files[0].binding.locatorSHA256 != files[1].binding.locatorSHA256 else { throw MultiEvidenceError.invalidSelection }
        let disclosures = try files.enumerated().map { index, file -> MultiEvidenceDisclosure in
            let selection = selections[index]
            if file.isPDF { return try makePDFDisclosure(file: file, selection: selection, index: index) }
            guard selection.pdfRanges.isEmpty, selection.pdfRedactions.isEmpty else { throw MultiEvidenceError.invalidSelection }
            try validateRanges(selection.ranges, bytes: file.bytes)
            try validateRanges(selection.redactions, bytes: file.bytes)
            let spans = Self.visibleRanges(selected: selection.ranges, redacted: selection.redactions)
            guard spans.count <= 64 else { throw MultiEvidenceError.budgetExceeded }
            let total = spans.reduce(0) { $0 + $1.count }
            guard total <= maximumExcerptBytes else { throw MultiEvidenceError.budgetExceeded }
            let segments = try spans.enumerated().map { offset, range -> MultiEvidenceSegment in
                let bytes = file.bytes.subdata(in: range.start..<range.end)
                guard let text = String(data: bytes, encoding: .utf8), !bytes.contains(0) else { throw MultiEvidenceError.invalidContent }
                return MultiEvidenceSegment(id: "\(index == 0 ? "A" : "B")\(offset + 1)", sourceRange: range,
                    disclosedSHA256: MultiEvidenceCoding.digest(bytes), byteCount: bytes.count, text: text)
            }
            return MultiEvidenceDisclosure(binding: file.binding, contentSHA256: file.receipt.sha256,
                verifiedAt: file.receipt.verifiedAt, selectedRanges: selection.ranges, redactedRanges: selection.redactions,
                segments: segments, disclosedByteCount: total, omittedByteCount: file.bytes.count - total)
        }
        let includesPDF = files.contains(where: \.isPDF)
        let context = Self(schemaVersion: includesPDF ? 2 : 1,
            transformation: includesPDF ? pdfTransformationVersion : transformationVersion, files: disclosures,
            warnings: [(includesPDF ? "Only selected, non-redacted text was disclosed. PDF positions refer to raw derived page UTF-16, never original PDF bytes; omitted text and visual/OCR coverage are unknown."
                : "Only selected, non-redacted UTF-8 byte ranges were disclosed; omitted content is unknown."),
                "Source containers and extracted file bytes were verified; recorded filesystem metadata and logical image hashes were not refreshed.",
                "References resolve disclosed bytes, not the correctness of an AI interpretation."])
        try context.validate(requireText: true)
        return context
    }

    public func withoutText() -> Self {
        Self(schemaVersion: schemaVersion, transformation: transformation, files: files.map { file in
            MultiEvidenceDisclosure(binding: file.binding, contentSHA256: file.contentSHA256, verifiedAt: file.verifiedAt,
                selectedRanges: file.selectedRanges, redactedRanges: file.redactedRanges,
                segments: file.segments.map { $0.withoutText() },
                disclosedByteCount: file.disclosedByteCount, omittedByteCount: file.omittedByteCount, pdf: file.pdf)
        }, warnings: warnings)
    }

    func validate(requireText: Bool) throws {
        guard ((schemaVersion == 1 && transformation == Self.transformationVersion && files.allSatisfy { $0.pdf == nil })
                || (schemaVersion == 2 && transformation == Self.pdfTransformationVersion && files.contains { $0.pdf != nil })), files.count == 2,
              files[0].binding.caseID == files[1].binding.caseID, files[0].binding.evidenceID == files[1].binding.evidenceID,
              files[0].binding.snapshotSHA256 == files[1].binding.snapshotSHA256,
              files[0].binding.locatorSHA256 != files[1].binding.locatorSHA256,
              warnings.count <= 32, warnings.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) else { throw MultiEvidenceError.invalidSelection }
        for (index, file) in files.enumerated() {
            try file.binding.validate()
            guard !file.binding.selectedEntry.isDirectory,
                  (0...(file.pdf == nil ? VerifiedContentService.maximumFileBytes : DocumentLimits.maximumInputBytes)).contains(file.binding.selectedEntry.size),
                  EngineValidation.validHash(file.contentSHA256), file.verifiedAt.timeIntervalSince1970.isFinite,
                  (0...Self.maximumExcerptBytes).contains(file.disclosedByteCount),
                  file.segments.count <= 64, file.selectedRanges.count <= 32, file.redactedRanges.count <= 32 else { throw MultiEvidenceError.invalidContent }
            if file.pdf != nil { try Self.validatePDFFile(file, index: index, requireText: requireText); continue }
            guard file.disclosedByteCount <= Int(file.binding.selectedEntry.size),
                  file.omittedByteCount == Int(file.binding.selectedEntry.size) - file.disclosedByteCount else { throw MultiEvidenceError.invalidContent }
            try Self.validateRanges(file.selectedRanges, size: Int(file.binding.selectedEntry.size))
            try Self.validateRanges(file.redactedRanges, size: Int(file.binding.selectedEntry.size))
            guard file.segments.compactMap(\.sourceRange) == Self.visibleRanges(selected: file.selectedRanges, redacted: file.redactedRanges) else {
                throw MultiEvidenceError.invalidContent
            }
            var last = 0, disclosedTotal = 0
            for (offset, segment) in file.segments.enumerated() {
                guard let source = segment.sourceRange, segment.pdfRange == nil,
                      segment.id == "\(index == 0 ? "A" : "B")\(offset + 1)", source.start >= last,
                      source.start >= 0, source.end > source.start,
                      source.end <= Int(file.binding.selectedEntry.size),
                      (1...Self.maximumExcerptBytes).contains(segment.byteCount),
                      source.count == segment.byteCount,
                      file.selectedRanges.contains(where: { $0.start <= source.start && $0.end >= source.end }),
                      !file.redactedRanges.contains(where: { $0.start < source.end && $0.end > source.start }),
                      EngineValidation.validHash(segment.disclosedSHA256) else { throw MultiEvidenceError.invalidContent }
                last = source.end; disclosedTotal += segment.byteCount
                if requireText {
                    guard let text = segment.text, text.utf8.count == segment.byteCount, !text.utf8.contains(0),
                          MultiEvidenceCoding.digest(Data(text.utf8)) == segment.disclosedSHA256 else { throw MultiEvidenceError.invalidContent }
                } else if segment.text != nil { throw MultiEvidenceError.invalidContent }
            }
            guard disclosedTotal == file.disclosedByteCount else { throw MultiEvidenceError.invalidContent }
        }
        // Counts are bounded above before arithmetic on untrusted sidecars.
        guard files.reduce(0, { $0 + $1.disclosedByteCount }) <= Self.maximumAggregateBytes else { throw MultiEvidenceError.budgetExceeded }
        guard files.filter({ $0.pdf != nil }).reduce(0, { $0 + $1.disclosedByteCount }) <= MultiEvidencePDFLimits.maximumPDFAggregateBytes else {
            throw MultiEvidenceError.budgetExceeded
        }
    }

    private static func visibleRanges(selected: [MultiEvidenceRange], redacted: [MultiEvidenceRange]) -> [MultiEvidenceRange] {
        var spans = selected
        for hidden in redacted {
            spans = spans.flatMap { span in
                guard hidden.start < span.end, hidden.end > span.start else { return [span] }
                var remaining: [MultiEvidenceRange] = []
                if span.start < hidden.start { remaining.append(.init(start: span.start, end: hidden.start)) }
                if hidden.end < span.end { remaining.append(.init(start: hidden.end, end: span.end)) }
                return remaining
            }
        }
        return spans
    }
    private static func validateRanges(_ ranges: [MultiEvidenceRange], bytes: Data) throws {
        try validateRanges(ranges, size: bytes.count)
        for range in ranges {
            guard String(data: bytes.prefix(range.start), encoding: .utf8) != nil,
                  String(data: bytes.prefix(range.end), encoding: .utf8) != nil else { throw MultiEvidenceError.invalidRange }
        }
    }
    private static func validateRanges(_ ranges: [MultiEvidenceRange], size: Int) throws {
        guard ranges.count <= 32 else { throw MultiEvidenceError.budgetExceeded }
        var end = 0
        for range in ranges {
            guard range.start >= end, range.start >= 0, range.end > range.start, range.end <= size else { throw MultiEvidenceError.invalidRange }
            end = range.end
        }
    }
}

public enum MultiEvidenceContextBuilder {
    public static func prepare(caseID: UUID, evidence: EvidenceRecord, result: EnumerationResult,
                               files: [FilesystemEntry], engine: EngineClient,
                               documents: DocumentAnalysisClient = DocumentAnalysisClient()) async throws -> [MultiEvidenceVerifiedFile] {
        guard files.count == 2, files[0].id != files[1].id else { throw MultiEvidenceError.invalidSelection }
        var prepared: [MultiEvidenceVerifiedFile] = []
        for file in files {
            try Task.checkCancellation()
            let binding = try CaseWorkBinding.make(caseID: caseID, evidence: evidence, result: result, file: file)
            guard file.size <= DocumentLimits.maximumInputBytes else { throw MultiEvidenceError.invalidContent }
            if file.size > VerifiedContentService.maximumFileBytes {
                let preview = try await FilesystemDocumentPreviewService(engine: engine, documents: documents)
                    .preview(evidence: evidence, result: result, file: file)
                prepared.append(try MultiEvidenceVerifiedFile(binding: binding, preview: preview)); continue
            }
            let content = try await VerifiedContentService.extract(evidence: evidence, result: result, file: file, engine: engine)
            if content.bytes.starts(with: Data("%PDF-".utf8)) {
                let preview = try await FilesystemDocumentPreviewService(engine: engine, documents: documents)
                    .preview(evidence: evidence, result: result, file: file)
                guard preview.receipt.sha256 == content.receipt.sha256 else { throw MultiEvidenceError.invalidContent }
                prepared.append(try MultiEvidenceVerifiedFile(binding: binding, preview: preview))
            } else { prepared.append(try MultiEvidenceVerifiedFile(binding: binding, content: content)) }
        }
        return prepared
    }
}

public enum MultiEvidenceError: Error, Equatable, Sendable, LocalizedError {
    case invalidSelection, invalidContent, invalidRange, budgetExceeded, staleReference, requestMismatch, parentMismatch
    public var errorDescription: String? {
        switch self {
        case .invalidSelection: "Choose two distinct regular files from the same evidence and saved analysis."
        case .invalidContent: "Choose verified UTF-8 content up to 1 MiB or a freshly decoded, provenance-bound PDF up to 128 MiB. Nothing was disclosed."
        case .invalidRange: "Use ordered, disjoint UTF-8 source-byte ranges, or PDF page/raw-derived UTF-16 ranges, at Unicode scalar boundaries."
        case .budgetExceeded: "Disclosure exceeds the bounded excerpt, range, prior-answer or serialized request budget."
        case .staleReference: "This citation is historical, stale or unavailable; verify the original context before using it."
        case .requestMismatch: "The exact reviewed request no longer matches this selection or answer."
        case .parentMismatch: "The follow-up parent does not belong to this exact case, evidence and snapshot."
        }
    }
}

enum MultiEvidenceCoding {
    static func encode<T: Encodable>(_ value: T) throws -> Data { try CaseWorkCoding.encode(value) }
    static func digest(_ bytes: Data) -> String { CaseWorkCoding.hex(SHA256.hash(data: bytes)) }
}
