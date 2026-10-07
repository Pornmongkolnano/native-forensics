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
    public init(ranges: [MultiEvidenceRange], redactions: [MultiEvidenceRange] = []) {
        self.ranges = ranges; self.redactions = redactions
    }
}

/// Complete verified bytes stay local. Only explicitly selected non-redacted
/// segments are copied into an outbound request or a full-retention sidecar.
public struct MultiEvidenceVerifiedFile: Sendable {
    public let binding: CaseWorkBinding
    public let receipt: VerifiedContentReceipt
    public let bytes: Data
    public init(binding: CaseWorkBinding, content: VerifiedContent) throws {
        try binding.validate()
        guard !binding.selectedEntry.isDirectory, content.bytes.count <= VerifiedContentService.maximumFileBytes,
              Int64(content.bytes.count) == binding.selectedEntry.size,
              content.receipt.byteCount == binding.selectedEntry.size,
              content.receipt.evidenceID == binding.evidenceID, content.receipt.fileID == binding.selectedEntry.id,
              content.receipt.orderedContainerSHA256 == binding.containerHashes.map(\.sha256),
              MultiEvidenceCoding.digest(content.bytes) == content.receipt.sha256,
              String(data: content.bytes, encoding: .utf8) != nil else { throw MultiEvidenceError.invalidContent }
        self.binding = binding; self.receipt = content.receipt; bytes = content.bytes
    }
    public var text: String { String(decoding: bytes, as: UTF8.self) }
    public var previewByteCount: Int { defaultSelection.ranges.first?.end ?? 0 }
    public var previewText: String { String(decoding: bytes.prefix(previewByteCount), as: UTF8.self) }
    public var defaultSelection: MultiEvidenceSelection {
        var end = min(bytes.count, MultiEvidenceContext.maximumExcerptBytes)
        while end > 0 && String(data: bytes.prefix(end), encoding: .utf8) == nil { end -= 1 }
        return MultiEvidenceSelection(ranges: end == 0 ? [] : [.init(start: 0, end: end)])
    }
}

public struct MultiEvidenceSegment: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let sourceRange: MultiEvidenceRange
    public let disclosedSHA256: String
    public let byteCount: Int
    public let text: String?
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
        let context = Self(schemaVersion: 1, transformation: transformationVersion, files: disclosures,
            warnings: ["Only selected, non-redacted UTF-8 byte ranges were disclosed; omitted content is unknown.",
                "Source containers and extracted file bytes were verified; recorded filesystem metadata and logical image hashes were not refreshed.",
                "References resolve disclosed bytes, not the correctness of an AI interpretation."])
        try context.validate(requireText: true)
        return context
    }

    public func withoutText() -> Self {
        Self(schemaVersion: schemaVersion, transformation: transformation, files: files.map { file in
            MultiEvidenceDisclosure(binding: file.binding, contentSHA256: file.contentSHA256, verifiedAt: file.verifiedAt,
                selectedRanges: file.selectedRanges, redactedRanges: file.redactedRanges,
                segments: file.segments.map { .init(id: $0.id, sourceRange: $0.sourceRange,
                    disclosedSHA256: $0.disclosedSHA256, byteCount: $0.byteCount, text: nil) },
                disclosedByteCount: file.disclosedByteCount, omittedByteCount: file.omittedByteCount)
        }, warnings: warnings)
    }

    func validate(requireText: Bool) throws {
        guard schemaVersion == 1, transformation == Self.transformationVersion, files.count == 2,
              files[0].binding.caseID == files[1].binding.caseID, files[0].binding.evidenceID == files[1].binding.evidenceID,
              files[0].binding.snapshotSHA256 == files[1].binding.snapshotSHA256,
              files[0].binding.locatorSHA256 != files[1].binding.locatorSHA256,
              warnings.count <= 32, warnings.allSatisfy({ EngineValidation.text($0, maximum: 4_096) }) else { throw MultiEvidenceError.invalidSelection }
        for (index, file) in files.enumerated() {
            try file.binding.validate()
            guard !file.binding.selectedEntry.isDirectory, (0...VerifiedContentService.maximumFileBytes).contains(file.binding.selectedEntry.size),
                  EngineValidation.validHash(file.contentSHA256), file.verifiedAt.timeIntervalSince1970.isFinite,
                  (0...Self.maximumExcerptBytes).contains(file.disclosedByteCount),
                  file.disclosedByteCount <= Int(file.binding.selectedEntry.size),
                  file.omittedByteCount == Int(file.binding.selectedEntry.size) - file.disclosedByteCount,
                  file.segments.count <= 64, file.selectedRanges.count <= 32, file.redactedRanges.count <= 32 else { throw MultiEvidenceError.invalidContent }
            try Self.validateRanges(file.selectedRanges, size: Int(file.binding.selectedEntry.size))
            try Self.validateRanges(file.redactedRanges, size: Int(file.binding.selectedEntry.size))
            guard file.segments.map(\.sourceRange) == Self.visibleRanges(selected: file.selectedRanges, redacted: file.redactedRanges) else {
                throw MultiEvidenceError.invalidContent
            }
            var last = 0, disclosedTotal = 0
            for (offset, segment) in file.segments.enumerated() {
                guard segment.id == "\(index == 0 ? "A" : "B")\(offset + 1)", segment.sourceRange.start >= last,
                      segment.sourceRange.start >= 0, segment.sourceRange.end > segment.sourceRange.start,
                      segment.sourceRange.end <= Int(file.binding.selectedEntry.size),
                      (1...Self.maximumExcerptBytes).contains(segment.byteCount),
                      segment.sourceRange.count == segment.byteCount,
                      file.selectedRanges.contains(where: { $0.start <= segment.sourceRange.start && $0.end >= segment.sourceRange.end }),
                      !file.redactedRanges.contains(where: { $0.start < segment.sourceRange.end && $0.end > segment.sourceRange.start }),
                      EngineValidation.validHash(segment.disclosedSHA256) else { throw MultiEvidenceError.invalidContent }
                last = segment.sourceRange.end; disclosedTotal += segment.byteCount
                if requireText {
                    guard let text = segment.text, text.utf8.count == segment.byteCount, !text.utf8.contains(0),
                          MultiEvidenceCoding.digest(Data(text.utf8)) == segment.disclosedSHA256 else { throw MultiEvidenceError.invalidContent }
                } else if segment.text != nil { throw MultiEvidenceError.invalidContent }
            }
            guard disclosedTotal == file.disclosedByteCount else { throw MultiEvidenceError.invalidContent }
        }
        // Counts are bounded above before arithmetic on untrusted sidecars.
        guard files.reduce(0, { $0 + $1.disclosedByteCount }) <= Self.maximumAggregateBytes else { throw MultiEvidenceError.budgetExceeded }
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
                               files: [FilesystemEntry], engine: EngineClient) async throws -> [MultiEvidenceVerifiedFile] {
        guard files.count == 2, files[0].id != files[1].id else { throw MultiEvidenceError.invalidSelection }
        var prepared: [MultiEvidenceVerifiedFile] = []
        for file in files {
            try Task.checkCancellation()
            let binding = try CaseWorkBinding.make(caseID: caseID, evidence: evidence, result: result, file: file)
            let content = try await VerifiedContentService.extract(evidence: evidence, result: result, file: file, engine: engine)
            prepared.append(try MultiEvidenceVerifiedFile(binding: binding, content: content))
        }
        return prepared
    }
}

public enum MultiEvidenceError: Error, Equatable, Sendable, LocalizedError {
    case invalidSelection, invalidContent, invalidRange, budgetExceeded, staleReference, requestMismatch, parentMismatch
    public var errorDescription: String? {
        switch self {
        case .invalidSelection: "Choose two distinct regular files from the same evidence and saved analysis."
        case .invalidContent: "Both complete files must be verified UTF-8 content up to 1 MiB. Nothing was disclosed."
        case .invalidRange: "Ranges must be ordered, disjoint UTF-8 byte boundaries within the complete file."
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
