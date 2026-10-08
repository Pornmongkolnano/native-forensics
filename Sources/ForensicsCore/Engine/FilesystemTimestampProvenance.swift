import Foundation

/// Raw filesystem civil-time fields are retained even when an instant cannot
/// be selected. A local DST gap has no candidate; an overlap has two candidates.
public struct FilesystemCivilTimestamp: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case recordedOffset = "recorded-offset"
        case assumedZone = "assumed-zone"
        case ambiguousLocalTime = "ambiguous-local-time"
        case nonexistentLocalTime = "nonexistent-local-time"
        case invalidCalendar = "invalid-calendar"
        case missing
    }
    public let rawDate: Int
    public let rawTime: Int
    public let rawIncrement: Int?
    public let rawUTCOffset: Int?
    public let civil: String?
    public let status: Status
    public let timezone: String?
    public let utcOffsetMinutes: Int?
    public let candidateEpochs: [Int64]
    public let precisionNanoseconds: Int64

    public init(rawDate: Int, rawTime: Int, rawIncrement: Int? = nil, rawUTCOffset: Int? = nil,
                civil: String? = nil, status: Status, timezone: String? = nil,
                utcOffsetMinutes: Int? = nil, candidateEpochs: [Int64] = [], precisionNanoseconds: Int64) {
        self.rawDate = rawDate; self.rawTime = rawTime; self.rawIncrement = rawIncrement
        self.rawUTCOffset = rawUTCOffset; self.civil = civil; self.status = status; self.timezone = timezone
        self.utcOffsetMinutes = utcOffsetMinutes; self.candidateEpochs = candidateEpochs
        self.precisionNanoseconds = precisionNanoseconds
    }

    func validate(epoch: Int64?, nanoseconds: Int32) throws {
        guard (0...65_535).contains(rawDate), (0...65_535).contains(rawTime),
              rawIncrement.map({ (0...255).contains($0) }) ?? true,
              rawUTCOffset.map({ (0...255).contains($0) }) ?? true,
              civil.map({ EngineValidation.text($0, maximum: 80) }) ?? true,
              timezone.map({ EngineValidation.text($0, maximum: 256) && TimeZone(identifier: $0) != nil }) ?? true,
              utcOffsetMinutes.map({ (-1_440...1_440).contains($0) }) ?? true,
              (1...86_400_000_000_000).contains(precisionNanoseconds),
              candidateEpochs.count <= 2, candidateEpochs == candidateEpochs.sorted(),
              Set(candidateEpochs).count == candidateEpochs.count else {
            throw EngineError.protocolViolation("Invalid raw filesystem timestamp provenance.")
        }
        switch status {
        case .recordedOffset:
            guard civil != nil, utcOffsetMinutes != nil, candidateEpochs.count == 1,
                  epoch == candidateEpochs.first else { throw invalidStatus() }
        case .assumedZone:
            guard civil != nil, timezone != nil, candidateEpochs.count == 1,
                  epoch == candidateEpochs.first else { throw invalidStatus() }
        case .ambiguousLocalTime:
            guard civil != nil, timezone != nil, candidateEpochs.count == 2,
                  epoch == nil, nanoseconds == 0 else { throw invalidStatus() }
        case .nonexistentLocalTime:
            guard civil != nil, timezone != nil, candidateEpochs.isEmpty,
                  epoch == nil, nanoseconds == 0 else { throw invalidStatus() }
        case .invalidCalendar, .missing:
            guard candidateEpochs.isEmpty, epoch == nil, nanoseconds == 0 else { throw invalidStatus() }
        }
    }
    private func invalidStatus() -> EngineError {
        .protocolViolation("Filesystem civil-time status contradicts its selected instant or candidates.")
    }
}

public struct FilesystemTimestampProvenance: Codable, Sendable, Equatable {
    public let created: FilesystemCivilTimestamp?
    public let modified: FilesystemCivilTimestamp?
    public let accessed: FilesystemCivilTimestamp?
    public init(created: FilesystemCivilTimestamp? = nil, modified: FilesystemCivilTimestamp? = nil,
                accessed: FilesystemCivilTimestamp? = nil) {
        self.created = created; self.modified = modified; self.accessed = accessed
    }
}
