import Foundation

/// A timestamp keeps the source spelling separate from its interpretation.
/// An unresolved local time is never assigned a guessed UTC instant.
public struct TimelineTimestamp: Codable, Sendable, Equatable {
    public let rawValue: String
    public let epochSeconds: Int64?
    public let nanoseconds: Int32
    public let precision: String
    public let timezoneAssumption: String?
    public let interpretation: String
    public let alternativeEpochSeconds: [Int64]

    private static let maximumRawBytes = 4_096
    private static let maximumEpoch: Int64 = 253_402_300_799

    private init(rawValue: String, epochSeconds: Int64? = nil, nanoseconds: Int32 = 0,
                 precision: String = "unknown", timezoneAssumption: String? = nil,
                 interpretation: String, alternativeEpochSeconds: [Int64] = []) {
        self.rawValue = rawValue
        self.epochSeconds = epochSeconds
        self.nanoseconds = nanoseconds
        self.precision = precision
        self.timezoneAssumption = timezoneAssumption
        self.interpretation = interpretation
        self.alternativeEpochSeconds = alternativeEpochSeconds
    }

    /// Unix instants are bounded to UTC years 1970 through 9999. `nanos` is a
    /// nonnegative fraction of `seconds`, never a floating-point date value.
    public static func unix(seconds: Int64, nanos: Int32 = 0,
                            precision: String = "second", timezoneAssumption: String? = nil) -> Self {
        let raw = nanos == 0 ? String(seconds) : "\(seconds) seconds, \(nanos) nanoseconds"
        guard (0...maximumEpoch).contains(seconds), (0...999_999_999).contains(nanos),
              !precision.isEmpty, precision.utf8.count <= 64,
              (timezoneAssumption?.utf8.count ?? 0) <= 256 else {
            return Self(rawValue: raw, interpretation: "invalid")
        }
        return Self(rawValue: raw, epochSeconds: seconds, nanoseconds: nanos,
                    precision: precision, timezoneAssumption: timezoneAssumption, interpretation: "exact")
    }

    public static func filesystem(_ provenance: FilesystemCivilTimestamp, epoch: Int64?, nanos: Int32) throws -> Self {
        try provenance.validate(epoch: epoch, nanoseconds: nanos)
        guard (0...999_999_999).contains(nanos), epoch.map({ (0...maximumEpoch).contains($0) }) ?? true,
              provenance.candidateEpochs.allSatisfy({ (0...maximumEpoch).contains($0) }) else {
            throw TimelineError.invalidInput("Filesystem timestamp provenance exceeds supported UTC bounds.")
        }
        let raw = "civil=\(provenance.civil ?? "unavailable"), rawDate=\(provenance.rawDate), rawTime=\(provenance.rawTime), rawIncrement=\(provenance.rawIncrement.map(String.init) ?? "none"), rawUTCOffset=\(provenance.rawUTCOffset.map(String.init) ?? "none")"
        let zone = provenance.utcOffsetMinutes.map { "recorded UTC offset minutes=\($0)" }
            ?? provenance.timezone.map { "assumed IANA timezone=\($0)" }
        return Self(rawValue: raw, epochSeconds: epoch, nanoseconds: nanos,
            precision: "native resolution=\(provenance.precisionNanoseconds) nanoseconds", timezoneAssumption: zone,
            interpretation: provenance.status.rawValue,
            alternativeEpochSeconds: provenance.status == .ambiguousLocalTime ? provenance.candidateEpochs : [])
    }

    /// Chromium timestamps count integer microseconds from 1601-01-01 UTC.
    /// The epoch conversion never passes through a floating-point `Date`.
    public static func chromium(microseconds: Int64) -> Self {
        let raw = String(microseconds), assumption = "epoch=1601-01-01T00:00:00Z"
        guard microseconds > 0 else {
            return Self(rawValue: raw, precision: "microsecond", timezoneAssumption: assumption,
                        interpretation: "missing")
        }
        let (unixMicroseconds, overflow) = microseconds.subtractingReportingOverflow(11_644_473_600_000_000)
        guard !overflow else { return Self(rawValue: raw, interpretation: "invalid") }
        var seconds = unixMicroseconds / 1_000_000
        var remainder = unixMicroseconds % 1_000_000
        if remainder < 0 {
            seconds -= 1
            remainder += 1_000_000
        }
        guard (0...maximumEpoch).contains(seconds) else {
            return Self(rawValue: raw, precision: "microsecond", timezoneAssumption: assumption,
                        interpretation: "invalid")
        }
        return Self(rawValue: raw, epochSeconds: seconds, nanoseconds: Int32(remainder * 1_000),
                    precision: "microsecond", timezoneAssumption: assumption, interpretation: "exact")
    }

    /// Parses ASCII RFC 3339 with a mandatory explicit offset and at most nine
    /// fractional digits. Leap seconds cannot be represented by this model.
    /// RFC 3339's unknown offset `-00:00` remains unresolved, unlike `+00:00`.
    public static func rfc3339(_ raw: String) -> Self {
        guard raw.utf8.count <= maximumRawBytes else { return overlong(raw) }
        let bytes = Array(raw.utf8)
        guard bytes.count >= 20, bytes.count <= 35,
              bytes[4] == 45, bytes[7] == 45, bytes[10] == 84 || bytes[10] == 116,
              bytes[13] == 58, bytes[16] == 58,
              let year = decimal(bytes, 0, 4), let month = decimal(bytes, 5, 2),
              let day = decimal(bytes, 8, 2), let hour = decimal(bytes, 11, 2),
              let minute = decimal(bytes, 14, 2), let second = decimal(bytes, 17, 2),
              let localEpoch = civilEpoch(year: year, month: month, day: day,
                                          hour: hour, minute: minute, second: second) else {
            return Self(rawValue: raw, interpretation: "invalid")
        }

        var index = 19, nanos: Int32 = 0, precision = "second"
        if bytes[index] == 46 {
            index += 1
            let start = index
            while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
            let digits = index - start
            guard (1...9).contains(digits), let fraction = decimal(bytes, start, digits) else {
                return Self(rawValue: raw, interpretation: "invalid")
            }
            var padded = fraction
            for _ in digits..<9 { padded *= 10 }
            nanos = Int32(padded)
            precision = "fractional-\(digits)"
        }

        guard index < bytes.count else { return Self(rawValue: raw, interpretation: "invalid") }
        let offset: Int64
        if (bytes[index] == 90 || bytes[index] == 122), index + 1 == bytes.count {
            offset = 0
        } else {
            guard index + 6 == bytes.count, bytes[index] == 43 || bytes[index] == 45,
                  bytes[index + 3] == 58, let offsetHour = decimal(bytes, index + 1, 2),
                  let offsetMinute = decimal(bytes, index + 4, 2),
                  (0...23).contains(offsetHour), (0...59).contains(offsetMinute) else {
                return Self(rawValue: raw, interpretation: "invalid")
            }
            if bytes[index] == 45, offsetHour == 0, offsetMinute == 0 {
                return Self(rawValue: raw, nanoseconds: nanos, precision: precision,
                            interpretation: "unknown-offset")
            }
            let magnitude = Int64(offsetHour * 3_600 + offsetMinute * 60)
            offset = bytes[index] == 43 ? magnitude : -magnitude
        }
        let epoch = localEpoch - offset
        guard (0...maximumEpoch).contains(epoch) else {
            return Self(rawValue: raw, interpretation: "invalid")
        }
        return Self(rawValue: raw, epochSeconds: epoch, nanoseconds: nanos,
                    precision: precision, interpretation: "exact")
    }

    /// Classic syslog omits both year and timezone. The caller must supply both
    /// explicitly; neither the current date nor the computer's zone is used.
    /// A DST overlap retains every valid candidate, with no preferred instant.
    public static func syslog(_ raw: String, year: Int?, timezone: String?) -> Self {
        guard raw.utf8.count <= maximumRawBytes else { return overlong(raw) }
        let parts = raw.split(separator: " ", omittingEmptySubsequences: true)
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        guard raw.utf8.count <= 32, parts.count == 3,
              let monthIndex = months.firstIndex(of: String(parts[0])) else {
            return Self(rawValue: raw, interpretation: "invalid")
        }
        let dayBytes = Array(parts[1].utf8), clock = Array(parts[2].utf8)
        guard (1...2).contains(dayBytes.count), let day = decimal(dayBytes, 0, dayBytes.count),
              clock.count == 8, clock[2] == 58, clock[5] == 58,
              let hour = decimal(clock, 0, 2), let minute = decimal(clock, 3, 2),
              let second = decimal(clock, 6, 2) else {
            return Self(rawValue: raw, interpretation: "invalid")
        }
        guard let year else { return Self(rawValue: raw, precision: "second", interpretation: "missing-year") }
        let month = monthIndex + 1
        guard let wallEpoch = civilEpoch(year: year, month: month, day: day,
                                         hour: hour, minute: minute, second: second) else {
            return Self(rawValue: raw, interpretation: "invalid")
        }
        guard let timezone else {
            return Self(rawValue: raw, precision: "second", interpretation: "missing-timezone")
        }
        guard !timezone.isEmpty, timezone.utf8.count <= 256, let zone = TimeZone(identifier: timezone) else {
            return Self(rawValue: raw, interpretation: "invalid")
        }
        let assumption = "year=\(year), zone=\(timezone)"
        let candidates = localCandidates(wallEpoch: wallEpoch, zone: zone)
        guard candidates.allSatisfy({ (0...maximumEpoch).contains($0) }) else {
            return Self(rawValue: raw, precision: "second", timezoneAssumption: assumption, interpretation: "invalid")
        }
        if candidates.count == 1 {
            return Self(rawValue: raw, epochSeconds: candidates[0], precision: "second",
                        timezoneAssumption: assumption, interpretation: "assumed-zone")
        }
        return Self(rawValue: raw, precision: "second", timezoneAssumption: assumption,
                    interpretation: candidates.isEmpty ? "nonexistent-local-time" : "ambiguous-local-time",
                    alternativeEpochSeconds: candidates)
    }

    private static func overlong(_ raw: String) -> Self {
        // Byte-bounded even for one extremely long Unicode grapheme cluster.
        let prefix = String(decoding: raw.utf8.prefix(maximumRawBytes), as: UTF8.self)
        return Self(rawValue: prefix, interpretation: "invalid-truncated")
    }

    private static func decimal(_ bytes: [UInt8], _ start: Int, _ length: Int) -> Int? {
        guard length > 0, start >= 0, start <= bytes.count - length else { return nil }
        var value = 0
        for byte in bytes[start..<(start + length)] {
            guard (48...57).contains(byte) else { return nil }
            value = value * 10 + Int(byte - 48)
        }
        return value
    }

    private static func civilEpoch(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int) -> Int64? {
        guard (1970...9999).contains(year), (1...12).contains(month),
              (0...23).contains(hour), (0...59).contains(minute), (0...59).contains(second) else { return nil }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        let monthLengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard (1...monthLengths[month - 1]).contains(day) else { return nil }
        func daysBefore(_ value: Int) -> Int {
            let preceding = value - 1
            return preceding * 365 + preceding / 4 - preceding / 100 + preceding / 400
        }
        let days = daysBefore(year) - daysBefore(1970) + monthLengths.prefix(month - 1).reduce(0, +) + day - 1
        return Int64(days) * 86_400 + Int64(hour * 3_600 + minute * 60 + second)
    }

    private static func localCandidates(wallEpoch: Int64, zone: TimeZone) -> [Int64] {
        let wallDate = Date(timeIntervalSince1970: TimeInterval(wallEpoch))
        let lower = wallDate.addingTimeInterval(-172_800), upper = wallDate.addingTimeInterval(172_800)
        var offsets = Set<Int>()
        // Include the surrounding ordinary regimes and transition boundaries.
        // Candidate acceptance below verifies the exact zone offset at the UTC
        // instant, so a sampled offset cannot turn a gap into a fabricated date.
        for hour in stride(from: -48, through: 48, by: 6) {
            offsets.insert(zone.secondsFromGMT(for: wallDate.addingTimeInterval(Double(hour) * 3_600)))
        }
        var cursor = lower
        for _ in 0..<16 {
            guard let transition = zone.nextDaylightSavingTimeTransition(after: cursor), transition <= upper else { break }
            offsets.insert(zone.secondsFromGMT(for: transition.addingTimeInterval(-1)))
            offsets.insert(zone.secondsFromGMT(for: transition))
            cursor = transition.addingTimeInterval(1)
        }
        return offsets.compactMap { offset in
            let candidate = wallEpoch - Int64(offset)
            guard zone.secondsFromGMT(for: Date(timeIntervalSince1970: TimeInterval(candidate))) == offset else { return nil }
            return candidate
        }.sorted()
    }
}
