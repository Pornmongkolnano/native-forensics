import Foundation
import Testing
@testable import ForensicsCore

struct TimelineTimestampTests {
    @Test("RFC 3339 keeps nanoseconds and resolves explicit offsets with fixed UTC oracles")
    func exactRFC3339() {
        let bangkok = TimelineTimestamp.rfc3339("2026-10-06T09:25:13.123456789+07:00")
        #expect(bangkok.epochSeconds == 1_791_253_513)
        #expect(bangkok.nanoseconds == 123_456_789)
        #expect(bangkok.precision == "fractional-9")
        #expect(bangkok.rawValue == "2026-10-06T09:25:13.123456789+07:00")
        #expect(bangkok.timezoneAssumption == nil)
        #expect(bangkok.interpretation == "exact")
        #expect(bangkok.alternativeEpochSeconds.isEmpty)
        let utc = TimelineTimestamp.rfc3339("2026-10-06t02:25:13.120z")
        #expect(utc.epochSeconds == 1_791_253_513)
        #expect(utc.nanoseconds == 120_000_000)
        #expect(utc.precision == "fractional-3")
        let west = TimelineTimestamp.rfc3339("2026-10-05T22:25:13-04:00")
        #expect(west.epochSeconds == 1_791_253_513)
        #expect(west.precision == "second")
    }

    @Test("Calendar fields, offset spelling and fractional precision cannot silently normalize", arguments: [
        "2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-10-06T24:00:00Z",
        "2026-10-06T02:60:00Z", "2026-10-06T02:25:60Z", "2026-10-06T02:25:13",
        "2026-10-06 02:25:13Z", "2026-10-06T02:25:13+0700", "2026-10-06T02:25:13+24:00",
        "2026-10-06T02:25:13+07:60", "2026-10-06T02:25:13.Z", "2026-10-06T02:25:13.1234567890Z",
        "2026-10-06T02:25:13Z ", "2026-10-06T02:25:13Zpayload", "1969-12-31T23:59:59Z",
        "10000-01-01T00:00:00Z", "1970-01-01T00:00:00+07:00", "9999-12-31T23:59:59-01:00"
    ])
    func invalidRFC3339(_ raw: String) {
        let value = TimelineTimestamp.rfc3339(raw)
        #expect(value.epochSeconds == nil)
        #expect(value.interpretation == "invalid")
        #expect(value.rawValue == raw)
    }

    @Test("Unknown RFC 3339 offset stays unresolved with its fraction preserved")
    func unknownOffset() {
        let value = TimelineTimestamp.rfc3339("2026-10-06T02:25:13.01-00:00")
        #expect(value.epochSeconds == nil)
        #expect(value.interpretation == "unknown-offset")
        #expect(value.nanoseconds == 10_000_000)
        #expect(value.precision == "fractional-2")
        #expect(TimelineTimestamp.rfc3339("2026-10-06T02:25:13+00:00").epochSeconds == 1_791_253_513)
    }

    @Test("Leap years and UTC bounds use independent exact epoch constants")
    func calendarBounds() {
        #expect(TimelineTimestamp.rfc3339("1970-01-01T00:00:00Z").epochSeconds == 0)
        #expect(TimelineTimestamp.rfc3339("2000-02-29T00:00:00Z").epochSeconds == 951_782_400)
        #expect(TimelineTimestamp.rfc3339("2400-02-29T00:00:00Z").epochSeconds == 13_574_563_200)
        #expect(TimelineTimestamp.rfc3339("2100-02-29T00:00:00Z").epochSeconds == nil)
        #expect(TimelineTimestamp.rfc3339("9999-12-31T23:59:59.999999999Z").epochSeconds == 253_402_300_799)
    }

    @Test("Classic syslog requires an explicit year and timezone")
    func explicitSyslogPolicy() {
        let value = TimelineTimestamp.syslog("Oct  6 09:25:13", year: 2026, timezone: "Asia/Bangkok")
        #expect(value.epochSeconds == 1_791_253_513)
        #expect(value.interpretation == "assumed-zone")
        #expect(value.timezoneAssumption == "year=2026, zone=Asia/Bangkok")
        #expect(value.precision == "second")
        #expect(TimelineTimestamp.syslog("Oct  6 09:25:13", year: nil, timezone: "Asia/Bangkok").interpretation == "missing-year")
        #expect(TimelineTimestamp.syslog("Oct  6 09:25:13", year: 2026, timezone: nil).interpretation == "missing-timezone")
        #expect(TimelineTimestamp.syslog("Jan  1 00:00:00", year: 1970, timezone: "UTC").epochSeconds == 0)
    }

    @Test("Valid local times outside the UTC budget are invalid rather than a DST gap")
    func syslogUTCBounds() {
        let earliest = TimelineTimestamp.syslog("Jan  1 00:00:00", year: 1970, timezone: "Asia/Bangkok")
        #expect(earliest.epochSeconds == nil)
        #expect(earliest.interpretation == "invalid")
        #expect(earliest.timezoneAssumption == "year=1970, zone=Asia/Bangkok")
        let latest = TimelineTimestamp.syslog("Dec 31 23:59:59", year: 9999, timezone: "America/New_York")
        #expect(latest.epochSeconds == nil)
        #expect(latest.interpretation == "invalid")
    }

    @Test("New York fall-back is ambiguous and retains both fixed UTC candidates")
    func daylightSavingOverlap() {
        let value = TimelineTimestamp.syslog("Nov  1 01:30:00", year: 2026, timezone: "America/New_York")
        #expect(value.epochSeconds == nil)
        #expect(value.interpretation == "ambiguous-local-time")
        #expect(value.alternativeEpochSeconds == [1_793_511_000, 1_793_514_600])
        #expect(value.rawValue == "Nov  1 01:30:00")
        #expect(value.timezoneAssumption == "year=2026, zone=America/New_York")
    }

    @Test("New York spring-forward gap does not borrow a neighboring clock time")
    func daylightSavingGap() {
        let value = TimelineTimestamp.syslog("Mar  8 02:30:00", year: 2026, timezone: "America/New_York")
        #expect(value.epochSeconds == nil)
        #expect(value.interpretation == "nonexistent-local-time")
        #expect(value.alternativeEpochSeconds.isEmpty)
        #expect(TimelineTimestamp.syslog("Mar  8 01:30:00", year: 2026, timezone: "America/New_York").epochSeconds == 1_772_951_400)
        #expect(TimelineTimestamp.syslog("Mar  8 03:30:00", year: 2026, timezone: "America/New_York").epochSeconds == 1_772_955_000)
    }

    @Test("Invalid syslog calendar values, zones and years remain unresolved", arguments: [
        ("Feb 29 00:00:00", 2026, "UTC"), ("Apr 31 00:00:00", 2026, "UTC"),
        ("Oct  6 24:00:00", 2026, "UTC"), ("Oct  6 09:25:60", 2026, "UTC"),
        ("Oct  6 09:25:13", 1969, "UTC"), ("Oct  6 09:25:13", 10000, "UTC"),
        ("Oct  6 09:25:13", 2026, "Invalid/Zone"), ("Oct  6 09:25:13", 2026, ""),
        ("Oct  6 09:25:13 payload", 2026, "UTC"), ("Oct\t6 09:25:13", 2026, "UTC")
    ])
    func invalidSyslog(_ fixture: (String, Int, String)) {
        let value = TimelineTimestamp.syslog(fixture.0, year: fixture.1, timezone: fixture.2)
        #expect(value.epochSeconds == nil)
        #expect(value.interpretation == "invalid")
    }

    @Test("Unix timestamps reject out-of-range seconds or fractions without floating-point loss")
    func unixValidation() {
        let exact = TimelineTimestamp.unix(seconds: 1_791_253_513, nanos: 123_456_789, precision: "nanosecond")
        #expect(exact.epochSeconds == 1_791_253_513)
        #expect(exact.nanoseconds == 123_456_789)
        #expect(exact.precision == "nanosecond")
        #expect(exact.interpretation == "exact")
        #expect(TimelineTimestamp.unix(seconds: -1).epochSeconds == nil)
        #expect(TimelineTimestamp.unix(seconds: 253_402_300_800).epochSeconds == nil)
        #expect(TimelineTimestamp.unix(seconds: 0, nanos: -1).epochSeconds == nil)
        #expect(TimelineTimestamp.unix(seconds: 0, nanos: 1_000_000_000).epochSeconds == nil)
    }

    @Test("Chromium integer microseconds use the fixed 1601 epoch without precision loss")
    func chromiumEpoch() {
        let value = TimelineTimestamp.chromium(microseconds: 13_435_727_113_123_456)
        #expect(value.rawValue == "13435727113123456")
        #expect(value.epochSeconds == 1_791_253_513)
        #expect(value.nanoseconds == 123_456_000)
        #expect(value.precision == "microsecond")
        #expect(value.timezoneAssumption == "epoch=1601-01-01T00:00:00Z")
        #expect(value.interpretation == "exact")
        #expect(TimelineTimestamp.chromium(microseconds: 11_644_473_600_000_000).epochSeconds == 0)
        #expect(TimelineTimestamp.chromium(microseconds: 11_644_473_599_999_999).epochSeconds == nil)
        #expect(TimelineTimestamp.chromium(microseconds: 0).interpretation == "missing")
        #expect(TimelineTimestamp.chromium(microseconds: -1).epochSeconds == nil)
        #expect(TimelineTimestamp.chromium(microseconds: Int64.max).epochSeconds == nil)
    }

    @Test("Overlong raw values are bounded before parsing, including a single Unicode grapheme")
    func rawLimits() {
        let ascii = String(repeating: "0", count: 4_097)
        let value = TimelineTimestamp.rfc3339(ascii)
        #expect(value.interpretation == "invalid-truncated")
        #expect(value.rawValue.utf8.count == 4_096)
        #expect(value.epochSeconds == nil)
        let unicode = "a" + String(repeating: "\u{0301}", count: 8_000)
        let syslog = TimelineTimestamp.syslog(unicode, year: 2026, timezone: "UTC")
        #expect(syslog.interpretation == "invalid-truncated")
        #expect(syslog.rawValue.utf8.count <= 4_098)
    }

    @Test("Exact and unresolved policy records survive JSON round trips")
    func codableRoundTrip() throws {
        for value in [TimelineTimestamp.rfc3339("2026-10-06T09:25:13.123456789+07:00"),
                      TimelineTimestamp.syslog("Nov  1 01:30:00", year: 2026, timezone: "America/New_York"),
                      TimelineTimestamp.syslog("Mar  8 02:30:00", year: 2026, timezone: "America/New_York")] {
            let data = try JSONEncoder().encode(value)
            #expect(try JSONDecoder().decode(TimelineTimestamp.self, from: data) == value)
        }
    }
}
