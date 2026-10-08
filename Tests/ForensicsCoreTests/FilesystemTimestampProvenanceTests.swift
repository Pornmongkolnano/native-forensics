import Foundation
import Testing
@testable import ForensicsCore

struct FilesystemTimestampProvenanceTests {
    private func file(_ modified: FilesystemCivilTimestamp?, epoch: Int64? = nil, nanos: Int32 = 0) -> FilesystemEntry {
        .init(id: "civil", path: "/LOG.TXT", name: "LOG.TXT", fsOffsetBytes: 0, metaAddress: 7,
            size: 16, isDirectory: false, isDeleted: false, modifiedEpoch: epoch, modifiedNanoseconds: nanos,
            timestampProvenance: modified.map { .init(modified: $0) })
    }

    @Test func actualDSTOverlapRetainsTwoUnselectedInstantsThroughReopen() throws {
        // Independent New York fall-back oracle: 01:30 occurs at 05:30 and 06:30 UTC.
        let value = file(.init(rawDate: 21_862, rawTime: 3_008, civil: "2022-11-06T01:30:00",
            status: .ambiguousLocalTime, timezone: "America/New_York",
            candidateEpochs: [1_667_712_600, 1_667_716_200], precisionNanoseconds: 2_000_000_000))
        try EngineValidation.file(value)
        let reopened = try JSONDecoder().decode(FilesystemEntry.self, from: JSONEncoder().encode(value))
        #expect(reopened == value)
        #expect(reopened.modifiedEpoch == nil)
        #expect(reopened.timestampProvenance?.modified?.candidateEpochs.count == 2)
    }

    @Test func actualDSTGapCannotBePresentedAsOneChosenInstant() throws {
        let raw = FilesystemCivilTimestamp(rawDate: 21_102, rawTime: 5_056, civil: "2021-03-14T02:30:00",
            status: .nonexistentLocalTime, timezone: "America/New_York", precisionNanoseconds: 2_000_000_000)
        try EngineValidation.file(file(raw))
        #expect(throws: EngineError.self) { try EngineValidation.file(file(raw, epoch: 1_615_707_000)) }
        #expect(throws: EngineError.self) { try EngineValidation.file(file(raw, nanos: 10_000_000)) }
    }

    @Test func recordedOffsetCannotContradictEpochOrLoseItsRawFields() throws {
        // 2026-10-06 11:48 +07:00 == 2026-10-06 04:48 UTC.
        let raw = FilesystemCivilTimestamp(rawDate: 23_878, rawTime: 24_064, rawIncrement: 12,
            rawUTCOffset: 156, civil: "2026-10-06T11:48:00", status: .recordedOffset,
            utcOffsetMinutes: 420, candidateEpochs: [1_791_262_080], precisionNanoseconds: 10_000_000)
        let value = file(raw, epoch: 1_791_262_080, nanos: 120_000_000)
        try EngineValidation.file(value)
        #expect(throws: EngineError.self) { try EngineValidation.file(file(raw, epoch: 1_791_262_081)) }
    }

    @Test func historicalRowsStillDecodeAndRecoveryWarningsRoundTrip() throws {
        let old = file(nil)
        let reopened = try JSONDecoder().decode(FilesystemEntry.self, from: JSONEncoder().encode(old))
        #expect(reopened.timestampProvenance == nil && reopened.recoveryStatus == nil)
        let receipt = ExtractionResult(outputPath: "/owned/NEW", byteCount: 16,
            sha256: String(repeating: "a", count: 64), contentStatus: "recovery-candidate",
            warnings: ["Current bytes are not proof of historical deleted contents."])
        #expect(try JSONDecoder().decode(ExtractionResult.self, from: JSONEncoder().encode(receipt)) == receipt)
    }

    @Test func malformedCandidateOrderAndExcessWarningsFailClosed() throws {
        let reversed = FilesystemCivilTimestamp(rawDate: 21_862, rawTime: 3_008, civil: "2022-11-06T01:30:00",
            status: .ambiguousLocalTime, timezone: "America/New_York",
            candidateEpochs: [1_667_716_200, 1_667_712_600], precisionNanoseconds: 2_000_000_000)
        #expect(throws: EngineError.self) { try EngineValidation.file(file(reversed)) }
        let bad = FilesystemEntry(id: "x", path: "/x", name: "x", fsOffsetBytes: 0, metaAddress: 1,
            size: 1, isDirectory: false, isDeleted: true, recoveryStatus: "deleted-current-bytes",
            recoveryWarnings: Array(repeating: "warning", count: 33))
        #expect(throws: EngineError.self) { try EngineValidation.file(bad) }
    }
}
