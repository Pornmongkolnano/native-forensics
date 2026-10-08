import Foundation
import Testing
@testable import ForensicsCore

@Suite("Observed bounded APFS snapshot inventory schema")
struct APFSSnapshotMetadataTests {
    private let observedUUID = "3222234B-EE3F-467B-9D1E-D1E430DF8F5B"

    @Test("Independently observed macOS 27 populated plist uses SnapshotName and SnapshotXID")
    func observedPopulatedSchema() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>Snapshots</key><array><dict>
        <key>SnapshotName</key><string>nf-before</string>
        <key>SnapshotUUID</key><string>3222234B-EE3F-467B-9D1E-D1E430DF8F5B</string>
        <key>SnapshotXID</key><integer>1</integer>
        <key>Purgeable</key><true/><key>LimitingContainerShrink</key><true/>
        <key>RevertTo</key><false/><key>RootTo</key><false/>
        </dict></array></dict></plist>
        """
        let listing = try #require(try PropertyListSerialization.propertyList(from: Data(xml.utf8),
            options: [], format: nil) as? [String: Any])
        let entries = try APFSSnapshotMetadata.entries(from: listing)
        let expectedUUID = try #require(UUID(uuidString: observedUUID))
        #expect(entries == [.init(uuid: expectedUUID, name: "nf-before", transactionID: 1)])
    }

    @Test("Recognized empty inventory differs from missing, malformed or error inventory")
    func emptyAndUnavailable() throws {
        #expect(try APFSSnapshotMetadata.entries(from: ["Snapshots": [] as [[String: Any]]]).isEmpty)
        let unavailable: [[String: Any]] = [
            [:], ["UnknownSnapshots": [] as [[String: Any]]], ["Snapshots": NSNull()],
            ["Snapshots": "none"], ["Snapshots": ["nf-before"]],
            ["ErrorMessage": "Synthetic inventory unavailable"],
            ["Snapshots": [] as [[String: Any]], "Error": "Synthetic error"],
            ["Snapshots": [] as [[String: Any]], "ErrorCode": -69461],
            ["Snapshots": [] as [[String: Any]], "DiskManagementErrorCode": -69461],
            ["Snapshots": [] as [[String: Any]], "Success": false]
        ]
        for listing in unavailable {
            #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: listing) }
        }
    }

    @Test("Positive stored integral XIDs preserve the full UInt64 range without rounding or wrapping")
    func integralTransactionIDs() throws {
        let accepted: [(NSNumber, UInt64)] = [
            (NSNumber(value: Int8(1)), 1), (NSNumber(value: UInt32.max), UInt64(UInt32.max)),
            (NSNumber(value: Int64.max), UInt64(Int64.max)), (NSNumber(value: UInt64.max), UInt64.max)
        ]
        for (number, expected) in accepted {
            let entries = try APFSSnapshotMetadata.entries(from: ["Snapshots": [row(xid: number)]])
            #expect(entries.first?.transactionID == expected)
        }
        let rejected: [Any] = [
            NSNumber(value: true), NSNumber(value: false), NSNumber(value: 0),
            NSNumber(value: Int64(-1)), NSNumber(value: Int64.min),
            NSNumber(value: Double(1)), NSNumber(value: 1.5),
            NSNumber(value: Double.greatestFiniteMagnitude), NSNumber(value: Double.nan),
            NSNumber(value: Double.infinity), NSDecimalNumber(string: "1"),
            "1", NSNull(), [1]
        ]
        for value in rejected {
            #expect(throws: APFSReadError.invalidResult) {
                _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [row(xid: value)]])
            }
        }
    }

    @Test("Snapshot UUID, mandatory actual keys and legacy aliases cannot create ambiguous identifiers")
    func identifiersAndAliases() {
        for key in ["SnapshotUUID", "SnapshotName", "SnapshotXID"] {
            var missing = row(); missing.removeValue(forKey: key)
            #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [missing]]) }
        }
        for invalid in ["not-a-uuid", "", observedUUID + "extra"] {
            var malformed = row(); malformed["SnapshotUUID"] = invalid
            #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [malformed]]) }
        }
        var legacy = row(); legacy["Name"] = legacy.removeValue(forKey: "SnapshotName")
        legacy["XID"] = legacy.removeValue(forKey: "SnapshotXID")
        #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [legacy]]) }
        for (key, value) in [("Name", "nf-before" as Any), ("Name", "conflicting-name" as Any),
                             ("Name", NSNumber(value: 1) as Any), ("XID", NSNumber(value: 1) as Any),
                             ("XID", NSNumber(value: 2) as Any), ("XID", "1" as Any)] {
            var aliased = row(); aliased[key] = value
            #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [aliased]]) }
        }
        #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [row(), row()]]) }
        var conflictingUUID = row(xid: NSNumber(value: 2)); conflictingUUID["SnapshotName"] = "nf-after"
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [row(), conflictingUUID]])
        }
        var conflictingName = row(xid: NSNumber(value: 2))
        conflictingName["SnapshotUUID"] = "4222234B-EE3F-467B-9D1E-D1E430DF8F5B"
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [row(), conflictingName]])
        }
        var conflictingTransaction = conflictingName
        conflictingTransaction["SnapshotName"] = "nf-after"
        conflictingTransaction["SnapshotXID"] = NSNumber(value: 1)
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [row(), conflictingTransaction]])
        }
    }

    @Test("Name limits count UTF8 bytes and refuse control characters")
    func boundedNames() throws {
        var boundary = row(); boundary["SnapshotName"] = String(repeating: "ก", count: 341) + "a"
        #expect(try APFSSnapshotMetadata.entries(from: ["Snapshots": [boundary]]).first?.name.utf8.count == 1_024)
        for name in ["", String(repeating: "ก", count: 341) + "aa", "nf\0before", "nf\nbefore", "nf\u{7f}before"] {
            var malformed = row(); malformed["SnapshotName"] = name
            #expect(throws: APFSReadError.invalidResult) { _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": [malformed]]) }
        }
    }

    @Test("4096 unique snapshot rows fit the bound and excessive rows fail")
    func rowBoundsAndStableOrder() throws {
        let rows: [[String: Any]] = (1...4_096).reversed().map { index in
            ["SnapshotUUID": "00000000-0000-0000-0000-" + String(format: "%012x", UInt32(index)),
             "SnapshotName": "nf-\(index)", "SnapshotXID": NSNumber(value: index)]
        }
        let entries = try APFSSnapshotMetadata.entries(from: ["Snapshots": rows])
        #expect(entries.count == 4_096 && entries.first?.transactionID == 1 && entries.last?.transactionID == 4_096)
        #expect(throws: APFSReadError.invalidResult) {
            _ = try APFSSnapshotMetadata.entries(from: ["Snapshots": rows + [row()]])
        }
    }

    private func row(xid: Any = NSNumber(value: 1)) -> [String: Any] {
        ["SnapshotUUID": observedUUID, "SnapshotName": "nf-before", "SnapshotXID": xid,
         "Purgeable": true, "LimitingContainerShrink": true, "RevertTo": false, "RootTo": false]
    }
}
