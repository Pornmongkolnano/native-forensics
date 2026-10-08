import CoreFoundation
import Foundation

/// Decodes the populated macOS 27 `diskutil apfs listSnapshots -plist`
/// schema. Inventory metadata does not establish readable snapshot content.
/// Missing or malformed inventory throws; only a recognized empty array is
/// evidence of a successfully observed inventory with no snapshots.
enum APFSSnapshotMetadata {
    static func entries(from listing: [String: Any]) throws -> [APFSSnapshotInventoryEntry] {
        guard !["Error", "ErrorCode", "ErrorMessage", "DiskManagementErrorCode", "Success"].contains(where: { listing[$0] != nil }),
              let rows = listing["Snapshots"] as? [[String: Any]], rows.count <= 4_096 else {
            throw APFSReadError.invalidResult
        }
        var entries: [APFSSnapshotInventoryEntry] = []
        var identifiers: Set<UUID> = []
        var names: Set<String> = []
        var transactions: Set<UInt64> = []
        entries.reserveCapacity(rows.count)
        for row in rows {
            // The observed keys are SnapshotName and SnapshotXID. Retaining
            // guessed Name/XID aliases would permit contradictory identifiers.
            guard row["Name"] == nil, row["XID"] == nil,
                  let uuidText = row["SnapshotUUID"] as? String, uuidText.utf8.count == 36,
                  let uuid = UUID(uuidString: uuidText), identifiers.insert(uuid).inserted,
                  let name = row["SnapshotName"] as? String, !name.isEmpty, name.utf8.count <= 1_024,
                  !name.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
                  let transaction = positiveIntegralUInt64(row["SnapshotXID"]),
                  names.insert(name).inserted, transactions.insert(transaction).inserted else {
                throw APFSReadError.invalidResult
            }
            entries.append(.init(uuid: uuid, name: name, transactionID: transaction))
        }
        return entries.sorted { $0.uuid.uuidString < $1.uuid.uuidString }
    }

    private static func positiveIntegralUInt64(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        // NSNumber's integer accessors would otherwise round doubles or wrap
        // signed negatives. Check the stored type before any integer accessor;
        // the unsigned branch never passes through Int64 or Double.
        switch String(cString: number.objCType) {
        case "c", "s", "i", "l", "q":
            let integer = number.int64Value
            return integer > 0 ? UInt64(integer) : nil
        case "C", "S", "I", "L", "Q":
            let integer = number.uint64Value
            return integer > 0 ? integer : nil
        default:
            return nil
        }
    }
}
