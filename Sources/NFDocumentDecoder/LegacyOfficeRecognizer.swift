import Foundation
import ForensicsCore

struct LegacyOfficeRecognition {
    let format: DocumentOfficeFormat?
    let mimeType: String
    let isStructurallyValid: Bool
    let warnings: [String]
}

/// Recognizes legacy Office containers from bounded CFB directory structures.
/// It never decodes stream bodies or treats a filename as evidence of a format.
/// Field layouts follow Microsoft's MS-CFB header, FAT/DIFAT and directory
/// specification; Office stream formats are outside this recognizer's scope.
enum LegacyOfficeRecognizer {
    private static let oleMIME = "application/x-ole-storage"
    private static let maximumInputBytes = 128 * 1_024 * 1_024
    private static let maximumDirectoryBytes = 4 * 1_024 * 1_024
    private static let freeSector: UInt32 = 0xFFFF_FFFF
    private static let endOfChain: UInt32 = 0xFFFF_FFFE
    private static let fatSector: UInt32 = 0xFFFF_FFFD
    private static let difatSector: UInt32 = 0xFFFF_FFFC

    static func inspect(_ data: Data) -> LegacyOfficeRecognition {
        guard data.count <= maximumInputBytes else {
            return invalid("OLE inspection reached the 128 MiB input limit.")
        }
        do {
            return try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                try inspect(bytes)
            }
        } catch let error as StructureError {
            return invalid("OLE structural validation failed: " + error.reason + ".")
        } catch {
            return invalid("OLE structural validation failed.")
        }
    }

    private struct StructureError: Error { let reason: String }

    private struct DirectoryEntry {
        let name: String
        let type: UInt8
        let left: UInt32
        let right: UInt32
        let child: UInt32
    }

    private static func invalid(_ warning: String) -> LegacyOfficeRecognition {
        LegacyOfficeRecognition(format: nil, mimeType: oleMIME,
                                isStructurallyValid: false, warnings: [warning])
    }

    private static func inspect(_ bytes: UnsafeRawBufferPointer) throws -> LegacyOfficeRecognition {
        func require(_ condition: Bool, _ reason: String) throws {
            guard condition else { throw StructureError(reason: reason) }
        }
        func uint16(_ offset: Int) -> UInt16 {
            UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
        }
        func uint32(_ offset: Int) -> UInt32 {
            UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
                | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
        }
        func uint64(_ offset: Int) -> UInt64 {
            UInt64(uint32(offset)) | UInt64(uint32(offset + 4)) << 32
        }
        try require(bytes.count >= 512, "truncated compound-file header")
        let signature: [UInt8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        try require(signature.indices.allSatisfy { bytes[$0] == signature[$0] }, "invalid compound-file signature")
        try require((8..<24).allSatisfy { bytes[$0] == 0 }, "nonzero reserved header CLSID")
        let major = uint16(26)
        let sectorShift = uint16(30)
        try require(major == 3 || major == 4, "unsupported compound-file version")
        try require(uint16(28) == 0xFFFE, "invalid byte order")
        try require((major == 3 && sectorShift == 9) || (major == 4 && sectorShift == 12), "invalid sector size")
        try require(uint16(32) == 6 && (34..<40).allSatisfy { bytes[$0] == 0 }, "invalid reserved header fields")
        try require(uint32(56) == 4_096, "invalid mini-stream cutoff")

        let sectorSize = 1 << Int(sectorShift)
        try require(bytes.count >= 3 * sectorSize && bytes.count % sectorSize == 0, "truncated or unaligned sectors")
        if major == 4 {
            try require((512..<sectorSize).allSatisfy { bytes[$0] == 0 }, "nonzero version-4 header padding")
        }
        let sectorCount = bytes.count / sectorSize - 1
        let entriesPerFAT = sectorSize / 4
        let fatCount = Int(uint32(44))
        let directoryCount = Int(uint32(40))
        let difatCount = Int(uint32(72))
        let miniFATCount = Int(uint32(64))
        try require(fatCount > 0 && fatCount <= sectorCount && fatCount * entriesPerFAT >= sectorCount,
                    "invalid FAT sector count")
        try require(difatCount <= sectorCount && miniFATCount <= sectorCount, "invalid allocation-table counts")
        try require(major != 3 || directoryCount == 0, "invalid version-3 directory count")
        try require(major != 4 || (directoryCount > 0 && directoryCount <= sectorCount), "invalid version-4 directory count")

        func isSector(_ value: UInt32) -> Bool { UInt64(value) < UInt64(sectorCount) }
        func sectorOffset(_ value: UInt32) -> Int { (Int(value) + 1) * sectorSize }

        let firstMiniFAT = uint32(60)
        try require(miniFATCount == 0 ? firstMiniFAT == endOfChain : isSector(firstMiniFAT),
                    "invalid mini-FAT start")
        var fatLocations: [UInt32] = []
        fatLocations.reserveCapacity(fatCount)
        var fatLocationSet = Set<UInt32>()
        var sawUnusedDIFATEntry = false
        func appendFATLocation(_ value: UInt32) throws {
            if value == freeSector { sawUnusedDIFATEntry = true; return }
            try require(!sawUnusedDIFATEntry && fatLocations.count < fatCount && isSector(value)
                            && fatLocationSet.insert(value).inserted, "invalid or duplicate DIFAT entry")
            fatLocations.append(value)
        }
        for index in 0..<109 { try appendFATLocation(uint32(76 + index * 4)) }

        var nextDIFAT = uint32(68)
        var difatLocations = Set<UInt32>()
        for _ in 0..<difatCount {
            try require(isSector(nextDIFAT) && !fatLocationSet.contains(nextDIFAT)
                            && difatLocations.insert(nextDIFAT).inserted, "cyclic or invalid DIFAT chain")
            let offset = sectorOffset(nextDIFAT)
            for index in 0..<(entriesPerFAT - 1) { try appendFATLocation(uint32(offset + index * 4)) }
            nextDIFAT = uint32(offset + sectorSize - 4)
        }
        try require(nextDIFAT == endOfChain && fatLocations.count == fatCount
                        && fatLocationSet.isDisjoint(with: difatLocations), "incomplete DIFAT chain")

        func fatEntry(_ sector: UInt32) -> UInt32 {
            let index = Int(sector)
            let location = fatLocations[index / entriesPerFAT]
            return uint32(sectorOffset(location) + (index % entriesPerFAT) * 4)
        }
        for sector in fatLocations {
            try require(fatEntry(sector) == fatSector, "FAT sector is not reserved in the FAT")
        }
        for sector in difatLocations {
            try require(fatEntry(sector) == difatSector, "DIFAT sector is not reserved in the FAT")
        }
        for index in 0..<sectorCount {
            let value = fatEntry(UInt32(index))
            try require(isSector(value) || [freeSector, endOfChain, fatSector, difatSector].contains(value),
                        "out-of-range FAT link")
        }

        var directoryLocations: [UInt32] = []
        var directoryLocationSet = Set<UInt32>()
        var nextDirectory = uint32(48)
        while nextDirectory != endOfChain {
            try require(isSector(nextDirectory) && !fatLocationSet.contains(nextDirectory)
                            && !difatLocations.contains(nextDirectory)
                            && directoryLocationSet.insert(nextDirectory).inserted, "cyclic or invalid directory chain")
            try require(directoryLocations.count < maximumDirectoryBytes / sectorSize,
                        "directory exceeds the 4 MiB inspection limit")
            directoryLocations.append(nextDirectory)
            nextDirectory = fatEntry(nextDirectory)
        }
        try require(!directoryLocations.isEmpty && (major != 4 || directoryLocations.count == directoryCount),
                    "incomplete directory chain")

        let entryCount = directoryLocations.count * (sectorSize / 128)
        var directoryEntries: [DirectoryEntry] = []
        directoryEntries.reserveCapacity(entryCount)
        func validID(_ value: UInt32) -> Bool { value == freeSector || UInt64(value) < UInt64(entryCount) }
        for location in directoryLocations {
            let sector = sectorOffset(location)
            for index in 0..<(sectorSize / 128) {
                let offset = sector + index * 128
                let type = bytes[offset + 66]
                if type == 0 {
                    directoryEntries.append(DirectoryEntry(name: "", type: 0, left: freeSector, right: freeSector, child: freeSector))
                    continue
                }
                try require([UInt8(1), 2, 5].contains(type) && bytes[offset + 67] <= 1,
                            "invalid directory object type or color")
                let nameBytes = Int(uint16(offset + 64))
                try require(nameBytes >= 4 && nameBytes <= 64 && nameBytes % 2 == 0
                                && uint16(offset + nameBytes - 2) == 0, "invalid UTF-16 directory name length")
                var nameUnits: [UInt16] = []
                for nameOffset in stride(from: 0, to: nameBytes - 2, by: 2) {
                    let unit = uint16(offset + nameOffset)
                    try require(unit != 0, "embedded null in directory name")
                    nameUnits.append(unit)
                }
                try require(validUTF16(nameUnits), "invalid UTF-16 directory name")
                let name = String(decoding: nameUnits, as: UTF16.self)
                try require(!name.contains(where: { "/\\:!".contains($0) }), "illegal directory-name character")
                let left = uint32(offset + 68)
                let right = uint32(offset + 72)
                let child = uint32(offset + 76)
                try require(validID(left) && validID(right) && validID(child)
                                && (type != 2 || child == freeSector), "out-of-range directory link")
                if major == 3 {
                    try require(uint64(offset + 120) <= 0x8000_0000, "invalid version-3 stream size")
                }
                directoryEntries.append(DirectoryEntry(name: name, type: type, left: left, right: right, child: child))
            }
        }
        let root = directoryEntries[0]
        try require(root.type == 5 && root.name == "Root Entry" && root.left == freeSector && root.right == freeSector
                        && directoryEntries.dropFirst().allSatisfy { $0.type != 5 }, "invalid root directory entry")

        // Only root-level active streams identify the document. Embedded Office
        // documents in a child storage must not override their outer container.
        var streamNames = Set<String>()
        var visited: Set<UInt32> = [0]
        var pending: [(id: UInt32, rootLevel: Bool)] = []
        if root.child != freeSector { pending.append((root.child, true)) }
        while let item = pending.popLast() {
            try require(visited.insert(item.id).inserted, "cyclic or duplicate directory links")
            let entry = directoryEntries[Int(item.id)]
            try require(entry.type == 1 || entry.type == 2, "directory points to an unallocated object")
            if item.rootLevel && entry.type == 2 { streamNames.insert(entry.name.lowercased()) }
            if entry.left != freeSector { pending.append((entry.left, item.rootLevel)) }
            if entry.right != freeSector { pending.append((entry.right, item.rootLevel)) }
            if entry.child != freeSector { pending.append((entry.child, false)) }
        }
        try require(directoryEntries.enumerated().allSatisfy { $0.element.type == 0 || visited.contains(UInt32($0.offset)) },
                    "unreachable allocated directory entry")

        let candidates: [DocumentOfficeFormat] = [
            streamNames.contains("worddocument") ? .doc : nil,
            streamNames.contains("workbook") || streamNames.contains("book") ? .xls : nil,
            streamNames.contains("powerpoint document") ? .ppt : nil
        ].compactMap { $0 }
        var warnings = ["OLE header, FAT/DIFAT references and reachable directory structure were checked. Mini-stream allocation and stream bodies were not validated; legacy Office text decoding and document openability are not supported."]
        if candidates.count > 1 { warnings.append("Conflicting legacy Office stream names prevent identifying a single document format.") }
        else if candidates.isEmpty { warnings.append("No supported legacy Office document stream was found in the root storage.") }
        let format = candidates.count == 1 ? candidates[0] : nil
        let mimeType: String
        switch format {
        case .doc: mimeType = "application/msword"
        case .xls: mimeType = "application/vnd.ms-excel"
        case .ppt: mimeType = "application/vnd.ms-powerpoint"
        default: mimeType = oleMIME
        }
        return LegacyOfficeRecognition(format: format, mimeType: mimeType, isStructurallyValid: true, warnings: warnings)
    }

    private static func validUTF16(_ units: [UInt16]) -> Bool {
        var index = 0
        while index < units.count {
            let unit = units[index]
            if (0xD800...0xDBFF).contains(unit) {
                guard index + 1 < units.count, (0xDC00...0xDFFF).contains(units[index + 1]) else { return false }
                index += 2
            } else {
                guard !(0xDC00...0xDFFF).contains(unit) else { return false }
                index += 1
            }
        }
        return true
    }
}
