import Foundation

/// Independent implementation of the ECMA-167 descriptor and UDF 2.01 VAT
/// layout. No mounted filesystem, repair, carver, or external parser is used.
/// See ECMA TR/112-4 (UDF 2.01), sections 2.1, 2.2.8, 2.2.10 and 2.3.
final class UDFParser {
    private let source: UDFPinnedSource
    private let options: UDFInspectionOptions
    private let progress: @Sendable (UDFInspectionProgress) -> Void
    private let deadline: TimeInterval
    private var metadataBlocks = 0
    private var fidRecords = 0
    private var directoryBytes: Int64 = 0
    private var allocationExtentRecords = 0
    private var partitionStart: Int64 = 0
    private var partitionCapacity: Int64 = 0
    private var partitionNumber: UInt16 = 0
    private var maps: [Bool] = [] // false physical, true virtual, map reference is its array index.
    private var fsdAddress = Address(block: 0, partition: 0)
    private var volumeIdentifier = ""
    private var limitations: [String] = []
    private var uniquePayloadBytes: Int64 = 0
    private var payloadHashes: [String: String] = [:]

    private struct Address: Hashable {
        let block: UInt32
        let partition: UInt16
    }
    private struct Allocation {
        let extents: [UDFSourceExtent]
        let logicalBytes: Int64
        let tagLocations: [TagLocation]
    }
    private struct TagLocation {
        let logicalOffset: Int64
        let byteCount: Int64
        let firstBlock: UInt32
    }
    private struct Node {
        let address: Address
        let sourceOffset: Int64
        let tag: UInt16
        let fileType: UInt8
        let allocation: Allocation
        let timestamps: UDFEntryTimestamps
    }
    private struct VAT {
        let absoluteBlock: Int64
        let previous: UInt32?
        let mappings: [UInt32]
        let modification: UDFTimestamp
        var id: String { "vat-\(absoluteBlock)" }
    }
    private struct FoundFile {
        let path: String
        let node: Node
        let characteristics: UInt8
        let fidOffset: Int64
    }
    private struct Namespace {
        var files: [FoundFile] = []
        var deletedDirectories: [UDFDeletedAncestorProof] = []
        var fileAddresses: Set<Address> = []
    }

    init(source: UDFPinnedSource, options: UDFInspectionOptions,
         progress: @escaping @Sendable (UDFInspectionProgress) -> Void) {
        self.source = source; self.options = options; self.progress = progress
        deadline = ProcessInfo.processInfo.systemUptime + options.timeoutSeconds
    }

    func parse(caseID: UUID) throws -> UDFInspectionResult {
        try options.validate()
        guard source.evidence.byteCount % 2_048 == 0 else {
            throw UDFError.unsupported("Only raw images with complete 2048-byte optical blocks are accepted.")
        }
        try readVolume()
        let latest = try latestVAT()
        var lineage: [VAT] = [], seen: Set<Int64> = [], cursor: VAT? = latest
        while let vat = cursor {
            try check()
            guard seen.insert(vat.absoluteBlock).inserted else { throw UDFError.malformed("A VAT lineage cycle was detected.") }
            guard lineage.count < options.maximumSnapshots else { throw UDFError.limitExceeded("VAT snapshot count") }
            lineage.append(vat)
            if let previous = vat.previous {
                let absolute = partitionStart + Int64(previous)
                guard absolute < vat.absoluteBlock else { throw UDFError.malformed("A previous VAT does not precede its successor.") }
                cursor = try readVAT(absoluteBlock: absolute)
            } else { cursor = nil }
        }

        var snapshots: [UDFSnapshot] = []
        var entries: [UDFFileEntry] = []
        var entryIndex: [String: Int] = [:]
        var latestDeleted: [UDFDeletedAncestorProof] = []
        for (index, vat) in lineage.enumerated() {
            try check()
            progress(.init(stage: "Reading UDF namespace \(index + 1)/\(lineage.count)",
                           completedBytes: uniquePayloadBytes, totalBytes: source.evidence.byteCount, files: entries.count))
            let namespace = try readNamespace(vat)
            if index == 0 { latestDeleted = namespace.deletedDirectories }
            snapshots.append(UDFSnapshot(id: vat.id, vatICBSourceOffset: vat.absoluteBlock * 2_048,
                previousVATLogicalBlock: vat.previous, mappedBlockCount: vat.mappings.count,
                namespaceFileCount: namespace.files.filter { $0.characteristics & 4 == 0 }.count,
                modification: vat.modification))
            for file in namespace.files {
                try check()
                let extentKey = file.node.allocation.extents.map { "\($0.offset):\($0.byteCount):\($0.allocation)" }.joined(separator: ",")
                let hash: String
                if let cached = payloadHashes[extentKey] { hash = cached }
                else {
                    guard file.node.allocation.logicalBytes <= options.maximumPayloadBytes - uniquePayloadBytes else {
                        throw UDFError.limitExceeded("Unique payload-byte budget")
                    }
                    hash = try source.digest(extents: file.node.allocation.extents, check: { try self.check() })
                    uniquePayloadBytes += file.node.allocation.logicalBytes
                    payloadHashes[extentKey] = hash
                }
                // An ICB is stable through directory renames. Content changes get
                // their own row; aliases from earlier states remain in the receipt.
                let id = UDFCoding.hash(Data("\(file.node.address.partition):\(file.node.address.block):\(hash)".utf8))
                if let existingIndex = entryIndex[id] {
                    let existing = entries[existingIndex]
                    guard !existing.snapshotIDs.contains(vat.id) else {
                        throw UDFError.unsupported("Multiple namespace aliases to one ICB/content within a VAT state")
                    }
                    entries[existingIndex] = UDFFileEntry(id: existing.id, originalPath: existing.originalPath,
                        state: existing.state, fidCharacteristics: existing.fidCharacteristics,
                        fidSourceOffset: existing.fidSourceOffset, deletedAncestorProof: existing.deletedAncestorProof,
                        byteCount: existing.byteCount, sha256: existing.sha256, icb: existing.icb,
                        sourceExtents: existing.sourceExtents, timestamps: existing.timestamps,
                        snapshotIDs: existing.snapshotIDs + [vat.id],
                        historicalPaths: file.path == existing.originalPath || existing.historicalPaths.contains(file.path)
                            ? existing.historicalPaths : existing.historicalPaths + [file.path])
                    continue
                }
                guard entries.count < options.maximumFiles else { throw UDFError.limitExceeded("Unique file count") }
                let ancestorProof = latestDeleted.filter { file.path.hasPrefix($0.originalPath + "/") }
                let state: UDFEntryState = file.characteristics & 4 != 0 ? .fidDeleted
                    : index == 0 ? .current : !ancestorProof.isEmpty ? .historicalDeletedAncestor : .historical
                entryIndex[id] = entries.count
                entries.append(UDFFileEntry(id: id, originalPath: file.path, state: state,
                    fidCharacteristics: file.characteristics, fidSourceOffset: file.fidOffset,
                    deletedAncestorProof: ancestorProof, byteCount: file.node.allocation.logicalBytes, sha256: hash,
                    icb: UDFEntryAddress(logicalBlock: file.node.address.block,
                        partitionReference: file.node.address.partition, sourceOffset: file.node.sourceOffset,
                        tagIdentifier: file.node.tag), sourceExtents: file.node.allocation.extents,
                    timestamps: file.node.timestamps, snapshotIDs: [vat.id]))
            }
        }
        limitations.append("The latest VAT is selected from a bounded tail search of at most \(options.tailSearchBlocks) blocks; only its linked predecessors are inventoried.")
        limitations.append("Deleted CS0 identifiers 254/255 are treated as residual labels. Original paths come from earlier valid namespace states; a deleted ancestor does not set a child's own FID deleted bit.")
        limitations.append("This profile supports raw 2048-byte UDF 2.01 physical/virtual maps and recorded short, long and inline allocations. Sparable/metadata maps, extended/continuation allocations, sparse gaps and unrelated sessions are unsupported.")
        limitations.append("Rows retain metadata from the nearest valid namespace state for each ICB/content identity. Older namespace paths and VAT membership are retained; separate historical timestamp versions and within-state hardlink aliases are not inventoried.")
        return UDFInspectionResult(caseID: caseID, sourceEvidenceID: source.evidence.id,
            sourceSHA256: source.evidence.sha256, sourceByteCount: source.evidence.byteCount,
            volumeIdentifier: volumeIdentifier, udfRevision: "2.01", latestSnapshotID: latest.id,
            snapshots: snapshots, entries: entries.sorted { $0.originalPath < $1.originalPath },
            deletedAncestors: latestDeleted, limitations: limitations, options: options)
    }

    private func check() throws {
        try Task.checkCancellation()
        guard ProcessInfo.processInfo.systemUptime <= deadline else { throw UDFError.timeout }
    }

    private func block(_ number: Int64) throws -> Data {
        try check()
        metadataBlocks += 1
        guard metadataBlocks <= options.maximumMetadataBlocks else { throw UDFError.limitExceeded("Metadata-block budget") }
        guard number >= 0, number < source.evidence.byteCount / 2_048 else {
            throw UDFError.malformed("A block address is outside the supplied image.")
        }
        return try source.read(offset: number * 2_048, count: 2_048)
    }

    private func readVolume() throws {
        guard source.evidence.byteCount / 2_048 > 256 else { throw UDFError.unsupported("No optical anchor fits in this image.") }
        var recognition = false
        for number in 16..<32 {
            let data = try block(Int64(number))
            if String(data: data.subdata(in: 1..<6), encoding: .ascii) == "NSR03" { recognition = true }
        }
        guard recognition else { throw UDFError.unsupported("The volume recognition sequence has no NSR03 descriptor.") }
        let anchor = try block(256)
        try UDFDescriptor.validate(anchor, expectedTag: 2, expectedLocation: 256)
        let length = try anchor.udf32(16), start = try anchor.udf32(20)
        guard length > 0, length % 2_048 == 0, length <= 128 * 2_048 else {
            throw UDFError.limitExceeded("Volume descriptor sequence length")
        }
        var partition: Data?, logical: Data?
        var terminated = false
        for step in 0..<Int(length / 2_048) {
            let number = Int64(start) + Int64(step)
            let data = try block(number), tag = try data.udf16(0)
            try UDFDescriptor.validate(data, expectedLocation: UInt32(number))
            if tag == 5 { partition = data }
            if tag == 6 { logical = data }
            if tag == 8 { terminated = true; break }
            guard [1, 4, 5, 6, 7].contains(tag) else { throw UDFError.unsupported("Chained or unknown volume descriptors") }
        }
        guard terminated, let partition, let logical else { throw UDFError.malformed("The volume sequence lacks its partition, logical volume, or terminator.") }
        partitionNumber = try partition.udf16(22)
        partitionStart = Int64(try partition.udf32(188))
        partitionCapacity = Int64(try partition.udf32(192))
        guard partitionCapacity > 0, partitionStart < source.evidence.byteCount / 2_048,
              try logical.udf32(212) == 2_048,
              try logical.udf16(240) == 0x0201 else {
            throw UDFError.unsupported("The selected logical volume is not the raw-2048 UDF 2.01 profile.")
        }
        if partitionStart + partitionCapacity > source.evidence.byteCount / 2_048 {
            limitations.append("The declared physical partition capacity exceeds supplied bytes. Reads remain bounded to supplied bytes; this does not by itself prove truncation on sequential-write media.")
        }
        volumeIdentifier = try UDFDescriptor.name(logical.subdata(in: 84..<212), dString: true)
        fsdAddress = try address(logical, at: 248)
        let tableLength = Int(try logical.udf32(264)), count = Int(try logical.udf32(268))
        guard count == 2, tableLength <= 1_608, tableLength >= 12 else {
            throw UDFError.unsupported("Only one physical and one virtual partition map are supported.")
        }
        var offset = 440
        for _ in 0..<count {
            let kind = try logical.udf8(offset), length = Int(try logical.udf8(offset + 1))
            guard length >= 2, offset + length <= 440 + tableLength else { throw UDFError.malformed("Invalid partition map length.") }
            if kind == 1, length == 6 {
                guard try logical.udf16(offset + 4) == partitionNumber else { throw UDFError.unsupported("Multiple physical partitions") }
                maps.append(false)
            } else if kind == 2, length == 64 {
                let identifier = String(data: logical.subdata(in: (offset + 5)..<(offset + 28)).prefix { $0 != 0 }, encoding: .ascii)
                guard identifier == "*UDF Virtual Partition", try logical.udf16(offset + 38) == partitionNumber,
                      try logical.udf16(offset + 28) == 0x0201 else {
                    throw UDFError.unsupported("A non-2.01 virtual, metadata, or sparable map was found.")
                }
                maps.append(true)
            } else { throw UDFError.unsupported("Unknown partition map type") }
            offset += length
        }
        guard offset == 440 + tableLength, maps.filter({ $0 }).count == 1, maps.filter({ !$0 }).count == 1 else {
            throw UDFError.malformed("The physical/virtual partition map pair is inconsistent.")
        }
    }

    private func latestVAT() throws -> VAT {
        let last = source.evidence.byteCount / 2_048 - 1
        let first = max(partitionStart, last - Int64(options.tailSearchBlocks) + 1)
        for number in stride(from: last, through: first, by: -1) {
            let data = try block(number)
            let tag = try data.udf16(0)
            if (tag == 261 || tag == 266), try data.udf8(27) == 248 {
                return try readVAT(absoluteBlock: number, cachedBlock: data)
            }
        }
        throw UDFError.unsupported("No UDF 2.01 VAT file entry occurs within the bounded image tail.")
    }

    private func readVAT(absoluteBlock: Int64, cachedBlock: Data? = nil) throws -> VAT {
        guard absoluteBlock >= partitionStart, absoluteBlock - partitionStart <= Int64(UInt32.max) else {
            throw UDFError.malformed("Invalid VAT address.")
        }
        let data: Data
        if let cachedBlock { data = cachedBlock } else { data = try block(absoluteBlock) }
        let tag = try data.udf16(0)
        guard [UInt16(261), 266].contains(tag), try data.udf8(27) == 248 else { throw UDFError.malformed("A previous VAT pointer does not identify a VAT file.") }
        try UDFDescriptor.validate(data, expectedLocation: UInt32(absoluteBlock - partitionStart))
        let physicalReference = UInt16(maps.firstIndex(of: false)!)
        let allocation = try allocations(data, absoluteOffset: absoluteBlock * 2_048,
            address: Address(block: UInt32(absoluteBlock - partitionStart), partition: physicalReference), vat: nil)
        guard allocation.logicalBytes <= 2 * 1_024 * 1_024 else { throw UDFError.limitExceeded("VAT payload length") }
        let bytes = try payload(allocation, maximum: 2 * 1_024 * 1_024)
        guard bytes.count >= 152 else { throw UDFError.malformed("VAT header is truncated.") }
        let headerLength = Int(try bytes.udf16(0)), implementationLength = Int(try bytes.udf16(2))
        guard headerLength >= 152, headerLength == 152 + implementationLength, headerLength <= bytes.count,
              (bytes.count - headerLength) % 4 == 0, try bytes.udf16(144) <= 0x0201,
              try bytes.udf16(146) <= 0x0201 else { throw UDFError.unsupported("The VAT header is not the supported 2.01 layout.") }
        let vatVolume = try UDFDescriptor.name(bytes.subdata(in: 4..<132), dString: true)
        if !vatVolume.isEmpty, vatVolume != volumeIdentifier {
            throw UDFError.malformed("A linked VAT belongs to a different logical volume.")
        }
        var mappings: [UInt32] = []
        for position in stride(from: headerLength, to: bytes.count, by: 4) { mappings.append(try bytes.udf32(position)) }
        guard !mappings.isEmpty else { throw UDFError.malformed("The VAT mapping array is empty.") }
        let previous = try bytes.udf32(132)
        let timestamps = try times(data, absoluteOffset: absoluteBlock * 2_048)
        return VAT(absoluteBlock: absoluteBlock, previous: previous == UInt32.max ? nil : previous,
                   mappings: mappings, modification: timestamps.modification)
    }

    private func translate(_ address: Address, vat: VAT?) throws -> Int64 {
        guard Int(address.partition) < maps.count else { throw UDFError.malformed("An allocation references an unknown partition map.") }
        let physical: UInt32
        if maps[Int(address.partition)] {
            guard let vat, Int(address.block) < vat.mappings.count else { throw UDFError.malformed("A virtual block is outside its VAT mapping array.") }
            physical = vat.mappings[Int(address.block)]
            guard physical != UInt32.max else { throw UDFError.unsupported("An unallocated virtual block was requested.") }
        } else { physical = address.block }
        guard Int64(physical) < partitionCapacity else { throw UDFError.malformed("A physical block exceeds declared partition capacity.") }
        let absolute = partitionStart + Int64(physical)
        guard absolute < source.evidence.byteCount / 2_048 else { throw UDFError.malformed("A translated block is beyond supplied bytes.") }
        return absolute
    }

    private func node(_ address: Address, vat: VAT) throws -> Node {
        let absolute = try translate(address, vat: vat)
        let data = try block(absolute), tag = try data.udf16(0)
        guard tag == 261 || tag == 266 else { throw UDFError.unsupported("Indirect, terminal or other unsupported ICB entry") }
        try UDFDescriptor.validate(data, expectedLocation: address.block)
        guard try data.udf16(20) == 4 else { throw UDFError.unsupported("Non-direct ICB strategy") }
        let fileType = try data.udf8(27)
        guard fileType == 4 || fileType == 5 else { throw UDFError.unsupported("Non-regular or non-directory ICB file type") }
        guard try data.udf16(34) & 0x0800 == 0 else { throw UDFError.unsupported("Transformed ICB content") }
        guard try data.udf32(tag == 266 ? 136 : 112) & 0x3fff_ffff == 0 else {
            throw UDFError.unsupported("External extended-attribute ICB")
        }
        if tag == 266, try data.udf32(152) & 0x3fff_ffff != 0 {
            throw UDFError.unsupported("Named stream directory ICB")
        }
        return Node(address: address, sourceOffset: absolute * 2_048, tag: tag, fileType: fileType,
            allocation: try allocations(data, absoluteOffset: absolute * 2_048, address: address, vat: vat),
            timestamps: try times(data, absoluteOffset: absolute * 2_048))
    }

    private func allocations(_ data: Data, absoluteOffset: Int64, address: Address, vat: VAT?) throws -> Allocation {
        let tag = try data.udf16(0), extended = tag == 266
        let info = try data.udf64(56)
        guard info <= UInt64(options.maximumFileBytes) else { throw UDFError.limitExceeded("Per-file byte budget") }
        let length = Int64(info), kind = try data.udf16(34) & 7
        let base = extended ? 216 : 176
        let extendedLength = Int(try data.udf32(extended ? 208 : 168))
        let allocationLength = Int(try data.udf32(extended ? 212 : 172))
        guard extendedLength <= data.count - base, allocationLength <= data.count - base - extendedLength else {
            throw UDFError.malformed("An ICB allocation area exceeds its descriptor block.")
        }
        let start = base + extendedLength
        if kind == 3 {
            guard length <= Int64(allocationLength) else { throw UDFError.malformed("An inline file's information length exceeds its allocation bytes.") }
            if length > 0 { try trackExtent() }
            return Allocation(extents: length == 0 ? [] : [.init(offset: absoluteOffset + Int64(start), byteCount: length, allocation: "inline")],
                logicalBytes: length, tagLocations: [.init(logicalOffset: 0, byteCount: length, firstBlock: address.block)])
        }
        guard kind == 0 || kind == 1 else { throw UDFError.unsupported("Extended or unknown allocation descriptors") }
        let step = kind == 0 ? 8 : 16
        guard allocationLength % step == 0 else { throw UDFError.malformed("A short or long allocation area is misaligned.") }
        var extents: [UDFSourceExtent] = [], tagLocations: [TagLocation] = [], remaining = length
        for position in stride(from: start, to: start + allocationLength, by: step) {
            try check()
            let encoded = try data.udf32(position), extentType = encoded >> 30
            let extentLength = Int64(encoded & 0x3fff_ffff)
            guard extentType == 0 else { throw UDFError.unsupported("Sparse/unrecorded bytes or allocation continuation descriptors") }
            if extentLength == 0 { continue }
            let startBlock = try data.udf32(position + 4)
            let reference = kind == 0 ? address.partition : try data.udf16(position + 8)
            let useful = min(extentLength, remaining)
            if useful > 0 { tagLocations.append(.init(logicalOffset: length - remaining, byteCount: useful, firstBlock: startBlock)) }
            var offset: Int64 = 0
            while offset < useful {
                if offset % 131_072 == 0 { try check() }
                guard Int64(startBlock) + offset / 2_048 <= Int64(UInt32.max) else { throw UDFError.malformed("Allocation block arithmetic overflow.") }
                let blockAddress = Address(block: startBlock + UInt32(offset / 2_048), partition: reference)
                let sourceOffset = try translate(blockAddress, vat: vat) * 2_048
                let amount = min(2_048, useful - offset)
                if let last = extents.last, last.allocation == "recorded", last.offset + last.byteCount == sourceOffset {
                    extents[extents.count - 1] = .init(offset: last.offset, byteCount: last.byteCount + amount)
                } else { try trackExtent(); extents.append(.init(offset: sourceOffset, byteCount: amount)) }
                offset += amount
                guard extents.count <= 65_536 else { throw UDFError.limitExceeded("Fragmented extent count") }
            }
            remaining -= useful
        }
        guard remaining == 0 else { throw UDFError.malformed("Recorded allocations do not cover the file's information length.") }
        return Allocation(extents: extents, logicalBytes: length, tagLocations: tagLocations)
    }

    private func trackExtent() throws {
        allocationExtentRecords += 1
        guard allocationExtentRecords <= options.maximumMetadataBlocks else {
            throw UDFError.limitExceeded("Aggregate allocation-extent budget")
        }
    }

    private func payload(_ allocation: Allocation, maximum: Int) throws -> Data {
        guard allocation.logicalBytes <= maximum else { throw UDFError.limitExceeded("Directory/metadata payload budget") }
        var bytes = Data()
        bytes.reserveCapacity(Int(allocation.logicalBytes))
        for extent in allocation.extents {
            try check()
            bytes.append(try source.read(offset: extent.offset, count: Int(extent.byteCount)))
        }
        return bytes
    }

    private func address(_ data: Data, at offset: Int) throws -> Address {
        guard try data.udf32(offset) & 0xc000_0000 == 0 else { throw UDFError.unsupported("An unrecorded ICB extent was found.") }
        return Address(block: try data.udf32(offset + 4), partition: try data.udf16(offset + 8))
    }

    private func readNamespace(_ vat: VAT) throws -> Namespace {
        let fsdBlock = try translate(fsdAddress, vat: vat), fsd = try block(fsdBlock)
        try UDFDescriptor.validate(fsd, expectedTag: 256, expectedLocation: fsdAddress.block)
        guard try fsd.udf32(448) & 0x3fff_ffff == 0, try fsd.udf32(464) & 0x3fff_ffff == 0 else {
            throw UDFError.unsupported("Chained file-set descriptors or system stream directories")
        }
        let root = try address(fsd, at: 400)
        var namespace = Namespace()
        try directory(root, path: "", vat: vat, ancestors: [], namespace: &namespace)
        return namespace
    }

    private func directory(_ address: Address, path: String, vat: VAT, ancestors: Set<Address>, namespace: inout Namespace) throws {
        try check()
        guard ancestors.count < 64, !ancestors.contains(address) else { throw UDFError.malformed("A directory cycle or excessive nesting was detected.") }
        var ancestors = ancestors; ancestors.insert(address)
        let directory = try node(address, vat: vat)
        guard directory.fileType == 4 else { throw UDFError.malformed("A directory FID points to a regular-file ICB.") }
        let byteBudget = min(options.maximumPayloadBytes, 64 * 1_024 * 1_024)
        guard directory.allocation.logicalBytes <= byteBudget - directoryBytes else {
            throw UDFError.limitExceeded("Aggregate directory metadata byte budget")
        }
        directoryBytes += directory.allocation.logicalBytes
        metadataBlocks += Int((directory.allocation.logicalBytes + 2_047) / 2_048)
        guard metadataBlocks <= options.maximumMetadataBlocks else { throw UDFError.limitExceeded("Directory metadata-block budget") }
        let bytes = try payload(directory.allocation, maximum: options.maximumDirectoryBytes)
        var offset = 0
        while offset < bytes.count {
            try check()
            if bytes.count - offset < 38 {
                guard bytes[offset...].allSatisfy({ $0 == 0 }) else { throw UDFError.malformed("A directory ends in a partial FID.") }
                break
            }
            if try bytes.udf16(offset) == 0, bytes[offset...].allSatisfy({ $0 == 0 }) { break }
            fidRecords += 1
            guard fidRecords <= options.maximumMetadataBlocks else { throw UDFError.limitExceeded("Aggregate FID-record budget") }
            let nameLength = Int(try bytes.udf8(offset + 19)), implementationLength = Int(try bytes.udf16(offset + 36))
            let contentLength = 38 + implementationLength + nameLength
            let total = (contentLength + 3) & ~3
            guard total <= 2_048, total <= bytes.count - offset else { throw UDFError.malformed("A FID exceeds one logical block or its directory information length.") }
            let fid = bytes.subdata(in: offset..<(offset + total))
            let isInline = directory.allocation.extents.first?.allocation == "inline"
            let location: UInt32
            if isInline { location = directory.address.block }
            else {
                guard let range = directory.allocation.tagLocations.first(where: {
                    Int64(offset) >= $0.logicalOffset && Int64(offset) < $0.logicalOffset + $0.byteCount
                }) else { throw UDFError.malformed("A FID has no allocation block provenance.") }
                let blockOffset = (Int64(offset) - range.logicalOffset) / 2_048
                guard Int64(range.firstBlock) + blockOffset <= Int64(UInt32.max) else { throw UDFError.malformed("FID tag location arithmetic overflow.") }
                location = range.firstBlock + UInt32(blockOffset)
            }
            try UDFDescriptor.validate(fid, expectedTag: 257, expectedLocation: location)
            let characteristics = try fid.udf8(18)
            guard characteristics & 0xe0 == 0 else { throw UDFError.unsupported("Reserved FID characteristics") }
            let fidOffset = try payloadOffset(offset, allocation: directory.allocation)
            defer { offset += total }
            if characteristics & 8 != 0 { continue }
            let rawName = fid.subdata(in: (38 + implementationLength)..<contentLength)
            let name = try UDFDescriptor.name(rawName, deleted: characteristics & 4 != 0)
            guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.utf8.contains(0),
                  name.utf8.count <= 1_024, path.utf8.count + name.utf8.count < 4_096 else {
                throw UDFError.malformed("A FID name is empty or unsafe as a logical namespace component.")
            }
            let filePath = path + "/" + name
            let icbLength = try fid.udf32(20) & 0x3fff_ffff
            if characteristics & 4 != 0, characteristics & 2 != 0 {
                guard icbLength == 0 else {
                    throw UDFError.unsupported("Deleted directory links retaining a non-null ICB")
                }
                guard namespace.deletedDirectories.count < options.maximumFiles else {
                    throw UDFError.limitExceeded("Deleted ancestor proof count")
                }
                namespace.deletedDirectories.append(.init(originalPath: filePath, latestSnapshotID: vat.id,
                    fidSourceOffset: fidOffset, fidCharacteristics: characteristics, nullICB: icbLength == 0,
                    rawNameHex: UDFCoding.hex(rawName)))
                // Deleted ancestor links are unreachable in this live namespace.
                // Earlier VAT states provide their actual children and paths.
                continue
            }
            if icbLength == 0 {
                if characteristics & 4 != 0 { continue }
                throw UDFError.malformed("A live FID has a null ICB.")
            }
            let childAddress = try self.address(fid, at: 20)
            if characteristics & 2 != 0 {
                try self.directory(childAddress, path: filePath, vat: vat, ancestors: ancestors, namespace: &namespace)
            } else {
                guard namespace.fileAddresses.insert(childAddress).inserted else {
                    throw UDFError.unsupported("Multiple namespace aliases to one file ICB within a VAT state")
                }
                let child = try node(childAddress, vat: vat)
                guard child.fileType == 5 else { throw UDFError.malformed("A file FID points to a directory ICB.") }
                guard namespace.files.count < options.maximumFiles else { throw UDFError.limitExceeded("Per-snapshot file count") }
                namespace.files.append(.init(path: filePath, node: child, characteristics: characteristics, fidOffset: fidOffset))
            }
        }
    }

    private func payloadOffset(_ index: Int, allocation: Allocation) throws -> Int64 {
        var remaining = Int64(index)
        for extent in allocation.extents {
            if remaining < extent.byteCount { return extent.offset + remaining }
            remaining -= extent.byteCount
        }
        throw UDFError.malformed("A FID source address is outside its recorded allocations.")
    }

    private func times(_ data: Data, absoluteOffset: Int64) throws -> UDFEntryTimestamps {
        let extended = try data.udf16(0) == 266
        let access = extended ? 80 : 72, modification = extended ? 92 : 84, attribute = extended ? 116 : 96
        var creation: UDFTimestamp?
        if extended { creation = try UDFDescriptor.timestamp(data.subdata(in: 104..<116), sourceOffset: absoluteOffset + 104) }
        else {
            let length = Int(try data.udf32(168))
            if length > 0 {
                guard length >= 24, length <= data.count - 176 else { throw UDFError.malformed("Extended attributes are truncated.") }
                let attributes = data.subdata(in: 176..<(176 + length))
                try UDFDescriptor.validate(attributes, expectedTag: 262)
                var position = 24
                while position < attributes.count {
                    guard attributes.count - position >= 12 else { throw UDFError.malformed("A generic extended attribute is truncated.") }
                    let type = try attributes.udf32(position), amount = Int(try attributes.udf32(position + 8))
                    guard amount >= 12, amount <= attributes.count - position else { throw UDFError.malformed("Invalid extended attribute length.") }
                    if type == 5, amount >= 32, try attributes.udf32(position + 16) & 1 != 0 {
                        creation = try UDFDescriptor.timestamp(attributes.subdata(in: (position + 20)..<(position + 32)),
                            sourceOffset: absoluteOffset + 176 + Int64(position + 20))
                    }
                    position += amount
                }
            }
        }
        return UDFEntryTimestamps(
            access: try UDFDescriptor.timestamp(data.subdata(in: access..<(access + 12)), sourceOffset: absoluteOffset + Int64(access)),
            modification: try UDFDescriptor.timestamp(data.subdata(in: modification..<(modification + 12)), sourceOffset: absoluteOffset + Int64(modification)),
            attribute: try UDFDescriptor.timestamp(data.subdata(in: attribute..<(attribute + 12)), sourceOffset: absoluteOffset + Int64(attribute)), creation: creation)
    }
}

enum UDFDescriptor {
    static func validate(_ data: Data, expectedTag: UInt16? = nil, expectedLocation: UInt32? = nil) throws {
        guard data.count >= 16 else { throw UDFError.malformed("Truncated descriptor tag.") }
        let tag = try data.udf16(0), version = try data.udf16(2), location = try data.udf32(12)
        let checksum = data.prefix(16).enumerated().filter { $0.offset != 4 }.reduce(UInt32(0)) { $0 + UInt32($1.element) }
        guard UInt8(truncatingIfNeeded: checksum) == data[4], version == 2 || version == 3,
              expectedTag == nil || expectedTag == tag,
              expectedLocation == nil || expectedLocation == location else {
            throw UDFError.malformed("Descriptor tag identity, location, version or checksum mismatch.")
        }
        let length = Int(try data.udf16(10))
        let minimumCoverage: Int
        switch tag {
        case 1, 2, 4, 5, 8, 256: minimumCoverage = 496
        case 7: minimumCoverage = 8 + Int(try data.udf32(20)) * 8
        case 6: minimumCoverage = 424 + Int(try data.udf32(264))
        case 261: minimumCoverage = 160 + Int(try data.udf32(168)) + Int(try data.udf32(172))
        case 266: minimumCoverage = 200 + Int(try data.udf32(208)) + Int(try data.udf32(212))
        case 257: minimumCoverage = 22 + Int(try data.udf8(19)) + Int(try data.udf16(36))
        case 262: minimumCoverage = 8
        default: minimumCoverage = 0
        }
        guard length >= minimumCoverage, length <= data.count - 16,
              crc(data.subdata(in: 16..<(16 + length))) == (try data.udf16(8)) else {
            throw UDFError.malformed("Descriptor tag \(tag) body CRC mismatch or coverage \(length) shorter than required \(minimumCoverage).")
        }
    }

    static func crc(_ data: Data) -> UInt16 {
        var value: UInt16 = 0
        for byte in data {
            value ^= UInt16(byte) << 8
            for _ in 0..<8 { value = value & 0x8000 != 0 ? (value &<< 1) ^ 0x1021 : value &<< 1 }
        }
        return value
    }

    static func name(_ data: Data, dString: Bool = false, deleted: Bool = false) throws -> String {
        let raw: Data
        if dString {
            guard let count = data.last, Int(count) < data.count else { throw UDFError.malformed("A d-string length exceeds its field.") }
            if count == 0 { return "" }
            raw = data.prefix(Int(count))
        } else { raw = data }
        guard let compression = raw.first else { return "" }
        let mode: UInt8
        if compression == 254 || compression == 255 {
            guard deleted else { throw UDFError.malformed("A deleted-only CS0 identifier occurs in a live FID.") }
            // These are residual bytes for corroborating an older namespace,
            // never a live UDF name. Preserve their original raw form separately.
            mode = compression == 254 ? 8 : 16
        } else { mode = compression }
        if mode == 8 { return String(String.UnicodeScalarView(raw.dropFirst().map { UnicodeScalar(UInt32($0))! })) }
        guard mode == 16, (raw.count - 1) % 2 == 0 else { throw UDFError.unsupported("Unknown or malformed CS0 name compression") }
        var units: [UInt16] = []
        let bytes = [UInt8](raw.dropFirst())
        for offset in stride(from: 0, to: bytes.count, by: 2) {
            let unit = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            guard !(0xd800...0xdfff).contains(unit), unit != 0xfffe, unit != 0xfeff else {
                throw UDFError.unsupported("Non-UCS2 or byte-order-mark CS0 character")
            }
            units.append(unit)
        }
        return String(decoding: units, as: UTF16.self)
    }

    static func timestamp(_ data: Data, sourceOffset: Int64) throws -> UDFTimestamp {
        guard data.count == 12 else { throw UDFError.malformed("Truncated timestamp.") }
        let typeAndZone = try data.udf16(0), type = typeAndZone >> 12
        var zone = Int(typeAndZone & 0x0fff)
        if zone & 0x800 != 0 { zone -= 4_096 }
        let microsecond = Int(data[9]) * 10_000 + Int(data[10]) * 100 + Int(data[11])
        guard data[9] < 100, data[10] < 100, data[11] < 100 else { throw UDFError.malformed("Timestamp subsecond fields are invalid.") }
        // All-zero timestamps are unspecified, not invented as epoch zero.
        if data.allSatisfy({ $0 == 0 }) {
            return .init(rawHex: UDFCoding.hex(data), sourceOffset: sourceOffset, type: type,
                         timezoneMinutes: nil, utcDate: nil, microsecond: 0)
        }
        var calendar = Calendar(identifier: .gregorian); calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = DateComponents(year: Int(try data.udf16(2)), month: Int(data[4]), day: Int(data[5]),
            hour: Int(data[6]), minute: Int(data[7]), second: Int(data[8]))
        guard let date = calendar.date(from: components), components.year! >= 1,
              calendar.component(.year, from: date) == components.year,
              calendar.component(.month, from: date) == components.month,
              calendar.component(.day, from: date) == components.day,
              calendar.component(.hour, from: date) == components.hour,
              calendar.component(.minute, from: date) == components.minute,
              calendar.component(.second, from: date) == components.second else {
            throw UDFError.malformed("Timestamp calendar fields are invalid.")
        }
        let timezone: Int? = type == 0 ? 0 : type == 1 && zone != -2_047 && (-1_440...1_440).contains(zone) ? zone : nil
        return .init(rawHex: UDFCoding.hex(data), sourceOffset: sourceOffset, type: type,
                     timezoneMinutes: timezone,
                     utcDate: timezone.map { date.addingTimeInterval(-Double($0) * 60 + Double(microsecond) / 1_000_000) },
                     microsecond: microsecond)
    }
}

extension Data {
    fileprivate func udf8(_ offset: Int) throws -> UInt8 {
        guard offset >= 0, offset < count else { throw UDFError.malformed("Metadata integer offset is out of range.") }
        return self[startIndex + offset]
    }
    fileprivate func udf16(_ offset: Int) throws -> UInt16 {
        UInt16(try udf8(offset)) | UInt16(try udf8(offset + 1)) << 8
    }
    fileprivate func udf32(_ offset: Int) throws -> UInt32 {
        UInt32(try udf16(offset)) | UInt32(try udf16(offset + 2)) << 16
    }
    fileprivate func udf64(_ offset: Int) throws -> UInt64 {
        UInt64(try udf32(offset)) | UInt64(try udf32(offset + 4)) << 32
    }
}
