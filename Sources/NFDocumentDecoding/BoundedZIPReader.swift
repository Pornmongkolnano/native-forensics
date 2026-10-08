import Foundation
import zlib

struct BoundedZIPEntry {
    let name: String
    let data: Data
    let originalByteCount: Int
    let isDataTruncated: Bool
    let isDataOmitted: Bool

    init(name: String, data: Data, originalByteCount: Int? = nil,
         isDataTruncated: Bool = false, isDataOmitted: Bool = false) {
        self.name = name
        self.data = data
        self.originalByteCount = originalByteCount ?? data.count
        self.isDataTruncated = isDataTruncated
        self.isDataOmitted = isDataOmitted
    }
}

struct BoundedZIPArchive {
    let entries: [BoundedZIPEntry]
}

enum ZIPReaderError: Error {
    case malformed
    case unsupported
    case limitExceeded
}

/// Validates every entry in a regular ZIP container with bounded stream buffers.
/// Only bounded XML parts and generic text prefixes are retained; binary media
/// and large XML retain names/sizes and omission flags after full CRC validation.
/// No entry path is written to disk.
enum BoundedZIPReader {
    private static let maximumInputBytes = 128 * 1_024 * 1_024
    private static let maximumEntries = 2_048
    private static let maximumEntryBytes = 128 * 1_024 * 1_024
    private static let maximumTotalBytes = 256 * 1_024 * 1_024
    private static let maximumExpansionRatio = 200
    private static let maximumXMLBytes = 16 * 1_024 * 1_024
    private static let maximumRetainedBytes = 64 * 1_024 * 1_024
    private static let maximumGenericTextBytes = 1_024 * 1_024
    private static let streamChunkBytes = 64 * 1_024

    static func read(_ data: Data) throws -> BoundedZIPArchive {
        guard data.count <= maximumInputBytes else { throw ZIPReaderError.limitExceeded }
        return try data.withUnsafeBytes { bytes in
            let reader = ZIPBytes(bytes: bytes)
            let endOffset = try endOfCentralDirectory(reader)
            let disk = try reader.u16(endOffset + 4)
            let directoryDisk = try reader.u16(endOffset + 6)
            let diskEntries = try reader.u16(endOffset + 8)
            let entryCount = try reader.u16(endOffset + 10)
            let directorySize = try reader.u32(endOffset + 12)
            let directoryOffset = try reader.u32(endOffset + 16)
            guard disk == 0, directoryDisk == 0, diskEntries == entryCount else {
                throw ZIPReaderError.unsupported
            }
            guard entryCount != UInt16.max, directorySize != UInt32.max,
                  directoryOffset != UInt32.max else { throw ZIPReaderError.unsupported }
            guard Int(entryCount) <= maximumEntries else { throw ZIPReaderError.limitExceeded }
            let centralStart = Int(directoryOffset)
            let centralRange = try reader.range(centralStart, Int(directorySize))
            guard centralRange.upperBound == endOffset else { throw ZIPReaderError.malformed }

            var cursor = centralStart
            var totalOutputBytes = 0
            var names: Set<String> = []
            var headers: [ZIPEntryHeader] = []
            headers.reserveCapacity(Int(entryCount))
            for _ in 0..<Int(entryCount) {
                guard cursor <= centralRange.upperBound - 46,
                      try reader.u32(cursor) == 0x0201_4b50 else { throw ZIPReaderError.malformed }
                let version = try reader.u16(cursor + 6)
                let flags = try reader.u16(cursor + 8)
                let method = try reader.u16(cursor + 10)
                let modificationTime = try reader.u16(cursor + 12)
                let modificationDate = try reader.u16(cursor + 14)
                let crc = try reader.u32(cursor + 16)
                let compressed = try reader.u32(cursor + 20)
                let uncompressed = try reader.u32(cursor + 24)
                let nameLength = Int(try reader.u16(cursor + 28))
                let extraLength = Int(try reader.u16(cursor + 30))
                let commentLength = Int(try reader.u16(cursor + 32))
                let startDisk = try reader.u16(cursor + 34)
                let localOffset = try reader.u32(cursor + 42)
                guard startDisk == 0, version <= 20,
                      compressed != UInt32.max, uncompressed != UInt32.max,
                      localOffset != UInt32.max else { throw ZIPReaderError.unsupported }
                try validateFlags(flags, method: method)
                let nameRange = try reader.range(cursor + 46, nameLength)
                let extraRange = try reader.range(nameRange.upperBound, extraLength)
                let commentRange = try reader.range(extraRange.upperBound, commentLength)
                guard commentRange.upperBound <= centralRange.upperBound else { throw ZIPReaderError.malformed }
                try validateExtraFields(reader, range: extraRange)
                guard let name = String(bytes: bytes[nameRange], encoding: .utf8),
                      safeName(name), names.insert(name.precomposedStringWithCanonicalMapping).inserted else {
                    throw ZIPReaderError.malformed
                }

                let compressedSize = Int(compressed)
                let uncompressedSize = Int(uncompressed)
                guard uncompressedSize <= maximumEntryBytes,
                      uncompressedSize <= compressedSize * maximumExpansionRatio,
                      uncompressedSize <= maximumTotalBytes - totalOutputBytes else {
                    throw ZIPReaderError.limitExceeded
                }
                totalOutputBytes += uncompressedSize
                if method == 0, compressed != uncompressed { throw ZIPReaderError.malformed }
                if name.hasSuffix("/"), uncompressedSize != 0 { throw ZIPReaderError.malformed }

                let localRecord = try localRecord(reader, offset: Int(localOffset),
                                                  centralStart: centralStart, version: version,
                                                  flags: flags, method: method,
                                                  modificationTime: modificationTime,
                                                  modificationDate: modificationDate,
                                                  crc: crc, compressed: compressed,
                                                  uncompressed: uncompressed, nameRange: nameRange)
                headers.append(ZIPEntryHeader(name: name, method: method, crc: crc,
                                              uncompressedSize: uncompressedSize,
                                              payload: localRecord.payload, record: localRecord.record))
                cursor = commentRange.upperBound
            }
            guard cursor == centralRange.upperBound else { throw ZIPReaderError.malformed }

            let records = headers.map(\.record).sorted { $0.lowerBound < $1.lowerBound }
            for index in records.indices.dropFirst() {
                guard records[index - 1].upperBound <= records[index].lowerBound else {
                    throw ZIPReaderError.malformed
                }
            }

            var entries: [BoundedZIPEntry] = []
            entries.reserveCapacity(headers.count)
            var retainedBytes = 0
            var retainedGenericBytes = 0
            for header in headers {
                let plan = retentionPlan(header, retainedBytes: retainedBytes,
                                         retainedGenericBytes: retainedGenericBytes)
                let retained = try streamEntry(reader, header: header, retainBytes: plan.byteCount)
                retainedBytes += retained.count
                if plan.isGenericText { retainedGenericBytes += retained.count }
                entries.append(BoundedZIPEntry(name: header.name, data: retained,
                                              originalByteCount: header.uncompressedSize,
                                              isDataTruncated: plan.isTruncated,
                                              isDataOmitted: plan.isOmitted))
            }
            return BoundedZIPArchive(entries: entries)
        }
    }

    private static func endOfCentralDirectory(_ reader: ZIPBytes) throws -> Int {
        guard reader.bytes.count >= 22 else { throw ZIPReaderError.malformed }
        let last = reader.bytes.count - 22
        let first = max(0, last - Int(UInt16.max))
        var candidate: Int?
        for offset in stride(from: last, through: first, by: -1) {
            if try reader.u32(offset) == 0x0605_4b50,
               offset + 22 + Int(try reader.u16(offset + 20)) == reader.bytes.count {
                let count = try reader.u16(offset + 10)
                let size = try reader.u32(offset + 12)
                let start = try reader.u32(offset + 16)
                let zip64 = count == UInt16.max || size == UInt32.max || start == UInt32.max
                // An EOCD-like byte sequence can be part of the real comment.
                // Its directory must reach this record, and an empty archive
                // cannot conceal preceding local files. Ambiguous candidates
                // are rejected rather than silently choosing an interpretation.
                let coherent = zip64
                    ? try zip64RecordPrecedesEOCD(reader, offset: offset)
                    : try zip32DirectoryPrecedesEOCD(reader, offset: offset,
                                                    count: Int(count), size: Int(size), start: Int(start))
                guard coherent else { continue }
                guard candidate == nil else { throw ZIPReaderError.malformed }
                candidate = offset
            }
        }
        guard let candidate else { throw ZIPReaderError.malformed }
        return candidate
    }

    private static func zip32DirectoryPrecedesEOCD(_ reader: ZIPBytes, offset: Int,
                                                  count: Int, size: Int, start: Int) throws -> Bool {
        guard size <= offset, start == offset - size else { return false }
        if count == 0 { return offset == 0 && size == 0 }
        guard size >= count * 46 else { return false }
        var cursor = start
        for _ in 0..<count {
            guard cursor <= offset - 46, try reader.u32(cursor) == 0x0201_4b50 else { return false }
            let nameLength = Int(try reader.u16(cursor + 28))
            let variableSize = nameLength + Int(try reader.u16(cursor + 30)) + Int(try reader.u16(cursor + 32))
            guard nameLength > 0, variableSize <= offset - cursor - 46 else { return false }
            cursor += 46 + variableSize
        }
        return cursor == offset
    }

    private static func zip64RecordPrecedesEOCD(_ reader: ZIPBytes, offset: Int) throws -> Bool {
        // ZIP64 is unsupported, but a sentinel in an arbitrary comment must not
        // masquerade as a second end record. Require its locator and bounded
        // end record before allowing the caller to classify it as unsupported.
        guard offset >= 20 else { return false }
        let locator = offset - 20
        guard try reader.u32(locator) == 0x0706_4b50 else { return false }
        let recordOffset = try reader.u64(locator + 8)
        guard recordOffset <= UInt64(locator), locator - Int(recordOffset) >= 56 else { return false }
        let record = Int(recordOffset)
        guard try reader.u32(record) == 0x0606_4b50 else { return false }
        let recordSize = try reader.u64(record + 4)
        return recordSize >= 44 && recordSize == UInt64(locator - record - 12)
    }

    private static func validateFlags(_ flags: UInt16, method: UInt16) throws {
        // Only deflate options, an optional data descriptor, and UTF-8 names are
        // supported. Encryption, masked headers and patched data are rejected.
        guard flags & ~UInt16(0x080e) == 0, method == 0 || method == 8 else {
            throw ZIPReaderError.unsupported
        }
        guard method != 0 || flags & 0x0006 == 0 else { throw ZIPReaderError.unsupported }
    }

    private static func safeName(_ name: String) -> Bool {
        guard !name.isEmpty, !name.hasPrefix("/"), !name.contains("\\"),
              !name.unicodeScalars.contains(where: { $0.value == 0 }) else { return false }
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts[0].contains(":"), !parts.contains("."), !parts.contains("..") else { return false }
        return parts.enumerated().allSatisfy { index, part in
            !part.isEmpty || (index == parts.count - 1 && name.hasSuffix("/"))
        }
    }

    private static func validateExtraFields(_ reader: ZIPBytes, range: Range<Int>) throws {
        var cursor = range.lowerBound
        while cursor < range.upperBound {
            guard range.upperBound - cursor >= 4 else { throw ZIPReaderError.malformed }
            let identifier = try reader.u16(cursor)
            let length = Int(try reader.u16(cursor + 2))
            let field = try reader.range(cursor + 4, length)
            guard field.upperBound <= range.upperBound else { throw ZIPReaderError.malformed }
            guard identifier != 0x0001 else { throw ZIPReaderError.unsupported }
            cursor = field.upperBound
        }
    }

    private static func localRecord(_ reader: ZIPBytes, offset: Int, centralStart: Int,
                                    version: UInt16, flags: UInt16, method: UInt16,
                                    modificationTime: UInt16, modificationDate: UInt16,
                                    crc: UInt32, compressed: UInt32, uncompressed: UInt32,
                                    nameRange: Range<Int>) throws -> (payload: Range<Int>, record: Range<Int>) {
        guard offset <= centralStart - 30,
              try reader.u32(offset) == 0x0403_4b50,
              try reader.u16(offset + 4) == version,
              try reader.u16(offset + 6) == flags,
              try reader.u16(offset + 8) == method,
              try reader.u16(offset + 10) == modificationTime,
              try reader.u16(offset + 12) == modificationDate else { throw ZIPReaderError.malformed }
        let localCRC = try reader.u32(offset + 14)
        let localCompressed = try reader.u32(offset + 18)
        let localUncompressed = try reader.u32(offset + 22)
        let localNameLength = Int(try reader.u16(offset + 26))
        let localExtraLength = Int(try reader.u16(offset + 28))
        let localNameRange = try reader.range(offset + 30, localNameLength)
        let localExtraRange = try reader.range(localNameRange.upperBound, localExtraLength)
        guard localNameLength == nameRange.count,
              reader.bytes[localNameRange].elementsEqual(reader.bytes[nameRange]) else {
            throw ZIPReaderError.malformed
        }
        try validateExtraFields(reader, range: localExtraRange)
        let payload = try reader.range(localExtraRange.upperBound, Int(compressed))
        guard payload.upperBound <= centralStart else { throw ZIPReaderError.malformed }
        var end = payload.upperBound
        if flags & 0x0008 == 0 {
            guard localCRC == crc, localCompressed == compressed,
                  localUncompressed == uncompressed else { throw ZIPReaderError.malformed }
        } else {
            guard (localCRC == 0 || localCRC == crc),
                  (localCompressed == 0 || localCompressed == compressed),
                  (localUncompressed == 0 || localUncompressed == uncompressed) else {
                throw ZIPReaderError.malformed
            }
            end = try descriptorEnd(reader, offset: end, centralStart: centralStart,
                                    crc: crc, compressed: compressed, uncompressed: uncompressed)
        }
        return (payload, offset..<end)
    }

    private static func descriptorEnd(_ reader: ZIPBytes, offset: Int, centralStart: Int,
                                      crc: UInt32, compressed: UInt32, uncompressed: UInt32) throws -> Int {
        if offset <= centralStart - 16,
           try reader.u32(offset) == 0x0807_4b50,
           try reader.u32(offset + 4) == crc,
           try reader.u32(offset + 8) == compressed,
           try reader.u32(offset + 12) == uncompressed {
            return offset + 16
        }
        // CRC-32 can itself equal the optional signature, so also validate the
        // unprefixed form rather than treating that value as a signature alone.
        if offset <= centralStart - 12,
           try reader.u32(offset) == crc,
           try reader.u32(offset + 4) == compressed,
           try reader.u32(offset + 8) == uncompressed {
            return offset + 12
        }
        throw ZIPReaderError.malformed
    }

    private static func retentionPlan(_ header: ZIPEntryHeader, retainedBytes: Int,
                                      retainedGenericBytes: Int) -> ZIPRetentionPlan {
        let name = header.name.lowercased()
        let size = header.uncompressedSize
        let availableBytes = maximumRetainedBytes - retainedBytes
        if name.hasSuffix(".xml") || name.hasSuffix(".rels") {
            let retain = size <= maximumXMLBytes && size <= availableBytes
            return ZIPRetentionPlan(byteCount: retain ? size : 0,
                                    isTruncated: false, isOmitted: !retain,
                                    isGenericText: false)
        }
        if [".txt", ".csv", ".log", ".json"].contains(where: { name.hasSuffix($0) }) {
            let prefixSize = min(size, availableBytes, maximumGenericTextBytes - retainedGenericBytes)
            return ZIPRetentionPlan(byteCount: prefixSize, isTruncated: prefixSize != size,
                                    isOmitted: prefixSize == 0 && size != 0,
                                    isGenericText: true)
        }
        return ZIPRetentionPlan(byteCount: 0, isTruncated: false,
                                isOmitted: size != 0, isGenericText: false)
    }

    private static func streamEntry(_ reader: ZIPBytes, header: ZIPEntryHeader,
                                    retainBytes: Int) throws -> Data {
        var retained = Data()
        retained.reserveCapacity(retainBytes)
        var checksum = crc32(0, nil, 0)
        if header.method == 0 {
            var cursor = header.payload.lowerBound
            while cursor < header.payload.upperBound {
                let end = min(cursor + streamChunkBytes, header.payload.upperBound)
                let chunk = UnsafeRawBufferPointer(rebasing: reader.bytes[cursor..<end])
                checksum = crc32(checksum, chunk.bindMemory(to: UInt8.self).baseAddress, uInt(chunk.count))
                retainPrefix(chunk, into: &retained, limit: retainBytes)
                cursor = end
            }
        } else {
            checksum = try inflateRaw(reader, payload: header.payload,
                                      expectedBytes: header.uncompressedSize,
                                      retained: &retained, retainBytes: retainBytes)
        }
        guard UInt32(checksum) == header.crc, retained.count == retainBytes else {
            throw ZIPReaderError.malformed
        }
        return retained
    }

    private static func retainPrefix(_ bytes: UnsafeRawBufferPointer,
                                     into retained: inout Data, limit: Int) {
        let count = min(bytes.count, limit - retained.count)
        if count > 0 { retained.append(contentsOf: bytes.prefix(count)) }
    }

    private static func inflateRaw(_ reader: ZIPBytes, payload: Range<Int>, expectedBytes: Int,
                                   retained: inout Data, retainBytes: Int) throws -> uLong {
        var stream = z_stream()
        let initialized = inflateInit2_(&stream, -MAX_WBITS, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initialized == Z_OK else { throw ZIPReaderError.unsupported }
        defer { inflateEnd(&stream) }
        var chunk = Data(count: streamChunkBytes)
        var suppliedInputBytes = 0
        var checksum = crc32(0, nil, 0)
        while true {
            if stream.avail_in == 0, suppliedInputBytes < payload.count {
                let inputSize = min(streamChunkBytes, payload.count - suppliedInputBytes)
                stream.next_in = UnsafeMutablePointer(mutating: reader.bytes.bindMemory(to: UInt8.self)
                    .baseAddress!.advanced(by: payload.lowerBound + suppliedInputBytes))
                stream.avail_in = uInt(inputSize)
                suppliedInputBytes += inputSize
            }
            let previousInputBytes = stream.total_in
            let previousOutputBytes = stream.total_out
            let status = try chunk.withUnsafeMutableBytes { outputBytes in
                stream.next_out = outputBytes.bindMemory(to: UInt8.self).baseAddress!
                stream.avail_out = uInt(outputBytes.count)
                let status = inflate(&stream, Z_NO_FLUSH)
                let produced = outputBytes.count - Int(stream.avail_out)
                guard stream.total_out <= expectedBytes else { throw ZIPReaderError.malformed }
                let decoded = UnsafeRawBufferPointer(rebasing: outputBytes.prefix(produced))
                if produced > 0 {
                    checksum = crc32(checksum, decoded.bindMemory(to: UInt8.self).baseAddress, uInt(decoded.count))
                }
                retainPrefix(decoded, into: &retained, limit: retainBytes)
                return status
            }
            if status == Z_STREAM_END {
                guard stream.total_in == payload.count, stream.total_out == expectedBytes else {
                    throw ZIPReaderError.malformed
                }
                return checksum
            }
            guard status == Z_OK,
                  stream.total_in != previousInputBytes || stream.total_out != previousOutputBytes else {
                throw ZIPReaderError.malformed
            }
        }
    }
}

private struct ZIPEntryHeader {
    let name: String
    let method: UInt16
    let crc: UInt32
    let uncompressedSize: Int
    let payload: Range<Int>
    let record: Range<Int>
}

private struct ZIPRetentionPlan {
    let byteCount: Int
    let isTruncated: Bool
    let isOmitted: Bool
    let isGenericText: Bool
}

private struct ZIPBytes {
    let bytes: UnsafeRawBufferPointer

    func range(_ offset: Int, _ length: Int) throws -> Range<Int> {
        guard offset >= 0, length >= 0, offset <= bytes.count,
              length <= bytes.count - offset else { throw ZIPReaderError.malformed }
        return offset..<(offset + length)
    }

    func u16(_ offset: Int) throws -> UInt16 {
        _ = try range(offset, 2)
        return UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
    }

    func u32(_ offset: Int) throws -> UInt32 {
        _ = try range(offset, 4)
        return UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }

    func u64(_ offset: Int) throws -> UInt64 {
        UInt64(try u32(offset)) | UInt64(try u32(offset + 4)) << 32
    }
}
