import Foundation
import ForensicsCore
import zlib

/// ImageIO can repair truncated PNG data while reporting a complete first
/// image. Validate the original datastream before using its decoded preview as
/// an observation. This checks critical framing, CRCs and the full default
/// image's compressed scanlines, not every ancillary chunk's semantics. Pixel
/// reconstruction and the bounded preview still belong to ImageIO.
/// Format reference: https://www.w3.org/TR/png/#5DataRep
enum PNGStructureValidator {
    enum Validation { case complete(unusedIDATBytes: Int), malformed, imagePixelLimit }

    static func validate(_ data: Data) -> Validation {
        data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Validation in
            let signature: [UInt8] = [137, 80, 78, 71, 13, 10, 26, 10]
            guard bytes.count >= 8, bytes.prefix(8).elementsEqual(signature) else { return .malformed }
            var stream = z_stream()
            guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return .malformed }
            defer { inflateEnd(&stream) }
            var output = [UInt8](repeating: 0, count: 65_536)
            var scanlines: PNGScanlines?
            var streamEnded = false
            var unusedIDATBytes = 0
            var cursor = 8
            var headerSeen = false, paletteSeen = false, dataSeen = false, dataEnded = false
            var colorType: UInt8 = 0, bitDepth: UInt8 = 0
            var dataBytes = 0
            while cursor < bytes.count {
                guard bytes.count - cursor >= 12 else { return .malformed }
                let length = Int(u32(bytes, cursor))
                // PNG integers are at most 2^31-1. Subtraction avoids overflow
                // or allocating a copy from an untrusted chunk length.
                guard length <= Int(Int32.max), length <= bytes.count - cursor - 12 else { return .malformed }
                let typeOffset = cursor + 4, payload = cursor + 8, next = cursor + 12 + length
                let type = u32(bytes, typeOffset)
                for offset in typeOffset..<payload {
                    let byte = bytes[offset]
                    guard (65...90).contains(byte) || (97...122).contains(byte) else { return .malformed }
                }
                // The reserved third letter must be uppercase.
                guard bytes[typeOffset + 2] & 0x20 == 0 else { return .malformed }
                let initial = crc32(0, nil, 0)
                let checksum = crc32(initial, bytes.baseAddress!.advanced(by: typeOffset).assumingMemoryBound(to: UInt8.self), uInt(length + 4))
                guard UInt32(checksum) == u32(bytes, payload + length) else { return .malformed }
                if !headerSeen, type != 0x49484452 { return .malformed } // IHDR
                switch type {
                case 0x49484452: // IHDR, first and exactly once
                    guard !headerSeen, cursor == 8, length == 13 else { return .malformed }
                    let width = u32(bytes, payload), height = u32(bytes, payload + 4)
                    guard width > 0, height > 0, width <= UInt32(Int32.max), height <= UInt32(Int32.max) else { return .malformed }
                    bitDepth = bytes[payload + 8]; colorType = bytes[payload + 9]
                    let validDepth: Bool
                    switch colorType {
                    case 0: validDepth = [1, 2, 4, 8, 16].contains(bitDepth)
                    case 2, 4, 6: validDepth = [8, 16].contains(bitDepth)
                    case 3: validDepth = [1, 2, 4, 8].contains(bitDepth)
                    default: return .malformed
                    }
                    guard validDepth, bytes[payload + 10] == 0, bytes[payload + 11] == 0,
                          bytes[payload + 12] <= 1 else { return .malformed }
                    guard Int64(width) * Int64(height) <= DocumentLimits.maximumImagePixels else { return .imagePixelLimit }
                    let channels = colorType == 2 ? 3 : colorType == 4 ? 2 : colorType == 6 ? 4 : 1
                    scanlines = PNGScanlines(width: Int(width), height: Int(height), bitsPerPixel: channels * Int(bitDepth),
                                             interlaced: bytes[payload + 12] == 1)
                    headerSeen = true
                case 0x504c5445: // PLTE before IDAT; required for indexed colour
                    guard !paletteSeen, !dataSeen, colorType != 0, colorType != 4,
                          length > 0, length <= 768, length.isMultiple(of: 3),
                          colorType != 3 || length / 3 <= 1 << bitDepth else { return .malformed }
                    paletteSeen = true
                case 0x49444154: // Consecutive IDAT chunks form one data stream
                    guard !dataEnded, colorType != 3 || paletteSeen else { return .malformed }
                    dataSeen = true
                    dataBytes += length // Each byte belongs to a bounded input chunk.
                    guard var layout = scanlines,
                          consume(bytes, payload: payload, length: length, stream: &stream,
                                  output: &output, layout: &layout, ended: &streamEnded,
                                  unusedBytes: &unusedIDATBytes) else { return .malformed }
                    scanlines = layout
                case 0x49454e44: // Empty IEND must end the original datastream
                    return length == 0 && dataSeen && dataBytes > 0 && streamEnded && scanlines?.complete == true
                        && next == bytes.count ? .complete(unusedIDATBytes: unusedIDATBytes) : .malformed
                default:
                    // An unknown critical chunk cannot be interpreted safely.
                    guard bytes[typeOffset] & 0x20 != 0 else { return .malformed }
                    if dataSeen { dataEnded = true }
                }
                cursor = next
            }
            return .malformed // no IEND
        }
    }

    private static func consume(_ bytes: UnsafeRawBufferPointer, payload: Int, length: Int,
                                stream: inout z_stream, output: inout [UInt8],
                                layout: inout PNGScanlines, ended: inout Bool, unusedBytes: inout Int) -> Bool {
        // PNG section 11.2.3 permits unused trailing bytes in the final IDAT.
        // Ignore them for decoding only after the full zlib checksum and all
        // expected scanlines passed; preserve/disclose their count separately.
        if ended { unusedBytes += length; return true }
        stream.next_in = UnsafeMutablePointer(mutating: bytes.baseAddress!.advanced(by: payload).assumingMemoryBound(to: UInt8.self))
        stream.avail_in = uInt(length)
        while true {
            let previousInput = stream.total_in, previousOutput = stream.total_out
            var decodedIsValid = true
            let status = output.withUnsafeMutableBufferPointer { decoded -> Int32 in
                stream.next_out = decoded.baseAddress!
                stream.avail_out = uInt(decoded.count)
                let status = inflate(&stream, Z_NO_FLUSH)
                let produced = decoded.count - Int(stream.avail_out)
                decodedIsValid = layout.consume(UnsafeBufferPointer(start: decoded.baseAddress!, count: produced))
                return status
            }
            stream.next_out = nil
            guard decodedIsValid else { return false }
            if status == Z_STREAM_END {
                ended = true
                unusedBytes += Int(stream.avail_in)
                return layout.complete
            }
            guard status == Z_OK || status == Z_BUF_ERROR else { return false }
            if stream.avail_in == 0, stream.avail_out > 0 { return true }
            guard stream.total_in != previousInput || stream.total_out != previousOutput else { return false }
        }
    }

    private static func u32(_ bytes: UnsafeRawBufferPointer, _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 |
        UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }
}

/// Tracks row boundaries without retaining decompressed image data. Each row
/// starts with a PNG filter byte. Adam7 uses up to seven nonempty pass layouts.
private struct PNGScanlines {
    private let passes: [(rowBytes: Int, rowCount: Int)]
    private var pass = 0
    private var rowsFinished = 0
    private var remainingRowBytes = 0
    var complete: Bool { pass == passes.count }

    init(width: Int, height: Int, bitsPerPixel: Int, interlaced: Bool) {
        if interlaced {
            let startsX = [0, 4, 0, 2, 0, 1, 0], startsY = [0, 0, 4, 0, 2, 0, 1]
            let stepsX = [8, 8, 4, 4, 2, 2, 1], stepsY = [8, 8, 8, 4, 4, 2, 2]
            passes = (0..<7).compactMap { index in
                let passWidth = width <= startsX[index] ? 0 : (width - startsX[index] + stepsX[index] - 1) / stepsX[index]
                let passHeight = height <= startsY[index] ? 0 : (height - startsY[index] + stepsY[index] - 1) / stepsY[index]
                return passWidth == 0 || passHeight == 0 ? nil : ((passWidth * bitsPerPixel + 7) / 8, passHeight)
            }
        } else {
            passes = [((width * bitsPerPixel + 7) / 8, height)]
        }
    }

    mutating func consume(_ bytes: UnsafeBufferPointer<UInt8>) -> Bool {
        var cursor = 0
        while cursor < bytes.count {
            guard !complete else { return false }
            if remainingRowBytes == 0 {
                guard bytes[cursor] <= 4 else { return false }
                cursor += 1
                remainingRowBytes = passes[pass].rowBytes
            }
            let consumed = min(bytes.count - cursor, remainingRowBytes)
            cursor += consumed
            remainingRowBytes -= consumed
            if remainingRowBytes == 0 {
                rowsFinished += 1
                if rowsFinished == passes[pass].rowCount { pass += 1; rowsFinished = 0 }
            }
        }
        return true
    }
}
