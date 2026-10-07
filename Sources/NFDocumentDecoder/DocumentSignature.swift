import Foundation

enum DetectedDocumentFormat: Equatable, Sendable {
    case jpeg
    case png
    case gif
    case tiff
    case pdf
    case zip
    case ole
    case mp4
    case asf
    case quicktime
    case riff
    case mpeg
    case unknown

    /// Identifies the container from its bytes. Decoding still validates its contents.
    static func detect(_ data: Data) -> DetectedDocumentFormat {
        data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            func matches(_ signature: [UInt8], at offset: Int = 0) -> Bool {
                guard offset >= 0, offset <= bytes.count,
                      signature.count <= bytes.count - offset else { return false }
                return signature.enumerated().allSatisfy { bytes[offset + $0.offset] == $0.element }
            }

            func bigEndian32(at offset: Int) -> UInt32? {
                guard offset >= 0, offset <= bytes.count,
                      bytes.count - offset >= 4 else { return nil }
                return (0..<4).reduce(UInt32(0)) { ($0 << 8) | UInt32(bytes[offset + $1]) }
            }

            func littleEndian64(at offset: Int) -> UInt64? {
                guard offset >= 0, offset <= bytes.count,
                      bytes.count - offset >= 8 else { return nil }
                return (0..<8).reduce(UInt64(0)) { $0 | (UInt64(bytes[offset + $1]) << ($1 * 8)) }
            }

            if matches([0xFF, 0xD8, 0xFF]) { return .jpeg }
            if matches([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return .png }
            if matches(Array("GIF87a".utf8)) || matches(Array("GIF89a".utf8)) { return .gif }
            if matches([0x49, 0x49, 0x2A, 0x00]) || matches([0x4D, 0x4D, 0x00, 0x2A]) {
                return .tiff
            }

            if matches(Array("%PDF-".utf8)), bytes.count >= 8 {
                let isVersion1 = bytes[5] == 0x31 && bytes[6] == 0x2E && (0x30...0x37).contains(bytes[7])
                let isVersion2 = bytes[5] == 0x32 && bytes[6] == 0x2E && bytes[7] == 0x30
                let hasVersionBoundary = bytes.count == 8 || [0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20].contains(bytes[8])
                if (isVersion1 || isVersion2) && hasVersionBoundary { return .pdf }
            }

            if matches([0x50, 0x4B, 0x03, 0x04]) || matches([0x50, 0x4B, 0x05, 0x06])
                || matches([0x50, 0x4B, 0x07, 0x08]) {
                return .zip
            }
            if matches([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) { return .ole }

            if matches(Array("ftyp".utf8), at: 4), let size = bigEndian32(at: 0) {
                if size >= 16, UInt64(size) <= UInt64(bytes.count), (size - 16) % 4 == 0 {
                    return .mp4
                }
                // Extended-size boxes carry an eight-byte size after the box type.
                if size == 1, let high = bigEndian32(at: 8), let low = bigEndian32(at: 12) {
                    let extendedSize = (UInt64(high) << 32) | UInt64(low)
                    if extendedSize >= 24, extendedSize <= UInt64(bytes.count), (extendedSize - 24) % 4 == 0 {
                        return .mp4
                    }
                }
            }

            if matches([0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
                        0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C]),
               bytes.count >= 30, let headerSize = littleEndian64(at: 16),
               headerSize >= 30, headerSize <= UInt64(bytes.count) {
                return .asf
            }

            if matches(Array("moov".utf8), at: 4) || matches(Array("mdat".utf8), at: 4)
                || matches(Array("wide".utf8), at: 4), let size = bigEndian32(at: 0) {
                if size >= 8, UInt64(size) <= UInt64(bytes.count) { return .quicktime }
                if size == 1, let high = bigEndian32(at: 8), let low = bigEndian32(at: 12) {
                    let extendedSize = (UInt64(high) << 32) | UInt64(low)
                    if extendedSize >= 16, extendedSize <= UInt64(bytes.count) { return .quicktime }
                }
            }

            if matches(Array("RIFF".utf8)), bytes.count >= 12,
               matches(Array("WAVE".utf8), at: 8) || matches(Array("AVI ".utf8), at: 8)
                || matches(Array("WEBP".utf8), at: 8) {
                return .riff
            }

            if matches(Array("ID3".utf8)) || matches([0x00, 0x00, 0x01, 0xBA])
                || matches([0x00, 0x00, 0x01, 0xB3]) {
                return .mpeg
            }
            if bytes.count >= 4, bytes[0] == 0xFF, bytes[1] & 0xE0 == 0xE0 {
                let version = (bytes[1] >> 3) & 0x03
                let layer = (bytes[1] >> 1) & 0x03
                let bitrateIndex = (bytes[2] >> 4) & 0x0F
                let sampleRateIndex = (bytes[2] >> 2) & 0x03
                let emphasis = bytes[3] & 0x03
                // Index zero denotes a valid free-format stream; only fifteen is reserved.
                if version != 1, layer != 0, bitrateIndex != 15,
                   sampleRateIndex != 3, emphasis != 2 {
                    return .mpeg
                }
            }
            return .unknown
        }
    }
}
