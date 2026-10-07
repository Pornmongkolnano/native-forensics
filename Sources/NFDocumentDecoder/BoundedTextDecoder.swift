import Foundation

struct DecodedLocalText {
    let value: String
    let encoding: String
    let encodingWasInferred: Bool
}

/// Display interpretation only. Original bytes and their digest remain the
/// evidence; inferred legacy encoding is always reported rather than asserted.
enum BoundedTextDecoder {
    static func decode(_ bytes: Data, allowLegacyEncoding: Bool,
                       prefixMayBeTruncated: Bool = false) -> DecodedLocalText? {
        let utf8Bytes = bytes.starts(with: [0xef, 0xbb, 0xbf]) ? Data(bytes.dropFirst(3)) : bytes
        var candidates = [utf8Bytes]
        if prefixMayBeTruncated && !utf8Bytes.isEmpty {
            // Retained ZIP prefixes can end in the middle of a UTF-8 scalar.
            candidates += (1...min(3, utf8Bytes.count)).map { Data(utf8Bytes.dropLast($0)) }
        }
        for candidate in candidates {
            if let value = String(data: candidate, encoding: .utf8), printable(value) {
                return DecodedLocalText(value: value, encoding: "UTF-8", encodingWasInferred: false)
            }
        }
        guard allowLegacyEncoding, !bytes.contains(where: { byte in
            if byte < 32 { return byte != 9 && byte != 10 && byte != 13 }
            switch byte { case 0x7f,0x81,0x8d,0x8f,0x90,0x9d: return true; default: return false }
        }),
              let value = String(data: bytes, encoding: .windowsCP1252), printable(value) else { return nil }
        return DecodedLocalText(value: value, encoding: "Windows-1252", encodingWasInferred: true)
    }

    private static func printable(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy {
            $0 == "\n" || $0 == "\r" || $0 == "\t" || !CharacterSet.controlCharacters.contains($0)
        }
    }
}
