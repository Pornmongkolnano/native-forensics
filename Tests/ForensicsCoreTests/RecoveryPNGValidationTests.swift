import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

/// Exercise the public isolated-decoder contract using independent PNG bytes
/// and deliberate framing/CRC/deflate mutations. No ImageIO repair is accepted
/// as proof that the original recovered PNG was complete.
@Suite("Recovered PNG structural completeness")
struct RecoveryPNGValidationTests {
    @Test("Independent RGB, alpha, monochrome, palette and Adam7 PNGs remain readable",
          arguments: ["rgb", "rgba", "one-bit", "palette", "adam7", "adam7-all", "adam7-tiny", "16-bit", "wide-row", "split-idat", "ancillary", "padded-idat"])
    func validProfiles(_ profile: String) async throws {
        let data = try PNGOracle.valid(profile)
        let analysis = try await inspect(data)
        #expect(analysis.status == .decoded && analysis.mimeType == "image/png")
        let dimensions: (Int, Int)
        switch profile {
        case "rgb", "split-idat", "ancillary", "padded-idat": dimensions = (17, 13)
        case "adam7-all": dimensions = (8, 8)
        case "adam7-tiny": dimensions = (1, 1)
        case "wide-row": dimensions = (40_000, 1)
        default: dimensions = (5, 3)
        }
        #expect(analysis.pixelWidth == dimensions.0 && analysis.pixelHeight == dimensions.1)
        #expect(analysis.thumbnailPNG != nil)
        if profile == "padded-idat" {
            #expect(analysis.warnings.contains { $0.contains("7 unused trailing IDAT bytes") })
        }
    }

    @Test("Malformed PNG framing, CRCs and incomplete image streams never receive decoded status",
          arguments: ["truncated", "missing-iend", "header-crc", "data-crc", "trailing-bytes", "duplicate-header",
                      "unknown-critical", "separated-idat", "chunk-overflow", "empty-idat", "missing-zlib-trailer",
                      "truncated-idat-valid-crc", "too-few-rows", "too-many-rows", "invalid-filter",
                      "missing-palette", "palette-in-greyscale", "duplicate-palette", "palette-overflow", "reserved-type-bit"])
    func malformedProfiles(_ profile: String) async throws {
        let analysis = try await inspect(PNGOracle.malformed(profile))
        #expect(analysis.status == .failed)
        #expect(analysis.failureCode == "MALFORMED_IMAGE")
        #expect(analysis.textPages.isEmpty && analysis.thumbnailPNG == nil)
    }

    private func inspect(_ data: Data) async throws -> DocumentAnalysis {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("png-oracle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("misleading.pdf")
        try data.write(to: url, options: .withoutOverwriting)
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let analysis = try await DocumentAnalysisClient(helperURL: recoveryCorpusDecoder()).analyze(DocumentInput(
            fileURL: url, expectedSHA256: hash, expectedByteCount: Int64(data.count)))
        #expect(analysis.sourceSHA256 == hash && analysis.sourceByteCount == Int64(data.count))
        #expect(try Data(contentsOf: url) == data)
        return analysis
    }
}

private enum PNGOracle {
    private static let signature = Data([137, 80, 78, 71, 13, 10, 26, 10])
    static func valid(_ profile: String) throws -> Data {
        let encoded: String
        switch profile {
        case "rgba": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAUAAAADCAYAAABbNsX4AAAAFElEQVR4nGMUtI2tZ0ADTOgCOAUBRrQBMOuZVN4AAAAASUVORK5CYII="
        case "one-bit": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAUAAAADAQAAAABzTfhVAAAADklEQVR4nGP4wcTAxAAABOoA/Wy8K6EAAAAASUVORK5CYII="
        case "palette": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAUAAAADAQMAAABh+Fe7AAAABlBMVEURPV2bWCpVpIoiAAAADklEQVR4nGP4wcTAxAAABOoA/Wy8K6EAAAAASUVORK5CYII="
        case "adam7": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAUAAAADCAIAAAGjU2I5AAAAFElEQVR4nGMQtI1lQMIQxICNgiMA9j0KBjPda6EAAAAASUVORK5CYII="
        case "adam7-all": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAAE8ahlKAAAAFUlEQVR4nGMQtI1lgGJcFC04NJIAANKCKsEj2n0HAAAAAElFTkSuQmCC"
        case "adam7-tiny": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAAHncGNIAAAADElEQVR4nGMQtI0FAAEOAKyrFejkAAAAAElFTkSuQmCC"
        case "16-bit": encoded = "iVBORw0KGgoAAAANSUhEUgAAAAUAAAADEAAAAAAuzUZnAAAAEklEQVR4nGNkZGSAAiYYA4UJAADDAAgryQc4AAAAAElFTkSuQmCC"
        case "wide-row": encoded = "iVBORw0KGgoAAAANSUhEUgAAnEAAAAABCAIAAAAyAlzTAAAAkUlEQVR4nO3CgRAAAAgEsBQeKJT8NTJ4gu022VNVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVtXxLwWTZAc5+lgAAAABJRU5ErkJggg=="
        default: encoded = "iVBORw0KGgoAAAANSUhEUgAAABEAAAANCAIAAADAGxJNAAAAHklEQVR4nGMUtI1lIBEwkaphVA8YMDGQDphG9TAAAObxAMVXg9PrAAAAAElFTkSuQmCC"
        }
        let data = try #require(Data(base64Encoded: encoded))
        if profile == "split-idat" || profile == "ancillary" || profile == "padded-idat" {
            var chunks = parse(data)
            if profile == "split-idat" {
                let payload = chunks[1].payload
                chunks.replaceSubrange(1...1, with: [("IDAT", Data(payload.prefix(5))), ("IDAT", Data()), ("IDAT", Data(payload.dropFirst(5)))])
            } else if profile == "ancillary" {
                chunks.insert(("rNDm", Data("unknown ancillary oracle".utf8)), at: 1)
            } else {
                chunks[1].payload.append(contentsOf: [0,0,0,0,0,0,0])
            }
            return assemble(chunks)
        }
        return data
    }
    static func malformed(_ profile: String) throws -> Data {
        let data = try valid("rgb")
        switch profile {
        case "truncated": return Data(data.prefix(44))
        case "missing-iend": return Data(data.dropLast(12))
        case "header-crc": var changed = data; changed[32] ^= 1; return changed
        case "data-crc": var changed = data; changed[74] ^= 1; return changed
        case "trailing-bytes": return data + Data([0])
        case "chunk-overflow": var changed = data; changed.replaceSubrange(33..<37, with: Data([0x7f,0xff,0xff,0xff])); return changed
        default: break
        }
        var chunks = parse(data)
        switch profile {
        case "duplicate-header": chunks.insert(chunks[0], at: 1)
        case "unknown-critical": chunks.insert(("ABCD", Data()), at: 1)
        case "reserved-type-bit": chunks.insert(("rNdm", Data()), at: 1)
        case "separated-idat":
            let payload = chunks[1].payload
            chunks.replaceSubrange(1...1, with: [("IDAT", Data(payload.prefix(5))), ("tEXt", Data("oracle\0text".utf8)), ("IDAT", Data(payload.dropFirst(5)))])
        case "empty-idat": chunks[1].payload = Data()
        case "missing-zlib-trailer": chunks[1].payload = Data(chunks[1].payload.dropLast(4))
        case "truncated-idat-valid-crc": chunks[1].payload = Data(chunks[1].payload.prefix(5))
        case "too-few-rows": chunks[1].payload = try #require(Data(base64Encoded: "eJxjYCAdAAAANAAB"))
        case "too-many-rows": chunks[1].payload = try #require(Data(base64Encoded: "eJxjYBgFo2D4AQAC2AAB"))
        case "invalid-filter": chunks[1].payload = try #require(Data(base64Encoded: "eJxjZSAdsI7qGdVDRz0AXxAAQg=="))
        case "missing-palette": chunks[0].payload[9] = 3
        case "palette-in-greyscale":
            chunks = parse(try valid("one-bit")); chunks.insert(("PLTE", Data([0,0,0])), at: 1)
        case "duplicate-palette": chunks = parse(try valid("palette")); chunks.insert(chunks[1], at: 2)
        case "palette-overflow": chunks = parse(try valid("palette")); chunks[1].payload.append(contentsOf: [0,0,0])
        default: throw RecoveryError.invalidResult
        }
        return assemble(chunks)
    }
    private static func parse(_ data: Data) -> [(type: String, payload: Data)] {
        var chunks: [(String, Data)] = [], offset = 8
        while offset < data.count {
            let length = Int(data[offset]) << 24 | Int(data[offset + 1]) << 16 | Int(data[offset + 2]) << 8 | Int(data[offset + 3])
            chunks.append((String(decoding: data[(offset + 4)..<(offset + 8)], as: UTF8.self), Data(data[(offset + 8)..<(offset + 8 + length)])))
            offset += length + 12
        }
        return chunks
    }
    private static func assemble(_ chunks: [(type: String, payload: Data)]) -> Data {
        var data = signature
        for chunk in chunks {
            append(UInt32(chunk.payload.count), to: &data)
            let bytes = Data(chunk.type.utf8) + chunk.payload
            data.append(bytes)
            // Independent bitwise IEEE CRC oracle; production uses zlib's C implementation.
            var crc = UInt32.max
            for byte in bytes {
                crc ^= UInt32(byte)
                for _ in 0..<8 { crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xedb88320 }
            }
            append(crc ^ UInt32.max, to: &data)
        }
        return data
    }
    private static func append(_ number: UInt32, to data: inout Data) {
        data.append(contentsOf: [UInt8(truncatingIfNeeded: number >> 24), UInt8(truncatingIfNeeded: number >> 16),
                                 UInt8(truncatingIfNeeded: number >> 8), UInt8(truncatingIfNeeded: number)])
    }
}
