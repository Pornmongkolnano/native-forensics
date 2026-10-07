import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Recorded RAW recovery scan scope")
struct RecoveryScanScopeTests {
    @Test("New jobs persist whole-image selection and legacy records retain their earlier selection")
    func commandProvenance() throws {
        let options = RecoveryOptions()
        #expect(options.photoRecCommand == "partition_none,wholespace,search")
        #expect(options.scanScope == "whole-single-RAW-image")
        let encoded = try JSONEncoder().encode(options)
        #expect(try JSONDecoder().decode(RecoveryOptions.self, from: encoded) == options)
        var legacy = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(legacy.removeValue(forKey: "photoRecCommand") as? String == options.photoRecCommand)
        let old = try JSONDecoder().decode(RecoveryOptions.self, from: JSONSerialization.data(withJSONObject: legacy))
        #expect(old.photoRecCommand == "search")
        #expect(old.scanScope == "auto-detected-selected-partition")
        let roundTrip = try JSONEncoder().encode(old)
        #expect(try JSONDecoder().decode(RecoveryOptions.self, from: roundTrip) == old)
        #expect(String(decoding: roundTrip, as: UTF8.self).contains("\"photoRecCommand\":\"search\""))
    }

    @Test("Decoded records cannot introduce arbitrary scanner commands", arguments: ["", "search,inter", "partition_none,search,write", "partition_i386,search"])
    func rejectsUnknownCommands(_ command: String) throws {
        var values = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(RecoveryOptions())) as? [String: Any])
        values["photoRecCommand"] = command
        let bytes = try JSONSerialization.data(withJSONObject: values)
        #expect(throws: RecoveryError.invalidOptions) { try JSONDecoder().decode(RecoveryOptions.self, from: bytes) }
    }

    @Test("Installed PhotoRec recovers an exact-byte sentinel outside a valid MBR partition",
          .enabled(if: FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/photorec")))
    func wholeImageIncludesPartitionGap() async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("recovery-scope-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("mbr.raw")
        let png = try #require(Data(base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j6GkAAAAASUVORK5CYII="))
        let expectedOffsets: [Int64] = [2 * 1_048_576, 12 * 1_048_576]
        let image = makeMBRImage(png: png, at: expectedOffsets)
        try image.write(to: source)
        let executable = URL(fileURLWithPath: "/opt/homebrew/bin/photorec").resolvingSymlinksInPath()

        // The control proves this fixture really exercises partition selection:
        // the old bare command sees the inner sentinel and misses the outer one.
        let baseline = try RecoveryProcessRunner.run(executableURL: executable,
            arguments: ["/d", "baseline", "/cmd", "mbr.raw", "search"], workingDirectory: root, timeout: 60)
        #expect(baseline.exitStatus == 0)
        let reportURL = root.appendingPathComponent("baseline.1/report.xml")
        let oldEntries = try RecoveryReportParser.parse(Data(contentsOf: reportURL),
            sourceSize: Int64(image.count), maximumFiles: 10)
        let oldPNGs = oldEntries.filter { $0.filename.hasSuffix(".png") }
        #expect(oldPNGs.count == 1)
        #expect(oldPNGs.first?.byteRuns.first?.sourceOffset == expectedOffsets[0])

        let created = try CaseStore.create(name: "Synthetic MBR scope", in: root)
        let inspection = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspection, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let result = try await PhotoRecRecoveryService(executableURL: executable)
            .recover(evidence: evidence, in: forensicCase, options: RecoveryOptions(timeout: 60))
        let artifacts = result.artifacts.filter { $0.formatHint == "png" }
        #expect(result.status == .completed && artifacts.count == 2)
        #expect(result.options.scanScope == "whole-single-RAW-image")
        #expect(Set(artifacts.compactMap { $0.verifiedByteRuns.first?.sourceOffset }) == Set(expectedOffsets))
        let digest = SHA256.hash(data: png).map { String(format: "%02x", $0) }.joined()
        for artifact in artifacts {
            #expect(artifact.sha256 == digest && artifact.byteCount == Int64(png.count))
            #expect(artifact.validationStatus == .sourceBytesVerified && artifact.deletionStatus == "unknown")
            #expect(artifact.verifiedByteRuns.count == 1 && artifact.verifiedByteRuns[0].length == Int64(png.count))
            #expect(try RecoveryResultStore.readArtifact(artifact: artifact, result: result,
                in: forensicCase.bundleURL, maximumBytes: 1_024) == png)
        }
        #expect(try Data(contentsOf: source) == image)
        #expect(try RecoveryResultStore.latest(evidenceID: evidence.id, in: forensicCase.bundleURL) == result)
    }

    private func makeMBRImage(png: Data, at offsets: [Int64]) -> Data {
        var bytes = Data(repeating: 0, count: 16 * 1_048_576)
        func write(_ value: UInt32, at offset: Int, length: Int) {
            for index in 0..<length { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
        }
        // One valid FAT16 partition: 1 MiB through 9 MiB. The 12 MiB
        // sentinel is outside its declared extent, yet inside the RAW image.
        let start: UInt32 = 2_048, sectors: UInt32 = 16_384
        bytes[450] = 0x06
        bytes.replaceSubrange(447..<450, with: [0x20, 0x21, 0x00])
        bytes.replaceSubrange(451..<454, with: [0xfe, 0xff, 0xff])
        write(start, at: 454, length: 4); write(sectors, at: 458, length: 4)
        bytes[510] = 0x55; bytes[511] = 0xaa
        let boot = Int(start) * 512
        bytes.replaceSubrange(boot..<boot + 3, with: [0xeb, 0x3c, 0x90])
        bytes.replaceSubrange(boot + 3..<boot + 11, with: Data("NFSYNTH ".utf8))
        write(512, at: boot + 11, length: 2); bytes[boot + 13] = 1
        write(1, at: boot + 14, length: 2); bytes[boot + 16] = 2
        write(512, at: boot + 17, length: 2); write(sectors, at: boot + 19, length: 2)
        bytes[boot + 21] = 0xf8; write(64, at: boot + 22, length: 2)
        write(63, at: boot + 24, length: 2); write(255, at: boot + 26, length: 2)
        write(start, at: boot + 28, length: 4)
        bytes[boot + 36] = 0x80; bytes[boot + 38] = 0x29
        write(0x1234abcd, at: boot + 39, length: 4)
        bytes.replaceSubrange(boot + 43..<boot + 54, with: Data("SCOPE TEST ".utf8))
        bytes.replaceSubrange(boot + 54..<boot + 62, with: Data("FAT16   ".utf8))
        bytes[boot + 510] = 0x55; bytes[boot + 511] = 0xaa
        for sector in [start + 1, start + 65] {
            let offset = Int(sector) * 512
            bytes.replaceSubrange(offset..<offset + 4, with: [0xf8, 0xff, 0xff, 0xff])
        }
        for offset in offsets { bytes.replaceSubrange(Int(offset)..<Int(offset) + png.count, with: png) }
        return bytes
    }
}
