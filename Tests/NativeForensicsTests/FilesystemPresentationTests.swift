import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("Filesystem presentation safety")
@MainActor
struct FilesystemPresentationTests {
    @Test("Historical results identify relevant correctness fixes without rewriting timestamps",
          arguments: ["0.1.0-tsk4.15.0|ntfs|yes", "0.1.1-tsk4.15.0|FAT16|yes",
                      "0.1.1-tsk4.15.0|fat32|yes", "0.1.1-tsk4.15.0|exfat|no",
                      "0.1.1-tsk4.15.0|ntfs|no", "0.1.2-tsk4.15.0|fat16|no"])
    func historicalCorrectnessNotice(_ scenario: String) {
        let pieces = scenario.split(separator: "|").map(String.init)
        let result = EnumerationResult(engineVersion: pieces[0], patchDigest: "fixture",
            sourcePaths: ["/synthetic.raw"], options: EngineOptions(hashLogicalImage: false),
            image: EngineImageMetadata(imageType: "RAW", logicalSize: 0, sectorSize: 512),
            volumes: [EngineVolume(id: "v", offsetBytes: 0, filesystem: pieces[1], blockSize: 512, blockCount: 0)],
            files: [], warnings: [], status: .completed)
        let original = result
        #expect((FilesystemFormatting.reanalysisNotice(for: result) != nil) == (pieces[2] == "yes"))
        #expect(result == original)
    }
}
