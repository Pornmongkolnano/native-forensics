import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@MainActor
struct ComparisonInputCandidateTests {
    @Test("Candidate discovery admits the 128 MiB document boundary independently of filename")
    func documentCandidatesAreNotTypeProof() async {
        let store = ComparisonSelectionStore()
        let files = [file("utf8-over", "large.txt", size: VerifiedContentService.maximumFileBytes + 1),
                     file("pdf-limit", "unknown.dat", size: DocumentLimits.maximumInputBytes),
                     file("pdf-over", "claimed.pdf", size: DocumentLimits.maximumInputBytes + 1)]
        store.configure(result: .init(engineVersion: "synthetic", patchDigest: "synthetic", sourcePaths: ["/synthetic-candidates.dd"],
            sourceFileHashes: ["/synthetic-candidates.dd": String(repeating: "a", count: 64)], options: EngineOptions(),
            image: .init(imageType: "raw", logicalSize: DocumentLimits.maximumInputBytes, sectorSize: 512),
            volumes: [], files: files, warnings: [], status: .partial))
        await store.waitForSearch()
        #expect(store.rows == Array(files.prefix(2)))
        store.selectedCandidateID = "utf8-over"; store.useSelected(asFirst: true)
        store.selectedCandidateID = "pdf-limit"; store.useSelected(asFirst: false)
        #expect(store.canCompare)
        // This only proves candidate size admission. Local verified-byte/type
        // preparation separately rejects an oversized UTF-8 body.
        #expect(store.firstFile == files[0] && store.secondFile == files[1])
    }
    private func file(_ id: String, _ name: String, size: Int64) -> FilesystemEntry {
        .init(id: id, path: "/\(name)", name: name, fsOffsetBytes: 0, metaAddress: 1,
              size: size, isDirectory: false, isDeleted: false)
    }
}
