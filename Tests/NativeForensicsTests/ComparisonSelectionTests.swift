import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("ComparisonSelectionTests")
@MainActor
struct ComparisonSelectionTests {
    @Test("Two distinct regular entries survive filtering while folders and oversized bodies are excluded")
    func selectionAndBudget() async {
        let store = ComparisonSelectionStore()
        let files = [file("a", "หลักฐาน.txt"), file("b", "other.txt"),
                     file("folder", "folder.txt", directory: true), file("large", "large.txt", size: DocumentLimits.maximumInputBytes + 1)]
        store.configure(result: result(files))
        await store.waitForSearch()
        #expect(store.rows == Array(files.prefix(2)))
        store.selectedCandidateID = "a"; store.useSelected(asFirst: true)
        store.selectedCandidateID = "b"; store.useSelected(asFirst: false)
        #expect(store.canCompare)
        store.query = "หลักฐาน"; await store.waitForSearch()
        #expect(store.rows == [files[0]])
        #expect(store.firstFile == files[0] && store.secondFile == files[1])
        store.selectedCandidateID = "a"; store.useSelected(asFirst: false)
        #expect(!store.canCompare && store.firstFile == nil && store.secondFile == files[0])
    }

    @Test("Superseded source/query cannot republish candidates from an old listing; presentation stays bounded")
    func supersededSelection() async {
        let store = ComparisonSelectionStore()
        let files = (0..<1_000).map { file("\($0)", "item-\($0).txt") }
        store.configure(result: result(files))
        store.query = "item"
        await store.waitForSearch()
        #expect(store.matchCount == 1_000 && store.rows.count == 100)
        store.selectedCandidateID = "0"; store.useSelected(asFirst: true)
        let replacement = file("new", "new.txt")
        store.configure(result: result([replacement]))
        store.query = "missing"; store.query = "new"
        await store.waitForSearch()
        #expect(store.rows == [replacement] && store.firstFile == nil && store.secondFile == nil)
        store.query = String(repeating: "ก", count: 1_500)
        #expect(store.rows.isEmpty && store.errorMessage != nil && !store.isSearching)
        await store.beginShutdown()?.value
        store.configure(result: result(files))
        #expect(store.rows.isEmpty && !store.hasActiveWork)
    }

    private func file(_ id: String, _ name: String, directory: Bool = false, size: Int64 = 20) -> FilesystemEntry {
        FilesystemEntry(id: id, path: "/\(name)", name: name, fsOffsetBytes: 0,
                        metaAddress: 10, size: size, isDirectory: directory, isDeleted: false)
    }

    private func result(_ files: [FilesystemEntry]) -> EnumerationResult {
        EnumerationResult(engineVersion: "test", patchDigest: "test", sourcePaths: ["/synthetic.raw"],
            sourceFileHashes: ["/synthetic.raw": String(repeating: "a", count: 64)], options: EngineOptions(),
            image: EngineImageMetadata(imageType: "raw", logicalSize: 4_096, sectorSize: 512, imagePaths: ["/synthetic.raw"]),
            volumes: [], files: files, warnings: [], status: .completed, savedAt: Date())
    }
}
