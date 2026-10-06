import Foundation
import Testing
@testable import ForensicsCore

@Suite("FilesystemSearchTests")
struct FilesystemSearchTests {
    @Test("Unicode and case searches preserve Foundation matches and metadata")
    func foundationSemantics() throws {
        let paths = [
            "/Reports/HELLO.TXT", "/รายงาน/หลักฐาน.txt", "/café/évidence.txt",
            "/cafe\u{301}/e\u{301}vidence.txt", "/İstanbul/Istanbul.txt",
            "/Straße/straße.txt", "/東京/証拠.txt", "/emoji/🔎.txt",
            "/nested/Folder/file.txt", "/nested/folder/FILE.TXT"
        ]
        let files = paths.enumerated().map { entry(id: $0.offset, path: $0.element) }
        let index = FilesystemSearchIndex(files: files)
        for query in ["", "HELLO", "hello", "รายงาน", "หลักฐาน", "é", "e\u{301}", "CAFE", "I", "ı", "İ", "SS", "straße", "証拠", "🔎", "/FOLDER/", "missing"] {
            let expected = query.isEmpty ? files : files.filter { $0.path.localizedCaseInsensitiveContains(query) }
            #expect(try index.rows(matching: query) == expected)
        }
    }

    @Test("Bounded snapshot retains source order and original rows")
    func boundedOrder() throws {
        let files = (0..<50_007).map { entry(id: $0, path: "/\(50_007 - $0)/match.txt") }
        let index = FilesystemSearchIndex(files: files)
        let bounded = Array(files.prefix(50_000))
        #expect(index.count == 50_000)
        #expect(try index.rows(matching: "") == bounded)
        #expect(try index.rows(matching: "MATCH") == bounded)
        #expect(try index.rows(matching: "absent").isEmpty)
    }

    @Test("An empty snapshot can be searched without invented entries")
    func emptySnapshot() throws {
        let index = FilesystemSearchIndex(files: [])
        #expect(index.count == 0)
        #expect(try index.rows(matching: "").isEmpty)
        #expect(try index.rows(matching: "file").isEmpty)
    }

    @Test("Cancelled tasks reject both empty and nonempty queries")
    func cancelledQueries() async throws {
        let index = FilesystemSearchIndex(files: [entry(id: 1, path: "/file.txt")])
        for query in ["", "file"] {
            let task = Task.detached {
                withUnsafeCurrentTask { $0?.cancel() }
                return try index.rows(matching: query)
            }
            await #expect(throws: CancellationError.self) { try await task.value }
        }
    }

    private func entry(id: Int, path: String) -> FilesystemEntry {
        FilesystemEntry(id: "file-\(id)", path: path,
                        name: URL(fileURLWithPath: path).lastPathComponent,
                        fsOffsetBytes: 4096, metaAddress: UInt64(id), attributeType: 128, attributeID: 3,
                        size: Int64(id), isDirectory: id.isMultiple(of: 3), isDeleted: id.isMultiple(of: 7),
                        createdEpoch: 1_700_000_000, modifiedEpoch: 1_700_000_001,
                        createdNanoseconds: 123_456_789, modifiedNanoseconds: 987_654_321)
    }
}
