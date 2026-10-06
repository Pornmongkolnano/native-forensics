import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("WorkspaceSearchTests")
@MainActor
struct WorkspaceSearchTests {
    @Test("A superseded query cannot replace the newest search result or selection")
    func supersededQueries() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        workspace.selectedFileID = fixture.firstFiles[0].id
        #expect(workspace.canExtractFilesystemFile)

        workspace.filesystemSearchText = "HELLO"
        let oldTask = try #require(workspace.filesystemSearchTask)
        let oldID = try #require(workspace.filesystemSearchID)
        #expect(!workspace.canExtractFilesystemFile)

        let latestQuery = "หลักฐาน"
        workspace.filesystemSearchText = latestQuery
        let latestTask = try #require(workspace.filesystemSearchTask)
        #expect(workspace.filesystemSearchID != oldID)
        #expect(workspace.isFilteringFilesystem)
        #expect(!workspace.canExtractFilesystemFile)

        await oldTask.value
        await latestTask.value

        let expected = fixture.firstFiles.filter { $0.path.localizedCaseInsensitiveContains(latestQuery) }
        #expect(workspace.filesystemRows == expected)
        #expect(workspace.filesystemSearchText == latestQuery)
        #expect(workspace.selectedFileID == nil)
        #expect(!workspace.canExtractFilesystemFile)
        expectSearchFinished(workspace)
    }

    @Test("Clearing a pending query restores the full snapshot synchronously")
    func clearPendingQuery() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        let selected = fixture.firstFiles[0]
        workspace.selectedFileID = selected.id

        workspace.filesystemSearchText = "missing"
        let pendingTask = try #require(workspace.filesystemSearchTask)
        #expect(workspace.isFilteringFilesystem)
        #expect(!workspace.canExtractFilesystemFile)

        workspace.filesystemSearchText = ""
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(workspace.selectedFilesystemFile == selected)
        #expect(workspace.canExtractFilesystemFile)
        expectSearchFinished(workspace)

        await pendingTask.value

        #expect(workspace.filesystemSearchText.isEmpty)
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(workspace.selectedFilesystemFile == selected)
        expectSearchFinished(workspace)
    }

    @Test("Changing evidence discards a pending search and clears the old file selection")
    func changeEvidenceWhilePending() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        workspace.selectedFileID = fixture.firstFiles[0].id
        workspace.filesystemSearchText = "HELLO"
        let oldTask = try #require(workspace.filesystemSearchTask)

        workspace.selectedEvidenceID = fixture.secondEvidence.id
        #expect(workspace.filesystemSearchText.isEmpty)
        #expect(workspace.filesystemRows == fixture.secondFiles)
        #expect(workspace.selectedFileID == nil)
        #expect(!workspace.canExtractFilesystemFile)
        #expect(workspace.filesystemFilesByID[fixture.firstFiles[0].id] == nil)
        expectSearchFinished(workspace)

        await oldTask.value

        #expect(workspace.selectedEvidence == fixture.secondEvidence)
        #expect(workspace.filesystemRows == fixture.secondFiles)
        expectSearchFinished(workspace)

        let secondQuery = "CAFÉ"
        workspace.filesystemSearchText = secondQuery
        let secondTask = try #require(workspace.filesystemSearchTask)
        await secondTask.value

        let expected = fixture.secondFiles.filter { $0.path.localizedCaseInsensitiveContains(secondQuery) }
        #expect(workspace.filesystemRows == expected)
        #expect(workspace.selectedEvidence == fixture.secondEvidence)
        expectSearchFinished(workspace)
    }

    @Test("Cancel restores a coherent query and snapshot before extraction becomes available")
    func cancelPendingSearch() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        let selected = fixture.firstFiles[0]
        workspace.selectedFileID = selected.id
        let originalResult = workspace.selectedFilesystemResult

        workspace.filesystemSearchText = "missing"
        let pendingTask = try #require(workspace.filesystemSearchTask)
        #expect(workspace.isFilteringFilesystem)
        #expect(!workspace.canExtractFilesystemFile)

        workspace.cancelCurrentJob()

        #expect(workspace.filesystemSearchText.isEmpty)
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(workspace.selectedFilesystemFile == selected)
        #expect(workspace.canExtractFilesystemFile)
        #expect(workspace.selectedFilesystemResult == originalResult)
        expectSearchFinished(workspace)

        await pendingTask.value

        #expect(workspace.filesystemSearchText.isEmpty)
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(workspace.selectedFilesystemResult == originalResult)
        #expect(workspace.canExtractFilesystemFile)
        expectSearchFinished(workspace)
    }

    private func expectSearchFinished(_ workspace: WorkspaceStore) {
        #expect(!workspace.isFilteringFilesystem)
        #expect(workspace.filesystemSearchTask == nil)
        #expect(workspace.filesystemSearchID == nil)
    }

    /// Cached DTOs deliberately keep these tests in memory: no helper, source
    /// hashing, native panel, or filesystem cache read is needed for searching.
    private func makeWorkspace() -> Fixture {
        let caseID = UUID()
        let bundleURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("WorkspaceSearch-\(caseID.uuidString).nativecase")
        let firstEvidence = evidence(named: "first.raw", beside: bundleURL)
        let secondEvidence = evidence(named: "second.raw", beside: bundleURL)
        let firstFiles = [
            entry(id: "first-hello", path: "/Reports/HELLO.TXT"),
            entry(id: "first-thai", path: "/รายงาน/หลักฐาน.txt"),
            entry(id: "first-other", path: "/archive/other.bin")
        ]
        let secondFiles = [
            entry(id: "second-cafe", path: "/café/évidence.txt"),
            entry(id: "second-tokyo", path: "/東京/証拠.txt")
        ]
        let workspace = WorkspaceStore()
        workspace.currentCase = ForensicCase(
            bundleURL: bundleURL,
            manifest: CaseManifest(id: caseID, name: "Search Regression", evidence: [firstEvidence, secondEvidence])
        )
        workspace.filesystemResults = [
            firstEvidence.id: result(for: firstEvidence, files: firstFiles),
            secondEvidence.id: result(for: secondEvidence, files: secondFiles)
        ]
        // Exercise the real selection observer after both cached results exist.
        workspace.selectedEvidenceID = firstEvidence.id
        return Fixture(workspace: workspace, secondEvidence: secondEvidence,
                       firstFiles: firstFiles, secondFiles: secondFiles)
    }

    private func evidence(named name: String, beside caseURL: URL) -> EvidenceRecord {
        EvidenceRecord(sourcePath: caseURL.deletingLastPathComponent().appendingPathComponent(name).path,
                       byteCount: 4096, sha256: String(repeating: "a", count: 64),
                       container: .raw, filesystemHint: "FAT16",
                       addedAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    private func entry(id: String, path: String) -> FilesystemEntry {
        FilesystemEntry(id: id, path: path, name: URL(fileURLWithPath: path).lastPathComponent,
                        fsOffsetBytes: 0, metaAddress: 10, size: 52,
                        isDirectory: false, isDeleted: false,
                        modifiedEpoch: 1_700_000_000, modifiedNanoseconds: 123_456_789)
    }

    private func result(for evidence: EvidenceRecord, files: [FilesystemEntry]) -> EnumerationResult {
        EnumerationResult(engineVersion: "search-test", patchDigest: "search-test",
                          sourcePaths: [evidence.sourcePath],
                          sourceFileHashes: [evidence.sourcePath: evidence.sha256],
                          options: EngineOptions(),
                          image: EngineImageMetadata(imageType: "raw", logicalSize: evidence.byteCount,
                                                     sectorSize: 512, imagePaths: [evidence.sourcePath]),
                          volumes: [EngineVolume(id: "test-volume", offsetBytes: 0, filesystem: "FAT16",
                                                 blockSize: 512, blockCount: 8)],
                          files: files, warnings: [], status: .completed,
                          savedAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    private struct Fixture {
        let workspace: WorkspaceStore
        let secondEvidence: EvidenceRecord
        let firstFiles: [FilesystemEntry]
        let secondFiles: [FilesystemEntry]
    }
}
