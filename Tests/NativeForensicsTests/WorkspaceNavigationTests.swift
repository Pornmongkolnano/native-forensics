import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("WorkspaceNavigationTests")
@MainActor
struct WorkspaceNavigationTests {
    @Test("Filename views ignore case, do not classify folders, and preserve deletion metadata")
    func filenameViews() throws {
        let image = entry("photo", name: "PHOTO.JpEg")
        let folder = entry("folder", name: "photo.jpg", directory: true)
        let deletedFolder = entry("deleted-folder", name: "Documents", directory: true, deleted: true)
        let document = entry("document", name: "HELLO.TXT", deleted: true)
        let unknown = entry("unknown", name: "payload.bin")
        #expect(FilesystemCategory.images.matches(image))
        #expect(!FilesystemCategory.images.matches(folder))
        #expect(!FilesystemCategory.documents.matches(deletedFolder))
        #expect(FilesystemCategory.deleted.matches(deletedFolder))
        #expect(FilesystemCategory.documents.matches(document))
        #expect(FilesystemCategory.deleted.matches(document))
        #expect(FilesystemCategory.category(for: unknown) == .all)
        #expect(FilesystemCategory.all.matches(folder))
    }

    @Test("Category and Unicode search compose in a single bounded snapshot without altering entries")
    func composedCategorySearch() throws {
        let files = [entry("thai-image", name: "หลักฐาน.PNG"),
                     entry("thai-text", name: "หลักฐาน.txt"),
                     entry("archive", name: "backup.ZIP"),
                     entry("media", name: "interview.MOV")]
        let index = FilesystemSearchIndex(files: files)
        #expect(try FilesystemCategory.rows(in: index, matching: "หลักฐาน", category: .images) == [files[0]])
        #expect(try FilesystemCategory.rows(in: index, matching: "BACKUP", category: .archives) == [files[2]])
        #expect(try FilesystemCategory.rows(in: index, matching: "", category: .media) == [files[3]])
        #expect(try FilesystemCategory.rows(in: index, matching: "", category: .all) == files)
    }

    @Test("NTFS stream icons use the base extension without rewriting ordinary colon filenames")
    func namedStreamFilenameHint() {
        let stream = FilesystemEntry(id: "stream", path: "/streams.TXT:note", name: "streams.TXT:note",
            fsOffsetBytes: 0, metaAddress: 30, attributeType: 128, attributeID: 3,
            size: 43, isDirectory: false, isDeleted: false)
        #expect(FilesystemCategory.documents.matches(stream))
        #expect(FilesystemCategory.filenameExtension(for: stream) == "txt")
        let ordinary = entry("ordinary", name: "streams.TXT:note")
        #expect(!FilesystemCategory.documents.matches(ordinary))
        #expect(ordinary.name == "streams.TXT:note")
    }

    @Test("A superseded category cannot publish over the newest query or leave an invisible selection")
    func supersededCategory() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        workspace.selectedFileID = fixture.firstFiles[1].id
        workspace.chooseFileView(.images)
        let oldTask = try #require(workspace.filesystemSearchTask)
        #expect(!workspace.canExtractFilesystemFile)

        workspace.chooseFileView(.documents)
        workspace.filesystemSearchText = "HELLO"
        let latestTask = try #require(workspace.filesystemSearchTask)
        await oldTask.value
        await latestTask.value

        #expect(workspace.navigationSelection == .fileView(.documents))
        #expect(workspace.filesystemRows == [fixture.firstFiles[0]])
        #expect(workspace.selectedFileID == nil)
        #expect(!workspace.isFilteringFilesystem)
        #expect(workspace.filesystemSearchTask == nil)
    }

    @Test("Changing data sources cancels filters, clears category, and uses only the new result")
    func changeDataSource() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        workspace.chooseFileView(.deleted)
        workspace.filesystemSearchText = "missing"
        let pending = try #require(workspace.filesystemSearchTask)
        workspace.chooseDataSource(fixture.secondEvidence.id)

        #expect(workspace.section == .filesystem)
        #expect(workspace.navigationSelection == .dataSource(fixture.secondEvidence.id))
        #expect(workspace.filesystemCategory == .all)
        #expect(workspace.filesystemSearchText.isEmpty)
        #expect(workspace.filesystemRows == fixture.secondFiles)
        #expect(workspace.selectedFileID == nil)
        #expect(!workspace.isFilteringFilesystem)
        await pending.value
        #expect(workspace.filesystemRows == fixture.secondFiles)
        #expect(workspace.selectedEvidence == fixture.secondEvidence)
    }

    @Test("Navigation rejects busy source changes and unknown records; cancelling a category restores all rows")
    func guardedNavigationAndCancel() async throws {
        let fixture = makeWorkspace()
        let workspace = fixture.workspace
        let originalID = workspace.selectedEvidenceID
        workspace.isEngineRunning = true
        workspace.navigate(to: .dataSource(fixture.secondEvidence.id))
        #expect(workspace.selectedEvidenceID == originalID)
        #expect(workspace.section == .evidence)
        workspace.isEngineRunning = false
        workspace.chooseDataSource(UUID())
        #expect(workspace.selectedEvidenceID == originalID)

        workspace.chooseFileView(.images)
        let pending = try #require(workspace.filesystemSearchTask)
        workspace.cancelCurrentJob()
        #expect(workspace.filesystemCategory == .all)
        #expect(workspace.filesystemRows == fixture.firstFiles)
        #expect(!workspace.isFilteringFilesystem)
        await pending.value
        #expect(workspace.filesystemRows == fixture.firstFiles)

        // Even the empty-query / All Files fast path clears stale selection.
        workspace.selectedFileID = "not-in-this-source"
        workspace.refreshFilesystemRows()
        #expect(workspace.selectedFileID == nil)
    }

    private func makeWorkspace() -> Fixture {
        let caseID = UUID()
        let caseURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("Navigation-\(caseID.uuidString).nativecase")
        let firstEvidence = evidence("first.raw", beside: caseURL)
        let secondEvidence = evidence("second.raw", beside: caseURL)
        let firstFiles = [entry("first-doc", name: "HELLO.TXT"),
                          entry("first-photo", name: "photo.jpg"),
                          entry("first-deleted", name: "removed.zip", deleted: true)]
        let secondFiles = [entry("second-media", name: "interview.mp4")]
        let workspace = WorkspaceStore()
        workspace.currentCase = ForensicCase(bundleURL: caseURL,
                                            manifest: CaseManifest(id: caseID, name: "Navigation Regression",
                                                                   evidence: [firstEvidence, secondEvidence]))
        workspace.filesystemResults = [firstEvidence.id: result(firstEvidence, files: firstFiles),
                                       secondEvidence.id: result(secondEvidence, files: secondFiles)]
        workspace.selectedEvidenceID = firstEvidence.id
        return Fixture(workspace: workspace, secondEvidence: secondEvidence,
                       firstFiles: firstFiles, secondFiles: secondFiles)
    }

    private func entry(_ id: String, name: String, directory: Bool = false, deleted: Bool = false) -> FilesystemEntry {
        FilesystemEntry(id: id, path: "/\(name)", name: name, fsOffsetBytes: 0,
                        metaAddress: 10, size: 52, isDirectory: directory, isDeleted: deleted,
                        modifiedEpoch: 1_700_000_000, modifiedNanoseconds: 123_456_789)
    }

    private func evidence(_ name: String, beside caseURL: URL) -> EvidenceRecord {
        EvidenceRecord(sourcePath: caseURL.deletingLastPathComponent().appendingPathComponent(name).path,
                       byteCount: 4096, sha256: String(repeating: "a", count: 64),
                       container: .raw, filesystemHint: "FAT16",
                       addedAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    private func result(_ evidence: EvidenceRecord, files: [FilesystemEntry]) -> EnumerationResult {
        EnumerationResult(engineVersion: "navigation-test", patchDigest: "navigation-test",
                          sourcePaths: [evidence.sourcePath],
                          sourceFileHashes: [evidence.sourcePath: evidence.sha256],
                          options: EngineOptions(),
                          image: EngineImageMetadata(imageType: "raw", logicalSize: evidence.byteCount,
                                                     sectorSize: 512, imagePaths: [evidence.sourcePath]),
                          volumes: [], files: files, warnings: [], status: .completed,
                          savedAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    private struct Fixture {
        let workspace: WorkspaceStore
        let secondEvidence: EvidenceRecord
        let firstFiles: [FilesystemEntry]
        let secondFiles: [FilesystemEntry]
    }
}
