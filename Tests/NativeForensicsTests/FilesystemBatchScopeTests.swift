import CryptoKit
import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("FilesystemBatchScopeTests")
@MainActor
struct FilesystemBatchScopeTests {
    @Test("Changing evidence clears the old completed receipt while its published files and manifest remain unchanged")
    func changingEvidencePreservesPublishedOutputs() async throws {
        let fixture = try await BatchScopeFixture.make()
        defer { fixture.remove() }
        let workspace = fixture.workspace()
        let published = try await fixture.completeExport(in: workspace)
        let manifestBytes = try Data(contentsOf: published.manifest)
        workspace.chooseDataSource(fixture.secondEvidence.id)
        #expect(workspace.selectedEvidenceID == fixture.secondEvidence.id)
        #expect(workspace.filesystemBatchExport.result == nil)
        #expect(!workspace.filesystemBatchExport.isExporting)
        #expect(try Data(contentsOf: published.payload) == fixture.payload)
        #expect(try Data(contentsOf: published.manifest) == manifestBytes)
        await workspace.shutdown()
    }

    @Test("Changing case scope clears the old receipt even when the selected evidence ID is reused")
    func changingCaseScope() async throws {
        let fixture = try await BatchScopeFixture.make()
        defer { fixture.remove() }
        let workspace = fixture.workspace()
        let published = try await fixture.completeExport(in: workspace)
        let manifestBytes = try Data(contentsOf: published.manifest)
        let originalEvidenceID = workspace.selectedEvidenceID
        // Case copies can retain evidence identifiers. Case identity remains a
        // separate namespace boundary for the displayed batch receipt.
        workspace.currentCase = ForensicCase(bundleURL: fixture.root.appendingPathComponent("Copied Case.nativecase"),
            manifest: CaseManifest(name: "Copied synthetic case", evidence: fixture.forensicCase.manifest.evidence))
        workspace.refreshFilesystemSelection()
        #expect(workspace.selectedEvidenceID == originalEvidenceID)
        #expect(workspace.filesystemBatchExport.result == nil)
        #expect(try Data(contentsOf: published.payload) == fixture.payload)
        #expect(try Data(contentsOf: published.manifest) == manifestBytes)
        await workspace.shutdown()
    }

    @Test("Refreshing the same source and case keeps its completed receipt available")
    func unchangedScopeRetainsReceipt() async throws {
        let fixture = try await BatchScopeFixture.make()
        defer { fixture.remove() }
        let workspace = fixture.workspace()
        let published = try await fixture.completeExport(in: workspace)
        let saved = try #require(workspace.filesystemBatchExport.result)
        workspace.refreshFilesystemSelection()
        #expect(workspace.filesystemBatchExport.result == saved)
        #expect(try Data(contentsOf: published.payload) == fixture.payload)
        await workspace.shutdown()
    }
}

private struct BatchScopeFixture: Sendable {
    let root: URL
    let forensicCase: ForensicCase
    let firstEvidence: EvidenceRecord
    let secondEvidence: EvidenceRecord
    let file: FilesystemEntry
    let firstAnalysis: EnumerationResult
    let secondAnalysis: EnumerationResult
    let payload = Data("synthetic published batch payload\n".utf8)

    static func make() async throws -> Self {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("FilesystemBatchScope-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        do {
            let source1 = root.appendingPathComponent("first.raw"), source2 = root.appendingPathComponent("second.raw")
            try Data(repeating: 0x41, count: 4096).write(to: source1)
            try Data(repeating: 0x42, count: 4096).write(to: source2)
            var forensicCase = try CaseStore.create(name: "Synthetic Batch Scope", in: root)
            let inspected1 = try await ImageInspector.inspect(url: source1) { _ in }
            forensicCase = try CaseStore.adding(image: inspected1, to: forensicCase)
            let inspected2 = try await ImageInspector.inspect(url: source2) { _ in }
            forensicCase = try CaseStore.adding(image: inspected2, to: forensicCase)
            let first = forensicCase.manifest.evidence[0], second = forensicCase.manifest.evidence[1]
            let file = FilesystemEntry(id: "first-payload", path: "/payload.txt", name: "payload.txt",
                fsOffsetBytes: 0, metaAddress: 2, size: Int64(Data("synthetic published batch payload\n".utf8).count),
                isDirectory: false, isDeleted: true)
            func analysis(_ evidence: EvidenceRecord, files: [FilesystemEntry]) -> EnumerationResult {
                EnumerationResult(engineVersion: "synthetic-fixture", patchDigest: "synthetic-only", sourcePaths: [evidence.sourcePath],
                    sourceFileHashes: [evidence.sourcePath: evidence.sha256], options: EngineOptions(),
                    image: EngineImageMetadata(imageType: "raw", logicalSize: evidence.byteCount, sectorSize: 512),
                    volumes: [], files: files, warnings: [], status: .completed)
            }
            return Self(root: root, forensicCase: forensicCase, firstEvidence: first, secondEvidence: second, file: file,
                firstAnalysis: analysis(first, files: [file]), secondAnalysis: analysis(second, files: []))
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }

    @MainActor func workspace() -> WorkspaceStore {
        let bytes = payload
        let batch = FilesystemBatchExportStore(engineHelperURL: URL(fileURLWithPath: "/synthetic/helper"),
            export: { analysis, files, destination, _, _ in
                let canonical = destination.deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath()
                    .appendingPathComponent(destination.lastPathComponent, isDirectory: true)
                try FileManager.default.createDirectory(at: canonical, withIntermediateDirectories: false)
                let outputName = "0001-payload.txt", output = canonical.appendingPathComponent(outputName)
                try bytes.write(to: output, options: .withoutOverwriting)
                let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
                let manifest = canonical.appendingPathComponent("manifest.json")
                let value = FilesystemBatchExportResult(destinationPath: canonical.path, manifestPath: manifest.path,
                    status: .completed, entries: files.map { FilesystemBatchExportEntry(sourceFile: $0,
                        outputFilename: outputName, byteCount: Int64(bytes.count), sha256: hash, errorMessage: nil) },
                    sourcePaths: analysis.sourcePaths, sourceFileHashes: analysis.sourceFileHashes,
                    engineVersion: analysis.engineVersion, patchDigest: analysis.patchDigest)
                try JSONEncoder().encode(value).write(to: manifest, options: .withoutOverwriting)
                return value
            })
        let workspace = WorkspaceStore(filesystemBatchExport: batch)
        workspace.currentCase = forensicCase
        workspace.filesystemResults = [firstEvidence.id: firstAnalysis, secondEvidence.id: secondAnalysis]
        workspace.selectedEvidenceID = firstEvidence.id
        return workspace
    }

    @MainActor func completeExport(in workspace: WorkspaceStore) async throws -> (payload: URL, manifest: URL) {
        let destination = root.appendingPathComponent("Published Export", isDirectory: true)
        workspace.filesystemBatchExport.start(analysis: firstAnalysis, files: [file], destination: destination,
            caseURL: forensicCase.bundleURL)
        await (try #require(workspace.filesystemBatchExport.exportTask)).value
        let published = try #require(workspace.filesystemBatchExport.result)
        #expect(published.status == .completed)
        #expect(published.successfulCount == 1)
        return (URL(fileURLWithPath: published.destinationPath).appendingPathComponent("0001-payload.txt"),
                URL(fileURLWithPath: published.manifestPath))
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
}
