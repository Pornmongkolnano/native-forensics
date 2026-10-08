import Foundation
import Testing
@testable import ForensicsCore

struct MultiEvidenceInputBudgetTests {
    @Test("Actual UTF-8 input bytes accept exactly 1 MiB and reject one extra byte")
    func completeUTF8InputBoundary() throws {
        var bytes = Data(repeating: 0x61, count: Int(VerifiedContentService.maximumFileBytes))
        let accepted = try utf8(bytes)
        #expect(accepted.bytes.count == 1_048_576 && !accepted.isPDF)
        #expect(accepted.previewByteCount == 32_768)
        bytes.append(0x61)
        #expect(bytes.count == 1_048_577)
        #expect(throws: MultiEvidenceError.invalidContent) { try utf8(bytes) }
    }

    @Test("Actual source-byte receipt sizes support the independent 128 MiB PDF cap without retaining raw bytes")
    func pdfSourceReceiptBoundary() throws {
        // This is an input-size/receipt oracle with injected decoded metadata,
        // not a PDF parser or decoder performance test.
        var bytes = Data(repeating: 0, count: Int(DocumentLimits.maximumInputBytes))
        bytes.replaceSubrange(0..<9, with: Data("%PDF-1.7\n".utf8))
        let accepted = try pdf(bytes)
        #expect(accepted.isPDF && accepted.bytes.isEmpty)
        #expect(accepted.receipt.byteCount == 134_217_728)
        #expect(accepted.receipt.sha256 == MultiEvidenceCoding.digest(bytes))
        bytes.append(0)
        #expect(bytes.count == 134_217_729)
        #expect(throws: MultiEvidenceError.invalidContent) { try pdf(bytes) }
    }

    private func utf8(_ bytes: Data) throws -> MultiEvidenceVerifiedFile {
        let (binding, receipt) = try input(bytes)
        return try .init(binding: binding, content: .init(bytes: bytes, receipt: receipt))
    }
    private func pdf(_ bytes: Data) throws -> MultiEvidenceVerifiedFile {
        let (binding, receipt) = try input(bytes)
        let page = DocumentTextPage(pageNumber: 1, text: "derived", isTruncated: false, referenceLabel: "Page 1", referenceKind: .page)
        let analysis = try DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: receipt.sha256, sourceByteCount: receipt.byteCount, pageCount: 1, textPages: [page])
            .attachingProvenance(executableSHA256: String(repeating: "d", count: 64), codeSigningCDHash: nil,
                isolation: .requiredDevelopmentSeatbelt, timeout: 12)
        return try .init(binding: binding, preview: .init(file: binding.selectedEntry, receipt: receipt, analysis: analysis))
    }
    private func input(_ bytes: Data) throws -> (CaseWorkBinding, VerifiedContentReceipt) {
        let path = "/synthetic-size-oracle.dd", hash = String(repeating: "a", count: 64)
        let evidence = EvidenceRecord(sourcePath: path, byteCount: Int64(bytes.count), sha256: hash, container: .raw, filesystemHint: nil)
        let file = FilesystemEntry(id: "0:1", path: "/TYPE-FROM-VERIFIED-BYTES.dat", name: "TYPE-FROM-VERIFIED-BYTES.dat",
            fsOffsetBytes: 0, metaAddress: 1, size: Int64(bytes.count), isDirectory: false, isDeleted: false)
        let result = EnumerationResult(engineVersion: "synthetic-size-oracle", patchDigest: "synthetic-only",
            sourcePaths: [path], sourceFileHashes: [path: hash], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: Int64(bytes.count), sectorSize: 512), volumes: [], files: [file], warnings: [], status: .partial)
        let binding = try CaseWorkBinding.make(caseID: UUID(), evidence: evidence, result: result, file: file)
        let receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id, byteCount: Int64(bytes.count),
            sha256: MultiEvidenceCoding.digest(bytes), verifiedAt: Date(), orderedContainerSHA256: [hash])
        return (binding, receipt)
    }
}
