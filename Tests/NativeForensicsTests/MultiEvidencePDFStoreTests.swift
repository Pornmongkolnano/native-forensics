import CryptoKit
import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("Reviewed PDF comparison store") @MainActor
struct MultiEvidencePDFStoreTests {
    @Test("Verified PDF type ignores filename; page ranges and redactions stay local before exact Send")
    func localReviewAndFreshSend() async throws {
        let fixture = try await PDFStoreFixture.make(); defer { fixture.remove() }
        let preparation = PDFStorePreparation(fixture.files), provider = PDFStoreProvider()
        let store = makeStore(fixture, preparation: preparation, provider: provider)
        await configure(store, fixture)
        #expect(store.context?.schemaVersion == 2)
        #expect(store.verifiedFiles.first?.isPDF == true)
        #expect(store.firstRanges == "1:0:19")
        #expect(await preparation.calls == 1)
        #expect(await provider.calls == 0)
        let original = store.outboundPrompt
        store.firstRedactions = "1:4:10"
        #expect(store.context == nil && !store.canAnalyze)
        store.rebuildDisclosure()
        #expect(!store.outboundPrompt.contains("SECRET"))
        #expect(store.context?.files[0].segments.map(\.text) == ["one ", " ก😀 tail"])
        #expect(store.context?.files[0].segments.allSatisfy { $0.sourceRange == nil } == true)
        store.analyze(confirmedPrompt: original)
        #expect(store.jobTask == nil && store.result == nil)
        #expect(await provider.calls == 0)
        let exact = store.outboundPrompt
        store.analyze(confirmedPrompt: exact)
        await (try #require(store.jobTask)).value
        #expect(store.errorMessage == nil && store.result != nil)
        #expect(await preparation.calls == 2)
        #expect(await provider.calls == 1)
        #expect(await provider.lastPrompt == exact)
        #expect(!exact.contains(fixture.source.path) && !exact.contains(fixture.directory.path))
    }

    @Test("A changed decoder, options or omitted derived page stops Send before the synthetic provider", arguments: ["executable", "options", "text"])
    func changedDerivationBeforeSend(_ fault: String) async throws {
        let fixture = try await PDFStoreFixture.make(); defer { fixture.remove() }
        let preparation = PDFStorePreparation(fixture.files), provider = PDFStoreProvider()
        let store = makeStore(fixture, preparation: preparation, provider: provider)
        await configure(store, fixture)
        let reviewed = store.outboundPrompt
        let altered = try fixture.changedPDF(fault)
        await preparation.replace(with: [altered, fixture.files[1]])
        store.analyze(confirmedPrompt: reviewed)
        await (try #require(store.jobTask)).value
        #expect(await preparation.calls == 2)
        #expect(await provider.calls == 0)
        #expect(store.result == nil && store.errorMessage != nil)
    }

    @Test("PDF citation navigation decodes freshly and labels only raw-derived page coordinates")
    func freshCitation() async throws {
        let fixture = try await PDFStoreFixture.make(); defer { fixture.remove() }
        let preparation = PDFStorePreparation(fixture.files), provider = PDFStoreProvider()
        let store = makeStore(fixture, preparation: preparation, provider: provider)
        await configure(store, fixture)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        await (try #require(store.jobTask)).value
        let citation = try #require(store.references.first)
        #expect(citation.sourceRange == nil)
        #expect(citation.pdfRange == .init(pageNumber: 1, start: 0, end: 3))
        store.openReference(citation)
        await (try #require(store.jobTask)).value
        #expect(store.openedReferenceText == "one")
        #expect(store.openedReferenceLabel?.contains("PDF page 1, raw derived UTF-16 0:3") == true)
        #expect(await preparation.calls == 3)
        #expect(await provider.calls == 1)
        await preparation.replace(with: [try fixture.changedPDF("text"), fixture.files[1]])
        store.openReference(citation)
        await (try #require(store.jobTask)).value
        #expect(store.openedReferenceText == nil && store.errorMessage != nil)
        #expect(await preparation.calls == 4)
        #expect(await provider.calls == 1)
    }

    @Test("PDF full and digest-only history retain exact immutable disclosure; changed redactions clear the parent", arguments: AnalysisRetention.allCases)
    func savedPDFAndFollowUp(_ retention: AnalysisRetention) async throws {
        let fixture = try await PDFStoreFixture.make(); defer { fixture.remove() }
        let preparation = PDFStorePreparation(fixture.files), provider = PDFStoreProvider()
        let store = makeStore(fixture, preparation: preparation, provider: provider)
        await configure(store, fixture)
        store.firstRedactions = "1:4:10"; store.rebuildDisclosure()
        store.analyze(confirmedPrompt: store.outboundPrompt)
        await (try #require(store.jobTask)).value
        store.saveAnalysis(retention: retention)
        await (try #require(store.jobTask)).value
        let record = try #require(store.savedRecord)
        #expect(record.schemaVersion == 2 && record.templateVersion == MultiEvidencePrompt.pdfTemplateVersion)
        #expect(record.context.files[0].pdf?.provenance == fixture.files[0].pdf?.provenance)
        #expect(record.context.files[0].segments.first?.text == (retention == .full ? "one " : nil))
        #expect(store.history.map(\.id) == [record.id])
        let sidecar = fixture.forensicCase.bundleURL.appendingPathComponent("comparisons")
            .appendingPathComponent(record.id.uuidString.lowercased() + ".json")
        let original = try Data(contentsOf: sidecar)
        #expect(!String(decoding: original, as: UTF8.self).contains("SECRET"))
        store.beginFollowUp()
        #expect(store.parentRecord?.id == record.id)
        #expect(store.outboundPrompt.contains("priorUntrustedInterpretation"))
        store.firstRedactions = "1:4:11"
        #expect(store.parentRecord == nil && store.context == nil)
        store.rebuildDisclosure()
        #expect(!store.outboundPrompt.contains("priorUntrustedInterpretation"))
        #expect(try Data(contentsOf: sidecar) == original)
        #expect(await provider.calls == 1)
    }

    @Test("PDF editors reject source-byte syntax and a surrogate split before any request")
    func malformedTypedRanges() async throws {
        let fixture = try await PDFStoreFixture.make(); defer { fixture.remove() }
        let preparation = PDFStorePreparation(fixture.files), provider = PDFStoreProvider()
        let store = makeStore(fixture, preparation: preparation, provider: provider)
        await configure(store, fixture)
        for text in ["0:3", "1:12:13", "2:0:99", "999:0:1"] {
            store.firstRanges = text; store.rebuildDisclosure()
            #expect(store.context == nil && store.errorMessage != nil && !store.canAnalyze)
        }
        #expect(await provider.calls == 0)
        #expect(await preparation.calls == 1)
    }

    @Test("Opening another historical answer clears the previous verified span and follow-up parent", arguments: ["citation", "parent"])
    func historyDoesNotCarryPreviousProof(_ previousState: String) async throws {
        let fixture = try await PDFStoreFixture.make(); defer { fixture.remove() }
        let preparation = PDFStorePreparation(fixture.files), provider = PDFStoreProvider()
        let store = makeStore(fixture, preparation: preparation, provider: provider)
        await configure(store, fixture)
        let context = try #require(store.context)
        let preparedBindings = store.verifiedFiles.map(\.binding)
        store.analyze(confirmedPrompt: store.outboundPrompt)
        await (try #require(store.jobTask)).value
        store.saveAnalysis(retention: .full)
        await (try #require(store.jobTask)).value
        let original = try #require(store.savedRecord)
        let question = "Another historical comparison"
        let prompt = try MultiEvidencePrompt.make(context: context, question: question)
        let result = CodexAnalysisResult(response: .init(summary: "Another historical answer [[A1:0:3]]",
            observations: [], hypotheses: [], limitations: ["Synthetic only"], nextSteps: []),
            requestSHA256: MultiEvidenceCoding.digest(Data(prompt.utf8)), completedAt: original.createdAt.addingTimeInterval(1))
        let another = try MultiEvidenceAnalysisRecord.make(context: context, question: question, prompt: prompt,
            result: result, retention: .full)
        try MultiEvidenceRecordStore.save(another, in: fixture.forensicCase.bundleURL)
        if previousState == "citation" {
            store.openReference(try #require(store.references.first))
            await (try #require(store.jobTask)).value
            #expect(store.openedReferenceText == "one" && store.openedReferenceLabel != nil)
        } else {
            store.beginFollowUp()
            #expect(store.parentRecord?.id == original.id)
        }
        let preparationsBeforeLoad = await preparation.calls
        store.loadRecord(id: another.id)
        await (try #require(store.jobTask)).value
        #expect(store.savedRecord == another && store.result == another.result)
        #expect(store.references == another.references)
        #expect(store.openedReferenceText == nil && store.openedReferenceLabel == nil && store.parentRecord == nil)
        #expect(store.context == context && store.verifiedFiles.map(\.binding) == preparedBindings)
        #expect(!store.canSaveAnalysis)
        #expect(await preparation.calls == preparationsBeforeLoad)
        #expect(await provider.calls == 1)
    }

    private func makeStore(_ fixture: PDFStoreFixture, preparation: PDFStorePreparation,
                           provider: PDFStoreProvider) -> MultiEvidenceAnalysisStore {
        .init(executableURL: fixture.executable,
              prepare: { _, _, _, _, _ in await preparation.prepare() },
              analyze: { prompt, _ in await provider.analyze(prompt) })
    }
    private func configure(_ store: MultiEvidenceAnalysisStore, _ fixture: PDFStoreFixture) async {
        store.configure(evidence: fixture.evidence, result: fixture.result, files: fixture.entries,
                        helperURL: fixture.helper, forensicCase: fixture.forensicCase)
        await store.jobTask?.value
        // Keep page 2 omitted to exercise the whole-derived-text receipt rather
        // than a receipt limited to the currently visible page.
        store.firstRanges = "1:0:19"
        store.rebuildDisclosure()
    }
}

private actor PDFStorePreparation {
    private(set) var calls = 0
    private var files: [MultiEvidenceVerifiedFile]
    init(_ files: [MultiEvidenceVerifiedFile]) { self.files = files }
    func replace(with files: [MultiEvidenceVerifiedFile]) { self.files = files }
    func prepare() -> [MultiEvidenceVerifiedFile] { calls += 1; return files }
}
private actor PDFStoreProvider {
    private(set) var calls = 0
    private(set) var lastPrompt: String?
    func analyze(_ prompt: String) -> CodexAnalysisResult {
        calls += 1; lastPrompt = prompt
        return .init(response: .init(summary: "Synthetic interpretation [[A1:0:3]]", observations: [], hypotheses: [],
            limitations: ["Injected provider; no external request"], nextSteps: []),
            requestSHA256: MultiEvidenceCoding.digest(Data(prompt.utf8)), completedAt: Date())
    }
}
private struct PDFStoreFixture: Sendable {
    let directory: URL, source: URL, helper: URL, executable: URL
    let forensicCase: ForensicCase
    let evidence: EvidenceRecord
    let result: EnumerationResult
    let entries: [FilesystemEntry]
    let files: [MultiEvidenceVerifiedFile]
    let pages: [DocumentTextPage]

    static func make() async throws -> Self {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("PDFComparisonStore-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let source = directory.appendingPathComponent("private-source.dd"), helper = directory.appendingPathComponent("never-launch-engine")
        let executable = directory.appendingPathComponent("never-launch-codex")
        try Data("synthetic image".utf8).write(to: source)
        try Data("synthetic, never executed\n".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let created = try CaseStore.create(name: "Synthetic PDF Comparison", in: directory)
        let inspected = try await ImageInspector.inspect(url: source, progress: { _ in })
        let forensicCase = try CaseStore.adding(image: inspected, to: created)
        let evidence = try #require(forensicCase.manifest.evidence.first)
        let entries = [FilesystemEntry(id: "0:1", path: "/VERIFIED-BY-CONTENT.dat", name: "VERIFIED-BY-CONTENT.dat",
            fsOffsetBytes: 0, metaAddress: 1, size: 2 * 1_024 * 1_024, isDirectory: false, isDeleted: false),
            FilesystemEntry(id: "0:2", path: "/OTHER.txt", name: "OTHER.txt", fsOffsetBytes: 0,
                metaAddress: 2, size: 6, isDirectory: false, isDeleted: false)]
        let result = EnumerationResult(engineVersion: "synthetic", patchDigest: "synthetic", sourcePaths: [source.path],
            sourceFileHashes: [source.path: evidence.sha256], options: EngineOptions(hashLogicalImage: false),
            image: .init(imageType: "raw", logicalSize: 15, sectorSize: 512), volumes: [], files: entries,
            warnings: [], status: .completed)
        let pages = [DocumentTextPage(pageNumber: 1, text: "one SECRET ก😀 tail", isTruncated: false, referenceLabel: "Page 1", referenceKind: .page),
                     DocumentTextPage(pageNumber: 2, text: "undisclosed page", isTruncated: false, referenceLabel: "Page 2", referenceKind: .page)]
        let pdfBinding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entries[0])
        let pdfReceipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entries[0].id, byteCount: entries[0].size,
            sha256: String(repeating: "b", count: 64), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
        let analysis = try DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: pdfReceipt.sha256, sourceByteCount: pdfReceipt.byteCount, pageCount: 2, textPages: pages)
            .attachingProvenance(executableSHA256: String(repeating: "d", count: 64), codeSigningCDHash: nil,
                isolation: .requiredDevelopmentSeatbelt, timeout: 12)
        let pdf = try MultiEvidenceVerifiedFile(binding: pdfBinding, preview: .init(file: entries[0], receipt: pdfReceipt, analysis: analysis))
        let utf8Binding = try CaseWorkBinding.make(caseID: forensicCase.manifest.id, evidence: evidence, result: result, file: entries[1])
        let bytes = Data("second".utf8)
        let utf8Receipt = VerifiedContentReceipt(evidenceID: evidence.id, fileID: entries[1].id, byteCount: entries[1].size,
            sha256: MultiEvidenceCoding.digest(bytes), verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256])
        let utf8 = try MultiEvidenceVerifiedFile(binding: utf8Binding, content: .init(bytes: bytes, receipt: utf8Receipt))
        return .init(directory: directory, source: source, helper: helper, executable: executable, forensicCase: forensicCase,
            evidence: evidence, result: result, entries: entries, files: [pdf, utf8], pages: pages)
    }
    func changedPDF(_ fault: String) throws -> MultiEvidenceVerifiedFile {
        let freshPages = fault == "text" ? [pages[0], DocumentTextPage(pageNumber: 2, text: "changed omitted page",
            isTruncated: false, referenceLabel: "Page 2", referenceKind: .page)] : pages
        let original = files[0]
        let analysis = try DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
            sourceSHA256: original.receipt.sha256, sourceByteCount: original.receipt.byteCount, pageCount: 2, textPages: freshPages)
            .attachingProvenance(executableSHA256: String(repeating: fault == "executable" ? "e" : "d", count: 64),
                codeSigningCDHash: nil, isolation: .requiredDevelopmentSeatbelt, timeout: fault == "options" ? 13 : 12)
        return try .init(binding: original.binding, preview: .init(file: entries[0], receipt: original.receipt, analysis: analysis))
    }
    func remove() { try? FileManager.default.removeItem(at: directory) }
}
