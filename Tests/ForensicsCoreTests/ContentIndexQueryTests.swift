import Foundation
import Testing
@testable import ForensicsCore

@Suite("ContentIndexQueryTests")
struct ContentIndexQueryTests {
    @Test("Literal, whole-word phrase and token-start prefix have independent UTF-16 oracles")
    func distinctModes() async throws {
        let snapshot = try await querySnapshot(pages: ["😀 café cafe\u{0301} cat scatter catfish cat"])
        let literal = try CaseContentIndexSearch.search("cat", in: snapshot, mode: .literal, caseSensitive: true)
        let phrase = try CaseContentIndexSearch.search("cat", in: snapshot, mode: .phrase, caseSensitive: true)
        let prefix = try CaseContentIndexSearch.search("cat", in: snapshot, mode: .tokenPrefix, caseSensitive: true)
        #expect(spans(literal) == [.init(location: 14, length: 3), .init(location: 19, length: 3),
                                   .init(location: 26, length: 3), .init(location: 34, length: 3)])
        #expect(spans(phrase) == [.init(location: 14, length: 3), .init(location: 34, length: 3)])
        #expect(spans(prefix) == [.init(location: 14, length: 3), .init(location: 26, length: 3), .init(location: 34, length: 3)])
        #expect(prefix.queryTokens.map(\.text) == ["cat"])
        for result in [literal, phrase, prefix] {
            #expect(result.queryIssue == nil)
            #expect(result.hits.allSatisfy { CaseContentIndexSearch.resolve($0.reference, in: snapshot) != nil })
        }
        let composed = try CaseContentIndexSearch.search("café", in: snapshot, mode: .phrase, caseSensitive: true)
        let decomposed = try CaseContentIndexSearch.search("cafe\u{0301}", in: snapshot, mode: .phrase, caseSensitive: true)
        #expect(spans(composed) == [.init(location: 3, length: 4)])
        #expect(spans(decomposed) == [.init(location: 8, length: 5)])
        #expect(try CaseContentIndexSearch.search("CAT", in: snapshot, mode: .phrase, caseSensitive: true).hits.isEmpty)
        #expect(try CaseContentIndexSearch.search("CAT", in: snapshot, mode: .phrase).hits.count == 2)
        #expect(try CaseContentIndexSearch.search("CAT", in: snapshot, mode: .tokenPrefix).hits.count == 3)
        #expect(spans(try CaseContentIndexSearch.search("café", in: snapshot, mode: .tokenPrefix, caseSensitive: true))
            == [.init(location: 3, length: 4)])
    }

    @Test("Phrase adjacency includes real separators, supports fallback and overlap, and stops at page boundaries")
    func phraseAdjacency() async throws {
        let snapshot = try await querySnapshot(pages: ["😀 cat,\ncat", "a a a b", "a b a b a", "cat", "cat"])
        let separators = try CaseContentIndexSearch.search("cat cat", in: snapshot, mode: .phrase, caseSensitive: true)
        #expect(spans(separators) == [.init(location: 3, length: 8)])
        let separatorHit = try #require(separators.hits.first)
        #expect(separatorHit.reference.indexReference.pageNumber == 1)
        #expect(separators.queryTokens.map(\.text) == ["cat", "cat"])
        let fallback = try CaseContentIndexSearch.search("a a b", in: snapshot, mode: .phrase, caseSensitive: true)
        #expect(spans(fallback) == [.init(location: 2, length: 5)])
        let overlapping = try CaseContentIndexSearch.search("a b a", in: snapshot, mode: .phrase, caseSensitive: true)
        #expect(spans(overlapping) == [.init(location: 0, length: 5), .init(location: 4, length: 5)])
        #expect(overlapping.hits.allSatisfy { $0.reference.indexReference.pageNumber == 3 })
    }

    @Test("Raw punctuation, wildcard-looking strings, short Thai and combining queries retain literal behavior")
    func rawLiteralAndValidation() async throws {
        let snapshot = try await querySnapshot(pages: ["ภาษาไทย [literal] foo-bar .* \"cat\" cafe\u{0301}"])
        for query in ["ภ", "ภา", "[literal]", "foo-bar", ".*", "\"cat\"", "\u{0301}"] {
            let legacy = try CaseContentIndexSearch.search(query, in: snapshot, caseSensitive: true)
            let explicit = try CaseContentIndexSearch.search(query, in: snapshot, mode: .literal, caseSensitive: true)
            #expect(legacy.hits.count == 1)
            #expect(explicit.query.utf8.elementsEqual(query.utf8))
            #expect(legacy.hits.map(\.reference) == explicit.hits.map { $0.reference.indexReference })
        }
        for query in ["[literal]", ".*", "\"cat\"", "cat*"] {
            let phrase = try CaseContentIndexSearch.search(query, in: snapshot, mode: .phrase)
            let prefix = try CaseContentIndexSearch.search(query, in: snapshot, mode: .tokenPrefix)
            #expect(phrase.queryIssue != nil); #expect(prefix.queryIssue != nil)
            #expect(phrase.hits.isEmpty); #expect(prefix.hits.isEmpty)
        }
        #expect(try CaseContentIndexSearch.search("cat cat", in: snapshot, mode: .tokenPrefix).queryIssue == .prefixRequiresSingleToken)
        #expect(try CaseContentIndexSearch.search("\u{0301}", in: snapshot, mode: .phrase).queryIssue == .noWordTokens)
        #expect(try CaseContentIndexSearch.search(String(repeating: "a", count: 4_097), in: snapshot, mode: .phrase).queryIssue == .queryTooLong)
    }

    @Test("Thai phrases omit internal whitespace while prefix uses actual compound boundaries")
    func thaiSample() async throws {
        // A small platform contract fixture, not a claim that Foundation can
        // resolve every Thai linguistic ambiguity or every OS tokenizer version.
        let snapshot = try await querySnapshot(pages: ["😀 ภาษาไทย", "ภาษา ไทย"])
        let phrase = try CaseContentIndexSearch.search("ภาษา ไทย", in: snapshot, mode: .phrase, caseSensitive: true)
        #expect(phrase.queryTokens.map(\.text) == ["ภาษา", "ไทย"])
        #expect(spans(phrase) == [.init(location: 3, length: 7), .init(location: 0, length: 8)])
        let unspaced = try CaseContentIndexSearch.search("ภาษาไทย", in: snapshot, mode: .phrase, caseSensitive: true)
        // Both public Apple tokenizers recognize this compound as one word;
        // phrase spacing does not fabricate component-word metadata.
        #expect(unspaced.queryTokens.map(\.text) == ["ภาษาไทย"])
        #expect(spans(unspaced) == [.init(location: 3, length: 7), .init(location: 0, length: 8)])
        let compoundPrefix = try CaseContentIndexSearch.search("ภาษาไทย", in: snapshot, mode: .tokenPrefix)
        #expect(compoundPrefix.queryIssue == nil)
        #expect(spans(compoundPrefix) == [.init(location: 3, length: 7)])
        let prefix = try CaseContentIndexSearch.search("ภ", in: snapshot, mode: .tokenPrefix, caseSensitive: true)
        #expect(spans(prefix) == [.init(location: 3, length: 1), .init(location: 0, length: 1)])
        #expect(try CaseContentIndexSearch.search("ษา", in: snapshot, mode: .tokenPrefix, caseSensitive: true).hits.isEmpty)
        #expect(try CaseContentIndexSearch.search("ภา", in: snapshot, mode: .literal, caseSensitive: true).hits.count == 2)
    }

    @Test("Thai phrase compaction rejects punctuation, intervening Latin and interior token edges")
    func thaiPhraseBoundaries() async throws {
        let snapshot = try await querySnapshot(pages: ["ภาษา-ไทย", "ภาษา / ไทย", "ภาษา cat ไทย", "ภาษารักไทย",
            "ภาษา\u{200B}ไทย", "ภาษา\u{FEFF}ไทย", "ภาษา\u{2060}ไทย"])
        let interrupted = try CaseContentIndexSearch.search("ภาษา ไทย", in: snapshot, mode: .phrase)
        #expect(interrupted.queryIssue == nil); #expect(interrupted.hits.isEmpty)
        let compound = try await querySnapshot(pages: ["😀 ภาษาไทย", "ภาษา ไทย"])
        let interior = try CaseContentIndexSearch.search("ษา ไทย", in: compound, mode: .phrase)
        #expect(interior.queryIssue == nil); #expect(interior.hits.isEmpty)
        let joined = try await querySnapshot(pages: ["ภาษาไทย"])
        let incomplete = try CaseContentIndexSearch.search("ภาษา", in: joined, mode: .phrase)
        let interiorPrefix = try CaseContentIndexSearch.search("ไทย", in: joined, mode: .tokenPrefix)
        #expect(incomplete.queryIssue == nil); #expect(incomplete.hits.isEmpty)
        #expect(interiorPrefix.queryIssue == nil); #expect(interiorPrefix.hits.isEmpty)
        let mixed = try await querySnapshot(pages: ["ภาษา catfish", "catfish"])
        for query in ["ภาษา cat fish", "cat fish"] {
            let result = try CaseContentIndexSearch.search(query, in: mixed, mode: .phrase)
            #expect(result.queryIssue == nil); #expect(result.hits.isEmpty)
        }
        #expect(spans(try CaseContentIndexSearch.search("ภาษา catfish", in: mixed, mode: .phrase)) == [.init(location: 0, length: 12)])
    }

    @Test("Thai phrase gaps accept Unicode White_Space and preserve format characters literally")
    func thaiWhitespaceProperty() async throws {
        let compound = try await querySnapshot(pages: ["😀 ภาษาไทย"])
        for separator in ["\t", "\n", "\u{00A0}", "\u{2003}", "\u{202F}"] {
            let spaced = try await querySnapshot(pages: ["ภาษา" + separator + "ไทย"])
            let sourceGap = try CaseContentIndexSearch.search("ภาษา ไทย", in: spaced, mode: .phrase)
            #expect(sourceGap.queryIssue == nil)
            #expect(spans(sourceGap) == [.init(location: 0, length: 8)])
            let query = "ภาษา" + separator + "ไทย"
            let queryGap = try CaseContentIndexSearch.search(query, in: compound, mode: .phrase)
            #expect(queryGap.queryIssue == nil)
            #expect(spans(queryGap) == [.init(location: 3, length: 7)])
            #expect(queryGap.request.query.utf8.elementsEqual(query.utf8))
        }
        for format in ["\u{200B}", "\u{FEFF}", "\u{2060}"] {
            let query = "ภาษา" + format + " ไทย"
            let result = try CaseContentIndexSearch.search(query, in: compound, mode: .phrase)
            #expect(result.queryIssue == .phraseContainsNonWordText)
            #expect(result.hits.isEmpty)
            let raw = "ภาษา" + format + "ไทย"
            let source = try await querySnapshot(pages: [raw])
            #expect(spans(try CaseContentIndexSearch.search(raw, in: source, mode: .literal)) == [.init(location: 0, length: 8)])
        }
    }

    @Test("Thai phrase overlap and reset preserve raw Thai marks and original offsets")
    func thaiPhraseOverlapAndMarks() async throws {
        let snapshot = try await querySnapshot(pages: ["ไทย ไทย ไทย", "ไทย ไทย cat ไทย ไทย", "😀 กิกิ", "กิ กิ", "กำ กำ", "ก\u{0E4D}า ก\u{0E4D}า"])
        let repeated = try CaseContentIndexSearch.search("ไทย ไทย", in: snapshot, mode: .phrase)
        #expect(spans(repeated) == [.init(location: 0, length: 7), .init(location: 4, length: 7),
                                    .init(location: 0, length: 7), .init(location: 12, length: 7)])
        #expect(spans(try CaseContentIndexSearch.search("กิ กิ", in: snapshot, mode: .phrase))
            == [.init(location: 3, length: 4), .init(location: 0, length: 5)])
        #expect(spans(try CaseContentIndexSearch.search("กำ กำ", in: snapshot, mode: .phrase)) == [.init(location: 0, length: 5)])
        #expect(spans(try CaseContentIndexSearch.search("ก\u{0E4D}า ก\u{0E4D}า", in: snapshot, mode: .phrase)) == [.init(location: 0, length: 7)])
        #expect(repeated.hits.allSatisfy { CaseContentIndexSearch.resolve($0.reference, in: snapshot) != nil })
    }

    @Test("Thai phrase bounds and references preserve whitespace, request and generation bindings")
    func thaiPhraseBoundsAndReferences() async throws {
        let body = "😀 ภาษา" + String(repeating: " ", count: 50_000) + "ไทย"
        let snapshot = try await querySnapshot(pages: [body, String(repeating: "ไทย ", count: 202)])
        let request = ContentIndexQueryRequest(query: "ภาษา ไทย", mode: .phrase, caseSensitive: true)
        let result = try CaseContentIndexSearch.search(request, in: snapshot)
        #expect(spans(result) == [.init(location: 3, length: 50_007)])
        let hit = try #require(result.hits.first)
        #expect(hit.snippet.utf16.count <= 162)
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: snapshot, expectedRequest: request) != nil)
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: snapshot,
            expectedRequest: .init(query: "ภาษาไทย", mode: .phrase, caseSensitive: true)) == nil)
        #expect(CaseContentIndexSearch.resolve(ContentIndexQueryReference(caseID: snapshot.caseID,
            request: .init(query: "ภาษา ไทย", mode: .literal, caseSensitive: true), indexReference: hit.reference.indexReference), in: snapshot) == nil)
        let shifted = ContentIndexQueryReference(caseID: snapshot.caseID, request: request,
            indexReference: replaceSpan(hit.reference.indexReference, offset: 4, length: 50_006))
        #expect(CaseContentIndexSearch.resolve(shifted, in: snapshot) == nil)
        let nextGeneration = try await querySnapshot(pages: [body], caseID: snapshot.caseID)
        #expect(CaseContentIndexSearch.resolve(hit.reference, in: nextGeneration) == nil)
        let limited = try CaseContentIndexSearch.search("ไทย", in: snapshot, mode: .phrase, maximumHits: 2)
        #expect(limited.hits.count == 2); #expect(limited.hitLimitReached)
        let exact = try await querySnapshot(pages: ["ไทย ไทย"])
        #expect(try !CaseContentIndexSearch.search("ไทย", in: exact, mode: .phrase, maximumHits: 2).hitLimitReached)
        #expect(try CaseContentIndexSearch.search(String(repeating: "ไทย", count: 456), in: exact, mode: .phrase).queryIssue == .queryTooLong)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try CaseContentIndexSearch.search(request, in: snapshot)
        }
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("Query references reject changed mode, raw spelling, case, range, generation and case bindings")
    func queryReferences() async throws {
        let snapshot = try await querySnapshot(pages: ["cat,\ncat café cafe\u{0301}"])
        let request = ContentIndexQueryRequest(query: "cat cat", mode: .phrase, caseSensitive: true)
        let result = try CaseContentIndexSearch.search(request, in: snapshot)
        let bound = try #require(result.hits.first?.reference)
        #expect(CaseContentIndexSearch.resolve(bound, in: snapshot, expectedRequest: request) != nil)
        let literal = ContentIndexQueryRequest(query: "cat cat", mode: .literal, caseSensitive: true)
        let changed = ContentIndexQueryReference(caseID: snapshot.caseID, request: literal, indexReference: bound.indexReference)
        #expect(CaseContentIndexSearch.resolve(changed, in: snapshot) == nil)
        #expect(CaseContentIndexSearch.resolve(bound, in: snapshot, expectedRequest: literal) == nil)
        let differentCase = ContentIndexQueryReference(caseID: UUID(), request: request, indexReference: bound.indexReference)
        #expect(CaseContentIndexSearch.resolve(differentCase, in: snapshot) == nil)
        let shifted = ContentIndexQueryReference(caseID: snapshot.caseID, request: request,
            indexReference: replaceSpan(bound.indexReference, offset: 1, length: 7))
        #expect(CaseContentIndexSearch.resolve(shifted, in: snapshot) == nil)
        let nextGeneration = try await querySnapshot(pages: ["cat,\ncat café cafe\u{0301}"], caseID: snapshot.caseID)
        #expect(CaseContentIndexSearch.resolve(bound, in: nextGeneration) == nil)
        let nfc = ContentIndexQueryRequest(query: "café", mode: .phrase, caseSensitive: true)
        let nfd = ContentIndexQueryRequest(query: "cafe\u{0301}", mode: .phrase, caseSensitive: true)
        #expect(nfc != nfd)
        let composed = try CaseContentIndexSearch.search(nfc, in: snapshot)
        let reference = try #require(composed.hits.first?.reference)
        #expect(CaseContentIndexSearch.resolve(reference, in: snapshot, expectedRequest: nfd) == nil)
        #expect(CaseContentIndexSearch.resolve(reference, in: snapshot,
            expectedRequest: .init(query: "café", mode: .phrase, caseSensitive: false)) == nil)
    }

    @Test("All modes enforce extra-hit detection, bounded snippets, and cancellation")
    func boundedAndCanceled() async throws {
        let snapshot = try await querySnapshot(pages: [String(repeating: "a ", count: 202)])
        for mode in ContentIndexSearchMode.allCases {
            let limited = try CaseContentIndexSearch.search("a", in: snapshot, mode: mode, maximumHits: 2)
            #expect(limited.hits.count == 2); #expect(limited.hitLimitReached)
            let task = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                return try CaseContentIndexSearch.search("a", in: snapshot, mode: mode)
            }
            await #expect(throws: CancellationError.self) { try await task.value }
        }
        let exact = try await querySnapshot(pages: ["a a"])
        #expect(try !CaseContentIndexSearch.search("a", in: exact, mode: .tokenPrefix, maximumHits: 2).hitLimitReached)
        let separated = try await querySnapshot(pages: ["😀 a" + String(repeating: ",", count: 50_000) + "a"])
        let phrase = try CaseContentIndexSearch.search("a a", in: separated, mode: .phrase)
        #expect(spans(phrase) == [.init(location: 3, length: 50_002)])
        let hit = try #require(phrase.hits.first)
        #expect(hit.snippet.utf16.count <= 162)
        #expect(!hit.snippet.contains("�"))
    }
}

private func spans(_ result: CaseContentQueryOutcome) -> [NSRange] {
    result.hits.map { NSRange(location: $0.reference.indexReference.utf16Offset, length: $0.reference.indexReference.utf16Length) }
}

private func replaceSpan(_ reference: ContentIndexReference, offset: Int, length: Int) -> ContentIndexReference {
    ContentIndexReference(snapshotID: reference.snapshotID, evidenceID: reference.evidenceID,
        listingSHA256: reference.listingSHA256, file: reference.file, locatorSHA256: reference.locatorSHA256,
        orderedContainerSHA256: reference.orderedContainerSHA256, contentSHA256: reference.contentSHA256,
        derivedTextSHA256: reference.derivedTextSHA256, decoderBinarySHA256: reference.decoderBinarySHA256,
        pageNumber: reference.pageNumber, utf16Offset: offset, utf16Length: length,
        referenceLabel: reference.referenceLabel, referenceKind: reference.referenceKind)
}

private func querySnapshot(pages: [String], caseID: UUID = UUID()) async throws -> CaseContentIndexSnapshot {
    let evidence = EvidenceRecord(sourcePath: "/synthetic/query.dd", byteCount: 1_024,
        sha256: String(repeating: "a", count: 64), container: .raw, filesystemHint: nil)
    let file = FilesystemEntry(id: "body-only", path: "/unrelated.txt", name: "unrelated.txt", fsOffsetBytes: 0,
        metaAddress: 9, size: 5, isDirectory: false, isDeleted: false)
    let listing = EnumerationResult(engineVersion: "synthetic-query-v1", patchDigest: "fixture",
        sourcePaths: [evidence.sourcePath], sourceFileHashes: [evidence.sourcePath: evidence.sha256],
        options: EngineOptions(hashLogicalImage: false),
        image: EngineImageMetadata(imageType: "raw", logicalSize: 1_024, sectorSize: 512),
        volumes: [], files: [file], warnings: [], status: .completed)
    let service = CaseContentIndexService(preview: { evidence, _, file in
        let hash = String(repeating: "c", count: 64)
        let textPages = pages.enumerated().map { DocumentTextPage(pageNumber: $0.offset + 1,
            text: $0.element, referenceLabel: "Page \($0.offset + 1)", referenceKind: .page) }
        return FilesystemDocumentPreview(file: file,
            receipt: VerifiedContentReceipt(evidenceID: evidence.id, fileID: file.id, byteCount: file.size,
                sha256: hash, verifiedAt: Date(), orderedContainerSHA256: [evidence.sha256]),
            analysis: DocumentAnalysis(contentKind: .pdf, mimeType: "application/pdf", status: .decoded,
                sourceSHA256: hash, sourceByteCount: file.size, pageCount: pages.count, textPages: textPages))
    }, verifySources: { _ in }, decoderFingerprint: { String(repeating: "d", count: 64) })
    let snapshot = try await service.rebuild(caseID: caseID, inputs: [.init(evidence: evidence, result: listing)])
    #expect(snapshot.indexedCount == 1)
    #expect(snapshot.failedCount == 0)
    return snapshot
}
