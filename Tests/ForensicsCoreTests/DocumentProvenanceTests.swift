import Foundation
import Testing
@testable import ForensicsCore

struct DocumentProvenanceTests {
    private let hash = String(repeating: "a", count: 64)
    private var input: DocumentInput {
        DocumentInput(fileURL: URL(fileURLWithPath: "/unused"), expectedSHA256: hash, expectedByteCount: 12)
    }
    private var historical: DocumentAnalysis {
        DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: hash, sourceByteCount: 12,
            textPages: [DocumentTextPage(pageNumber: 1, text: "derived text", referenceLabel: "Text document", referenceKind: .document)])
    }
    private func current() throws -> DocumentAnalysis {
        try historical.attachingProvenance(executableSHA256: String(repeating: "b", count: 64),
            codeSigningCDHash: nil, isolation: .requiredDevelopmentSeatbelt, timeout: 12)
    }

    @Test func historicalV1RemainsReadableWithoutInventedProvenance() throws {
        let json = try JSONEncoder().encode(historical)
        let reopened = try JSONDecoder().decode(DocumentAnalysis.self, from: json)
        #expect(reopened.schemaVersion == 1 && reopened.provenance == nil)
        #expect(reopened == historical)
        try DocumentAnalysisClient.validate(reopened, for: input)
    }

    @Test func currentResultBindsFinalTextReferencesFlagsAndOptions() throws {
        let value = try current()
        let provenance = try #require(value.provenance)
        #expect(value.schemaVersion == 2)
        #expect(provenance.decoderIdentifier == DocumentDecoderContract.identifier)
        #expect(provenance.decoderVersion == DocumentDecoderContract.version)
        #expect(provenance.optionsSHA256 == (try CaseWorkCoding.digest(provenance.options)))
        #expect(provenance.derivedTextSHA256 == (try CaseWorkCoding.digest(value.textPages)))
        #expect(provenance.options.maximumInputBytes == 128 * 1_024 * 1_024)
        #expect(provenance.options.maximumResponseBytes == 2 * 1_024 * 1_024)
        #expect(provenance.options.timeoutSeconds == 12)
        let reopened = try JSONDecoder().decode(DocumentAnalysis.self, from: JSONEncoder().encode(value))
        #expect(reopened == value)
        try DocumentAnalysisClient.validate(reopened, for: input)
    }

    @Test func missingV2AndContradictoryV1ProvenanceFailClosed() throws {
        let missing = DocumentAnalysis(schemaVersion: 2, contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: hash, sourceByteCount: 12, textPages: historical.textPages)
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(missing, for: input) }
        let receipt = try #require(current().provenance)
        let inconsistent = DocumentAnalysis(schemaVersion: 1, contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: hash, sourceByteCount: 12, textPages: historical.textPages, provenance: receipt)
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(inconsistent, for: input) }
    }

    @Test func textAndPolicyTamperingCannotReuseProvenance() throws {
        let value = try current()
        let changedText = DocumentAnalysis(schemaVersion: 2, contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: hash, sourceByteCount: 12,
            textPages: [DocumentTextPage(pageNumber: 1, text: "different text", isTruncated: true)], provenance: value.provenance)
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(changedText, for: input) }
        var root = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
        var provenance = try #require(root["provenance"] as? [String: Any])
        var options = try #require(provenance["options"] as? [String: Any])
        options["maximumPages"] = 201
        provenance["options"] = options
        root["provenance"] = provenance
        let modified = try JSONDecoder().decode(DocumentAnalysis.self, from: JSONSerialization.data(withJSONObject: root))
        #expect(throws: DocumentAnalysisError.invalidResponse) { try DocumentAnalysisClient.validate(modified, for: input) }
    }

    @Test func sandboxProvenanceRequiresVerifiedCodeSigningIdentity() throws {
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try historical.attachingProvenance(executableSHA256: String(repeating: "b", count: 64),
                codeSigningCDHash: nil, isolation: .appSandboxXPC, timeout: 12)
        }
    }

    @Test func currentXPCProvenanceSeparatelyBindsParserAndBroker() throws {
        let parser = String(repeating: "b", count: 64), broker = String(repeating: "c", count: 64)
        let value = try historical.attachingProvenance(executableSHA256: parser,
            codeSigningCDHash: String(repeating: "d", count: 40), isolation: .appSandboxXPC, timeout: 12,
            brokerExecutableSHA256: broker, brokerCodeSigningCDHash: String(repeating: "e", count: 40))
        let provenance = try #require(value.provenance)
        #expect(provenance.decoderExecutableSHA256 == parser && provenance.brokerExecutableSHA256 == broker)
        try provenance.validateMetadata()
        try DocumentAnalysisClient.validate(value, for: input)
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try historical.attachingProvenance(executableSHA256: parser,
                codeSigningCDHash: String(repeating: "d", count: 40), isolation: .appSandboxXPC, timeout: 12)
        }
    }

}
