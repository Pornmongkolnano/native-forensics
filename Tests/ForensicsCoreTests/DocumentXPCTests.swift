import CryptoKit
import Darwin
import Foundation
import NFDecoderIPC
import NFDocumentDecoding
import Security
import Testing
@testable import ForensicsCore

struct DocumentXPCTests {
    private let nonce = String(repeating: "a", count: 32)
    private let otherNonce = String(repeating: "b", count: 32)
    private let bytes = Data("synthetic XPC text".utf8)
    private var hash: String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    private var input: DocumentInput {
        DocumentInput(fileURL: URL(fileURLWithPath: "/synthetic-receipt-only"),
                      expectedSHA256: hash, expectedByteCount: Int64(bytes.count))
    }
    private var request: DocumentXPCDecodeRequest {
        DocumentXPCDecodeRequest(nonce: nonce, sourceSHA256: hash, sourceByteCount: Int64(bytes.count))
    }
    private var analysis: DocumentAnalysis {
        DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
                         sourceSHA256: hash, sourceByteCount: Int64(bytes.count),
                         textPages: [DocumentTextPage(pageNumber: 1, text: "synthetic XPC text")])
    }

    @Test func snapshotDecodingRequiresEveryReceiptByteAndDigest() throws {
        let source = try VerifiedDocument(data: bytes, expectedSHA256: hash, expectedByteCount: Int64(bytes.count))
        let decoded = DocumentDecoder.decode(source)
        #expect(decoded.status == .decoded && decoded.contentKind == .text)
        #expect(decoded.sourceSHA256 == hash && decoded.sourceByteCount == Int64(bytes.count))
        #expect(decoded.textPages.first?.text == String(decoding: bytes, as: UTF8.self))
        #expect(throws: DocumentAnalysisError.integrityMismatch) {
            try VerifiedDocument(data: bytes.dropLast(), expectedSHA256: hash, expectedByteCount: Int64(bytes.count))
        }
        #expect(throws: DocumentAnalysisError.integrityMismatch) {
            try VerifiedDocument(data: bytes, expectedSHA256: String(repeating: "f", count: 64), expectedByteCount: Int64(bytes.count))
        }
    }

    @Test func controlMessagesContainNoSourcePathAndValidateProtocol() throws {
        let encoded = try DocumentXPCTransport.controlData(request)
        #expect(encoded.count <= DocumentXPCWire.maximumControlBytes)
        let text = String(decoding: encoded, as: UTF8.self)
        #expect(!text.contains("fileURL") && !text.contains(input.fileURL.path))
        #expect(request.isValid)
        #expect(!DocumentXPCDecodeRequest(nonce: "not-a-nonce", sourceSHA256: hash, sourceByteCount: 1).isValid)
        #expect(!DocumentXPCDecodeRequest(nonce: nonce, sourceSHA256: hash, sourceByteCount: DocumentLimits.maximumInputBytes + 1).isValid)
        #expect(!DocumentXPCSessionRequest(nonce: nonce, timeoutMilliseconds: 120_001).isValid)
    }

    @Test func responseCannotReplayAnotherJobOrSourceReceipt() throws {
        let valid = try JSONEncoder().encode(DocumentXPCDecodeResponse(request: request, analysis: analysis))
        #expect(try DocumentXPCTransport.decodeResponse(valid, request: request, input: input) == analysis)
        for replacement in [
            DocumentXPCDecodeRequest(nonce: otherNonce, sourceSHA256: hash, sourceByteCount: Int64(bytes.count)),
            DocumentXPCDecodeRequest(nonce: nonce, sourceSHA256: String(repeating: "f", count: 64), sourceByteCount: Int64(bytes.count)),
            DocumentXPCDecodeRequest(nonce: nonce, sourceSHA256: hash, sourceByteCount: Int64(bytes.count) + 1)
        ] {
            let data = try JSONEncoder().encode(DocumentXPCDecodeResponse(request: replacement, analysis: analysis))
            #expect(throws: DocumentAnalysisError.invalidResponse) {
                try DocumentXPCTransport.decodeResponse(data, request: request, input: input)
            }
        }
        let contradictory = try JSONEncoder().encode(DocumentXPCDecodeResponse(request: request,
            analysis: analysis, failureCode: "INVALID_INPUT"))
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try DocumentXPCTransport.decodeResponse(contradictory, request: request, input: input)
        }
    }

    @Test func malformedFloodAndFailureResponsesFailClosed() throws {
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try DocumentXPCTransport.decodeResponse(Data("{bad-json}".utf8), request: request, input: input)
        }
        #expect(throws: DocumentAnalysisError.outputLimit) {
            try DocumentXPCTransport.decodeResponse(Data(repeating: 32, count: DocumentLimits.maximumResponseBytes + 1),
                                                   request: request, input: input)
        }
        let failed = try JSONEncoder().encode(DocumentXPCDecodeResponse(request: request, failureCode: "INTEGRITY_MISMATCH"))
        #expect(throws: DocumentAnalysisError.integrityMismatch) {
            try DocumentXPCTransport.decodeResponse(failed, request: request, input: input)
        }
    }

    @Test func encodedOutputBudgetKeepsIncompleteCoverageVisible() throws {
        let oversizedJSON = DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
            sourceSHA256: hash, sourceByteCount: Int64(bytes.count),
            textPages: [DocumentTextPage(pageNumber: 1, text: String(repeating: "\0", count: DocumentLimits.maximumTextBytes))])
        let encoded = try DocumentResponseEncoder.encodeXPC(oversizedJSON, request: request)
        #expect(encoded.count <= DocumentLimits.maximumResponseBytes)
        let accepted = try DocumentXPCTransport.decodeResponse(encoded, request: request, input: input)
        #expect(accepted.textPages.count == 1 && accepted.textPages[0].isTruncated)
        #expect(!accepted.textIsComplete)
        #expect(accepted.warnings.contains { $0.contains("shortened") })
    }

    @Test func parentRejectsPNGHeaderWithoutCompleteDatastream() throws {
        // This satisfies the former prefix/dimensions-only thumbnail check.
        var incompletePNG = Data([137,80,78,71,13,10,26,10, 0,0,0,13,73,72,68,82])
        incompletePNG.append(Data([0,0,0,1, 0,0,0,1, 8,6,0,0,0, 0,0,0,0]))
        let hostile = DocumentAnalysis(contentKind: .image, mimeType: "image/png", status: .decoded,
            sourceSHA256: hash, sourceByteCount: Int64(bytes.count), pixelWidth: 1, pixelHeight: 1,
            thumbnailPNG: incompletePNG)
        let encoded = try JSONEncoder().encode(DocumentXPCDecodeResponse(request: request, analysis: hostile))
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try DocumentXPCTransport.decodeResponse(encoded, request: request, input: input)
        }
    }

    @Test func cancellationOfQueuedRequestDoesNotReleaseAnotherOwner() async throws {
        let gate = DocumentXPCOwnershipGate()
        let owner = DocumentCancellation(), waiting = DocumentCancellation()
        try gate.acquire(cancellation: owner)
        let queued = Task {
            try await BlockingWork.run { try gate.acquire(cancellation: waiting) }
        }
        waiting.cancel()
        do { try await queued.value; Issue.record("A cancelled queued request acquired another owner's gate.") }
        catch { #expect(error is CancellationError) }
        // The first owner can still release normally; no unrelated job was
        // granted ownership by a cancelled waiter's cleanup.
        gate.release()
        let next = DocumentCancellation()
        try gate.acquire(cancellation: next)
        gate.release()
    }

    @Test func unverifiableCleanupPoisonsFutureXPCRequests() throws {
        let gate = DocumentXPCOwnershipGate()
        gate.poison()
        #expect(throws: DocumentAnalysisError.cleanupFailed) { try gate.acquire(cancellation: DocumentCancellation()) }
    }

    @Test func auditTokensRejectMalformedBytesAndBindCurrentKernelIdentity() throws {
        #expect(NFDecoderAuditTokenPID(Data(repeating: 0, count: 31)) == -1)
        #expect(NFDecoderAuditTokenUID(Data(repeating: 0, count: 33)) == uid_t.max)
        let token = try #require(NFDecoderCurrentAuditToken())
        #expect(NFDecoderAuditTokenPID(token) == Darwin.getpid())
        #expect(NFDecoderAuditTokenUID(token) == Darwin.geteuid())
    }

    @Test func serviceEntitlementsRejectNetworkFileAndInheritanceGrants() throws {
        let sandbox: [String: Any] = ["com.apple.security.app-sandbox": true]
        try DocumentXPCServiceConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: sandbox])
        for extra in ["com.apple.security.network.client", "com.apple.security.network.server",
                      "com.apple.security.files.user-selected.read-only", "com.apple.security.inherit"] {
            var entitlements = sandbox; entitlements[extra] = true
            #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
                try DocumentXPCServiceConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: entitlements])
            }
        }
    }

    @Test func serviceSandboxRequiresAnExactTrueCFBoolean() throws {
        for rejected in [NSNumber(value: 1), NSNumber(value: 1.0), "true", false] as [Any] {
            let entitlement: [String: Any] = ["com.apple.security.app-sandbox": rejected]
            #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
                try DocumentXPCServiceConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: entitlement])
            }
        }
        let boolean: [String: Any] = ["com.apple.security.app-sandbox": NSNumber(value: true)]
        try DocumentXPCServiceConfiguration.validateEntitlements([kSecCodeInfoEntitlementsDict as String: boolean])
    }

}
