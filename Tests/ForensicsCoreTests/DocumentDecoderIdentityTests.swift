import Foundation
import Testing
@testable import ForensicsCore

struct DocumentDecoderIdentityTests {
    private let parser = String(repeating: "a", count: 64)
    private let broker = String(repeating: "b", count: 64)
    private let parserCD = String(repeating: "c", count: 40)
    private let brokerCD = String(repeating: "d", count: 40)

    private func identity(brokerHash: String? = nil, brokerSigningHash: String? = nil,
                          timeout: Double = 12) throws -> DocumentDecoderIdentity {
        try DocumentDecoderIdentity(executableSHA256: parser, codeSigningCDHash: parserCD,
            isolation: .appSandboxXPC, timeout: timeout,
            brokerExecutableSHA256: brokerHash ?? broker, brokerCodeSigningCDHash: brokerSigningHash ?? brokerCD,
            ipcProtocolVersion: DocumentXPCWire.protocolVersion)
    }

    @Test func completeBackendMetadataBindsProvenanceWithoutIncludingResultText() throws {
        let identity = try identity()
        let first = try DocumentDecodeProvenance(executableSHA256: parser, codeSigningCDHash: parserCD,
            isolation: .appSandboxXPC, timeout: 12, pages: [.init(pageNumber: 1, text: "one")],
            brokerExecutableSHA256: broker, brokerCodeSigningCDHash: brokerCD)
        let second = try DocumentDecodeProvenance(executableSHA256: parser, codeSigningCDHash: parserCD,
            isolation: .appSandboxXPC, timeout: 12, pages: [.init(pageNumber: 1, text: "two")],
            brokerExecutableSHA256: broker, brokerCodeSigningCDHash: brokerCD)
        #expect(identity.matches(first) && identity.matches(second))
        #expect(first.derivedTextSHA256 != second.derivedTextSHA256)
        let changedBroker = try self.identity(brokerHash: String(repeating: "e", count: 64))
        let changedBrokerSigning = try self.identity(brokerSigningHash: String(repeating: "f", count: 40))
        let changedTimeout = try self.identity(timeout: 11)
        #expect(!changedBroker.matches(first) && !changedBrokerSigning.matches(first) && !changedTimeout.matches(first))
    }

    @Test func identityRejectsMissingIPCOrBrokerAndDoesNotInferDecodedMissingFields() throws {
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try DocumentDecoderIdentity(executableSHA256: parser, codeSigningCDHash: parserCD,
                isolation: .appSandboxXPC, timeout: 12, brokerExecutableSHA256: broker, brokerCodeSigningCDHash: brokerCD)
        }
        #expect(throws: DocumentAnalysisError.invalidResponse) {
            try DocumentDecoderIdentity(executableSHA256: parser, codeSigningCDHash: parserCD,
                isolation: .appSandboxXPC, timeout: 12, ipcProtocolVersion: DocumentXPCWire.protocolVersion)
        }
        let data = try JSONEncoder().encode(identity())
        var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object.removeValue(forKey: "ipcProtocolVersion")
        let decoded = try JSONDecoder().decode(DocumentDecoderIdentity.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded.ipcProtocolVersion == nil)
        #expect(throws: DocumentAnalysisError.invalidResponse) { try decoded.validateMetadata() }
    }

    @Test func inspectionReadsFreshDevelopmentHelperBytesWithoutLaunchingIt() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let helper = root.appendingPathComponent("synthetic-decoder")
        let executed = root.appendingPathComponent("must-not-exist")
        let quotedCanary = "'" + executed.path.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
        // Invocation would create the canary. Identity inspection must only
        // read this owned synthetic executable, without running its parser.
        try Data("#!/bin/sh\nprintf invoked > \(quotedCanary)\n".utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        let client = DocumentAnalysisClient(developmentHelperURL: helper)
        let first = try await client.currentDecoderIdentity()
        #expect(first.isolation == .requiredDevelopmentSeatbelt && first.brokerExecutableSHA256 == nil
                && first.ipcProtocolVersion == nil)
        #expect(!FileManager.default.fileExists(atPath: executed.path))
        try Data("#!/bin/sh\nprintf changed > \(quotedCanary)\n".utf8).write(to: helper)
        let changed = try await client.currentDecoderIdentity()
        #expect(first.decoderExecutableSHA256 != changed.decoderExecutableSHA256)
        let compatibilityHash = try await client.decoderBinarySHA256()
        #expect(changed.decoderExecutableSHA256 == compatibilityHash)
        #expect(!FileManager.default.fileExists(atPath: executed.path))
    }
}
