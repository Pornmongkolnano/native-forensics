import Darwin
import Foundation
import NFDecoderIPC
import Security

/// Both the host and broker verify the fixed inherited worker before launching
/// or accepting its identity. It has no independently expanded file/network grant.
struct DocumentWorkerExecutableConfiguration: @unchecked Sendable {
    static let identifier = "org.nativeforensics.NFDocumentDecoderWorker"
    let executableURL: URL
    let executableReceipt: DocumentDecoderExecutableReceipt
    let requirement: SecRequirement
    let codeSigningCDHash: Data

    static func load(at url: URL, cancellation: DocumentCancellation) throws -> Self {
        let resolved = url.standardizedFileURL
        var metadata = stat()
        guard resolved.isFileURL, resolved.lastPathComponent == "NFDocumentDecoderWorker",
              Darwin.lstat(resolved.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              Darwin.access(resolved.path, X_OK) == 0 else { throw DocumentAnalysisError.unavailable }
        var code: SecStaticCode?
        let flags = SecCSFlags(rawValue: 0)
        guard SecStaticCodeCreateWithPath(resolved as CFURL, flags, &code) == errSecSuccess,
              let code, SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        let info = try signingInformation(code)
        try validateEntitlements(info)
        guard info[kSecCodeInfoIdentifier as String] as? String == identifier,
              let cdhash = info[kSecCodeInfoUnique as String] as? Data, [20, 32].contains(cdhash.count) else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        var requirement: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(code, flags, &requirement) == errSecSuccess,
              let requirement else { throw DocumentAnalysisError.sandboxUnavailable }
        let receipt = try DocumentDecoderExecutableReceipt.inspect(resolved, cancellation: cancellation)
        return Self(executableURL: resolved.resolvingSymlinksInPath(), executableReceipt: receipt,
                    requirement: requirement, codeSigningCDHash: cdhash)
    }

    func verifyLive(_ hello: DocumentWorkerHello, nonce: String) throws {
        guard hello.protocolVersion == DocumentXPCWire.protocolVersion, hello.nonce == nonce,
              hello.processIdentifier > 0, NFDecoderAuditTokenPID(hello.auditToken) == hello.processIdentifier,
              NFDecoderAuditTokenUID(hello.auditToken) == Darwin.geteuid() else { throw DocumentAnalysisError.invalidResponse }
        var code: SecCode?
        let flags = SecCSFlags(rawValue: 0)
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: hello.auditToken] as CFDictionary,
                                            flags, &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, flags, requirement) == errSecSuccess else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        let info = try Self.signingInformation(unsafeBitCast(code, to: SecStaticCode.self))
        try Self.validateEntitlements(info)
        guard info[kSecCodeInfoIdentifier as String] as? String == Self.identifier,
              let path = info[kSecCodeInfoMainExecutable as String] as? URL,
              path.resolvingSymlinksInPath() == executableURL,
              info[kSecCodeInfoUnique as String] as? Data == codeSigningCDHash else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
    }

    static func validateEntitlements(_ info: [String: Any]) throws {
        guard let values = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any], values.count == 2 else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        for key in ["com.apple.security.app-sandbox", "com.apple.security.inherit"] {
            guard let boolean = values[key] as? NSNumber,
                  CFGetTypeID(boolean) == CFBooleanGetTypeID(), boolean.boolValue else {
                throw DocumentAnalysisError.sandboxUnavailable
            }
        }
    }

    private static func signingInformation(_ code: SecStaticCode) throws -> [String: Any] {
        var dictionary: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &dictionary) == errSecSuccess,
              let values = dictionary as? [String: Any] else { throw DocumentAnalysisError.sandboxUnavailable }
        return values
    }
}
