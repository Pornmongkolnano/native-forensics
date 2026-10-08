import CryptoKit
import Darwin
import Foundation

/// ImageIO/PDFKit run in an isolated helper. Bundled applications always use
/// the entitlement-sandboxed XPC broker and fresh parser worker, with no fallback on failure.
/// Non-bundled tools may explicitly use the required Seatbelt development mode.
public struct DocumentAnalysisClient: Sendable {
    public let helperURL: URL
    public let timeout: TimeInterval
    let sandboxPolicy: DocumentSandboxPolicy
    private let backend: DocumentDecoderBackend

    public init(timeout: TimeInterval = DocumentLimits.timeout) {
        self.helperURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoder")
        self.timeout = timeout; self.sandboxPolicy = .required; self.backend = .appSandboxXPC
    }

    /// Existing application callers are routed to XPC solely by the containing
    /// app bundle. A missing/broken service never selects the development helper.
    public init(helperURL: URL, timeout: TimeInterval = DocumentLimits.timeout) {
        self.helperURL = helperURL; self.timeout = timeout; self.sandboxPolicy = .required
        self.backend = Bundle.main.bundleURL.pathExtension == "app" ? .appSandboxXPC : .developmentSeatbelt
    }

    /// Explicit CLI/SwiftPM development mode. This still requires Seatbelt and
    /// cannot be selected inside a bundled application.
    public init(developmentHelperURL: URL, timeout: TimeInterval = DocumentLimits.timeout) {
        self.helperURL = developmentHelperURL; self.timeout = timeout; self.sandboxPolicy = .required
        self.backend = Bundle.main.bundleURL.pathExtension == "app" ? .appSandboxXPC : .developmentSeatbelt
    }

    /// Only @testable fixture code can run fake helpers without the policy.
    init(helperURL: URL, timeout: TimeInterval = DocumentLimits.timeout, sandboxPolicy: DocumentSandboxPolicy) {
        self.helperURL = helperURL; self.timeout = timeout; self.sandboxPolicy = sandboxPolicy
        self.backend = .developmentSeatbelt
    }

    public var isAvailable: Bool {
        backend == .appSandboxXPC ? DocumentXPCServiceConfiguration.isPresent
            : FileManager.default.isExecutableFile(atPath: helperURL.path)
    }

    /// Fingerprints the executable that this backend actually uses. A bundled
    /// app never reports the development CLI hash as its XPC decoder identity.
    public func decoderBinarySHA256() async throws -> String {
        try await currentDecoderIdentity().decoderExecutableSHA256
    }

    /// Inspects actual current parser/broker bytes, signed identities and fixed
    /// policy without launching a parser or connecting to an XPC service.
    public func currentDecoderIdentity() async throws -> DocumentDecoderIdentity {
        try Task.checkCancellation()
        guard timeout.isFinite, timeout > 0, timeout <= 120 else { throw DocumentAnalysisError.invalidInput }
        let cancellation = DocumentCancellation()
        let result = try await withTaskCancellationHandler {
            try await BlockingWork.run {
                switch backend {
                case .appSandboxXPC:
                    let configuration = try DocumentXPCServiceConfiguration.load(cancellation: cancellation)
                    let identity = try DocumentDecoderIdentity(executableSHA256: configuration.worker.executableReceipt.sha256,
                        codeSigningCDHash: CaseWorkCoding.hex(configuration.worker.codeSigningCDHash),
                        isolation: .appSandboxXPC, timeout: timeout,
                        brokerExecutableSHA256: configuration.executableReceipt.sha256,
                        brokerCodeSigningCDHash: CaseWorkCoding.hex(configuration.codeSigningCDHash),
                        ipcProtocolVersion: DocumentXPCWire.protocolVersion)
                    // Re-read signed metadata as well as bytes. A signature
                    // change between the first Security inspection and its
                    // file hash must not produce a mixed identity snapshot.
                    let refreshed = try DocumentXPCServiceConfiguration.load(cancellation: cancellation)
                    let refreshedIdentity = try DocumentDecoderIdentity(executableSHA256: refreshed.worker.executableReceipt.sha256,
                        codeSigningCDHash: CaseWorkCoding.hex(refreshed.worker.codeSigningCDHash),
                        isolation: .appSandboxXPC, timeout: timeout,
                        brokerExecutableSHA256: refreshed.executableReceipt.sha256,
                        brokerCodeSigningCDHash: CaseWorkCoding.hex(refreshed.codeSigningCDHash),
                        ipcProtocolVersion: DocumentXPCWire.protocolVersion)
                    try configuration.worker.executableReceipt.verify(cancellation: cancellation)
                    try configuration.executableReceipt.verify(cancellation: cancellation)
                    guard identity == refreshedIdentity else { throw DocumentAnalysisError.sourceChanged }
                    return identity
                case .developmentSeatbelt:
                    guard FileManager.default.isExecutableFile(atPath: helperURL.path) else { throw DocumentAnalysisError.unavailable }
                    let receipt = try DocumentDecoderExecutableReceipt.inspect(helperURL.standardizedFileURL, cancellation: cancellation)
                    let identity = try DocumentDecoderIdentity(executableSHA256: receipt.sha256,
                        isolation: sandboxPolicy == .required ? .requiredDevelopmentSeatbelt : .testFixture, timeout: timeout)
                    try receipt.verify(cancellation: cancellation)
                    return identity
                }
            }
        } onCancel: { cancellation.cancel() }
        try Task.checkCancellation()
        return result
    }

    public func analyze(_ input: DocumentInput) async throws -> DocumentAnalysis {
        try await analyze(input, started: nil, lifecycle: nil)
    }

    /// Local diagnostics expose only owned-process lifecycle, without evidence
    /// paths or content. Exited means work stopped; launchd owns XPC reaping.
    public func analyze(_ input: DocumentInput,
                        lifecycle: @escaping @Sendable (DocumentDecoderLifecycleEvent) -> Void) async throws -> DocumentAnalysis {
        try await analyze(input, started: nil, lifecycle: lifecycle)
    }

    func analyze(_ input: DocumentInput, started: (@Sendable (Int32) -> Void)?) async throws -> DocumentAnalysis {
        try await analyze(input, started: started, lifecycle: nil)
    }

    private func analyze(_ input: DocumentInput, started: (@Sendable (Int32) -> Void)?,
                         lifecycle: (@Sendable (DocumentDecoderLifecycleEvent) -> Void)?) async throws -> DocumentAnalysis {
        try Task.checkCancellation()
        guard timeout.isFinite, timeout > 0, timeout <= 120 else { throw DocumentAnalysisError.invalidInput }
        let cancellation = DocumentCancellation()
        let normalized = DocumentInput(fileURL: input.fileURL.standardizedFileURL,
            expectedSHA256: input.expectedSHA256.lowercased(), expectedByteCount: input.expectedByteCount)
        do {
            let result = try await withTaskCancellationHandler {
                try await BlockingWork.run {
                    switch backend {
                    case .appSandboxXPC:
                        return try DocumentXPCTransport(timeout: timeout, cancellation: cancellation,
                            started: started, lifecycle: lifecycle).run(normalized)
                    case .developmentSeatbelt:
                        return try DocumentProcessRunner(helperURL: helperURL, timeout: timeout,
                            cancellation: cancellation, started: started, sandboxPolicy: sandboxPolicy).run(normalized)
                    }
                }
            } onCancel: { cancellation.cancel() }
            try Task.checkCancellation()
            return result
        } catch {
            // Cleanup is complete (or explicitly failed closed) before any
            // cancellation/result is delivered back to the application.
            try Task.checkCancellation()
            throw error
        }
    }

    static func validate(_ analysis: DocumentAnalysis, for input: DocumentInput) throws {
        guard ((analysis.schemaVersion == 1 && analysis.provenance == nil)
               || (analysis.schemaVersion == 2 && analysis.provenance != nil)),
              analysis.sourceSHA256 == input.expectedSHA256.lowercased(),
              analysis.sourceByteCount == input.expectedByteCount,
              analysis.mimeType.utf8.count <= 128, !analysis.mimeType.isEmpty,
              (analysis.title?.utf8.count ?? 0) <= DocumentLimits.maximumMetadataValueBytes,
              analysis.textPages.count <= DocumentLimits.maximumPages,
              analysis.textPages.allSatisfy({ ($0.referenceLabel?.utf8.count ?? 0) <= 4_096 }),
              analysis.textPages.reduce(0, { $0 + $1.text.utf8.count }) <= DocumentLimits.maximumTextBytes,
              analysis.rawMetadata.count <= DocumentLimits.maximumMetadataItems,
              analysis.rawMetadata.allSatisfy({ !$0.name.isEmpty && $0.name.utf8.count <= 128
                  && $0.value.utf8.count <= DocumentLimits.maximumMetadataValueBytes }),
              analysis.warnings.count <= 32, analysis.warnings.allSatisfy({ $0.utf8.count <= 4_096 }),
              (analysis.failureCode?.utf8.count ?? 0) <= 128 else { throw DocumentAnalysisError.invalidResponse }
        let pageNumbers = analysis.textPages.map(\.pageNumber)
        guard pageNumbers == pageNumbers.sorted(), Set(pageNumbers).count == pageNumbers.count,
              pageNumbers.allSatisfy({ $0 > 0 && $0 <= (analysis.contentUnitCount ?? analysis.pageCount ?? 1) }),
              analysis.pageCount.map({ $0 > 0 && $0 <= 1_000_000 }) ?? true,
              analysis.contentUnitCount.map({ $0 > 0 && $0 <= 1_000_000 }) ?? true else {
            throw DocumentAnalysisError.invalidResponse
        }
        if let png = analysis.thumbnailPNG {
            let bytes = [UInt8](png.prefix(33))
            guard png.count <= DocumentLimits.maximumThumbnailBytes, bytes.count == 33,
                  Array(bytes[0..<8]) == [137,80,78,71,13,10,26,10],
                  Array(bytes[8..<16]) == [0,0,0,13,73,72,68,82] else { throw DocumentAnalysisError.invalidResponse }
            func integer(_ offset: Int) -> UInt32 {
                bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | UInt32($1) }
            }
            guard (1...1_024).contains(integer(16)), (1...1_024).contains(integer(20)) else {
                throw DocumentAnalysisError.invalidResponse
            }
            guard case .complete = DocumentPNGStructureValidator.validate(png) else {
                throw DocumentAnalysisError.invalidResponse
            }
        }
        if let provenance = analysis.provenance { try provenance.validate(pages: analysis.textPages) }
        switch analysis.status {
        case .decoded:
            guard analysis.failureCode == nil, [.image, .pdf, .text, .office, .archive].contains(analysis.contentKind) else {
                throw DocumentAnalysisError.invalidResponse
            }
            if analysis.contentKind == .image {
                guard let width = analysis.pixelWidth, let height = analysis.pixelHeight,
                      width > 0, height > 0, Int64(width) <= DocumentLimits.maximumImagePixels,
                      Int64(height) <= DocumentLimits.maximumImagePixels,
                      Int64(width) * Int64(height) <= DocumentLimits.maximumImagePixels,
                      analysis.textPages.isEmpty else { throw DocumentAnalysisError.invalidResponse }
            }
            if analysis.contentKind == .pdf && analysis.pageCount == nil { throw DocumentAnalysisError.invalidResponse }
            if analysis.contentKind == .text && analysis.textPages.count != 1 { throw DocumentAnalysisError.invalidResponse }
            if analysis.contentKind == .office {
                guard let format = analysis.officeFormat, [.docx, .pptx, .xlsx].contains(format),
                      analysis.contentUnitCount != nil, analysis.structuralValidation == .validated,
                      analysis.textPages.allSatisfy({ $0.referenceKind != nil && $0.referenceLabel != nil }) else {
                    throw DocumentAnalysisError.invalidResponse
                }
            }
            if analysis.contentKind == .archive {
                guard analysis.contentUnitCount != nil, analysis.structuralValidation == .validated,
                      !analysis.textPages.isEmpty, analysis.textPages.count <= DocumentLimits.maximumArchiveMembers,
                      analysis.textPages.allSatisfy({ $0.referenceKind == .archiveMember && $0.referenceLabel != nil }) else {
                    throw DocumentAnalysisError.invalidResponse
                }
            }
        case .failed, .unsupported:
            guard analysis.thumbnailPNG == nil, analysis.textPages.isEmpty else { throw DocumentAnalysisError.invalidResponse }
            if analysis.status == .failed && analysis.failureCode == nil { throw DocumentAnalysisError.invalidResponse }
        }
    }
}

final class DocumentCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isCancelled: Bool { lock.withLock { value } }
    func cancel() { lock.withLock { value = true } }
}

struct DocumentSourceHandle {
    let descriptor: Int32
    let identity: SourceIdentity
    let url: URL

    static func open(_ input: DocumentInput, cancellation: DocumentCancellation) throws -> DocumentSourceHandle {
        let url = input.fileURL.standardizedFileURL
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              !url.path.isEmpty, !url.path.utf8.contains(0), url.path.utf8.count <= 8_192,
              input.expectedByteCount >= 0, input.expectedByteCount <= DocumentLimits.maximumInputBytes,
              EngineValidation.validHash(input.expectedSHA256.lowercased()) else { throw DocumentAnalysisError.invalidInput }
        let fd: Int32
        do { fd = try FileAccess.openReadOnly(url) } catch { throw DocumentAnalysisError.invalidInput }
        do {
            let identity = try FileAccess.identity(of: fd)
            guard identity.size == input.expectedByteCount else { throw DocumentAnalysisError.integrityMismatch }
            let source = DocumentSourceHandle(descriptor: fd, identity: identity, url: url)
            try source.verify(input, cancellation: cancellation)
            return source
        } catch { Darwin.close(fd); throw error }
    }

    func snapshot(_ input: DocumentInput, cancellation: DocumentCancellation) throws -> Data {
        guard (try? FileAccess.identity(of: descriptor)) == identity,
              (try? FileAccess.identity(at: url)) == identity else { throw DocumentAnalysisError.sourceChanged }
        var data = Data()
        data.reserveCapacity(Int(input.expectedByteCount))
        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 128 * 1_024)
        var offset: Int64 = 0
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            let count = buffer.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress, $0.count, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw DocumentAnalysisError.sourceChanged }
            if count == 0 { break }
            offset += Int64(count)
            guard offset <= input.expectedByteCount, offset <= DocumentLimits.maximumInputBytes else {
                throw DocumentAnalysisError.sourceChanged
            }
            let chunk = Data(buffer.prefix(count))
            data.append(chunk); hasher.update(data: chunk)
        }
        guard offset == input.expectedByteCount,
              hasher.finalize().map({ String(format: "%02x", $0) }).joined() == input.expectedSHA256,
              (try? FileAccess.identity(of: descriptor)) == identity,
              (try? FileAccess.identity(at: url)) == identity else { throw DocumentAnalysisError.sourceChanged }
        return data
    }

    func verify(_ input: DocumentInput, cancellation: DocumentCancellation) throws {
        guard (try? FileAccess.identity(of: descriptor)) == identity,
              (try? FileAccess.identity(at: url)) == identity, Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else {
            throw DocumentAnalysisError.sourceChanged
        }
        var hasher = SHA256(), bytes: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 128 * 1_024)
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            let count = try buffer.withUnsafeMutableBytes { try FileAccess.read(descriptor, into: $0, count: $0.count) }
            guard count > 0 else { break }
            bytes += Int64(count)
            guard bytes <= input.expectedByteCount else { throw DocumentAnalysisError.sourceChanged }
            hasher.update(data: Data(buffer.prefix(count)))
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        guard bytes == input.expectedByteCount, digest == input.expectedSHA256.lowercased() else {
            throw DocumentAnalysisError.integrityMismatch
        }
        guard (try? FileAccess.identity(of: descriptor)) == identity,
              (try? FileAccess.identity(at: url)) == identity else { throw DocumentAnalysisError.sourceChanged }
    }
}
