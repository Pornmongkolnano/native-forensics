import CryptoKit
import Darwin
import Foundation

/// ImageIO/PDFKit run only in the bundled helper, never in the desktop process.
/// Cancellation and timeout terminate and reap the request's own process group.
public struct DocumentAnalysisClient: Sendable {
    public let helperURL: URL
    public let timeout: TimeInterval

    public init(helperURL: URL, timeout: TimeInterval = DocumentLimits.timeout) {
        self.helperURL = helperURL; self.timeout = timeout
    }

    public func analyze(_ input: DocumentInput) async throws -> DocumentAnalysis {
        try await analyze(input, started: nil)
    }

    /// Internal ownership notification lets safety tests synchronize with an
    /// actually spawned request, rather than guessing from executor timing.
    func analyze(_ input: DocumentInput, started: (@Sendable (Int32) -> Void)?) async throws -> DocumentAnalysis {
        try Task.checkCancellation()
        guard timeout.isFinite, timeout > 0, timeout <= 120 else { throw DocumentAnalysisError.invalidInput }
        let cancellation = DocumentCancellation()
        let normalized = DocumentInput(fileURL: input.fileURL.standardizedFileURL,
            expectedSHA256: input.expectedSHA256.lowercased(), expectedByteCount: input.expectedByteCount)
        do {
            let result = try await withTaskCancellationHandler {
                try await BlockingWork.run {
                    try DocumentProcessRunner(helperURL: helperURL, timeout: timeout,
                        cancellation: cancellation, started: started).run(normalized)
                }
            } onCancel: {
                cancellation.cancel()
            }
            try Task.checkCancellation()
            return result
        } catch {
            // Owned process cleanup has finished. A cancelled caller remains
            // cancelled when a timeout or bad response races its resumption.
            try Task.checkCancellation()
            throw error
        }
    }

    static func validate(_ analysis: DocumentAnalysis, for input: DocumentInput) throws {
        guard analysis.schemaVersion == 1, analysis.sourceSHA256 == input.expectedSHA256.lowercased(),
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
        }
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
