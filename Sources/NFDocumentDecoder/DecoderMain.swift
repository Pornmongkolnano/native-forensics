import Darwin
import Foundation
import ForensicsCore

@main
enum DecoderMain {
    static func main() {
        resourceLimits()
        do {
            let input = try readInput()
            let source = try VerifiedDocument(input: input)
            let analysis = DocumentDecoder.decode(source)
            try source.checkUnchanged()
            let response = try boundedResponse(analysis)
            try FileHandle.standardOutput.write(contentsOf: response)
            try FileHandle.standardOutput.write(contentsOf: Data([0x0A]))
        } catch {
            let code: String
            switch error as? DocumentAnalysisError {
            case .integrityMismatch: code = "INTEGRITY_MISMATCH"
            case .sourceChanged: code = "SOURCE_CHANGED"
            case .outputLimit: code = "OUTPUT_LIMIT"
            default: code = "INVALID_INPUT"
            }
            try? FileHandle.standardError.write(contentsOf: Data(("NF_DOCUMENT_DECODER_" + code + "\n").utf8))
            Darwin.exit(1)
        }
    }

    private static func readInput() throws -> DocumentInput {
        var data = Data()
        while true {
            guard let chunk = try FileHandle.standardInput.read(upToCount: min(4_096, 16_385 - data.count)), !chunk.isEmpty else { break }
            data.append(chunk)
            guard data.count <= 16_384 else { throw DocumentAnalysisError.invalidInput }
        }
        guard !data.isEmpty else { throw DocumentAnalysisError.invalidInput }
        do { return try JSONDecoder().decode(DocumentInput.self, from: data) }
        catch { throw DocumentAnalysisError.invalidInput }
    }

    private static func boundedResponse(_ analysis: DocumentAnalysis) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var current = analysis
        var encoded = try encoder.encode(current)
        if encoded.count + 1 > DocumentLimits.maximumResponseBytes, current.thumbnailPNG != nil {
            current = copy(current, thumbnail: nil, pages: current.textPages,
                           warnings: current.warnings + ["Thumbnail omitted to preserve the bounded document response."])
            encoded = try encoder.encode(current)
        }
        var budget = current.textPages.reduce(0) { $0 + $1.text.utf8.count }
        for _ in 0..<8 where encoded.count + 1 > DocumentLimits.maximumResponseBytes {
            budget /= 2
            var remaining = budget
            let pages = current.textPages.map { page in
                let limited = DocumentDecoder.limitedUTF8(page.text, maximumBytes: remaining)
                remaining -= limited.value.utf8.count
                return DocumentTextPage(pageNumber: page.pageNumber, text: limited.value,
                                        isTruncated: page.isTruncated || limited.truncated,
                                        referenceLabel: page.referenceLabel, referenceKind: page.referenceKind)
            }
            let warning = "Extracted text was shortened to preserve the bounded JSON response."
            current = copy(current, thumbnail: current.thumbnailPNG, pages: pages,
                           warnings: current.warnings.contains(warning) ? current.warnings : current.warnings + [warning])
            encoded = try encoder.encode(current)
        }
        guard encoded.count + 1 <= DocumentLimits.maximumResponseBytes else { throw DocumentAnalysisError.outputLimit }
        return encoded
    }

    private static func copy(_ analysis: DocumentAnalysis, thumbnail: Data?, pages: [DocumentTextPage], warnings: [String]) -> DocumentAnalysis {
        DocumentAnalysis(contentKind: analysis.contentKind, mimeType: analysis.mimeType, status: analysis.status,
                         sourceSHA256: analysis.sourceSHA256, sourceByteCount: analysis.sourceByteCount,
                         title: analysis.title, pixelWidth: analysis.pixelWidth, pixelHeight: analysis.pixelHeight,
                         pageCount: analysis.pageCount, officeFormat: analysis.officeFormat,
                         contentUnitCount: analysis.contentUnitCount, structuralValidation: analysis.structuralValidation,
                         textPages: pages, thumbnailPNG: thumbnail,
                         rawMetadata: analysis.rawMetadata, warnings: warnings, failureCode: analysis.failureCode)
    }

    /// Wall-clock timeout and process-group cleanup belong to the parent. These
    /// are additional best-effort limits. The parent applies the required
    /// read-only/no-network sandbox before this executable starts; invoking
    /// this CLI directly does not apply that parent-owned policy.
    private static func resourceLimits() {
        var core = rlimit(rlim_cur: 0, rlim_max: 0)
        _ = Darwin.setrlimit(RLIMIT_CORE, &core)
        var cpu = rlimit(rlim_cur: 12, rlim_max: 13)
        _ = Darwin.setrlimit(RLIMIT_CPU, &cpu)
        var descriptors = rlimit(rlim_cur: 128, rlim_max: 128)
        _ = Darwin.setrlimit(RLIMIT_NOFILE, &descriptors)
    }
}
