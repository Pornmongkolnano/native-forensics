import Darwin
import Foundation
import ForensicsCore
import NFDocumentDecoding

@main
enum DecoderMain {
    static func main() {
        resourceLimits()
        do {
            let input = try readInput()
            let source = try VerifiedDocumentFile(input: input)
            let analysis = DocumentDecoder.decode(source.snapshot)
            try source.checkUnchanged()
            let response = try DocumentResponseEncoder.encode(analysis)
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
