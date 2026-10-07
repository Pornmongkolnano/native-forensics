import Foundation

public enum UDFReportBuilder {
    public static func renderMarkdown(result: UDFInspectionResult,
                                       analyses: [String: DocumentAnalysis] = [:]) -> String {
        do {
            try validate(result: result, analyses: analyses)
            return UDFReportRendering.render(result: result, analyses: analyses)
        } catch {
            return "# UDF report unavailable\n\nThe UDF receipt or decoder provenance failed validation. No findings were rendered.\n"
        }
    }

    @discardableResult
    public static func exportMarkdown(result: UDFInspectionResult,
        analyses: [String: DocumentAnalysis] = [:], in forensicCase: ForensicCase, to outputURL: URL) throws -> URL {
        try export(result: result, analyses: analyses, in: forensicCase, to: outputURL)
    }

    static func exportForTesting(result: UDFInspectionResult, analyses: [String: DocumentAnalysis] = [:],
        in forensicCase: ForensicCase, to outputURL: URL, beforePublication: () throws -> Void = {},
        afterPublication: () -> Void = {}) throws -> URL {
        try export(result: result, analyses: analyses, in: forensicCase, to: outputURL,
                   beforePublication: beforePublication, afterPublication: afterPublication)
    }

    private static func export(result: UDFInspectionResult, analyses: [String: DocumentAnalysis],
        in forensicCase: ForensicCase, to outputURL: URL, beforePublication: () throws -> Void = {},
        afterPublication: () -> Void = {}) throws -> URL {
        try Task.checkCancellation()
        try validate(result: result, analyses: analyses)
        guard forensicCase.manifest.id == result.caseID,
              let evidence = forensicCase.manifest.evidence.first(where: { $0.id == result.sourceEvidenceID }),
              evidence.container == .raw, evidence.hashScope == FileHashScope.selectedFileBytes,
              evidence.sha256 == result.sourceSHA256, evidence.byteCount == result.sourceByteCount else {
            throw RecoveryError.scopeMismatch
        }
        let binding = {
            guard try UDFResultStore.loadLatest(in: forensicCase, evidenceID: result.sourceEvidenceID) == result else {
                throw UDFError.invalidResult("The report selection is not the latest persisted UDF job in this case.")
            }
        }
        try binding()
        let bytes = Data(UDFReportRendering.render(result: result, analyses: analyses).utf8)
        return try ReportPublication.publish(bytes, in: forensicCase, to: outputURL,
            validateBinding: binding, beforePublication: beforePublication, afterPublication: afterPublication)
    }

    private static func validate(result: UDFInspectionResult, analyses: [String: DocumentAnalysis]) throws {
        try UDFResultStore.validateResult(result)
        let entries = Dictionary(uniqueKeysWithValues: result.entries.map { ($0.id, $0) })
        for (id, analysis) in analyses {
            guard let entry = entries[id] else { throw RecoveryError.scopeMismatch }
            try DocumentAnalysisClient.validate(analysis, for: DocumentInput(fileURL: URL(fileURLWithPath: "/"),
                expectedSHA256: entry.sha256, expectedByteCount: entry.byteCount))
        }
    }
}
