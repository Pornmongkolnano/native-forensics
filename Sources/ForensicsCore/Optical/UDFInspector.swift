import Foundation

public enum UDFInspector {
    public static func inspect(evidence: EvidenceRecord, in forensicCase: ForensicCase,
                               options: UDFInspectionOptions = .init(),
                               progress: @escaping @Sendable (UDFInspectionProgress) -> Void = { _ in }) async throws -> UDFInspectionResult {
        try Task.checkCancellation()
        try options.validate()
        guard forensicCase.manifest.evidence.contains(evidence) else {
            throw UDFError.invalidResult("The evidence receipt is not part of this case.")
        }
        let requestedPriority = ForensicWorkExecutionContext.requestedPriority
        let worker = Task.detached(priority: (requestedPriority ?? .userInitiated).taskPriority) {
            try ForensicWorkExecutionContext.$requestedPriority.withValue(requestedPriority) {
            let source = try UDFPinnedSource(evidence: evidence, maximumSourceBytes: options.maximumSourceBytes)
            let deadline = ProcessInfo.processInfo.systemUptime + options.timeoutSeconds
            let hashProgress: @Sendable (Int64) throws -> Void = { amount in
                guard ProcessInfo.processInfo.systemUptime <= deadline else { throw UDFError.timeout }
                progress(.init(stage: "Verifying original evidence", completedBytes: amount, totalBytes: evidence.byteCount))
            }
            try source.verifyHash(progress: hashProgress)
            let parser = UDFParser(source: source, options: options, progress: progress)
            let result = try parser.parse(caseID: forensicCase.manifest.id)
            try Task.checkCancellation()
            return try UDFResultStore.save(result, in: forensicCase, prePublicationValidation: {
                try Task.checkCancellation()
                try source.verifyHash(progress: hashProgress)
            })
            }
        }
        return try await withTaskCancellationHandler {
            // save's latest-pointer rename is the commit boundary. A late
            // cancellation must not hide an already published generation.
            try await worker.value
        } onCancel: { worker.cancel() }
    }

    public static func loadLatest(in forensicCase: ForensicCase, evidenceID: UUID) throws -> UDFInspectionResult? {
        try UDFResultStore.loadLatest(in: forensicCase, evidenceID: evidenceID)
    }

    public static func export(entryID: String, from result: UDFInspectionResult,
                              in forensicCase: ForensicCase, to destination: URL) async throws -> UDFExportReceipt {
        try await UDFResultStore.export(entryID: entryID, from: result, in: forensicCase, to: destination)
    }

    // A fault hook tests source replacement without introducing sleeps or relying
    // on a race. It cannot publish a result and never changes evidence itself.
    static func parseForTesting(evidence: EvidenceRecord, caseID: UUID,
                               options: UDFInspectionOptions = .init(),
                               afterParse: () throws -> Void = {}) throws -> UDFInspectionResult {
        let source = try UDFPinnedSource(evidence: evidence, maximumSourceBytes: options.maximumSourceBytes)
        try source.verifyHash()
        let result = try UDFParser(source: source, options: options, progress: { _ in }).parse(caseID: caseID)
        try afterParse()
        try source.verifyHash()
        return result
    }
}
