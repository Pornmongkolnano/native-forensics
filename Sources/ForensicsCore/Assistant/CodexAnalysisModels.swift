import Foundation

/// AI interpretations of a caller-approved context. These are not verified
/// forensic findings and must not replace the engine's hashes or provenance.
public struct CodexAnalysisResponse: Codable, Equatable, Sendable {
    public let summary: String
    public let observations: [String]
    public let hypotheses: [String]
    public let limitations: [String]
    public let nextSteps: [String]

    public init(summary: String, observations: [String], hypotheses: [String], limitations: [String], nextSteps: [String]) {
        self.summary = summary
        self.observations = observations
        self.hypotheses = hypotheses
        self.limitations = limitations
        self.nextSteps = nextSteps
    }

    func validate() throws {
        func valid(_ text: String, limit: Int) -> Bool {
            !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                text.utf8.count <= limit && !text.unicodeScalars.contains(where: {
                    CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\t"
                })
        }
        guard valid(summary, limit: 4_096),
              [observations, hypotheses, limitations, nextSteps].allSatisfy({
                  $0.count <= 20 && $0.allSatisfy({ valid($0, limit: 2_048) })
              }) else { throw CodexAnalysisError.invalidProtocol }
    }
}

/// Request binding is calculated locally. The model cannot choose the request
/// hash, completion time or execution description supplied to the UI.
public struct CodexAnalysisResult: Codable, Equatable, Sendable {
    public let response: CodexAnalysisResponse
    public let requestSHA256: String
    public let completedAt: Date
    public let provider: String
    public let executionMode: String
    public let startupDiagnosticCount: Int

    public init(response: CodexAnalysisResponse, requestSHA256: String, completedAt: Date, startupDiagnosticCount: Int = 0) {
        self.response = response
        self.requestSHA256 = requestSHA256
        self.completedAt = completedAt
        self.provider = "Codex CLI"
        self.executionMode = "Reviewed context; restricted filesystem permissions"
        self.startupDiagnosticCount = startupDiagnosticCount
    }
}

/// Provider diagnostics may contain credentials, paths or request contents.
/// Only these fixed messages cross the adapter's error boundary.
public enum CodexAnalysisError: Error, LocalizedError, Equatable, Sendable {
    case invalidRequest
    case unavailable
    case launchFailed
    case timeout
    case outputLimit
    case invalidProtocol
    case providerFailed
    case toolActivityDetected

    public var errorDescription: String? {
        switch self {
        case .invalidRequest: "The analysis request or deadline is invalid."
        case .unavailable: "Choose an installed, executable Codex CLI."
        case .launchFailed: "Codex could not start in its isolated workspace."
        case .timeout: "Codex did not complete before the analysis deadline."
        case .outputLimit: "Codex returned more output than this analysis permits."
        case .invalidProtocol: "Codex did not return a complete, valid structured analysis."
        case .providerFailed: "Codex could not complete this request. Check its sign-in and service availability separately."
        case .toolActivityDetected: "Codex attempted a tool action; this analysis was stopped and its output was discarded."
        }
    }
}
