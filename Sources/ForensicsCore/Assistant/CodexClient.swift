import CryptoKit
import Darwin
import Foundation

/// Executes one bounded request in a new private workspace. Prompts go to
/// stdin, never argv. This adapter does not read credentials or evidence files.
public struct CodexAnalysisClient: Sendable {
    public let executableURL: URL
    public let timeout: TimeInterval

    public init(executableURL: URL, timeout: TimeInterval = 120) {
        self.executableURL = executableURL
        self.timeout = timeout
    }

    public func analyze(prompt: String) async throws -> CodexAnalysisResult {
        try Task.checkCancellation()
        guard timeout.isFinite, timeout > 0, timeout <= 3_600,
              !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              prompt.utf8.count <= 256 * 1_024, !prompt.utf8.contains(0) else {
            throw CodexAnalysisError.invalidRequest
        }
        let cancellation = CodexCancellation()
        let executable = executableURL
        let deadline = timeout
        do {
            let outcome = try await withTaskCancellationHandler {
                try await BlockingWork.run {
                    try CodexProcessRunner(executableURL: executable, timeout: deadline, cancellation: cancellation).run(prompt: prompt)
                }
            } onCancel: {
                cancellation.cancel()
            }
            try Task.checkCancellation()
            let hash = SHA256.hash(data: Data(prompt.utf8)).map { String(format: "%02x", $0) }.joined()
            return CodexAnalysisResult(response: outcome.response, requestSHA256: hash, completedAt: Date(), startupDiagnosticCount: outcome.startupDiagnosticCount)
        } catch {
            // Cleanup and owned-process reaping complete before the caller can
            // publish another request or tear down its workspace.
            try Task.checkCancellation()
            throw error
        }
    }

    static let responseJSONSchema = #"""
    {"type":"object","additionalProperties":false,"required":["summary","observations","hypotheses","limitations","nextSteps"],"properties":{"summary":{"type":"string","minLength":1,"maxLength":1024},"observations":{"type":"array","maxItems":20,"items":{"type":"string","minLength":1,"maxLength":512}},"hypotheses":{"type":"array","maxItems":20,"items":{"type":"string","minLength":1,"maxLength":512}},"limitations":{"type":"array","maxItems":20,"items":{"type":"string","minLength":1,"maxLength":512}},"nextSteps":{"type":"array","maxItems":20,"items":{"type":"string","minLength":1,"maxLength":512}}}}
    """#

    /// CLI 0.160.1 flags. The named filesystem profile explicitly denies host
    /// and temporary paths; inheriting `:read-only` would expose host reads.
    static func arguments(schemaURL: URL) -> [String] {
        let disabledFeatures = [
            "shell_tool", "unified_exec", "unified_exec_tty", "shell_snapshot", "shell_snapshot_v2",
            "apps", "plugins", "remote_plugin", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
            "computer_use", "code_mode", "code_mode_host", "view_image", "image_generation",
            "multi_agent", "multi_agent_v2", "skill_mcp_dependency_install", "skill_search", "memories",
            "hooks", "workspace_dependencies", "goals", "sleep_tool", "chronicle", "tool_suggest",
            "tool_call_mcp_elicitation", "daemon_auto_start", "auth_elicitation", "request_permissions_tool"
        ]
        let settings = [
            "model_provider=\"openai\"", "forced_login_method=\"chatgpt\"", "approval_policy=\"never\"",
            "web_search=\"disabled\"", "project_doc_max_bytes=0", "skills.include_instructions=false",
            "skills.bundled.enabled=false", "tools.update_plan.enabled=false",
            "tools.experimental_request_user_input.enabled=false", "agents.enabled=false",
            "allow_login_shell=false", "history.persistence=\"none\"", "analytics.enabled=false",
            "suppress_unstable_features_warning=true", "default_permissions=\"nft_assistant\"",
            "permissions.nft_assistant={filesystem={\":root\"=\"deny\",\":minimal\"=\"read\",\":tmpdir\"=\"deny\",\":slash_tmp\"=\"deny\",\":workspace_roots\"=\"read\"},network={enabled=false}}"
        ]
        return ["exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules",
                "--strict-config", "--skip-git-repo-check", "--output-schema", schemaURL.path] +
            disabledFeatures.flatMap { ["--disable", $0] } + ["--enable", "skip_host_skill_discovery"] +
            settings.flatMap { ["-c", $0] } + ["-"]
    }
}

final class CodexCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

/// Only complete JSONL events are accepted. Tool activity fails closed even
/// when a later event contains an apparently valid response.
struct CodexEventStream {
    static let disabledCodeModeNotice = "Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`."
    private(set) var startupDiagnosticCount = 0
    private var pending = Data()
    private var totalBytes = 0
    private var finalMessage: String?
    private var completed = false
    private var started = false

    mutating func receive(_ bytes: Data) throws {
        totalBytes += bytes.count
        guard totalBytes <= 2 * 1_024 * 1_024 else { throw CodexAnalysisError.outputLimit }
        pending.append(bytes)
        while let newline = pending.firstIndex(of: 10) {
            let line = pending.prefix(upTo: newline)
            guard line.count <= 192 * 1_024 else { throw CodexAnalysisError.outputLimit }
            pending.removeSubrange(...newline)
            guard !line.isEmpty else { continue }
            try accept(Data(line))
        }
        guard pending.count <= 192 * 1_024 else { throw CodexAnalysisError.outputLimit }
    }

    private mutating func accept(_ line: Data) throws {
        guard !completed, let event = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let type = event["type"] as? String else { throw CodexAnalysisError.invalidProtocol }
        switch type {
        case "thread.started": break
        case "turn.started":
            guard !started else { throw CodexAnalysisError.invalidProtocol }
            started = true
        case "item.started", "item.updated", "item.completed":
            guard let item = event["item"] as? [String: Any], let itemType = item["type"] as? String else {
                throw CodexAnalysisError.invalidProtocol
            }
            if itemType == "error" {
                // CLI 0.160.1 emits this exact optional-component notice before
                // turn.started when our own flags disable Code Mode Host. It
                // is not a model error or a permissions-profile failure.
                guard !started, type == "item.completed",
                      item["message"] as? String == Self.disabledCodeModeNotice,
                      startupDiagnosticCount < 4 else { throw CodexAnalysisError.providerFailed }
                startupDiagnosticCount += 1
                return
            }
            guard ["agent_message", "reasoning"].contains(itemType) else { throw CodexAnalysisError.toolActivityDetected }
            guard started else { throw CodexAnalysisError.invalidProtocol }
            if type == "item.completed" && itemType == "agent_message" {
                guard let text = item["text"] as? String else { throw CodexAnalysisError.invalidProtocol }
                finalMessage = text
            }
        case "turn.completed":
            guard started, finalMessage != nil else { throw CodexAnalysisError.invalidProtocol }
            completed = true
        case "turn.failed", "error": throw CodexAnalysisError.providerFailed
        default: throw CodexAnalysisError.invalidProtocol
        }
    }

    func finish(exitStatus: Int32) throws -> CodexAnalysisResponse {
        guard exitStatus == 0 else { throw CodexAnalysisError.providerFailed }
        guard pending.isEmpty, completed, let text = finalMessage, let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["summary", "observations", "hypotheses", "limitations", "nextSteps"]),
              let response = try? JSONDecoder().decode(CodexAnalysisResponse.self, from: data) else {
            throw CodexAnalysisError.invalidProtocol
        }
        try response.validate()
        return response
    }
}
