import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Codex analysis adapter")
struct CodexClientTests {
    @Test("Spawn cannot inherit an unrelated parent pipe without FD_CLOEXEC")
    func unrelatedDescriptorIsNotInherited() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        var pipe: [Int32] = [-1, -1]
        try #require(Darwin.pipe(&pipe) == 0)
        defer { for descriptor in pipe { Darwin.close(descriptor) } }
        // Use a high descriptor to avoid an interpreter reusing the same
        // numeric slot while starting. The canary is explicitly inheritable.
        let canary = fcntl(pipe[1], F_DUPFD, 128)
        try #require(canary >= 0)
        defer { Darwin.close(canary) }
        try #require(fcntl(canary, F_SETFD, 0) == 0)
        #expect(fcntl(canary, F_GETFD) == 0)
        var identity = stat()
        try #require(Darwin.fstat(canary, &identity) == 0)
        let record = fixture.root.appendingPathComponent("descriptor-state.json")
        let helper = try fixture.helper(body: """
        import errno
        try:
            metadata = os.fstat(\(canary))
            state = dict(open=True, device=metadata.st_dev, inode=metadata.st_ino)
        except OSError as error:
            state = dict(open=False, closed=(error.errno == errno.EBADF))
        with open(\(CodexMockFixture.literal(record.path)), 'x') as output:
            json.dump(state, output)
        success()
        """)
        let result = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic descriptor isolation probe")
        #expect(result.response.summary == "Synthetic observation.")
        let state = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any])
        #expect(state["open"] as? Bool == false)
        #expect(state["closed"] as? Bool == true)
        // The parent's descriptor remains valid and belongs to the same pipe;
        // only the spawned child loses access to it.
        var after = stat()
        #expect(Darwin.fstat(canary, &after) == 0)
        #expect(after.st_dev == identity.st_dev && after.st_ino == identity.st_ino)
    }

    @Test("Only stdin contains the approved prompt; workspace is private and cleaned")
    func isolatedSuccess() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let record = fixture.root.appendingPathComponent("launch.json")
        let helper = try fixture.helper(body: """
        with open(\(CodexMockFixture.literal(record.path)), 'x') as output:
            json.dump(dict(prompt=prompt, argv=sys.argv[1:], cwd=os.getcwd(),
                mode=os.stat(os.getcwd()).st_mode & 0o777, entries=os.listdir('.'),
                pid=os.getpid(), group=os.getpgrp()), output)
        success()
        """)
        let prompt = "Synthetic context only: αβ secret-request-token"
        let result = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: prompt)
        #expect(result.response.summary == "Synthetic observation.")
        #expect(result.requestSHA256 == SHA256.hash(data: Data(prompt.utf8)).map { String(format: "%02x", $0) }.joined())
        #expect(result.provider == "Codex CLI")
        let json = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any])
        #expect(json["prompt"] as? String == prompt)
        let arguments = try #require(json["argv"] as? [String])
        #expect(!arguments.contains(where: { $0.contains("secret-request-token") }))
        #expect(arguments.last == "-")
        #expect(arguments.contains("--ignore-user-config"))
        #expect(arguments.contains("--ignore-rules"))
        #expect(arguments.contains("--ephemeral"))
        #expect(arguments.contains("--strict-config"))
        #expect(arguments.contains("model_provider=\"openai\""))
        #expect(arguments.contains("forced_login_method=\"chatgpt\""))
        #expect(arguments.contains("approval_policy=\"never\""))
        #expect(!arguments.contains("--sandbox"))
        #expect(arguments.contains("default_permissions=\"nft_assistant\""))
        #expect(arguments.contains("permissions.nft_assistant={filesystem={\":root\"=\"deny\",\":minimal\"=\"read\",\":tmpdir\"=\"deny\",\":slash_tmp\"=\"deny\",\":workspace_roots\"=\"read\"},network={enabled=false}}"))
        #expect(!arguments.contains(where: { $0.contains("sandbox_mode") || $0.contains("sandbox_workspace_write") || $0.contains(":read-only") }))
        #expect(!(arguments.contains("--model") || arguments.contains("-m")))
        #expect(json["mode"] as? Int == 0o700)
        #expect(json["entries"] as? [String] == [])
        #expect(json["pid"] as? Int == json["group"] as? Int)
        let directory = try #require(json["cwd"] as? String)
        #expect(!FileManager.default.fileExists(atPath: directory))
        #expect(!FileManager.default.fileExists(atPath: URL(fileURLWithPath: directory).deletingLastPathComponent().path))
    }

    @Test("Incomplete, invalid and failed output never becomes a successful analysis", arguments: ["missing-terminal", "nonzero", "malformed", "tool", "error", "unknown", "extra-property", "oversized-list", "control-text"])
    func rejectedOutput(_ mode: String) async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let body: String
        let expected: CodexAnalysisError
        switch mode {
        case "missing-terminal": body = "message(response)"; expected = .invalidProtocol
        case "nonzero": body = "success(); sys.exit(9)"; expected = .providerFailed
        case "malformed": body = "sys.stdout.write('{malformed}\\n'); sys.stdout.flush()"; expected = .invalidProtocol
        case "tool": body = "emit(dict(type='item.started', item=dict(type='command_execution', command='never-trust-this'))); success()"; expected = .toolActivityDetected
        case "error": body = "emit(dict(type='turn.failed', error=dict(message='secret-provider-key')))"; expected = .providerFailed
        case "unknown": body = "emit(dict(type='unexpected.event'))"; expected = .invalidProtocol
        case "extra-property": body = "response['verifiedHash'] = 'invented'; success()"; expected = .invalidProtocol
        case "oversized-list": body = "response['observations'] = ['claim'] * 21; success()"; expected = .invalidProtocol
        default: body = "response['summary'] = 'bad\\x1bcontent'; success()"; expected = .invalidProtocol
        }
        let helper = try fixture.helper(body: body)
        await #expect(throws: expected) {
            _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
        }
    }

    @Test("Provider stderr is drained but never included in returned errors")
    func secretDiagnostics() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        sys.stderr.write('SENSITIVE_PROVIDER_CREDENTIAL\\n' * 1000)
        sys.stderr.flush()
        success()
        sys.exit(3)
        """)
        do {
            _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
            Issue.record("An unsuccessful provider exit was accepted.")
        } catch {
            #expect(error as? CodexAnalysisError == .providerFailed)
            #expect(!error.localizedDescription.contains("SENSITIVE"))
        }
    }

    @Test("Both output channels have bounded byte counts", arguments: ["stdout", "stderr"])
    func outputBounds(_ channel: String) async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: """
        sys.\(channel).write('x' * (3 * 1024 * 1024))
        sys.\(channel).flush()
        signal.pause()
        """)
        await #expect(throws: CodexAnalysisError.outputLimit) {
            _ = try await CodexAnalysisClient(executableURL: helper, timeout: 5).analyze(prompt: "Synthetic context")
        }
    }

    @Test("Deadline and cancellation reap the owned process group without stopping another process", arguments: [false, true])
    func ownedProcessCleanup(_ explicitCancellation: Bool) async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let gate = try ProcessTestGate(in: fixture.root)
        defer { gate.close() }
        let record = fixture.root.appendingPathComponent("owned-pids.json")
        let helper = try fixture.helper(body: """
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            os.read(os.open(\(CodexMockFixture.literal(gate.holdURL.path)), os.O_RDONLY), 1)
            os._exit(0)
        with open(\(CodexMockFixture.literal(record.path)), 'x') as output:
            json.dump(dict(parent=os.getpid(), child=child, cwd=os.getcwd()), output)
        with open(\(CodexMockFixture.literal(gate.readyURL.path)), 'wb', buffering=0) as ready:
            ready.write(b'R')
        os.read(os.open(\(CodexMockFixture.literal(gate.holdURL.path)), os.O_RDONLY), 1)
        """)
        let unrelated = try HeldOpenTestProcess()
        defer { unrelated.close() }
        let task = Task {
            try await CodexAnalysisClient(executableURL: helper, timeout: explicitCancellation ? 10 : 5).analyze(prompt: "Synthetic context")
        }
        do {
            try await gate.waitUntilReady { if explicitCancellation { task.cancel() } }
        } catch {
            task.cancel()
            _ = try? await task.value
            throw error
        }
        if explicitCancellation {
            await #expect(throws: CancellationError.self) { _ = try await task.value }
        } else {
            await #expect(throws: CodexAnalysisError.timeout) { _ = try await task.value }
        }
        let json = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any])
        let parent = try #require(json["parent"] as? Int32)
        let child = try #require(json["child"] as? Int32)
        await ProcessTestGate.expectStopped(parent)
        await ProcessTestGate.expectStopped(child)
        #expect(unrelated.process.isRunning)
        let scratch = try #require(json["cwd"] as? String)
        #expect(!FileManager.default.fileExists(atPath: scratch))
    }

    @Test("Invalid requests and missing CLI fail before execution")
    func invalidRequest() async throws {
        let missing = URL(fileURLWithPath: "/synthetic/nonexistent-codex")
        await #expect(throws: CodexAnalysisError.invalidRequest) {
            _ = try await CodexAnalysisClient(executableURL: missing, timeout: .infinity).analyze(prompt: "Synthetic context")
        }
        await #expect(throws: CodexAnalysisError.invalidRequest) {
            _ = try await CodexAnalysisClient(executableURL: missing).analyze(prompt: String(repeating: "a", count: 256 * 1_024 + 1))
        }
        await #expect(throws: CodexAnalysisError.unavailable) {
            _ = try await CodexAnalysisClient(executableURL: missing).analyze(prompt: "Synthetic context")
        }
    }

    @Test("Provider secrets, endpoints and loader overrides are excluded from the child environment")
    func sanitizedEnvironment() {
        let inherited = ["HOME": "/synthetic/home", "CODEX_HOME": "/synthetic/codex", "TMPDIR": "/synthetic/tmp/",
            "LANG": "en_US.UTF-8", "PATH": "/untrusted/bin", "OPENAI_API_KEY": "secret", "CODEX_API_KEY": "secret",
            "OPENAI_BASE_URL": "https://untrusted.invalid", "DYLD_INSERT_LIBRARIES": "/untrusted/library", "CUSTOM_SECRET": "secret"]
        let child = CodexProcessRunner.environment(inherited: inherited)
        #expect(Set(child.keys) == Set(["HOME", "CODEX_HOME", "TMPDIR", "LANG", "PATH"]))
        #expect(child["HOME"] == "/synthetic/home")
        #expect(child["CODEX_HOME"] == "/synthetic/codex")
        #expect(child["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin")
        #expect(!child.values.contains("secret"))
    }

    @Test("Scratch cleanup preserves a replacement directory and its unrelated contents")
    func scratchReplacement() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let record = fixture.root.appendingPathComponent("scratch-path.json")
        let moved = fixture.root.appendingPathComponent("moved-owned-scratch")
        let helper = try fixture.helper(body: """
        root = os.path.dirname(os.getcwd())
        os.rename(root, \(CodexMockFixture.literal(moved.path)))
        os.mkdir(root, 0o700)
        with open(os.path.join(root, 'unrelated.txt'), 'x') as output:
            output.write('preserve this replacement')
        with open(\(CodexMockFixture.literal(record.path)), 'x') as output:
            json.dump(dict(root=root), output)
        success()
        """)
        _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
        let json = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any])
        let root = URL(fileURLWithPath: try #require(json["root"] as? String))
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(try String(contentsOf: root.appendingPathComponent("unrelated.txt"), encoding: .utf8) == "preserve this replacement")
        #expect(try FileManager.default.contentsOfDirectory(atPath: moved.path).isEmpty)
    }

    @Test("An exited leader cannot leave a pipe-detached descendant running", arguments: [false, true])
    func detachedPipeChild(_ validResponse: Bool) async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let gate = try ProcessTestGate(in: fixture.root)
        defer { gate.close() }
        let record = fixture.root.appendingPathComponent("detached-child.json")
        let helper = try fixture.helper(body: """
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            for descriptor in [0, 1, 2]:
                os.close(descriptor)
            os.read(os.open(\(CodexMockFixture.literal(gate.holdURL.path)), os.O_RDONLY), 1)
            os._exit(0)
        with open(\(CodexMockFixture.literal(record.path)), 'x') as output:
            json.dump(dict(parent=os.getpid(), child=child), output)
        \(validResponse ? "success()" : "message(response)")
        """)
        if validResponse {
            _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
        } else {
            await #expect(throws: CodexAnalysisError.invalidProtocol) {
                _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
            }
        }
        let json = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any])
        let parent = try #require(json["parent"] as? Int32)
        let child = try #require(json["child"] as? Int32)
        await ProcessTestGate.expectStopped(parent)
        await ProcessTestGate.expectStopped(child)
    }

    @Test("A provider that closes stdin early cannot claim a result for the complete request")
    func incompletePrompt() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let helper = try fixture.helper(body: "os.close(0); success()", readInput: false)
        await #expect(throws: CodexAnalysisError.providerFailed) {
            _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: String(repeating: "synthetic context ", count: 12_000))
        }
    }

    @Test("Spawn clears a signal mask inherited from its launch thread")
    func inheritedSignalMask() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let record = fixture.root.appendingPathComponent("signal-state.json")
        let helper = try fixture.helper(body: """
        import signal
        with open(\(CodexMockFixture.literal(record.path)), 'x') as output:
            json.dump(dict(blocked=list(signal.pthread_sigmask(signal.SIG_BLOCK, [])),
                termination=int(signal.getsignal(signal.SIGTERM))), output)
        success()
        """)
        let result: CodexRunOutcome = try await withCheckedThrowingContinuation { continuation in
            Thread {
                var blocked = sigset_t(), previous = sigset_t()
                sigemptyset(&blocked)
                sigaddset(&blocked, SIGTERM)
                guard pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0 else {
                    continuation.resume(throwing: CodexAnalysisError.launchFailed)
                    return
                }
                defer { pthread_sigmask(SIG_SETMASK, &previous, nil) }
                do {
                    let result = try CodexProcessRunner(executableURL: helper, timeout: 5, cancellation: CodexCancellation()).run(prompt: "Synthetic context")
                    continuation.resume(returning: result)
                } catch { continuation.resume(throwing: error) }
            }.start()
        }
        #expect(result.response.summary == "Synthetic observation.")
        let json = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any])
        #expect(!(try #require(json["blocked"] as? [Int32])).contains(SIGTERM))
        #expect(json["termination"] as? Int == 0)
    }

    @Test("The exact intentionally disabled optional startup notice is recorded locally")
    func optionalStartupNotice() async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let startup = "emit(dict(type='item.completed', item=dict(type='error', message=\(CodexMockFixture.literal(CodexEventStream.disabledCodeModeNotice)))))"
        let helper = try fixture.helper(body: "success()", beforeTurn: startup)
        let result = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
        #expect(result.startupDiagnosticCount == 1)
        #expect(result.response.summary == "Synthetic observation.")
    }

    @Test("Unknown, enforcement-related, excessive and in-turn error items still fail", arguments: ["unknown", "permission", "excessive", "in-turn"])
    func rejectedStartupNotice(_ mode: String) async throws {
        let fixture = try CodexMockFixture()
        defer { fixture.remove() }
        let known = "emit(dict(type='item.completed', item=dict(type='error', message=\(CodexMockFixture.literal(CodexEventStream.disabledCodeModeNotice)))))"
        let beforeTurn: String
        let body: String
        switch mode {
        case "unknown": beforeTurn = "emit(dict(type='item.completed', item=dict(type='error', message='Unknown component startup failure')))"; body = "success()"
        case "permission": beforeTurn = "emit(dict(type='item.completed', item=dict(type='error', message='Permissions profile could not be enforced')))"; body = "success()"
        case "excessive": beforeTurn = "for _ in range(5):\n    \(known)"; body = "success()"
        default: beforeTurn = ""; body = known + "\nsuccess()"
        }
        let helper = try fixture.helper(body: body, beforeTurn: beforeTurn)
        await #expect(throws: CodexAnalysisError.providerFailed) {
            _ = try await CodexAnalysisClient(executableURL: helper).analyze(prompt: "Synthetic context")
        }
    }
}

private struct CodexMockFixture {
    let root: URL
    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("codex-mock-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
    static func literal(_ value: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(data: try! encoder.encode(value), encoding: .utf8)!
    }
    func helper(body: String, readInput: Bool = true, beforeTurn: String = "") throws -> URL {
        let url = root.appendingPathComponent("mock-codex")
        let script = """
        #!/usr/bin/env python3
        import sys, json, os, time, signal
        prompt = \(readInput ? "sys.stdin.read()" : "''")
        def emit(value):
            print(json.dumps(value), flush=True)
        response = dict(summary='Synthetic observation.', observations=['Observed synthetic bytes.'],
            hypotheses=['A hypothesis, not a verified conclusion.'], limitations=['Only synthetic context was supplied.'],
            nextSteps=['Verify using the read-only engine.'])
        def message(value):
            emit(dict(type='item.completed', item=dict(id='item_0', type='agent_message', text=json.dumps(value))))
        def success():
            message(response)
            emit(dict(type='turn.completed', usage=dict(input_tokens=1, output_tokens=1)))
        emit(dict(type='thread.started', thread_id='synthetic-thread'))
        \(beforeTurn)
        emit(dict(type='turn.started'))
        \(body)
        """
        try Data(script.utf8).write(to: url)
        guard Darwin.chmod(url.path, 0o700) == 0 else { throw CodexAnalysisError.launchFailed }
        return url
    }
}
