import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Owned recovery tool processes")
struct RecoveryProcessTests {
    @Test("Arguments remain literal, stdin is EOF, and tool diagnostics and status remain distinct")
    func literalArgumentsAndDiagnostics() throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let argument = "spaces ; $(touch injected) `touch injected` \" literal"
        let result = try fixture.run("""
        if IFS= read -r value; then exit 99; fi
        printf '%s' "$1"
        printf 'separate diagnostic' >&2
        exit 7
        """, arguments: [argument])
        #expect(result.exitStatus == 7)
        #expect(result.stdout == Data(argument.utf8))
        #expect(result.stderr == Data("separate diagnostic".utf8))
        #expect(!FileManager.default.fileExists(atPath: fixture.workspace.appendingPathComponent("injected").path))
    }

    @Test("PhotoRec receives an owned HOME and TMPDIR with a deterministic locale and PATH")
    func deterministicEnvironment() throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        #expect(RecoveryProcessRunner.environment(workspace: fixture.workspace) == [
            "HOME": fixture.workspace.path, "TMPDIR": fixture.workspace.path + "/",
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"
        ])
        let result = try fixture.run("""
        printf '%s\n' "$HOME" "$TMPDIR" "$PATH" "$LANG" "$LC_ALL" "${DYLD_LIBRARY_PATH-unset}"
        """)
        let expected = [fixture.workspace.path, fixture.workspace.path + "/", "/usr/bin:/bin", "C", "C", "unset"]
            .joined(separator: "\n") + "\n"
        #expect(result.exitStatus == 0)
        #expect(result.stdout == Data(expected.utf8))
    }

    @Test("All buffered output survives short-lived process exit")
    func bufferedOutputTail() throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let result = try fixture.run("/usr/bin/head -c 524288 /dev/zero; printf 'tail' >&2")
        #expect(result.exitStatus == 0)
        #expect(result.stdout == Data(repeating: 0, count: 524_288))
        #expect(result.stderr == Data("tail".utf8))
    }

    @Test("A continuous diagnostic flood trips its independent byte limit", arguments: [true, false])
    func diagnosticFlood(_ standardOutput: Bool) throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let start = DispatchTime.now().uptimeNanoseconds
        #expect(throws: RecoveryError.outputLimit) {
            _ = try fixture.run(
                standardOutput ? "exec /usr/bin/yes synthetic" : "exec /usr/bin/yes synthetic >&2",
                maximumStdoutBytes: 128, maximumStderrBytes: 128
            )
        }
        #expect(Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000 < 5)
    }

    @Test("A deadline stops and reaps its group while an unrelated process remains alive")
    func timeoutOwnsOnlyItsGroup() async throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let gate = try ProcessTestGate(in: fixture.workspace)
        defer { gate.close() }
        let unrelated = try HeldOpenTestProcess()
        defer { unrelated.close() }
        #expect(throws: RecoveryError.timeout) {
            _ = try fixture.run(gate.shellDescendants, timeout: 0.5)
        }
        #expect(unrelated.process.isRunning)
        try await gate.expectStoppedProcesses()
    }

    @Test("Task cancellation stops a running owned group and propagates cancellation")
    func cancellationStopsGroup() async throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let gate = try ProcessTestGate(in: fixture.workspace)
        defer { gate.close() }
        let task = Task.detached {
            try fixture.run(gate.shellDescendants, timeout: 10)
        }
        do {
            try await gate.waitUntilReady { task.cancel() }
        } catch {
            task.cancel()
            _ = try? await task.value
            throw error
        }
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        try await gate.expectStoppedProcesses()
    }

    @Test("Exited leaders do not leave descendants holding inherited pipes open", arguments: [0, 7])
    func exitedLeaderStillStopsDescendant(_ status: Int) async throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let gate = try ProcessTestGate(in: fixture.workspace)
        defer { gate.close() }
        let start = DispatchTime.now().uptimeNanoseconds
        let result = try fixture.run("""
        trap '' TERM
        printf '%s\n' "$$" > leader.pid
        /bin/sh -c \(ProcessTestGate.quote("IFS= read -r held < " + ProcessTestGate.quote(gate.holdURL.path))) &
        printf '%s\n' "$!" > child.pid
        printf 'complete'
        exit \(status)
        """, timeout: 5)
        #expect(result.exitStatus == Int32(status))
        #expect(result.stdout == Data("complete".utf8))
        #expect(Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000 < 4)
        try await gate.expectStoppedProcesses()
    }

    @Test("Periodic output-file monitoring can stop a running group with its original error")
    func monitorStopsTool() async throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let gate = try ProcessTestGate(in: fixture.workspace)
        defer { gate.close() }
        var checks = 0
        #expect(throws: RecoveryError.outputLimit) {
            _ = try fixture.run(gate.shellDescendants, timeout: 5) {
                checks += 1
                if checks >= 2 { throw RecoveryError.outputLimit }
            }
        }
        #expect(checks == 2)
        try await gate.expectStoppedProcesses()
    }

    @Test("A borrowed directory descriptor pins relative output across a workspace path replacement")
    func pinnedWorkingDirectory() throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        let descriptor = Darwin.open(fixture.workspace.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        #expect(descriptor >= 0)
        guard descriptor >= 0 else { return }
        defer { Darwin.close(descriptor) }
        let held = fixture.root.appendingPathComponent("held-workspace", isDirectory: true)
        try FileManager.default.moveItem(at: fixture.workspace, to: held)
        try FileManager.default.createDirectory(at: fixture.workspace, withIntermediateDirectories: false)
        let result = try RecoveryProcessRunner.run(
            executableURL: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "printf 'pinned' > marker"],
            workingDirectory: fixture.workspace, workingDirectoryDescriptor: descriptor, timeout: 5
        )
        #expect(result.exitStatus == 0)
        #expect(try Data(contentsOf: held.appendingPathComponent("marker")) == Data("pinned".utf8))
        #expect(!FileManager.default.fileExists(atPath: fixture.workspace.appendingPathComponent("marker").path))
        var information = stat()
        #expect(Darwin.fstat(descriptor, &information) == 0)
    }

    @Test("Invalid limits and embedded argument NUL bytes are rejected before spawn")
    func invalidOptions() throws {
        let fixture = try RecoveryProcessFixture()
        defer { fixture.remove() }
        #expect(throws: RecoveryError.invalidOptions) { _ = try fixture.run("exit 0", timeout: .infinity) }
        #expect(throws: RecoveryError.invalidOptions) { _ = try fixture.run("exit 0", maximumStdoutBytes: -1) }
        #expect(throws: RecoveryError.invalidOptions) { _ = try fixture.run("exit 0", arguments: ["bad\0argument"]) }
    }
}

private struct RecoveryProcessFixture: Sendable {
    let root: URL
    let workspace: URL

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-process-\(UUID().uuidString)", isDirectory: true)
        workspace = root.appendingPathComponent("workspace", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        } catch { try? FileManager.default.removeItem(at: root); throw error }
    }

    func remove() { try? FileManager.default.removeItem(at: root) }

    func run(
        _ body: String, arguments: [String] = [], timeout: TimeInterval = 5,
        maximumStdoutBytes: Int = 8 * 1_024 * 1_024, maximumStderrBytes: Int = 64 * 1_024,
        monitor: () throws -> Void = {}
    ) throws -> RecoveryProcessOutcome {
        try RecoveryProcessRunner.run(
            executableURL: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", body, "synthetic-tool"] + arguments,
            workingDirectory: workspace, timeout: timeout, maximumStdoutBytes: maximumStdoutBytes,
            maximumStderrBytes: maximumStderrBytes, monitor: monitor
        )
    }

}
