import Darwin
import Foundation
import Testing
@testable import ForensicsCore

@Suite("Exited engine pipe draining")
struct EngineExitPipeTests {
    @Test("Native engine spawn closes an unrelated writer before its parent sets CLOEXEC")
    func spawnDescriptorIsolation() throws {
        var unrelated: [Int32] = [-1, -1]
        try #require(Darwin.pipe(&unrelated) == 0)
        defer {
            for descriptor in unrelated where descriptor >= 0 { Darwin.close(descriptor) }
        }
        // Deliberately preserve the creation-to-fcntl race state throughout
        // spawn. The child must close these even without a parent CLOEXEC flag.
        for descriptor in unrelated {
            try #require(fcntl(descriptor, F_SETFD, 0) == 0)
            #expect(fcntl(descriptor, F_GETFD) & FD_CLOEXEC == 0)
        }
        let channels = try EngineChannels()
        defer { channels.close() }
        let process = try EngineProcess(executable: URL(fileURLWithPath: "/bin/cat"), channels: channels)
        channels.closeChildEnds()
        defer { process.terminateAndReap(grace: 0.1) }
        // cat remains alive on its own stdin. EOF here therefore proves the
        // unrelated writer was not retained by a still-running engine child.
        #expect(try process.isRunning())
        Darwin.close(unrelated[1]); unrelated[1] = -1
        var readiness = pollfd(fd: unrelated[0], events: Int16(POLLIN), revents: 0)
        try #require(Darwin.poll(&readiness, 1, 0) >= 0)
        try #require(readiness.revents & Int16(POLLHUP) != 0)
        var byte: UInt8 = 0
        #expect(Darwin.read(unrelated[0], &byte, 1) == 0)
        #expect(try process.isRunning())
        process.terminateAndReap(grace: 0.1)
        var status: Int32 = 0
        #expect(Darwin.waitpid(process.processIdentifier, &status, WNOHANG) == -1)
        #expect(errno == ECHILD)
    }

    // Synthetic clock values model a worker returning after a scheduler stall
    // without sleeping or changing a production timeout. Readiness comes from
    // real nonblocking Darwin pipes, including their writer lifetime.
    @Test("An overdue worker may observe EOF already waiting in either closed pipe", arguments: [false, true])
    func delayedEOF(_ stderr: Bool) throws {
        let pipe = try ExitTestPipe()
        pipe.closeWriter()
        try EnginePipeExitDeadline.validate(exitedAt: 100, now: 105,
            stdoutFD: stderr ? nil : pipe.readFD, stderrFD: stderr ? pipe.readFD : nil)
        #expect(try pipe.readAvailable() == Data())
        #expect(pipe.observedEOF)
    }

    @Test("Finite buffered output from a closed writer survives the post-exit deadline", arguments: [false, true])
    func delayedBufferedTail(_ stderr: Bool) throws {
        let pipe = try ExitTestPipe()
        let payload = Data("synthetic final protocol frame\n".utf8)
        try pipe.write(payload)
        pipe.closeWriter()
        try EnginePipeExitDeadline.validate(exitedAt: 100, now: 105,
            stdoutFD: stderr ? nil : pipe.readFD, stderrFD: stderr ? pipe.readFD : nil)
        #expect(try pipe.readAvailable() == payload)
        #expect(pipe.observedEOF)
    }

    @Test("An idle open writer is rejected at the unchanged two-second boundary", arguments: [false, true])
    func idleOpenWriter(_ stderr: Bool) throws {
        let pipe = try ExitTestPipe()
        try EnginePipeExitDeadline.validate(exitedAt: 100, now: 101.999,
            stdoutFD: stderr ? nil : pipe.readFD, stderrFD: stderr ? pipe.readFD : nil)
        #expect(throws: Self.heldWriterError) {
            try EnginePipeExitDeadline.validate(exitedAt: 100, now: 102,
                stdoutFD: stderr ? nil : pipe.readFD, stderrFD: stderr ? pipe.readFD : nil)
        }
    }

    @Test("Readable output from a still-open flooding writer cannot suppress the deadline", arguments: [false, true])
    func floodingOpenWriter(_ stderr: Bool) throws {
        let pipe = try ExitTestPipe()
        // Fill the OS pipe to EAGAIN. This is the same readiness state seen
        // when a descendant continuously replenishes discarded stderr.
        #expect(try pipe.fill() > 0)
        #expect(throws: Self.heldWriterError) {
            try EnginePipeExitDeadline.validate(exitedAt: 100, now: 105,
                stdoutFD: stderr ? nil : pipe.readFD, stderrFD: stderr ? pipe.readFD : nil)
        }
    }

    @Test("One closed output channel cannot conceal a live writer in the other", arguments: [false, true])
    func mixedWriterLifetimes(_ closedStdout: Bool) throws {
        let output = try ExitTestPipe(), errors = try ExitTestPipe()
        try output.write(Data("finite tail".utf8))
        output.closeWriter()
        #expect(try errors.fill() > 0)
        #expect(throws: Self.heldWriterError) {
            try EnginePipeExitDeadline.validate(exitedAt: 100, now: 105,
                stdoutFD: closedStdout ? output.readFD : errors.readFD,
                stderrFD: closedStdout ? errors.readFD : output.readFD)
        }
        errors.closeWriter()
        try EnginePipeExitDeadline.validate(exitedAt: 100, now: 105,
            stdoutFD: closedStdout ? output.readFD : errors.readFD,
            stderrFD: closedStdout ? errors.readFD : output.readFD)
    }

    private static let heldWriterError = EngineError.protocolViolation(
        "The helper exited while a descendant kept its output pipes open.")
}

private final class ExitTestPipe {
    let readFD: Int32
    private var writeFD: Int32
    private(set) var observedEOF = false

    init() throws {
        var descriptors: [Int32] = [-1, -1]
        guard Darwin.pipe(&descriptors) == 0 else { throw FileAccess.posixError("Cannot create test pipe") }
        for descriptor in descriptors {
            let flags = fcntl(descriptor, F_GETFL)
            let descriptorFlags = fcntl(descriptor, F_GETFD)
            // Other tests launch Foundation helpers concurrently. Neither end
            // may survive exec and accidentally extend a fixture writer's life.
            guard flags >= 0, descriptorFlags >= 0,
                  fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0,
                  fcntl(descriptor, F_GETFD) & FD_CLOEXEC != 0 else {
                Darwin.close(descriptors[0]); Darwin.close(descriptors[1])
                throw FileAccess.posixError("Cannot configure test pipe")
            }
        }
        readFD = descriptors[0]; writeFD = descriptors[1]
    }

    deinit {
        Darwin.close(readFD)
        if writeFD >= 0 { Darwin.close(writeFD) }
    }

    func closeWriter() {
        if writeFD >= 0 { Darwin.close(writeFD); writeFD = -1 }
    }

    func write(_ data: Data) throws {
        let count = data.withUnsafeBytes { Darwin.write(writeFD, $0.baseAddress, $0.count) }
        guard count == data.count else { throw FileAccess.posixError("Cannot write test pipe") }
    }

    func fill() throws -> Int {
        let data = Data(repeating: 65, count: 4_096)
        var count = 0
        while count < 8 * 1_024 * 1_024 {
            let written = data.withUnsafeBytes { Darwin.write(writeFD, $0.baseAddress, $0.count) }
            if written > 0 { count += written }
            else if written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { return count }
            else if written < 0 && errno == EINTR { continue }
            else { throw FileAccess.posixError("Cannot fill test pipe") }
        }
        throw EngineError.limitExceeded("The synthetic pipe did not reach its finite capacity.")
    }

    func readAvailable() throws -> Data {
        var result = Data(), buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(readFD, $0.baseAddress, $0.count) }
            if count > 0 { result.append(contentsOf: buffer.prefix(count)) }
            else if count == 0 { observedEOF = true; return result }
            else if errno == EINTR { continue }
            else if errno == EAGAIN || errno == EWOULDBLOCK { return result }
            else { throw FileAccess.posixError("Cannot read test pipe") }
        }
    }
}
