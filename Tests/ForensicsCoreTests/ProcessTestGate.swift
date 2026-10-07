import Darwin
import Foundation
import Testing

/// A synthetic tool stays blocked on the hold FIFO until its owned process
/// group is stopped. Readiness and cancellation do not depend on a test task
/// resuming promptly on Swift's cooperative executor.
final class ProcessTestGate: @unchecked Sendable {
    let holdURL: URL
    let readyURL: URL
    let leaderURL: URL
    let childURL: URL
    private var holdDescriptor: Int32 = -1
    private var readyDescriptor: Int32 = -1

    init(in directory: URL) throws {
        holdURL = directory.appendingPathComponent("process-hold.fifo")
        readyURL = directory.appendingPathComponent("process-ready.fifo")
        leaderURL = directory.appendingPathComponent("leader.pid")
        childURL = directory.appendingPathComponent("child.pid")
        do {
            for url in [holdURL, readyURL] {
                guard Darwin.mkfifo(url.path, 0o600) == 0 else { throw GateError.setup }
            }
            // A retained writer makes a held child's read block rather than
            // returning EOF. CLOEXEC keeps these parent descriptors private.
            holdDescriptor = Darwin.open(holdURL.path, O_RDWR | O_NONBLOCK | O_CLOEXEC)
            readyDescriptor = Darwin.open(readyURL.path, O_RDWR | O_NONBLOCK | O_CLOEXEC)
            guard holdDescriptor >= 0, readyDescriptor >= 0 else { throw GateError.setup }
        } catch { close(); throw error }
    }

    deinit { close() }

    func close() {
        for descriptor in [holdDescriptor, readyDescriptor] where descriptor >= 0 { Darwin.close(descriptor) }
        holdDescriptor = -1
        readyDescriptor = -1
    }

    /// The controller executes onReady on its own queue before it wakes the
    /// async test. In cancellation tests, this cancels the real task as soon
    /// as the tool has published its PID records and acknowledged readiness.
    func waitUntilReady(onReady: @escaping @Sendable () -> Void = {}) async throws {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
                    while DispatchTime.now().uptimeNanoseconds < deadline {
                        var descriptor = pollfd(fd: self.readyDescriptor, events: Int16(POLLIN), revents: 0)
                        let polled = Darwin.poll(&descriptor, 1, 100)
                        if polled < 0 {
                            if errno == EINTR { continue }
                            throw GateError.handshake
                        }
                        if descriptor.revents & Int16(POLLIN) != 0 {
                            var byte: UInt8 = 0
                            let count = Darwin.read(self.readyDescriptor, &byte, 1)
                            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
                            guard count == 1, byte == Character("R").asciiValue else { throw GateError.handshake }
                            onReady()
                            continuation.resume()
                            return
                        }
                    }
                    throw GateError.readinessTimeout
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    var shellDescendants: String {
        """
        trap '' TERM
        printf '%s\\n' "$$" > \(Self.quote(leaderURL.path))
        /bin/sh -c \(Self.quote("IFS= read -r held < " + Self.quote(holdURL.path))) &
        printf '%s\\n' "$!" > \(Self.quote(childURL.path))
        printf R > \(Self.quote(readyURL.path))
        wait
        """
    }

    func expectStoppedProcesses() async throws {
        let leader = try Self.recordedPID(at: leaderURL)
        let child = try Self.recordedPID(at: childURL)
        await Self.expectStopped(leader)
        await Self.expectStopped(child)
    }

    static func recordedPID(at url: URL) throws -> Int32 {
        let pid = try #require(Int32(String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)))
        try #require(pid > 0)
        return pid
    }

    static func expectStopped(_ pid: Int32) async {
        // Orphaned zombies may exist briefly while the OS reaper catches up.
        // Observe a bounded monotonic interval on a noncooperative queue.
        let result: (Int32, Int32) = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
                var observed = Darwin.kill(pid, 0)
                while observed == 0 && DispatchTime.now().uptimeNanoseconds < deadline {
                    _ = Darwin.poll(nil, 0, 10)
                    observed = Darwin.kill(pid, 0)
                }
                continuation.resume(returning: (observed, errno))
            }
        }
        #expect(result.0 == -1)
        #expect(result.1 == ESRCH)
    }

    static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private enum GateError: Error { case setup, handshake, readinessTimeout }
}

/// Unlike a finite sleep, this unrelated process cannot end naturally while a
/// heavily loaded test executor delays an assertion. The test owns its stdin.
final class HeldOpenTestProcess {
    let process: HeldTestProcess
    private var inputWriter: Int32

    init() throws {
        var input: [Int32] = [-1, -1]
        guard Darwin.pipe(&input) == 0 else { throw HeldProcessError.launch }
        var ownsWriter = true
        defer {
            Darwin.close(input[0])
            if ownsWriter { Darwin.close(input[1]) }
        }
        for index in input.indices {
            input[index] = try Self.aboveStdio(input[index])
            guard fcntl(input[index], F_SETFD, FD_CLOEXEC) == 0 else { throw HeldProcessError.launch }
        }
        var null = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard null >= 0 else { throw HeldProcessError.launch }
        defer { Darwin.close(null) }
        null = try Self.aboveStdio(null)
        process = try HeldTestProcess(input: input[0], output: null)
        inputWriter = input[1]
        ownsWriter = false
    }

    deinit { close() }

    func close() {
        if inputWriter >= 0 { Darwin.close(inputWriter); inputWriter = -1 }
        process.stopAndReap()
    }

    private static func aboveStdio(_ descriptor: Int32) throws -> Int32 {
        guard descriptor <= STDERR_FILENO else { return descriptor }
        let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 3)
        guard duplicate >= 0 else { throw HeldProcessError.launch }
        Darwin.close(descriptor)
        return duplicate
    }
}

/// The unrelated sentinel must not itself extend any other test's pipe
/// lifetime. CLOEXEC_DEFAULT closes every unlisted descriptor at spawn,
/// including descriptors concurrently created before their CLOEXEC flag.
final class HeldTestProcess {
    private(set) var processIdentifier: pid_t = 0

    init(input: Int32, output: Int32) throws {
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw HeldProcessError.launch }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw HeldProcessError.launch }
        defer { posix_spawnattr_destroy(&attributes) }
        for (source, target) in [(input, STDIN_FILENO), (output, STDOUT_FILENO), (output, STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw HeldProcessError.launch }
        }
        for descriptor in [input, output] {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else { throw HeldProcessError.launch }
        }
        var defaults = sigset_t(), mask = sigset_t()
        sigemptyset(&defaults); sigemptyset(&mask)
        for signal in [SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, signal) }
        guard posix_spawnattr_setflags(&attributes, Int16(
            POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
        )) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0 else { throw HeldProcessError.launch }
        let arguments = [strdup("/bin/cat"), nil]
        let environment = [strdup("LC_ALL=C"), nil]
        defer { for pointer in arguments + environment { free(pointer) } }
        guard arguments[0] != nil, environment[0] != nil else { throw HeldProcessError.launch }
        var argv = arguments, env = environment, child: pid_t = 0
        let status = argv.withUnsafeMutableBufferPointer { argv in
            env.withUnsafeMutableBufferPointer { env in
                posix_spawn(&child, "/bin/cat", &actions, &attributes, argv.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw HeldProcessError.launch }
        processIdentifier = child
    }

    var isRunning: Bool {
        guard processIdentifier > 0 else { return false }
        var information = siginfo_t()
        var observed: Int32
        repeat {
            observed = Darwin.waitid(P_PID, id_t(processIdentifier), &information, WEXITED | WNOHANG | WNOWAIT)
        } while observed < 0 && errno == EINTR
        if observed < 0 && errno == ECHILD {
            // A later deferred cleanup must not signal a reusable PID after
            // any unexpected external reaping.
            processIdentifier = 0
        }
        return observed == 0 && information.si_pid == 0
    }

    func stopAndReap() {
        guard processIdentifier > 0 else { return }
        let child = processIdentifier
        var information = siginfo_t()
        var observed: Int32
        repeat {
            observed = Darwin.waitid(P_PID, id_t(child), &information, WEXITED | WNOHANG | WNOWAIT)
        } while observed < 0 && errno == EINTR
        // Refuse to signal a PID if an external reaper broke our ownership.
        guard observed == 0 else {
            #expect(observed == 0, "The held fixture lost ownership of its unreaped child.")
            processIdentifier = 0
            return
        }
        // Retain the unreaped PID throughout graceful shutdown. The child
        // cannot be reused as an unrelated PID before our fallback signal.
        _ = Darwin.kill(child, SIGTERM)
        let deadline = DispatchTime.now().uptimeNanoseconds + 250_000_000
        while isRunning && DispatchTime.now().uptimeNanoseconds < deadline { _ = Darwin.poll(nil, 0, 10) }
        if isRunning { _ = Darwin.kill(child, SIGKILL) }
        var status: Int32 = 0
        var reaped: pid_t
        repeat { reaped = Darwin.waitpid(child, &status, 0) } while reaped < 0 && errno == EINTR
        #expect(reaped == child)
        processIdentifier = 0
    }
}

private enum HeldProcessError: Error { case launch }
