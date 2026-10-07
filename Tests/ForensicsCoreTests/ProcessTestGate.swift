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
    let process = Process()
    private let input = Pipe()

    init() throws {
        process.executableURL = URL(fileURLWithPath: "/bin/cat")
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        try input.fileHandleForReading.close()
    }

    func close() {
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }
}
