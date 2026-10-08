import Darwin
import Dispatch
import Foundation

final class APFSCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var deadline: UInt64?
    func setDeadline(seconds: Double) {
        lock.lock(); deadline = DispatchTime.now().uptimeNanoseconds + UInt64(seconds * 1_000_000_000); lock.unlock()
    }
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    func check(allowCancelled: Bool = false) throws {
        lock.lock(); let stopped = cancelled; let expiry = deadline; lock.unlock()
        if stopped && !allowCancelled { throw CancellationError() }
        if let expiry, DispatchTime.now().uptimeNanoseconds >= expiry { throw APFSReadError.timeout }
    }
}

/// Fixed system tools, no shell, no inherited credentials, bounded nonblocking
/// pipes. Secret input is never an argument, environment value or diagnostic.
struct APFSSnapshotMountDiagnostic: Sendable {
    let arguments: [String]
    let naturalRawWaitStatus: Int32
    let standardError: Data
}

enum APFSSystemCommand {
    static func run(_ tool: String, _ arguments: [String], input: Data = Data(),
                    timeout: Double, cancellation: APFSCancellation?, outputLimit: Int = 2 * 1_024 * 1_024,
                    started: ((Int32) -> Void)? = nil, confirmedTerminal: (() -> Void)? = nil,
                    drainOnCancellation: Bool = false,
                    snapshotMountDiagnostic: (@Sendable (APFSSnapshotMountDiagnostic) -> Void)? = nil) throws -> Data {
        guard ["/usr/bin/hdiutil", "/usr/sbin/diskutil", "/sbin/mount_apfs", "/sbin/umount"].contains(tool),
              input.count <= 1_025, outputLimit > 0, outputLimit <= 2 * 1_024 * 1_024 else { throw APFSReadError.invalidOptions }
        if tool == "/sbin/mount_apfs" {
            guard input.isEmpty, arguments.count == 6, arguments[0] == "-o",
                  arguments[1] == "rdonly,nobrowse,noexec,nosuid,nodev,nofollow", arguments[2] == "-s",
                  !arguments[3].isEmpty, arguments[3].utf8.count <= 1_024,
                  !arguments[3].unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
                  arguments[4].hasPrefix("/"), arguments[5].hasPrefix("/"),
                  !arguments[4].utf8.contains(0), !arguments[5].utf8.contains(0) else { throw APFSReadError.invalidOptions }
        } else if tool == "/sbin/umount" {
            guard input.isEmpty, arguments.count == 1, arguments[0].hasPrefix("/"),
                  !arguments[0].utf8.contains(0) else { throw APFSReadError.invalidOptions }
        }
        try cancellation?.check()
        let channels = try Channels(); defer { channels.closeAll() }
        var actions: posix_spawn_file_actions_t?, attrs: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw APFSReadError.commandFailed(-1) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attrs) == 0 else { throw APFSReadError.commandFailed(-1) }
        defer { posix_spawnattr_destroy(&attrs) }
        for (from, to) in [(channels.input[0], STDIN_FILENO), (channels.output[1], STDOUT_FILENO), (channels.error[1], STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, from, to) == 0 else { throw APFSReadError.commandFailed(-1) }
        }
        for fd in channels.all { guard posix_spawn_file_actions_addclose(&actions, fd) == 0 else { throw APFSReadError.commandFailed(-1) } }
        var mask = sigset_t(), defaults = sigset_t(); sigemptyset(&mask); sigemptyset(&defaults)
        for signal in [SIGTERM, SIGINT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, signal) }
        guard posix_spawnattr_setflags(&attrs, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0,
              posix_spawnattr_setpgroup(&attrs, 0) == 0, posix_spawnattr_setsigmask(&attrs, &mask) == 0,
              posix_spawnattr_setsigdefault(&attrs, &defaults) == 0 else { throw APFSReadError.commandFailed(-1) }
        let argPointers = ([tool] + arguments).map { strdup($0) }
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"]
        let envPointers = environmentStrings.map { strdup($0) }
        defer { for p in argPointers + envPointers { free(p) } }
        var argv = argPointers + [nil], env = envPointers + [nil], child: pid_t = 0
        let status = argv.withUnsafeMutableBufferPointer { args in
            env.withUnsafeMutableBufferPointer { environment in
                posix_spawn(&child, tool, &actions, &attrs, args.baseAddress!, environment.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw APFSReadError.commandFailed(status) }
        channels.closeChildEnds()
        var reaped = false
        defer { if !reaped { terminateAndReap(child) } }
        started?(child)
        var bytes = Data(), inputOffset = 0, errorBytes = 0
        // Internal opt-in fixture seam only. Ordinary reads still discard
        // stderr without copying it; no hdiutil/diskutil or stdin/key diagnostic
        // is admitted, and the existing 128 KiB stderr bound is unchanged.
        var retainedSnapshotError: Data? = snapshotMountDiagnostic != nil && tool == "/sbin/mount_apfs" && input.isEmpty ? Data() : nil
        var outputEOF = false, errorEOF = false, inputClosed = false
        var buffer = [UInt8](repeating: 0, count: 32_768)
        let deadline = uptime() + timeout
        while true {
            // These operations act only on an owned read-only image/view. Cancel
            // can wait for its natural terminal within the SAME deadline,
            // allowing owned detach before cancellation is reported. Hard job
            // deadlines, command deadlines and output bounds remain enforced.
            try cancellation?.check(allowCancelled: drainOnCancellation)
            guard uptime() < deadline else { throw APFSReadError.timeout }
            if !inputClosed && inputOffset == input.count { channels.closeInput(); inputClosed = true }
            var polling = [pollfd(fd: outputEOF ? -1 : channels.output[0], events: Int16(POLLIN), revents: 0),
                           pollfd(fd: errorEOF ? -1 : channels.error[0], events: Int16(POLLIN), revents: 0),
                           pollfd(fd: inputClosed ? -1 : channels.input[1], events: Int16(POLLOUT), revents: 0)]
            let count = Darwin.poll(&polling, nfds_t(polling.count), 20)
            if count < 0 { if errno == EINTR { continue }; throw APFSReadError.commandFailed(-1) }
            for index in 0..<2 where polling[index].revents != 0 {
                for _ in 0..<8 {
                    let fd = index == 0 ? channels.output[0] : channels.error[0]
                    let amount = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if amount > 0 {
                        if index == 0 {
                            guard amount <= outputLimit - bytes.count else { throw APFSReadError.outputLimit }
                            bytes.append(contentsOf: buffer.prefix(amount))
                        } else {
                            errorBytes += amount
                            guard errorBytes <= 128 * 1_024 else { throw APFSReadError.outputLimit }
                            retainedSnapshotError?.append(contentsOf: buffer.prefix(amount))
                        }
                    } else if amount == 0 {
                        if index == 0 { outputEOF = true } else { errorEOF = true }; break
                    } else if errno == EINTR { continue }
                    else if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    else { throw APFSReadError.commandFailed(-1) }
                }
            }
            if !inputClosed && polling[2].revents != 0 {
                guard polling[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else { throw APFSReadError.commandFailed(-1) }
                let amount = input.withUnsafeBytes { Darwin.write(channels.input[1], $0.baseAddress!.advanced(by: inputOffset), input.count - inputOffset) }
                if amount > 0 { inputOffset += amount }
                else if amount < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw APFSReadError.commandFailed(-1) }
            }
            if outputEOF && errorEOF {
                var terminal = siginfo_t()
                let observed = Darwin.waitid(P_PID, id_t(child), &terminal, WEXITED | WNOHANG | WNOWAIT)
                if observed < 0 && errno != EINTR { throw APFSReadError.commandFailed(-1) }
                guard observed == 0, terminal.si_pid == child else { continue }
                var value: Int32 = 0
                let done = Darwin.waitpid(child, &value, WNOHANG)
                if done == child {
                    reaped = true
                    if terminal.si_code == CLD_EXITED {
                        confirmedTerminal?()
                        if let retainedSnapshotError, let snapshotMountDiagnostic {
                            snapshotMountDiagnostic(.init(arguments: arguments, naturalRawWaitStatus: value,
                                                          standardError: retainedSnapshotError))
                        }
                    }
                    if cancellation?.isCancelled == true { throw CancellationError() }
                    guard value == 0, inputOffset == input.count else { throw APFSReadError.commandFailed(value) }
                    return bytes
                }
                if done < 0 && errno != EINTR { throw APFSReadError.commandFailed(-1) }
            }
        }
    }

    static func plist(_ data: Data) throws -> [String: Any] {
        guard data.count <= 2 * 1_024 * 1_024,
              let result = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw APFSReadError.invalidResult
        }
        return result
    }

    private static func uptime() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }
    private static func terminateAndReap(_ child: pid_t) {
        _ = Darwin.kill(-child, SIGTERM)
        let deadline = uptime() + 0.3
        var result: Int32 = 0
        while uptime() < deadline {
            let done = Darwin.waitpid(child, &result, WNOHANG)
            if done == child || (done < 0 && errno == ECHILD) { return }
            _ = Darwin.poll(nil, 0, 10)
        }
        _ = Darwin.kill(-child, SIGKILL)
        while Darwin.waitpid(child, &result, 0) < 0 && errno == EINTR {}
    }

    private final class Channels {
        var input = [Int32](repeating: -1, count: 2), output = [Int32](repeating: -1, count: 2), error = [Int32](repeating: -1, count: 2)
        var all: [Int32] { input + output + error }
        init() throws {
            do {
                try Self.make(&input); try Self.make(&output); try Self.make(&error)
                for fd in all {
                    guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw APFSReadError.commandFailed(-1) }
                    let noSignal: Int32 = 1
                    guard fcntl(fd, F_SETNOSIGPIPE, noSignal) == 0 else { throw APFSReadError.commandFailed(-1) }
                }
                for fd in [input[1], output[0], error[0]] {
                    let flags = fcntl(fd, F_GETFL)
                    guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw APFSReadError.commandFailed(-1) }
                }
            } catch { closeAll(); throw error }
        }
        static func make(_ descriptors: inout [Int32]) throws {
            guard Darwin.pipe(&descriptors) == 0 else { throw APFSReadError.commandFailed(-1) }
            for index in 0..<2 where descriptors[index] < 3 {
                let replacement = fcntl(descriptors[index], F_DUPFD_CLOEXEC, 3)
                guard replacement >= 3 else { throw APFSReadError.commandFailed(-1) }
                Darwin.close(descriptors[index]); descriptors[index] = replacement
            }
        }
        func closeChildEnds() { closeFD(&input[0]); closeFD(&output[1]); closeFD(&error[1]) }
        func closeInput() { closeFD(&input[1]) }
        func closeAll() { for i in 0..<2 { closeFD(&input[i]); closeFD(&output[i]); closeFD(&error[i]) } }
        private func closeFD(_ descriptor: inout Int32) { if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 } }
    }
}
