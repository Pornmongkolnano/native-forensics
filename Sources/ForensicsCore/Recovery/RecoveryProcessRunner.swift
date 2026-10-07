import Darwin
import Foundation

/// Bounded diagnostics from one owned tool invocation. A nonzero tool status is
/// returned so callers can distinguish tool failure from transport failure.
struct RecoveryProcessOutcome: Sendable {
    let exitStatus: Int32
    let stdout: Data
    let stderr: Data
}

/// Launches no shell and inherits neither loader variables nor the user's
/// PhotoRec configuration directory. The unreaped leader pins process-group
/// ownership until its descendants have been stopped and the leader is reaped.
struct RecoveryProcessRunner {
    static func run(
        executableURL: URL,
        arguments: [String],
        workingDirectory: URL,
        workingDirectoryDescriptor: Int32? = nil,
        timeout: TimeInterval,
        maximumStdoutBytes: Int = 8 * 1_024 * 1_024,
        maximumStderrBytes: Int = 64 * 1_024,
        monitor: () throws -> Void = {}
    ) throws -> RecoveryProcessOutcome {
        try Task.checkCancellation()
        guard timeout.isFinite, timeout > 0, timeout <= 3_600,
              (0...64 * 1_024 * 1_024).contains(maximumStdoutBytes),
              (0...64 * 1_024 * 1_024).contains(maximumStderrBytes),
              validFileURL(workingDirectory), arguments.count <= 256,
              arguments.allSatisfy({ !$0.utf8.contains(0) && $0.utf8.count <= 65_536 }),
              arguments.reduce(0, { $0 + $1.utf8.count }) <= 1_048_576 else {
            throw RecoveryError.invalidOptions
        }
        guard validFileURL(executableURL), Darwin.access(executableURL.path, X_OK) == 0 else {
            throw RecoveryError.unavailable
        }
        var executableMetadata = stat()
        guard Darwin.lstat(executableURL.path, &executableMetadata) == 0,
              executableMetadata.st_mode & S_IFMT == S_IFREG else {
            throw RecoveryError.unavailable
        }
        // Dup a borrowed descriptor: callers retain ownership of their FD and
        // this invocation retains a directory pin even if its path is renamed.
        let directory = try directoryDescriptor(workingDirectory, borrowed: workingDirectoryDescriptor)
        defer { Darwin.close(directory) }
        let channels = try RecoveryChannels()
        defer { channels.close() }
        let deadline = uptime() + timeout
        try monitor()
        try Task.checkCancellation()
        guard uptime() < deadline else { throw RecoveryError.timeout }
        let child = try spawn(
            executable: executableURL, arguments: arguments, workspace: workingDirectory,
            directoryDescriptor: directory, channels: channels
        )
        channels.closeChildEnds()
        var ownsUnreapedLeader = true
        defer {
            if ownsUnreapedLeader { terminateAndReap(child) }
        }
        var stdout = Data(), stderr = Data()
        var stdoutEOF = false, stderrEOF = false
        var exitStatus: Int32?
        var nextMonitor = uptime() + 0.25
        var buffer = [UInt8](repeating: 0, count: 32_768)
        while true {
            try Task.checkCancellation()
            let now = uptime()
            guard now < deadline else { throw RecoveryError.timeout }
            if now >= nextMonitor {
                try monitor()
                nextMonitor = uptime() + 0.25
                try Task.checkCancellation()
                guard uptime() < deadline else { throw RecoveryError.timeout }
            }
            if exitStatus == nil {
                var information = siginfo_t()
                let observed = Darwin.waitid(P_PID, id_t(child), &information, WEXITED | WNOHANG | WNOWAIT)
                if observed == 0 && information.si_pid == child {
                    exitStatus = information.si_code == CLD_EXITED
                        ? information.si_status : 128 + information.si_status
                } else if observed < 0 && errno != EINTR {
                    // An external reaper would invalidate our PID ownership.
                    // Never signal a group whose leader is no longer pinned.
                    if errno == ECHILD { ownsUnreapedLeader = false }
                    throw RecoveryError.launchFailed
                }
            }
            var polling = [
                pollfd(fd: stdoutEOF ? -1 : channels.outputRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: stderrEOF ? -1 : channels.errorRead, events: Int16(POLLIN), revents: 0)
            ]
            let polled = Darwin.poll(&polling, nfds_t(polling.count), exitStatus == nil ? 20 : 0)
            if polled < 0 {
                if errno == EINTR { continue }
                throw RecoveryError.launchFailed
            }
            // Once the leader exits, its writes are already in the pipes.
            // Drain them without waiting for a descendant to close inherited
            // writers; deferred shutdown also applies to successful tools.
            var outputQuiescent = stdoutEOF, errorQuiescent = stderrEOF
            for index in 0..<2 where polling[index].revents != 0 || exitStatus != nil {
                if (index == 0 && stdoutEOF) || (index == 1 && stderrEOF) { continue }
                guard polling[index].revents & Int16(POLLNVAL) == 0 else { throw RecoveryError.launchFailed }
                let descriptor = index == 0 ? channels.outputRead : channels.errorRead
                let state: DrainState
                if index == 0 {
                    state = try drain(descriptor, into: &stdout, maximum: maximumStdoutBytes, buffer: &buffer)
                    stdoutEOF = state == .eof
                    outputQuiescent = state != .yielded
                } else {
                    state = try drain(descriptor, into: &stderr, maximum: maximumStderrBytes, buffer: &buffer)
                    stderrEOF = state == .eof
                    errorQuiescent = state != .yielded
                }
            }
            if let exitStatus, outputQuiescent && errorQuiescent {
                try monitor()
                try Task.checkCancellation()
                guard uptime() < deadline else { throw RecoveryError.timeout }
                return RecoveryProcessOutcome(exitStatus: exitStatus, stdout: stdout, stderr: stderr)
            }
        }
    }

    private static func validFileURL(_ url: URL) -> Bool {
        url.isFileURL && (url.host == nil || url.host == "" || url.host == "localhost")
            && url.path.hasPrefix("/") && !url.path.utf8.contains(0)
    }

    private static func directoryDescriptor(_ url: URL, borrowed: Int32?) throws -> Int32 {
        let descriptor: Int32
        if let borrowed {
            guard borrowed >= 0 else { throw RecoveryError.invalidOptions }
            descriptor = Darwin.fcntl(borrowed, F_DUPFD_CLOEXEC, 3)
        } else {
            let opened = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard opened >= 0 else { throw RecoveryError.launchFailed }
            do { descriptor = try RecoveryChannels.aboveStdio(opened) }
            catch { Darwin.close(opened); throw error }
        }
        var metadata = stat()
        guard descriptor >= 0 else { throw RecoveryError.launchFailed }
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
            Darwin.close(descriptor)
            throw RecoveryError.launchFailed
        }
        return descriptor
    }

    private static func spawn(
        executable: URL, arguments: [String], workspace: URL,
        directoryDescriptor: Int32, channels: RecoveryChannels
    ) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw RecoveryError.launchFailed }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw RecoveryError.launchFailed }
        defer { posix_spawnattr_destroy(&attributes) }
        // This action precedes every close and stdio mapping. A renamed or
        // replaced workspace path cannot redirect the child's relative files.
        guard posix_spawn_file_actions_addfchdir_np(&actions, directoryDescriptor) == 0 else {
            throw RecoveryError.launchFailed
        }
        for (source, target) in [
            (channels.nullRead, STDIN_FILENO), (channels.outputWrite, STDOUT_FILENO),
            (channels.errorWrite, STDERR_FILENO)
        ] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw RecoveryError.launchFailed }
        }
        for descriptor in channels.allDescriptors + [directoryDescriptor] {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else { throw RecoveryError.launchFailed }
        }
        var defaults = sigset_t(), mask = sigset_t()
        sigemptyset(&defaults); sigemptyset(&mask)
        for signal in [SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, signal) }
        guard posix_spawnattr_setflags(&attributes, Int16(
            POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
        )) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else { throw RecoveryError.launchFailed }
        let argumentPointers = ([executable.path] + arguments).map { strdup($0) }
        let environmentPointers = environment(workspace: workspace).sorted { $0.key < $1.key }
            .map { strdup("\($0.key)=\($0.value)") }
        defer { for pointer in argumentPointers + environmentPointers { free(pointer) } }
        guard (argumentPointers + environmentPointers).allSatisfy({ $0 != nil }) else { throw RecoveryError.launchFailed }
        var argv = argumentPointers + [nil], env = environmentPointers + [nil]
        var child: pid_t = 0
        let status = argv.withUnsafeMutableBufferPointer { argv in
            env.withUnsafeMutableBufferPointer { env in
                posix_spawn(&child, executable.path, &actions, &attributes, argv.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw RecoveryError.launchFailed }
        return child
    }

    static func environment(workspace: URL) -> [String: String] {
        ["PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
         "HOME": workspace.path, "TMPDIR": workspace.path + "/"]
    }

    private enum DrainState { case eof, empty, yielded }

    private static func drain(
        _ descriptor: Int32, into output: inout Data, maximum: Int, buffer: inout [UInt8]
    ) throws -> DrainState {
        // Bounded work lets cancellation, output-file monitoring and the
        // monotonic deadline progress even if the tool continuously writes.
        for _ in 0..<8 {
            let received = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if received > 0 {
                guard received <= maximum - output.count else { throw RecoveryError.outputLimit }
                output.append(contentsOf: buffer.prefix(received))
            } else if received == 0 { return .eof }
            else if errno == EINTR { continue }
            else if errno == EAGAIN || errno == EWOULDBLOCK { return .empty }
            else { throw RecoveryError.launchFailed }
        }
        return .yielded
    }

    private static func terminateAndReap(_ child: pid_t) {
        // Never reap during the grace period: that would allow the PGID to be
        // reused before the final group signal. Only this request's PGID is used.
        _ = Darwin.kill(-child, SIGTERM)
        let grace = uptime() + 0.25
        while uptime() < grace { _ = Darwin.poll(nil, 0, 10) }
        _ = Darwin.kill(-child, SIGKILL)
        var status: Int32 = 0
        while Darwin.waitpid(child, &status, 0) < 0 && errno == EINTR {}
    }

    private static func uptime() -> Double {
        Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
    }
}

private final class RecoveryChannels {
    var nullRead: Int32 = -1
    var outputRead: Int32 = -1, outputWrite: Int32 = -1
    var errorRead: Int32 = -1, errorWrite: Int32 = -1
    var allDescriptors: [Int32] {
        [nullRead, outputRead, outputWrite, errorRead, errorWrite].filter { $0 >= 0 }
    }

    init() throws {
        do {
            let opened = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
            guard opened >= 0 else { throw RecoveryError.launchFailed }
            do { nullRead = try Self.aboveStdio(opened) }
            catch { Darwin.close(opened); throw error }
            (outputRead, outputWrite) = try Self.pipe()
            (errorRead, errorWrite) = try Self.pipe()
            for descriptor in allDescriptors {
                guard Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else { throw RecoveryError.launchFailed }
            }
            for descriptor in [outputRead, errorRead] {
                let flags = Darwin.fcntl(descriptor, F_GETFL)
                guard flags >= 0, Darwin.fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                    throw RecoveryError.launchFailed
                }
            }
        } catch { close(); throw error }
    }

    static func aboveStdio(_ descriptor: Int32) throws -> Int32 {
        if descriptor > STDERR_FILENO { return descriptor }
        let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 3)
        guard duplicate >= 0 else { throw RecoveryError.launchFailed }
        Darwin.close(descriptor)
        return duplicate
    }

    private static func pipe() throws -> (Int32, Int32) {
        var descriptors: [Int32] = [-1, -1]
        guard Darwin.pipe(&descriptors) == 0 else { throw RecoveryError.launchFailed }
        do {
            descriptors[0] = try aboveStdio(descriptors[0])
            descriptors[1] = try aboveStdio(descriptors[1])
            return (descriptors[0], descriptors[1])
        } catch {
            for descriptor in descriptors where descriptor >= 0 { Darwin.close(descriptor) }
            throw error
        }
    }

    func closeChildEnds() {
        for descriptor in [nullRead, outputWrite, errorWrite] where descriptor >= 0 { Darwin.close(descriptor) }
        nullRead = -1; outputWrite = -1; errorWrite = -1
    }

    func close() {
        for descriptor in allDescriptors { Darwin.close(descriptor) }
        nullRead = -1; outputRead = -1; outputWrite = -1; errorRead = -1; errorWrite = -1
    }
}
