import Darwin
import Foundation

/// Each CLI receives an owned process group at spawn time. Failure, timeout
/// and cancellation stop only that group, then reap its leader before return.
struct CodexProcessRunner {
    let executableURL: URL
    let timeout: TimeInterval
    let cancellation: CodexCancellation

    func run(prompt: String) throws -> CodexRunOutcome {
        if cancellation.isCancelled { throw CancellationError() }
        guard executableURL.isFileURL, executableURL.host == nil || executableURL.host == "" || executableURL.host == "localhost",
              !executableURL.path.utf8.contains(0), Darwin.access(executableURL.path, X_OK) == 0 else {
            throw CodexAnalysisError.unavailable
        }
        let executable = executableURL.resolvingSymlinksInPath()
        var metadata = stat()
        guard Darwin.lstat(executable.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG else {
            throw CodexAnalysisError.unavailable
        }
        let scratch = try CodexScratch()
        defer { scratch.remove() }
        let arguments = CodexAnalysisClient.arguments(schemaURL: scratch.schema)
        let channels = try CodexChannels()
        defer { channels.close() }
        let child = try spawn(executable: executable, arguments: arguments, workspace: scratch.workspace, channels: channels)
        channels.closeChildEnds()
        defer { terminateAndReap(child) }
        do {
            let result = try exchange(prompt: prompt, child: child, channels: channels)
            let response = try result.stream.finish(exitStatus: result.status)
            return CodexRunOutcome(response: response, startupDiagnosticCount: result.stream.startupDiagnosticCount)
        } catch {
            if cancellation.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func spawn(executable: URL, arguments: [String], workspace: URL, channels: CodexChannels) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw CodexAnalysisError.launchFailed }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw CodexAnalysisError.launchFailed }
        defer { posix_spawnattr_destroy(&attributes) }
        let mappings = [(channels.inputRead, STDIN_FILENO), (channels.outputWrite, STDOUT_FILENO), (channels.errorWrite, STDERR_FILENO)]
        for (source, target) in mappings {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw CodexAnalysisError.launchFailed }
        }
        for descriptor in channels.allDescriptors {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else { throw CodexAnalysisError.launchFailed }
        }
        var signalDefaults = sigset_t()
        var signalMask = sigset_t()
        sigemptyset(&signalDefaults)
        sigemptyset(&signalMask)
        for signal in [SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&signalDefaults, signal) }
        // Close every unrelated parent descriptor atomically at spawn, even
        // descriptors created concurrently before their FD_CLOEXEC is set.
        // The explicit dup2 actions retain only this request's three stdio
        // channels; another engine job's pipe writers must never leak here.
        guard posix_spawn_file_actions_addchdir_np(&actions, workspace.path) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0,
              posix_spawnattr_setsigdefault(&attributes, &signalDefaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &signalMask) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else { throw CodexAnalysisError.launchFailed }
        let argumentPointers = ([executable.path] + arguments).map { strdup($0) }
        // Keep only the variables needed to find the existing ChatGPT account
        // and system runtime. API keys, provider endpoints and loader overrides
        // must not flow from the desktop process into this subprocess.
        let environmentPointers = Self.environment().map { strdup("\($0.key)=\($0.value)") }
        defer {
            for pointer in argumentPointers + environmentPointers { free(pointer) }
        }
        var argv = argumentPointers + [nil]
        var env = environmentPointers + [nil]
        var child: pid_t = 0
        let status = argv.withUnsafeMutableBufferPointer { arguments in
            env.withUnsafeMutableBufferPointer { environment in
                posix_spawn(&child, executable.path, &actions, &attributes, arguments.baseAddress!, environment.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw CodexAnalysisError.launchFailed }
        return child
    }

    private func exchange(prompt: String, child: pid_t, channels: CodexChannels) throws -> (stream: CodexEventStream, status: Int32) {
        let input = Data(prompt.utf8)
        var offset = 0
        var stdoutEOF = false, stderrEOF = false, stdinClosed = false
        var stderrBytes = 0
        var stream = CodexEventStream()
        var buffer = [UInt8](repeating: 0, count: 32_768)
        let deadline = uptime() + timeout
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            if uptime() >= deadline { throw CodexAnalysisError.timeout }
            if stdoutEOF && stderrEOF {
                var exit = siginfo_t()
                let waited = Darwin.waitid(P_PID, id_t(child), &exit, WEXITED | WNOHANG | WNOWAIT)
                if waited == 0 && exit.si_pid == child {
                    guard offset == input.count else { throw CodexAnalysisError.providerFailed }
                    // Observe without reaping. Even a child that closed the
                    // pipes remains in our group until deferred shutdown; the
                    // unreaped leader pins ownership against PID reuse.
                    let exitStatus = exit.si_code == CLD_EXITED ? exit.si_status : -1
                    return (stream, exitStatus)
                }
                if waited < 0 && errno != EINTR { throw CodexAnalysisError.providerFailed }
            }
            var polling = [
                pollfd(fd: stdoutEOF ? -1 : channels.outputRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: stderrEOF ? -1 : channels.errorRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: stdinClosed ? -1 : channels.inputWrite, events: Int16(POLLOUT), revents: 0)
            ]
            let count = Darwin.poll(&polling, nfds_t(polling.count), 20)
            if count < 0 {
                if errno == EINTR { continue }
                throw CodexAnalysisError.providerFailed
            }
            for index in 0..<2 where polling[index].revents != 0 {
                let descriptor = index == 0 ? channels.outputRead : channels.errorRead
                // Bounded per iteration so an output flood cannot postpone
                // cancellation or the monotonic deadline indefinitely.
                for _ in 0..<8 {
                    let read = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
                    if read > 0 {
                        if index == 0 { try stream.receive(Data(buffer.prefix(read))) }
                        else {
                            // Never retain or expose provider stderr.
                            stderrBytes += read
                            guard stderrBytes <= 64 * 1_024 else { throw CodexAnalysisError.outputLimit }
                        }
                    } else if read == 0 {
                        if index == 0 { stdoutEOF = true } else { stderrEOF = true }
                        break
                    } else if errno == EINTR { continue }
                    else if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    else { throw CodexAnalysisError.providerFailed }
                }
            }
            if !stdinClosed && polling[2].revents != 0 {
                if polling[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                    guard offset == input.count else { throw CodexAnalysisError.providerFailed }
                    channels.closeInput(); stdinClosed = true
                } else {
                    let written = input.withUnsafeBytes {
                        Darwin.write(channels.inputWrite, $0.baseAddress?.advanced(by: offset), input.count - offset)
                    }
                    if written > 0 { offset += written }
                    else if written < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
                        throw CodexAnalysisError.providerFailed
                    }
                }
            }
            if !stdinClosed && offset == input.count {
                channels.closeInput(); stdinClosed = true
            }
        }
    }

    private func terminateAndReap(_ child: pid_t) {
        // The leader has not been reaped, so its PID cannot be reused while
        // signalling the group created specifically for this request.
        _ = Darwin.kill(-child, SIGTERM)
        let grace = uptime() + 0.25
        while uptime() < grace { _ = Darwin.poll(nil, 0, 10) }
        _ = Darwin.kill(-child, SIGKILL)
        var status: Int32 = 0
        while Darwin.waitpid(child, &status, 0) < 0 && errno == EINTR {}
    }

    private func uptime() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }

    static func environment(inherited: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        var environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"]
        for name in ["HOME", "CODEX_HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"] {
            if let value = inherited[name], !value.utf8.contains(0) { environment[name] = value }
        }
        if environment["HOME"] == nil { environment["HOME"] = NSHomeDirectory() }
        return environment
    }
}

struct CodexRunOutcome: Sendable {
    let response: CodexAnalysisResponse
    let startupDiagnosticCount: Int
}

private final class CodexChannels {
    var inputRead: Int32 = -1, inputWrite: Int32 = -1
    var outputRead: Int32 = -1, outputWrite: Int32 = -1
    var errorRead: Int32 = -1, errorWrite: Int32 = -1
    var allDescriptors: [Int32] { [inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite].filter { $0 >= 0 } }

    init() throws {
        do {
            (inputRead, inputWrite) = try Self.pipe()
            (outputRead, outputWrite) = try Self.pipe()
            (errorRead, errorWrite) = try Self.pipe()
            for descriptor in allDescriptors {
                guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else { throw CodexAnalysisError.launchFailed }
            }
            for descriptor in [inputWrite, outputRead, errorRead] {
                let flags = fcntl(descriptor, F_GETFL)
                guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw CodexAnalysisError.launchFailed }
            }
            guard fcntl(inputWrite, F_SETNOSIGPIPE, 1) == 0 else { throw CodexAnalysisError.launchFailed }
        } catch {
            close()
            throw error
        }
    }

    static func pipe() throws -> (Int32, Int32) {
        var descriptors: [Int32] = [-1, -1]
        guard Darwin.pipe(&descriptors) == 0 else { throw CodexAnalysisError.launchFailed }
        do {
            for index in descriptors.indices where descriptors[index] <= STDERR_FILENO {
                // Keep original channel ends distinct from dup2's stdio
                // destinations even when the calling host closed 0, 1 or 2.
                let duplicate = fcntl(descriptors[index], F_DUPFD_CLOEXEC, STDERR_FILENO + 1)
                guard duplicate >= 0 else { throw CodexAnalysisError.launchFailed }
                Darwin.close(descriptors[index])
                descriptors[index] = duplicate
            }
            return (descriptors[0], descriptors[1])
        } catch {
            for descriptor in descriptors { Darwin.close(descriptor) }
            throw error
        }
    }
    func closeChildEnds() {
        for descriptor in [inputRead, outputWrite, errorWrite] where descriptor >= 0 { Darwin.close(descriptor) }
        inputRead = -1; outputWrite = -1; errorWrite = -1
    }
    func closeInput() {
        if inputWrite >= 0 { Darwin.close(inputWrite); inputWrite = -1 }
    }
    func close() {
        for descriptor in allDescriptors { Darwin.close(descriptor) }
        inputRead = -1; inputWrite = -1; outputRead = -1; outputWrite = -1; errorRead = -1; errorWrite = -1
    }
}

private final class CodexScratch {
    let root: URL
    let workspace: URL
    let schema: URL
    private var rootFD: Int32 = -1
    private var rootIdentity: stat?
    private var workspaceIdentity: stat?
    private var schemaIdentity: stat?
    private var cleaned = false

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("native-codex-\(UUID().uuidString)", isDirectory: true)
        workspace = root.appendingPathComponent("workspace", isDirectory: true)
        schema = root.appendingPathComponent("response-schema.json")
        guard Darwin.mkdir(root.path, 0o700) == 0 else { throw CodexAnalysisError.launchFailed }
        do {
            rootFD = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            var rootMetadata = stat()
            guard rootFD >= 0, Darwin.fstat(rootFD, &rootMetadata) == 0 else { throw CodexAnalysisError.launchFailed }
            rootIdentity = rootMetadata
            guard Darwin.mkdirat(rootFD, "workspace", 0o700) == 0 else { throw CodexAnalysisError.launchFailed }
            var workspaceMetadata = stat()
            guard Darwin.fstatat(rootFD, "workspace", &workspaceMetadata, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw CodexAnalysisError.launchFailed
            }
            workspaceIdentity = workspaceMetadata
            let descriptor = Darwin.openat(rootFD, "response-schema.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw CodexAnalysisError.launchFailed }
            defer { Darwin.close(descriptor) }
            var schemaMetadata = stat()
            guard Darwin.fstat(descriptor, &schemaMetadata) == 0 else { throw CodexAnalysisError.launchFailed }
            schemaIdentity = schemaMetadata
            let data = Data(CodexAnalysisClient.responseJSONSchema.utf8)
            let written = data.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
            guard written == data.count else { throw CodexAnalysisError.launchFailed }
        } catch {
            remove()
            throw error
        }
    }

    func remove() {
        guard !cleaned else { return }
        cleaned = true
        // Never recursively remove an untrusted replacement or an unexpected
        // CLI-created entry. Descriptors pin cleanup to our own directory.
        if rootFD >= 0 {
            var current = stat()
            if let schemaIdentity,
               Darwin.fstatat(rootFD, "response-schema.json", &current, AT_SYMLINK_NOFOLLOW) == 0,
               Self.sameObject(current, schemaIdentity) {
                _ = Darwin.unlinkat(rootFD, "response-schema.json", 0)
            }
            if let workspaceIdentity,
               Darwin.fstatat(rootFD, "workspace", &current, AT_SYMLINK_NOFOLLOW) == 0,
               Self.sameObject(current, workspaceIdentity) {
                _ = Darwin.unlinkat(rootFD, "workspace", AT_REMOVEDIR)
            }
            if let rootIdentity, Darwin.lstat(root.path, &current) == 0, Self.sameObject(current, rootIdentity) {
                _ = Darwin.rmdir(root.path)
            }
            Darwin.close(rootFD); rootFD = -1
        }
    }

    private static func sameObject(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev && first.st_ino == second.st_ino && first.st_mode & S_IFMT == second.st_mode & S_IFMT
    }
}
