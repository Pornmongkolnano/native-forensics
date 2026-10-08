import Darwin
import Foundation

struct DocumentProcessRunner {
    let helperURL: URL
    let timeout: TimeInterval
    let cancellation: DocumentCancellation
    let started: (@Sendable (Int32) -> Void)?
    let sandboxPolicy: DocumentSandboxPolicy

    func run(_ input: DocumentInput) throws -> DocumentAnalysis {
        if cancellation.isCancelled { throw CancellationError() }
        let source = try DocumentSourceHandle.open(input, cancellation: cancellation)
        defer { Darwin.close(source.descriptor) }
        let executable = helperURL.standardizedFileURL
        var metadata = stat()
        guard executable.isFileURL, executable.host == nil || executable.host == "" || executable.host == "localhost",
              !executable.path.utf8.contains(0), Darwin.lstat(executable.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG, Darwin.access(executable.path, X_OK) == 0 else {
            throw DocumentAnalysisError.unavailable
        }
        let decoderReceipt = try DocumentDecoderExecutableReceipt.inspect(executable, cancellation: cancellation)
        let request = try JSONEncoder().encode(input)
        guard request.count <= 16 * 1_024 else { throw DocumentAnalysisError.invalidInput }
        let channels = try DocumentChannels()
        defer { channels.close() }
        let child = try spawn(executable, input: input, channels: channels)
        channels.closeChildEnds()
        defer { terminateAndReap(child) }
        started?(child)
        do {
            let response = try exchange(request, child: child, channels: channels)
            let analysis: DocumentAnalysis
            do { analysis = try JSONDecoder().decode(DocumentAnalysis.self, from: response) }
            catch { throw DocumentAnalysisError.invalidResponse }
            try DocumentAnalysisClient.validate(analysis, for: input)
            try source.verify(input, cancellation: cancellation)
            try decoderReceipt.verify(cancellation: cancellation)
            return try analysis.attachingProvenance(executableSHA256: decoderReceipt.sha256,
                codeSigningCDHash: nil, isolation: sandboxPolicy == .required ? .requiredDevelopmentSeatbelt : .testFixture,
                timeout: timeout)
        } catch {
            if cancellation.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func spawn(_ executable: URL, input: DocumentInput, channels: DocumentChannels) throws -> pid_t {
        let launch = try DocumentSandbox.launch(helper: executable, input: input.fileURL, policy: sandboxPolicy)
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw DocumentAnalysisError.launchFailed }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw DocumentAnalysisError.launchFailed }
        defer { posix_spawnattr_destroy(&attributes) }
        for (source, target) in [(channels.inputRead, STDIN_FILENO), (channels.outputWrite, STDOUT_FILENO), (channels.errorWrite, STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw DocumentAnalysisError.launchFailed }
        }
        for fd in channels.allDescriptors {
            guard posix_spawn_file_actions_addclose(&actions, fd) == 0 else { throw DocumentAnalysisError.launchFailed }
        }
        var defaults = sigset_t(), mask = sigset_t()
        sigemptyset(&defaults); sigemptyset(&mask)
        for signal in [SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, signal) }
        guard posix_spawnattr_setflags(&attributes,
              Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else { throw DocumentAnalysisError.launchFailed }
        let argvPointers = launch.arguments.map { strdup($0) }
        // No credentials, loader overrides, proxy settings or evidence paths
        // enter the process environment. The request arrives only over stdin.
        let envStrings: [String] = ["PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"]
        let envPointers = envStrings.map { strdup($0) }
        defer { for pointer in argvPointers + envPointers { free(pointer) } }
        var argv = argvPointers + [nil], environment = envPointers + [nil], child: pid_t = 0
        let status = argv.withUnsafeMutableBufferPointer { arguments in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&child, launch.executable.path, &actions, &attributes, arguments.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, child > 0 else { throw DocumentAnalysisError.launchFailed }
        return child
    }

    private func exchange(_ request: Data, child: pid_t, channels: DocumentChannels) throws -> Data {
        var offset = 0, errorBytes = 0, response = Data()
        var stdoutEOF = false, stderrEOF = false, stdinClosed = false
        var buffer = [UInt8](repeating: 0, count: 32_768)
        let deadline = uptime() + timeout
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            if uptime() >= deadline { throw DocumentAnalysisError.timeout }
            if stdoutEOF && stderrEOF {
                var exit = siginfo_t()
                let result = Darwin.waitid(P_PID, id_t(child), &exit, WEXITED | WNOHANG | WNOWAIT)
                if result == 0 && exit.si_pid == child {
                    guard offset == request.count, exit.si_code == CLD_EXITED, exit.si_status == 0 else {
                        throw DocumentAnalysisError.invalidResponse
                    }
                    return response
                }
                if result < 0 && errno != EINTR { throw DocumentAnalysisError.invalidResponse }
            }
            var polling = [
                pollfd(fd: stdoutEOF ? -1 : channels.outputRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: stderrEOF ? -1 : channels.errorRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: stdinClosed ? -1 : channels.inputWrite, events: Int16(POLLOUT), revents: 0)
            ]
            let polled = Darwin.poll(&polling, nfds_t(polling.count), 20)
            if polled < 0 { if errno == EINTR { continue }; throw DocumentAnalysisError.invalidResponse }
            for index in 0..<2 where polling[index].revents != 0 {
                for _ in 0..<8 {
                    let fd = index == 0 ? channels.outputRead : channels.errorRead
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if count > 0 {
                        if index == 0 {
                            guard response.count + count <= DocumentLimits.maximumResponseBytes else { throw DocumentAnalysisError.outputLimit }
                            response.append(contentsOf: buffer.prefix(count))
                        } else {
                            errorBytes += count
                            guard errorBytes <= 64 * 1_024 else { throw DocumentAnalysisError.outputLimit }
                        }
                    } else if count == 0 {
                        if index == 0 { stdoutEOF = true } else { stderrEOF = true }
                        break
                    } else if errno == EINTR { continue }
                    else if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    else { throw DocumentAnalysisError.invalidResponse }
                }
            }
            if !stdinClosed && polling[2].revents != 0 {
                if polling[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                    guard offset == request.count else { throw DocumentAnalysisError.invalidResponse }
                    channels.closeInput(); stdinClosed = true
                } else {
                    let count = request.withUnsafeBytes {
                        Darwin.write(channels.inputWrite, $0.baseAddress?.advanced(by: offset), request.count - offset)
                    }
                    if count > 0 { offset += count }
                    else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
                        throw DocumentAnalysisError.invalidResponse
                    }
                }
            }
            if !stdinClosed && offset == request.count { channels.closeInput(); stdinClosed = true }
        }
    }

    private func terminateAndReap(_ child: pid_t) {
        // The unreaped leader pins ownership while the request group is stopped.
        _ = Darwin.kill(-child, SIGTERM)
        var exit = siginfo_t()
        if Darwin.waitid(P_PID, id_t(child), &exit, WEXITED | WNOHANG | WNOWAIT) != 0 || exit.si_pid != child {
            let grace = uptime() + 0.15
            while uptime() < grace { _ = Darwin.poll(nil, 0, 10) }
        }
        _ = Darwin.kill(-child, SIGKILL)
        var status: Int32 = 0
        while Darwin.waitpid(child, &status, 0) < 0 && errno == EINTR {}
    }

    private func uptime() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }
}

/// A development Seatbelt backend, not an App Sandbox entitlement or a claim of
/// future macOS compatibility. The only public client mode is `required`.
enum DocumentSandboxPolicy: Sendable {
    case required
    case disabledForTesting
}

enum DocumentSandbox {
    static let launcherURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")

    /// No writable location, internet/Unix sockets, Mach service lookups, fork,
    /// or executable other than this request's decoder is allowed. Stdio pipes
    /// are the only inherited descriptors. Data reads are exact input/helper
    /// plus Apple runtime/font/resources. Metadata traversal is intentionally
    /// wider than data reads; file contents outside these grants stay denied.
    /// Dyld needs the root directory and its narrowly listed signature fcntls.
    static let profile = """
    (version 1)
    (deny default)
    (allow syscall*)
    (allow mach-bootstrap)
    (allow sysctl-read)
    (allow signal (target self))
    (allow file-read-metadata)
    (allow file-read* (literal "/"))
    (allow system-fcntl (fcntl-command F_ADDFILESIGS_RETURN F_CHECK_LV F_GETPATH))
    (allow system-mac-syscall (require-all (mac-policy-name "Sandbox") (mac-syscall-number 2)))
    (allow process-exec (literal (param "NF_HELPER")))
    (allow file-read-data
        (literal (param "NF_INPUT"))
        (literal (param "NF_HELPER"))
        (subpath "/System/Library")
        (subpath "/System/Cryptexes/OS")
        (subpath "/System/Volumes/Preboot/Cryptexes/OS")
        (subpath "/usr/lib")
        (subpath "/usr/share"))
    (allow file-map-executable
        (literal (param "NF_HELPER"))
        (subpath "/System/Library")
        (subpath "/System/Cryptexes/OS")
        (subpath "/System/Volumes/Preboot/Cryptexes/OS")
        (subpath "/usr/lib"))
    """

    struct Launch {
        let executable: URL
        let arguments: [String]
    }

    static func launch(helper: URL, input: URL, policy: DocumentSandboxPolicy,
                       launcher: URL = launcherURL) throws -> Launch {
        if policy == .disabledForTesting {
            return Launch(executable: helper, arguments: [helper.path])
        }
        var metadata = stat()
        guard launcher.isFileURL, Darwin.lstat(launcher.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG, Darwin.access(launcher.path, X_OK) == 0 else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        // -D arguments are opaque profile parameters, not code interpolation.
        // Use the POSIX canonical pathname that Seatbelt actually matches.
        // Foundation resolvingSymlinksInPath may retain the friendly /var or
        // /tmp alias instead of /private/var or /private/tmp, even after asking
        // it to resolve symlinks. The source keeps its separately held identity.
        let canonicalHelper = try canonicalPath(helper, failure: .unavailable)
        let canonicalInput = try canonicalPath(input, failure: .sourceChanged)
        return Launch(executable: launcher, arguments: [launcher.path,
            "-D", "NF_HELPER=" + canonicalHelper, "-D", "NF_INPUT=" + canonicalInput,
            "-p", profile, canonicalHelper])
    }

    private static func canonicalPath(_ url: URL, failure: DocumentAnalysisError) throws -> String {
        guard let resolved = Darwin.realpath(url.path, nil) else { throw failure }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}

final class DocumentChannels {
    var inputRead: Int32 = -1, inputWrite: Int32 = -1
    var outputRead: Int32 = -1, outputWrite: Int32 = -1
    var errorRead: Int32 = -1, errorWrite: Int32 = -1
    var allDescriptors: [Int32] { [inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite].filter { $0 >= 0 } }
    init() throws {
        do {
            (inputRead, inputWrite) = try Self.pipe()
            (outputRead, outputWrite) = try Self.pipe()
            (errorRead, errorWrite) = try Self.pipe()
            for fd in allDescriptors {
                guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw DocumentAnalysisError.launchFailed }
            }
            for fd in [inputWrite, outputRead, errorRead] {
                let flags = fcntl(fd, F_GETFL)
                guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw DocumentAnalysisError.launchFailed }
            }
            guard fcntl(inputWrite, F_SETNOSIGPIPE, 1) == 0 else { throw DocumentAnalysisError.launchFailed }
        } catch { close(); throw error }
    }
    static func pipe() throws -> (Int32, Int32) {
        var fds: [Int32] = [-1, -1]
        guard Darwin.pipe(&fds) == 0 else { throw DocumentAnalysisError.launchFailed }
        do {
            for index in fds.indices where fds[index] <= STDERR_FILENO {
                // A host with closed stdio must not allocate request channels
                // at 0/1/2: later addclose actions would close the child's
                // newly duplicated standard streams instead of old pipe ends.
                let duplicate = fcntl(fds[index], F_DUPFD_CLOEXEC, STDERR_FILENO + 1)
                guard duplicate >= 0 else { throw DocumentAnalysisError.launchFailed }
                Darwin.close(fds[index])
                fds[index] = duplicate
            }
            return (fds[0], fds[1])
        } catch {
            for fd in fds { Darwin.close(fd) }
            throw error
        }
    }
    func closeChildEnds() {
        for fd in [inputRead, outputWrite, errorWrite] where fd >= 0 { Darwin.close(fd) }
        inputRead = -1; outputWrite = -1; errorWrite = -1
    }
    func closeInput() { if inputWrite >= 0 { Darwin.close(inputWrite); inputWrite = -1 } }
    func close() {
        for fd in allDescriptors { Darwin.close(fd) }
        inputRead = -1; inputWrite = -1; outputRead = -1; outputWrite = -1; errorRead = -1; errorWrite = -1
    }
}
