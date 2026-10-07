import Darwin
import Foundation

/// Explicit spawn isolation closes unrelated descriptors in the child even
/// when another thread has not yet marked its newly created pipe CLOEXEC.
/// The unreaped group leader pins ownership until all cleanup has completed.
final class EngineProcess {
    let processIdentifier: pid_t
    private var reaped = false
    private var observedExit: siginfo_t?

    init(executable: URL, channels: EngineChannels) throws {
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw EngineError.helperFailed("Cannot initialize native engine launch.")
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw EngineError.helperFailed("Cannot initialize native engine launch attributes.")
        }
        defer { posix_spawnattr_destroy(&attributes) }
        for (source, target) in [(channels.inputRead, STDIN_FILENO),
                                 (channels.outputWrite, STDOUT_FILENO),
                                 (channels.errorWrite, STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else {
                throw EngineError.helperFailed("Cannot configure native engine standard streams.")
            }
        }
        for descriptor in channels.allDescriptors {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
                throw EngineError.helperFailed("Cannot isolate native engine descriptors.")
            }
        }
        var defaults = sigset_t(), mask = sigset_t()
        sigemptyset(&defaults); sigemptyset(&mask)
        for signal in [SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGPIPE, SIGCHLD] {
            sigaddset(&defaults, signal)
        }
        guard posix_spawnattr_setflags(&attributes, Int16(
            POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP |
            POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
        )) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else {
            throw EngineError.helperFailed("Cannot isolate native engine process ownership.")
        }
        // Preserve the previous Foundation launch environment. Descriptor and
        // signal isolation do not change the helper's runtime configuration.
        let argumentPointers = [strdup(executable.path)]
        let environmentPointers = ProcessInfo.processInfo.environment.map { strdup("\($0.key)=\($0.value)") }
        defer { for pointer in argumentPointers + environmentPointers { free(pointer) } }
        guard (argumentPointers + environmentPointers).allSatisfy({ $0 != nil }) else {
            throw EngineError.helperFailed("Cannot allocate native engine launch arguments.")
        }
        var argv = argumentPointers + [nil], environment = environmentPointers + [nil]
        var child: pid_t = 0
        let status = argv.withUnsafeMutableBufferPointer { arguments in
            environment.withUnsafeMutableBufferPointer { env in
                posix_spawn(&child, executable.path, &actions, &attributes,
                            arguments.baseAddress!, env.baseAddress!)
            }
        }
        guard status == 0, child > 0 else {
            throw EngineError.helperFailed("Cannot launch native engine (POSIX status \(status)).")
        }
        processIdentifier = child
    }

    func isRunning() throws -> Bool {
        guard !reaped else { return false }
        var exit = siginfo_t()
        let status = Darwin.waitid(P_PID, id_t(processIdentifier), &exit, WEXITED | WNOHANG | WNOWAIT)
        if status < 0 {
            if errno == EINTR { return true }
            // Another reaper must not let deferred cleanup signal a PID or
            // process group that no longer belongs to this request.
            if errno == ECHILD { reaped = true }
            throw FileAccess.posixError("Cannot observe native engine exit")
        }
        if exit.si_pid == processIdentifier { observedExit = exit; return false }
        return true
    }

    var terminationStatus: Int32 {
        guard let exit = observedExit else { return -1 }
        return exit.si_code == CLD_EXITED ? exit.si_status : -1
    }

    func signal(_ signal: Int32) {
        guard !reaped else { return }
        _ = Darwin.kill(-processIdentifier, signal)
    }

    func terminateAndReap(grace: TimeInterval) {
        guard !reaped else { return }
        _ = try? isRunning()
        guard !reaped else { return }
        signal(SIGTERM)
        let deadline = Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 + grace
        while (try? isRunning()) == true &&
              Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 < deadline {
            _ = Darwin.poll(nil, 0, 20)
        }
        guard !reaped else { return }
        // A helper may have exited while descendants still hold stdio. Kill
        // only its owned group before reaping and releasing the leader's PID.
        signal(SIGKILL)
        var status: Int32 = 0
        while Darwin.waitpid(processIdentifier, &status, 0) < 0 && errno == EINTR {}
        reaped = true
    }
}

final class EngineChannels {
    var inputRead: Int32 = -1, inputWrite: Int32 = -1
    var outputRead: Int32 = -1, outputWrite: Int32 = -1
    var errorRead: Int32 = -1, errorWrite: Int32 = -1
    var allDescriptors: [Int32] {
        [inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite].filter { $0 >= 0 }
    }

    init() throws {
        do {
            (inputRead, inputWrite) = try Self.pipe()
            (outputRead, outputWrite) = try Self.pipe()
            (errorRead, errorWrite) = try Self.pipe()
            for descriptor in allDescriptors {
                guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
                    throw FileAccess.posixError("Cannot protect native engine pipe inheritance")
                }
            }
            for descriptor in [inputWrite, outputRead, errorRead] {
                let flags = fcntl(descriptor, F_GETFL)
                guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                    throw FileAccess.posixError("Cannot configure native engine pipe")
                }
            }
            guard fcntl(inputWrite, F_SETNOSIGPIPE, 1) == 0 else {
                throw FileAccess.posixError("Cannot protect native engine request pipe")
            }
        } catch { close(); throw error }
    }

    private static func pipe() throws -> (Int32, Int32) {
        var descriptors: [Int32] = [-1, -1]
        guard Darwin.pipe(&descriptors) == 0 else {
            throw FileAccess.posixError("Cannot create native engine pipe")
        }
        do {
            for index in descriptors.indices where descriptors[index] <= STDERR_FILENO {
                // Closed host stdio must not let an addclose action later
                // close the helper's newly duplicated descriptor 0, 1 or 2.
                let duplicate = fcntl(descriptors[index], F_DUPFD_CLOEXEC, STDERR_FILENO + 1)
                guard duplicate >= 0 else {
                    throw FileAccess.posixError("Cannot isolate native engine pipe from standard streams")
                }
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
