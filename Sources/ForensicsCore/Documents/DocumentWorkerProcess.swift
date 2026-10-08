import Darwin
import Foundation
import NFDecoderIPC

/// A broker-owned, unreaped child pins process ownership until final cleanup.
/// The fixed signed helper inherits the broker sandbox; no evidence descriptor,
/// host path, loader override or credential is passed to it.
final class DocumentWorkerProcess: @unchecked Sendable {
    let processIdentifier: Int32
    let session: DocumentXPCSessionRequest
    private let cancellation: DocumentCancellation
    private let channels: DocumentChannels
    private var reaped = false
    private var stdoutBuffer = Data()
    private var stderrBytes = 0
    private var stdoutEOF = false, stderrEOF = false

    init(configuration: DocumentWorkerExecutableConfiguration, session: DocumentXPCSessionRequest,
         cancellation: DocumentCancellation) throws {
        self.session = session; self.cancellation = cancellation
        let requestChannels = try DocumentChannels()
        self.channels = requestChannels
        do {
            self.processIdentifier = try Self.spawn(configuration.executableURL, channels: requestChannels)
            requestChannels.closeChildEnds()
        } catch { requestChannels.close(); throw error }
    }

    deinit { try? stopAndReap(); channels.close() }

    func handshake() throws -> DocumentWorkerHello {
        let frame = try DocumentWorkerWire.encodeFrame(JSONEncoder().encode(session))
        let bytes = try exchange([frame], maximumResponseBytes: DocumentXPCWire.maximumControlBytes, final: false)
        let hello: DocumentWorkerHello
        do { hello = try JSONDecoder().decode(DocumentWorkerHello.self, from: bytes) }
        catch { throw DocumentAnalysisError.invalidResponse }
        guard hello.protocolVersion == DocumentXPCWire.protocolVersion, hello.nonce == session.nonce,
              hello.processIdentifier == processIdentifier,
              NFDecoderAuditTokenPID(hello.auditToken) == processIdentifier,
              NFDecoderAuditTokenUID(hello.auditToken) == Darwin.geteuid() else { throw DocumentAnalysisError.invalidResponse }
        return hello
    }

    func decode(_ data: Data, request: DocumentXPCDecodeRequest) throws -> Data {
        guard request.isValid, request.nonce == session.nonce, request.sourceByteCount == Int64(data.count) else {
            throw DocumentAnalysisError.invalidInput
        }
        let control = try DocumentWorkerWire.encodeFrame(JSONEncoder().encode(request))
        return try exchange([control, data], maximumResponseBytes: DocumentLimits.maximumResponseBytes, final: true)
    }

    func stopAndReap() throws {
        guard !reaped else { return }
        // Closing the still-open request pipe independently revokes a worker
        // whose parser is blocked. Signals also target the pinned owned leader
        // itself, even if it changed its group, and its original request group.
        channels.closeInput()
        if try ownedChildState() == .alreadyReaped { finishAlreadyReaped(); return }
        _ = Darwin.kill(-processIdentifier, SIGTERM)
        _ = Darwin.kill(processIdentifier, SIGTERM)
        if try ownedChildState() == .alive {
            let grace = DocumentXPCTransport.uptime() + 0.15
            while DocumentXPCTransport.uptime() < grace { _ = Darwin.poll(nil, 0, 5) }
        }
        if try ownedChildState() == .alreadyReaped { finishAlreadyReaped(); return }
        _ = Darwin.kill(-processIdentifier, SIGKILL)
        _ = Darwin.kill(processIdentifier, SIGKILL)
        var status: Int32 = 0
        var waited: pid_t
        repeat { waited = Darwin.waitpid(processIdentifier, &status, 0) } while waited < 0 && errno == EINTR
        guard waited == processIdentifier || (waited < 0 && errno == ECHILD) else {
            throw DocumentAnalysisError.cleanupFailed
        }
        reaped = true
        channels.close()
    }

    private enum OwnedChildState: Equatable { case alive, exited, alreadyReaped }

    private func ownedChildState() throws -> OwnedChildState {
        var observed = siginfo_t(), result: Int32
        repeat { result = Darwin.waitid(P_PID, id_t(processIdentifier), &observed, WEXITED | WNOHANG | WNOWAIT) }
        while result < 0 && errno == EINTR
        if result < 0, errno == ECHILD { return .alreadyReaped }
        guard result == 0 else { throw DocumentAnalysisError.cleanupFailed }
        guard observed.si_pid == 0 || observed.si_pid == processIdentifier else { throw DocumentAnalysisError.cleanupFailed }
        return observed.si_pid == processIdentifier ? .exited : .alive
    }

    private func finishAlreadyReaped() {
        // Losing the unreaped ownership pin never authorizes a cached PID signal.
        reaped = true
        channels.close()
    }

    private func exchange(_ segments: [Data], maximumResponseBytes: Int, final: Bool) throws -> Data {
        var segmentIndex = 0, offset = 0
        var buffer = [UInt8](repeating: 0, count: 32_768)
        let deadline = Double(session.deadlineUptimeNanoseconds) / 1_000_000_000
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            if DocumentXPCTransport.uptime() >= deadline { throw DocumentAnalysisError.timeout }
            while segmentIndex < segments.count && offset == segments[segmentIndex].count {
                segmentIndex += 1; offset = 0
            }
            let sent = segmentIndex == segments.count
            let payload = try framedPayload(maximumBytes: maximumResponseBytes)
            if let payload, sent {
                if !final {
                    guard !stdoutEOF else { throw DocumentAnalysisError.invalidResponse }
                    stdoutBuffer.removeAll(keepingCapacity: false)
                    return payload
                }
                if stdoutEOF && stderrEOF {
                    var info = siginfo_t()
                    let observed = Darwin.waitid(P_PID, id_t(processIdentifier), &info, WEXITED | WNOHANG | WNOWAIT)
                    if observed == 0, info.si_pid == processIdentifier {
                        guard info.si_code == CLD_EXITED, info.si_status == 0 else { throw DocumentAnalysisError.invalidResponse }
                        return payload
                    }
                    if observed < 0 && errno != EINTR { throw DocumentAnalysisError.invalidResponse }
                }
            }
            if stdoutEOF && payload == nil { throw DocumentAnalysisError.invalidResponse }
            var polling = [
                pollfd(fd: stdoutEOF ? -1 : channels.outputRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: stderrEOF ? -1 : channels.errorRead, events: Int16(POLLIN), revents: 0),
                pollfd(fd: sent ? -1 : channels.inputWrite, events: Int16(POLLOUT), revents: 0)
            ]
            let result = Darwin.poll(&polling, nfds_t(polling.count), 5)
            if result < 0 { if errno == EINTR { continue }; throw DocumentAnalysisError.invalidResponse }
            for index in 0..<2 where polling[index].revents != 0 {
                for _ in 0..<8 {
                    let fd = index == 0 ? channels.outputRead : channels.errorRead
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if count > 0 {
                        if index == 0 {
                            guard stdoutBuffer.count + count <= maximumResponseBytes + 4 else { throw DocumentAnalysisError.outputLimit }
                            stdoutBuffer.append(contentsOf: buffer.prefix(count))
                        } else {
                            stderrBytes += count
                            guard stderrBytes <= 64 * 1_024 else { throw DocumentAnalysisError.outputLimit }
                        }
                    } else if count == 0 {
                        if index == 0 { stdoutEOF = true } else { stderrEOF = true }
                        break
                    } else if errno == EINTR { continue }
                    else if errno == EAGAIN || errno == EWOULDBLOCK { break }
                    else { throw DocumentAnalysisError.invalidResponse }
                }
            }
            if !sent, polling[2].revents != 0 {
                if polling[2].revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 { throw DocumentAnalysisError.invalidResponse }
                let data = segments[segmentIndex]
                let count = data.withUnsafeBytes {
                    Darwin.write(channels.inputWrite, $0.baseAddress!.advanced(by: offset), min(32_768, data.count - offset))
                }
                if count > 0 { offset += count }
                else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw DocumentAnalysisError.invalidResponse }
            }
        }
    }

    private func framedPayload(maximumBytes: Int) throws -> Data? {
        guard stdoutBuffer.count >= 4 else { return nil }
        let length = Int(stdoutBuffer.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
        guard length <= maximumBytes else { throw DocumentAnalysisError.outputLimit }
        guard stdoutBuffer.count <= length + 4 else { throw DocumentAnalysisError.invalidResponse }
        guard stdoutBuffer.count == length + 4 else { return nil }
        return Data(stdoutBuffer.dropFirst(4))
    }

    private static func spawn(_ executable: URL, channels: DocumentChannels) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw DocumentAnalysisError.launchFailed }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw DocumentAnalysisError.launchFailed }
        defer { posix_spawnattr_destroy(&attributes) }
        for (source, target) in [(channels.inputRead, STDIN_FILENO), (channels.outputWrite, STDOUT_FILENO), (channels.errorWrite, STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, source, target) == 0 else { throw DocumentAnalysisError.launchFailed }
        }
        for descriptor in channels.allDescriptors {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else { throw DocumentAnalysisError.launchFailed }
        }
        var defaults = sigset_t(), mask = sigset_t()
        sigemptyset(&defaults); sigemptyset(&mask)
        for signal in [SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, signal) }
        guard posix_spawnattr_setflags(&attributes,
                Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0 else { throw DocumentAnalysisError.launchFailed }
        let arguments = [executable.path].map { strdup($0) }
        let workerEnvironmentStrings: [String] = ["PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"]
        let variables = workerEnvironmentStrings.map { strdup($0) }
        defer { for pointer in arguments + variables { free(pointer) } }
        var argv = arguments + [nil], environment = variables + [nil], child: pid_t = 0
        let result = argv.withUnsafeMutableBufferPointer { argumentBuffer in
            environment.withUnsafeMutableBufferPointer { environmentBuffer in
                posix_spawn(&child, executable.path, &actions, &attributes, argumentBuffer.baseAddress!, environmentBuffer.baseAddress!)
            }
        }
        guard result == 0, child > 0 else { throw DocumentAnalysisError.launchFailed }
        return child
    }
}
