import Darwin
import Dispatch
import Foundation
import ForensicsCore
import NFDecoderIPC
import NFDocumentDecoding
import Security

@main
enum WorkerMain {
    static func main() {
        guard hasInheritedSandbox(), applyResourceLimits() else { Darwin._exit(1) }
        let watchdog = WorkerDeadline()
        withExtendedLifetime(watchdog) {
            run(watchdog: watchdog)
        }
    }

    private static func run(watchdog: WorkerDeadline) -> Never {
        let input = FileHandle.standardInput
        let output = FileHandle.standardOutput
        var acceptedRequest: DocumentXPCDecodeRequest?
        do {
            let sessionBytes = try DocumentWorkerWire.readFrame(input)
            let session = try JSONDecoder().decode(DocumentXPCSessionRequest.self, from: sessionBytes)
            let now = DispatchTime.now().uptimeNanoseconds
            guard session.isValid, session.drainOnly != true, session.protocolVersion == DocumentWorkerWire.protocolVersion,
                  session.deadlineUptimeNanoseconds > now,
                  session.deadlineUptimeNanoseconds - now <= UInt64(session.timeoutMilliseconds) * 1_000_000,
                  let auditToken = NFDecoderCurrentAuditToken() else { throw DocumentAnalysisError.invalidInput }
            watchdog.replaceDeadline(session.deadlineUptimeNanoseconds)

            // The broker authenticates this kernel identity and its owned child
            // before supplying any attacker-controlled document bytes.
            let hello = DocumentWorkerHello(nonce: session.nonce, processIdentifier: Darwin.getpid(), auditToken: auditToken)
            try output.write(contentsOf: DocumentWorkerWire.encodeFrame(JSONEncoder().encode(hello)))

            let requestBytes = try DocumentWorkerWire.readFrame(input)
            let request = try JSONDecoder().decode(DocumentXPCDecodeRequest.self, from: requestBytes)
            guard request.isValid, request.protocolVersion == DocumentWorkerWire.protocolVersion,
                  request.nonce == session.nonce else { throw DocumentAnalysisError.invalidInput }
            acceptedRequest = request
            requireBeforeDeadline(session.deadlineUptimeNanoseconds)

            let responseBytes = try autoreleasepool {
                let snapshot = try DocumentWorkerWire.readExact(input, count: Int(request.sourceByteCount),
                                                               maxBytes: Int(DocumentLimits.maximumInputBytes))
                requireInputOpenAndIdle()
                // During parsing no more stdin bytes are permitted. Keeping the
                // broker's pipe open makes its closure independently observable.
                installInputMonitor()
                requireBeforeDeadline(session.deadlineUptimeNanoseconds)
                let source = try VerifiedDocument(data: snapshot, expectedSHA256: request.sourceSHA256,
                                                  expectedByteCount: request.sourceByteCount)
                requireBeforeDeadline(session.deadlineUptimeNanoseconds)
                let analysis = DocumentDecoder.decode(source)
                requireBeforeDeadline(session.deadlineUptimeNanoseconds)
                return try DocumentResponseEncoder.encodeXPC(analysis, request: request)
            }
            requireBeforeDeadline(session.deadlineUptimeNanoseconds)
            try output.write(contentsOf: DocumentWorkerWire.encodeFrame(responseBytes,
                                                                        maximumBytes: DocumentLimits.maximumResponseBytes))
            Darwin._exit(0)
        } catch {
            // A malformed initial session has no trusted response identity. Once
            // a decode envelope is accepted, return only a bounded failure code.
            guard let request = acceptedRequest else { Darwin._exit(1) }
            let failureCode: String
            switch error as? DocumentAnalysisError {
            case .integrityMismatch: failureCode = "INTEGRITY_MISMATCH"
            case .outputLimit: failureCode = "OUTPUT_LIMIT"
            default: failureCode = "INVALID_INPUT"
            }
            do {
                let failure = DocumentXPCDecodeResponse(request: request, failureCode: failureCode)
                let bytes = try JSONEncoder().encode(failure)
                try output.write(contentsOf: DocumentWorkerWire.encodeFrame(bytes))
            } catch {
                Darwin._exit(1)
            }
            Darwin._exit(0)
        }
    }

    private static func hasInheritedSandbox() -> Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        for name in ["com.apple.security.app-sandbox", "com.apple.security.inherit"] {
            guard let value = SecTaskCopyValueForEntitlement(task, name as CFString, nil),
                  CFGetTypeID(value) == CFBooleanGetTypeID(), (value as? Bool) == true else { return false }
        }
        return true
    }

    private static func applyResourceLimits() -> Bool {
        var core = rlimit(rlim_cur: 0, rlim_max: 0)
        guard Darwin.setrlimit(RLIMIT_CORE, &core) == 0 else { return false }
        var cpu = rlimit(rlim_cur: 12, rlim_max: 13)
        guard Darwin.setrlimit(RLIMIT_CPU, &cpu) == 0 else { return false }
        var descriptors = rlimit(rlim_cur: 128, rlim_max: 128)
        return Darwin.setrlimit(RLIMIT_NOFILE, &descriptors) == 0
    }

    private static func requireBeforeDeadline(_ deadline: UInt64) {
        guard DispatchTime.now().uptimeNanoseconds < deadline else { Darwin._exit(1) }
    }

    private static func requireInputOpenAndIdle() {
        let terminalEvents = Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL)
        while true {
            var descriptor = pollfd(fd: STDIN_FILENO, events: terminalEvents, revents: 0)
            let result = Darwin.poll(&descriptor, nfds_t(1), 0)
            if result == -1, errno == EINTR { continue }
            guard result >= 0, descriptor.revents & terminalEvents == 0 else { Darwin._exit(1) }
            return
        }
    }

    private static func installInputMonitor() {
        Thread.detachNewThread {
            let terminalEvents = Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL)
            while true {
                var descriptor = pollfd(fd: STDIN_FILENO, events: terminalEvents, revents: 0)
                let result = Darwin.poll(&descriptor, nfds_t(1), -1)
                if result == -1 {
                    if errno == EINTR { continue }
                    Darwin._exit(1)
                }
                if descriptor.revents & terminalEvents != 0 { Darwin._exit(1) }
            }
        }
    }
}

/// Runs independently of the synchronous parser and pipe reads. A queued event
/// from the startup deadline rechecks the replacement deadline before exiting.
private final class WorkerDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private let timer: any DispatchSourceTimer
    private var deadline: UInt64

    init() {
        deadline = DispatchTime.now().uptimeNanoseconds + 15_000_000_000
        timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        timer.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline), leeway: .milliseconds(1))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.lock.withLock {
                guard DispatchTime.now().uptimeNanoseconds < self.deadline else { Darwin._exit(1) }
                self.timer.schedule(deadline: DispatchTime(uptimeNanoseconds: self.deadline), leeway: .milliseconds(1))
            }
        }
        timer.resume()
    }

    func replaceDeadline(_ value: UInt64) {
        lock.withLock {
            deadline = value
            timer.schedule(deadline: DispatchTime(uptimeNanoseconds: value), leeway: .milliseconds(1))
        }
    }
}
