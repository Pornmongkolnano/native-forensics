import Darwin
import Foundation
import Dispatch
@testable import ForensicsCore

enum EngineHeartbeatStall: String, Sendable, CaseIterable { case silent, partialBytes, stderr }

/// Lets an independent failure guard distinguish an active operation from a
/// completed operation whose test continuation has not been scheduled yet.
final class EngineHeartbeatOperationCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false
    func markFinished() { lock.withLock { finished = true } }
    var isFinished: Bool { lock.withLock { finished } }
}

/// Test-only cadence is expressed relative to the same stage deadline used by
/// both success and silent-gap controls. Real callbacks acknowledge each frame.
struct EngineHeartbeatFixturePlan: Sendable {
    let count: Int
    let interval: Double
    let inactivity: Double
    let startup: Double
    let stage = "heartbeat-proof"

    init(count: Int = 81, interval: Double = 0.05, inactivity: Double = 1.5, startup: Double = 10) {
        precondition((2...255).contains(count) && interval > 0 && inactivity >= 10 * interval)
        self.count = count; self.interval = interval; self.inactivity = inactivity; self.startup = startup
    }

    var minimumSpan: Double { Double(count - 1) * interval }
    var timeouts: EngineTimeouts {
        .init(startup: startup, inactivity: inactivity, cancellationGrace: 0.1, terminationGrace: 0.1)
    }

    func body(acknowledgements: URL, terminalMarker: URL, silentMarker: URL? = nil,
              stall: EngineHeartbeatStall = .silent) throws -> String {
        let ackPath = try Self.quote(acknowledgements.path), terminalPath = try Self.quote(terminalMarker.path)
        let final: String
        if let silentMarker {
            let initialNuisance: String, hold: String
            switch stall {
            case .silent:
                initialNuisance = "pass"
                hold = "acknowledgements.read(1)"
            case .partialBytes:
                initialNuisance = "sys.stdout.write('{'); sys.stdout.flush()"
                hold = "while True:\n    sys.stdout.write('{'); sys.stdout.flush(); time.sleep(\(interval))"
            case .stderr:
                initialNuisance = "sys.stderr.write('x' * 4096); sys.stderr.flush()"
                hold = "while True:\n    sys.stderr.write('x' * 4096); sys.stderr.flush(); time.sleep(\(interval))"
            }
            final = """
            \(initialNuisance)
            with open(\(try Self.quote(silentMarker.path)), 'x') as marker:
                marker.write('validated-prefix-then-\(stall.rawValue)')
            # Parent leaves this FIFO open and sends no further ACK. A helper
            # ending naturally cannot satisfy the timeout expectation.
            \(hold)
            with open(\(terminalPath), 'x') as marker:
                marker.write('unexpected-silence-release')
            emit('completed', fileCount=0)
            """
        } else {
            final = """
            with open(\(terminalPath), 'x') as marker:
                marker.write('all-heartbeats-acknowledged')
            emit('completed', fileCount=0)
            """
        }
        let completion = final.components(separatedBy: "\n").map { "    " + $0 }.joined(separator: "\n")
        return """
        with open(\(ackPath), 'rb', buffering=0) as acknowledgements:
            for ordinal in range(\(count)):
                emit('progress', stage='\(stage)', completed=ordinal, total=\(count), unit='beats')
                if acknowledgements.read(1) != bytes([ordinal]):
                    raise RuntimeError('heartbeat acknowledgement ordinal mismatch')
                if ordinal + 1 < \(count):
                    time.sleep(\(interval))
        \(completion)
        """
    }

    private static func quote(_ value: String) throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }
}

/// At the end of the first validated read pass, releases the helper and waits
/// for its flushed tail before holding the clock beyond inactivity. No further
/// read in that pass can refresh the recorded production activity timestamp.
final class EngineBufferedActivityPause: @unchecked Sendable {
    private let lock = NSLock()
    private let terminal: URL
    private let recorded: EngineHeartbeatRecorder
    private let acknowledgements: EngineHeartbeatAcknowledgements
    private let seconds: Double
    private var started = false, finished = false, failure: String?
    private var elapsed: Double = 0

    init(terminal: URL, recorded: EngineHeartbeatRecorder, acknowledgements: EngineHeartbeatAcknowledgements, seconds: Double) {
        self.terminal = terminal; self.recorded = recorded; self.acknowledgements = acknowledgements; self.seconds = seconds
    }

    func checkpoint() {
        guard recorded.observations.count == 1 else { return }
        let shouldPause = lock.withLock { () -> Bool in
            guard !started else { return false }; started = true; return true
        }
        guard shouldPause else { return }
        do { try acknowledgements.send(0) }
        catch {
            lock.withLock { failure = "Cannot release the helper after the first read pass: \(error)" }; return
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        while !FileManager.default.fileExists(atPath: terminal.path), DispatchTime.now().uptimeNanoseconds < deadline {
            Thread.sleep(forTimeInterval: 0.005)
        }
        guard FileManager.default.fileExists(atPath: terminal.path) else {
            lock.withLock { failure = "Helper never flushed its terminal marker." }; return
        }
        let before = DispatchTime.now().uptimeNanoseconds
        Thread.sleep(forTimeInterval: seconds)
        lock.withLock {
            elapsed = Double(DispatchTime.now().uptimeNanoseconds - before) / 1_000_000_000
            finished = true
        }
    }

    var didPause: Bool { lock.withLock { finished } }
    var elapsedSeconds: Double { lock.withLock { elapsed } }
    var failureMessage: String? { lock.withLock { failure } }
}

/// O_RDWR keeps the named control pipe open during helper startup. CLOEXEC
/// prevents inheriting the parent's endpoint; writes never block the callback.
final class EngineHeartbeatAcknowledgements: @unchecked Sendable {
    let url: URL
    private let lock = NSLock()
    private var descriptor: Int32 = -1

    init(in folder: URL) throws {
        url = folder.appendingPathComponent("heartbeat-ack.fifo")
        guard Darwin.mkfifo(url.path, mode_t(0o600)) == 0 else { throw FileAccess.posixError("Cannot create heartbeat test pipe") }
        descriptor = Darwin.open(url.path, O_RDWR | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw FileAccess.posixError("Cannot open heartbeat test pipe") }
    }

    func send(_ ordinal: UInt8) throws {
        try lock.withLock {
            guard descriptor >= 0 else { throw EngineError.protocolViolation("Heartbeat test pipe is closed.") }
            var byte = ordinal
            while true {
                let written = Darwin.write(descriptor, &byte, 1)
                if written == 1 { return }
                if written < 0 && errno == EINTR { continue }
                throw FileAccess.posixError("Cannot acknowledge heartbeat test frame")
            }
        }
    }

    func close() { lock.withLock { if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 } } }
    deinit { close() }
}

final class EngineHeartbeatRecorder: @unchecked Sendable {
    struct Observation: Sendable {
        let completed: Int64
        let total: Int64?
        let unit: String
        let at: Double
    }
    private let lock = NSLock()
    private let pipe: EngineHeartbeatAcknowledgements
    private let stage: String
    private var recorded: [Observation] = []
    private var failures: [String] = []

    init(pipe: EngineHeartbeatAcknowledgements, stage: String) { self.pipe = pipe; self.stage = stage }

    func observe(_ progress: EngineProgress, acknowledge: Bool = true) {
        guard progress.stage == stage else { return }
        let now = Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
        lock.withLock { recorded.append(.init(completed: progress.completed, total: progress.total, unit: progress.unit, at: now)) }
        guard acknowledge else { return }
        do {
            guard let ordinal = UInt8(exactly: progress.completed) else {
                throw EngineError.protocolViolation("Heartbeat ordinal cannot be acknowledged.")
            }
            try pipe.send(ordinal)
        } catch { lock.withLock { failures.append(String(describing: error)) } }
    }

    var observations: [Observation] { lock.withLock { recorded } }
    var acknowledgementFailures: [String] { lock.withLock { failures } }
    var gaps: [Double] {
        let values = observations
        return zip(values, values.dropFirst()).map { $1.at - $0.at }
    }
    var diagnostic: String {
        let values = observations
        let span = values.first.flatMap { first in values.last.map { $0.at - first.at } } ?? 0
        return "validated=\(values.count), span=\(span)s, maxGap=\(gaps.max() ?? 0)s, ackErrors=\(acknowledgementFailures)"
    }
}
