import Darwin
import Dispatch
import Foundation

/// A process source is trusted only after its asynchronous kernel registration
/// AND fresh verification of the original live audit-token peer. It observes
/// actual process exit across exec, without adopting/signalling a reused PID.
final class DocumentProcessExitObserver: @unchecked Sendable {
    private let source: any DispatchSourceProcess
    private let verifyLive: @Sendable () throws -> Void
    private let lock = NSLock()
    private var registration: Result<Void, DocumentAnalysisError>?
    private var exitObserved = false

    init(processIdentifier: Int32, verifyLive: @escaping @Sendable () throws -> Void) {
        self.verifyLive = verifyLive
        source = DispatchSource.makeProcessSource(identifier: processIdentifier, eventMask: .exit,
            queue: DispatchQueue(label: "org.nativeforensics.decoder-exit-\(UUID().uuidString)"))
        source.setRegistrationHandler { [weak self] in
            guard let self else { return }
            do {
                try self.verifyLive()
                self.lock.withLock { self.registration = .success(()) }
            } catch {
                self.lock.withLock { self.registration = .failure(.sandboxUnavailable) }
            }
        }
        source.setEventHandler { [weak self] in
            guard let self, self.source.data.contains(.exit) else { return }
            self.lock.withLock { self.exitObserved = true }
        }
        source.activate()
    }

    deinit { source.cancel() }

    func awaitTrustedRegistration(deadline: Double, cancellation: DocumentCancellation) throws {
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            if let result = lock.withLock({ registration }) { try result.get(); return }
            if DocumentXPCTransport.uptime() >= deadline { throw DocumentAnalysisError.timeout }
            _ = Darwin.poll(nil, 0, 5)
        }
    }

    var hasExited: Bool {
        lock.withLock {
            guard case .success? = registration else { return false }
            return exitObserved
        }
    }

    func waitUntilExited(deadline: Double) throws {
        while true {
            guard case .success? = lock.withLock({ registration }) else { throw DocumentAnalysisError.cleanupFailed }
            if hasExited { return }
            if DocumentXPCTransport.uptime() >= deadline { throw DocumentAnalysisError.cleanupFailed }
            _ = Darwin.poll(nil, 0, 5)
        }
    }
}
