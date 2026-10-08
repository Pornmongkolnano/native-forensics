import Darwin
import Foundation
import NFDecoderIPC
import Security

/// Exported only by the embedded sandboxed broker. Each connection owns one
/// nonce/job; a process-wide slot admits one fresh worker at a time. Cancelling
/// one connection never stops the broker or a different connection's child.
public final class DocumentXPCBrokerSession: NSObject, NFDocumentDecoderXPC, @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.nativeforensics.document-broker-\(UUID().uuidString)", qos: .userInitiated)
    private let lock = NSLock()
    private let cancellation: DocumentCancellation
    private let configuration: DocumentWorkerExecutableConfiguration
    private var nonce: String?
    private var closed = false
    private var beganDecode = false
    // Accessed only on this connection's serial queue.
    private var worker: DocumentWorkerProcess?
    private var ownsSlot = false

    @available(*, unavailable, message: "Use the verified embedded broker initializer.")
    public override init() { fatalError("Unavailable initializer") }

    public init(verifiedEmbeddedBroker: Bool) throws {
        guard verifiedEmbeddedBroker, Bundle.main.bundleURL.pathExtension == "xpc",
              Bundle.main.bundleIdentifier == NFDocumentDecoderXPCServiceName,
              let task = SecTaskCreateFromSelf(nil),
              let sandbox = SecTaskCopyValueForEntitlement(task, "com.apple.security.app-sandbox" as CFString, nil),
              CFGetTypeID(sandbox) == CFBooleanGetTypeID(), (sandbox as? Bool) == true else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        let cancellation = DocumentCancellation()
        self.cancellation = cancellation
        let workerURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoderWorker")
        configuration = try DocumentWorkerExecutableConfiguration.load(at: workerURL, cancellation: cancellation)
        super.init()
    }

    public func beginSession(_ data: Data, reply: @escaping (Data) -> Void) {
        let now = DispatchTime.now().uptimeNanoseconds
        guard data.count <= DocumentXPCWire.maximumControlBytes,
              let request = try? JSONDecoder().decode(DocumentXPCSessionRequest.self, from: data), request.isValid,
              request.deadlineUptimeNanoseconds > now,
              request.deadlineUptimeNanoseconds - now <= UInt64(request.timeoutMilliseconds) * 1_000_000 else { reply(Data()); return }
        if request.drainOnly == true {
            guard lock.withLock({ nonce == request.nonce }) else { reply(Data()); return }
            cancellation.cancel()
            let responder = DocumentBrokerResponder(reply)
            queue.async {
                let stopped: Bool
                do { try self.cleanupOwnedWorker(); stopped = true } catch { stopped = false }
                guard let token = NFDecoderCurrentAuditToken() else { responder.send(Data()); return }
                let receipt = DocumentXPCDrainResponse(nonce: request.nonce, processIdentifier: Darwin.getpid(),
                                                      auditToken: token, workerStopped: stopped)
                responder.send((try? JSONEncoder().encode(receipt)) ?? Data())
            }
            return
        }
        let accepted = lock.withLock {
            guard !closed, nonce == nil else { return false }
            nonce = request.nonce
            return true
        }
        guard accepted else { reply(Data()); return }
        let responder = DocumentBrokerResponder(reply)
        queue.async {
            do {
                try DocumentBrokerWorkerSlot.shared.acquire(deadline: request.deadlineUptimeNanoseconds, cancellation: self.cancellation)
                self.ownsSlot = true
                if self.cancellation.isCancelled { throw CancellationError() }
                try self.configuration.executableReceipt.verify(cancellation: self.cancellation)
                let child = try DocumentWorkerProcess(configuration: self.configuration, session: request, cancellation: self.cancellation)
                self.worker = child
                self.queue.asyncAfter(deadline: DispatchTime(uptimeNanoseconds: request.deadlineUptimeNanoseconds)) {
                    if self.worker?.session.nonce == request.nonce {
                        self.cancellation.cancel()
                        try? self.cleanupOwnedWorker()
                    }
                }
                let hello = try child.handshake()
                try self.configuration.verifyLive(hello, nonce: request.nonce)
                guard let token = NFDecoderCurrentAuditToken() else { throw DocumentAnalysisError.sandboxUnavailable }
                let response = DocumentXPCSessionResponse(nonce: request.nonce, processIdentifier: Darwin.getpid(),
                                                         auditToken: token, worker: hello)
                let encoded = try JSONEncoder().encode(response)
                guard encoded.count <= DocumentXPCWire.maximumControlBytes else { throw DocumentAnalysisError.outputLimit }
                responder.send(encoded)
            } catch {
                try? self.cleanupOwnedWorker()
                responder.send(Data())
            }
        }
    }

    public func decodeDocument(_ document: Data, request data: Data, reply: @escaping (Data) -> Void) {
        guard document.count <= Int(DocumentLimits.maximumInputBytes), data.count <= DocumentXPCWire.maximumControlBytes,
              let request = try? JSONDecoder().decode(DocumentXPCDecodeRequest.self, from: data), request.isValid,
              request.sourceByteCount == Int64(document.count) else { reply(Data()); return }
        let accepted = lock.withLock {
            guard !closed, nonce == request.nonce, !beganDecode else { return false }
            beganDecode = true
            return true
        }
        guard accepted else { reply(Data()); return }
        let responder = DocumentBrokerResponder(reply)
        queue.async {
            let result: Result<Data, any Error>
            do {
                guard let child = self.worker else { throw DocumentAnalysisError.invalidResponse }
                result = .success(try child.decode(document, request: request))
            } catch { result = .failure(error) }
            // The owned leader remains unreaped until this cleanup. Terminal
            // XPC replies therefore cannot outrun a live parser or reused PID.
            do { try self.cleanupOwnedWorker() }
            catch {
                let failed = DocumentXPCDecodeResponse(request: request, failureCode: "CLEANUP_FAILED")
                responder.send((try? JSONEncoder().encode(failed)) ?? Data())
                return
            }
            switch result {
            case .success(let bytes): responder.send(bytes)
            case .failure(let error):
                let code: String
                if error is CancellationError { code = "CANCELLED" }
                else {
                    switch error as? DocumentAnalysisError {
                    case .timeout: code = "TIMEOUT"
                    case .outputLimit: code = "OUTPUT_LIMIT"
                    case .invalidInput: code = "INVALID_INPUT"
                    default: code = "WORKER_FAILED"
                    }
                }
                let response = DocumentXPCDecodeResponse(request: request, failureCode: code)
                responder.send((try? JSONEncoder().encode(response)) ?? Data())
            }
        }
    }

    public func cancelSession(_ value: Data) {
        guard value.count == 32, lock.withLock({ nonce.map { Data($0.utf8) == value } ?? false }) else { return }
        cancellation.cancel()
        queue.async { try? self.cleanupOwnedWorker() }
    }

    /// NSXPC invalidation revokes only this connection's work. The shared broker
    /// continues serving other connections after the owned child has drained.
    public func invalidate() {
        lock.withLock { closed = true }
        cancellation.cancel()
        queue.async { try? self.cleanupOwnedWorker() }
    }

    private func cleanupOwnedWorker() throws {
        do { try worker?.stopAndReap() }
        catch {
            DocumentBrokerWorkerSlot.shared.poison()
            throw DocumentAnalysisError.cleanupFailed
        }
        worker = nil
        if ownsSlot { ownsSlot = false; DocumentBrokerWorkerSlot.shared.release() }
    }
}

private final class DocumentBrokerResponder: @unchecked Sendable {
    private let reply: (Data) -> Void
    init(_ reply: @escaping (Data) -> Void) { self.reply = reply }
    func send(_ data: Data) { reply(data) }
}

private final class DocumentBrokerWorkerSlot: @unchecked Sendable {
    static let shared = DocumentBrokerWorkerSlot()
    private let semaphore = DispatchSemaphore(value: 1)
    private let lock = NSLock()
    private var poisoned = false
    func poison() { lock.withLock { poisoned = true } }
    func acquire(deadline: UInt64, cancellation: DocumentCancellation) throws {
        while true {
            if lock.withLock({ poisoned }) { throw DocumentAnalysisError.cleanupFailed }
            if cancellation.isCancelled { throw CancellationError() }
            if DispatchTime.now().uptimeNanoseconds >= deadline { throw DocumentAnalysisError.timeout }
            if semaphore.wait(timeout: .now() + .milliseconds(5)) == .success {
                if lock.withLock({ poisoned }) { semaphore.signal(); throw DocumentAnalysisError.cleanupFailed }
                if cancellation.isCancelled { semaphore.signal(); throw CancellationError() }
                if DispatchTime.now().uptimeNanoseconds >= deadline { semaphore.signal(); throw DocumentAnalysisError.timeout }
                return
            }
        }
    }
    func release() { semaphore.signal() }
}
