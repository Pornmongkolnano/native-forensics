import Darwin
import Foundation
import NFDecoderIPC
import Security

/// One host request owns a fresh parser child of the persistent sandbox broker.
/// NSXPC invalidation alone is never mistaken for physical parser termination;
/// a kernel observer is registered and live-authenticated before input is sent.
struct DocumentXPCTransport {
    let timeout: TimeInterval
    let cancellation: DocumentCancellation
    let started: (@Sendable (Int32) -> Void)?
    let lifecycle: (@Sendable (DocumentDecoderLifecycleEvent) -> Void)?

    func run(_ input: DocumentInput) throws -> DocumentAnalysis {
        try DocumentXPCOwnershipGate.shared.acquire(cancellation: cancellation)
        defer { DocumentXPCOwnershipGate.shared.release() }
        if cancellation.isCancelled { throw CancellationError() }
        let source = try DocumentSourceHandle.open(input, cancellation: cancellation)
        defer { Darwin.close(source.descriptor) }
        let bytes = try source.snapshot(input, cancellation: cancellation)
        let configuration = try DocumentXPCServiceConfiguration.load(cancellation: cancellation)
        let connection = NSXPCConnection(serviceName: NFDocumentDecoderXPCServiceName)
        connection.setCodeSigningRequirement(configuration.requirementString)
        connection.remoteObjectInterface = NSXPCInterface(with: NFDocumentDecoderXPC.self)
        let failed = DocumentXPCFailureState()
        connection.interruptionHandler = { failed.fail(.invalidResponse) }
        connection.invalidationHandler = { failed.fail(.launchFailed) }
        connection.resume()
        defer { connection.invalidate() }
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let deadline = Self.uptime() + timeout
        var peer: DocumentXPCOwnedPeer?
        var beginSent = false
        let outcome: Result<DocumentAnalysis, any Error>
        do {
            let begin = DocumentXPCSessionRequest(nonce: nonce, timeoutMilliseconds: Int(ceil(timeout * 1_000)),
                                                  deadlineUptimeNanoseconds: UInt64(deadline * 1_000_000_000))
            let request = try Self.controlData(begin)
            let handshakeData = try reply(connection: connection, failed: failed, deadline: deadline,
                maximumBytes: DocumentXPCWire.maximumControlBytes) { proxy, callback in
                    beginSent = true
                    proxy.beginSession(request, reply: callback)
                }
            let handshake: DocumentXPCSessionResponse
            do { handshake = try JSONDecoder().decode(DocumentXPCSessionResponse.self, from: handshakeData) }
            catch { throw DocumentAnalysisError.invalidResponse }
            peer = try configuration.validate(handshake, connection: connection, nonce: nonce,
                                              deadline: deadline, cancellation: cancellation)
            started?(handshake.worker.processIdentifier)
            lifecycle?(.started(processIdentifier: handshake.worker.processIdentifier, backend: .appSandboxXPC))
            if cancellation.isCancelled { throw CancellationError() }
            let decodeRequest = DocumentXPCDecodeRequest(nonce: nonce, sourceSHA256: input.expectedSHA256,
                                                          sourceByteCount: input.expectedByteCount)
            let decodeControl = try Self.controlData(decodeRequest)
            let responseData = try reply(connection: connection, failed: failed, deadline: deadline,
                maximumBytes: DocumentLimits.maximumResponseBytes) { proxy, callback in
                    proxy.decodeDocument(bytes, request: decodeControl, reply: callback)
                }
            let analysis = try Self.decodeResponse(responseData, request: decodeRequest, input: input)
            try source.verify(input, cancellation: cancellation)
            try configuration.executableReceipt.verify(cancellation: cancellation)
            try configuration.worker.executableReceipt.verify(cancellation: cancellation)
            guard let peer else { throw DocumentAnalysisError.invalidResponse }
            outcome = .success(try analysis.attachingProvenance(executableSHA256: configuration.worker.executableReceipt.sha256,
                codeSigningCDHash: peer.codeSigningCDHash, isolation: .appSandboxXPC, timeout: timeout,
                brokerExecutableSHA256: configuration.executableReceipt.sha256,
                brokerCodeSigningCDHash: CaseWorkCoding.hex(configuration.codeSigningCDHash)))
        } catch { outcome = .failure(error) }

        // A matching nonce revokes only this connection's owned child. The
        // broker stops/reaps it; the registered kernel observer proves physical
        // exit even across exec, without any host PID signalling.
        if let peer {
            if let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in }) as? NFDocumentDecoderXPC {
                proxy.cancelSession(Data(nonce.utf8))
            }
            connection.invalidate()
            do {
                try peer.exitObserver.waitUntilExited(deadline: deadline + 2)
                lifecycle?(.exited(processIdentifier: peer.processIdentifier))
            } catch {
                // Do not start another request in a possibly live old process.
                // No host PID signal or unrestricted backend can bypass this.
                DocumentXPCOwnershipGate.shared.poison()
                throw DocumentAnalysisError.cleanupFailed
            }
        } else if beginSent {
            // No document bytes were sent, but a worker may already exist.
            // Require the verified broker's nonce-bound reap acknowledgement;
            // invalidating the connection alone is not ownership cleanup proof.
            do {
                let cleanupDeadline = min(deadline + 2, Self.uptime() + 2)
                let drain = DocumentXPCSessionRequest(nonce: nonce, timeoutMilliseconds: 2_000,
                    deadlineUptimeNanoseconds: UInt64(cleanupDeadline * 1_000_000_000), drainOnly: true)
                let control = try Self.controlData(drain)
                let bytes = try reply(connection: connection, failed: failed, deadline: cleanupDeadline,
                    maximumBytes: DocumentXPCWire.maximumControlBytes, allowCancelled: true) { proxy, callback in
                        proxy.beginSession(control, reply: callback)
                    }
                let receipt = try JSONDecoder().decode(DocumentXPCDrainResponse.self, from: bytes)
                try configuration.validateDrain(receipt, connection: connection, nonce: nonce)
            } catch {
                DocumentXPCOwnershipGate.shared.poison()
                throw DocumentAnalysisError.cleanupFailed
            }
        }
        if case .failure(let error) = outcome, error as? DocumentAnalysisError == .cleanupFailed {
            DocumentXPCOwnershipGate.shared.poison()
        }
        if cancellation.isCancelled { throw CancellationError() }
        return try outcome.get()
    }

    private func reply(connection: NSXPCConnection, failed: DocumentXPCFailureState, deadline: Double,
                       maximumBytes: Int, allowCancelled: Bool = false,
                       send: (any NFDocumentDecoderXPC, @escaping @Sendable (Data) -> Void) -> Void) throws -> Data {
        if !allowCancelled && cancellation.isCancelled { throw CancellationError() }
        if Self.uptime() >= deadline { throw DocumentAnalysisError.timeout }
        let box = DocumentXPCReplyBox(maximumBytes: maximumBytes)
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in box.fail(.invalidResponse) }) as? NFDocumentDecoderXPC else {
            throw DocumentAnalysisError.launchFailed
        }
        send(proxy) { box.receive($0) }
        while true {
            if !allowCancelled && cancellation.isCancelled { throw CancellationError() }
            if Self.uptime() >= deadline { throw DocumentAnalysisError.timeout }
            if let result = box.take() { return try result.get() }
            if let failure = failed.value { throw failure }
            _ = Darwin.poll(nil, 0, 10)
        }
    }

    static func controlData<T: Encodable>(_ value: T) throws -> Data {
        let data = try JSONEncoder().encode(value)
        guard data.count <= DocumentXPCWire.maximumControlBytes else { throw DocumentAnalysisError.invalidInput }
        return data
    }

    static func decodeResponse(_ data: Data, request: DocumentXPCDecodeRequest, input: DocumentInput) throws -> DocumentAnalysis {
        guard !data.isEmpty, data.count <= DocumentLimits.maximumResponseBytes else {
            throw data.count > DocumentLimits.maximumResponseBytes ? DocumentAnalysisError.outputLimit : .invalidResponse
        }
        let response: DocumentXPCDecodeResponse
        do { response = try JSONDecoder().decode(DocumentXPCDecodeResponse.self, from: data) }
        catch { throw DocumentAnalysisError.invalidResponse }
        guard response.protocolVersion == DocumentXPCWire.protocolVersion,
              response.nonce == request.nonce, response.sourceSHA256 == request.sourceSHA256,
              response.sourceByteCount == request.sourceByteCount else { throw DocumentAnalysisError.invalidResponse }
        if let failure = response.failureCode {
            guard response.analysis == nil else { throw DocumentAnalysisError.invalidResponse }
            switch failure {
            case "INTEGRITY_MISMATCH": throw DocumentAnalysisError.integrityMismatch
            case "OUTPUT_LIMIT": throw DocumentAnalysisError.outputLimit
            case "INVALID_INPUT": throw DocumentAnalysisError.invalidInput
            case "TIMEOUT": throw DocumentAnalysisError.timeout
            case "CANCELLED": throw CancellationError()
            case "CLEANUP_FAILED": throw DocumentAnalysisError.cleanupFailed
            default: throw DocumentAnalysisError.invalidResponse
            }
        }
        guard let analysis = response.analysis else { throw DocumentAnalysisError.invalidResponse }
        try DocumentAnalysisClient.validate(analysis, for: input)
        return analysis
    }

    static func uptime() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }
}

private final class DocumentXPCReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private let maximumBytes: Int
    private var result: Result<Data, DocumentAnalysisError>?
    init(maximumBytes: Int) { self.maximumBytes = maximumBytes }
    func receive(_ data: Data) {
        lock.withLock {
            guard result == nil else { return }
            result = data.count > maximumBytes ? .failure(.outputLimit) : .success(data)
        }
    }
    func fail(_ error: DocumentAnalysisError) { lock.withLock { if result == nil { result = .failure(error) } } }
    func take() -> Result<Data, DocumentAnalysisError>? { lock.withLock { result } }
}

private final class DocumentXPCFailureState: @unchecked Sendable {
    private let lock = NSLock()
    private var failure: DocumentAnalysisError?
    var value: DocumentAnalysisError? { lock.withLock { failure } }
    func fail(_ error: DocumentAnalysisError) { lock.withLock { if failure == nil { failure = error } } }
}

final class DocumentXPCOwnershipGate: @unchecked Sendable {
    static let shared = DocumentXPCOwnershipGate()
    private let semaphore = DispatchSemaphore(value: 1)
    private let lock = NSLock()
    private var unavailable = false
    func acquire(cancellation: DocumentCancellation) throws {
        while true {
            if cancellation.isCancelled { throw CancellationError() }
            if lock.withLock({ unavailable }) { throw DocumentAnalysisError.cleanupFailed }
            if semaphore.wait(timeout: .now() + .milliseconds(10)) == .success {
                if lock.withLock({ unavailable }) { semaphore.signal(); throw DocumentAnalysisError.cleanupFailed }
                if cancellation.isCancelled { semaphore.signal(); throw CancellationError() }
                return
            }
        }
    }
    func release() { semaphore.signal() }
    func poison() { lock.withLock { unavailable = true } }
}

/// The parser is a fresh child owned by the broker. A registered live-verified
/// kernel observer proves physical exit; audit-token absence alone does not.
private struct DocumentXPCOwnedPeer {
    let processIdentifier: Int32
    let codeSigningCDHash: String
    let exitObserver: DocumentProcessExitObserver
}

struct DocumentXPCServiceConfiguration {
    let executableURL: URL
    let requirement: SecRequirement
    let requirementString: String
    let codeSigningCDHash: Data
    let executableReceipt: DocumentDecoderExecutableReceipt
    let worker: DocumentWorkerExecutableConfiguration

    static var serviceBundleURL: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/XPCServices/NFDocumentDecoderXPC.xpc", isDirectory: true)
    }
    static var isPresent: Bool {
        Bundle.main.bundleURL.pathExtension == "app"
            && FileManager.default.isExecutableFile(atPath: serviceBundleURL.appendingPathComponent("Contents/MacOS/NFDocumentDecoderXPC").path)
            && FileManager.default.isExecutableFile(atPath: serviceBundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoderWorker").path)
    }

    static func load(cancellation: DocumentCancellation) throws -> DocumentXPCServiceConfiguration {
        guard isPresent, let bundle = Bundle(url: serviceBundleURL),
              bundle.bundleIdentifier == NFDocumentDecoderXPCServiceName,
              bundle.object(forInfoDictionaryKey: "CFBundlePackageType") as? String == "XPC!",
              let executable = bundle.executableURL, executable.lastPathComponent == "NFDocumentDecoderXPC" else {
            throw DocumentAnalysisError.unavailable
        }
        var code: SecStaticCode?
        let flags = SecCSFlags(rawValue: 0)
        guard SecStaticCodeCreateWithPath(serviceBundleURL as CFURL, flags, &code) == errSecSuccess,
              let code, SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        let info = try signingInformation(code)
        try validateEntitlements(info)
        guard info[kSecCodeInfoIdentifier as String] as? String == NFDocumentDecoderXPCServiceName else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        var requirement: SecRequirement?, text: CFString?
        guard SecCodeCopyDesignatedRequirement(code, flags, &requirement) == errSecSuccess,
              let requirement, SecRequirementCopyString(requirement, flags, &text) == errSecSuccess,
              let text else { throw DocumentAnalysisError.sandboxUnavailable }
        guard let cdhash = info[kSecCodeInfoUnique as String] as? Data, [20, 32].contains(cdhash.count) else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        let resolvedExecutable = executable.resolvingSymlinksInPath()
        let receipt = try DocumentDecoderExecutableReceipt.inspect(resolvedExecutable, cancellation: cancellation)
        let worker = try DocumentWorkerExecutableConfiguration.load(at:
            serviceBundleURL.appendingPathComponent("Contents/Helpers/NFDocumentDecoderWorker"), cancellation: cancellation)
        return DocumentXPCServiceConfiguration(executableURL: resolvedExecutable,
            requirement: requirement, requirementString: text as String, codeSigningCDHash: cdhash,
            executableReceipt: receipt, worker: worker)
    }

    fileprivate func validate(_ handshake: DocumentXPCSessionResponse, connection: NSXPCConnection,
                              nonce: String, deadline: Double,
                              cancellation: DocumentCancellation) throws -> DocumentXPCOwnedPeer {
        guard handshake.protocolVersion == DocumentXPCWire.protocolVersion, handshake.nonce == nonce else {
            throw DocumentAnalysisError.invalidResponse
        }
        try verifyBrokerIdentity(processIdentifier: handshake.processIdentifier, auditToken: handshake.auditToken,
                                 connection: connection)
        let workerConfiguration = worker
        let hello = handshake.worker
        try workerConfiguration.verifyLive(hello, nonce: nonce)
        let observer = DocumentProcessExitObserver(processIdentifier: hello.processIdentifier) {
            try workerConfiguration.verifyLive(hello, nonce: nonce)
        }
        try observer.awaitTrustedRegistration(deadline: deadline, cancellation: cancellation)
        guard !observer.hasExited else { throw DocumentAnalysisError.invalidResponse }
        return DocumentXPCOwnedPeer(processIdentifier: hello.processIdentifier,
            codeSigningCDHash: CaseWorkCoding.hex(workerConfiguration.codeSigningCDHash), exitObserver: observer)
    }

    fileprivate func validateDrain(_ receipt: DocumentXPCDrainResponse, connection: NSXPCConnection, nonce: String) throws {
        guard receipt.protocolVersion == DocumentXPCWire.protocolVersion, receipt.nonce == nonce, receipt.workerStopped else {
            throw DocumentAnalysisError.cleanupFailed
        }
        try verifyBrokerIdentity(processIdentifier: receipt.processIdentifier, auditToken: receipt.auditToken,
                                 connection: connection)
    }

    private func verifyBrokerIdentity(processIdentifier: Int32, auditToken: Data, connection: NSXPCConnection) throws {
        let pid = NFDecoderAuditTokenPID(auditToken)
        guard processIdentifier > 0, processIdentifier == connection.processIdentifier,
              pid == processIdentifier, NFDecoderAuditTokenUID(auditToken) == Darwin.geteuid(),
              connection.effectiveUserIdentifier == Darwin.geteuid() else { throw DocumentAnalysisError.invalidResponse }
        var peer: SecCode?
        let flags = SecCSFlags(rawValue: 0)
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: auditToken] as CFDictionary,
                                            flags, &peer) == errSecSuccess,
              let peer, SecCodeCheckValidity(peer, flags, requirement) == errSecSuccess else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
        let info = try Self.signingInformation(unsafeBitCast(peer, to: SecStaticCode.self))
        try Self.validateEntitlements(info)
        guard let peerURL = info[kSecCodeInfoMainExecutable as String] as? URL,
              peerURL.resolvingSymlinksInPath() == executableURL,
              info[kSecCodeInfoUnique as String] as? Data == codeSigningCDHash else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
    }

    private static func signingInformation(_ code: SecStaticCode) throws -> [String: Any] {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dictionary = info as? [String: Any] else { throw DocumentAnalysisError.sandboxUnavailable }
        return dictionary
    }

    static func validateEntitlements(_ info: [String: Any]) throws {
        guard let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              entitlements.count == 1,
              let sandbox = entitlements["com.apple.security.app-sandbox"] as? NSNumber,
              CFGetTypeID(sandbox) == CFBooleanGetTypeID(), sandbox.boolValue else {
            throw DocumentAnalysisError.sandboxUnavailable
        }
    }
}
