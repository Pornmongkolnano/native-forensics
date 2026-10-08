import Foundation

/// The XPC protocol carries NSData only. These bounded JSON envelopes contain
/// receipts and a nonce, never host paths, bookmarks or sandbox extensions.
public enum DocumentXPCWire {
    public static let protocolVersion = 2
    public static let maximumControlBytes = 4_096

    public static func validNonce(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

public struct DocumentXPCSessionRequest: Codable, Sendable {
    public let protocolVersion: Int
    public let nonce: String
    public let timeoutMilliseconds: Int
    public let deadlineUptimeNanoseconds: UInt64
    /// Cleanup acknowledgement through the same bounded control RPC; no new
    /// command, path or execution surface is introduced.
    public let drainOnly: Bool?
    public init(nonce: String, timeoutMilliseconds: Int, deadlineUptimeNanoseconds: UInt64? = nil, drainOnly: Bool? = nil) {
        self.protocolVersion = DocumentXPCWire.protocolVersion
        self.nonce = nonce; self.timeoutMilliseconds = timeoutMilliseconds
        self.drainOnly = drainOnly
        self.deadlineUptimeNanoseconds = deadlineUptimeNanoseconds ?? (DispatchTime.now().uptimeNanoseconds + UInt64(max(0, min(timeoutMilliseconds, 120_000))) * 1_000_000)
    }
    public var isValid: Bool {
        protocolVersion == DocumentXPCWire.protocolVersion && DocumentXPCWire.validNonce(nonce)
            && (1...120_000).contains(timeoutMilliseconds)
    }
}

public struct DocumentXPCSessionResponse: Codable, Sendable {
    public let protocolVersion: Int
    public let nonce: String
    public let processIdentifier: Int32
    /// A kernel-issued token captured before parsing attacker-controlled bytes.
    public let auditToken: Data
    public let worker: DocumentWorkerHello
    public init(nonce: String, processIdentifier: Int32, auditToken: Data, worker: DocumentWorkerHello) {
        self.protocolVersion = DocumentXPCWire.protocolVersion
        self.nonce = nonce; self.processIdentifier = processIdentifier; self.auditToken = auditToken
        self.worker = worker
    }
}

public struct DocumentXPCDrainResponse: Codable, Sendable {
    public let protocolVersion: Int
    public let nonce: String
    public let processIdentifier: Int32
    public let auditToken: Data
    public let workerStopped: Bool
    public init(nonce: String, processIdentifier: Int32, auditToken: Data, workerStopped: Bool) {
        self.protocolVersion = DocumentXPCWire.protocolVersion
        self.nonce = nonce; self.processIdentifier = processIdentifier
        self.auditToken = auditToken; self.workerStopped = workerStopped
    }
}

public struct DocumentXPCDecodeRequest: Codable, Sendable {
    public let protocolVersion: Int
    public let nonce: String
    public let sourceSHA256: String
    public let sourceByteCount: Int64
    public init(nonce: String, sourceSHA256: String, sourceByteCount: Int64) {
        self.protocolVersion = DocumentXPCWire.protocolVersion
        self.nonce = nonce; self.sourceSHA256 = sourceSHA256; self.sourceByteCount = sourceByteCount
    }
    public var isValid: Bool {
        protocolVersion == DocumentXPCWire.protocolVersion && DocumentXPCWire.validNonce(nonce)
            && sourceSHA256.utf8.count == 64
            && sourceSHA256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
            && sourceByteCount >= 0 && sourceByteCount <= DocumentLimits.maximumInputBytes
    }
}

public struct DocumentXPCDecodeResponse: Codable, Sendable {
    public let protocolVersion: Int
    public let nonce: String
    public let sourceSHA256: String
    public let sourceByteCount: Int64
    public let analysis: DocumentAnalysis?
    public let failureCode: String?

    public init(request: DocumentXPCDecodeRequest, analysis: DocumentAnalysis? = nil, failureCode: String? = nil) {
        self.protocolVersion = DocumentXPCWire.protocolVersion
        self.nonce = request.nonce; self.sourceSHA256 = request.sourceSHA256
        self.sourceByteCount = request.sourceByteCount; self.analysis = analysis; self.failureCode = failureCode
    }
}

public enum DocumentDecoderBackend: String, Codable, Sendable {
    case appSandboxXPC, developmentSeatbelt
}

public enum DocumentDecoderLifecycleEvent: Sendable, Equatable {
    case started(processIdentifier: Int32, backend: DocumentDecoderBackend)
    /// The owned work has stopped. launchd, rather than the host app, reaps XPC.
    case exited(processIdentifier: Int32)
}
