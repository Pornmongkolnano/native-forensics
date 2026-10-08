import Foundation

/// Private pipe framing for a fresh document worker. The four-byte header is
/// an unsigned big-endian payload length; envelopes contain no source handles.
public enum DocumentWorkerWire {
    public static let protocolVersion = 2
    public static let maximumControlBytes = 4_096
    private static let readChunkBytes = 64 * 1_024

    public static func encodeFrame(_ data: Data, maximumBytes: Int = maximumControlBytes) throws -> Data {
        guard maximumBytes >= 0 else { throw DocumentAnalysisError.invalidInput }
        guard data.count <= maximumBytes, UInt64(data.count) <= UInt64(UInt32.max) else {
            throw DocumentAnalysisError.outputLimit
        }
        let length = UInt32(data.count)
        var frame = Data([
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length)
        ])
        frame.append(data)
        return frame
    }

    public static func readFrame(_ handle: FileHandle, maximumBytes: Int = maximumControlBytes) throws -> Data {
        guard maximumBytes >= 0 else { throw DocumentAnalysisError.invalidInput }
        let header = try readExact(handle, count: 4, maxBytes: 4)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard UInt64(length) <= UInt64(maximumBytes) else { throw DocumentAnalysisError.outputLimit }
        return try readExact(handle, count: Int(length), maxBytes: maximumBytes)
    }

    /// Reads exactly the declared byte count without waiting for pipe EOF. Each
    /// intermediate read is bounded, including when the source streams slowly.
    public static func readExact(_ handle: FileHandle, count: Int, maxBytes: Int) throws -> Data {
        guard count >= 0, maxBytes >= 0 else { throw DocumentAnalysisError.invalidInput }
        guard count <= maxBytes else { throw DocumentAnalysisError.outputLimit }
        var data = Data()
        data.reserveCapacity(count)
        while data.count < count {
            let remaining = count - data.count
            let requested = min(remaining, readChunkBytes)
            guard let chunk = try handle.read(upToCount: requested), !chunk.isEmpty,
                  chunk.count <= requested else { throw DocumentAnalysisError.invalidInput }
            data.append(chunk)
        }
        return data
    }
}

public struct DocumentWorkerHello: Codable, Sendable {
    public let protocolVersion: Int
    public let nonce: String
    public let processIdentifier: Int32
    public let auditToken: Data

    public init(nonce: String, processIdentifier: Int32, auditToken: Data) {
        self.protocolVersion = DocumentWorkerWire.protocolVersion
        self.nonce = nonce
        self.processIdentifier = processIdentifier
        self.auditToken = auditToken
    }
}
