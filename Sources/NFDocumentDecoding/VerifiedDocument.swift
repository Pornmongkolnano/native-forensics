import CryptoKit
import Foundation
import ForensicsCore

/// The isolated parser receives only this complete, receipt-checked memory
/// snapshot. It has no input pathname, descriptor or security-scoped bookmark.
public struct VerifiedDocument: Sendable {
    public let data: Data
    public let sha256: String
    public let byteCount: Int64

    public init(data: Data, expectedSHA256: String, expectedByteCount: Int64) throws {
        guard expectedByteCount >= 0, expectedByteCount <= DocumentLimits.maximumInputBytes,
              expectedSHA256.utf8.count == 64,
              expectedSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw DocumentAnalysisError.invalidInput
        }
        guard Int64(data.count) == expectedByteCount else { throw DocumentAnalysisError.integrityMismatch }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard digest == expectedSHA256 else { throw DocumentAnalysisError.integrityMismatch }
        self.data = data
        self.sha256 = digest
        self.byteCount = expectedByteCount
    }
}
