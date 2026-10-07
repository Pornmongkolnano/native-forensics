import Dispatch

/// POSIX process polling must not occupy Swift's cooperative executor. Callers
/// retain their own cancellation token and await this continuation until the
/// operation has finished unwinding and reaping its owned child.
enum BlockingWork {
    private static let queue = DispatchQueue(
        label: "io.nativeforensics.blocking-work", qos: .userInitiated, attributes: .concurrent
    )

    static func run<Value: Sendable>(
        _ operation: @escaping @Sendable () throws -> Value
    ) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}
